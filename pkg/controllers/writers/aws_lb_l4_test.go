package writers

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	gatewayApiv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/adevinta/ingress-allowlisting-controller/pkg/resolvers"
)

// awsGateway is a Gateway of class aws-alb, annotated with the allowlist group, that references
// the LoadBalancerConfiguration config ("" for none).
func awsGateway(name, config, group string) *gatewayApiv1.Gateway {
	gw := &gatewayApiv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "team-a", Annotations: map[string]string{}},
		Spec:       gatewayApiv1.GatewaySpec{GatewayClassName: "aws-alb"},
	}
	if group != "" {
		gw.Annotations["ipam.adevinta.com/allowlist-group"] = group
	}
	if config != "" {
		gw.Spec.Infrastructure = &gatewayApiv1.GatewayInfrastructure{ParametersRef: &gatewayApiv1.LocalParametersReference{
			Group: "gateway.k8s.aws", Kind: "LoadBalancerConfiguration", Name: config,
		}}
	}
	return gw
}

// awsClass is the GatewayClass aws-alb, with the LoadBalancerConfiguration platform/config when
// config isn't "".
func awsClass(config string) *gatewayApiv1.GatewayClass {
	class := &gatewayApiv1.GatewayClass{
		ObjectMeta: metav1.ObjectMeta{Name: "aws-alb"},
		Spec:       gatewayApiv1.GatewayClassSpec{ControllerName: AWSALBControllerName},
	}
	if config != "" {
		ns := gatewayApiv1.Namespace("platform")
		class.Spec.ParametersRef = &gatewayApiv1.ParametersReference{Group: "gateway.k8s.aws", Kind: "LoadBalancerConfiguration", Name: config, Namespace: &ns}
	}
	return class
}

// lbConfig is a LoadBalancerConfiguration with the given spec.
func lbConfig(namespace, name string, spec map[string]any) *unstructured.Unstructured {
	u := &unstructured.Unstructured{Object: map[string]any{"spec": spec}}
	u.SetGroupVersionKind(awsLBConfigGVK)
	u.SetNamespace(namespace)
	u.SetName(name)
	return u
}

func getLBConfig(t *testing.T, c client.Client, namespace, name string) *unstructured.Unstructured {
	t.Helper()
	u := &unstructured.Unstructured{}
	u.SetGroupVersionKind(awsLBConfigGVK)
	require.NoError(t, c.Get(context.Background(), client.ObjectKey{Namespace: namespace, Name: name}, u))
	return u
}

func sourceRanges(t *testing.T, u *unstructured.Unstructured) []string {
	t.Helper()
	ranges, _, err := unstructured.NestedStringSlice(u.Object, "spec", "sourceRanges")
	require.NoError(t, err)
	return ranges
}

func newAWSWriter(objs ...client.Object) (*AWSLBL4Writer, client.Client) {
	c := fake.NewClientBuilder().WithScheme(istioL7Scheme).WithObjects(objs...).Build()
	return NewAWSLBL4Writer(c, resolvers.DefaultPrefix), c
}

func warningReason(t *testing.T, err error) string {
	t.Helper()
	var warning *Warning
	require.True(t, errors.As(err, &warning), "want a *Warning, got %v", err)
	return warning.Reason
}

// TestAWSWriterWritesSourceRanges verifies that the allowlist goes into the sourceRanges of the
// LoadBalancerConfiguration the Gateway references, and that its other settings stay as they are.
func TestAWSWriterWritesSourceRanges(t *testing.T) {
	ctx := context.Background()
	gw := awsGateway("web", "web-lb", "office")
	config := lbConfig("team-a", "web-lb", map[string]any{"scheme": "internet-facing", "sourceRanges": []any{"0.0.0.0/0"}})
	w, c := newAWSWriter(gw, awsClass(""), config)

	require.NoError(t, w.Apply(ctx, nil, gw, []string{"192.0.2.0/24", "198.51.100.7/32"}))
	got := getLBConfig(t, c, "team-a", "web-lb")
	assert.Equal(t, []string{"192.0.2.0/24", "198.51.100.7/32"}, sourceRanges(t, got))
	assert.Equal(t, "internet-facing", stringField(got, "spec", "scheme"), "other settings stay")

	// The same allowlist again: nothing to write.
	before := got.GetResourceVersion()
	lines := infoLines(t, func() { require.NoError(t, w.Apply(ctx, nil, gw, []string{"192.0.2.0/24", "198.51.100.7/32"})) })
	assert.Empty(t, lines, "unchanged: no info line")
	assert.Equal(t, before, getLBConfig(t, c, "team-a", "web-lb").GetResourceVersion(), "unchanged: not patched")
}

// TestAWSWriterEmptyAllowlistDeniesAll verifies that an empty allowlist becomes the deny-all
// address, never an empty list.
func TestAWSWriterEmptyAllowlistDeniesAll(t *testing.T) {
	gw := awsGateway("web", "web-lb", "office")
	w, c := newAWSWriter(gw, awsClass(""), lbConfig("team-a", "web-lb", map[string]any{}))
	require.NoError(t, w.Apply(context.Background(), nil, gw, nil))
	assert.Equal(t, []string{resolvers.DenyAllCIDR}, sourceRanges(t, getLBConfig(t, c, "team-a", "web-lb")))
}

// TestAWSWriterDeleteLeavesTheAllowlist verifies that without the annotation the last allowlist
// stays: removing sourceRanges would open the load balancer to everyone.
func TestAWSWriterDeleteLeavesTheAllowlist(t *testing.T) {
	gw := awsGateway("web", "web-lb", "")
	w, c := newAWSWriter(gw, lbConfig("team-a", "web-lb", map[string]any{"sourceRanges": []any{"192.0.2.0/24"}}))
	require.NoError(t, w.Delete(context.Background(), gw))
	assert.Equal(t, []string{"192.0.2.0/24"}, sourceRanges(t, getLBConfig(t, c, "team-a", "web-lb")))
}

// TestAWSWriterWithoutConfigWarns verifies that a Gateway without a LoadBalancerConfiguration, or
// with one that doesn't exist, gets a warning: nothing can be written without changing the Gateway.
func TestAWSWriterWithoutConfigWarns(t *testing.T) {
	ctx := context.Background()
	noRef := awsGateway("web", "", "office")
	w, _ := newAWSWriter(noRef, awsClass(""))
	err := w.Apply(ctx, nil, noRef, []string{"192.0.2.0/24"})
	assert.Equal(t, ReasonAllowlistTargetMissing, warningReason(t, err))
	assert.Contains(t, err.Error(), "set spec.infrastructure.parametersRef")

	missing := awsGateway("web", "web-lb", "office")
	w, _ = newAWSWriter(missing, awsClass(""))
	err = w.Apply(ctx, nil, missing, []string{"192.0.2.0/24"})
	assert.Equal(t, ReasonAllowlistTargetMissing, warningReason(t, err))
	assert.Contains(t, err.Error(), "LoadBalancerConfiguration team-a/web-lb, referenced by Gateway web, doesn't exist")
}

// TestAWSWriterSharedConfig verifies that a LoadBalancerConfiguration shared by Gateways with the
// same allowlist is written, and one shared with a Gateway with another allowlist, or none, isn't:
// it would set that Gateway's load balancer too.
func TestAWSWriterSharedConfig(t *testing.T) {
	ctx := context.Background()
	gw := awsGateway("web", "shared-lb", "office")
	cases := map[string]struct {
		other    *gatewayApiv1.Gateway
		conflict bool
	}{
		"same allowlist":    {awsGateway("api", "shared-lb", "office"), false},
		"another allowlist": {awsGateway("api", "shared-lb", "partners"), true},
		"no allowlist":      {awsGateway("api", "shared-lb", ""), true},
		"another config":    {awsGateway("api", "api-lb", "partners"), false},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			w, c := newAWSWriter(gw.DeepCopy(), tc.other, awsClass(""), lbConfig("team-a", "shared-lb", map[string]any{}))
			err := w.Apply(ctx, nil, gw, []string{"192.0.2.0/24"})
			if !tc.conflict {
				require.NoError(t, err)
				assert.Equal(t, []string{"192.0.2.0/24"}, sourceRanges(t, getLBConfig(t, c, "team-a", "shared-lb")))
				return
			}
			assert.Equal(t, ReasonAllowlistPolicyConflict, warningReason(t, err))
			assert.Contains(t, err.Error(), "also used by Gateway api")
			assert.Empty(t, sourceRanges(t, getLBConfig(t, c, "team-a", "shared-lb")), "not written")
		})
	}
}

// TestAWSWriterWarnsWhenIneffective verifies the warnings when the AWS controller won't apply the
// written sourceRanges: securityGroups set, or the GatewayClass's sourceRanges winning the merge.
// The allowlist is written anyway, so it applies once the other setting goes away.
func TestAWSWriterWarnsWhenIneffective(t *testing.T) {
	ctx := context.Background()
	gw := awsGateway("web", "web-lb", "office")
	cases := map[string]struct {
		gateway, class map[string]any // specs; class nil: the GatewayClass has no LoadBalancerConfiguration
		want           string         // "" for no warning
	}{
		"plain":                                                    {map[string]any{}, nil, ""},
		"securityGroups on the Gateway's":                          {map[string]any{"securityGroups": []any{"sg-1"}}, nil, "spec.securityGroups is set (in LoadBalancerConfiguration team-a/web-lb)"},
		"empty securityGroups":                                     {map[string]any{"securityGroups": []any{}}, nil, ""},
		"class without sourceRanges":                               {map[string]any{}, map[string]any{"scheme": "internal"}, ""},
		"class sourceRanges win":                                   {map[string]any{}, map[string]any{"sourceRanges": []any{"10.0.0.0/8"}}, "of GatewayClass aws-alb sets its own sourceRanges"},
		"class sourceRanges, prefer-gateway":                       {map[string]any{}, map[string]any{"sourceRanges": []any{"10.0.0.0/8"}, "mergingMode": "prefer-gateway"}, ""},
		"securityGroups on the class's":                            {map[string]any{}, map[string]any{"securityGroups": []any{"sg-1"}}, "spec.securityGroups is set (in LoadBalancerConfiguration platform/class-lb)"},
		"Gateway's securityGroups win over the class's empty ones": {map[string]any{"securityGroups": []any{"sg-1"}}, map[string]any{"securityGroups": []any{}, "mergingMode": "prefer-gateway"}, "spec.securityGroups is set (in LoadBalancerConfiguration team-a/web-lb)"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			objs := []client.Object{gw.DeepCopy(), lbConfig("team-a", "web-lb", tc.gateway)}
			if tc.class != nil {
				objs = append(objs, awsClass("class-lb"), lbConfig("platform", "class-lb", tc.class))
			} else {
				objs = append(objs, awsClass(""))
			}
			w, c := newAWSWriter(objs...)
			err := w.Apply(ctx, nil, gw, []string{"192.0.2.0/24"})
			assert.Equal(t, []string{"192.0.2.0/24"}, sourceRanges(t, getLBConfig(t, c, "team-a", "web-lb")), "written in every case")
			if tc.want == "" {
				assert.NoError(t, err)
				return
			}
			assert.Equal(t, ReasonAllowlistIneffective, warningReason(t, err))
			assert.Contains(t, err.Error(), tc.want)
		})
	}
}
