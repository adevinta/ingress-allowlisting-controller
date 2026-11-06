package controllers

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	gatewayApiv1 "sigs.k8s.io/gateway-api/apis/v1"

	ipamv1alpha1 "github.com/adevinta/ingress-allowlisting-controller/pkg/apis/ipam.adevinta.com/v1alpha1"
	"github.com/adevinta/ingress-allowlisting-controller/pkg/controllers/writers"
	"github.com/adevinta/ingress-allowlisting-controller/pkg/resolvers"
)

var lbConfigGVK = schema.GroupVersionKind{Group: "gateway.k8s.aws", Version: "v1beta1", Kind: "LoadBalancerConfiguration"}

// TestReconcileAWSGateway verifies that a Gateway of the AWS Load Balancer Controller gets its
// allowlist in the sourceRanges of its LoadBalancerConfiguration, for an ALB and an NLB class, and
// that a Gateway without one gets a Warning Event instead of an endless retry.
func TestReconcileAWSGateway(t *testing.T) {
	ctx := context.Background()
	cidrs := &ipamv1alpha1.CIDRs{
		ObjectMeta: metav1.ObjectMeta{Name: "office", Namespace: "team-a"},
		Status:     ipamv1alpha1.CIDRsStatus{CIDRs: []string{"192.0.2.0/24"}},
	}
	for _, controller := range []string{writers.AWSALBControllerName, writers.AWSNLBControllerName} {
		t.Run(controller, func(t *testing.T) {
			class := &gatewayApiv1.GatewayClass{
				ObjectMeta: metav1.ObjectMeta{Name: "aws"},
				Spec:       gatewayApiv1.GatewayClassSpec{ControllerName: gatewayApiv1.GatewayController(controller)},
			}
			withConfig := &gatewayApiv1.Gateway{
				ObjectMeta: metav1.ObjectMeta{Name: "web", Namespace: "team-a", Annotations: map[string]string{"ipam.adevinta.com/allowlist-group": "office"}},
				Spec: gatewayApiv1.GatewaySpec{GatewayClassName: "aws", Infrastructure: &gatewayApiv1.GatewayInfrastructure{
					ParametersRef: &gatewayApiv1.LocalParametersReference{Group: "gateway.k8s.aws", Kind: "LoadBalancerConfiguration", Name: "web-lb"},
				}},
			}
			without := &gatewayApiv1.Gateway{
				ObjectMeta: metav1.ObjectMeta{Name: "api", Namespace: "team-a", Annotations: map[string]string{"ipam.adevinta.com/allowlist-group": "office"}},
				Spec:       gatewayApiv1.GatewaySpec{GatewayClassName: "aws"},
			}
			config := &unstructured.Unstructured{Object: map[string]any{"spec": map[string]any{"scheme": "internal"}}}
			config.SetGroupVersionKind(lbConfigGVK)
			config.SetNamespace("team-a")
			config.SetName("web-lb")

			c := fake.NewClientBuilder().WithScheme(extendedScheme).WithObjects(cidrs, class, withConfig, without, config).Build()
			resolver := newTestCidrResolver(c)
			aws := writers.NewAWSLBL4Writer(c, resolvers.DefaultPrefix)
			r := &GatewayAllowlistingReconciler{Client: c, Scheme: extendedScheme, CidrResolver: resolver, L4Writers: writers.L4WriterRegistry{
				writers.AWSALBControllerName: aws, writers.AWSNLBControllerName: aws,
			}}

			result, err := r.Reconcile(ctx, reconcile.Request{NamespacedName: client.ObjectKeyFromObject(withConfig)})
			require.NoError(t, err)
			assert.Equal(t, reconcile.Result{}, result)
			got := &unstructured.Unstructured{}
			got.SetGroupVersionKind(lbConfigGVK)
			require.NoError(t, c.Get(ctx, client.ObjectKeyFromObject(config), got))
			ranges, _, _ := unstructured.NestedStringSlice(got.Object, "spec", "sourceRanges")
			assert.Equal(t, []string{"192.0.2.0/24"}, ranges)

			result, err = r.Reconcile(ctx, reconcile.Request{NamespacedName: client.ObjectKeyFromObject(without)})
			require.NoError(t, err, "a warning, not a retry")
			assert.Equal(t, reconcile.Result{}, result)
			events := recordedEvents(t, resolver)
			require.Len(t, events, 1)
			assert.Contains(t, events[0], "Warning AllowlistTargetMissing")
			assert.Contains(t, events[0], "Gateway team-a/api references no LoadBalancerConfiguration")
		})
	}
}

// TestBuildWriterRegistriesRegistersAWS verifies that the AWS writer is registered for both of the
// AWS Load Balancer Controller's GatewayClass controllers when its LoadBalancerConfiguration CRD is
// installed, and not otherwise.
func TestBuildWriterRegistriesRegistersAWS(t *testing.T) {
	mapper := meta.NewDefaultRESTMapper(nil)
	l4, _ := BuildWriterRegistries(nil, mapper, "test", resolvers.CidrResolver{AnnotationPrefix: resolvers.DefaultPrefix})
	assert.NotContains(t, l4, writers.AWSALBControllerName)
	assert.NotContains(t, l4, writers.AWSNLBControllerName)

	mapper.Add(lbConfigGVK, meta.RESTScopeNamespace)
	l4, _ = BuildWriterRegistries(nil, mapper, "test", resolvers.CidrResolver{AnnotationPrefix: resolvers.DefaultPrefix})
	assert.IsType(t, &writers.AWSLBL4Writer{}, l4[writers.AWSALBControllerName])
	assert.IsType(t, &writers.AWSLBL4Writer{}, l4[writers.AWSNLBControllerName])
	assert.NotContains(t, l4, writers.IstioControllerName, "Istio isn't installed")
}
