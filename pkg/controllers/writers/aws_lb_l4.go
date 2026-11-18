package writers

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	gatewayApiv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/adevinta/ingress-allowlisting-controller/pkg/resolvers"
)

// The GatewayClass controllers of the AWS Load Balancer Controller: an ALB (HTTP, L7 load balancer)
// or an NLB (TCP/UDP, L4) per Gateway.
const (
	AWSALBControllerName = "gateway.k8s.aws/alb"
	AWSNLBControllerName = "gateway.k8s.aws/nlb"
)

// awsLBConfigGVK is the AWS Load Balancer Controller's LoadBalancerConfiguration. It's read and
// patched as an unstructured object: controller-runtime reads those from the API server instead of
// starting an informer, so supporting it adds no watch; and the patch carries only the field we
// manage, so no other field of the object is touched.
var awsLBConfigGVK = schema.GroupVersionKind{Group: "gateway.k8s.aws", Version: "v1beta1", Kind: "LoadBalancerConfiguration"}

// The merge modes of a GatewayClass's LoadBalancerConfiguration (spec.mergingMode).
const (
	awsMergePreferGatewayClass = "prefer-gateway-class" // the default
	awsMergePreferGateway      = "prefer-gateway"
)

// AWSLBL4Writer writes the allowlist of a Gateway of the AWS Load Balancer Controller into the
// spec.sourceRanges of the LoadBalancerConfiguration the Gateway references
// (spec.infrastructure.parametersRef). The AWS controller turns it into the inbound rules of the
// load balancer's security group, for an ALB and an NLB alike.
//
// The LoadBalancerConfiguration isn't ours: the Gateway's owner made it, with other settings, and
// references it on purpose. So, like the Service's loadBalancerSourceRanges, only that field is
// written, and only while the Gateway carries the allowlist annotation. Without the annotation the
// last value stays: removing it would open the load balancer to everyone (0.0.0.0/0).
type AWSLBL4Writer struct {
	client           client.Client
	annotationPrefix string
}

// NewAWSLBL4Writer returns a writer for the GatewayClasses of the AWS Load Balancer Controller.
// annotationPrefix tells which Gateways carry an allowlist (see sharedWithOtherAllowlist).
func NewAWSLBL4Writer(c client.Client, annotationPrefix string) *AWSLBL4Writer {
	return &AWSLBL4Writer{client: c, annotationPrefix: annotationPrefix}
}

// RequiredPermissions returns the RBAC permissions needed by this writer: reading a
// LoadBalancerConfiguration and patching its sourceRanges. No list or watch: it is read on demand.
func (w *AWSLBL4Writer) RequiredPermissions() []Permission {
	return Permissions(awsLBConfigGVK.Group, "loadbalancerconfigurations", "get", "patch")
}

// Apply writes ips into the sourceRanges of the Gateway's LoadBalancerConfiguration. What a person
// has to fix comes back as a *Warning: no LoadBalancerConfiguration referenced, one shared with a
// Gateway with another allowlist (nothing written), or settings that make the AWS controller ignore
// sourceRanges (written, but without effect).
func (w *AWSLBL4Writer) Apply(ctx context.Context, _ *runtime.Scheme, gateway *gatewayApiv1.Gateway, ips []string) error {
	ref := gateway.Spec.Infrastructure
	if ref == nil || ref.ParametersRef == nil || string(ref.ParametersRef.Group) != awsLBConfigGVK.Group || string(ref.ParametersRef.Kind) != awsLBConfigGVK.Kind {
		return &Warning{Reason: ReasonAllowlistTargetMissing, Message: fmt.Sprintf(
			"Gateway %s/%s references no LoadBalancerConfiguration: set spec.infrastructure.parametersRef (group %s, kind %s) to one, its sourceRanges get the allowlist",
			gateway.Namespace, gateway.Name, awsLBConfigGVK.Group, awsLBConfigGVK.Kind)}
	}
	config, err := w.getConfig(ctx, gateway.Namespace, ref.ParametersRef.Name)
	if apierrors.IsNotFound(err) {
		return &Warning{Reason: ReasonAllowlistTargetMissing, Message: fmt.Sprintf(
			"LoadBalancerConfiguration %s/%s, referenced by Gateway %s, doesn't exist", gateway.Namespace, ref.ParametersRef.Name, gateway.Name)}
	}
	if err != nil {
		return err
	}

	if other, err := w.sharedWithOtherAllowlist(ctx, gateway); err != nil {
		return err
	} else if other != "" {
		return &Warning{Reason: ReasonAllowlistPolicyConflict, Message: fmt.Sprintf(
			"LoadBalancerConfiguration %s/%s is also used by Gateway %s, which has another allowlist or none: not written, give each Gateway its own LoadBalancerConfiguration",
			config.GetNamespace(), config.GetName(), other)}
	}

	if len(ips) == 0 {
		ips = []string{resolvers.DenyAllCIDR}
	}
	if err := w.writeSourceRanges(ctx, config, ips, gateway.Name); err != nil {
		return err
	}
	return w.ineffective(ctx, gateway, config)
}

// Delete does nothing: without the annotation the last allowlist stays on the
// LoadBalancerConfiguration, as on every object we only modify (see AWSLBL4Writer). It is called on
// every reconcile of a Gateway without the annotation, so it must not read anything either.
func (w *AWSLBL4Writer) Delete(context.Context, *gatewayApiv1.Gateway) error {
	return nil
}

func (w *AWSLBL4Writer) getConfig(ctx context.Context, namespace, name string) (*unstructured.Unstructured, error) {
	config := &unstructured.Unstructured{}
	config.SetGroupVersionKind(awsLBConfigGVK)
	err := w.client.Get(ctx, types.NamespacedName{Namespace: namespace, Name: name}, config)
	return config, err
}

// writeSourceRanges patches spec.sourceRanges to ips, unless it already holds them. A merge patch
// replaces the list as a whole and needs no resourceVersion: another controller's change to the
// object (the AWS controller adds a finalizer) doesn't conflict with it.
func (w *AWSLBL4Writer) writeSourceRanges(ctx context.Context, config *unstructured.Unstructured, ips []string, gatewayName string) error {
	current, _, err := unstructured.NestedStringSlice(config.Object, "spec", "sourceRanges")
	if err != nil {
		return fmt.Errorf("LoadBalancerConfiguration %s/%s: spec.sourceRanges: %w", config.GetNamespace(), config.GetName(), err)
	}
	if slices.Equal(current, ips) {
		return nil
	}
	patch, err := json.Marshal(map[string]any{"spec": map[string]any{"sourceRanges": ips}})
	if err != nil {
		return err
	}
	if err := w.client.Patch(ctx, config, client.RawPatch(types.MergePatchType, patch)); err != nil {
		return err
	}
	logChange(ctx, controllerutil.OperationResultUpdated, "LoadBalancerConfiguration", config, "Gateway "+gatewayName)
	return nil
}

// sharedWithOtherAllowlist returns the name of another Gateway of the namespace that references the
// same LoadBalancerConfiguration with other allowlist annotations, or none, "" if there's none.
// Writing would then set the load balancer of that Gateway too, to an allowlist it didn't ask for.
// The Gateways come from the cache, as for every Gateway reconcile.
func (w *AWSLBL4Writer) sharedWithOtherAllowlist(ctx context.Context, gateway *gatewayApiv1.Gateway) (string, error) {
	list := &gatewayApiv1.GatewayList{}
	if err := w.client.List(ctx, list, client.InNamespace(gateway.Namespace)); err != nil {
		return "", err
	}
	name := gateway.Spec.Infrastructure.ParametersRef.Name
	ours := w.allowlistAnnotations(gateway)
	for i := range list.Items {
		other := &list.Items[i]
		if other.Name == gateway.Name || other.Spec.Infrastructure == nil || other.Spec.Infrastructure.ParametersRef == nil {
			continue
		}
		ref := other.Spec.Infrastructure.ParametersRef
		if string(ref.Group) != awsLBConfigGVK.Group || string(ref.Kind) != awsLBConfigGVK.Kind || ref.Name != name {
			continue
		}
		if w.allowlistAnnotations(other) != ours {
			return other.Name, nil
		}
	}
	return "", nil
}

// allowlistAnnotations are the values of the allowlist annotations of obj, as one string.
func (w *AWSLBL4Writer) allowlistAnnotations(obj client.Object) string {
	a := obj.GetAnnotations()
	return a[w.annotationPrefix+"/allowlist-group"] + "\x00" + a[w.annotationPrefix+"/cluster-allowlist-group"]
}

// ineffective returns a *Warning when the AWS controller won't apply the sourceRanges just
// written, nil otherwise. It merges the Gateway's LoadBalancerConfiguration with its GatewayClass's
// like the AWS controller does (lb_config_merger.go): per field, the value of the higher-priority
// one if it sets the field, the other's otherwise; the GatewayClass's has priority unless its
// mergingMode is prefer-gateway. sourceRanges has no effect when the GatewayClass's value is the one
// used, or when the merged securityGroups isn't empty: the AWS controller then uses those security
// groups as they are.
func (w *AWSLBL4Writer) ineffective(ctx context.Context, gateway *gatewayApiv1.Gateway, config *unstructured.Unstructured) error {
	classConfig, err := w.gatewayClassConfig(ctx, gateway)
	if err != nil {
		return err
	}
	high, low := classConfig, config
	if classConfig == nil || stringField(classConfig, "spec", "mergingMode") == awsMergePreferGateway {
		high, low = config, classConfig
	}

	var problems []string
	if from := mergedFrom(high, low, "sourceRanges"); from != nil && from != config {
		problems = append(problems, fmt.Sprintf("the LoadBalancerConfiguration %s/%s of GatewayClass %s sets its own sourceRanges, and they win (mergingMode %s)",
			from.GetNamespace(), from.GetName(), gateway.Spec.GatewayClassName, awsMergePreferGatewayClass))
	}
	if from := mergedFrom(high, low, "securityGroups"); from != nil {
		if groups, _, _ := unstructured.NestedSlice(from.Object, "spec", "securityGroups"); len(groups) > 0 {
			problems = append(problems, fmt.Sprintf("spec.securityGroups is set (in LoadBalancerConfiguration %s/%s), so the AWS Load Balancer Controller uses those security groups as they are and ignores sourceRanges",
				from.GetNamespace(), from.GetName()))
		}
	}
	if len(problems) == 0 {
		return nil
	}
	return &Warning{Reason: ReasonAllowlistIneffective, Message: fmt.Sprintf(
		"the allowlist of Gateway %s/%s was written to LoadBalancerConfiguration %s/%s but has no effect: %s",
		gateway.Namespace, gateway.Name, config.GetNamespace(), config.GetName(), strings.Join(problems, "; "))}
}

// mergedFrom returns the configuration whose spec.<field> the AWS controller uses: high if it sets
// the field, else low if it does, else nil. Either may be nil.
func mergedFrom(high, low *unstructured.Unstructured, field string) *unstructured.Unstructured {
	for _, c := range []*unstructured.Unstructured{high, low} {
		if c != nil && hasField(c, "spec", field) {
			return c
		}
	}
	return nil
}

// gatewayClassConfig returns the LoadBalancerConfiguration of the Gateway's GatewayClass
// (spec.parametersRef), nil if it has none.
func (w *AWSLBL4Writer) gatewayClassConfig(ctx context.Context, gateway *gatewayApiv1.Gateway) (*unstructured.Unstructured, error) {
	class := &gatewayApiv1.GatewayClass{}
	if err := w.client.Get(ctx, types.NamespacedName{Name: string(gateway.Spec.GatewayClassName)}, class); err != nil {
		return nil, client.IgnoreNotFound(err)
	}
	ref := class.Spec.ParametersRef
	if ref == nil || string(ref.Group) != awsLBConfigGVK.Group || string(ref.Kind) != awsLBConfigGVK.Kind || ref.Namespace == nil {
		return nil, nil
	}
	config, err := w.getConfig(ctx, string(*ref.Namespace), ref.Name)
	if apierrors.IsNotFound(err) {
		return nil, nil
	}
	return config, err
}

func hasField(obj *unstructured.Unstructured, fields ...string) bool {
	_, found, _ := unstructured.NestedFieldNoCopy(obj.Object, fields...)
	return found
}

func stringField(obj *unstructured.Unstructured, fields ...string) string {
	value, _, _ := unstructured.NestedString(obj.Object, fields...)
	return value
}
