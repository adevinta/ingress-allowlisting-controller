package writers

import (
	"context"
	"fmt"
	"regexp"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	gatewayApiv1 "sigs.k8s.io/gateway-api/apis/v1"

	istioApiSecurityV1 "istio.io/api/security/v1"
	istioApiTypeV1beta1 "istio.io/api/type/v1beta1"
	istiosecurityv1 "istio.io/client-go/pkg/apis/security/v1"

	"github.com/adevinta/ingress-allowlisting-controller/pkg/resolvers"
)

// invalidLabelValue matches characters not allowed in k8s label values.
var invalidLabelValue = regexp.MustCompile(`[^-A-Za-z0-9_.]`)

// LabelSafe sanitizes a string for use as a Kubernetes label value.
func LabelSafe(s string) string {
	v := invalidLabelValue.ReplaceAllString(s, "_")
	if len(v) > 63 {
		v = v[:63]
	}
	return v
}

// IstioL7Writer creates/deletes Istio AuthorizationPolicies for HTTPRoute-level (L7) allowlisting.
type IstioL7Writer struct {
	client           client.Client
	managedBy        string
	annotationPrefix string
	cidrResolver     resolvers.CidrResolver
}

// NewIstioL7Writer returns a new IstioL7Writer.
func NewIstioL7Writer(c client.Client, managedBy string, cidrResolver resolvers.CidrResolver) *IstioL7Writer {
	return &IstioL7Writer{
		client:           c,
		managedBy:        managedBy,
		annotationPrefix: cidrResolver.AnnotationPrefix,
		cidrResolver:     cidrResolver,
	}
}

// applyLabels sets standard managed-by and owner labels on the policy.
func (w *IstioL7Writer) applyLabels(policy *istiosecurityv1.AuthorizationPolicy, ownerNamespace, ownerName string) {
	if policy.Labels == nil {
		policy.Labels = map[string]string{}
	}
	policy.Labels["app.kubernetes.io/managed-by"] = w.managedBy
	policy.Labels[w.annotationPrefix+"/owner-namespace"] = LabelSafe(ownerNamespace)
	policy.Labels[w.annotationPrefix+"/owner-name"] = LabelSafe(ownerName)
}

// policyName computes the AP name for a given route at the given index.
// index is the position of this parentRef among Gateway parentRefs (0-based).
// crossNamespace is true when the gateway is in a different namespace than the route.
func policyName(route *gatewayApiv1.HTTPRoute, gateway *gatewayApiv1.Gateway, index int) (name, namespace string, crossNamespace bool) {
	crossNamespace = gateway.Namespace != route.Namespace
	namespace = route.Namespace
	baseName := route.Name
	if crossNamespace {
		namespace = gateway.Namespace
		baseName = route.Namespace + "-" + route.Name
	}
	name = baseName
	if index > 0 {
		name = fmt.Sprintf("%s-%d", baseName, index)
	}
	return name, namespace, crossNamespace
}

// Apply creates or updates an AuthorizationPolicy for the given HTTPRoute parentRef at the given index.
func (w *IstioL7Writer) Apply(ctx context.Context, scheme *runtime.Scheme, route *gatewayApiv1.HTTPRoute, gateway *gatewayApiv1.Gateway, ips, hosts, paths []string, index int) error {
	apName, apNamespace, crossNamespace := policyName(route, gateway, index)

	policy := &istiosecurityv1.AuthorizationPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: apName, Namespace: apNamespace},
	}
	rules := buildAuthorizationRules(ips, hosts)
	_, err := ctrl.CreateOrUpdate(ctx, w.client, policy, func() error {
		if !crossNamespace {
			if err := ctrl.SetControllerReference(route, policy, scheme); err != nil {
				return err
			}
		}
		w.applyLabels(policy, route.Namespace, route.Name)
		policy.Spec = istioApiSecurityV1.AuthorizationPolicy{
			Action: istioApiSecurityV1.AuthorizationPolicy_ALLOW,
			Rules:  rules,
			TargetRefs: []*istioApiTypeV1beta1.PolicyTargetReference{
				{Name: gateway.Name, Kind: "Gateway", Group: "gateway.networking.k8s.io"},
			},
		}
		return nil
	})
	return err
}

// ApplyMerged creates or updates a merged AuthorizationPolicy for a merge group.
// It aggregates IPs and hosts from all sibling HTTPRoutes internally.
// Path support (granularity=path) is not yet implemented — paths are ignored for now.
func (w *IstioL7Writer) ApplyMerged(ctx context.Context, gateway *gatewayApiv1.Gateway, siblings []*gatewayApiv1.HTTPRoute, mergeKey string, index int) error {
	seenIPs := map[string]struct{}{}
	seenHosts := map[string]struct{}{}
	var mergedIPs, mergedHosts []string

	for _, sibling := range siblings {
		ips, err := w.cidrResolver.GetCidrsFromObject(ctx, sibling)
		if err == w.cidrResolver.AnnotationNotFoundError() {
			continue
		}
		if err != nil {
			return err
		}
		for _, ip := range ips {
			if _, seen := seenIPs[ip]; !seen {
				seenIPs[ip] = struct{}{}
				mergedIPs = append(mergedIPs, ip)
			}
		}
		for _, h := range sibling.Spec.Hostnames {
			host := string(h)
			if _, seen := seenHosts[host]; !seen {
				seenHosts[host] = struct{}{}
				mergedHosts = append(mergedHosts, host)
			}
		}
	}

	if len(mergedIPs) == 0 {
		return nil
	}

	apName := mergeKey
	if index > 0 {
		apName = fmt.Sprintf("%s-%d", mergeKey, index)
	}
	policy := &istiosecurityv1.AuthorizationPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: apName, Namespace: gateway.Namespace},
	}
	_, err := ctrl.CreateOrUpdate(ctx, w.client, policy, func() error {
		w.applyLabels(policy, "merged", mergeKey)
		policy.Spec = istioApiSecurityV1.AuthorizationPolicy{
			Action: istioApiSecurityV1.AuthorizationPolicy_ALLOW,
			Rules:  buildAuthorizationRules(mergedIPs, mergedHosts),
			TargetRefs: []*istioApiTypeV1beta1.PolicyTargetReference{
				{Name: gateway.Name, Kind: "Gateway", Group: "gateway.networking.k8s.io"},
			},
		}
		return nil
	})
	return err
}

// ListManaged returns all AuthorizationPolicies managed by this controller (identified by managedBy label).
func (w *IstioL7Writer) ListManaged(ctx context.Context, managedBy string) ([]client.Object, error) {
	list := &istiosecurityv1.AuthorizationPolicyList{}
	if err := w.client.List(ctx, list, client.MatchingLabels{
		"app.kubernetes.io/managed-by": managedBy,
	}); err != nil {
		return nil, err
	}
	result := make([]client.Object, len(list.Items))
	for i, item := range list.Items {
		result[i] = item
	}
	return result, nil
}

// IsOrphaned reports whether the given AP no longer has a valid owner HTTPRoute.
func (w *IstioL7Writer) IsOrphaned(obj client.Object, allRoutes []gatewayApiv1.HTTPRoute) bool {
	ownerNS := obj.GetLabels()[w.annotationPrefix+"/owner-namespace"]
	ownerName := obj.GetLabels()[w.annotationPrefix+"/owner-name"]
	mergeAnnotation := w.annotationPrefix + "/merge"

	if ownerNS == "merged" {
		// Merge-mode AP: check if any route still has this merge key
		for i := range allRoutes {
			if allRoutes[i].Annotations[mergeAnnotation] == ownerName {
				return false
			}
		}
		return true
	}

	// Normal AP: check if owner route still exists and still produces this AP
	for i := range allRoutes {
		r := &allRoutes[i]
		if r.Namespace != ownerNS || r.Name != ownerName {
			continue
		}
		// Route exists — check if it's in merge mode now
		if r.Annotations[mergeAnnotation] != "" {
			// Route switched to merge mode — old non-merge AP is orphaned
			return true
		}
		// Check if the route still produces this AP
		if routeProducesPolicy(r, obj.GetNamespace(), obj.GetName()) {
			return false
		}
		return true
	}

	// Route not found in list — it's gone
	return true
}

// Delete removes the given object from the cluster.
func (w *IstioL7Writer) Delete(ctx context.Context, obj client.Object) error {
	return client.IgnoreNotFound(w.client.Delete(ctx, obj))
}

// policyTargets computes the complete set of AuthorizationPolicies that the non-merge
// reconcile path would produce for route: one per Gateway parentRef.
// This mirrors the naming convention used in Apply.
type policyTarget struct {
	namespace string
	name      string
}

func policyTargetsForRoute(route *gatewayApiv1.HTTPRoute) []policyTarget {
	var targets []policyTarget
	refs := gatewayParentRefs(route)
	for i, ref := range refs {
		crossNamespace := ref.Namespace != nil && string(*ref.Namespace) != route.Namespace
		targetNamespace := route.Namespace
		baseName := route.Name
		if crossNamespace {
			targetNamespace = string(*ref.Namespace)
			baseName = route.Namespace + "-" + route.Name
		}
		name := baseName
		if i > 0 {
			name = fmt.Sprintf("%s-%d", baseName, i)
		}
		targets = append(targets, policyTarget{
			namespace: targetNamespace,
			name:      name,
		})
	}
	return targets
}

// routeProducesPolicy reports whether the non-merge reconcile path for route would generate
// an AuthorizationPolicy at the given {namespace, name}.
func routeProducesPolicy(route *gatewayApiv1.HTTPRoute, policyNamespace, policyName string) bool {
	for _, pt := range policyTargetsForRoute(route) {
		if pt.namespace == policyNamespace && pt.name == policyName {
			return true
		}
	}
	return false
}

// gatewayParentRefs returns all parentRefs that target a Gateway.
func gatewayParentRefs(httproute *gatewayApiv1.HTTPRoute) []gatewayApiv1.ParentReference {
	var refs []gatewayApiv1.ParentReference
	for _, ref := range httproute.Spec.ParentRefs {
		if ref.Kind != nil && *ref.Kind != "Gateway" {
			continue
		}
		if ref.Group != nil && *ref.Group != "gateway.networking.k8s.io" {
			continue
		}
		refs = append(refs, ref)
	}
	return refs
}

// buildAuthorizationRules builds the Istio rules for an AuthorizationPolicy.
func buildAuthorizationRules(allowedIPs, hostnames []string) []*istioApiSecurityV1.Rule {
	rules := []*istioApiSecurityV1.Rule{
		{
			From: []*istioApiSecurityV1.Rule_From{
				{Source: &istioApiSecurityV1.Source{RemoteIpBlocks: allowedIPs}},
			},
		},
	}
	if len(hostnames) > 0 {
		rules[0].To = []*istioApiSecurityV1.Rule_To{
			{Operation: &istioApiSecurityV1.Operation{Hosts: hostnames}},
		}
	}
	return rules
}
