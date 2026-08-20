package writers

import (
	"context"
	"fmt"
	"hash/fnv"
	"regexp"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	gatewayApiv1 "sigs.k8s.io/gateway-api/apis/v1"

	istioApiSecurityV1 "istio.io/api/security/v1"
	istioApiTypeV1beta1 "istio.io/api/type/v1beta1"
	istiosecurityv1 "istio.io/client-go/pkg/apis/security/v1"

	"github.com/adevinta/ingress-allowlisting-controller/pkg/controllers/internal"
	"github.com/adevinta/ingress-allowlisting-controller/pkg/util"
	"github.com/adevinta/ingress-allowlisting-controller/pkg/resolvers"
)

// invalidLabelValue matches characters not allowed in k8s label values.
var invalidLabelValue = regexp.MustCompile(`[^-A-Za-z0-9_.]`)

// LabelSafe sanitizes a string for use as a Kubernetes label value.
// Names longer than 63 chars are truncated to 54 chars and suffixed with
// "-{fnv32hex}" to stay collision-resistant (same approach as truncateName).
func LabelSafe(s string) string {
	v := invalidLabelValue.ReplaceAllString(s, "_")
	if len(v) > 63 {
		h := fnv.New32a()
		_, _ = h.Write([]byte(s))
		v = fmt.Sprintf("%s-%08x", v[:54], h.Sum32())
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

// policyName computes the AP name and namespace for a given route+gateway+paths.
// Format: {gateway.Name}-{route.Name} (same-namespace)
//
//	{gateway.Name}-{route.Namespace}-{route.Name} (cross-namespace, AP lives in gateway's namespace)
//
// When paths is non-empty, a FNV-32a hash of the sorted path set is appended so each HTTPRoute
// rule gets its own AP. The hash is order-independent and collision-resistant.
func policyName(route *gatewayApiv1.HTTPRoute, gateway *gatewayApiv1.Gateway, paths []string) (name, namespace string, crossNamespace bool) {
	crossNamespace = gateway.Namespace != route.Namespace
	namespace = route.Namespace
	baseName := gateway.Name + "-" + route.Name
	if crossNamespace {
		namespace = gateway.Namespace
		baseName = gateway.Name + "-" + route.Namespace + "-" + route.Name
	}
	name = baseName
	if len(paths) > 0 {
		h := fnv.New32a()
		for _, p := range util.DedupSorted(paths) {
			_, _ = h.Write([]byte(p))
		}
		name = fmt.Sprintf("%s-%08x", baseName, h.Sum32())
	}
	name = truncateName(name)
	return name, namespace, crossNamespace
}

// truncateName ensures a Kubernetes resource name stays within the 253-char limit.
// Names that fit are returned unchanged. Names that overflow are truncated to 244 chars
// and suffixed with "-{fnv32hex(fullName)}" (9 chars) to keep them collision-resistant.
func truncateName(name string) string {
	const maxLen = 253
	const hashSuffixLen = 9 // "-" + 8 hex chars
	if len(name) <= maxLen {
		return name
	}
	h := fnv.New32a()
	_, _ = h.Write([]byte(name))
	return fmt.Sprintf("%s-%08x", name[:maxLen-hashSuffixLen], h.Sum32())
}

// policyNameSuffix returns the AP name suffix for a given path set, mirroring policyName.
func policyNameSuffix(paths []string) string {
	if len(paths) == 0 {
		return ""
	}
	h := fnv.New32a()
	for _, p := range util.DedupSorted(paths) {
		_, _ = h.Write([]byte(p))
	}
	return fmt.Sprintf("-%08x", h.Sum32())
}

// RequiredPermissions returns the RBAC permissions needed by this writer.
func (w *IstioL7Writer) RequiredPermissions() []Permission {
	return []Permission{
		{Group: "security.istio.io", Resource: "authorizationpolicies", Verb: "get"},
		{Group: "security.istio.io", Resource: "authorizationpolicies", Verb: "create"},
		{Group: "security.istio.io", Resource: "authorizationpolicies", Verb: "update"},
		{Group: "security.istio.io", Resource: "authorizationpolicies", Verb: "delete"},
	}
}

// Apply creates or updates an AuthorizationPolicy for the given HTTPRoute+gateway+paths combination.
// When paths is non-empty the AP name includes a hash suffix so each rule gets its own AP.
// If ips is empty, any previously created AP for this route+paths is deleted instead.
func (w *IstioL7Writer) Apply(ctx context.Context, scheme *runtime.Scheme, route *gatewayApiv1.HTTPRoute, gateway *gatewayApiv1.Gateway, ips, hosts, paths []string) error {
	apName, apNamespace, crossNamespace := policyName(route, gateway, paths)
	if len(ips) == 0 {
		policy := &istiosecurityv1.AuthorizationPolicy{}
		policy.Name = apName
		policy.Namespace = apNamespace
		return client.IgnoreNotFound(w.client.Delete(ctx, policy))
	}

	policy := &istiosecurityv1.AuthorizationPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: apName, Namespace: apNamespace},
	}
	rules := buildAuthorizationRules(ips, hosts, paths)
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

	if ownerNS == "MERGED" {
		// Merge-mode AP: check if any route still has this merge key
		for i := range allRoutes {
			if allRoutes[i].Annotations[mergeAnnotation] == ownerName {
				return false
			}
		}
		return true
	}

	// Normal AP: check if owner route still exists and still produces this AP.
	// Labels are stored via LabelSafe() so we must compare using LabelSafe() on both sides.
	for i := range allRoutes {
		r := &allRoutes[i]
		if LabelSafe(r.Namespace) != ownerNS || LabelSafe(r.Name) != ownerName {
			continue
		}
		// Route exists — check if it's in merge mode now
		if r.Annotations[mergeAnnotation] != "" {
			return true
		}
		// Check if the route still produces this AP (exact or path-suffixed)
		if w.routeProducesPolicy(r, obj.GetNamespace(), obj.GetName()) {
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

// DeleteForRoute deletes all APs owned by the given route, identified by owner labels.
func (w *IstioL7Writer) DeleteForRoute(ctx context.Context, managedBy, routeNamespace, routeName string) error {
	list := &istiosecurityv1.AuthorizationPolicyList{}
	if err := w.client.List(ctx, list, client.MatchingLabels{
		"app.kubernetes.io/managed-by":          managedBy,
		w.annotationPrefix + "/owner-namespace": LabelSafe(routeNamespace),
		w.annotationPrefix + "/owner-name":      LabelSafe(routeName),
	}); err != nil {
		return err
	}
	for i := range list.Items {
		if err := client.IgnoreNotFound(w.client.Delete(ctx, list.Items[i])); err != nil {
			return err
		}
	}
	return nil
}

// policyTarget is a single (namespace, name) pair identifying an AuthorizationPolicy.
type policyTarget struct {
	namespace string
	name      string
}

// policyTargetsForRoute returns the exact set of AP (namespace, name) pairs that the
// non-merge reconcile path would produce for route — mirrors the Apply call-sites exactly.
// Used by IsOrphaned for exact matching — no prefix heuristics.
func (w *IstioL7Writer) policyTargetsForRoute(route *gatewayApiv1.HTTPRoute) []policyTarget {
	granularity := route.Annotations[w.annotationPrefix+"/granularity"]

	var targets []policyTarget
	for _, ref := range gateway.GatewayParentRefs(route) {
		refNS := route.Namespace
		if ref.Namespace != nil {
			refNS = string(*ref.Namespace)
		}
		crossNamespace := refNS != route.Namespace
		targetNamespace := route.Namespace
		gatewayName := string(ref.Name)
		baseName := gatewayName + "-" + route.Name
		if crossNamespace {
			targetNamespace = refNS
			baseName = gatewayName + "-" + route.Namespace + "-" + route.Name
		}

		// granularity=host: one AP with base name, no path suffix.
		if granularity == "host" {
			targets = append(targets, policyTarget{namespace: targetNamespace, name: baseName})
			continue
		}

		// granularity=rule (default): one AP per rule with path suffix.
		if len(route.Spec.Rules) == 0 {
			targets = append(targets, policyTarget{namespace: targetNamespace, name: baseName})
			continue
		}
		for _, rule := range route.Spec.Rules {
			paths := w.TranslatePaths(rule.Matches)
			targets = append(targets, policyTarget{
				namespace: targetNamespace,
				name:      truncateName(baseName + policyNameSuffix(paths)),
			})
		}
	}
	return targets
}

// routeProducesPolicy reports whether the non-merge reconcile path for route would generate
// an AuthorizationPolicy at the given {namespace, name}. Uses exact matching only.
func (w *IstioL7Writer) routeProducesPolicy(route *gatewayApiv1.HTTPRoute, policyNamespace, policyName string) bool {
	for _, pt := range w.policyTargetsForRoute(route) {
		if pt.namespace == policyNamespace && pt.name == policyName {
			return true
		}
	}
	return false
}

// buildAuthorizationRules builds the Istio rules for an AuthorizationPolicy.
// When paths is non-empty, Operation.Paths is set to restrict to those paths.
func buildAuthorizationRules(allowedIPs, hostnames, paths []string) []*istioApiSecurityV1.Rule {
	rules := []*istioApiSecurityV1.Rule{
		{
			From: []*istioApiSecurityV1.Rule_From{
				{Source: &istioApiSecurityV1.Source{RemoteIpBlocks: allowedIPs}},
			},
		},
	}
	if len(hostnames) > 0 || len(paths) > 0 {
		op := &istioApiSecurityV1.Operation{}
		if len(hostnames) > 0 {
			op.Hosts = hostnames
		}
		if len(paths) > 0 {
			op.Paths = paths
		}
		rules[0].To = []*istioApiSecurityV1.Rule_To{
			{Operation: op},
		}
	}
	return rules
}

// TranslatePaths implements PathTranslator for Istio AuthorizationPolicy path semantics.
// PathPrefix /chaos → ["/chaos", "/chaos/*"] (exact + glob, covers /chaos and all sub-paths)
// Exact /chaos     → ["/chaos"]              (passed through unchanged)
// RegularExpression → skipped                (not supported by Istio AuthorizationPolicy)
func (w *IstioL7Writer) TranslatePaths(matches []gatewayApiv1.HTTPRouteMatch) []string {
	var paths []string
	for _, match := range matches {
		if match.Path == nil || match.Path.Value == nil {
			continue
		}
		v := *match.Path.Value
		t := gatewayApiv1.PathMatchPathPrefix // default per Gateway API spec
		if match.Path.Type != nil {
			t = *match.Path.Type
		}
		switch t {
		case gatewayApiv1.PathMatchPathPrefix:
			if v == "/" {
				paths = append(paths, "/*")
			} else {
				paths = append(paths, v, v+"/*")
			}
		case gatewayApiv1.PathMatchExact:
			paths = append(paths, v)
		// RegularExpression: not supported by Istio AP — skip
		}
	}
	return paths
}

