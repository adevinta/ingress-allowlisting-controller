package writers

import (
	"context"

	log "github.com/adevinta/go-log-toolkit"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	gatewayApiv1 "sigs.k8s.io/gateway-api/apis/v1"

	istioApiSecurityV1 "istio.io/api/security/v1"
	istioApiTypeV1beta1 "istio.io/api/type/v1beta1"
	istiosecurityv1 "istio.io/client-go/pkg/apis/security/v1"

	"github.com/adevinta/ingress-allowlisting-controller/pkg/controllers/internal"
	"github.com/adevinta/ingress-allowlisting-controller/pkg/resolvers"
)

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

// applyLabels sets the ownership labels on the policy (see ownership.go).
func (w *IstioL7Writer) applyLabels(policy *istiosecurityv1.AuthorizationPolicy, kind, ownerNamespace, ownerName string) {
	setOwnerLabels(policy, w.annotationPrefix, w.managedBy, kind, ownerNamespace, ownerName)
}

// policyName returns the name and namespace of the policy of route on gateway for a rule with
// paths (see policy_names.go), and whether it lives in the Gateway's namespace (cross-namespace).
func (w *IstioL7Writer) policyName(route *gatewayApiv1.HTTPRoute, gateway *gatewayApiv1.Gateway, paths []string) (name, namespace string, crossNamespace bool) {
	t := w.policyTarget(route.Namespace, route.Name, gateway.Namespace, gateway.Name, paths)
	return t.name, t.namespace, t.namespace != route.Namespace
}

// policyTarget is the policy of the route routeNS/route on the Gateway gwNS/gw for a rule with
// paths. The one function that names route policies: Apply and the orphan checks must agree.
func (w *IstioL7Writer) policyTarget(routeNS, route, gwNS, gw string, paths []string) policyTarget {
	if gwNS == routeNS {
		return policyTarget{namespace: routeNS, name: sameNamespacePolicyName(gw, route, paths)}
	}
	return policyTarget{
		namespace:  gwNS,
		name:       CrossNamespacePolicyName(w.annotationPrefix, routeNS, gw, route, paths),
		legacyName: legacyCrossNamespacePolicyName(routeNS, gw, route, paths),
	}
}

// RequiredPermissions returns the RBAC permissions needed by this writer.
func (w *IstioL7Writer) RequiredPermissions() []Permission {
	// list/watch: the policies are watched (Owns) and read through the cache.
	return Permissions("security.istio.io", "authorizationpolicies", "get", "list", "watch", "create", "update", "delete")
}

// Apply creates or updates an AuthorizationPolicy for the given HTTPRoute+gateway+paths combination.
// When paths is non-empty the AP name includes a hash suffix so each rule gets its own AP.
// If ips is empty, any previously created AP for this route+paths is deleted instead.
// If hosts is empty, the AP is deleted as well and a warning is logged: without `to.hosts` (paths
// alone don't scope it) the AP would allow the CIDRs on every host of the gateway, including hosts
// of other routes and namespaces.
func (w *IstioL7Writer) Apply(ctx context.Context, scheme *runtime.Scheme, route *gatewayApiv1.HTTPRoute, gateway *gatewayApiv1.Gateway, ips, hosts, paths []string) error {
	apName, apNamespace, crossNamespace := w.policyName(route, gateway, paths)
	legacyName := w.policyTarget(route.Namespace, route.Name, gateway.Namespace, gateway.Name, paths).legacyName
	if len(ips) == 0 || len(hosts) == 0 {
		if len(hosts) == 0 {
			log.DefaultLogger.WithContext(ctx).Warnf("HTTPRoute %s/%s has no hostnames: no AuthorizationPolicy for gateway %s/%s, it would allow its CIDRs on every host of the gateway",
				route.Namespace, route.Name, gateway.Namespace, gateway.Name)
		}
		for _, name := range []string{apName, legacyName} {
			if name == "" {
				continue
			}
			policy := &istiosecurityv1.AuthorizationPolicy{}
			policy.Name = name
			policy.Namespace = apNamespace
			ours := func(obj client.Object) bool { return w.isOurs(obj, route) }
			if err := deleteIfOurs(ctx, w.client, policy, ours, "AuthorizationPolicy", "HTTPRoute "+route.Namespace+"/"+route.Name+": no CIDRs or no hostnames"); err != nil {
				return err
			}
		}
		return nil
	}

	policy := &istiosecurityv1.AuthorizationPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: apName, Namespace: apNamespace},
	}
	rules := buildAuthorizationRules(ips, hosts, paths)
	op, err := createOrUpdatePolicy(ctx, w.client, policy, func() error {
		// ResourceVersion is set only when the policy exists.
		if policy.ResourceVersion != "" && !w.isOurs(policy, route) {
			return notOurs("AuthorizationPolicy", policy, "HTTPRoute "+route.Namespace+"/"+route.Name)
		}
		if !crossNamespace {
			if err := ctrl.SetControllerReference(route, policy, scheme); err != nil {
				return err
			}
		}
		w.applyLabels(policy, OwnerKindHTTPRoute, route.Namespace, route.Name)
		policy.Spec = istioApiSecurityV1.AuthorizationPolicy{
			Action: istioApiSecurityV1.AuthorizationPolicy_ALLOW,
			Rules:  rules,
			TargetRefs: []*istioApiTypeV1beta1.PolicyTargetReference{
				{Name: gateway.Name, Kind: "Gateway", Group: "gateway.networking.k8s.io"},
			},
		}
		return nil
	})
	if err != nil {
		return err
	}
	logChange(ctx, op, "AuthorizationPolicy", policy, "HTTPRoute "+route.Namespace+"/"+route.Name)
	return w.deleteLegacy(ctx, route, apNamespace, legacyName, apName)
}

// deleteLegacy deletes the policy the route had under its pre-v0.3.0 name, now that the one under
// the new name is written: in this order, so access has no gap. Only ours. Remove with
// policyTarget.legacyName.
func (w *IstioL7Writer) deleteLegacy(ctx context.Context, route *gatewayApiv1.HTTPRoute, namespace, legacyName, newName string) error {
	if legacyName == "" {
		return nil
	}
	policy := &istiosecurityv1.AuthorizationPolicy{}
	policy.Name = legacyName
	policy.Namespace = namespace
	ours := func(obj client.Object) bool { return w.isOurs(obj, route) }
	return deleteIfOurs(ctx, w.client, policy, ours, "AuthorizationPolicy", "HTTPRoute "+route.Namespace+"/"+route.Name+": renamed to "+newName)
}

// isOurs reports whether policy is one this writer created for route (see isOurs).
func (w *IstioL7Writer) isOurs(policy client.Object, route *gatewayApiv1.HTTPRoute) bool {
	return isOurs(policy, w.annotationPrefix, w.managedBy, OwnerKindHTTPRoute, route.Namespace, route.Name, "")
}

// ListManaged returns all AuthorizationPolicies managed by this controller (identified by managedBy label).
func (w *IstioL7Writer) ListManaged(ctx context.Context, managedBy string) ([]client.Object, error) {
	list := &istiosecurityv1.AuthorizationPolicyList{}
	if err := w.client.List(ctx, list, managedByUs(w.annotationPrefix, managedBy)...); err != nil {
		return nil, err
	}
	// The policies of routes and merge groups only: the Gateway policies are the L4 writer's.
	var result []client.Object
	for _, item := range keepKinds(list.Items, w.annotationPrefix, OwnerKindHTTPRoute, OwnerKindMerged) {
		result = append(result, item)
	}
	return result, nil
}

// routeOnTargetGateway reports whether route points to one of the Gateways obj, an
// AuthorizationPolicy, targets (in the policy's namespace).
func routeOnTargetGateway(route *gatewayApiv1.HTTPRoute, obj client.Object) bool {
	policy, ok := obj.(*istiosecurityv1.AuthorizationPolicy)
	if !ok {
		return false
	}
	for _, ref := range policy.Spec.TargetRefs {
		if ref.GetGroup() == gatewayApiv1.GroupName && ref.GetKind() == "Gateway" &&
			gateway.RoutePointsToGateway(route, ref.GetName(), policy.Namespace) {
			return true
		}
	}
	return false
}

// IsOrphaned reports whether the given AP no longer has a valid owner HTTPRoute.
func (w *IstioL7Writer) IsOrphaned(obj client.Object, allRoutes []gatewayApiv1.HTTPRoute) bool {
	ownerNS := obj.GetLabels()[OwnerNamespaceLabel(w.annotationPrefix)]
	ownerName := obj.GetLabels()[OwnerNameLabel(w.annotationPrefix)]
	mergeAnnotation := MergeAnnotation(w.annotationPrefix)

	if ownerNS == MergedOwnerNamespace {
		// Merge-mode AP: kept while a route has this merge key and points to a Gateway the AP
		// targets. The same key can be used on several Gateways, each with its own AP: a route on
		// another Gateway doesn't keep this one, which nothing would rewrite. The label holds
		// LabelSafe of the key, which differs from it for a key longer than 63 characters.
		for i := range allRoutes {
			if key := allRoutes[i].Annotations[mergeAnnotation]; key != "" && LabelSafe(key) == ownerName &&
				routeOnTargetGateway(&allRoutes[i], obj) {
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
		// Route exists. In merge mode the merged policy replaces its own. An invalid merge key is
		// ignored (the route keeps its own policies), so it doesn't count.
		if inMergeMode(r, mergeAnnotation) {
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
	if err := w.client.List(ctx, list, ownedBy(w.annotationPrefix, managedBy, routeNamespace, routeName)...); err != nil {
		return err
	}
	// The route's policies only: a Gateway with the same namespace and name has its own.
	items := keepKinds(list.Items, w.annotationPrefix, OwnerKindHTTPRoute)
	for i := range items {
		if err := deleteLogged(ctx, w.client, items[i], "AuthorizationPolicy", "HTTPRoute "+routeNamespace+"/"+routeName+" no longer uses this writer"); err != nil {
			return err
		}
	}
	return nil
}

// policyTarget is a single (namespace, name) pair identifying an AuthorizationPolicy.
type policyTarget struct {
	namespace string
	name      string
	// legacyName is the name a cross-namespace policy had before v0.3.0. Apply deletes it once
	// the new one is written; until then the orphan checks count it as produced, so the startup
	// cleanup, which runs alongside the first reconciles, doesn't delete it before its replacement
	// exists. Remove once no cluster runs an older version.
	legacyName string
}

// policyTargetsForRoute returns the exact set of AP (namespace, name) pairs that the
// non-merge reconcile path would produce for route — mirrors the Apply call-sites exactly.
// Used by IsOrphaned for exact matching — no prefix heuristics.
func (w *IstioL7Writer) policyTargetsForRoute(route *gatewayApiv1.HTTPRoute) []policyTarget {
	// Apply writes no AP for a route without hostnames, so any left over is orphaned.
	if len(route.Spec.Hostnames) == 0 {
		return nil
	}
	granularity := route.Annotations[GranularityAnnotation(w.annotationPrefix)]

	var targets []policyTarget
	for _, ref := range gateway.GatewayParentRefs(route) {
		gwNS := route.Namespace
		if ref.Namespace != nil {
			gwNS = string(*ref.Namespace)
		}
		target := func(paths []string) policyTarget {
			return w.policyTarget(route.Namespace, route.Name, gwNS, string(ref.Name), paths)
		}

		// granularity=host, or no rules: one AP without paths.
		if granularity == "host" || len(route.Spec.Rules) == 0 {
			targets = append(targets, target(nil))
			continue
		}
		// granularity=rule (default): one AP per rule.
		for _, rule := range route.Spec.Rules {
			targets = append(targets, target(w.TranslatePaths(rule.Matches)))
		}
	}
	return targets
}

// routeProducesPolicy reports whether the non-merge reconcile path for route would generate
// an AuthorizationPolicy at the given {namespace, name}. Uses exact matching only.
func (w *IstioL7Writer) routeProducesPolicy(route *gatewayApiv1.HTTPRoute, policyNamespace, policyName string) bool {
	for _, pt := range w.policyTargetsForRoute(route) {
		if pt.namespace == policyNamespace && (pt.name == policyName || pt.legacyName != "" && pt.legacyName == policyName) {
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
