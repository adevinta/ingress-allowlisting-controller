// Package gateway provides shared Gateway API helpers used by both the controllers
// and writers packages. It exists as a separate internal package to break the
// import cycle: controllers imports writers, so writers cannot import controllers.
// Any logic that both layers need must live here instead.
package gateway

import gatewayApiv1 "sigs.k8s.io/gateway-api/apis/v1"

// GatewayParentRefs returns only the parentRefs from an HTTPRoute that target a Gateway,
// filtering out any other kinds (e.g. Service). Used in two places:
//   - httproute_controller: to discover which Gateways the route is attached to and
//     drive the reconcile loop (one AP per gateway).
//   - istio_l7 (policyTargetsForRoute): to predict the exact AP names the reconcile loop
//     would produce, so orphan detection can do exact matching without prefix heuristics.
func GatewayParentRefs(httproute *gatewayApiv1.HTTPRoute) []gatewayApiv1.ParentReference {
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
