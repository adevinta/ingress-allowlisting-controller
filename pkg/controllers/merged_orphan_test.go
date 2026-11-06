package controllers

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	gatewayApiv1 "sigs.k8s.io/gateway-api/apis/v1"

	istiosecurityv1 "istio.io/client-go/pkg/apis/security/v1"
)

// TestStartupCleanupMergedPolicyOfAnotherGateway verifies that the startup cleanup deletes the
// merged AP of a Gateway whose routes of the group are gone, even when the same merge key is still
// used on another Gateway: that route keeps only its own Gateway's AP. Before, any route with the
// key kept the AP, and nothing rewrote it, so it kept allowing the group's old CIDRs.
func TestStartupCleanupMergedPolicyOfAnotherGateway(t *testing.T) {
	ctx := context.Background()
	onGateway := func(name, gw string) *gatewayApiv1.HTTPRoute {
		route := mergeRoute(name, "ns", "shared")
		route.Spec.ParentRefs[0].Name = gatewayApiv1.ObjectName(gw)
		return route
	}
	route1, route2 := onGateway("route-1", "gw-1"), onGateway("route-2", "gw-2")
	c := fake.NewClientBuilder().WithScheme(extendedScheme).WithObjects(allowlist("ns"), route1, route2,
		newIstioGatewayClass("istio"), newTestGateway("gw-1", "gw-ns", "istio"), newTestGateway("gw-2", "gw-ns", "istio")).Build()
	r := newHTTPRouteReconciler(t, c, extendedScheme)
	exists := func(gw string) bool {
		err := c.Get(ctx, client.ObjectKey{Namespace: "gw-ns", Name: mergedName(gw, "shared")}, &istiosecurityv1.AuthorizationPolicy{})
		if apierrors.IsNotFound(err) {
			return false
		}
		require.NoError(t, err)
		return true
	}

	reconcileMergeRoute(t, r, "ns", "route-1")
	reconcileMergeRoute(t, r, "ns", "route-2")
	require.True(t, exists("gw-1") && exists("gw-2"), "precondition: one merged AP per Gateway")

	r.runStartupCleanup(ctx)
	assert.True(t, exists("gw-1") && exists("gw-2"), "both groups still have routes")

	// gw-1's only route is deleted while the controller is down: no reconcile sees it.
	require.NoError(t, c.Delete(ctx, route1))
	r.runStartupCleanup(ctx)
	assert.False(t, exists("gw-1"), "gw-1 has no route of the group left")
	assert.True(t, exists("gw-2"), "route-2 keeps gw-2's")
}
