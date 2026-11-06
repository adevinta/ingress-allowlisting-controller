package controllers

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/client-go/util/workqueue"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	gatewayApiv1 "sigs.k8s.io/gateway-api/apis/v1"

	istiosecurityv1 "istio.io/client-go/pkg/apis/security/v1"

	"github.com/adevinta/ingress-allowlisting-controller/pkg/controllers/writers"
)

// enqueued returns the requests the merge sibling watch adds for these events.
func enqueued(r *HTTPRouteAllowlistingReconciler, events ...any) []reconcile.Request {
	ctx := context.Background()
	q := workqueue.NewTypedRateLimitingQueue(workqueue.DefaultTypedControllerRateLimiter[reconcile.Request]())
	defer q.ShutDown()
	h := r.mergeSiblingEnqueuer()
	for _, e := range events {
		switch e := e.(type) {
		case event.UpdateEvent:
			h.Update(ctx, e, q)
		case event.DeleteEvent:
			h.Delete(ctx, e, q)
		}
	}
	var added []reconcile.Request
	for q.Len() > 0 {
		req, _ := q.Get()
		added = append(added, req)
		q.Done(req)
	}
	return added
}

// mergedHosts returns the hosts of the merged policy of group key on gw-ns/my-gw, nil if it is gone.
func mergedHosts(t *testing.T, c client.Client, key string) []string {
	t.Helper()
	policy := &istiosecurityv1.AuthorizationPolicy{}
	err := c.Get(context.Background(), client.ObjectKey{Namespace: "gw-ns", Name: mergedName("my-gw", key)}, policy)
	if apierrors.IsNotFound(err) {
		return nil
	}
	require.NoError(t, err)
	var hosts []string
	for _, rule := range policy.Spec.GetRules() {
		for _, to := range rule.GetTo() {
			hosts = append(hosts, to.GetOperation().GetHosts()...)
		}
	}
	return hosts
}

// TestDeletedMergeMemberLeavesTheGroup verifies that a route deleted from a merge group leaves the
// merged policy: the sibling watch enqueues the other members, which rebuild it without the
// route. When the last member is deleted, the merged policy is deleted. Before, a deleted member's
// host stayed in the merged policy, allowed with the group's CIDRs, until another member changed.
func TestDeletedMergeMemberLeavesTheGroup(t *testing.T) {
	ctx := context.Background()
	a, b := mergeRoute("route-a", "ns", "grp"), mergeRoute("route-b", "ns", "grp")
	other := mergeRoute("route-c", "ns", "other")
	c := fake.NewClientBuilder().WithScheme(extendedScheme).
		WithObjects(allowlist("ns"), a, b, other, newIstioGatewayClass("istio"), newTestGateway("my-gw", "gw-ns", "istio")).Build()
	r := newHTTPRouteReconciler(t, c, extendedScheme)
	reconcileMergeRoute(t, r, "ns", "route-a")
	require.ElementsMatch(t, []string{"route-a.example.com", "route-b.example.com"}, mergedHosts(t, c, "grp"))

	require.NoError(t, c.Delete(ctx, a))
	assert.Equal(t, []reconcile.Request{{NamespacedName: client.ObjectKeyFromObject(b)}}, enqueued(r, event.DeleteEvent{Object: a}),
		"only the other member of the group")
	reconcileMergeRoute(t, r, "ns", "route-a") // gone: its own policies
	reconcileMergeRoute(t, r, "ns", "route-b") // enqueued by the watch
	assert.Equal(t, []string{"route-b.example.com"}, mergedHosts(t, c, "grp"))

	require.NoError(t, c.Delete(ctx, b))
	assert.Empty(t, enqueued(r, event.DeleteEvent{Object: b}), "no member left to enqueue")
	reconcileMergeRoute(t, r, "ns", "route-b")
	assert.Nil(t, mergedHosts(t, c, "grp"), "the last member is gone: deleted")
}

// TestRouteBeingDeleted verifies that a route being deleted (a finalizer holds it) is handled as
// gone: its own policies are deleted and not written again, and it leaves its merge group, whose
// other members rebuild the merged policy without it.
func TestRouteBeingDeleted(t *testing.T) {
	ctx := context.Background()
	const finalizer = "example.com/hold"

	t.Run("own policies", func(t *testing.T) {
		route := mergeRoute("route-a", "ns", "")
		route.Finalizers = []string{finalizer}
		c := fake.NewClientBuilder().WithScheme(extendedScheme).
			WithObjects(allowlist("ns"), route, newIstioGatewayClass("istio"), newTestGateway("my-gw", "gw-ns", "istio")).Build()
		r := newHTTPRouteReconciler(t, c, extendedScheme)
		own := func() int {
			list := &istiosecurityv1.AuthorizationPolicyList{}
			require.NoError(t, c.List(ctx, list, client.MatchingLabels{writers.OwnerNameLabel("ipam.adevinta.com"): "route-a"}))
			return len(list.Items)
		}
		reconcileMergeRoute(t, r, "ns", "route-a")
		require.Equal(t, 1, own(), "precondition: the route's policy")

		require.NoError(t, c.Delete(ctx, route)) // the finalizer keeps it, with a deletionTimestamp
		reconcileMergeRoute(t, r, "ns", "route-a")
		assert.Zero(t, own(), "deleted")
		reconcileMergeRoute(t, r, "ns", "route-a")
		assert.Zero(t, own(), "not written again")
	})

	t.Run("merge group", func(t *testing.T) {
		a, b := mergeRoute("route-a", "ns", "grp"), mergeRoute("route-b", "ns", "grp")
		a.Finalizers = []string{finalizer}
		c := fake.NewClientBuilder().WithScheme(extendedScheme).
			WithObjects(allowlist("ns"), a, b, newIstioGatewayClass("istio"), newTestGateway("my-gw", "gw-ns", "istio")).Build()
		r := newHTTPRouteReconciler(t, c, extendedScheme)
		reconcileMergeRoute(t, r, "ns", "route-a")

		old := &gatewayApiv1.HTTPRoute{}
		require.NoError(t, c.Get(ctx, client.ObjectKeyFromObject(a), old))
		require.NoError(t, c.Delete(ctx, a))
		deleting := &gatewayApiv1.HTTPRoute{}
		require.NoError(t, c.Get(ctx, client.ObjectKeyFromObject(a), deleting))
		require.False(t, deleting.DeletionTimestamp.IsZero(), "precondition: being deleted")

		assert.Equal(t, []reconcile.Request{{NamespacedName: client.ObjectKeyFromObject(b)}}, enqueued(r, event.UpdateEvent{ObjectOld: old, ObjectNew: deleting}))
		reconcileMergeRoute(t, r, "ns", "route-a")
		reconcileMergeRoute(t, r, "ns", "route-b")
		assert.Equal(t, []string{"route-b.example.com"}, mergedHosts(t, c, "grp"), "route-a left the group")
	})
}

// TestGatewayBeingDeleted verifies that a Gateway being deleted gets no policy written: the
// garbage collector removes the one it has, as its owner is the Gateway.
func TestGatewayBeingDeleted(t *testing.T) {
	ctx := context.Background()
	gw := newTestGateway("my-gw", "ns", "istio")
	gw.Annotations = map[string]string{"ipam.adevinta.com/allowlist-group": "allowlist"}
	gw.Finalizers = []string{"example.com/hold"}
	c := fake.NewClientBuilder().WithScheme(extendedScheme).WithObjects(allowlist("ns"), gw, newIstioGatewayClass("istio")).Build()
	r := newGatewayReconciler(t, c, extendedScheme)
	require.NoError(t, c.Delete(ctx, gw))

	_, err := r.Reconcile(ctx, reconcile.Request{NamespacedName: client.ObjectKeyFromObject(gw)})
	require.NoError(t, err)
	err = c.Get(ctx, client.ObjectKey{Namespace: "ns", Name: "my-gw"}, &istiosecurityv1.AuthorizationPolicy{})
	assert.True(t, apierrors.IsNotFound(err), "no policy written for a Gateway being deleted, got %v", err)
}
