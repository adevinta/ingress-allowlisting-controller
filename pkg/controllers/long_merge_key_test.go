package controllers

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	gatewayApiv1 "sigs.k8s.io/gateway-api/apis/v1"

	istiosecurityv1 "istio.io/client-go/pkg/apis/security/v1"

	ipamv1alpha1 "github.com/adevinta/ingress-allowlisting-controller/pkg/apis/ipam.adevinta.com/v1alpha1"
	"github.com/adevinta/ingress-allowlisting-controller/pkg/controllers/writers"
)

// longMergeKey is a valid merge key longer than a label value (63): the merged AP's owner-name
// label holds LabelSafe of it, which differs from the key.
var longMergeKey = "shop-" + strings.Repeat("a", 70)

// mergeRoute is a route of namespace ns on Gateway gw-ns/my-gw, in the merge group key ("" for
// none), with the allowlist "allowlist".
func mergeRoute(name, ns, key string) *gatewayApiv1.HTTPRoute {
	gwNS := gatewayApiv1.Namespace("gw-ns")
	annotations := map[string]string{"ipam.adevinta.com/allowlist-group": "allowlist"}
	if key != "" {
		annotations["ipam.adevinta.com/merge"] = key
	}
	return &gatewayApiv1.HTTPRoute{
		ObjectMeta: v1.ObjectMeta{Name: name, Namespace: ns, Annotations: annotations},
		Spec: gatewayApiv1.HTTPRouteSpec{
			CommonRouteSpec: gatewayApiv1.CommonRouteSpec{ParentRefs: []gatewayApiv1.ParentReference{{Name: "my-gw", Namespace: &gwNS}}},
			Hostnames:       []gatewayApiv1.Hostname{gatewayApiv1.Hostname(name + ".example.com")},
		},
	}
}

func allowlist(ns string) *ipamv1alpha1.CIDRs {
	return &ipamv1alpha1.CIDRs{
		ObjectMeta: v1.ObjectMeta{Name: "allowlist", Namespace: ns},
		Status:     ipamv1alpha1.CIDRsStatus{CIDRs: []string{"1.2.3.4/32"}},
	}
}

func reconcileMergeRoute(t *testing.T, r *HTTPRouteAllowlistingReconciler, ns, name string) {
	t.Helper()
	_, err := r.Reconcile(context.Background(), reconcile.Request{NamespacedName: client.ObjectKey{Namespace: ns, Name: name}})
	require.NoError(t, err)
}

// TestLongMergeKeyMergedPolicyIsKept verifies that the merged AP of a group whose key is longer
// than 63 characters counts as in use while a route has the key: the startup cleanup keeps it, and
// a route leaving the group leaves it to the others. Only when the last route leaves is it deleted.
// Before, the raw key was compared with the shortened label, so the group always looked empty.
func TestLongMergeKeyMergedPolicyIsKept(t *testing.T) {
	ctx := context.Background()
	require.NoError(t, writers.ValidateMergeKey(longMergeKey))
	require.NotEqual(t, longMergeKey, writers.LabelSafe(longMergeKey), "precondition: the label is shortened")

	routeA, routeB := mergeRoute("route-a", "ns", longMergeKey), mergeRoute("route-b", "ns", longMergeKey)
	c := fake.NewClientBuilder().WithScheme(extendedScheme).
		WithObjects(allowlist("ns"), routeA, routeB, newIstioGatewayClass("istio"), newTestGateway("my-gw", "gw-ns", "istio")).Build()
	r := newHTTPRouteReconciler(t, c, extendedScheme)
	policyKey := client.ObjectKey{Namespace: "gw-ns", Name: mergedName("my-gw", longMergeKey)}
	exists := func() bool {
		err := c.Get(ctx, policyKey, &istiosecurityv1.AuthorizationPolicy{})
		if apierrors.IsNotFound(err) {
			return false
		}
		require.NoError(t, err)
		return true
	}

	reconcileMergeRoute(t, r, "ns", "route-a")
	require.True(t, exists(), "precondition: the merged AP is written")

	r.runStartupCleanup(ctx)
	assert.True(t, exists(), "startup cleanup: the group still has routes")

	routeA.Annotations["ipam.adevinta.com/merge"] = ""
	require.NoError(t, c.Update(ctx, routeA))
	reconcileMergeRoute(t, r, "ns", "route-a")
	assert.True(t, exists(), "route-b is still in the group")

	routeB.Annotations["ipam.adevinta.com/merge"] = ""
	require.NoError(t, c.Update(ctx, routeB))
	reconcileMergeRoute(t, r, "ns", "route-b")
	assert.False(t, exists(), "the last route left: deleted")
}

// TestMergedCleanupListsRoutesOnce verifies that the reconcile of a route outside any merge group
// lists the routes once from the cache and once from the API, however many merged APs the
// Gateway has, instead of once per merged AP.
func TestMergedCleanupListsRoutesOnce(t *testing.T) {
	ctx := context.Background()
	objs := []client.Object{allowlist("ns"), allowlist("other"), newIstioGatewayClass("istio"), newTestGateway("my-gw", "gw-ns", "istio")}
	keys := []string{"group-a", "group-b", "group-c"}
	for _, key := range keys {
		objs = append(objs, mergeRoute("member-"+key, "ns", key))
	}
	objs = append(objs, mergeRoute("plain", "other", ""))
	base := fake.NewClientBuilder().WithScheme(extendedScheme).WithObjects(objs...).Build()

	var cachedLists, apiLists int
	countRouteLists := func(n *int) interceptor.Funcs {
		return interceptor.Funcs{List: func(ctx context.Context, c client.WithWatch, list client.ObjectList, opts ...client.ListOption) error {
			if _, ok := list.(*gatewayApiv1.HTTPRouteList); ok {
				*n++
			}
			return c.List(ctx, list, opts...)
		}}
	}
	r := newHTTPRouteReconciler(t, interceptor.NewClient(base, countRouteLists(&cachedLists)), extendedScheme)
	r.APIReader = interceptor.NewClient(base, countRouteLists(&apiLists))
	for _, key := range keys {
		reconcileMergeRoute(t, r, "ns", "member-"+key)
		// The members leave without a reconcile: their merged APs look orphaned to the next one.
		route := &gatewayApiv1.HTTPRoute{}
		require.NoError(t, base.Get(ctx, client.ObjectKey{Namespace: "ns", Name: "member-" + key}, route))
		delete(route.Annotations, "ipam.adevinta.com/merge")
		require.NoError(t, base.Update(ctx, route))
	}

	cachedLists, apiLists = 0, 0
	require.NoError(t, r.cleanupOrphanedMergedAPs(ctx, mergeRoute("plain", "other", ""), mergeRoute("plain", "other", "").Spec.ParentRefs))
	assert.Equal(t, 1, cachedLists, "cache lists")
	assert.Equal(t, 1, apiLists, "API lists")
	for _, key := range keys {
		err := base.Get(ctx, client.ObjectKey{Namespace: "gw-ns", Name: mergedName("my-gw", key)}, &istiosecurityv1.AuthorizationPolicy{})
		assert.True(t, apierrors.IsNotFound(err), "%s: orphaned merged AP deleted, got %v", key, err)
	}
}
