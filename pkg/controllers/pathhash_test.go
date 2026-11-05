package controllers

import (
	"context"
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	istiosecurityv1 "istio.io/client-go/pkg/apis/security/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	gatewayApiv1 "sigs.k8s.io/gateway-api/apis/v1"
)

// exactRule is an HTTPRoute rule matching the given Exact paths.
func exactRule(paths ...string) gatewayApiv1.HTTPRouteRule {
	exact := gatewayApiv1.PathMatchExact
	var matches []gatewayApiv1.HTTPRouteMatch
	for _, p := range paths {
		p := p
		matches = append(matches, gatewayApiv1.HTTPRouteMatch{Path: &gatewayApiv1.HTTPPathMatch{Type: &exact, Value: &p}})
	}
	return gatewayApiv1.HTTPRouteRule{Matches: matches}
}

// TestRulesWithJoinedPathsGetTheirOwnPolicies verifies that two rules of a route whose paths,
// joined, are the same ([/api /v1] and [/api/v1]) get one AuthorizationPolicy each. Before, they
// got one name: each reconcile wrote the policy twice, only the last rule's paths were allowed,
// and every write triggered the next reconcile.
func TestRulesWithJoinedPathsGetTheirOwnPolicies(t *testing.T) {
	route := allowlistedRoute("shop", "ns", parentRef("gw", ""))
	route.Spec.Rules = []gatewayApiv1.HTTPRouteRule{exactRule("/api", "/v1"), exactRule("/api/v1")}
	writes := 0
	count := func(obj client.Object) {
		if _, ok := obj.(*istiosecurityv1.AuthorizationPolicy); ok {
			writes++
		}
	}
	c := fake.NewClientBuilder().WithScheme(extendedScheme).
		WithObjects(route, localnet("ns", "192.0.2.0/24"), newIstioGatewayClass("istio"), newTestGateway("gw", "ns", "istio")).
		WithInterceptorFuncs(interceptor.Funcs{
			Create: func(ctx context.Context, cl client.WithWatch, obj client.Object, opts ...client.CreateOption) error {
				count(obj)
				return cl.Create(ctx, obj, opts...)
			},
			Update: func(ctx context.Context, cl client.WithWatch, obj client.Object, opts ...client.UpdateOption) error {
				count(obj)
				return cl.Update(ctx, obj, opts...)
			},
		}).Build()
	r := newHTTPRouteReconciler(t, c, extendedScheme)
	req := reconcile.Request{NamespacedName: client.ObjectKeyFromObject(route)}

	_, err := r.Reconcile(context.Background(), req)
	require.NoError(t, err)
	var paths [][]string
	for _, ap := range listAPs(t, c, "ns") {
		var p []string
		for _, rule := range ap.Spec.Rules {
			for _, to := range rule.To {
				p = append(p, to.Operation.Paths...)
			}
		}
		slices.Sort(p)
		paths = append(paths, p)
	}
	assert.ElementsMatch(t, [][]string{{"/api", "/v1"}, {"/api/v1"}}, paths, "one policy per rule, each with its own paths")

	writes = 0
	_, err = r.Reconcile(context.Background(), req)
	require.NoError(t, err)
	assert.Zero(t, writes, "nothing changed: no write, so no reconcile loop")
}

// TestRenamedRulePolicyIsCleanedUp verifies that the policy of a rule with several paths, written
// under its name from before the \0 separator, is deleted by the route's stale cleanup once the
// policy under the new name exists: no migration code needed.
func TestRenamedRulePolicyIsCleanedUp(t *testing.T) {
	prefix := gatewayApiv1.PathMatchPathPrefix
	path := "/api"
	route := allowlistedRoute("shop", "ns", parentRef("gw", ""))
	route.Spec.Rules = []gatewayApiv1.HTTPRouteRule{{Matches: []gatewayApiv1.HTTPRouteMatch{{Path: &gatewayApiv1.HTTPPathMatch{Type: &prefix, Value: &path}}}}}
	// gw-shop-64eaeb4c: the name of PathPrefix /api (paths /api, /api/*) before the separator.
	old := &istiosecurityv1.AuthorizationPolicy{ObjectMeta: v1.ObjectMeta{Name: "gw-shop-64eaeb4c", Namespace: "ns", Labels: map[string]string{
		"app.kubernetes.io/managed-by":      "ingress-allowlisting-controller",
		"ipam.adevinta.com/owner-kind":      "HTTPRoute",
		"ipam.adevinta.com/owner-namespace": "ns",
		"ipam.adevinta.com/owner-name":      "shop",
	}}}
	c := fake.NewClientBuilder().WithScheme(extendedScheme).
		WithObjects(route, old, localnet("ns", "192.0.2.0/24"), newIstioGatewayClass("istio"), newTestGateway("gw", "ns", "istio")).Build()

	_, err := newHTTPRouteReconciler(t, c, extendedScheme).Reconcile(context.Background(), reconcile.Request{NamespacedName: client.ObjectKeyFromObject(route)})
	require.NoError(t, err)

	err = c.Get(context.Background(), client.ObjectKeyFromObject(old), &istiosecurityv1.AuthorizationPolicy{})
	assert.True(t, apierrors.IsNotFound(err), "the old name is gone, got %v", err)
	aps := listAPs(t, c, "ns")
	require.Len(t, aps, 1)
	assert.Regexp(t, `^gw-shop-[0-9a-f]{8}$`, aps[0].Name)
	assert.NotEqual(t, "gw-shop-64eaeb4c", aps[0].Name)
}
