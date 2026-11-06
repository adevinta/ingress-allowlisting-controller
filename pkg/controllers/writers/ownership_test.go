package writers

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	gatewayApiv1 "sigs.k8s.io/gateway-api/apis/v1"

	istioApiSecurityV1 "istio.io/api/security/v1"
	istiosecurityv1 "istio.io/client-go/pkg/apis/security/v1"

	"github.com/adevinta/ingress-allowlisting-controller/pkg/resolvers"
)

const testManagedBy = "ingress-allowlisting-controller"

func getPolicy(t *testing.T, c client.Client, namespace, name string) *istiosecurityv1.AuthorizationPolicy {
	t.Helper()
	ap := &istiosecurityv1.AuthorizationPolicy{}
	require.NoError(t, c.Get(context.Background(), client.ObjectKey{Namespace: namespace, Name: name}, ap))
	return ap
}

// TestCreatedObjectsCarryOwnerLabels verifies that every kind of object the writers create carries
// the same ownership labels, under the annotation prefix (see ownership.go).
func TestCreatedObjectsCarryOwnerLabels(t *testing.T) {
	ctx := context.Background()
	gw := testGateway("my-gw", "gw-ns")
	route := testRoute("my-route", "gw-ns", "app.example.com")
	cidrs := testCIDRs("allowlist", "gw-ns", "1.2.3.4/32")
	merged := testRoute("svc-a", "gw-ns", "svc-a.example.com")
	merged.Annotations["ipam.adevinta.com/allowlist-group"] = "allowlist"
	c := fake.NewClientBuilder().WithScheme(istioL7Scheme).WithObjects(gw, route, cidrs, merged).Build()

	require.NoError(t, NewIstioL4Writer(c, testManagedBy, resolvers.DefaultPrefix).Apply(ctx, istioL7Scheme, gw, []string{"10.0.0.0/8"}))
	l7 := newIstioL7Writer(c)
	require.NoError(t, l7.Apply(ctx, istioL7Scheme, route, gw, []string{"10.0.0.0/8"}, []string{"app.example.com"}, nil))
	require.NoError(t, l7.ApplyMerged(ctx, gw, []*gatewayApiv1.HTTPRoute{merged}, "shared"))

	want := func(kind, ns, name string) map[string]string {
		return map[string]string{
			"app.kubernetes.io/managed-by":      testManagedBy,
			"ipam.adevinta.com/owner-kind":      kind,
			"ipam.adevinta.com/owner-namespace": ns,
			"ipam.adevinta.com/owner-name":      name,
		}
	}
	assert.Equal(t, want("Gateway", "gw-ns", "my-gw"), getPolicy(t, c, "gw-ns", "my-gw").Labels, "Gateway policy")
	assert.Equal(t, want("HTTPRoute", "gw-ns", "my-route"), getPolicy(t, c, "gw-ns", "my-gw-my-route").Labels, "route policy")
	assert.Equal(t, want("Merged", "MERGED", "shared"), getPolicy(t, c, "gw-ns", MergedPolicyName(resolvers.DefaultPrefix, "my-gw", "shared")).Labels, "merged policy")

	tc := fake.NewClientBuilder().WithScheme(traefikScheme).WithObjects(route.DeepCopy()).Build()
	require.NoError(t, newTraefikWriter(tc).Apply(ctx, traefikScheme, route, gw, []string{"10.0.0.0/8"}, nil, nil))
	mw := &TraefikMiddleware{}
	require.NoError(t, tc.Get(ctx, client.ObjectKey{Namespace: "gw-ns", Name: "my-route"}, mw))
	assert.Equal(t, want("HTTPRoute", "gw-ns", "my-route"), mw.Labels, "Middleware")
}

// TestRouteWriterLeavesGatewayPoliciesAlone verifies that the route writer neither lists nor deletes
// a Gateway's policy, also when a route has the same namespace and name as the Gateway: the
// owner-kind tells them apart.
func TestRouteWriterLeavesGatewayPoliciesAlone(t *testing.T) {
	ctx := context.Background()
	gw := testGateway("web", "gw-ns")
	c := fake.NewClientBuilder().WithScheme(istioL7Scheme).WithObjects(gw).Build()
	require.NoError(t, NewIstioL4Writer(c, testManagedBy, resolvers.DefaultPrefix).Apply(ctx, istioL7Scheme, gw, []string{"10.0.0.0/8"}))
	l7 := newIstioL7Writer(c)

	listed, err := l7.ListManaged(ctx, testManagedBy)
	require.NoError(t, err)
	assert.Empty(t, listed, "a Gateway policy is not a route policy")

	require.NoError(t, l7.DeleteForRoute(ctx, testManagedBy, "gw-ns", "web"))
	getPolicy(t, c, "gw-ns", "web") // still there
}

// TestInstancesWithOtherPrefixesDontSeeEachOther verifies that a second controller instance with
// another annotation prefix never lists, and so never cleans up, our policies. Before, both
// selected by managed-by alone, and at startup each deleted the other's policies as orphans.
func TestInstancesWithOtherPrefixesDontSeeEachOther(t *testing.T) {
	ctx := context.Background()
	gw := testGateway("my-gw", "gw-ns")
	route := testRoute("my-route", "gw-ns", "app.example.com")
	c := fake.NewClientBuilder().WithScheme(istioL7Scheme).WithObjects(gw, route).Build()
	ours := newIstioL7Writer(c)
	require.NoError(t, ours.Apply(ctx, istioL7Scheme, route, gw, []string{"10.0.0.0/8"}, []string{"app.example.com"}, nil))

	other := NewIstioL7Writer(c, testManagedBy, resolvers.CidrResolver{Client: c, AnnotationPrefix: "other.example.com"})
	listed, err := other.ListManaged(ctx, testManagedBy)
	require.NoError(t, err)
	assert.Empty(t, listed, "the other instance doesn't see our policy")

	listed, err = ours.ListManaged(ctx, testManagedBy)
	require.NoError(t, err)
	assert.Len(t, listed, 1, "we still do")
}

// othersLabels are the ownership labels of another instance, with the prefix other.example.com.
func othersLabels(kind, ns, name string) map[string]string {
	return map[string]string{
		"app.kubernetes.io/managed-by":      testManagedBy,
		"other.example.com/owner-kind":      kind,
		"other.example.com/owner-namespace": ns,
		"other.example.com/owner-name":      name,
	}
}

func othersPolicy(ns, name string, labels map[string]string) *istiosecurityv1.AuthorizationPolicy {
	return &istiosecurityv1.AuthorizationPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns, Labels: labels},
		Spec: istioApiSecurityV1.AuthorizationPolicy{Action: istioApiSecurityV1.AuthorizationPolicy_DENY, Rules: []*istioApiSecurityV1.Rule{{
			From: []*istioApiSecurityV1.Rule_From{{Source: &istioApiSecurityV1.Source{RemoteIpBlocks: []string{"192.0.2.1/32"}}}},
		}}},
	}
}

// assertPolicyUntouched verifies that the policy ns/name still has the labels, action and owners of want.
func assertPolicyUntouched(t *testing.T, c client.Client, want *istiosecurityv1.AuthorizationPolicy) {
	t.Helper()
	got := getPolicy(t, c, want.Namespace, want.Name)
	assert.Equal(t, want.Labels, got.Labels, "labels")
	assert.Equal(t, istioApiSecurityV1.AuthorizationPolicy_DENY, got.Spec.Action, "spec")
	assert.Empty(t, got.OwnerReferences, "owner references")
}

// TestWritersLeaveOthersObjectsAlone verifies that a writer neither overwrites nor deletes an
// object with the name it writes that isn't ours: another instance's (other labels), or one
// without any ownership label, e.g. an admin's. It returns ErrPolicyNotManaged instead of writing.
func TestWritersLeaveOthersObjectsAlone(t *testing.T) {
	ctx := context.Background()
	gw := testGateway("my-gw", "gw-ns")
	route := testRoute("my-route", "gw-ns", "app.example.com")
	owners := map[string]func(kind, ns, name string) map[string]string{
		"another instance": othersLabels,
		"no labels":        func(string, string, string) map[string]string { return nil },
	}
	for owner, labels := range owners {
		t.Run(owner, func(t *testing.T) {
			t.Run("Gateway policy", func(t *testing.T) {
				theirs := othersPolicy("gw-ns", "my-gw", labels(OwnerKindGateway, "gw-ns", "my-gw"))
				c := fake.NewClientBuilder().WithScheme(istioL7Scheme).WithObjects(gw.DeepCopy(), theirs.DeepCopy()).Build()
				w := NewIstioL4Writer(c, testManagedBy, resolvers.DefaultPrefix)

				assert.ErrorIs(t, w.Apply(ctx, istioL7Scheme, gw, []string{"10.0.0.0/8"}), ErrPolicyNotManaged)
				assertPolicyUntouched(t, c, theirs)
				require.NoError(t, w.Delete(ctx, gw))
				assertPolicyUntouched(t, c, theirs)
			})

			t.Run("route policy", func(t *testing.T) {
				theirs := othersPolicy("gw-ns", "my-gw-my-route", labels(OwnerKindHTTPRoute, "gw-ns", "my-route"))
				c := fake.NewClientBuilder().WithScheme(istioL7Scheme).WithObjects(gw.DeepCopy(), route.DeepCopy(), theirs.DeepCopy()).Build()
				w := newIstioL7Writer(c)

				err := w.Apply(ctx, istioL7Scheme, route, gw, []string{"10.0.0.0/8"}, []string{"app.example.com"}, nil)
				assert.ErrorIs(t, err, ErrPolicyNotManaged)
				assertPolicyUntouched(t, c, theirs)
				// No CIDRs: the policy with that name would be deleted, if it were ours.
				require.NoError(t, w.Apply(ctx, istioL7Scheme, route, gw, nil, []string{"app.example.com"}, nil))
				assertPolicyUntouched(t, c, theirs)
			})

			t.Run("Middleware", func(t *testing.T) {
				theirs := &TraefikMiddleware{
					ObjectMeta: metav1.ObjectMeta{Name: "my-route", Namespace: "gw-ns", Labels: labels(OwnerKindHTTPRoute, "gw-ns", "my-route")},
					Spec:       TraefikMiddlewareSpec{IPAllowList: &TraefikIPAllowList{SourceRange: []string{"192.0.2.1/32"}}},
				}
				routeWithRule := testTraefikRouteWithRules("my-route", "gw-ns", "/")
				c := fake.NewClientBuilder().WithScheme(traefikScheme).WithObjects(routeWithRule, theirs.DeepCopyObject().(client.Object)).Build()

				err := newTraefikWriter(c).Apply(ctx, traefikScheme, routeWithRule, gw, []string{"10.0.0.0/8"}, nil, nil)
				assert.ErrorIs(t, err, ErrPolicyNotManaged)
				got := &TraefikMiddleware{}
				require.NoError(t, c.Get(ctx, client.ObjectKeyFromObject(theirs), got))
				assert.Equal(t, theirs.Labels, got.Labels)
				assert.Equal(t, []string{"192.0.2.1/32"}, got.Spec.IPAllowList.SourceRange)
				assert.Empty(t, got.OwnerReferences)

				// The route must not use someone else's allowlist.
				gotRoute := &gatewayApiv1.HTTPRoute{}
				require.NoError(t, c.Get(ctx, client.ObjectKeyFromObject(routeWithRule), gotRoute))
				assert.Empty(t, gotRoute.Spec.Rules[0].Filters, "no filter to a Middleware that isn't ours")
			})
		})
	}
}

// TestTraefikKeepsFiltersToOthersMiddlewares verifies that a route without the allowlist
// annotation keeps its filter to a Middleware named like the route that isn't ours, e.g. a team's
// own rate limit: only the filter to our Middleware is removed, or one to a Middleware that is gone.
func TestTraefikKeepsFiltersToOthersMiddlewares(t *testing.T) {
	ctx := context.Background()
	withFilter := func() *gatewayApiv1.HTTPRoute {
		route := testTraefikRouteWithRules("my-route", "gw-ns", "/")
		route.Spec.Rules[0].Filters = []gatewayApiv1.HTTPRouteFilter{traefikFilter("my-route")}
		return route
	}
	filters := func(t *testing.T, c client.Client) []gatewayApiv1.HTTPRouteFilter {
		t.Helper()
		route := &gatewayApiv1.HTTPRoute{}
		require.NoError(t, c.Get(ctx, client.ObjectKey{Namespace: "gw-ns", Name: "my-route"}, route))
		return route.Spec.Rules[0].Filters
	}
	middleware := func(labels map[string]string) *TraefikMiddleware {
		return &TraefikMiddleware{ObjectMeta: metav1.ObjectMeta{Name: "my-route", Namespace: "gw-ns", Labels: labels}}
	}

	for owner, labels := range map[string]map[string]string{
		"another instance": othersLabels(OwnerKindHTTPRoute, "gw-ns", "my-route"),
		"no labels":        nil,
	} {
		t.Run(owner, func(t *testing.T) {
			c := fake.NewClientBuilder().WithScheme(traefikScheme).WithObjects(withFilter(), middleware(labels)).Build()
			require.NoError(t, newTraefikWriter(c).DeleteForRoute(ctx, testManagedBy, "gw-ns", "my-route"))
			assert.Len(t, filters(t, c), 1, "the filter to their Middleware stays")
			require.NoError(t, c.Get(ctx, client.ObjectKey{Namespace: "gw-ns", Name: "my-route"}, &TraefikMiddleware{}), "their Middleware stays")
		})
	}

	t.Run("ours", func(t *testing.T) {
		ours := middleware(nil)
		setOwnerLabels(ours, resolvers.DefaultPrefix, testManagedBy, OwnerKindHTTPRoute, "gw-ns", "my-route")
		c := fake.NewClientBuilder().WithScheme(traefikScheme).WithObjects(withFilter(), ours).Build()
		require.NoError(t, newTraefikWriter(c).DeleteForRoute(ctx, testManagedBy, "gw-ns", "my-route"))
		assert.Empty(t, filters(t, c), "our filter is removed with our Middleware")
	})

	t.Run("gone", func(t *testing.T) {
		c := fake.NewClientBuilder().WithScheme(traefikScheme).WithObjects(withFilter()).Build()
		require.NoError(t, newTraefikWriter(c).DeleteForRoute(ctx, testManagedBy, "gw-ns", "my-route"))
		assert.Empty(t, filters(t, c), "a filter to a Middleware that is gone is removed")
	})
}
