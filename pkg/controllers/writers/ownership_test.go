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
	assert.Equal(t, want("Merged", "MERGED", "shared"), getPolicy(t, c, "gw-ns", "shared").Labels, "merged policy")

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

// TestPoliciesWithoutOwnerKindStillCount verifies the transition: policies written before the
// owner-kind label still count as ours, a route's or a merge group's, until their next write adds it.
func TestPoliciesWithoutOwnerKindStillCount(t *testing.T) {
	ctx := context.Background()
	old := func(name, ownerNS, ownerName string) *istiosecurityv1.AuthorizationPolicy {
		return &istiosecurityv1.AuthorizationPolicy{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "gw-ns", Labels: map[string]string{
			"app.kubernetes.io/managed-by":      testManagedBy,
			"ipam.adevinta.com/owner-namespace": ownerNS,
			"ipam.adevinta.com/owner-name":      ownerName,
		}}}
	}
	routePolicy, mergedPolicy := old("my-gw-my-route", "gw-ns", "my-route"), old("shared", "MERGED", "shared")
	c := fake.NewClientBuilder().WithScheme(istioL7Scheme).WithObjects(routePolicy, mergedPolicy).Build()
	l7 := newIstioL7Writer(c)

	assert.Equal(t, OwnerKindHTTPRoute, ownerKind(routePolicy, resolvers.DefaultPrefix))
	assert.Equal(t, OwnerKindMerged, ownerKind(mergedPolicy, resolvers.DefaultPrefix))
	assert.True(t, l7.isMergedPolicy(mergedPolicy, "shared"))

	listed, err := l7.ListManaged(ctx, testManagedBy)
	require.NoError(t, err)
	assert.Len(t, listed, 2)

	require.NoError(t, l7.DeleteForRoute(ctx, testManagedBy, "gw-ns", "my-route"))
	err = c.Get(ctx, client.ObjectKeyFromObject(routePolicy), &istiosecurityv1.AuthorizationPolicy{})
	assert.True(t, client.IgnoreNotFound(err) == nil && err != nil, "the old route policy is still found and deleted")
}
