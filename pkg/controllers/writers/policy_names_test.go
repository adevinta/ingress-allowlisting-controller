package writers

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	gatewayApiv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/adevinta/ingress-allowlisting-controller/pkg/resolvers"
)

var prefix = resolvers.DefaultPrefix

// TestPolicyNameFormats verifies the three formats: same-namespace route policies unchanged,
// cross-namespace route and merged policies readable and ending with the 8-hex identity hash, also
// without paths.
func TestPolicyNameFormats(t *testing.T) {
	assert.Equal(t, "gw-r", sameNamespacePolicyName("gw", "r", nil), "same-namespace: unchanged")
	assert.Regexp(t, `^gw-r-[0-9a-f]{8}$`, sameNamespacePolicyName("gw", "r", []string{"/api"}))

	assert.Regexp(t, `^team-a\.gw\.r\.[0-9a-f]{8}$`, CrossNamespacePolicyName(prefix, "team-a", "gw", "r", nil))
	assert.Regexp(t, `^team-a\.gw\.r\.[0-9a-f]{8}$`, CrossNamespacePolicyName(prefix, "team-a", "gw", "r", []string{"/api"}))
	assert.Regexp(t, `^merge\.gw\.shop\.[0-9a-f]{8}$`, MergedPolicyName(prefix, "gw", "shop"))
}

// TestPolicyNamesDontCollide verifies the cases the hash tells apart, which joining the parts
// couldn't.
func TestPolicyNamesDontCollide(t *testing.T) {
	cross := func(routeNS, gw, route string, paths ...string) string {
		return CrossNamespacePolicyName(prefix, routeNS, gw, route, paths)
	}
	cases := map[string][2]string{
		// The old names {gw}-{routeNS}-{route}: both gw-team-a-x.
		"namespace and route split differently": {cross("team-a", "gw", "x"), cross("team", "gw", "a-x")},
		// "merge" is a valid namespace: a route there has the shape of a merged policy.
		"route of namespace merge vs merge group": {cross("merge", "gw", "shop"), MergedPolicyName(prefix, "gw", "shop")},
		"dots in Gateway and route names":         {cross("ns", "a.b", "c"), cross("ns", "a", "b.c")},
		// The old path hash had no separator.
		"paths [/a /b] vs [/a/b]": {cross("ns", "gw", "r", "/a", "/b"), cross("ns", "gw", "r", "/a/b")},
		"no paths vs a path":      {cross("ns", "gw", "r"), cross("ns", "gw", "r", "/")},
		// Two instances with different prefixes, same merge key on a shared Gateway.
		"merge key under two prefixes": {MergedPolicyName("a.example.com", "gw", "shop"), MergedPolicyName("b.example.com", "gw", "shop")},
		"route under two prefixes":     {CrossNamespacePolicyName("a.example.com", "ns", "gw", "r", nil), CrossNamespacePolicyName("b.example.com", "ns", "gw", "r", nil)},
		"merge key on two Gateways":    {MergedPolicyName(prefix, "gw-a", "shop"), MergedPolicyName(prefix, "gw-b", "shop")},
	}
	for name, pair := range cases {
		assert.NotEqual(t, pair[0], pair[1], name)
	}
	assert.Equal(t, cross("ns", "gw", "r", "/b", "/a"), cross("ns", "gw", "r", "/a", "/b", "/a"), "path order and duplicates don't matter")
}

// TestPolicyNamesFitAndStayUnique verifies that long names are cut to 253 characters, stay valid
// names and keep the hash whole, so names differing past the cut still differ.
func TestPolicyNamesFitAndStayUnique(t *testing.T) {
	long := strings.Repeat("a", 120)
	a := CrossNamespacePolicyName(prefix, "ns", long, long+"-x", nil)
	b := CrossNamespacePolicyName(prefix, "ns", long, long+"-y", nil)
	for _, name := range []string{a, b, MergedPolicyName(prefix, long, long+"."+long)} {
		assert.LessOrEqual(t, len(name), maxNameLength)
		assert.Regexp(t, `^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$`, name, "a valid name")
		assert.NotContains(t, name, "..")
		assert.Regexp(t, `[a-z0-9]\.[0-9a-f]{8}$`, name, "the hash stays whole after a cut part")
	}
	assert.NotEqual(t, a, b)
}

// TestTwoInstancesShareAMergeKey verifies that two instances with different annotation prefixes,
// using the same merge key on a shared Gateway for different groups, each get their merged policy:
// before the prefix was part of the name, the second was refused as not its own.
func TestTwoInstancesShareAMergeKey(t *testing.T) {
	ctx := context.Background()
	gw := testGateway("shared-gw", "gw-ns")
	routeA := testRoute("svc-a", "ns-a", "svc-a.example.com")
	routeA.Annotations["a.example.com/allowlist-group"] = "allowlist"
	routeB := testRoute("svc-b", "ns-b", "svc-b.example.com")
	routeB.Annotations["b.example.com/allowlist-group"] = "allowlist"
	c := fake.NewClientBuilder().WithScheme(istioL7Scheme).WithObjects(gw, routeA, routeB,
		testCIDRs("allowlist", "ns-a", "1.2.3.4/32"), testCIDRs("allowlist", "ns-b", "5.6.7.8/32")).Build()
	instance := func(p string) *IstioL7Writer {
		return NewIstioL7Writer(c, "ingress-allowlisting-controller", resolvers.CidrResolver{Client: c, AnnotationPrefix: p})
	}

	require.NoError(t, instance("a.example.com").ApplyMerged(ctx, gw, []*gatewayApiv1.HTTPRoute{routeA}, "shop"))
	require.NoError(t, instance("b.example.com").ApplyMerged(ctx, gw, []*gatewayApiv1.HTTPRoute{routeB}, "shop"))
	assert.Equal(t, []string{"svc-a.example.com"}, allPolicyHosts(getPolicy(t, c, "gw-ns", MergedPolicyName("a.example.com", "shared-gw", "shop"))))
	assert.Equal(t, []string{"svc-b.example.com"}, allPolicyHosts(getPolicy(t, c, "gw-ns", MergedPolicyName("b.example.com", "shared-gw", "shop"))))
}

// TestSameNamespacePathHash verifies the path hash of same-namespace names: the paths are joined
// with \0, so [/api /v1] and [/api/v1] no longer share a name, while a single path hashes as
// before (the names of single-path rules don't change).
func TestSameNamespacePathHash(t *testing.T) {
	assert.Equal(t, "gw-shop-0b81c40a", sameNamespacePolicyName("gw", "shop", []string{"/api"}), "Exact /api: unchanged")
	assert.Equal(t, "gw-shop-a5d26b9c", sameNamespacePolicyName("gw", "shop", []string{"/*"}), "PathPrefix /: unchanged")
	assert.Equal(t, "gw-shop", sameNamespacePolicyName("gw", "shop", nil), "no paths: unchanged")
	assert.NotEqual(t, "gw-shop-64eaeb4c", sameNamespacePolicyName("gw", "shop", []string{"/api", "/api/*"}), "several paths: renamed")
	assert.NotEqual(t, sameNamespacePolicyName("gw", "shop", []string{"/api", "/v1"}), sameNamespacePolicyName("gw", "shop", []string{"/api/v1"}))
	assert.Equal(t, sameNamespacePolicyName("gw", "shop", []string{"/v1", "/api"}), sameNamespacePolicyName("gw", "shop", []string{"/api", "/v1", "/api"}), "order and duplicates don't matter")
}
