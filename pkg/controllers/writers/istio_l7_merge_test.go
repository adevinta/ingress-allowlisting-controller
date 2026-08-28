package writers

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	gatewayApiv1 "sigs.k8s.io/gateway-api/apis/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	istioApiSecurityV1 "istio.io/api/security/v1"
	istiosecurityv1 "istio.io/client-go/pkg/apis/security/v1"

	ipamv1alpha1 "github.com/adevinta/ingress-allowlisting-controller/pkg/apis/ipam.adevinta.com/v1alpha1"
	"github.com/adevinta/ingress-allowlisting-controller/pkg/resolvers"
)

// countingGetClient wraps a client.Client and invokes onGet for every Get call,
// letting tests assert how many times specific object types are fetched from the API.
type countingGetClient struct {
	client.Client
	onGet func(obj client.Object)
}

func (c *countingGetClient) Get(ctx context.Context, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
	if c.onGet != nil {
		c.onGet(obj)
	}
	return c.Client.Get(ctx, key, obj, opts...)
}

func testClusterCIDRs(name string, cidrs ...string) *ipamv1alpha1.ClusterCIDRs {
	return &ipamv1alpha1.ClusterCIDRs{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Status:     ipamv1alpha1.CIDRsStatus{CIDRs: cidrs},
	}
}

// allPolicyHosts collects every host across all rules and to-blocks of a policy.
func allPolicyHosts(p *istiosecurityv1.AuthorizationPolicy) []string {
	var hosts []string
	for _, rule := range p.Spec.Rules {
		for _, to := range rule.To {
			if to.Operation != nil {
				hosts = append(hosts, to.Operation.Hosts...)
			}
		}
	}
	return hosts
}

// allPolicyCIDRs collects every CIDR across all rules of a policy.
func allPolicyCIDRs(p *istiosecurityv1.AuthorizationPolicy) []string {
	var cidrs []string
	for _, rule := range p.Spec.Rules {
		for _, from := range rule.From {
			if from.Source != nil {
				cidrs = append(cidrs, from.Source.RemoteIpBlocks...)
			}
		}
	}
	return cidrs
}

// TestApplyMerged_SameCIDRSet verifies that two routes sharing the same CIDR set and no paths
// are compacted into a single Rule with one `to` containing both hosts.
func TestApplyMerged_SameCIDRSet(t *testing.T) {
	cidr0 := testCIDRs("allowlist", "ns-a", "1.2.3.4/32")
	cidr1 := testCIDRs("allowlist", "ns-b", "1.2.3.4/32")
	route0 := testRoute("svc-a", "ns-a", "svc-a.example.com")
	route0.Annotations["ipam.adevinta.com/allowlist-group"] = "allowlist"
	route1 := testRoute("svc-b", "ns-b", "svc-b.example.com")
	route1.Annotations["ipam.adevinta.com/allowlist-group"] = "allowlist"
	gw := testGateway("my-gw", "gw-ns")

	k8sClient := fake.NewClientBuilder().WithScheme(istioL7Scheme).
		WithObjects(cidr0, cidr1, route0, route1, gw).Build()
	w := newIstioL7Writer(k8sClient)

	err := w.ApplyMerged(context.Background(), gw, []*gatewayApiv1.HTTPRoute{route0, route1}, "shared-service")
	require.NoError(t, err)

	policy := &istiosecurityv1.AuthorizationPolicy{}
	err = k8sClient.Get(context.Background(), client.ObjectKey{Name: "shared-service", Namespace: "gw-ns"}, policy)
	require.NoError(t, err)

	assert.Len(t, policy.Spec.Rules, 1, "same CIDR set must produce exactly one Rule")
	assert.Equal(t, []string{"1.2.3.4/32"}, policy.Spec.Rules[0].From[0].Source.RemoteIpBlocks)
	assert.Len(t, policy.Spec.Rules[0].To, 1, "same path set must be compacted into one To operation")
	assert.ElementsMatch(t, []string{"svc-a.example.com", "svc-b.example.com"}, allPolicyHosts(policy))
}

// TestApplyMerged_DifferentCIDRSets verifies that routes with different CIDR sets each
// produce their own Rule — the security boundary between CIDR sets must not be crossed.
func TestApplyMerged_DifferentCIDRSets(t *testing.T) {
	cidr0 := testCIDRs("allowlist", "ns-a", "1.2.3.4/32")
	cidr1 := testCIDRs("allowlist", "ns-b", "5.6.7.8/32")
	route0 := testRoute("svc-a", "ns-a", "svc-a.example.com")
	route0.Annotations["ipam.adevinta.com/allowlist-group"] = "allowlist"
	route1 := testRoute("svc-b", "ns-b", "svc-b.example.com")
	route1.Annotations["ipam.adevinta.com/allowlist-group"] = "allowlist"
	gw := testGateway("my-gw", "gw-ns")

	k8sClient := fake.NewClientBuilder().WithScheme(istioL7Scheme).
		WithObjects(cidr0, cidr1, route0, route1, gw).Build()
	w := newIstioL7Writer(k8sClient)

	err := w.ApplyMerged(context.Background(), gw, []*gatewayApiv1.HTTPRoute{route0, route1}, "multi-service")
	require.NoError(t, err)

	policy := &istiosecurityv1.AuthorizationPolicy{}
	err = k8sClient.Get(context.Background(), client.ObjectKey{Name: "multi-service", Namespace: "gw-ns"}, policy)
	require.NoError(t, err)

	assert.Len(t, policy.Spec.Rules, 2, "distinct CIDR sets must each produce their own Rule")
	assert.ElementsMatch(t, []string{"1.2.3.4/32", "5.6.7.8/32"}, allPolicyCIDRs(policy))
	assert.ElementsMatch(t, []string{"svc-a.example.com", "svc-b.example.com"}, allPolicyHosts(policy))

	for _, rule := range policy.Spec.Rules {
		cidr := rule.From[0].Source.RemoteIpBlocks[0]
		host := rule.To[0].Operation.Hosts[0]
		switch cidr {
		case "1.2.3.4/32":
			assert.Equal(t, "svc-a.example.com", host)
		case "5.6.7.8/32":
			assert.Equal(t, "svc-b.example.com", host)
		default:
			t.Fatalf("unexpected CIDR in rule: %s", cidr)
		}
	}
}

// TestApplyMerged_SameCIDRSameHost collapses paths from multiple rules into one `to`.
func TestApplyMerged_SameCIDRSameHost(t *testing.T) {
	cidr := testCIDRs("allowlist", "ns-a", "1.2.3.4/32")
	pathValue1 := "/api"
	pathValue2 := "/health"
	route := testRoute("svc-a", "ns-a", "svc-a.example.com")
	route.Annotations["ipam.adevinta.com/allowlist-group"] = "allowlist"
	route.Spec.Rules = []gatewayApiv1.HTTPRouteRule{
		{Matches: []gatewayApiv1.HTTPRouteMatch{{Path: &gatewayApiv1.HTTPPathMatch{Value: &pathValue1}}}},
		{Matches: []gatewayApiv1.HTTPRouteMatch{{Path: &gatewayApiv1.HTTPPathMatch{Value: &pathValue2}}}},
	}
	gw := testGateway("my-gw", "gw-ns")

	k8sClient := fake.NewClientBuilder().WithScheme(istioL7Scheme).
		WithObjects(cidr, route, gw).Build()
	w := newIstioL7Writer(k8sClient)

	err := w.ApplyMerged(context.Background(), gw, []*gatewayApiv1.HTTPRoute{route}, "my-service")
	require.NoError(t, err)

	policy := &istiosecurityv1.AuthorizationPolicy{}
	err = k8sClient.Get(context.Background(), client.ObjectKey{Name: "my-service", Namespace: "gw-ns"}, policy)
	require.NoError(t, err)

	assert.Len(t, policy.Spec.Rules, 1)
	assert.Len(t, policy.Spec.Rules[0].To, 1)
	assert.ElementsMatch(t, []string{"/api", "/api/*", "/health", "/health/*"}, policy.Spec.Rules[0].To[0].Operation.Paths)
}

// TestApplyMerged_GranularityHost verifies that granularity=host produces no paths in the merged AP.
func TestApplyMerged_GranularityHost(t *testing.T) {
	cidr := testCIDRs("allowlist", "ns-a", "1.2.3.4/32")
	pathValue := "/api"
	route := testRoute("svc-a", "ns-a", "svc-a.example.com")
	route.Annotations["ipam.adevinta.com/allowlist-group"] = "allowlist"
	route.Annotations["ipam.adevinta.com/granularity"] = "host"
	route.Spec.Rules = []gatewayApiv1.HTTPRouteRule{
		{Matches: []gatewayApiv1.HTTPRouteMatch{{Path: &gatewayApiv1.HTTPPathMatch{Value: &pathValue}}}},
	}
	gw := testGateway("my-gw", "gw-ns")

	k8sClient := fake.NewClientBuilder().WithScheme(istioL7Scheme).
		WithObjects(cidr, route, gw).Build()
	w := newIstioL7Writer(k8sClient)

	err := w.ApplyMerged(context.Background(), gw, []*gatewayApiv1.HTTPRoute{route}, "my-service")
	require.NoError(t, err)

	policy := &istiosecurityv1.AuthorizationPolicy{}
	err = k8sClient.Get(context.Background(), client.ObjectKey{Name: "my-service", Namespace: "gw-ns"}, policy)
	require.NoError(t, err)

	assert.Equal(t, []string{"svc-a.example.com"}, policy.Spec.Rules[0].To[0].Operation.Hosts)
	assert.Nil(t, policy.Spec.Rules[0].To[0].Operation.Paths, "granularity=host must produce no path restriction")
}

// TestApplyMerged_SamePathsDifferentHosts verifies that two routes with the same CIDR set and
// the same path set but different hosts are compacted into a single `to` operation with both hosts.
func TestApplyMerged_SamePathsDifferentHosts(t *testing.T) {
	cidr0 := testCIDRs("allowlist", "ns-a", "1.2.3.4/32")
	cidr1 := testCIDRs("allowlist", "ns-b", "1.2.3.4/32")
	pathValue := "/"
	routeA := testRoute("svc-a", "ns-a", "host-a.example.com")
	routeA.Annotations["ipam.adevinta.com/allowlist-group"] = "allowlist"
	routeA.Spec.Rules = []gatewayApiv1.HTTPRouteRule{
		{Matches: []gatewayApiv1.HTTPRouteMatch{{Path: &gatewayApiv1.HTTPPathMatch{Value: &pathValue}}}},
	}
	routeB := testRoute("svc-b", "ns-b", "host-b.example.com")
	routeB.Annotations["ipam.adevinta.com/allowlist-group"] = "allowlist"
	routeB.Spec.Rules = []gatewayApiv1.HTTPRouteRule{
		{Matches: []gatewayApiv1.HTTPRouteMatch{{Path: &gatewayApiv1.HTTPPathMatch{Value: &pathValue}}}},
	}
	gw := testGateway("my-gw", "gw-ns")

	k8sClient := fake.NewClientBuilder().WithScheme(istioL7Scheme).
		WithObjects(cidr0, cidr1, routeA, routeB, gw).Build()
	w := newIstioL7Writer(k8sClient)

	err := w.ApplyMerged(context.Background(), gw, []*gatewayApiv1.HTTPRoute{routeA, routeB}, "my-service")
	require.NoError(t, err)

	policy := &istiosecurityv1.AuthorizationPolicy{}
	err = k8sClient.Get(context.Background(), client.ObjectKey{Name: "my-service", Namespace: "gw-ns"}, policy)
	require.NoError(t, err)

	require.Len(t, policy.Spec.Rules, 1, "same CIDR set must produce one Rule")
	require.Len(t, policy.Spec.Rules[0].To, 1, "same path set must be compacted into one To operation")
	assert.ElementsMatch(t, []string{"host-a.example.com", "host-b.example.com"}, policy.Spec.Rules[0].To[0].Operation.Hosts)
	assert.Equal(t, []string{"/*"}, policy.Spec.Rules[0].To[0].Operation.Paths)
}

// TestApplyMerged_MixedGranularity verifies that when one route uses granularity=host and another
// uses granularity=rule within the same host group, the merged AP must have no path restriction —
// the host-granularity route wins and overrides any path restriction from the rule-granularity route.
func TestApplyMerged_MixedGranularity(t *testing.T) {
	cidr0 := testCIDRs("allowlist", "ns-a", "1.2.3.4/32")
	cidr1 := testCIDRs("allowlist", "ns-b", "1.2.3.4/32")
	pathValue := "/api"
	routeHost := testRoute("svc-host", "ns-a", "shared.example.com")
	routeHost.Annotations["ipam.adevinta.com/allowlist-group"] = "allowlist"
	routeHost.Annotations["ipam.adevinta.com/granularity"] = "host"
	routeRule := testRoute("svc-rule", "ns-b", "shared.example.com")
	routeRule.Annotations["ipam.adevinta.com/allowlist-group"] = "allowlist"
	routeRule.Spec.Rules = []gatewayApiv1.HTTPRouteRule{
		{Matches: []gatewayApiv1.HTTPRouteMatch{{Path: &gatewayApiv1.HTTPPathMatch{Value: &pathValue}}}},
	}
	gw := testGateway("my-gw", "gw-ns")

	k8sClient := fake.NewClientBuilder().WithScheme(istioL7Scheme).
		WithObjects(cidr0, cidr1, routeHost, routeRule, gw).Build()
	w := newIstioL7Writer(k8sClient)

	err := w.ApplyMerged(context.Background(), gw, []*gatewayApiv1.HTTPRoute{routeHost, routeRule}, "my-service")
	require.NoError(t, err)

	policy := &istiosecurityv1.AuthorizationPolicy{}
	err = k8sClient.Get(context.Background(), client.ObjectKey{Name: "my-service", Namespace: "gw-ns"}, policy)
	require.NoError(t, err)

	require.Len(t, policy.Spec.Rules, 1)
	require.Len(t, policy.Spec.Rules[0].To, 1)
	assert.Equal(t, []string{"shared.example.com"}, policy.Spec.Rules[0].To[0].Operation.Hosts)
	assert.Nil(t, policy.Spec.Rules[0].To[0].Operation.Paths, "host-granularity route must suppress path restriction for the entire host group")
}

// TestApplyMerged_EmptySkipped verifies that routes without a CIDR annotation are skipped.
func TestApplyMerged_EmptySkipped(t *testing.T) {
	route := testRoute("no-cidr", "ns-a", "no-cidr.example.com")
	gw := testGateway("my-gw", "gw-ns")

	k8sClient := fake.NewClientBuilder().WithScheme(istioL7Scheme).
		WithObjects(route, gw).Build()
	w := newIstioL7Writer(k8sClient)

	err := w.ApplyMerged(context.Background(), gw, []*gatewayApiv1.HTTPRoute{route}, "my-service")
	require.NoError(t, err)

	policy := &istiosecurityv1.AuthorizationPolicy{}
	err = k8sClient.Get(context.Background(), client.ObjectKey{Name: "my-service", Namespace: "gw-ns"}, policy)
	assert.True(t, client.IgnoreNotFound(err) == nil && err != nil, "no policy should be created when no CIDRs are available")
}

// TestApplyMerged_DeduplicatesPaths verifies that duplicate paths within the same host group are collapsed.
func TestApplyMerged_DeduplicatesPaths(t *testing.T) {
	cidr0 := testCIDRs("allowlist", "ns-a", "1.2.3.4/32")
	cidr1 := testCIDRs("allowlist", "ns-b", "1.2.3.4/32")
	pathValue := "/api"
	makeRoute := func(name, ns string) *gatewayApiv1.HTTPRoute {
		r := testRoute(name, ns, "shared.example.com")
		r.Annotations["ipam.adevinta.com/allowlist-group"] = "allowlist"
		r.Spec.Rules = []gatewayApiv1.HTTPRouteRule{
			{Matches: []gatewayApiv1.HTTPRouteMatch{{Path: &gatewayApiv1.HTTPPathMatch{Value: &pathValue}}}},
		}
		return r
	}
	gw := testGateway("my-gw", "gw-ns")

	k8sClient := fake.NewClientBuilder().WithScheme(istioL7Scheme).
		WithObjects(cidr0, cidr1, makeRoute("svc-a", "ns-a"), makeRoute("svc-b", "ns-b"), gw).Build()
	w := newIstioL7Writer(k8sClient)

	err := w.ApplyMerged(context.Background(), gw, []*gatewayApiv1.HTTPRoute{makeRoute("svc-a", "ns-a"), makeRoute("svc-b", "ns-b")}, "my-service")
	require.NoError(t, err)

	policy := &istiosecurityv1.AuthorizationPolicy{}
	err = k8sClient.Get(context.Background(), client.ObjectKey{Name: "my-service", Namespace: "gw-ns"}, policy)
	require.NoError(t, err)

	assert.Len(t, policy.Spec.Rules, 1)
	assert.Len(t, policy.Spec.Rules[0].To, 1)
	assert.ElementsMatch(t, []string{"/api", "/api/*"}, policy.Spec.Rules[0].To[0].Operation.Paths, "duplicate paths must appear only once after expansion")
}

// TestMergeTosByPaths_PathOrderIndependent verifies that two `to` operations with the same paths
// in different order are compacted into one. Without sorting the path key, they would produce
// different keys and survive as separate redundant `to` blocks — causing spurious AP updates.
func TestMergeTosByPaths_PathOrderIndependent(t *testing.T) {
	istioOp := func(hosts, paths []string) *istioApiSecurityV1.Rule_To {
		return &istioApiSecurityV1.Rule_To{
			Operation: &istioApiSecurityV1.Operation{Hosts: hosts, Paths: paths},
		}
	}

	// Same paths, different order — must compact to one To block.
	result := mergeTosByPaths([]*istioApiSecurityV1.Rule_To{
		istioOp([]string{"host-a.example.com"}, []string{"/health", "/api"}),
		istioOp([]string{"host-b.example.com"}, []string{"/api", "/health"}),
	})
	require.Len(t, result, 1, "same paths in different order must compact into one To operation")
	assert.ElementsMatch(t, []string{"host-a.example.com", "host-b.example.com"}, result[0].Operation.Hosts)
	assert.ElementsMatch(t, []string{"/api", "/health"}, result[0].Operation.Paths)
}

// TestApplyMerged_MixedLocalAndClusterCIDRs verifies that two routes in different namespaces,
// each carrying both a cluster annotation (shared) and a local annotation (namespace-specific),
// produce two separate Istio Rules — one per unique resolved CIDR set.
//
// The resolved CIDR set for each route is the union of its local CIDRs and the shared cluster CIDRs.
// Because the local CIDRs differ across namespaces, the two union sets are distinct, and the
// security model requires separate Rules.
func TestApplyMerged_MixedLocalAndClusterCIDRs(t *testing.T) {
	clusterCIDR := testClusterCIDRs("global-net", "10.0.0.0/8")
	localOne := testCIDRs("one", "ns-one", "192.168.1.0/24")
	localTwo := testCIDRs("two", "ns-two", "192.168.2.0/24")

	routeOne := testRoute("svc-one", "ns-one", "svc-one.example.com")
	routeOne.Annotations["ipam.adevinta.com/allowlist-group"] = "one"
	routeOne.Annotations["ipam.adevinta.com/cluster-allowlist-group"] = "global-net"

	routeTwo := testRoute("svc-two", "ns-two", "svc-two.example.com")
	routeTwo.Annotations["ipam.adevinta.com/allowlist-group"] = "two"
	routeTwo.Annotations["ipam.adevinta.com/cluster-allowlist-group"] = "global-net"

	gw := testGateway("my-gw", "gw-ns")

	k8sClient := fake.NewClientBuilder().WithScheme(istioL7Scheme).
		WithObjects(clusterCIDR, localOne, localTwo, routeOne, routeTwo, gw).Build()
	w := newIstioL7Writer(k8sClient)

	err := w.ApplyMerged(context.Background(), gw, []*gatewayApiv1.HTTPRoute{routeOne, routeTwo}, "shared-service")
	require.NoError(t, err)

	policy := &istiosecurityv1.AuthorizationPolicy{}
	err = k8sClient.Get(context.Background(), client.ObjectKey{Name: "shared-service", Namespace: "gw-ns"}, policy)
	require.NoError(t, err)

	// Each route resolves to a different CIDR set: cluster + namespace-local.
	// Different CIDR sets must NOT share a `from` block → two Rules.
	require.Len(t, policy.Spec.Rules, 2,
		"routes with different local CIDRs must produce separate Rules even if they share a cluster annotation")

	// Build a map from host → CIDRs for deterministic assertions.
	hostToCIDRs := map[string][]string{}
	for _, rule := range policy.Spec.Rules {
		cidrs := rule.From[0].Source.RemoteIpBlocks
		for _, to := range rule.To {
			for _, h := range to.Operation.Hosts {
				hostToCIDRs[h] = cidrs
			}
		}
	}

	assert.ElementsMatch(t, []string{"10.0.0.0/8", "192.168.1.0/24"}, hostToCIDRs["svc-one.example.com"],
		"svc-one must be allowed from global-net + its own local CIDR")
	assert.ElementsMatch(t, []string{"10.0.0.0/8", "192.168.2.0/24"}, hostToCIDRs["svc-two.example.com"],
		"svc-two must be allowed from global-net + its own local CIDR")
}

// TestApplyMerged_CacheDeduplicatesResolutionsAcrossNamespaces verifies that ApplyMerged
// resolves CIDRs exactly once when all siblings share the same cluster annotation value,
// even when they are spread across different namespaces.
//
// Without the within-call cache (with namespace-ignoring key for cluster-only annotations),
// each sibling triggers an independent GetCidrsFromObject call — one Get per sibling.
// With the cache: the first sibling populates it; the rest are cache hits — one Get total.
func TestApplyMerged_CacheDeduplicatesResolutionsAcrossNamespaces(t *testing.T) {
	const siblingCount = 5
	sharedCIDR := testClusterCIDRs("shared-vpn", "10.0.0.0/8")
	gw := testGateway("my-gw", "gw-ns")

	var siblings []*gatewayApiv1.HTTPRoute
	objs := []client.Object{sharedCIDR, gw}
	for i := 0; i < siblingCount; i++ {
		r := testRoute(
			fmt.Sprintf("svc.ns-%d.example.com", i),
			fmt.Sprintf("ns-%d", i),
			fmt.Sprintf("svc.ns-%d.example.com", i),
		)
		r.Annotations["ipam.adevinta.com/cluster-allowlist-group"] = "shared-vpn"
		siblings = append(siblings, r)
		objs = append(objs, r)
	}

	var clusterCIDRGetCount int
	baseClient := fake.NewClientBuilder().WithScheme(istioL7Scheme).WithObjects(objs...).Build()
	counting := &countingGetClient{
		Client: baseClient,
		onGet: func(obj client.Object) {
			if _, ok := obj.(*ipamv1alpha1.ClusterCIDRs); ok {
				clusterCIDRGetCount++
			}
		},
	}
	resolver := resolvers.CidrResolver{Client: counting, AnnotationPrefix: resolvers.DefaultPrefix}
	w := NewIstioL7Writer(counting, "ingress-allowlisting-controller", resolver)

	err := w.ApplyMerged(context.Background(), gw, siblings, "my-service")
	require.NoError(t, err)

	// With the cache: 1 Get — all siblings share the same cluster annotation, namespace
	// is excluded from the cache key for cluster-only annotations.
	// Without the cache fix: 5 Gets — one per sibling due to per-namespace cache keys.
	assert.Equal(t, 1, clusterCIDRGetCount,
		"ClusterCIDRs must be fetched once across %d siblings with identical cluster annotations", siblingCount)
}
