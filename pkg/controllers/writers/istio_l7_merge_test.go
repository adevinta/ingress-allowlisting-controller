package writers

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	gatewayApiv1 "sigs.k8s.io/gateway-api/apis/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	istiosecurityv1 "istio.io/client-go/pkg/apis/security/v1"
)

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
