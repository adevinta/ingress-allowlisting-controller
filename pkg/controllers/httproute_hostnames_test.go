package controllers

import (
	"context"
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	istiosecurityv1 "istio.io/client-go/pkg/apis/security/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	gatewayApiv1 "sigs.k8s.io/gateway-api/apis/v1"
)

// TestIntersectHostnames verifies the Gateway API hostname matching (HTTPRouteSpec.Hostnames),
// with the examples of the spec: the more specific hostname of the two, or no match.
func TestIntersectHostnames(t *testing.T) {
	cases := []struct {
		listener, route, want string
		ok                    bool
	}{
		{"test.example.com", "test.example.com", "test.example.com", true},
		{"test.example.com", "*.example.com", "test.example.com", true},
		{"test.example.com", "other.example.com", "", false},
		{"*.example.com", "test.example.com", "test.example.com", true},
		{"*.example.com", "foo.test.example.com", "foo.test.example.com", true},
		{"*.example.com", "*.example.com", "*.example.com", true},
		{"*.example.com", "*.test.example.com", "*.test.example.com", true},
		{"*.test.example.com", "*.example.com", "*.test.example.com", true},
		{"*.example.com", "example.com", "", false},
		{"*.example.com", "test.example.net", "", false},
		{"*.team-a.example.com", "shop.team-b.example.com", "", false},
		{"*.example.com", "badexample.com", "", false},
	}
	for _, tc := range cases {
		got, ok := intersectHostnames(tc.listener, tc.route)
		assert.Equal(t, tc.ok, ok, "%s / %s", tc.listener, tc.route)
		if tc.ok {
			assert.Equal(t, tc.want, got, "%s / %s", tc.listener, tc.route)
		}
	}
}

// tenantListener is an HTTP listener for hostname, accepting routes of namespace ns only.
func tenantListener(name, hostname, ns string) gatewayApiv1.Listener {
	l := httpListener(name, gatewayApiv1.NamespacesFromSelector, &v1.LabelSelector{MatchLabels: map[string]string{"kubernetes.io/metadata.name": ns}})
	h := gatewayApiv1.Hostname(hostname)
	l.Hostname = &h
	return l
}

// policyHosts are the sorted to.hosts of every rule of the AuthorizationPolicies.
func policyHosts(aps []*istiosecurityv1.AuthorizationPolicy) []string {
	var hosts []string
	for _, ap := range aps {
		for _, rule := range ap.Spec.Rules {
			for _, to := range rule.To {
				hosts = append(hosts, to.Operation.Hosts...)
			}
		}
	}
	slices.Sort(hosts)
	return hosts
}

// sharedTenantGateway is the Gateway infra/shared with one listener per tenant, each for its own
// hostnames and namespace.
func sharedTenantGateway() *gatewayApiv1.Gateway {
	return newTestGatewayWithListeners("shared", "infra", "istio",
		tenantListener("team-a", "*.team-a.example.com", "team-a"),
		tenantListener("team-b", "*.team-b.example.com", "team-b"))
}

func reconcileRoute(t *testing.T, objs []client.Object, route *gatewayApiv1.HTTPRoute) client.Client {
	t.Helper()
	objs = append(objs, route,
		testNamespace("team-a", map[string]string{"kubernetes.io/metadata.name": "team-a"}),
		testNamespace("team-b", map[string]string{"kubernetes.io/metadata.name": "team-b"}),
		localnet("team-a", "0.0.0.0/0"), localnet("team-b", "192.0.2.0/24"), newIstioGatewayClass("istio"))
	c := fake.NewClientBuilder().WithScheme(extendedScheme).WithObjects(objs...).Build()
	_, err := newHTTPRouteReconciler(t, c, extendedScheme).Reconcile(context.Background(), reconcile.Request{NamespacedName: client.ObjectKeyFromObject(route)})
	require.NoError(t, err)
	return c
}

// TestRoutePolicyGetsOnlyAttachedHostnames verifies that a route's AuthorizationPolicy gets only
// the hostnames the Gateway routes for it: the ones the listeners that accept it match. Before, it
// got every hostname of the route, so team-a could put team-b's hostname on its route and open it
// with its own CIDRs, on the shared Gateway (Istio ORs ALLOW policies by host).
func TestRoutePolicyGetsOnlyAttachedHostnames(t *testing.T) {
	ref := parentRef("shared", "infra")

	t.Run("a hostname of another tenant's listener is left out", func(t *testing.T) {
		route := allowlistedRoute("app", "team-a", ref)
		route.Spec.Hostnames = append(route.Spec.Hostnames, "shop.team-b.example.com")
		c := reconcileRoute(t, []client.Object{sharedTenantGateway()}, route)
		assert.Equal(t, []string{"app.team-a.example.com"}, policyHosts(listAPs(t, c, "infra")))
	})

	t.Run("only other tenants' hostnames: no policy", func(t *testing.T) {
		route := allowlistedRoute("app", "team-a", ref)
		route.Spec.Hostnames = []gatewayApiv1.Hostname{"shop.team-b.example.com"}
		c := reconcileRoute(t, []client.Object{sharedTenantGateway()}, route)
		assert.Empty(t, listAPs(t, c, "infra"), "not attached: Gateway API routes nothing for it there")
	})

	t.Run("a route wildcard gives the listener's more specific hostname", func(t *testing.T) {
		route := allowlistedRoute("app", "team-a", ref)
		route.Spec.Hostnames = []gatewayApiv1.Hostname{"*.example.com"}
		c := reconcileRoute(t, []client.Object{sharedTenantGateway()}, route)
		assert.Equal(t, []string{"*.team-a.example.com"}, policyHosts(listAPs(t, c, "infra")))
	})

	t.Run("a listener without hostname matches all of them", func(t *testing.T) {
		gw := newTestGatewayWithListeners("shared", "infra", "istio", httpListener("http", gatewayApiv1.NamespacesFromAll, nil))
		route := allowlistedRoute("app", "team-a", ref)
		route.Spec.Hostnames = append(route.Spec.Hostnames, "shop.team-b.example.com")
		c := reconcileRoute(t, []client.Object{gw}, route)
		assert.Equal(t, []string{"app.team-a.example.com", "shop.team-b.example.com"}, policyHosts(listAPs(t, c, "infra")),
			"unchanged on such a listener: Gateway API attaches all of them there")
	})

	t.Run("only the listener the parentRef names", func(t *testing.T) {
		gw := newTestGatewayWithListeners("shared", "infra", "istio",
			tenantListener("a", "a.example.com", "team-a"), tenantListener("b", "b.example.com", "team-a"))
		section := gatewayApiv1.SectionName("a")
		named := ref
		named.SectionName = &section
		route := allowlistedRoute("app", "team-a", named)
		route.Spec.Hostnames = []gatewayApiv1.Hostname{"a.example.com", "b.example.com"}
		c := reconcileRoute(t, []client.Object{gw}, route)
		assert.Equal(t, []string{"a.example.com"}, policyHosts(listAPs(t, c, "infra")))
	})
}

// TestMergedPolicyGetsOnlyAttachedHostnames verifies the same for a merge group: each sibling
// enters the merged AuthorizationPolicy with only the hostnames the Gateway routes for it.
func TestMergedPolicyGetsOnlyAttachedHostnames(t *testing.T) {
	ref := parentRef("shared", "infra")
	member := func(ns string, extra ...gatewayApiv1.Hostname) *gatewayApiv1.HTTPRoute {
		route := allowlistedRoute("app", ns, ref)
		route.Annotations["ipam.adevinta.com/merge"] = "app"
		route.Spec.Hostnames = append(route.Spec.Hostnames, extra...)
		return route
	}
	teamA, teamB := member("team-a", "shop.team-b.example.com"), member("team-b")
	c := reconcileRoute(t, []client.Object{sharedTenantGateway(), teamB}, teamA)

	policy := &istiosecurityv1.AuthorizationPolicy{}
	require.NoError(t, c.Get(context.Background(), client.ObjectKey{Namespace: "infra", Name: mergedName("shared", "app")}, policy))
	assert.Equal(t, []string{"app.team-a.example.com", "app.team-b.example.com"}, policyHosts([]*istiosecurityv1.AuthorizationPolicy{policy}),
		"team-a's claim on shop.team-b.example.com is left out")
}
