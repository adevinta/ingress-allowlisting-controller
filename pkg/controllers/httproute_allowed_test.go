package controllers

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	istiosecurityv1 "istio.io/client-go/pkg/apis/security/v1"
	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	gatewayApiv1 "sigs.k8s.io/gateway-api/apis/v1"

	ipamv1alpha1 "github.com/adevinta/ingress-allowlisting-controller/pkg/apis/ipam.adevinta.com/v1alpha1"
)

var sharedAccess = &v1.LabelSelector{MatchLabels: map[string]string{"shared-gateway-access": "true"}}

func testNamespace(name string, labels map[string]string) *corev1.Namespace {
	return &corev1.Namespace{ObjectMeta: v1.ObjectMeta{Name: name, Labels: labels}}
}

// allowlistedRoute returns an HTTPRoute in ns, allowlisted with the CIDRs "localnet" of its
// namespace, attached to the given parentRefs.
func allowlistedRoute(name, ns string, refs ...gatewayApiv1.ParentReference) *gatewayApiv1.HTTPRoute {
	return &gatewayApiv1.HTTPRoute{
		ObjectMeta: v1.ObjectMeta{Name: name, Namespace: ns, Annotations: map[string]string{
			"ipam.adevinta.com/allowlist-group": "localnet",
		}},
		Spec: gatewayApiv1.HTTPRouteSpec{
			CommonRouteSpec: gatewayApiv1.CommonRouteSpec{ParentRefs: refs},
			Hostnames:       []gatewayApiv1.Hostname{gatewayApiv1.Hostname(name + "." + ns + ".example.com")},
		},
	}
}

func localnet(ns string, cidrs ...string) *ipamv1alpha1.CIDRs {
	return &ipamv1alpha1.CIDRs{
		ObjectMeta: v1.ObjectMeta{Name: "localnet", Namespace: ns},
		Status:     ipamv1alpha1.CIDRsStatus{CIDRs: cidrs},
	}
}

func listAPs(t *testing.T, c client.Client, ns string) []*istiosecurityv1.AuthorizationPolicy {
	t.Helper()
	list := &istiosecurityv1.AuthorizationPolicyList{}
	require.NoError(t, c.List(context.Background(), list, client.InNamespace(ns)))
	return list.Items
}

func TestRouteAllowedByParentRef(t *testing.T) {
	tlsListener := gatewayApiv1.Listener{Name: "tls", Protocol: gatewayApiv1.TLSProtocolType, Port: 443}
	httpsDefault := gatewayApiv1.Listener{Name: "https", Protocol: gatewayApiv1.HTTPSProtocolType, Port: 443}
	tcpOnly := httpListener("tcp-kinds", gatewayApiv1.NamespacesFromAll, nil)
	tcpOnly.AllowedRoutes.Kinds = []gatewayApiv1.RouteGroupKind{{Kind: "TCPRoute"}}
	httpKind := httpListener("http-kinds", gatewayApiv1.NamespacesFromAll, nil)
	httpKind.AllowedRoutes.Kinds = []gatewayApiv1.RouteGroupKind{{Kind: "HTTPRoute"}}
	section := func(ref gatewayApiv1.ParentReference, name string) gatewayApiv1.ParentReference {
		s := gatewayApiv1.SectionName(name)
		ref.SectionName = &s
		return ref
	}
	port := func(ref gatewayApiv1.ParentReference, p gatewayApiv1.PortNumber) gatewayApiv1.ParentReference {
		ref.Port = &p
		return ref
	}

	cases := []struct {
		name      string
		routeNS   string
		listeners []gatewayApiv1.Listener
		ref       gatewayApiv1.ParentReference
		want      bool
	}{
		{"Same: route in the gateway namespace", "infra", []gatewayApiv1.Listener{httpListener("http", gatewayApiv1.NamespacesFromSame, nil)}, parentRef("gw", ""), true},
		{"Same: route in another namespace", "team-a", []gatewayApiv1.Listener{httpListener("http", gatewayApiv1.NamespacesFromSame, nil)}, parentRef("gw", "infra"), false},
		{"default is Same", "team-a", []gatewayApiv1.Listener{{Name: "http", Protocol: gatewayApiv1.HTTPProtocolType, Port: 80}}, parentRef("gw", "infra"), false},
		{"All", "team-a", []gatewayApiv1.Listener{httpListener("http", gatewayApiv1.NamespacesFromAll, nil)}, parentRef("gw", "infra"), true},
		{"None, even in the gateway namespace", "infra", []gatewayApiv1.Listener{httpListener("http", gatewayApiv1.NamespacesFromNone, nil)}, parentRef("gw", ""), false},
		{"Selector matches the namespace labels", "team-a", []gatewayApiv1.Listener{httpListener("http", gatewayApiv1.NamespacesFromSelector, sharedAccess)}, parentRef("gw", "infra"), true},
		{"Selector doesn't match", "team-b", []gatewayApiv1.Listener{httpListener("http", gatewayApiv1.NamespacesFromSelector, sharedAccess)}, parentRef("gw", "infra"), false},
		{"Selector without selector accepts nothing", "team-a", []gatewayApiv1.Listener{httpListener("http", gatewayApiv1.NamespacesFromSelector, nil)}, parentRef("gw", "infra"), false},
		{"any listener accepting is enough", "team-a", []gatewayApiv1.Listener{httpListener("same", gatewayApiv1.NamespacesFromSame, nil), httpListener("all", gatewayApiv1.NamespacesFromAll, nil)}, parentRef("gw", "infra"), true},
		{"sectionName limits to that listener", "team-a", []gatewayApiv1.Listener{httpListener("same", gatewayApiv1.NamespacesFromSame, nil), httpListener("all", gatewayApiv1.NamespacesFromAll, nil)}, section(parentRef("gw", "infra"), "same"), false},
		{"sectionName to the accepting listener", "team-a", []gatewayApiv1.Listener{httpListener("same", gatewayApiv1.NamespacesFromSame, nil), httpListener("all", gatewayApiv1.NamespacesFromAll, nil)}, section(parentRef("gw", "infra"), "all"), true},
		{"port matching no listener", "team-a", []gatewayApiv1.Listener{httpListener("http", gatewayApiv1.NamespacesFromAll, nil)}, port(parentRef("gw", "infra"), 8080), false},
		{"port matching the listener", "team-a", []gatewayApiv1.Listener{httpListener("http", gatewayApiv1.NamespacesFromAll, nil)}, port(parentRef("gw", "infra"), 80), true},
		{"TLS listener doesn't take HTTPRoutes", "infra", []gatewayApiv1.Listener{tlsListener}, parentRef("gw", ""), false},
		{"HTTPS listener takes HTTPRoutes by default", "infra", []gatewayApiv1.Listener{httpsDefault}, parentRef("gw", ""), true},
		{"kinds without HTTPRoute", "team-a", []gatewayApiv1.Listener{tcpOnly}, parentRef("gw", "infra"), false},
		{"kinds with HTTPRoute", "team-a", []gatewayApiv1.Listener{httpKind}, parentRef("gw", "infra"), true},
		{"no listeners", "infra", nil, parentRef("gw", ""), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			k8sClient := fake.NewClientBuilder().WithScheme(extendedScheme).WithObjects(
				testNamespace("team-a", map[string]string{"shared-gateway-access": "true"}),
				testNamespace("team-b", nil),
			).Build()
			r := newHTTPRouteReconciler(t, k8sClient, extendedScheme)
			gw := newTestGatewayWithListeners("gw", "infra", "istio", tc.listeners...)
			route := allowlistedRoute("app", tc.routeNS, tc.ref)

			got, err := r.routeAllowedByParentRef(context.Background(), route, tc.ref, gw)
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}

	t.Run("Selector with a namespace that can't be read is an error, not a refusal", func(t *testing.T) {
		r := newHTTPRouteReconciler(t, fake.NewClientBuilder().WithScheme(extendedScheme).Build(), extendedScheme)
		gw := newTestGatewayWithListeners("gw", "infra", "istio", httpListener("http", gatewayApiv1.NamespacesFromSelector, sharedAccess))
		ref := parentRef("gw", "infra")

		_, err := r.routeAllowedByParentRef(context.Background(), allowlistedRoute("app", "missing", ref), ref, gw)
		assert.Error(t, err)
	})
}

// countingReader counts Get calls, to check that namespace labels come from the cache.
type countingReader struct {
	client.Reader
	gets int
}

func (c *countingReader) Get(ctx context.Context, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
	c.gets++
	return c.Reader.Get(ctx, key, obj, opts...)
}

func TestNamespaceLabelCache(t *testing.T) {
	reader := &countingReader{Reader: fake.NewClientBuilder().WithScheme(extendedScheme).WithObjects(
		testNamespace("team-a", map[string]string{"shared-gateway-access": "true"}),
	).Build()}
	cache := newNamespaceLabelCache(reader)
	now := time.Now()
	cache.now = func() time.Time { return now }

	labels, err := cache.get(context.Background(), "team-a")
	require.NoError(t, err)
	assert.Equal(t, "true", labels["shared-gateway-access"])

	now = now.Add(namespaceLabelsTTL - time.Second)
	_, err = cache.get(context.Background(), "team-a")
	require.NoError(t, err)
	assert.Equal(t, 1, reader.gets, "within the TTL the labels come from the cache")

	now = now.Add(2 * time.Second)
	_, err = cache.get(context.Background(), "team-a")
	require.NoError(t, err)
	assert.Equal(t, 2, reader.gets, "after the TTL the namespace is read again")
}

// TestReconcileHTTPRouteNotAllowedByGateway verifies that no AP is written for a route the
// Gateway doesn't accept, and that an AP written while it was accepted is removed.
func TestReconcileHTTPRouteNotAllowedByGateway(t *testing.T) {
	ctx := context.Background()
	route := allowlistedRoute("app", "team-b", parentRef("shared", "infra"))
	gw := newTestGatewayWithListeners("shared", "infra", "istio", httpListener("http", gatewayApiv1.NamespacesFromAll, nil))
	k8sClient := fake.NewClientBuilder().WithScheme(extendedScheme).WithObjects(
		localnet("team-b", "0.0.0.0/0"), route, gw, newIstioGatewayClass("istio"),
	).Build()
	r := newHTTPRouteReconciler(t, k8sClient, extendedScheme)
	req := reconcile.Request{NamespacedName: client.ObjectKeyFromObject(route)}

	_, err := r.Reconcile(ctx, req)
	require.NoError(t, err)
	require.Len(t, listAPs(t, k8sClient, "infra"), 1, "precondition: accepted route gets an AP")

	// The gateway owner restricts the listener to its own namespace.
	require.NoError(t, k8sClient.Get(ctx, client.ObjectKeyFromObject(gw), gw))
	same := gatewayApiv1.NamespacesFromSame
	gw.Spec.Listeners[0].AllowedRoutes.Namespaces.From = &same
	require.NoError(t, k8sClient.Update(ctx, gw))

	_, err = r.Reconcile(ctx, req)
	require.NoError(t, err, "a refused route is not an error (no retry loop)")
	assert.Empty(t, listAPs(t, k8sClient, "infra"), "no AP may be left for a route the gateway doesn't accept")
}

// TestReconcileHTTPRouteSelector verifies the namespace selector: a labelled namespace gets an AP,
// an unlabelled one doesn't.
func TestReconcileHTTPRouteSelector(t *testing.T) {
	ctx := context.Background()
	gw := newTestGatewayWithListeners("shared", "infra", "istio", httpListener("http", gatewayApiv1.NamespacesFromSelector, sharedAccess))
	allowed := allowlistedRoute("app", "team-a", parentRef("shared", "infra"))
	refused := allowlistedRoute("app", "team-b", parentRef("shared", "infra"))
	k8sClient := fake.NewClientBuilder().WithScheme(extendedScheme).WithObjects(
		testNamespace("team-a", map[string]string{"shared-gateway-access": "true"}), testNamespace("team-b", nil),
		localnet("team-a", "10.0.0.0/8"), localnet("team-b", "0.0.0.0/0"),
		allowed, refused, gw, newIstioGatewayClass("istio"),
	).Build()
	r := newHTTPRouteReconciler(t, k8sClient, extendedScheme)

	for _, route := range []*gatewayApiv1.HTTPRoute{allowed, refused} {
		_, err := r.Reconcile(ctx, reconcile.Request{NamespacedName: client.ObjectKeyFromObject(route)})
		require.NoError(t, err)
	}

	aps := listAPs(t, k8sClient, "infra")
	require.Len(t, aps, 1)
	assert.Equal(t, "team-a", aps[0].Labels["ipam.adevinta.com/owner-namespace"])
}

// TestReconcileHTTPRouteRefusedOnOneOfTwoGateways verifies that a route accepted by one Gateway
// and refused by another keeps only the AP of the accepting one.
func TestReconcileHTTPRouteRefusedOnOneOfTwoGateways(t *testing.T) {
	ctx := context.Background()
	open := newTestGatewayWithListeners("open", "infra", "istio", httpListener("http", gatewayApiv1.NamespacesFromAll, nil))
	closing := newTestGatewayWithListeners("closing", "infra", "istio", httpListener("http", gatewayApiv1.NamespacesFromAll, nil))
	route := allowlistedRoute("app", "team-b", parentRef("open", "infra"), parentRef("closing", "infra"))
	k8sClient := fake.NewClientBuilder().WithScheme(extendedScheme).WithObjects(
		localnet("team-b", "10.0.0.0/8"), route, open, closing, newIstioGatewayClass("istio"),
	).Build()
	r := newHTTPRouteReconciler(t, k8sClient, extendedScheme)
	req := reconcile.Request{NamespacedName: client.ObjectKeyFromObject(route)}

	_, err := r.Reconcile(ctx, req)
	require.NoError(t, err)
	require.Len(t, listAPs(t, k8sClient, "infra"), 2, "precondition: one AP per accepting gateway")

	require.NoError(t, k8sClient.Get(ctx, client.ObjectKeyFromObject(closing), closing))
	none := gatewayApiv1.NamespacesFromNone
	closing.Spec.Listeners[0].AllowedRoutes.Namespaces.From = &none
	require.NoError(t, k8sClient.Update(ctx, closing))

	_, err = r.Reconcile(ctx, req)
	require.NoError(t, err)
	aps := listAPs(t, k8sClient, "infra")
	require.Len(t, aps, 1)
	assert.Equal(t, "open", aps[0].Spec.TargetRefs[0].Name)
}

// TestReconcileHTTPRouteMergeLeavesOutRefusedSiblings verifies that a sibling the Gateway doesn't
// accept is left out of the merged AP, and that the merged AP is deleted once no sibling is
// accepted.
func TestReconcileHTTPRouteMergeLeavesOutRefusedSiblings(t *testing.T) {
	ctx := context.Background()
	merged := func(ns string) *gatewayApiv1.HTTPRoute {
		route := allowlistedRoute("app", ns, parentRef("shared", "infra"))
		route.Annotations["ipam.adevinta.com/merge"] = "app"
		return route
	}
	allowed, refused := merged("team-a"), merged("team-b")
	gw := newTestGatewayWithListeners("shared", "infra", "istio", httpListener("http", gatewayApiv1.NamespacesFromSelector, sharedAccess))
	teamA := testNamespace("team-a", map[string]string{"shared-gateway-access": "true"})
	k8sClient := fake.NewClientBuilder().WithScheme(extendedScheme).WithObjects(
		teamA, testNamespace("team-b", nil),
		localnet("team-a", "10.0.0.0/8"), localnet("team-b", "0.0.0.0/0"),
		allowed, refused, gw, newIstioGatewayClass("istio"),
	).Build()
	r := newHTTPRouteReconciler(t, k8sClient, extendedScheme)

	// Reconciling the refused route still rewrites the merged AP, without its rules.
	_, err := r.Reconcile(ctx, reconcile.Request{NamespacedName: client.ObjectKeyFromObject(refused)})
	require.NoError(t, err)
	policy := &istiosecurityv1.AuthorizationPolicy{}
	require.NoError(t, k8sClient.Get(ctx, client.ObjectKey{Name: "app", Namespace: "infra"}, policy))
	var cidrs []string
	for _, rule := range policy.Spec.Rules {
		for _, from := range rule.From {
			cidrs = append(cidrs, from.Source.RemoteIpBlocks...)
		}
	}
	assert.Equal(t, []string{"10.0.0.0/8"}, cidrs, "the refused sibling's CIDRs must not be in the merged AP")

	// team-a loses the label: no sibling is accepted any more. A fresh reconciler, so the label
	// isn't served from the namespace cache.
	require.NoError(t, k8sClient.Get(ctx, client.ObjectKeyFromObject(teamA), teamA))
	teamA.Labels = nil
	require.NoError(t, k8sClient.Update(ctx, teamA))
	r = newHTTPRouteReconciler(t, k8sClient, extendedScheme)

	_, err = r.Reconcile(ctx, reconcile.Request{NamespacedName: client.ObjectKeyFromObject(allowed)})
	require.NoError(t, err)
	assert.Empty(t, listAPs(t, k8sClient, "infra"), "the merged AP must be deleted when no sibling is accepted")
}
