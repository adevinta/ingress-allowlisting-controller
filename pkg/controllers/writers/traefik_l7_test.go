package writers

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	gatewayApiv1 "sigs.k8s.io/gateway-api/apis/v1"

	ipamv1alpha1 "github.com/adevinta/ingress-allowlisting-controller/pkg/apis/ipam.adevinta.com/v1alpha1"
	"github.com/adevinta/ingress-allowlisting-controller/pkg/resolvers"
)

var traefikScheme = func() *runtime.Scheme {
	s := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(s)
	_ = gatewayApiv1.Install(s)
	_ = AddTraefikToScheme(s)
	_ = ipamv1alpha1.AddToScheme(s)
	return s
}()

func newTraefikWriter(c client.Client) *TraefikL7Writer {
	resolver := resolvers.CidrResolver{Client: c, AnnotationPrefix: resolvers.DefaultPrefix}
	return NewTraefikL7Writer(c, "ingress-allowlisting-controller", resolver)
}

func testTraefikGateway(name, namespace string) *gatewayApiv1.Gateway {
	return &gatewayApiv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
		Spec:       gatewayApiv1.GatewaySpec{GatewayClassName: "traefik"},
	}
}

func testTraefikRoute(name, namespace string) *gatewayApiv1.HTTPRoute {
	return &gatewayApiv1.HTTPRoute{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
	}
}

func testTraefikRouteWithRules(name, namespace string, paths ...string) *gatewayApiv1.HTTPRoute {
	rules := make([]gatewayApiv1.HTTPRouteRule, len(paths))
	for i, p := range paths {
		pathType := gatewayApiv1.PathMatchPathPrefix
		rules[i] = gatewayApiv1.HTTPRouteRule{
			Matches: []gatewayApiv1.HTTPRouteMatch{
				{Path: &gatewayApiv1.HTTPPathMatch{Type: &pathType, Value: &p}},
			},
		}
	}
	return &gatewayApiv1.HTTPRoute{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
		Spec:       gatewayApiv1.HTTPRouteSpec{Rules: rules},
	}
}

// TestTraefikL7Writer_Apply_SameNamespace verifies a Middleware is created in the route's namespace.
func TestTraefikL7Writer_Apply_SameNamespace(t *testing.T) {
	route := testTraefikRoute("my-route", "mynamespace")
	gw := testTraefikGateway("my-gateway", "mynamespace")
	k8sClient := fake.NewClientBuilder().WithScheme(traefikScheme).WithObjects(route).Build()
	w := newTraefikWriter(k8sClient)

	err := w.Apply(context.Background(), traefikScheme, route, gw, []string{"10.0.0.0/8"}, nil, nil)
	assert.NoError(t, err)

	mw := &TraefikMiddleware{}
	err = k8sClient.Get(context.Background(), client.ObjectKey{Name: "my-route", Namespace: "mynamespace"}, mw)
	assert.NoError(t, err)
	assert.Equal(t, []string{"10.0.0.0/8"}, mw.Spec.IPAllowList.SourceRange)
	assert.Equal(t, "ingress-allowlisting-controller", mw.Labels["app.kubernetes.io/managed-by"])
	assert.Equal(t, "mynamespace", mw.Labels["ipam.adevinta.com/owner-namespace"])
	assert.Equal(t, "my-route", mw.Labels["ipam.adevinta.com/owner-name"])
}

// TestTraefikL7Writer_Apply_CrossNamespace verifies a Middleware is always placed in the route's
// own namespace regardless of gateway namespace, so the HTTPRoute extensionRef can reach it.
func TestTraefikL7Writer_Apply_CrossNamespace(t *testing.T) {
	route := testTraefikRoute("my-route", "app-ns")
	gw := testTraefikGateway("my-gateway", "gw-ns")
	k8sClient := fake.NewClientBuilder().WithScheme(traefikScheme).WithObjects(route).Build()
	w := newTraefikWriter(k8sClient)

	err := w.Apply(context.Background(), traefikScheme, route, gw, []string{"10.0.0.0/8"}, nil, nil)
	assert.NoError(t, err)

	// Middleware must be in route namespace (app-ns), not gateway namespace (gw-ns).
	mw := &TraefikMiddleware{}
	err = k8sClient.Get(context.Background(), client.ObjectKey{Name: "my-route", Namespace: "app-ns"}, mw)
	assert.NoError(t, err)
	assert.Equal(t, []string{"10.0.0.0/8"}, mw.Spec.IPAllowList.SourceRange)
}

// TestTraefikL7Writer_Apply_PathsIgnored verifies that paths have no effect on the Middleware name or spec.
func TestTraefikL7Writer_Apply_PathsIgnored(t *testing.T) {
	route := testTraefikRoute("my-route", "mynamespace")
	gw := testTraefikGateway("my-gateway", "mynamespace")
	k8sClient := fake.NewClientBuilder().WithScheme(traefikScheme).WithObjects(route).Build()
	w := newTraefikWriter(k8sClient)

	err := w.Apply(context.Background(), traefikScheme, route, gw, []string{"10.0.0.0/8"}, nil, []string{"/admin/*"})
	assert.NoError(t, err)

	// Name is still just route name — no path suffix for Traefik
	mw := &TraefikMiddleware{}
	err = k8sClient.Get(context.Background(), client.ObjectKey{Name: "my-route", Namespace: "mynamespace"}, mw)
	assert.NoError(t, err)
	assert.Equal(t, []string{"10.0.0.0/8"}, mw.Spec.IPAllowList.SourceRange)
}

// TestTraefikL7Writer_Apply_OwnerRef verifies owner reference is always set (same or cross namespace).
func TestTraefikL7Writer_Apply_OwnerRef(t *testing.T) {
	for _, tc := range []struct {
		name      string
		routeNS   string
		gatewayNS string
	}{
		{"same-namespace", "mynamespace", "mynamespace"},
		{"cross-namespace", "app-ns", "gw-ns"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			route := testTraefikRoute("my-route", tc.routeNS)
			gw := testTraefikGateway("my-gateway", tc.gatewayNS)
			k8sClient := fake.NewClientBuilder().WithScheme(traefikScheme).WithObjects(route).Build()
			w := newTraefikWriter(k8sClient)

			err := w.Apply(context.Background(), traefikScheme, route, gw, []string{"10.0.0.0/8"}, nil, nil)
			assert.NoError(t, err)

			mw := &TraefikMiddleware{}
			err = k8sClient.Get(context.Background(), client.ObjectKey{Name: "my-route", Namespace: tc.routeNS}, mw)
			assert.NoError(t, err)
			assert.Len(t, mw.OwnerReferences, 1)
			assert.Equal(t, "my-route", mw.OwnerReferences[0].Name)
		})
	}
}

// TestTraefikL7Writer_Apply_InjectsFilters verifies that Apply patches every HTTPRoute rule
// with an extensionRef filter pointing to the Middleware.
func TestTraefikL7Writer_Apply_InjectsFilters(t *testing.T) {
	route := testTraefikRouteWithRules("my-route", "mynamespace", "/api", "/health")
	gw := testTraefikGateway("my-gateway", "mynamespace")
	k8sClient := fake.NewClientBuilder().WithScheme(traefikScheme).WithObjects(route).Build()
	w := newTraefikWriter(k8sClient)

	err := w.Apply(context.Background(), traefikScheme, route, gw, []string{"10.0.0.0/8"}, nil, nil)
	assert.NoError(t, err)

	updated := &gatewayApiv1.HTTPRoute{}
	err = k8sClient.Get(context.Background(), client.ObjectKey{Name: "my-route", Namespace: "mynamespace"}, updated)
	assert.NoError(t, err)
	assert.Len(t, updated.Spec.Rules, 2, "rule count must be preserved")
	for i, rule := range updated.Spec.Rules {
		assert.True(t, hasTraefikFilter(rule.Filters, "my-route"),
			"rule %d must have extensionRef filter", i)
	}
}

// TestTraefikL7Writer_Apply_InjectsFilters_Idempotent verifies a second Apply does not duplicate filters.
func TestTraefikL7Writer_Apply_InjectsFilters_Idempotent(t *testing.T) {
	route := testTraefikRouteWithRules("my-route", "mynamespace", "/api")
	gw := testTraefikGateway("my-gateway", "mynamespace")
	k8sClient := fake.NewClientBuilder().WithScheme(traefikScheme).WithObjects(route).Build()
	w := newTraefikWriter(k8sClient)

	assert.NoError(t, w.Apply(context.Background(), traefikScheme, route, gw, []string{"10.0.0.0/8"}, nil, nil))
	assert.NoError(t, w.Apply(context.Background(), traefikScheme, route, gw, []string{"10.0.0.0/8"}, nil, nil))

	updated := &gatewayApiv1.HTTPRoute{}
	err := k8sClient.Get(context.Background(), client.ObjectKey{Name: "my-route", Namespace: "mynamespace"}, updated)
	assert.NoError(t, err)

	count := 0
	for _, f := range updated.Spec.Rules[0].Filters {
		if f.Type == gatewayApiv1.HTTPRouteFilterExtensionRef {
			count++
		}
	}
	assert.Equal(t, 1, count, "extensionRef filter must not be duplicated")
}

// TestTraefikL7Writer_DeleteForRoute_RemovesFilters verifies that DeleteForRoute also removes
// the extensionRef filter from the HTTPRoute's rules.
func TestTraefikL7Writer_DeleteForRoute_RemovesFilters(t *testing.T) {
	route := testTraefikRouteWithRules("my-route", "mynamespace", "/api")
	gw := testTraefikGateway("my-gateway", "mynamespace")
	k8sClient := fake.NewClientBuilder().WithScheme(traefikScheme).WithObjects(route).Build()
	w := newTraefikWriter(k8sClient)

	// First apply so the filter and Middleware exist.
	assert.NoError(t, w.Apply(context.Background(), traefikScheme, route, gw, []string{"10.0.0.0/8"}, nil, nil))

	// Confirm filter was added.
	before := &gatewayApiv1.HTTPRoute{}
	assert.NoError(t, k8sClient.Get(context.Background(), client.ObjectKey{Name: "my-route", Namespace: "mynamespace"}, before))
	assert.True(t, hasTraefikFilter(before.Spec.Rules[0].Filters, "my-route"))

	// Now delete.
	assert.NoError(t, w.DeleteForRoute(context.Background(), "ingress-allowlisting-controller", "mynamespace", "my-route"))

	// Middleware gone.
	mw := &TraefikMiddleware{}
	err := k8sClient.Get(context.Background(), client.ObjectKey{Name: "my-route", Namespace: "mynamespace"}, mw)
	assert.True(t, client.IgnoreNotFound(err) == nil && err != nil, "Middleware should be gone")

	// Filter removed.
	after := &gatewayApiv1.HTTPRoute{}
	assert.NoError(t, k8sClient.Get(context.Background(), client.ObjectKey{Name: "my-route", Namespace: "mynamespace"}, after))
	assert.False(t, hasTraefikFilter(after.Spec.Rules[0].Filters, "my-route"), "extensionRef filter must be removed")
}

// TestTraefikL7Writer_ListManaged verifies only managed Middlewares are returned.
func TestTraefikL7Writer_ListManaged(t *testing.T) {
	managed := &TraefikMiddleware{
		ObjectMeta: metav1.ObjectMeta{
			Name: "managed", Namespace: "mynamespace",
			Labels: map[string]string{"app.kubernetes.io/managed-by": "ingress-allowlisting-controller"},
		},
	}
	unmanaged := &TraefikMiddleware{
		ObjectMeta: metav1.ObjectMeta{Name: "unmanaged", Namespace: "mynamespace"},
	}
	k8sClient := fake.NewClientBuilder().WithScheme(traefikScheme).WithObjects(managed, unmanaged).Build()
	w := newTraefikWriter(k8sClient)

	objs, err := w.ListManaged(context.Background(), "ingress-allowlisting-controller")
	assert.NoError(t, err)
	assert.Len(t, objs, 1)
	assert.Equal(t, "managed", objs[0].GetName())
}

// TestTraefikL7Writer_IsOrphaned verifies orphan detection by owner labels.
func TestTraefikL7Writer_IsOrphaned(t *testing.T) {
	mw := &TraefikMiddleware{
		ObjectMeta: metav1.ObjectMeta{
			Name: "my-route", Namespace: "mynamespace",
			Labels: map[string]string{
				"ipam.adevinta.com/owner-namespace": "mynamespace",
				"ipam.adevinta.com/owner-name":      "my-route",
			},
		},
	}
	k8sClient := fake.NewClientBuilder().WithScheme(traefikScheme).Build()
	w := newTraefikWriter(k8sClient)

	existingRoute := gatewayApiv1.HTTPRoute{ObjectMeta: metav1.ObjectMeta{Name: "my-route", Namespace: "mynamespace"}}
	deletedRoute := gatewayApiv1.HTTPRoute{ObjectMeta: metav1.ObjectMeta{Name: "other-route", Namespace: "mynamespace"}}

	assert.False(t, w.IsOrphaned(mw, []gatewayApiv1.HTTPRoute{existingRoute}), "should not be orphaned when owner route exists")
	assert.True(t, w.IsOrphaned(mw, []gatewayApiv1.HTTPRoute{deletedRoute}), "should be orphaned when owner route is gone")
	assert.True(t, w.IsOrphaned(mw, []gatewayApiv1.HTTPRoute{}), "should be orphaned when no routes exist")
}

// TestTraefikL7Writer_DoesNotImplementMerge verifies TraefikL7Writer does not satisfy MergeableL7PolicyWriter.
func TestTraefikL7Writer_DoesNotImplementMerge(t *testing.T) {
	k8sClient := fake.NewClientBuilder().WithScheme(traefikScheme).Build()
	w := newTraefikWriter(k8sClient)

	var iface L7PolicyWriter = w
	_, ok := iface.(MergeableL7PolicyWriter)
	assert.False(t, ok, "TraefikL7Writer must not implement MergeableL7PolicyWriter")
}
