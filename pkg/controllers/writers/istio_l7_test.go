package writers

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	gatewayApiv1 "sigs.k8s.io/gateway-api/apis/v1"

	istiosecurityv1 "istio.io/client-go/pkg/apis/security/v1"

	ipamv1alpha1 "github.com/adevinta/ingress-allowlisting-controller/pkg/apis/ipam.adevinta.com/v1alpha1"
	"github.com/adevinta/ingress-allowlisting-controller/pkg/resolvers"
)

var istioL7Scheme = func() *runtime.Scheme {
	s := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(s)
	_ = gatewayApiv1.Install(s)
	_ = istiosecurityv1.AddToScheme(s)
	_ = ipamv1alpha1.AddToScheme(s)
	return s
}()

func newIstioL7Writer(c client.Client) *IstioL7Writer {
	resolver := resolvers.CidrResolver{Client: c, AnnotationPrefix: resolvers.DefaultPrefix}
	return NewIstioL7Writer(c, "ingress-allowlisting-controller", resolver)
}

func testGateway(name, namespace string) *gatewayApiv1.Gateway {
	return &gatewayApiv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
		Spec:       gatewayApiv1.GatewaySpec{GatewayClassName: "istio"},
	}
}

func testRoute(name, namespace string, hostnames ...string) *gatewayApiv1.HTTPRoute {
	r := &gatewayApiv1.HTTPRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:        name,
			Namespace:   namespace,
			Annotations: map[string]string{},
		},
	}
	for _, h := range hostnames {
		r.Spec.Hostnames = append(r.Spec.Hostnames, gatewayApiv1.Hostname(h))
	}
	return r
}

func testCIDRs(name, namespace string, cidrs ...string) *ipamv1alpha1.CIDRs {
	return &ipamv1alpha1.CIDRs{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
		Status:     ipamv1alpha1.CIDRsStatus{CIDRs: cidrs},
	}
}

// TestIstioPathsForRule verifies correct translation of HTTPRoute path match types.
func TestIstioPathsForRule(t *testing.T) {
	prefix := gatewayApiv1.PathMatchPathPrefix
	exact := gatewayApiv1.PathMatchExact
	regex := gatewayApiv1.PathMatchRegularExpression

	api := "/api"
	root := "/"
	chaos := "/chaos"

	tests := []struct {
		name     string
		matches  []gatewayApiv1.HTTPRouteMatch
		expected []string
	}{
		{
			name: "PathPrefix /api → /api and /api/*",
			matches: []gatewayApiv1.HTTPRouteMatch{
				{Path: &gatewayApiv1.HTTPPathMatch{Type: &prefix, Value: &api}},
			},
			expected: []string{"/api", "/api/*"},
		},
		{
			name: "PathPrefix / → /* only (no double slash)",
			matches: []gatewayApiv1.HTTPRouteMatch{
				{Path: &gatewayApiv1.HTTPPathMatch{Type: &prefix, Value: &root}},
			},
			expected: []string{"/*"},
		},
		{
			name: "Exact /chaos → /chaos only",
			matches: []gatewayApiv1.HTTPRouteMatch{
				{Path: &gatewayApiv1.HTTPPathMatch{Type: &exact, Value: &chaos}},
			},
			expected: []string{"/chaos"},
		},
		{
			name: "RegularExpression → skipped",
			matches: []gatewayApiv1.HTTPRouteMatch{
				{Path: &gatewayApiv1.HTTPPathMatch{Type: &regex, Value: &api}},
			},
			expected: nil,
		},
		{
			name: "nil type defaults to PathPrefix",
			matches: []gatewayApiv1.HTTPRouteMatch{
				{Path: &gatewayApiv1.HTTPPathMatch{Value: &api}},
			},
			expected: []string{"/api", "/api/*"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			w := newIstioL7Writer(fake.NewClientBuilder().WithScheme(istioL7Scheme).Build())
			assert.ElementsMatch(t, tc.expected, w.TranslatePaths(tc.matches))
		})
	}
}

// TestIsOrphaned_GranularityHost verifies that a route with granularity=host produces
// the base AP name (no path suffix), and that orphan detection recognises it as live.
func TestIsOrphaned_GranularityHost(t *testing.T) {
	gwNS := gatewayApiv1.Namespace("ns")
	prefix := gatewayApiv1.PathMatchPathPrefix
	path := "/api"
	route := gatewayApiv1.HTTPRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name: "my-route", Namespace: "ns",
			Annotations: map[string]string{"ipam.adevinta.com/granularity": "host"},
		},
		Spec: gatewayApiv1.HTTPRouteSpec{
			CommonRouteSpec: gatewayApiv1.CommonRouteSpec{ParentRefs: []gatewayApiv1.ParentReference{
				{Name: "gw", Namespace: &gwNS},
			}},
			Rules: []gatewayApiv1.HTTPRouteRule{
				{Matches: []gatewayApiv1.HTTPRouteMatch{
					{Path: &gatewayApiv1.HTTPPathMatch{Type: &prefix, Value: &path}},
				}},
			},
		},
	}

	k8sClient := fake.NewClientBuilder().WithScheme(istioL7Scheme).Build()
	w := newIstioL7Writer(k8sClient)

	// AP at base name (no path suffix) — what Apply actually creates for granularity=host.
	liveAP := &istiosecurityv1.AuthorizationPolicy{}
	liveAP.Name = "gw-my-route"
	liveAP.Namespace = "ns"
	liveAP.Labels = map[string]string{
		"ipam.adevinta.com/owner-namespace": "ns",
		"ipam.adevinta.com/owner-name":      "my-route",
	}
	assert.False(t, w.IsOrphaned(liveAP, []gatewayApiv1.HTTPRoute{route}),
		"granularity=host AP at base name must NOT be orphaned")

	// AP at path-suffixed name — what the old logic would have computed (bug).
	staleAP := &istiosecurityv1.AuthorizationPolicy{}
	staleAP.Name = "gw-my-route-api-" // some hash-suffixed name
	staleAP.Namespace = "ns"
	staleAP.Labels = map[string]string{
		"ipam.adevinta.com/owner-namespace": "ns",
		"ipam.adevinta.com/owner-name":      "my-route",
	}
	assert.True(t, w.IsOrphaned(staleAP, []gatewayApiv1.HTTPRoute{route}),
		"path-suffixed AP must be orphaned when route uses granularity=host")
}

// TestIsOrphaned_PathPrefixRoute verifies that orphan detection correctly resolves the AP name
// for a PathPrefix route (which expands to two paths and gets a hash-suffixed name).
func TestIsOrphaned_PathPrefixRoute(t *testing.T) {
	gwNS := gatewayApiv1.Namespace("ns")
	prefix := gatewayApiv1.PathMatchPathPrefix
	path := "/api"
	route := gatewayApiv1.HTTPRoute{
		ObjectMeta: metav1.ObjectMeta{Name: "my-route", Namespace: "ns"},
		Spec: gatewayApiv1.HTTPRouteSpec{
			CommonRouteSpec: gatewayApiv1.CommonRouteSpec{ParentRefs: []gatewayApiv1.ParentReference{
				{Name: "gw", Namespace: &gwNS},
			}},
			Rules: []gatewayApiv1.HTTPRouteRule{
				{Matches: []gatewayApiv1.HTTPRouteMatch{
					{Path: &gatewayApiv1.HTTPPathMatch{Type: &prefix, Value: &path}},
				}},
			},
		},
	}

	k8sClient := fake.NewClientBuilder().WithScheme(istioL7Scheme).Build()
	w := newIstioL7Writer(k8sClient)

	// Compute the name Apply would actually create.
	targets := w.policyTargetsForRoute(&route)
	require.Len(t, targets, 1)
	liveAPName := targets[0].name

	liveAP := &istiosecurityv1.AuthorizationPolicy{}
	liveAP.Name = liveAPName
	liveAP.Namespace = "ns"
	liveAP.Labels = map[string]string{
		"ipam.adevinta.com/owner-namespace": "ns",
		"ipam.adevinta.com/owner-name":      "my-route",
	}
	assert.False(t, w.IsOrphaned(liveAP, []gatewayApiv1.HTTPRoute{route}),
		"PathPrefix AP at correct hash name must NOT be orphaned")

	// The old (pre-fix) name using only the raw path value.
	oldAP := &istiosecurityv1.AuthorizationPolicy{}
	oldAP.Name = "gw-my-route-api" // single-path name, no hash
	oldAP.Namespace = "ns"
	oldAP.Labels = map[string]string{
		"ipam.adevinta.com/owner-namespace": "ns",
		"ipam.adevinta.com/owner-name":      "my-route",
	}
	assert.True(t, w.IsOrphaned(oldAP, []gatewayApiv1.HTTPRoute{route}),
		"old single-path AP name must be orphaned after PathPrefix expansion fix")
}

// TestPolicyNameHashSuffix verifies the AP naming scheme: any non-empty path set produces
// {base}-{fnv32hex}, order-independent and collision-resistant.
func TestPolicyNameHashSuffix(t *testing.T) {
	gw := &gatewayApiv1.Gateway{}
	gw.Name = "gw"
	gw.Namespace = "ns"
	route := &gatewayApiv1.HTTPRoute{}
	route.Name = "r"
	route.Namespace = "ns"

	// Single path: hash suffix, no human-readable path in name.
	nameSingle, _, _ := policyName(route, gw, []string{"/api"})
	assert.Regexp(t, `^gw-r-[0-9a-f]{8}$`, nameSingle, "single path must produce {base}-{hash}")

	// Multiple paths: same format.
	nameMulti, _, _ := policyName(route, gw, []string{"/api", "/health"})
	assert.Regexp(t, `^gw-r-[0-9a-f]{8}$`, nameMulti, "multi-path must produce {base}-{hash}")

	// Order must not matter.
	nameReversed, _, _ := policyName(route, gw, []string{"/health", "/api"})
	assert.Equal(t, nameMulti, nameReversed, "path order must not affect the AP name")

	// Different path sets must produce different names.
	nameOther, _, _ := policyName(route, gw, []string{"/api", "/admin"})
	assert.NotEqual(t, nameMulti, nameOther, "different path sets must produce different names")

	// Single-path and multi-path with same first path must differ.
	assert.NotEqual(t, nameSingle, nameMulti)

	// No paths: base name only.
	nameBase, _, _ := policyName(route, gw, nil)
	assert.Equal(t, "gw-r", nameBase)
}

// TestTruncateName verifies the 253-char name length cap.
func TestTruncateName(t *testing.T) {
	short := "my-gateway-my-route-api"
	assert.Equal(t, short, truncateName(short))

	exact := strings.Repeat("a", 253)
	assert.Equal(t, exact, truncateName(exact))

	long := strings.Repeat("a", 254)
	result := truncateName(long)
	assert.Len(t, result, 253)
	assert.Regexp(t, `^a{244}-[0-9a-f]{8}$`, result)

	longA := strings.Repeat("a", 244) + strings.Repeat("x", 10)
	longB := strings.Repeat("a", 244) + strings.Repeat("y", 10)
	assert.NotEqual(t, truncateName(longA), truncateName(longB))
}

// TestRoutePolicyPrefixOverlap is the regression test for the false-negative in IsOrphaned.
//
// Scenario: gateway "gw" in "ns". Two routes once existed: "api" and "api-v2".
// "api"    → AP "gw-api"
// "api-v2" → AP "gw-api-v2"
//
// "api-v2" is deleted. Cleanup must identify "gw-api-v2" as orphaned.
// The old HasPrefix logic found route "api", computed base "gw-api", and concluded
// HasPrefix("gw-api-v2", "gw-api-") == true → not orphaned (wrong).
// The new exact-match logic finds no rule in route "api" that produces "gw-api-v2" → orphaned (correct).
func TestRoutePolicyPrefixOverlap(t *testing.T) {
	gwNS := gatewayApiv1.Namespace("ns")
	routeApi := gatewayApiv1.HTTPRoute{
		ObjectMeta: metav1.ObjectMeta{Name: "api", Namespace: "ns"},
		Spec: gatewayApiv1.HTTPRouteSpec{
			CommonRouteSpec: gatewayApiv1.CommonRouteSpec{ParentRefs: []gatewayApiv1.ParentReference{
				{Name: "gw", Namespace: &gwNS},
			}},
		},
	}

	k8sClient := fake.NewClientBuilder().WithScheme(istioL7Scheme).Build()
	w := newIstioL7Writer(k8sClient)

	staleAP := &istiosecurityv1.AuthorizationPolicy{}
	staleAP.Name = "gw-api-v2"
	staleAP.Namespace = "ns"
	staleAP.Labels = map[string]string{
		"ipam.adevinta.com/owner-namespace": "ns",
		"ipam.adevinta.com/owner-name":      "api",
	}
	assert.True(t, w.IsOrphaned(staleAP, []gatewayApiv1.HTTPRoute{routeApi}),
		"AP gw-api-v2 must be orphaned: route api exists but only produces gw-api, not gw-api-v2")

	liveAP := &istiosecurityv1.AuthorizationPolicy{}
	liveAP.Name = "gw-api"
	liveAP.Namespace = "ns"
	liveAP.Labels = map[string]string{
		"ipam.adevinta.com/owner-namespace": "ns",
		"ipam.adevinta.com/owner-name":      "api",
	}
	assert.False(t, w.IsOrphaned(liveAP, []gatewayApiv1.HTTPRoute{routeApi}),
		"AP gw-api must NOT be orphaned: route api still produces it")
}

// TestIsOrphaned_CrossNamespace verifies that orphan detection works correctly for
// cross-namespace APs where the AP lives in the gateway's namespace but is owned by
// a route in a different namespace.
func TestIsOrphaned_CrossNamespace(t *testing.T) {
	gwNS := gatewayApiv1.Namespace("gw-ns")
	route := gatewayApiv1.HTTPRoute{
		ObjectMeta: metav1.ObjectMeta{Name: "my-route", Namespace: "route-ns"},
		Spec: gatewayApiv1.HTTPRouteSpec{
			CommonRouteSpec: gatewayApiv1.CommonRouteSpec{ParentRefs: []gatewayApiv1.ParentReference{
				{Name: "my-gw", Namespace: &gwNS},
			}},
		},
	}

	k8sClient := fake.NewClientBuilder().WithScheme(istioL7Scheme).Build()
	w := newIstioL7Writer(k8sClient)

	// Compute the expected cross-namespace AP name.
	targets := w.policyTargetsForRoute(&route)
	require.Len(t, targets, 1)
	assert.Equal(t, "gw-ns", targets[0].namespace, "cross-namespace AP must live in gateway's namespace")

	// Live cross-namespace AP — should NOT be orphaned.
	liveAP := &istiosecurityv1.AuthorizationPolicy{}
	liveAP.Name = targets[0].name
	liveAP.Namespace = targets[0].namespace
	liveAP.Labels = map[string]string{
		"ipam.adevinta.com/owner-namespace": LabelSafe("route-ns"),
		"ipam.adevinta.com/owner-name":      LabelSafe("my-route"),
	}
	assert.False(t, w.IsOrphaned(liveAP, []gatewayApiv1.HTTPRoute{route}),
		"cross-namespace AP at correct name must NOT be orphaned")

	// Stale AP from a route that no longer exists — should be orphaned.
	staleAP := &istiosecurityv1.AuthorizationPolicy{}
	staleAP.Name = "my-gw-route-ns-deleted-route"
	staleAP.Namespace = "gw-ns"
	staleAP.Labels = map[string]string{
		"ipam.adevinta.com/owner-namespace": LabelSafe("route-ns"),
		"ipam.adevinta.com/owner-name":      LabelSafe("deleted-route"),
	}
	assert.True(t, w.IsOrphaned(staleAP, []gatewayApiv1.HTTPRoute{route}),
		"AP for a deleted cross-namespace route must be orphaned")

	// AP with wrong name for the existing route — should be orphaned (e.g. gateway changed).
	wrongNameAP := &istiosecurityv1.AuthorizationPolicy{}
	wrongNameAP.Name = "old-gw-route-ns-my-route"
	wrongNameAP.Namespace = "gw-ns"
	wrongNameAP.Labels = map[string]string{
		"ipam.adevinta.com/owner-namespace": LabelSafe("route-ns"),
		"ipam.adevinta.com/owner-name":      LabelSafe("my-route"),
	}
	assert.True(t, w.IsOrphaned(wrongNameAP, []gatewayApiv1.HTTPRoute{route}),
		"AP with wrong name for existing cross-namespace route must be orphaned")
}

// TestIsOrphaned_LongRouteName verifies that routes with names > 63 chars (which get
// truncated by LabelSafe) are still correctly recognised as owners during orphan detection.
func TestIsOrphaned_LongRouteName(t *testing.T) {
	longName := strings.Repeat("a", 54) + strings.Repeat("b", 20) // 74 chars — exceeds 63
	gwNS := gatewayApiv1.Namespace("ns")
	route := gatewayApiv1.HTTPRoute{
		ObjectMeta: metav1.ObjectMeta{Name: longName, Namespace: "ns"},
		Spec: gatewayApiv1.HTTPRouteSpec{
			CommonRouteSpec: gatewayApiv1.CommonRouteSpec{ParentRefs: []gatewayApiv1.ParentReference{
				{Name: "gw", Namespace: &gwNS},
			}},
		},
	}

	k8sClient := fake.NewClientBuilder().WithScheme(istioL7Scheme).Build()
	w := newIstioL7Writer(k8sClient)

	targets := w.policyTargetsForRoute(&route)
	require.Len(t, targets, 1)

	liveAP := &istiosecurityv1.AuthorizationPolicy{}
	liveAP.Name = targets[0].name
	liveAP.Namespace = targets[0].namespace
	liveAP.Labels = map[string]string{
		"ipam.adevinta.com/owner-namespace": LabelSafe("ns"),
		"ipam.adevinta.com/owner-name":      LabelSafe(longName),
	}
	assert.False(t, w.IsOrphaned(liveAP, []gatewayApiv1.HTTPRoute{route}),
		"AP with LabelSafe'd long name must NOT be orphaned when route still exists")
}
