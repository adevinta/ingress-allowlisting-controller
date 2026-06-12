package writers

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
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

// TestPolicyNameMultiPathNoCollision verifies the AP naming scheme for multi-path rules.
// Single path: human-readable pathSafe suffix (unchanged from before).
// Multiple paths: FNV-32a hex hash of the sorted set — valid K8s name chars, order-independent.
func TestPolicyNameMultiPathNoCollision(t *testing.T) {
	gw := &gatewayApiv1.Gateway{}
	gw.Name = "gw"
	gw.Namespace = "ns"
	route := &gatewayApiv1.HTTPRoute{}
	route.Name = "r"
	route.Namespace = "ns"

	// Single path: readable suffix, no hash.
	nameSingle, _, _ := policyName(route, gw, []string{"/api"})
	assert.Equal(t, "gw-r-api", nameSingle)

	// Multi-path: first path + hash suffix.
	nameMulti, _, _ := policyName(route, gw, []string{"/api", "/health"})
	assert.Regexp(t, `^gw-r-api-[0-9a-f]{8}$`, nameMulti, "multi-path name must be {base}-{firstPath}-{hash}")

	// Order must not matter.
	nameReversed, _, _ := policyName(route, gw, []string{"/health", "/api"})
	assert.Equal(t, nameMulti, nameReversed, "path order must not affect the AP name")

	// Different path sets must produce different names.
	nameOther, _, _ := policyName(route, gw, []string{"/api", "/admin"})
	assert.NotEqual(t, nameMulti, nameOther, "different path sets must produce different names")

	// Multi-path must never collide with single-path.
	assert.NotEqual(t, nameMulti, nameSingle)
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
