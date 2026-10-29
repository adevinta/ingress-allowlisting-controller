//go:build functional

package functional

import (
	"context"
	"fmt"
	"os"
	"slices"
	"testing"
	"time"

	istiosecurityv1 "istio.io/client-go/pkg/apis/security/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/client"
	gatewayApiv1 "sigs.k8s.io/gateway-api/apis/v1"

	ipamv1alpha1 "github.com/adevinta/ingress-allowlisting-controller/pkg/apis/ipam.adevinta.com/v1alpha1"
	"github.com/adevinta/ingress-allowlisting-controller/pkg/controllers/writers"
)

// discovery is what the cluster offers beyond core Kubernetes, found before the plan is printed.
type discovery struct {
	annotationPrefix string
	gatewayAPI       bool // Gateway and HTTPRoute CRDs
	istio            bool // security.istio.io AuthorizationPolicy CRD
	traefik          bool // traefik.io Middleware CRD
	// istioClass / traefikClass are GatewayClasses handled by Istio / Traefik, empty if none.
	istioClass   string
	traefikClass string
	// httpRouteLabels must be set on HTTPRoutes when the controller watches only labelled routes
	// (--httproute-label-selector). httpRouteLabelsErr is set when that selector cannot be met.
	httpRouteLabels    map[string]string
	httpRouteLabelsErr error
}

func discover(ctx context.Context, c client.Client, ctrl controllerInfo, annotationPrefix string) discovery {
	has := func(group, kind string) bool {
		_, err := c.RESTMapper().RESTMapping(schema.GroupKind{Group: group, Kind: kind})
		return err == nil
	}
	d := discovery{
		annotationPrefix: annotationPrefix,
		gatewayAPI:       has(gatewayApiv1.GroupName, "Gateway") && has(gatewayApiv1.GroupName, "HTTPRoute"),
		istio:            has("security.istio.io", "AuthorizationPolicy"),
		traefik:          has("traefik.io", "Middleware"),
	}
	if d.gatewayAPI {
		d.istioClass = gatewayClassFor(ctx, c, writers.IstioControllerName, os.Getenv("IAC_ISTIO_GATEWAYCLASS"))
		d.traefikClass = gatewayClassFor(ctx, c, writers.TraefikControllerName, os.Getenv("IAC_TRAEFIK_GATEWAYCLASS"))
	}
	if selector := ctrl.flag("httproute-label-selector", ""); selector != "" {
		set, err := labels.ConvertSelectorToLabelsMap(selector)
		if err != nil {
			d.httpRouteLabelsErr = fmt.Errorf("--httproute-label-selector %q is not a plain key=value list the test can satisfy: %v", selector, err)
		}
		d.httpRouteLabels = set
	}
	return d
}

// gatewayClassFor returns the GatewayClass named by override, or the first one (alphabetically)
// handled by controllerName.
func gatewayClassFor(ctx context.Context, c client.Client, controllerName, override string) string {
	list := &gatewayApiv1.GatewayClassList{}
	if err := c.List(ctx, list); err != nil {
		return ""
	}
	var names []string
	for _, gc := range list.Items {
		if string(gc.Spec.ControllerName) == controllerName {
			names = append(names, gc.Name)
		}
	}
	slices.Sort(names)
	if override != "" {
		if slices.Contains(names, override) {
			return override
		}
		return ""
	}
	if len(names) == 0 {
		return ""
	}
	return names[0]
}

func serviceTarget() target {
	return target{
		name:        "service",
		kind:        "v1 Service type=LoadBalancer (spec.loadBalancerSourceRanges)",
		flag:        "service-support-enabled",
		flagDefault: false,
		create: func(ctx context.Context, c client.Client, ns, name string, annotations map[string]string) error {
			// A loadBalancerClass no load balancer controller implements: the cloud provider and
			// e.g. the AWS Load Balancer Controller ignore the Service, so nothing is provisioned.
			class := namespaceLabel + ".invalid/none"
			return c.Create(ctx, &corev1.Service{
				ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns, Annotations: annotations},
				Spec: corev1.ServiceSpec{
					Type:              corev1.ServiceTypeLoadBalancer,
					LoadBalancerClass: &class,
					Selector:          map[string]string{namespaceLabel + "-none": "true"},
					Ports:             []corev1.ServicePort{{Name: "http", Port: 80}},
				},
			})
		},
		observe: func(ctx context.Context, c client.Client, ns, name string) ([]string, error) {
			obj := &corev1.Service{}
			if err := c.Get(ctx, client.ObjectKey{Namespace: ns, Name: name}, obj); err != nil {
				return nil, err
			}
			if len(obj.Spec.LoadBalancerSourceRanges) == 0 {
				return nil, nil
			}
			return obj.Spec.LoadBalancerSourceRanges, nil
		},
	}
}

// parentGateway is the Gateway a target's HTTPRoutes attach to, one per target: targets share the
// namespace, and Istio and Traefik each need a Gateway of their own class.
func parentGateway(targetName string) string { return targetName + "-parent" }

// newGateway returns a Gateway with one HTTP listener for *.functional.invalid only, so it cannot
// match real traffic. For Istio it asks for a ClusterIP Service, so no cloud load balancer is
// provisioned for the auto-deployed gateway.
func newGateway(ns, name, class string, istio bool, annotations map[string]string) *gatewayApiv1.Gateway {
	hostname := gatewayApiv1.Hostname("*.functional.invalid")
	all := map[string]string{}
	for k, v := range annotations {
		all[k] = v
	}
	if istio {
		all["networking.istio.io/service-type"] = string(corev1.ServiceTypeClusterIP)
	}
	return &gatewayApiv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns, Annotations: all},
		Spec: gatewayApiv1.GatewaySpec{
			GatewayClassName: gatewayApiv1.ObjectName(class),
			Listeners: []gatewayApiv1.Listener{{
				Name:     "http",
				Port:     80,
				Protocol: gatewayApiv1.HTTPProtocolType,
				Hostname: &hostname,
			}},
		},
	}
}

// allowRoutesFrom sets which namespaces may attach routes to every listener of gw.
func allowRoutesFrom(gw *gatewayApiv1.Gateway, from gatewayApiv1.FromNamespaces) *gatewayApiv1.Gateway {
	for i := range gw.Spec.Listeners {
		gw.Spec.Listeners[i].AllowedRoutes = &gatewayApiv1.AllowedRoutes{Namespaces: &gatewayApiv1.RouteNamespaces{From: &from}}
	}
	return gw
}

// attachTo points route at the Gateway ns/name instead of the same-namespace parent.
func attachTo(route *gatewayApiv1.HTTPRoute, ns, name string) *gatewayApiv1.HTTPRoute {
	namespace := gatewayApiv1.Namespace(ns)
	route.Spec.ParentRefs = []gatewayApiv1.ParentReference{{Name: gatewayApiv1.ObjectName(name), Namespace: &namespace}}
	return route
}

// newHTTPRoute returns an HTTPRoute with one rule, attached to the Gateway parent in its own namespace.
func newHTTPRoute(d discovery, ns, name, parent string, annotations map[string]string) *gatewayApiv1.HTTPRoute {
	pathType := gatewayApiv1.PathMatchPathPrefix
	path := "/"
	return &gatewayApiv1.HTTPRoute{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns, Annotations: annotations, Labels: d.httpRouteLabels},
		Spec: gatewayApiv1.HTTPRouteSpec{
			CommonRouteSpec: gatewayApiv1.CommonRouteSpec{
				ParentRefs: []gatewayApiv1.ParentReference{{Name: gatewayApiv1.ObjectName(parent)}},
			},
			Hostnames: []gatewayApiv1.Hostname{gatewayApiv1.Hostname(name + ".functional.invalid")},
			Rules: []gatewayApiv1.HTTPRouteRule{{
				Matches: []gatewayApiv1.HTTPRouteMatch{{Path: &gatewayApiv1.HTTPPathMatch{Type: &pathType, Value: &path}}},
			}},
		},
	}
}

func istioGatewayTarget(d discovery) target {
	return target{
		name:        "istio-gateway",
		kind:        "Gateway → Istio AuthorizationPolicy (L4) class " + orNone(d.istioClass),
		flag:        "gateway-support-enabled",
		flagDefault: false,
		unavailable: istioUnavailable(d),
		create: func(ctx context.Context, c client.Client, ns, name string, annotations map[string]string) error {
			return c.Create(ctx, newGateway(ns, name, d.istioClass, true, annotations))
		},
		observe: func(ctx context.Context, c client.Client, ns, name string) ([]string, error) {
			// One policy per Gateway, named after it.
			policy := &istiosecurityv1.AuthorizationPolicy{}
			if err := c.Get(ctx, client.ObjectKey{Namespace: ns, Name: name}, policy); err != nil {
				return nil, client.IgnoreNotFound(err)
			}
			return remoteIPBlocks(policy)
		},
	}
}

const (
	istioHTTPRouteName   = "istio-httproute"
	traefikHTTPRouteName = "traefik-httproute"
)

func istioHTTPRouteTarget(d discovery) target {
	return target{
		name:        istioHTTPRouteName,
		kind:        "HTTPRoute → Istio AuthorizationPolicy (L7) class " + orNone(d.istioClass),
		flag:        "httproute-support-enabled",
		flagDefault: false,
		unavailable: firstNonEmpty(istioUnavailable(d), httpRouteLabelsUnavailable(d)),
		setup: func(ctx context.Context, c client.Client, ns string) error {
			return c.Create(ctx, newGateway(ns, parentGateway(istioHTTPRouteName), d.istioClass, true, nil))
		},
		create: func(ctx context.Context, c client.Client, ns, name string, annotations map[string]string) error {
			return c.Create(ctx, newHTTPRoute(d, ns, name, parentGateway(istioHTTPRouteName), annotations))
		},
		observe: func(ctx context.Context, c client.Client, ns, name string) ([]string, error) {
			return observeIstioPolicy(ctx, c, d, ns, ns, name)
		},
		extraScenarios: func(t *testing.T, env scenarioEnv) {
			crossNamespaceScenarios(t, env, d, istioCrossNamespace(d))
		},
	}
}

func traefikHTTPRouteTarget(d discovery) target {
	unavailable := firstNonEmpty(gatewayAPIUnavailable(d), httpRouteLabelsUnavailable(d))
	switch {
	case unavailable != "":
	case !d.traefik:
		unavailable = "traefik.io Middleware CRD not installed"
	case d.traefikClass == "":
		unavailable = "no GatewayClass with controller " + writers.TraefikControllerName
	}
	return target{
		name:        traefikHTTPRouteName,
		kind:        "HTTPRoute → Traefik Middleware (IPAllowList) class " + orNone(d.traefikClass),
		flag:        "httproute-support-enabled",
		flagDefault: false,
		unavailable: unavailable,
		setup: func(ctx context.Context, c client.Client, ns string) error {
			return c.Create(ctx, newGateway(ns, parentGateway(traefikHTTPRouteName), d.traefikClass, false, nil))
		},
		create: func(ctx context.Context, c client.Client, ns, name string, annotations map[string]string) error {
			return c.Create(ctx, newHTTPRoute(d, ns, name, parentGateway(traefikHTTPRouteName), annotations))
		},
		observe: func(ctx context.Context, c client.Client, ns, name string) ([]string, error) {
			return observeTraefik(ctx, c, ns, name)
		},
		extraScenarios: func(t *testing.T, env scenarioEnv) {
			crossNamespaceScenarios(t, env, d, traefikCrossNamespace(d))
		},
	}
}

// absenceWindow is how long a scenario watches for something that must not be written.
const absenceWindow = 30 * time.Second

// crossNamespaceKind is what differs between gateway controllers in the cross-namespace scenarios.
type crossNamespaceKind struct {
	prefix string // object name prefix, e.g. "traefik"
	class  string // GatewayClass of the Gateways in the peer namespace
	istio  bool
	// observe returns the allowlist written for the route routeNS/name attached to a Gateway in
	// gatewayNS, or nil, nil if none was written.
	observe func(ctx context.Context, c client.Client, routeNS, gatewayNS, name string) ([]string, error)
	// stray returns a description of anything written where it must not be, "" if nothing.
	stray func(ctx context.Context, c client.Client, routeNS, gatewayNS, name string) (string, error)
}

// crossNamespaceScenarios attaches routes in the main namespace to Gateways in the peer namespace:
// one Gateway accepting routes from all namespaces, one accepting only its own namespace.
func crossNamespaceScenarios(t *testing.T, env scenarioEnv, d discovery, k crossNamespaceKind) {
	ctx, c, ns, peer := env.ctx, env.c, env.ns, env.peerNS
	cidrsName := k.prefix + "-xns"
	spec := ipamv1alpha1.CIDRsSpec{CIDRsSource: ipamv1alpha1.CIDRsSource{CIDRs: []string{"203.0.113.0/24"}}}
	if err := createCIDRs(ctx, c, ns, cidrsName, spec); err != nil {
		t.Fatalf("creating CIDRs %s: %v", cidrsName, err)
	}
	// attach creates a Gateway in the peer namespace accepting routes from `from`, and a route in
	// the main namespace attached to it.
	attach := func(t *testing.T, gwName, routeName string, from gatewayApiv1.FromNamespaces) {
		t.Helper()
		if err := c.Create(ctx, allowRoutesFrom(newGateway(peer, gwName, k.class, k.istio, nil), from)); err != nil {
			t.Fatalf("creating Gateway %s/%s: %v", peer, gwName, err)
		}
		if err := c.Create(ctx, attachTo(newHTTPRoute(d, ns, routeName, gwName, map[string]string{env.annotation: cidrsName}), peer, gwName)); err != nil {
			t.Fatalf("creating HTTPRoute: %v", err)
		}
	}
	noStray := func(t *testing.T, name string) {
		t.Helper()
		found, err := k.stray(ctx, c, ns, peer, name)
		if err != nil {
			t.Fatal(err)
		}
		if found != "" {
			t.Fatal(found)
		}
	}

	t.Run("cross-namespace", func(t *testing.T) {
		name := k.prefix + "-xns"
		attach(t, k.prefix+"-shared-all", name, gatewayApiv1.NamespacesFromAll)
		expectAllowlist(t, "allowlist for route "+ns+"/"+name+" on a Gateway in "+peer,
			func() ([]string, error) { return k.observe(ctx, c, ns, peer, name) }, exactly("203.0.113.0/24"))
		noStray(t, name)
	})

	t.Run("allowedroutes-same", func(t *testing.T) {
		// The Gateway only accepts routes from its own namespace, so nothing may be written for a
		// route from another namespace (NEW_IDEAS item 1). For Istio a policy would still apply to
		// the Gateway by host, e.g. to other tenants' hosts.
		gwName, name := k.prefix+"-shared-same", k.prefix+"-not-allowed"
		attach(t, gwName, name, gatewayApiv1.NamespacesFromSame)
		deadline := time.Now().Add(absenceWindow)
		for time.Now().Before(deadline) {
			got, err := k.observe(ctx, c, ns, peer, name)
			if err == nil && got != nil {
				t.Fatalf("allowlist %v written for route %s/%s although Gateway %s/%s only allows routes from its own namespace", got, ns, name, peer, gwName)
			}
			time.Sleep(pollInterval)
		}
		noStray(t, name)
	})
}

func traefikCrossNamespace(d discovery) crossNamespaceKind {
	return crossNamespaceKind{
		prefix: "traefik",
		class:  d.traefikClass,
		// extensionRef cannot cross namespaces, so the Middleware is in the route's namespace.
		observe: func(ctx context.Context, c client.Client, routeNS, _, name string) ([]string, error) {
			return observeTraefik(ctx, c, routeNS, name)
		},
		stray: func(ctx context.Context, c client.Client, _, gatewayNS, _ string) (string, error) {
			list := &writers.TraefikMiddlewareList{}
			if err := c.List(ctx, list, client.InNamespace(gatewayNS)); err != nil {
				return "", fmt.Errorf("listing Middlewares in %s: %w", gatewayNS, err)
			}
			if len(list.Items) > 0 {
				return fmt.Sprintf("no Middleware may be written in the Gateway's namespace %s, found %d", gatewayNS, len(list.Items)), nil
			}
			return "", nil
		},
	}
}

func istioCrossNamespace(d discovery) crossNamespaceKind {
	return crossNamespaceKind{
		prefix: "istio",
		class:  d.istioClass,
		istio:  true,
		// The policy is in the Gateway's namespace, labelled with the route as owner.
		observe: func(ctx context.Context, c client.Client, routeNS, gatewayNS, name string) ([]string, error) {
			return observeIstioPolicy(ctx, c, d, gatewayNS, routeNS, name)
		},
		stray: func(ctx context.Context, c client.Client, routeNS, _, name string) (string, error) {
			list := &istiosecurityv1.AuthorizationPolicyList{}
			if err := c.List(ctx, list, client.InNamespace(routeNS), ownerLabels(d, routeNS, name)); err != nil {
				return "", fmt.Errorf("listing AuthorizationPolicies in %s: %w", routeNS, err)
			}
			if len(list.Items) > 0 {
				return fmt.Sprintf("no AuthorizationPolicy may be written in the route's namespace %s for a Gateway in another namespace, found %d", routeNS, len(list.Items)), nil
			}
			return "", nil
		},
	}
}

// observeIstioPolicy returns the allowlist of the one AuthorizationPolicy in policyNS owned by the
// route routeNS/name (the route has one rule, so one policy), or nil, nil if there is none yet.
func observeIstioPolicy(ctx context.Context, c client.Client, d discovery, policyNS, routeNS, name string) ([]string, error) {
	list := &istiosecurityv1.AuthorizationPolicyList{}
	if err := c.List(ctx, list, client.InNamespace(policyNS), ownerLabels(d, routeNS, name)); err != nil {
		return nil, err
	}
	switch len(list.Items) {
	case 0:
		return nil, nil
	case 1:
		return remoteIPBlocks(list.Items[0])
	default:
		return nil, fmt.Errorf("want one AuthorizationPolicy for HTTPRoute %s/%s in %s, got %d", routeNS, name, policyNS, len(list.Items))
	}
}

// observeTraefik returns the allowlist of the Middleware named after the route, once every rule of
// the route references it.
func observeTraefik(ctx context.Context, c client.Client, ns, name string) ([]string, error) {
	// The Middleware is named after the route, and every rule must reference it.
	mw := &writers.TraefikMiddleware{}
	if err := c.Get(ctx, client.ObjectKey{Namespace: ns, Name: name}, mw); err != nil {
		return nil, client.IgnoreNotFound(err)
	}
	if mw.Spec.IPAllowList == nil {
		return nil, fmt.Errorf("Middleware %s has no ipAllowList", name)
	}
	route := &gatewayApiv1.HTTPRoute{}
	if err := c.Get(ctx, client.ObjectKey{Namespace: ns, Name: name}, route); err != nil {
		return nil, err
	}
	for i, rule := range route.Spec.Rules {
		if !referencesMiddleware(rule.Filters, name) {
			return nil, fmt.Errorf("HTTPRoute rule %d has no ExtensionRef filter to Middleware %s yet", i, name)
		}
	}
	return mw.Spec.IPAllowList.SourceRange, nil
}

func referencesMiddleware(filters []gatewayApiv1.HTTPRouteFilter, name string) bool {
	for _, f := range filters {
		if f.Type == gatewayApiv1.HTTPRouteFilterExtensionRef && f.ExtensionRef != nil &&
			string(f.ExtensionRef.Group) == "traefik.io" && string(f.ExtensionRef.Kind) == "Middleware" &&
			string(f.ExtensionRef.Name) == name {
			return true
		}
	}
	return false
}

// remoteIPBlocks returns the CIDRs of a controller-written AuthorizationPolicy, which always has a
// single rule with a single source.
func remoteIPBlocks(policy *istiosecurityv1.AuthorizationPolicy) ([]string, error) {
	rules := policy.Spec.GetRules()
	if len(rules) != 1 || len(rules[0].GetFrom()) != 1 || rules[0].GetFrom()[0].GetSource() == nil {
		return nil, fmt.Errorf("AuthorizationPolicy %s: want one rule with one source, got %v", policy.Name, rules)
	}
	return rules[0].GetFrom()[0].GetSource().GetRemoteIpBlocks(), nil
}

// ownerLabels selects the policies the controller wrote for one HTTPRoute.
func ownerLabels(d discovery, ns, name string) client.MatchingLabels {
	return client.MatchingLabels{
		"app.kubernetes.io/managed-by":          "ingress-allowlisting-controller",
		d.annotationPrefix + "/owner-namespace": ns,
		d.annotationPrefix + "/owner-name":      name,
	}
}

func gatewayAPIUnavailable(d discovery) string {
	if !d.gatewayAPI {
		return "Gateway API CRDs (Gateway, HTTPRoute) not installed"
	}
	return ""
}

func istioUnavailable(d discovery) string {
	switch {
	case !d.gatewayAPI:
		return gatewayAPIUnavailable(d)
	case !d.istio:
		return "security.istio.io AuthorizationPolicy CRD not installed"
	case d.istioClass == "":
		return "no GatewayClass with controller " + writers.IstioControllerName
	}
	return ""
}

func httpRouteLabelsUnavailable(d discovery) string {
	if d.httpRouteLabelsErr != nil {
		return d.httpRouteLabelsErr.Error()
	}
	return ""
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

func orNone(s string) string {
	if s == "" {
		return "(none)"
	}
	return s
}
