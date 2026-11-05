package controllers

import (
	"context"
	"slices"
	"strings"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"sigs.k8s.io/controller-runtime/pkg/client"
	gatewayApiv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/adevinta/ingress-allowlisting-controller/pkg/controllers/internal"
)

// namespaceLabelsTTL is how long the labels of a namespace are reused for allowedRoutes
// namespace selectors. Removing a label takes effect at the next reconcile of the route after it.
const namespaceLabelsTTL = 10 * time.Minute

// namespaceLabelCache keeps namespace labels for allowedRoutes selectors. It reads through an
// uncached reader on a miss, so it never starts a Namespace informer (no list/watch).
type namespaceLabelCache struct {
	reader  client.Reader
	ttl     time.Duration
	now     func() time.Time
	mu      sync.Mutex
	entries map[string]namespaceLabelEntry
}

type namespaceLabelEntry struct {
	labels  labels.Set
	expires time.Time
}

func newNamespaceLabelCache(reader client.Reader) *namespaceLabelCache {
	return &namespaceLabelCache{reader: reader, ttl: namespaceLabelsTTL, now: time.Now, entries: map[string]namespaceLabelEntry{}}
}

func (c *namespaceLabelCache) get(ctx context.Context, namespace string) (labels.Set, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if e, ok := c.entries[namespace]; ok && c.now().Before(e.expires) {
		return e.labels, nil
	}
	// Metadata only: labels are all we need.
	ns := &metav1.PartialObjectMetadata{}
	ns.SetGroupVersionKind(corev1.SchemeGroupVersion.WithKind("Namespace"))
	if err := c.reader.Get(ctx, client.ObjectKey{Name: namespace}, ns); err != nil {
		return nil, err
	}
	set := labels.Set(ns.GetLabels())
	c.entries[namespace] = namespaceLabelEntry{labels: set, expires: c.now().Add(c.ttl)}
	return set, nil
}

// namespaceLabels returns the reconciler's namespace label cache, created on first use.
func (r *HTTPRouteAllowlistingReconciler) namespaceLabels() *namespaceLabelCache {
	r.nsLabelsOnce.Do(func() { r.nsLabels = newNamespaceLabelCache(r.APIReader) })
	return r.nsLabels
}

// routeHostnamesOnParentRef returns the route's hostnames the Gateway routes for it through this
// parentRef, following the Gateway API attachment rules on the listeners the parentRef targets
// (sectionName, port): allowedRoutes.kinds, allowedRoutes.namespaces, and the listeners'
// hostnames. reason is "" when the route is attached, else why it isn't.
//
// A route the Gateway doesn't accept serves no traffic there, and the hostnames a listener doesn't
// match are ignored for routing. But an Istio AuthorizationPolicy targets the whole Gateway by host,
// so one written for those hostnames would allow its CIDRs on other routes' hosts, e.g. another
// tenant's on another listener. So the policy gets only the hostnames returned here.
//
// A route without hostnames is attached with none: it gets no policy (see Apply), as it would
// cover every host of the listener.
func (r *HTTPRouteAllowlistingReconciler) routeHostnamesOnParentRef(ctx context.Context, route *gatewayApiv1.HTTPRoute, ref gatewayApiv1.ParentReference, gw *gatewayApiv1.Gateway) (hostnames []string, reason string, err error) {
	var listeners []gatewayApiv1.Listener
	for _, l := range gw.Spec.Listeners {
		if ref.SectionName != nil && l.Name != *ref.SectionName {
			continue
		}
		if ref.Port != nil && l.Port != *ref.Port {
			continue
		}
		if !listenerAllowsHTTPRoute(l) {
			continue
		}
		ok, err := r.listenerAllowsNamespace(ctx, l, route.Namespace, gw.Namespace)
		if err != nil {
			return nil, "", err
		}
		if ok {
			listeners = append(listeners, l)
		}
	}
	if len(listeners) == 0 {
		return nil, "it is not allowed by the listeners (allowedRoutes)", nil
	}
	hostnames = attachedHostnames(route.Spec.Hostnames, listeners)
	if len(route.Spec.Hostnames) > 0 && len(hostnames) == 0 {
		return nil, "none of its hostnames matches the hostnames of the listeners that allow it", nil
	}
	return hostnames, "", nil
}

// routeHostnamesOnGateway is routeHostnamesOnParentRef over all of the route's parentRefs to gw:
// the union of their hostnames, attached if any of them is.
func (r *HTTPRouteAllowlistingReconciler) routeHostnamesOnGateway(ctx context.Context, route *gatewayApiv1.HTTPRoute, gw *gatewayApiv1.Gateway) (hostnames []string, attached bool, err error) {
	for _, ref := range gateway.GatewayParentRefs(route) {
		refNS := route.Namespace
		if ref.Namespace != nil {
			refNS = string(*ref.Namespace)
		}
		if string(ref.Name) != gw.Name || refNS != gw.Namespace {
			continue
		}
		hosts, reason, err := r.routeHostnamesOnParentRef(ctx, route, ref, gw)
		if err != nil {
			return nil, false, err
		}
		if reason == "" {
			attached = true
			hostnames = append(hostnames, hosts...)
		}
	}
	slices.Sort(hostnames)
	return slices.Compact(hostnames), attached, nil
}

// attachedHostnames returns the route hostnames the listeners match, as Gateway API defines it
// (HTTPRouteSpec.Hostnames): a listener without hostname matches all of them; otherwise each
// route hostname intersecting the listener's gives the more specific of the two. Sorted, unique.
func attachedHostnames(routeHostnames []gatewayApiv1.Hostname, listeners []gatewayApiv1.Listener) []string {
	var out []string
	for _, l := range listeners {
		for _, h := range routeHostnames {
			if l.Hostname == nil || *l.Hostname == "" {
				out = append(out, string(h))
				continue
			}
			if match, ok := intersectHostnames(string(*l.Hostname), string(h)); ok {
				out = append(out, match)
			}
		}
	}
	slices.Sort(out)
	return slices.Compact(out)
}

// intersectHostnames returns the hostname matched by both a listener hostname and a route
// hostname, either of which may be a wildcard (*.suffix, a suffix match of one or more labels):
// the more specific one.
func intersectHostnames(listener, route string) (string, bool) {
	lWild, rWild := strings.HasPrefix(listener, "*."), strings.HasPrefix(route, "*.")
	switch {
	case !lWild && !rWild:
		return route, listener == route
	case lWild && !rWild:
		return route, strings.HasSuffix(route, listener[1:])
	case !lWild && rWild:
		return listener, strings.HasSuffix(listener, route[1:])
	default:
		lSuffix, rSuffix := listener[1:], route[1:]
		switch {
		case lSuffix == rSuffix || strings.HasSuffix(rSuffix, lSuffix):
			return route, true
		case strings.HasSuffix(lSuffix, rSuffix):
			return listener, true
		}
		return "", false
	}
}

// listenerAllowsHTTPRoute applies allowedRoutes.kinds; without kinds, a listener accepts the
// route kinds of its protocol, which include HTTPRoute for HTTP and HTTPS only.
func listenerAllowsHTTPRoute(l gatewayApiv1.Listener) bool {
	if l.AllowedRoutes == nil || len(l.AllowedRoutes.Kinds) == 0 {
		return l.Protocol == gatewayApiv1.HTTPProtocolType || l.Protocol == gatewayApiv1.HTTPSProtocolType
	}
	for _, k := range l.AllowedRoutes.Kinds {
		group := gatewayApiv1.GroupName
		if k.Group != nil {
			group = string(*k.Group)
		}
		if group == gatewayApiv1.GroupName && k.Kind == "HTTPRoute" {
			return true
		}
	}
	return false
}

// listenerAllowsNamespace applies allowedRoutes.namespaces (default Same). Only Selector reads the
// route namespace's labels.
func (r *HTTPRouteAllowlistingReconciler) listenerAllowsNamespace(ctx context.Context, l gatewayApiv1.Listener, routeNS, gatewayNS string) (bool, error) {
	from := gatewayApiv1.NamespacesFromSame
	var selector *metav1.LabelSelector
	if l.AllowedRoutes != nil && l.AllowedRoutes.Namespaces != nil {
		if l.AllowedRoutes.Namespaces.From != nil {
			from = *l.AllowedRoutes.Namespaces.From
		}
		selector = l.AllowedRoutes.Namespaces.Selector
	}
	switch from {
	case gatewayApiv1.NamespacesFromAll:
		return true, nil
	case gatewayApiv1.NamespacesFromSame:
		return routeNS == gatewayNS, nil
	case gatewayApiv1.NamespacesFromSelector:
		if selector == nil {
			return false, nil
		}
		sel, err := metav1.LabelSelectorAsSelector(selector)
		if err != nil {
			return false, nil // an invalid selector accepts nothing
		}
		nsLabels, err := r.namespaceLabels().get(ctx, routeNS)
		if err != nil {
			return false, err
		}
		return sel.Matches(nsLabels), nil
	default: // None, or a value this version doesn't know
		return false, nil
	}
}
