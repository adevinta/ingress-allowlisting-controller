package controllers

import (
	"context"
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

// routeAllowedByParentRef reports whether the Gateway accepts the route through this parentRef,
// following the Gateway API attachment rules on the listeners the parentRef targets
// (sectionName, port): allowedRoutes.kinds and allowedRoutes.namespaces. Listener hostnames are
// not checked. A route the Gateway doesn't accept serves no traffic there, but an Istio
// AuthorizationPolicy written for it would still apply to the Gateway by host, so no policy may be
// written for it.
func (r *HTTPRouteAllowlistingReconciler) routeAllowedByParentRef(ctx context.Context, route *gatewayApiv1.HTTPRoute, ref gatewayApiv1.ParentReference, gw *gatewayApiv1.Gateway) (bool, error) {
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
			return false, err
		}
		if ok {
			return true, nil
		}
	}
	return false, nil
}

// routeAllowedByGateway reports whether the Gateway accepts the route through any of the route's
// parentRefs that point to it.
func (r *HTTPRouteAllowlistingReconciler) routeAllowedByGateway(ctx context.Context, route *gatewayApiv1.HTTPRoute, gw *gatewayApiv1.Gateway) (bool, error) {
	for _, ref := range gateway.GatewayParentRefs(route) {
		refNS := route.Namespace
		if ref.Namespace != nil {
			refNS = string(*ref.Namespace)
		}
		if string(ref.Name) != gw.Name || refNS != gw.Namespace {
			continue
		}
		ok, err := r.routeAllowedByParentRef(ctx, route, ref, gw)
		if err != nil || ok {
			return ok, err
		}
	}
	return false, nil
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
