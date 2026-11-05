package writers

import (
	"context"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/retry"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	gatewayApiv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/adevinta/ingress-allowlisting-controller/pkg/resolvers"
)

const TraefikControllerName = "traefik.io/gateway-controller"

// TraefikL7Writer creates/deletes Traefik Middleware objects for HTTPRoute-level allowlisting.
// It does not support merge (Traefik Middleware is attached per-route, not per-gateway).
type TraefikL7Writer struct {
	client           client.Client
	managedBy        string
	annotationPrefix string
	cidrResolver     resolvers.CidrResolver
}

// NewTraefikL7Writer returns a new TraefikL7Writer.
func NewTraefikL7Writer(c client.Client, managedBy string, cidrResolver resolvers.CidrResolver) *TraefikL7Writer {
	return &TraefikL7Writer{
		client:           c,
		managedBy:        managedBy,
		annotationPrefix: cidrResolver.AnnotationPrefix,
		cidrResolver:     cidrResolver,
	}
}

// RequiredPermissions returns the RBAC permissions needed by this writer.
func (w *TraefikL7Writer) RequiredPermissions() []Permission {
	// list/watch: the middlewares are watched (Owns) and read through the cache. The middleware
	// filter is added to and removed from the HTTPRoute with a patch.
	return append(Permissions("traefik.io", "middlewares", "get", "list", "watch", "create", "update", "delete"),
		Permissions("gateway.networking.k8s.io", "httproutes", "patch")...)
}

func (w *TraefikL7Writer) applyLabels(middleware *TraefikMiddleware, ownerNamespace, ownerName string) {
	setOwnerLabels(middleware, w.annotationPrefix, w.managedBy, OwnerKindHTTPRoute, ownerNamespace, ownerName)
}

// Apply creates or updates a Traefik Middleware with an IPAllowList for the given HTTPRoute,
// then patches the HTTPRoute so every rule references the Middleware via an extensionRef filter.
//
// The Middleware is always placed in the route's own namespace so the HTTPRoute can reference
// it via extensionRef (which uses LocalObjectReference — no cross-namespace field).
func (w *TraefikL7Writer) Apply(ctx context.Context, scheme *runtime.Scheme, route *gatewayApiv1.HTTPRoute, _ *gatewayApiv1.Gateway, ips, hosts, paths []string) error {
	middleware := &TraefikMiddleware{
		ObjectMeta: metav1.ObjectMeta{Name: route.Name, Namespace: route.Namespace},
	}
	op, err := ctrl.CreateOrUpdate(ctx, w.client, middleware, func() error {
		// ResourceVersion is set only when the Middleware exists. One that isn't ours is left
		// alone, and the route doesn't get a filter to it: it would use someone else's allowlist.
		if middleware.ResourceVersion != "" && !isOurs(middleware, w.annotationPrefix, w.managedBy, OwnerKindHTTPRoute, route.Namespace, route.Name, "") {
			return notOurs("Middleware", middleware, "HTTPRoute "+route.Namespace+"/"+route.Name)
		}
		if err := ctrl.SetControllerReference(route, middleware, scheme); err != nil {
			return err
		}
		w.applyLabels(middleware, route.Namespace, route.Name)
		middleware.Spec = TraefikMiddlewareSpec{
			IPAllowList: &TraefikIPAllowList{SourceRange: ips},
		}
		return nil
	})
	if err != nil {
		return err
	}
	logChange(ctx, op, "Middleware", middleware, "HTTPRoute "+route.Namespace+"/"+route.Name)
	return w.ensureHTTPRouteFilters(ctx, client.ObjectKeyFromObject(route), route.Name)
}

// patchRouteRules reads the HTTPRoute, lets change edit its rules, and patches it if change
// reports a change. The patch replaces spec.rules as a whole, so it carries the resourceVersion:
// if the route changed since the read, the API server refuses it, and it is done again on the new
// route instead of writing the old rules back over the other change. A route that is gone is no
// error.
func (w *TraefikL7Writer) patchRouteRules(ctx context.Context, key client.ObjectKey, change func(*gatewayApiv1.HTTPRoute) bool, what string) error {
	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		route := &gatewayApiv1.HTTPRoute{}
		if err := w.client.Get(ctx, key, route); err != nil {
			return client.IgnoreNotFound(err)
		}
		patch := client.MergeFromWithOptions(route.DeepCopy(), client.MergeFromWithOptimisticLock{})
		if !change(route) {
			return nil
		}
		if err := w.client.Patch(ctx, route, patch); err != nil {
			return err
		}
		logChange(ctx, controllerutil.OperationResultUpdated, "HTTPRoute", route, what)
		return nil
	})
}

// ensureHTTPRouteFilters adds an extensionRef filter pointing to mwName to any HTTPRoute rule
// that doesn't already have one. It is idempotent.
func (w *TraefikL7Writer) ensureHTTPRouteFilters(ctx context.Context, key client.ObjectKey, mwName string) error {
	filter := traefikFilter(mwName)
	return w.patchRouteRules(ctx, key, func(route *gatewayApiv1.HTTPRoute) bool {
		changed := false
		for i := range route.Spec.Rules {
			if !hasTraefikFilter(route.Spec.Rules[i].Filters, mwName) {
				route.Spec.Rules[i].Filters = append(route.Spec.Rules[i].Filters, filter)
				changed = true
			}
		}
		return changed
	}, "Middleware filter "+mwName+" added")
}

// traefikFilter is the filter that attaches the Middleware mwName to a route rule. Adding
// (ensureHTTPRouteFilters) and removing (removeHTTPRouteFilters) must agree on it exactly: a filter
// that removal doesn't recognise would stay on the route and point at a deleted Middleware.
func traefikFilter(mwName string) gatewayApiv1.HTTPRouteFilter {
	return gatewayApiv1.HTTPRouteFilter{
		Type: gatewayApiv1.HTTPRouteFilterExtensionRef,
		ExtensionRef: &gatewayApiv1.LocalObjectReference{
			Group: gatewayApiv1.Group("traefik.io"),
			Kind:  gatewayApiv1.Kind("Middleware"),
			Name:  gatewayApiv1.ObjectName(mwName),
		},
	}
}

// isTraefikFilter reports whether f is traefikFilter(mwName).
func isTraefikFilter(f gatewayApiv1.HTTPRouteFilter, mwName string) bool {
	want := traefikFilter(mwName)
	return f.Type == want.Type && f.ExtensionRef != nil && *f.ExtensionRef == *want.ExtensionRef
}

func hasTraefikFilter(filters []gatewayApiv1.HTTPRouteFilter, mwName string) bool {
	for _, f := range filters {
		if isTraefikFilter(f, mwName) {
			return true
		}
	}
	return false
}

// ListManaged returns all Traefik Middlewares managed by this controller.
func (w *TraefikL7Writer) ListManaged(ctx context.Context, managedBy string) ([]client.Object, error) {
	list := &TraefikMiddlewareList{}
	if err := w.client.List(ctx, list, managedByUs(w.annotationPrefix, managedBy)...); err != nil {
		return nil, err
	}
	var result []client.Object
	for i := range list.Items {
		result = append(result, &list.Items[i])
	}
	return keepKinds(result, w.annotationPrefix, OwnerKindHTTPRoute), nil
}

// IsOrphaned reports whether the given Middleware no longer has a valid owner HTTPRoute.
func (w *TraefikL7Writer) IsOrphaned(obj client.Object, allRoutes []gatewayApiv1.HTTPRoute) bool {
	ownerNS := obj.GetLabels()[w.annotationPrefix+"/owner-namespace"]
	ownerName := obj.GetLabels()[w.annotationPrefix+"/owner-name"]

	// Labels are stored via LabelSafe(), so we must compare using LabelSafe() on both sides.
	for i := range allRoutes {
		r := &allRoutes[i]
		if LabelSafe(r.Namespace) == ownerNS && LabelSafe(r.Name) == ownerName {
			return false
		}
	}
	return true
}

// Delete removes the given Middleware from the cluster.
func (w *TraefikL7Writer) Delete(ctx context.Context, obj client.Object) error {
	return client.IgnoreNotFound(w.client.Delete(ctx, obj))
}

// DeleteForRoute deletes all Middlewares owned by the given route and removes the
// extensionRef filter from the HTTPRoute's rules, unless the Middleware it points to isn't ours.
func (w *TraefikL7Writer) DeleteForRoute(ctx context.Context, managedBy, routeNamespace, routeName string) error {
	list := &TraefikMiddlewareList{}
	if err := w.client.List(ctx, list, ownedBy(w.annotationPrefix, managedBy, routeNamespace, routeName)...); err != nil {
		return err
	}
	for i := range list.Items {
		if ownerKind(&list.Items[i], w.annotationPrefix) != OwnerKindHTTPRoute {
			continue
		}
		if err := deleteLogged(ctx, w.client, &list.Items[i], "Middleware", "HTTPRoute "+routeNamespace+"/"+routeName+" no longer uses this writer"); err != nil {
			return err
		}
	}

	// The filter points to the Middleware named after the route. If that one isn't ours, the
	// filter is someone else's too (e.g. a team's own Middleware): it stays.
	named := &TraefikMiddleware{}
	err := w.client.Get(ctx, types.NamespacedName{Namespace: routeNamespace, Name: routeName}, named)
	if client.IgnoreNotFound(err) != nil {
		return err
	}
	if err == nil && !isOurs(named, w.annotationPrefix, w.managedBy, OwnerKindHTTPRoute, routeNamespace, routeName, "") {
		return nil
	}

	return w.removeHTTPRouteFilters(ctx, types.NamespacedName{Namespace: routeNamespace, Name: routeName}, routeName)
}

// removeHTTPRouteFilters removes the extensionRef filter pointing to mwName from every rule.
func (w *TraefikL7Writer) removeHTTPRouteFilters(ctx context.Context, key client.ObjectKey, mwName string) error {
	return w.patchRouteRules(ctx, key, func(route *gatewayApiv1.HTTPRoute) bool {
		changed := false
		for i := range route.Spec.Rules {
			kept := route.Spec.Rules[i].Filters[:0]
			for _, f := range route.Spec.Rules[i].Filters {
				if isTraefikFilter(f, mwName) {
					changed = true
					continue
				}
				kept = append(kept, f)
			}
			route.Spec.Rules[i].Filters = kept
		}
		return changed
	}, "Middleware filter "+mwName+" removed")
}
