package controllers

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"sync"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	workqueue "k8s.io/client-go/util/workqueue"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	istiosecurityv1 "istio.io/client-go/pkg/apis/security/v1"
	gatewayApiv1 "sigs.k8s.io/gateway-api/apis/v1"

	log "github.com/adevinta/go-log-toolkit"
	ipamv1alpha1 "github.com/adevinta/ingress-allowlisting-controller/pkg/apis/ipam.adevinta.com/v1alpha1"
	"github.com/adevinta/ingress-allowlisting-controller/pkg/controllers/internal"
	"github.com/adevinta/ingress-allowlisting-controller/pkg/controllers/writers"
	"github.com/adevinta/ingress-allowlisting-controller/pkg/resolvers"
)

type HTTPRouteAllowlistingReconciler struct {
	client.Client
	APIReader    client.Reader // bypasses cache — used by startup cleanup to confirm deletions and for namespace labels
	Scheme       *runtime.Scheme
	Prefix       string
	CidrResolver resolvers.CidrResolver
	L7Writers    writers.L7WriterRegistry

	nsLabelsOnce sync.Once
	nsLabels     *namespaceLabelCache // allowedRoutes namespace selectors, see namespaceLabels()
}

// +kubebuilder:rbac:groups="",resources=namespaces,verbs=get
// +kubebuilder:rbac:groups=ipam.adevinta.com,resources=cidrs,verbs=get;list;watch
// +kubebuilder:rbac:groups=ipam.adevinta.com,resources=clustercidrs,verbs=get;list;watch
// +kubebuilder:rbac:groups=gateway.networking.k8s.io,resources=httproutes,verbs=get;list;watch;patch
// +kubebuilder:rbac:groups=gateway.networking.k8s.io,resources=gateways,verbs=get;list;watch
// +kubebuilder:rbac:groups=gateway.networking.k8s.io,resources=gatewayclasses,verbs=get;list;watch
// +kubebuilder:rbac:groups=security.istio.io,resources=authorizationpolicies,verbs=get;list;watch;create;update;delete
// +kubebuilder:rbac:groups=traefik.io,resources=middlewares,verbs=get;list;watch;create;update;delete

func (r *HTTPRouteAllowlistingReconciler) mergeAnnotation() string {
	return r.CidrResolver.AnnotationPrefix + "/merge"
}

func (r *HTTPRouteAllowlistingReconciler) granularityAnnotation() string {
	return r.CidrResolver.AnnotationPrefix + "/granularity"
}

func (r *HTTPRouteAllowlistingReconciler) managedByValue() string {
	return managedByLabel(r.Prefix)
}

func (r *HTTPRouteAllowlistingReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := log.DefaultLogger.WithContext(ctx).WithField("httproute", req.NamespacedName)

	httproute := gatewayApiv1.HTTPRoute{}
	if err := r.Get(ctx, req.NamespacedName, &httproute); err != nil {
		if client.IgnoreNotFound(err) != nil {
			return ctrl.Result{}, err
		}
		// Route not found — it was deleted or evicted from the cache (e.g. watch-selector label removed).
		// Clean up any policies that were created for it, and its metrics series.
		resolvers.ForgetObject(req.Namespace, "HTTPRoute", req.Name)
		for _, writer := range r.L7Writers {
			if err := writer.DeleteForRoute(ctx, r.managedByValue(), req.Namespace, req.Name); err != nil {
				return ctrl.Result{}, err
			}
		}
		return ctrl.Result{}, nil
	}
	log.Debugf("HTTPRoute %s being reconciled. Creating/updating writers...", httproute.GetName())

	parentRefs := gateway.GatewayParentRefs(&httproute)

	mergeKey := httproute.Annotations[r.mergeAnnotation()]
	if mergeKey != "" {
		if err := writers.ValidateMergeKey(mergeKey); err != nil {
			// Ignored: the route is handled as one without a merge key, so its own policies keep
			// following its CIDRs. Stopping here would freeze them with the old CIDRs, or leave a new
			// route with no policy at all. The startup cleanup ignores the key too (IsOrphaned).
			msg := fmt.Sprintf("%v: ignored, the route gets its own policies until it is fixed", err)
			log.Warnf("HTTPRoute %s/%s: %s", httproute.Namespace, httproute.Name, msg)
			r.CidrResolver.WarningEvent(&httproute, "InvalidMergeKey", "ReadMergeKey", msg)
			mergeKey = ""
		}
	}
	if mergeKey == "" {
		// Route is not in merge mode — clean up any stale merged APs where this route was the last member.
		if err := r.cleanupOrphanedMergedAPs(ctx, &httproute, parentRefs); err != nil {
			return ctrl.Result{}, err
		}
	}

	granularity := httproute.Annotations[r.granularityAnnotation()]

	// Lazy CIDR resolution: only needed for per-route writers (Traefik always, Istio without mergeKey).
	// Merge-mode routes (Istio + mergeKey) resolve all siblings' CIDRs inside ApplyMerged, so
	// resolving the current route here would be wasted work if no per-route writer is present.
	var allowedIps []string
	var cidrErr error
	var cidrResolved bool
	resolveCIDRs := func() {
		if !cidrResolved {
			allowedIps, cidrErr = r.CidrResolver.GetCidrsFromObject(ctx, &httproute)
			cidrResolved = true
		}
	}

	// invokedWriters tracks which writers were used in this reconcile.
	// Any registered writer not present here had its gateway removed from parentRefs
	// and must have its stale policies cleaned up after the loop.
	invokedWriters := map[string]struct{}{}
	// refusedRefs are the parentRefs whose Gateway doesn't accept the route.
	var refusedRefs []gatewayApiv1.ParentReference
	// mergeRefused are the mergeable writers whose merged policy couldn't be written (one with that
	// name isn't ours): the route keeps its own policies there, see below.
	mergeRefused := map[string]bool{}

	for _, ref := range parentRefs {
		gatewayNS := httproute.Namespace
		if ref.Namespace != nil {
			gatewayNS = string(*ref.Namespace)
		}
		gateway := &gatewayApiv1.Gateway{}
		if err := r.Get(ctx, types.NamespacedName{Name: string(ref.Name), Namespace: gatewayNS}, gateway); err != nil {
			if client.IgnoreNotFound(err) != nil {
				return ctrl.Result{}, err
			}
			log.Infof("gateway %s/%s not found, skipping parentRef", gatewayNS, ref.Name)
			continue
		}
		gwClass := &gatewayApiv1.GatewayClass{}
		if err := r.Get(ctx, types.NamespacedName{Name: string(gateway.Spec.GatewayClassName)}, gwClass); err != nil {
			if client.IgnoreNotFound(err) != nil {
				return ctrl.Result{}, err
			}
			log.Infof("GatewayClass %s not found, skipping parentRef", gateway.Spec.GatewayClassName)
			continue
		}
		writer, ok := r.L7Writers[string(gwClass.Spec.ControllerName)]
		if !ok {
			log.Infof("no L7 writer for controller %s, skipping", gwClass.Spec.ControllerName)
			continue
		}
		controllerName := string(gwClass.Spec.ControllerName)

		// Only the hostnames the Gateway routes for the route here, and no policy at all for a route
		// it doesn't attach: an Istio AP applies to the whole Gateway by host, so one for other
		// hostnames would allow the route's CIDRs on other routes' hosts, e.g. another tenant's.
		hostnames, refusal, err := r.routeHostnamesOnParentRef(ctx, &httproute, ref, gateway)
		if err != nil {
			return ctrl.Result{}, err
		}
		allowed := refusal == ""
		if !allowed {
			log.Warnf("HTTPRoute %s/%s is not attached to gateway %s/%s, %s: no policy for it on this gateway",
				httproute.Namespace, httproute.GetName(), gateway.Namespace, gateway.Name, refusal)
		}

		// Mergeable writers (e.g. Istio) with a merge annotation share one AP across the group.
		// Non-mergeable writers (e.g. Traefik) always get a per-route policy regardless of mergeKey.
		if mw, ok := writer.(writers.MergeableL7PolicyWriter); ok && mergeKey != "" {
			// Even when this route isn't allowed: the merged AP is rewritten without it.
			invokedWriters[controllerName] = struct{}{}
			err := r.reconcileMergedGateway(ctx, &httproute, gateway, mw, mergeKey)
			if errors.Is(err, writers.ErrPolicyNotManaged) {
				mergeRefused[controllerName] = true
			}
			if err := notManaged(ctx, r.CidrResolver, "HTTPRoute", &httproute, err); err != nil {
				return ctrl.Result{}, err
			}
			continue
		}

		if !allowed {
			// Not marked as invoked: unless another accepted parentRef uses this writer, the
			// cleanup after the loop deletes its policies for the route. Otherwise the stale
			// cleanup below no longer counts this parentRef.
			refusedRefs = append(refusedRefs, ref)
			continue
		}

		// Per-route apply path — Traefik always, Istio when no mergeKey.
		resolveCIDRs()
		if errors.Is(cidrErr, resolvers.ErrAnnotationNotFound) {
			if err := writer.DeleteForRoute(ctx, r.managedByValue(), httproute.Namespace, httproute.Name); err != nil {
				return ctrl.Result{}, err
			}
			invokedWriters[controllerName] = struct{}{}
			continue
		}
		if cidrErr != nil {
			return ctrl.Result{}, cidrErr
		}

		var rulePaths [][]string
		if granularity == "" || granularity == "rule" {
			rulePaths = make([][]string, len(httproute.Spec.Rules))
			for i, rule := range httproute.Spec.Rules {
				rulePaths[i] = translatePaths(writer, rule.Matches)
			}
		}

		switch granularity {
		case "host":
			// One policy per route, host-matched, no path restriction.
			if err := notManaged(ctx, r.CidrResolver, "HTTPRoute", &httproute, writer.Apply(ctx, r.Scheme, &httproute, gateway, allowedIps, hostnames, nil)); err != nil {
				return ctrl.Result{}, err
			}
			log.Debugf("policy (host) created/updated for HTTPRoute %s → gateway %s/%s", httproute.GetName(), gateway.Namespace, gateway.Name)
		default:
			// granularity=rule (default): one policy per HTTPRoute rule.
			for ruleIdx, paths := range rulePaths {
				if err := notManaged(ctx, r.CidrResolver, "HTTPRoute", &httproute, writer.Apply(ctx, r.Scheme, &httproute, gateway, allowedIps, hostnames, paths)); err != nil {
					return ctrl.Result{}, err
				}
				log.Debugf("policy (rule) created/updated for HTTPRoute %s rule %d → gateway %s/%s", httproute.GetName(), ruleIdx, gateway.Namespace, gateway.Name)
			}
			// Fallback: HTTPRoute with no rules — single policy, no path restriction.
			if len(rulePaths) == 0 {
				if err := notManaged(ctx, r.CidrResolver, "HTTPRoute", &httproute, writer.Apply(ctx, r.Scheme, &httproute, gateway, allowedIps, hostnames, nil)); err != nil {
					return ctrl.Result{}, err
				}
				log.Debugf("policy (rule/fallback) created/updated for HTTPRoute %s → gateway %s/%s", httproute.GetName(), gateway.Namespace, gateway.Name)
			}
		}
		invokedWriters[controllerName] = struct{}{}
	}

	// A route in a merge group is in the merged policies now: its own policies, from before it
	// joined, go. They would otherwise stay until the next restart, frozen with the CIDRs it had
	// then, and keep allowing them next to the merged policy. Only once the merged policies are
	// written: where one was refused, the route's own policies are all it has.
	if mergeKey != "" {
		for controllerName := range invokedWriters {
			writer := r.L7Writers[controllerName]
			if _, ok := writer.(writers.MergeableL7PolicyWriter); !ok || mergeRefused[controllerName] {
				continue
			}
			if err := writer.DeleteForRoute(ctx, r.managedByValue(), httproute.Namespace, httproute.Name); err != nil {
				return ctrl.Result{}, err
			}
		}
	}

	// Delete all policies for writers that had no matching parentRef this reconcile.
	// This fires when a gateway is removed from the route's parentRefs while the route itself still exists.
	for controllerName, writer := range r.L7Writers {
		if _, used := invokedWriters[controllerName]; !used {
			if err := writer.DeleteForRoute(ctx, r.managedByValue(), httproute.Namespace, httproute.Name); err != nil {
				return ctrl.Result{}, err
			}
			log.Debugf("deleted stale policies for writer %s — no matching parentRef for HTTPRoute %s", controllerName, httproute.GetName())
		}
	}

	// Delete stale per-route policies that this reconcile no longer produces
	// (e.g. rule count reduced, granularity changed). Skipped for merge mode because
	// mergeable writers manage their own AP lifecycle via ApplyMerged/DeleteMerged.
	if mergeKey == "" {
		// Judge the route without the parentRefs its Gateways refused, so their APs are orphaned.
		produced := httproute.DeepCopy()
		if len(refusedRefs) > 0 {
			produced.Spec.ParentRefs = slices.DeleteFunc(produced.Spec.ParentRefs, func(ref gatewayApiv1.ParentReference) bool {
				return slices.ContainsFunc(refusedRefs, func(refused gatewayApiv1.ParentReference) bool { return reflect.DeepEqual(ref, refused) })
			})
		}
		for _, writer := range r.L7Writers {
			managed, err := writer.ListManaged(ctx, r.managedByValue())
			if err != nil {
				return ctrl.Result{}, err
			}
			for _, obj := range managed {
				ownerNS := obj.GetLabels()[r.CidrResolver.AnnotationPrefix+"/owner-namespace"]
				ownerName := obj.GetLabels()[r.CidrResolver.AnnotationPrefix+"/owner-name"]
				if ownerNS != writers.LabelSafe(httproute.Namespace) || ownerName != writers.LabelSafe(httproute.Name) {
					continue
				}
				if writer.IsOrphaned(obj, []gatewayApiv1.HTTPRoute{*produced}) {
					if err := writer.Delete(ctx, obj); err != nil {
						return ctrl.Result{}, err
					}
					log.Infof("Deleted stale policy %s/%s for HTTPRoute %s", obj.GetNamespace(), obj.GetName(), httproute.GetName())
				}
			}
		}
	}

	return ctrl.Result{}, nil
}

// cleanupRunnable returns a manager.Runnable that waits for the cache to sync and then
// runs orphan cleanup exactly once at startup, independent of the reconcile loop.
func cleanupRunnable(mgr ctrl.Manager, r *HTTPRouteAllowlistingReconciler) manager.Runnable {
	return manager.RunnableFunc(func(ctx context.Context) error {
		if !mgr.GetCache().WaitForCacheSync(ctx) {
			return nil
		}
		r.runStartupCleanup(ctx)
		return nil
	})
}

// runStartupCleanup lists all policies managed by this controller, checks whether the owning
// HTTPRoute still exists and would still produce that policy, and deletes any that are orphaned.
func (r *HTTPRouteAllowlistingReconciler) runStartupCleanup(ctx context.Context) {
	log := log.DefaultLogger.WithContext(ctx)
	log.Infof("Running post-startup orphan cleanup for managed policies")

	allRoutes := &gatewayApiv1.HTTPRouteList{}
	if err := r.APIReader.List(ctx, allRoutes); err != nil {
		log.Errorf("startup cleanup: failed to list HTTPRoutes: %v", err)
		return
	}

	for _, writer := range r.L7Writers {
		managed, err := writer.ListManaged(ctx, r.managedByValue())
		if err != nil {
			log.Errorf("startup cleanup: failed to list managed policies: %v", err)
			continue
		}
		if len(allRoutes.Items) == 0 && len(managed) > 0 {
			log.Infof("startup cleanup: no HTTPRoutes found but managed policies exist — skipping to avoid dirty-read deletions")
			continue
		}
		for _, obj := range managed {
			obj := obj
			shouldDelete := writer.IsOrphaned(obj, allRoutes.Items)
			if !shouldDelete {
				// Also delete if the owning route exists but lost its allowlist annotation —
				// the runtime DeleteForRoute would have handled this, but a restart may have missed it.
				ownerNS := obj.GetLabels()[r.CidrResolver.AnnotationPrefix+"/owner-namespace"]
				ownerName := obj.GetLabels()[r.CidrResolver.AnnotationPrefix+"/owner-name"]
				for i := range allRoutes.Items {
					route := &allRoutes.Items[i]
					if writers.LabelSafe(route.Namespace) == ownerNS && writers.LabelSafe(route.Name) == ownerName {
						if !hasAllowlistAnnotation(r.CidrResolver.AnnotationPrefix, route) {
							shouldDelete = true
						}
						break
					}
				}
			}
			if shouldDelete {
				if err := writer.Delete(ctx, obj); client.IgnoreNotFound(err) != nil {
					log.Errorf("startup cleanup: failed to delete %s/%s: %v", obj.GetNamespace(), obj.GetName(), err)
					continue
				}
				log.Infof("Startup cleanup: deleted orphaned policy %s/%s", obj.GetNamespace(), obj.GetName())
			}
		}
	}
}

// cleanupOrphanedMergedAPs checks whether the route just left a merge group as the last member.
// For each gateway the route is attached to, it looks for a merged AP whose group now has
// no remaining siblings in the cache — and confirms via APIReader before deleting.
//
// The merged AP's owner-name label holds LabelSafe(mergeKey), which differs from the key when it
// is longer than 63 characters: routes are matched on LabelSafe of their key, and the AP found is
// deleted as it is, since its name can't be rebuilt from the label. The routes are listed at most
// once per call (cache, then API), not once per merged AP.
func (r *HTTPRouteAllowlistingReconciler) cleanupOrphanedMergedAPs(ctx context.Context, httproute *gatewayApiv1.HTTPRoute, parentRefs []gatewayApiv1.ParentReference) error {
	log := log.DefaultLogger.WithContext(ctx)
	var cached, confirmed *gatewayApiv1.HTTPRouteList // listed on first need, once per call
	for _, ref := range parentRefs {
		gatewayNS := httproute.Namespace
		if ref.Namespace != nil {
			gatewayNS = string(*ref.Namespace)
		}
		gateway := &gatewayApiv1.Gateway{}
		if err := r.Get(ctx, types.NamespacedName{Name: string(ref.Name), Namespace: gatewayNS}, gateway); err != nil {
			if client.IgnoreNotFound(err) != nil {
				return err
			}
			continue
		}
		gwClass := &gatewayApiv1.GatewayClass{}
		if err := r.Get(ctx, types.NamespacedName{Name: string(gateway.Spec.GatewayClassName)}, gwClass); err != nil {
			if client.IgnoreNotFound(err) != nil {
				return err
			}
			continue
		}
		writer, ok := r.L7Writers[string(gwClass.Spec.ControllerName)]
		if !ok {
			continue
		}
		mw, ok := writer.(writers.MergeableL7PolicyWriter)
		if !ok {
			continue
		}

		managed, err := mw.ListManaged(ctx, r.managedByValue())
		if err != nil {
			return err
		}
		for _, obj := range managed {
			ownerNS := obj.GetLabels()[r.CidrResolver.AnnotationPrefix+"/owner-namespace"]
			if ownerNS != "MERGED" {
				continue
			}
			keyLabel := obj.GetLabels()[r.CidrResolver.AnnotationPrefix+"/owner-name"]
			// Only the merged policies of this Gateway: another Gateway of the namespace can have a
			// merge group with members there and none here. Skipped before the sibling checks, which
			// read the API directly.
			if keyLabel == "" || !mw.ServesGateway(obj, gateway) {
				continue
			}
			// Check cache: any sibling still in this group?
			if cached == nil {
				cached = &gatewayApiv1.HTTPRouteList{}
				if err := r.List(ctx, cached); err != nil {
					return err
				}
			}
			if r.hasMergeSibling(cached.Items, keyLabel, gateway) {
				continue
			}
			// Confirm via direct API read before deleting.
			if confirmed == nil {
				confirmed = &gatewayApiv1.HTTPRouteList{}
				if err := r.APIReader.List(ctx, confirmed); err != nil {
					return err
				}
			}
			if r.hasMergeSibling(confirmed.Items, keyLabel, gateway) {
				continue
			}
			if err := mw.Delete(ctx, obj); err != nil {
				return err
			}
			log.Infof("Deleted orphaned merged AuthorizationPolicy %s/%s: its merge group has no routes left on gateway %s", obj.GetNamespace(), obj.GetName(), gateway.Name)
		}
	}
	return nil
}

// hasMergeSibling reports whether one of routes is in the merge group whose merged AP has the
// owner-name label keyLabel (LabelSafe of the key) and points to gateway.
func (r *HTTPRouteAllowlistingReconciler) hasMergeSibling(routes []gatewayApiv1.HTTPRoute, keyLabel string, gateway *gatewayApiv1.Gateway) bool {
	for i := range routes {
		key := routes[i].Annotations[r.mergeAnnotation()]
		if key != "" && writers.LabelSafe(key) == keyLabel && httproutePointsToGateway(&routes[i], gateway.Name, gateway.Namespace) {
			return true
		}
	}
	return false
}

func (r *HTTPRouteAllowlistingReconciler) reconcileMergedGateway(ctx context.Context, httproute *gatewayApiv1.HTTPRoute, gateway *gatewayApiv1.Gateway, writer writers.MergeableL7PolicyWriter, mergeKey string) error {
	log := log.DefaultLogger.WithContext(ctx)

	allRoutes := &gatewayApiv1.HTTPRouteList{}
	if err := r.List(ctx, allRoutes); err != nil {
		return err
	}

	var siblings []*gatewayApiv1.HTTPRoute
	for idx := range allRoutes.Items {
		sibling := &allRoutes.Items[idx]
		if sibling.Annotations[r.mergeAnnotation()] != mergeKey {
			continue
		}
		if !httproutePointsToGateway(sibling, gateway.Name, gateway.Namespace) {
			continue
		}
		// Siblings the Gateway doesn't attach are left out of the merged AP, and the others enter it
		// with only the hostnames the Gateway routes for them (see routeHostnamesOnParentRef).
		hostnames, attached, err := r.routeHostnamesOnGateway(ctx, sibling, gateway)
		if err != nil {
			return err
		}
		if !attached {
			continue
		}
		sibling = sibling.DeepCopy()
		sibling.Spec.Hostnames = nil
		for _, h := range hostnames {
			sibling.Spec.Hostnames = append(sibling.Spec.Hostnames, gatewayApiv1.Hostname(h))
		}
		siblings = append(siblings, sibling)
	}

	if len(siblings) == 0 {
		// Cache shows no siblings — confirm via direct API read before deleting,
		// to avoid removing the AP on a dirty cache read (same guard as startup cleanup).
		confirmed := &gatewayApiv1.HTTPRouteList{}
		if err := r.APIReader.List(ctx, confirmed); err != nil {
			return err
		}
		for _, route := range confirmed.Items {
			if route.Annotations[r.mergeAnnotation()] != mergeKey ||
				!httproutePointsToGateway(&route, gateway.Name, gateway.Namespace) {
				continue
			}
			_, attached, err := r.routeHostnamesOnGateway(ctx, &route, gateway)
			if err != nil {
				return err
			}
			if attached {
				return nil // cache was stale — sibling still exists, skip deletion
			}
		}
		if err := writer.DeleteMerged(ctx, gateway, mergeKey); err != nil {
			return err
		}
		log.Debugf("Deleted merged AuthorizationPolicy for empty group %q → gateway %s/%s", mergeKey, gateway.Namespace, gateway.Name)
		return nil
	}

	if err := writer.ApplyMerged(ctx, gateway, siblings, mergeKey); err != nil {
		return err
	}
	log.Debugf("Merged AuthorizationPolicy created/updated for merge group %q → gateway %s/%s", mergeKey, gateway.Namespace, gateway.Name)
	return nil
}

// mergeSiblingEnqueuer returns an EventHandler that, when an HTTPRoute's merge annotation
// changes, enqueues all remaining members of the old merge group so they rebuild their AP
// without the departed route's stale data.
func (r *HTTPRouteAllowlistingReconciler) mergeSiblingEnqueuer() handler.EventHandler {
	return handler.Funcs{
		UpdateFunc: func(ctx context.Context, e event.UpdateEvent, q workqueue.TypedRateLimitingInterface[reconcile.Request]) {
			oldKey := e.ObjectOld.GetAnnotations()[r.mergeAnnotation()]
			newKey := e.ObjectNew.GetAnnotations()[r.mergeAnnotation()]
			if oldKey == newKey || oldKey == "" {
				return // no merge key change — nothing to do
			}
			// Route left merge group oldKey — enqueue all current members so they rebuild
			routes := &gatewayApiv1.HTTPRouteList{}
			if err := r.List(ctx, routes); err != nil {
				// Only this requeue rebuilds the old group's merged policy, so until then it still
				// allows the route that left.
				log.DefaultLogger.WithContext(ctx).Errorf("dropped merge group change of HTTPRoute %s: listing %T failed, the merged AuthorizationPolicy of group %q keeps the route until a member of the group changes or the resync: %v",
					client.ObjectKeyFromObject(e.ObjectNew), routes, oldKey, err)
				return
			}
			for _, route := range routes.Items {
				if route.Annotations[r.mergeAnnotation()] == oldKey {
					q.Add(reconcile.Request{NamespacedName: types.NamespacedName{
						Namespace: route.Namespace,
						Name:      route.Name,
					}})
				}
			}
		},
	}
}

func httproutePointsToGateway(httproute *gatewayApiv1.HTTPRoute, gatewayName, gatewayNamespace string) bool {
	for _, ref := range gateway.GatewayParentRefs(httproute) {
		if string(ref.Name) != gatewayName {
			continue
		}
		// nil Namespace means same namespace as the route — resolve it before comparing.
		refNS := httproute.Namespace
		if ref.Namespace != nil {
			refNS = string(*ref.Namespace)
		}
		if refNS == gatewayNamespace {
			return true
		}
	}
	return false
}

// translatePaths delegates path translation to the writer if it implements PathTranslator,
// falling back to raw path values for writers that handle their own path semantics.
func translatePaths(writer writers.L7PolicyWriter, matches []gatewayApiv1.HTTPRouteMatch) []string {
	if pt, ok := writer.(writers.PathTranslator); ok {
		return pt.TranslatePaths(matches)
	}
	var paths []string
	for _, match := range matches {
		if match.Path != nil && match.Path.Value != nil {
			paths = append(paths, *match.Path.Value)
		}
	}
	return paths
}

func hasAllowlistAnnotation(annotationPrefix string, obj client.Object) bool {
	a := obj.GetAnnotations()
	_, hasLocal := a[annotationPrefix+"/allowlist-group"]
	_, hasCluster := a[annotationPrefix+"/cluster-allowlist-group"]
	return hasLocal || hasCluster
}

// l7OwnedTypes are the types the HTTPRoute controller watches as its own: those of its writers,
// see l4OwnedTypes.
func l7OwnedTypes(l7 writers.L7WriterRegistry) []client.Object {
	var owned []client.Object
	if _, ok := l7[writers.IstioControllerName]; ok {
		owned = append(owned, &istiosecurityv1.AuthorizationPolicy{})
	}
	if _, ok := l7[writers.TraefikControllerName]; ok {
		owned = append(owned, &writers.TraefikMiddleware{})
	}
	return owned
}

func (r *HTTPRouteAllowlistingReconciler) SetupWithManager(mgr ctrl.Manager, namePrefix string) error {
	r.Prefix = namePrefix
	r.APIReader = mgr.GetAPIReader()
	annotationPredicate := predicate.Funcs{
		CreateFunc: func(e event.CreateEvent) bool {
			return hasAllowlistAnnotation(r.CidrResolver.AnnotationPrefix, e.Object)
		},
		DeleteFunc: func(e event.DeleteEvent) bool {
			return hasAllowlistAnnotation(r.CidrResolver.AnnotationPrefix, e.Object)
		},
		GenericFunc: func(e event.GenericEvent) bool {
			return hasAllowlistAnnotation(r.CidrResolver.AnnotationPrefix, e.Object)
		},
		// Check both old and new: annotation removal must trigger reconcile to clean up the AuthorizationPolicy.
		UpdateFunc: func(e event.UpdateEvent) bool {
			return hasAllowlistAnnotation(r.CidrResolver.AnnotationPrefix, e.ObjectNew) || hasAllowlistAnnotation(r.CidrResolver.AnnotationPrefix, e.ObjectOld)
		},
	}

	if err := mgr.Add(cleanupRunnable(mgr, r)); err != nil {
		return err
	}

	build := ctrl.NewControllerManagedBy(mgr).
		For(&gatewayApiv1.HTTPRoute{}, builder.WithPredicates(annotationPredicate))
	for _, owned := range l7OwnedTypes(r.L7Writers) {
		build = build.Owns(owned)
	}
	build = build.
		Watches(
			&ipamv1alpha1.CIDRs{},
			handler.EnqueueRequestsFromMapFunc(newHTTPRoutesFromCIDRFuncMap(r.Client, r.CidrResolver.Annotation()))).
		Watches(
			&ipamv1alpha1.ClusterCIDRs{},
			handler.EnqueueRequestsFromMapFunc(newHTTPRoutesFromCIDRFuncMap(r.Client, r.CidrResolver.ClusterAnnotation()))).
		Watches(
			&gatewayApiv1.HTTPRoute{},
			r.mergeSiblingEnqueuer(),
			builder.WithPredicates(predicate.Funcs{
				CreateFunc:  func(e event.CreateEvent) bool { return false },
				DeleteFunc:  func(e event.DeleteEvent) bool { return false },
				GenericFunc: func(e event.GenericEvent) bool { return false },
				UpdateFunc: func(e event.UpdateEvent) bool {
					oldKey := e.ObjectOld.GetAnnotations()[r.mergeAnnotation()]
					newKey := e.ObjectNew.GetAnnotations()[r.mergeAnnotation()]
					return oldKey != newKey && oldKey != ""
				},
			}))
	if namePrefix != "" {
		build = build.Named(namePrefix + "-httproute")
	}
	return build.Complete(r)
}

func newHTTPRoutesFromCIDRFuncMap(c client.Client, annotation string) handler.MapFunc {
	return newObjectsFromCIDRFuncMap(c, func() client.ObjectList { return &gatewayApiv1.HTTPRouteList{} }, annotation)
}
