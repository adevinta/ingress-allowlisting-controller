package controllers

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	workqueue "k8s.io/client-go/util/workqueue"

	istiosecurityv1 "istio.io/client-go/pkg/apis/security/v1"
	gatewayApiv1 "sigs.k8s.io/gateway-api/apis/v1"

	log "github.com/adevinta/go-log-toolkit"
	ipamv1alpha1 "github.com/adevinta/ingress-allowlisting-controller/pkg/apis/ipam.adevinta.com/v1alpha1"
	ipamv1alpha1_legacy "github.com/adevinta/ingress-allowlisting-controller/pkg/apis/legacy/v1alpha1"
	"github.com/adevinta/ingress-allowlisting-controller/pkg/controllers/internal"
	"github.com/adevinta/ingress-allowlisting-controller/pkg/controllers/writers"
	"github.com/adevinta/ingress-allowlisting-controller/pkg/resolvers"
)

type HTTPRouteAllowlistingReconciler struct {
	client.Client
	APIReader          client.Reader // bypasses cache — used only by startup cleanup to confirm deletions
	Scheme             *runtime.Scheme
	LegacyGroupVersion string
	Prefix             string
	CidrResolver       resolvers.CidrResolver
	L7Writers          writers.L7WriterRegistry
}

// +kubebuilder:rbac:groups=ipam.adevinta.com,resources=cidrs,verbs=get;list;watch
// +kubebuilder:rbac:groups=ipam.adevinta.com,resources=clustercidrs,verbs=get;list;watch
// +kubebuilder:rbac:groups=gateway.networking.k8s.io,resources=httproutes,verbs=get;list;watch;update
// +kubebuilder:rbac:groups=gateway.networking.k8s.io,resources=gateways,verbs=get;list;watch
// +kubebuilder:rbac:groups=gateway.networking.k8s.io,resources=gatewayclasses,verbs=get;list;watch
// +kubebuilder:rbac:groups=security.istio.io,resources=authorizationpolicies,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=traefik.io,resources=middlewares,verbs=get;list;watch;create;update;delete

func (r *HTTPRouteAllowlistingReconciler) mergeAnnotation() string {
	return r.CidrResolver.AnnotationPrefix + "/merge"
}

func (r *HTTPRouteAllowlistingReconciler) granularityAnnotation() string {
	return r.CidrResolver.AnnotationPrefix + "/granularity"
}

func (r *HTTPRouteAllowlistingReconciler) managedByValue() string {
	if r.Prefix != "" {
		return r.Prefix + "-ingress-allowlisting-controller"
	}
	return "ingress-allowlisting-controller"
}

func (r *HTTPRouteAllowlistingReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := log.DefaultLogger.WithContext(ctx).WithField("httproute", req.NamespacedName)

	httproute := gatewayApiv1.HTTPRoute{}
	if err := r.Get(ctx, req.NamespacedName, &httproute); err != nil {
		if client.IgnoreNotFound(err) != nil {
			return ctrl.Result{}, err
		}
		// Route not found — it was deleted or evicted from the cache (e.g. watch-selector label removed).
		// Clean up any policies that were created for it.
		for _, writer := range r.L7Writers {
			if err := writer.DeleteForRoute(ctx, r.managedByValue(), req.Namespace, req.Name); err != nil {
				return ctrl.Result{}, err
			}
		}
		return ctrl.Result{}, nil
	}
	log.Infof("HTTPRoute %s being reconciled. Creating/updating writers...", httproute.GetName())

	parentRefs := gateway.GatewayParentRefs(&httproute)

	mergeKey := httproute.Annotations[r.mergeAnnotation()]
	if mergeKey != "" {
		if err := validateMergeKey(mergeKey); err != nil {
			log.Errorf("HTTPRoute %s/%s has invalid merge key: %v", httproute.Namespace, httproute.GetName(), err)
			return ctrl.Result{}, nil
		}
	} else {
		// Route is not in merge mode — clean up any stale merged APs where this route was the last member.
		if err := r.cleanupOrphanedMergedAPs(ctx, &httproute, parentRefs); err != nil {
			return ctrl.Result{}, err
		}
	}

	var hostnames []string
	for _, h := range httproute.Spec.Hostnames {
		hostnames = append(hostnames, string(h))
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

		// Mergeable writers (e.g. Istio) with a merge annotation share one AP across the group.
		// Non-mergeable writers (e.g. Traefik) always get a per-route policy regardless of mergeKey.
		if mw, ok := writer.(writers.MergeableL7PolicyWriter); ok && mergeKey != "" {
			invokedWriters[controllerName] = struct{}{}
			if err := r.reconcileMergedGateway(ctx, &httproute, gateway, mw, mergeKey); err != nil {
				return ctrl.Result{}, err
			}
			continue
		}

		// Per-route apply path — Traefik always, Istio when no mergeKey.
		resolveCIDRs()
		if cidrErr == r.CidrResolver.AnnotationNotFoundError() {
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
			if err := writer.Apply(ctx, r.Scheme, &httproute, gateway, allowedIps, hostnames, nil); err != nil {
				return ctrl.Result{}, err
			}
			log.Infof("policy (host) created/updated for HTTPRoute %s → gateway %s/%s", httproute.GetName(), gateway.Namespace, gateway.Name)
		default:
			// granularity=rule (default): one policy per HTTPRoute rule.
			for ruleIdx, paths := range rulePaths {
				if err := writer.Apply(ctx, r.Scheme, &httproute, gateway, allowedIps, hostnames, paths); err != nil {
					return ctrl.Result{}, err
				}
				log.Infof("policy (rule) created/updated for HTTPRoute %s rule %d → gateway %s/%s", httproute.GetName(), ruleIdx, gateway.Namespace, gateway.Name)
			}
			// Fallback: HTTPRoute with no rules — single policy, no path restriction.
			if len(rulePaths) == 0 {
				if err := writer.Apply(ctx, r.Scheme, &httproute, gateway, allowedIps, hostnames, nil); err != nil {
					return ctrl.Result{}, err
				}
				log.Infof("policy (rule/fallback) created/updated for HTTPRoute %s → gateway %s/%s", httproute.GetName(), gateway.Namespace, gateway.Name)
			}
		}
		invokedWriters[controllerName] = struct{}{}
	}

	// Delete all policies for writers that had no matching parentRef this reconcile.
	// This fires when a gateway is removed from the route's parentRefs while the route itself still exists.
	for controllerName, writer := range r.L7Writers {
		if _, used := invokedWriters[controllerName]; !used {
			if err := writer.DeleteForRoute(ctx, r.managedByValue(), httproute.Namespace, httproute.Name); err != nil {
				return ctrl.Result{}, err
			}
			log.Infof("deleted stale policies for writer %s — no matching parentRef for HTTPRoute %s", controllerName, httproute.GetName())
		}
	}

	// Delete stale per-route policies that this reconcile no longer produces
	// (e.g. rule count reduced, granularity changed). Skipped for merge mode because
	// mergeable writers manage their own AP lifecycle via ApplyMerged/DeleteMerged.
	if mergeKey == "" {
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
				if writer.IsOrphaned(obj, []gatewayApiv1.HTTPRoute{httproute}) {
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
func (r *HTTPRouteAllowlistingReconciler) cleanupOrphanedMergedAPs(ctx context.Context, httproute *gatewayApiv1.HTTPRoute, parentRefs []gatewayApiv1.ParentReference) error {
	log := log.DefaultLogger.WithContext(ctx)
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
			mergeKey := obj.GetLabels()[r.CidrResolver.AnnotationPrefix+"/owner-name"]
			if mergeKey == "" || obj.GetNamespace() != gatewayNS {
				continue
			}
			// Check cache: any sibling still in this group?
			allRoutes := &gatewayApiv1.HTTPRouteList{}
			if err := r.List(ctx, allRoutes); err != nil {
				return err
			}
			hasSibling := false
			for _, route := range allRoutes.Items {
				if route.Annotations[r.mergeAnnotation()] == mergeKey &&
					httproutePointsToGateway(&route, gateway.Name, gateway.Namespace) {
					hasSibling = true
					break
				}
			}
			if hasSibling {
				continue
			}
			// Confirm via direct API read before deleting.
			confirmed := &gatewayApiv1.HTTPRouteList{}
			if err := r.APIReader.List(ctx, confirmed); err != nil {
				return err
			}
			for _, route := range confirmed.Items {
				if route.Annotations[r.mergeAnnotation()] == mergeKey &&
					httproutePointsToGateway(&route, gateway.Name, gateway.Namespace) {
					hasSibling = true
					break
				}
			}
			if hasSibling {
				continue
			}
			if err := mw.DeleteMerged(ctx, gatewayNS, mergeKey); err != nil {
				return err
			}
			log.Infof("Deleted orphaned merged AP %q — no siblings remain in group", mergeKey)
		}
	}
	return nil
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
			if route.Annotations[r.mergeAnnotation()] == mergeKey &&
				httproutePointsToGateway(&route, gateway.Name, gateway.Namespace) {
				return nil // cache was stale — sibling still exists, skip deletion
			}
		}
		if err := writer.DeleteMerged(ctx, gateway.Namespace, mergeKey); err != nil {
			return err
		}
		log.Infof("Deleted merged AuthorizationPolicy for empty group %q → gateway %s/%s", mergeKey, gateway.Namespace, gateway.Name)
		return nil
	}

	if err := writer.ApplyMerged(ctx, gateway, siblings, mergeKey); err != nil {
		return err
	}
	log.Infof("Merged AuthorizationPolicy created/updated for merge group %q → gateway %s/%s", mergeKey, gateway.Namespace, gateway.Name)
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

// validK8sName matches a valid Kubernetes resource name: lowercase alphanumeric and hyphens,
// must start and end with alphanumeric, max 253 chars.
var validK8sName = regexp.MustCompile(`^[a-z0-9]([a-z0-9\-\.]{0,251}[a-z0-9])?$`)

// validateMergeKey returns an error if key is not a valid Kubernetes resource name.
func validateMergeKey(key string) error {
	if !validK8sName.MatchString(key) {
		return fmt.Errorf("merge key %q is not a valid Kubernetes resource name: must match [a-z0-9][a-z0-9-.]*[a-z0-9] and be ≤253 chars", key)
	}
	return nil
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
	if isCRDInstalled(mgr.GetRESTMapper(), "security.istio.io", "v1", "AuthorizationPolicy") {
		build = build.Owns(&istiosecurityv1.AuthorizationPolicy{})
	}
	if isCRDInstalled(mgr.GetRESTMapper(), "traefik.io", "v1alpha1", "Middleware") {
		build = build.Owns(&writers.TraefikMiddleware{})
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
	if r.LegacyGroupVersion != "" {
		build = build.Watches(&ipamv1alpha1_legacy.ClusterCIDRs{}, handler.EnqueueRequestsFromMapFunc(newHTTPRoutesFromCIDRFuncMap(r.Client, r.CidrResolver.ClusterAnnotation()))).
			Watches(&ipamv1alpha1_legacy.CIDRs{}, handler.EnqueueRequestsFromMapFunc(newHTTPRoutesFromCIDRFuncMap(r.Client, r.CidrResolver.Annotation())))
	}
	return build.Complete(r)
}

func newHTTPRoutesFromCIDRFuncMap(c client.Client, annotation string) handler.MapFunc {
	return func(ctx context.Context, cidr client.Object) []reconcile.Request {
		httproutes := &gatewayApiv1.HTTPRouteList{}
		options := client.ListOptions{
			Namespace: cidr.GetNamespace(),
		}
		err := c.List(ctx, httproutes, &options)
		if err != nil {
			return []reconcile.Request{}
		}
		var requests []reconcile.Request
		for _, httproute := range httproutes.Items {
			val, ok := httproute.Annotations[annotation]
			if !ok {
				continue
			}
			cidrsFound := map[string]struct{}{}
			for _, cidrName := range strings.Split(val, ",") {
				cidrsFound[strings.TrimSpace(cidrName)] = struct{}{}
			}
			if _, found := cidrsFound[cidr.GetName()]; found {
				requests = append(requests, reconcile.Request{NamespacedName: types.NamespacedName{Namespace: httproute.Namespace, Name: httproute.Name}})
			}
		}
		return requests
	}
}
