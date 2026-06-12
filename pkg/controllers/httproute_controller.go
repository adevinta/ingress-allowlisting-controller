package controllers

import (
	"context"
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
// +kubebuilder:rbac:groups=gateway.networking.k8s.io,resources=httproutes,verbs=get;list;watch
// +kubebuilder:rbac:groups=security.istio.io,resources=authorizationpolicies,verbs=get;list;watch;create;update;patch;delete

// gatewayParentRefs returns all parentRefs that target a Gateway.
func gatewayParentRefs(httproute *gatewayApiv1.HTTPRoute) []gatewayApiv1.ParentReference {
	var refs []gatewayApiv1.ParentReference
	for _, ref := range httproute.Spec.ParentRefs {
		if ref.Kind != nil && *ref.Kind != "Gateway" {
			continue
		}
		if ref.Group != nil && *ref.Group != "gateway.networking.k8s.io" {
			continue
		}
		refs = append(refs, ref)
	}
	return refs
}

func (r *HTTPRouteAllowlistingReconciler) mergeAnnotation() string {
	return r.CidrResolver.AnnotationPrefix + "/merge"
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
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	log.Infof("HTTPRoute %s being reconciled. Creating/updating writers...", httproute.GetName())

	parentRefs := gatewayParentRefs(&httproute)
	if len(parentRefs) == 0 {
		log.Infof("HTTPRoute %s has no Gateway parentRefs, skipping", httproute.GetName())
		return ctrl.Result{}, nil
	}

	if mergeKey := httproute.Annotations[r.mergeAnnotation()]; mergeKey != "" {
		i := 0
		for _, ref := range parentRefs {
			if ref.Namespace == nil || string(*ref.Namespace) == httproute.Namespace {
				continue // merge only applies to cross-namespace refs
			}
			gatewayNS := string(*ref.Namespace)
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
			mw, ok := writer.(writers.MergeableL7PolicyWriter)
			if !ok {
				log.Infof("writer for controller %s does not support merge, skipping", gwClass.Spec.ControllerName)
				continue
			}
			if err := r.reconcileMergedGateway(ctx, &httproute, gateway, mw, mergeKey, i); err != nil {
				return ctrl.Result{}, err
			}
			i++
		}
		return ctrl.Result{}, nil
	}

	allowedIps, err := r.CidrResolver.GetCidrsFromObject(ctx, &httproute)
	if err == r.CidrResolver.AnnotationNotFoundError() {
		return ctrl.Result{}, nil
	}
	if err != nil {
		return ctrl.Result{}, err
	}

	var hostnames []string
	for _, h := range httproute.Spec.Hostnames {
		hostnames = append(hostnames, string(h))
	}

	for i, ref := range parentRefs {
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
		if err := writer.Apply(ctx, r.Scheme, &httproute, gateway, allowedIps, hostnames, nil, i); err != nil {
			return ctrl.Result{}, err
		}
		log.Infof("AuthorizationPolicy created/updated for HTTPRoute %s parentRef %d", httproute.GetName(), i)
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

// runStartupCleanup lists all APs managed by this controller, checks whether the owning
// HTTPRoute still exists and would still produce that AP, and deletes any that are orphaned.
func (r *HTTPRouteAllowlistingReconciler) runStartupCleanup(ctx context.Context) {
	log := log.DefaultLogger.WithContext(ctx)
	log.Infof("Running post-startup orphan cleanup for managed AuthorizationPolicies")

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
			log.Infof("startup cleanup: no HTTPRoutes found but managed APs exist — skipping to avoid dirty-read deletions")
			continue
		}
		for _, obj := range managed {
			obj := obj
			if writer.IsOrphaned(obj, allRoutes.Items) {
				if err := writer.Delete(ctx, obj); client.IgnoreNotFound(err) != nil {
					log.Errorf("startup cleanup: failed to delete %s/%s: %v", obj.GetNamespace(), obj.GetName(), err)
					continue
				}
				log.Infof("Startup cleanup: deleted orphaned policy %s/%s", obj.GetNamespace(), obj.GetName())
			}
		}
	}
}

func (r *HTTPRouteAllowlistingReconciler) reconcileMergedGateway(ctx context.Context, httproute *gatewayApiv1.HTTPRoute, gateway *gatewayApiv1.Gateway, writer writers.MergeableL7PolicyWriter, mergeKey string, i int) error {
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

	if err := writer.ApplyMerged(ctx, gateway, siblings, mergeKey, i); err != nil {
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
	for _, ref := range gatewayParentRefs(httproute) {
		if string(ref.Name) == gatewayName && ref.Namespace != nil && string(*ref.Namespace) == gatewayNamespace {
			return true
		}
	}
	return false
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
		For(&gatewayApiv1.HTTPRoute{}, builder.WithPredicates(annotationPredicate)).
		Owns(&istiosecurityv1.AuthorizationPolicy{}).
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
		build.Watches(&ipamv1alpha1_legacy.ClusterCIDRs{}, handler.EnqueueRequestsFromMapFunc(newHTTPRoutesFromCIDRFuncMap(r.Client, r.CidrResolver.ClusterAnnotation()))).
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
		err := c.List(context.Background(), httproutes, &options)
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
