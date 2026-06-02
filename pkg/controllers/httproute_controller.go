package controllers

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"sync"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	istioApiSecurityV1 "istio.io/api/security/v1"
	istioApiTypeV1beta1 "istio.io/api/type/v1beta1"
	istiosecurityv1 "istio.io/client-go/pkg/apis/security/v1"
	gatewayApiv1 "sigs.k8s.io/gateway-api/apis/v1"

	log "github.com/adevinta/go-log-toolkit"
	ipamv1alpha1 "github.com/adevinta/ingress-allowlisting-controller/pkg/apis/ipam.adevinta.com/v1alpha1"
	ipamv1alpha1_legacy "github.com/adevinta/ingress-allowlisting-controller/pkg/apis/legacy/v1alpha1"
	"github.com/adevinta/ingress-allowlisting-controller/pkg/resolvers"
)

type HTTPRouteAllowlistingReconciler struct {
	client.Client
	APIReader          client.Reader // bypasses cache — used only by startup cleanup to confirm deletions
	Scheme             *runtime.Scheme
	LegacyGroupVersion string
	Prefix             string
	CidrResolver       resolvers.CidrResolver
	startupCleanupOnce sync.Once
}

// +kubebuilder:rbac:groups=ipam.adevinta.com,resources=cidrs,verbs=get;list;watch
// +kubebuilder:rbac:groups=gateway.networking.k8s.io,resources=httproutes,verbs=get;list;watch
// +kubebuilder:rbac:groups=security.istio.io,resources=authorizationpolicies,verbs=get;list;watch;create;update;patch;delete

type policyTarget struct {
	namespace      string
	name           string
	gatewayName    string
	crossNamespace bool
	ref            gatewayApiv1.ParentReference
}

// policyTargets computes the complete set of AuthorizationPolicies that the non-merge
// reconcile path would produce for route: one per Gateway parentRef, with namespace and
// name derived from the cross-namespace flag and index. Single source of truth for AP naming.
func policyTargets(route *gatewayApiv1.HTTPRoute) []policyTarget {
	var targets []policyTarget
	for i, ref := range gatewayParentRefs(route) {
		crossNamespace := ref.Namespace != nil && string(*ref.Namespace) != route.Namespace
		targetNamespace := route.Namespace
		baseName := route.Name
		if crossNamespace {
			targetNamespace = string(*ref.Namespace)
			baseName = route.Namespace + "-" + route.Name
		}
		name := baseName
		if i > 0 {
			name = fmt.Sprintf("%s-%d", baseName, i)
		}
		targets = append(targets, policyTarget{
			namespace:      targetNamespace,
			name:           name,
			gatewayName:    string(ref.Name),
			crossNamespace: crossNamespace,
			ref:            ref,
		})
	}
	return targets
}

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

// invalidLabelValue matches characters not allowed in k8s label values: (([A-Za-z0-9][-A-Za-z0-9_.]*)?[A-Za-z0-9])?
var invalidLabelValue = regexp.MustCompile(`[^-A-Za-z0-9_.]`)

func labelSafe(s string) string {
	v := invalidLabelValue.ReplaceAllString(s, "_")
	if len(v) > 63 {
		v = v[:63]
	}
	return v
}

func (r *HTTPRouteAllowlistingReconciler) applyLabels(policy *istiosecurityv1.AuthorizationPolicy, ownerNamespace, ownerName string) {
	if policy.Labels == nil {
		policy.Labels = map[string]string{}
	}
	policy.Labels["app.kubernetes.io/managed-by"] = r.managedByValue()
	policy.Labels[r.CidrResolver.AnnotationPrefix+"/owner-namespace"] = labelSafe(ownerNamespace)
	policy.Labels[r.CidrResolver.AnnotationPrefix+"/owner-name"] = labelSafe(ownerName)
}

func (r *HTTPRouteAllowlistingReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := log.DefaultLogger.WithContext(ctx).WithField("httproute", req.NamespacedName)
	httproute := gatewayApiv1.HTTPRoute{}
	if err := r.Get(ctx, req.NamespacedName, &httproute); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	log.Infof("HTTPRoute %s being reconciled. Creating/updating allowlist...", httproute.GetName())

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
			if err := r.reconcileMergedGateway(ctx, &httproute, ref, mergeKey, i); err != nil {
				return ctrl.Result{}, err
			}
			i++
		}
		r.runStartupCleanup(ctx)
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

	rules := buildAuthorizationRules(allowedIps, hostnames)

	for _, pt := range policyTargets(&httproute) {
		policy := &istiosecurityv1.AuthorizationPolicy{
			ObjectMeta: metav1.ObjectMeta{Name: pt.name, Namespace: pt.namespace},
		}
		_, err = ctrl.CreateOrUpdate(ctx, r.Client, policy, func() error {
			if !pt.crossNamespace {
				// Same-namespace: owner reference enables automatic GC when the HTTPRoute is deleted.
				// Cross-namespace owner references are silently stripped by the API server; controller-runtime
				// rejects them early, so we skip the call entirely.
				if err := ctrl.SetControllerReference(&httproute, policy, r.Scheme); err != nil {
					return err
				}
			}
			r.applyLabels(policy, httproute.Namespace, httproute.Name)
			policy.Spec = istioApiSecurityV1.AuthorizationPolicy{
				Action: istioApiSecurityV1.AuthorizationPolicy_ALLOW,
				Rules:  rules,
				TargetRefs: []*istioApiTypeV1beta1.PolicyTargetReference{
					{Name: pt.gatewayName, Kind: "Gateway", Group: "gateway.networking.k8s.io"},
				},
			}
			return nil
		})
		if err != nil {
			return ctrl.Result{}, err
		}
		log.Infof("AuthorizationPolicy %s/%s created/updated for HTTPRoute %s", pt.namespace, pt.name, httproute.GetName())
	}

	r.runStartupCleanup(ctx)

	return ctrl.Result{}, nil
}

// runStartupCleanup runs once after the first reconcile completes. It lists all APs managed by this
// controller, checks whether the owning HTTPRoute still exists and would still produce that AP,
// and deletes any that are orphaned. This handles APs left behind by previous controller runs.
func (r *HTTPRouteAllowlistingReconciler) runStartupCleanup(ctx context.Context) {
	r.startupCleanupOnce.Do(func() {
		log := log.DefaultLogger.WithContext(ctx)
		log.Infof("Running post-startup orphan cleanup for managed AuthorizationPolicies")

		existing := &istiosecurityv1.AuthorizationPolicyList{}
		if err := r.List(ctx, existing, client.MatchingLabels{
			"app.kubernetes.io/managed-by": r.managedByValue(),
		}); err != nil {
			log.Errorf("startup cleanup: failed to list AuthorizationPolicies: %v", err)
			return
		}

		// Safety check: list all HTTPRoutes once upfront. If the list call fails or returns
		// empty while we have managed APs, the API server or cache may be in a degraded state.
		// Abort rather than risk deleting valid APs based on a dirty read.
		allRoutes := &gatewayApiv1.HTTPRouteList{}
		if err := r.List(ctx, allRoutes); err != nil {
			log.Errorf("startup cleanup: failed to list HTTPRoutes, aborting to avoid dirty-read deletions: %v", err)
			return
		}
		if len(allRoutes.Items) == 0 && len(existing.Items) > 0 {
			log.Infof("startup cleanup: no HTTPRoutes found but managed APs exist — skipping to avoid dirty-read deletions")
			return
		}

		for _, ap := range existing.Items {
			ap := ap
			ownerNS := ap.Labels[r.CidrResolver.AnnotationPrefix+"/owner-namespace"]
			ownerName := ap.Labels[r.CidrResolver.AnnotationPrefix+"/owner-name"]

			if ownerNS == "merged" {
				// Merge-mode AP: first check the cache (fast path); if not found there, confirm
				// via direct API server read to rule out label-selector filtering.
				found := false
				for i := range allRoutes.Items {
					if allRoutes.Items[i].Annotations[r.mergeAnnotation()] == ownerName {
						found = true
						break
					}
				}
				if found {
					continue
				}
				// Cache returned nothing — confirm via API server before deleting
				directRoutes := &gatewayApiv1.HTTPRouteList{}
				if err := r.APIReader.List(ctx, directRoutes); err != nil {
					log.Errorf("startup cleanup: API reader failed to list HTTPRoutes: %v", err)
					return
				}
				for i := range directRoutes.Items {
					if directRoutes.Items[i].Annotations[r.mergeAnnotation()] == ownerName {
						found = true
						break
					}
				}
				if found {
					continue
				}
			} else {
				// Normal AP: check cache first; if the route is absent from cache, confirm via
				// direct API server read — it may simply be outside the label selector.
				route := &gatewayApiv1.HTTPRoute{}
				err := r.Get(ctx, types.NamespacedName{Namespace: ownerNS, Name: ownerName}, route)
				if client.IgnoreNotFound(err) != nil {
					log.Errorf("startup cleanup: failed to get HTTPRoute %s/%s: %v", ownerNS, ownerName, err)
					return
				}
				if err == nil && route.Annotations[r.mergeAnnotation()] == "" {
					// Route is in cache and not in merge mode — check it still produces this AP
					if routeProducesPolicy(route, ap.Namespace, ap.Name) {
						continue
					}
				}
				if err != nil {
					// Not in cache — confirm via API server before deleting
					directRoute := &gatewayApiv1.HTTPRoute{}
					directErr := r.APIReader.Get(ctx, types.NamespacedName{Namespace: ownerNS, Name: ownerName}, directRoute)
					if client.IgnoreNotFound(directErr) != nil {
						log.Errorf("startup cleanup: API reader failed to get HTTPRoute %s/%s: %v", ownerNS, ownerName, directErr)
						return
					}
					if directErr == nil {
						// Route exists on API server but not in cache — outside label selector, keep AP
						continue
					}
					// Confirmed 404 on API server — truly gone, fall through to delete
				}
				// Falls through if: confirmed gone, switched to merge, or no longer produces this AP
			}

			if err := r.Delete(ctx, ap); client.IgnoreNotFound(err) != nil {
				log.Errorf("startup cleanup: failed to delete orphaned AP %s/%s: %v", ap.Namespace, ap.Name, err)
				return
			}
			log.Infof("Startup cleanup: deleted orphaned AuthorizationPolicy %s/%s (owner: %s/%s)", ap.Namespace, ap.Name, ownerNS, ownerName)
		}
	})
}

func (r *HTTPRouteAllowlistingReconciler) reconcileMergedGateway(ctx context.Context, httproute *gatewayApiv1.HTTPRoute, ref gatewayApiv1.ParentReference, mergeKey string, i int) error {
	log := log.DefaultLogger.WithContext(ctx)
	gatewayName := string(ref.Name)
	gatewayNamespace := string(*ref.Namespace)

	allRoutes := &gatewayApiv1.HTTPRouteList{}
	if err := r.List(ctx, allRoutes); err != nil {
		return err
	}

	seenIPs := map[string]struct{}{}
	seenHosts := map[string]struct{}{}
	var mergedIPs, mergedHosts []string

	for i := range allRoutes.Items {
		sibling := &allRoutes.Items[i]
		if sibling.Annotations[r.mergeAnnotation()] != mergeKey {
			continue
		}
		if !httproutePointsToGateway(sibling, gatewayName, gatewayNamespace) {
			continue
		}

		ips, err := r.CidrResolver.GetCidrsFromObject(ctx, sibling)
		if err == r.CidrResolver.AnnotationNotFoundError() {
			continue
		}
		if err != nil {
			return err
		}
		for _, ip := range ips {
			if _, seen := seenIPs[ip]; !seen {
				seenIPs[ip] = struct{}{}
				mergedIPs = append(mergedIPs, ip)
			}
		}
		for _, h := range sibling.Spec.Hostnames {
			host := string(h)
			if _, seen := seenHosts[host]; !seen {
				seenHosts[host] = struct{}{}
				mergedHosts = append(mergedHosts, host)
			}
		}
	}

	if len(mergedIPs) == 0 {
		log.Infof("No CIDRs found for merge group %q → gateway %s/%s, skipping", mergeKey, gatewayNamespace, gatewayName)
		return nil
	}

	policyName := mergeKey
	if i > 0 {
		policyName = fmt.Sprintf("%s-%d", mergeKey, i)
	}
	policy := &istiosecurityv1.AuthorizationPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: policyName, Namespace: gatewayNamespace},
	}
	_, err := ctrl.CreateOrUpdate(ctx, r.Client, policy, func() error {
		r.applyLabels(policy, "merged", mergeKey)
		policy.Spec = istioApiSecurityV1.AuthorizationPolicy{
			Action: istioApiSecurityV1.AuthorizationPolicy_ALLOW,
			Rules:  buildAuthorizationRules(mergedIPs, mergedHosts),
			TargetRefs: []*istioApiTypeV1beta1.PolicyTargetReference{
				{Name: gatewayName, Kind: "Gateway", Group: "gateway.networking.k8s.io"},
			},
		}
		return nil
	})
	if err != nil {
		return err
	}
	log.Infof("Merged AuthorizationPolicy %s/%s created/updated for merge group %q", gatewayNamespace, policyName, mergeKey)
	return nil
}

// routeProducesPolicy reports whether the non-merge reconcile path for route would generate
// an AuthorizationPolicy at the given {namespace, name}. Used by startup cleanup to decide
// whether an existing AP is still valid or has become orphaned (e.g. parentRef removed,
// route switched to merge mode, or index shift after reordering parentRefs).
func routeProducesPolicy(route *gatewayApiv1.HTTPRoute, policyNamespace, policyName string) bool {
	for _, pt := range policyTargets(route) {
		if pt.namespace == policyNamespace && pt.name == policyName {
			return true
		}
	}
	return false
}

func httproutePointsToGateway(httproute *gatewayApiv1.HTTPRoute, gatewayName, gatewayNamespace string) bool {
	for _, ref := range gatewayParentRefs(httproute) {
		if string(ref.Name) == gatewayName && ref.Namespace != nil && string(*ref.Namespace) == gatewayNamespace {
			return true
		}
	}
	return false
}

func buildAuthorizationRules(allowedIPs, hostnames []string) []*istioApiSecurityV1.Rule {
	rules := []*istioApiSecurityV1.Rule{
		{
			From: []*istioApiSecurityV1.Rule_From{
				{Source: &istioApiSecurityV1.Source{RemoteIpBlocks: allowedIPs}},
			},
		},
	}
	if len(hostnames) > 0 {
		rules[0].To = []*istioApiSecurityV1.Rule_To{
			{Operation: &istioApiSecurityV1.Operation{Hosts: hostnames}},
		}
	}
	return rules
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

	build := ctrl.NewControllerManagedBy(mgr).
		For(&gatewayApiv1.HTTPRoute{}, builder.WithPredicates(annotationPredicate)).
		Owns(&istiosecurityv1.AuthorizationPolicy{}).
		Watches(
			&ipamv1alpha1.CIDRs{},
			handler.EnqueueRequestsFromMapFunc(newHTTPRoutesFromCIDRFuncMap(r.Client, r.CidrResolver.Annotation()))).
		Watches(
			&ipamv1alpha1.ClusterCIDRs{},
			handler.EnqueueRequestsFromMapFunc(newHTTPRoutesFromCIDRFuncMap(r.Client, r.CidrResolver.ClusterAnnotation())))
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
