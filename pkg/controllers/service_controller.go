package controllers

import (
	"context"
	"reflect"

	corev1 "k8s.io/api/core/v1"

	log "github.com/adevinta/go-log-toolkit"
	ipamv1alpha1 "github.com/adevinta/ingress-allowlisting-controller/pkg/apis/ipam.adevinta.com/v1alpha1"
	ipamv1alpha1_legacy "github.com/adevinta/ingress-allowlisting-controller/pkg/apis/legacy/v1alpha1"
	"github.com/adevinta/ingress-allowlisting-controller/pkg/resolvers"

	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
)

type ServiceReconciler struct {
	client.Client
	Scheme             *runtime.Scheme
	LegacyGroupVersion string
	CidrResolver       resolvers.CidrResolver
}

// +kubebuilder:rbac:groups="",resources=services,verbs=get;list;watch;update;patch

func (r *ServiceReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := log.DefaultLogger.WithContext(ctx).WithField("service", req.NamespacedName)

	service := corev1.Service{}

	if err := r.Get(ctx, req.NamespacedName, &service); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	if !service.ObjectMeta.DeletionTimestamp.IsZero() { // service being deleted
		return ctrl.Result{}, nil
	}

	updatedService, err := r.reconcileService(ctx, service)
	if err != nil {
		if err == r.CidrResolver.AnnotationNotFoundError() {
			return ctrl.Result{}, nil
		}
		log.Error(err, "Error creating or updating service")
		return ctrl.Result{}, err
	}

	// Skip the Update (and its self-triggered reconcile) when the resolved
	// allowlist already matches what is on the object. This is what keeps a
	// single change from turning into a reconcile loop.
	if reflect.DeepEqual(service.Spec.LoadBalancerSourceRanges, updatedService.Spec.LoadBalancerSourceRanges) {
		return ctrl.Result{}, nil
	}

	log.Infof("Service %s allowlist changed; updating loadBalancerSourceRanges...", service.GetName())

	service = updatedService
	if err := r.Client.Update(ctx, &service); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	return ctrl.Result{}, nil
}

func (r *ServiceReconciler) reconcileService(ctx context.Context, service corev1.Service) (corev1.Service, error) {
	log := log.DefaultLogger.WithContext(ctx)

	// loadBalancerSourceRanges is only valid for type=LoadBalancer Services; the API
	// server rejects it on any other type. Skip other types before resolving CIDRs, so a
	// non-LoadBalancer Service never emits a not-found Event or sets the cidrsNotFound
	// metric for something we don't manage. Logged at debug: the Service watch has no
	// annotation filter, so every non-LoadBalancer Service in the cluster reaches this and
	// it would be noise at a higher level.
	if service.Spec.Type != corev1.ServiceTypeLoadBalancer {
		log.Debugf("Service %s/%s is not of type LoadBalancer (%s); skipping loadBalancerSourceRanges", service.GetNamespace(), service.GetName(), service.Spec.Type)
		return service, nil
	}

	cidrs, err := r.CidrResolver.GetCidrsFromObject(ctx, &service)
	if err == r.CidrResolver.AnnotationNotFoundError() {
		return service, err
	}
	if err != nil {
		return corev1.Service{}, err
	}

	service.Spec.LoadBalancerSourceRanges = cidrs

	return service, nil
}

// +kubebuilder:rbac:groups=ipam.adevinta.com,resources=cidrs;clustercidrs,verbs=get;list;watch

func (r *ServiceReconciler) SetupWithManager(mgr ctrl.Manager, namePrefix string) error {
	build := ctrl.NewControllerManagedBy(mgr).
		For(&corev1.Service{}).
		Watches(
			&ipamv1alpha1.CIDRs{},
			handler.EnqueueRequestsFromMapFunc(newServicesFromCIDRFuncMap(r.Client, r.CidrResolver.Annotation()))).
		Watches(
			&ipamv1alpha1.ClusterCIDRs{},
			handler.EnqueueRequestsFromMapFunc(newServicesFromCIDRFuncMap(r.Client, r.CidrResolver.ClusterAnnotation())))
	if namePrefix != "" {
		build = build.Named(namePrefix + "-service")
	}
	if r.LegacyGroupVersion != "" {
		build.Watches(&ipamv1alpha1_legacy.ClusterCIDRs{}, handler.EnqueueRequestsFromMapFunc(newServicesFromCIDRFuncMap(r.Client, r.CidrResolver.ClusterAnnotation()))).
			Watches(&ipamv1alpha1_legacy.CIDRs{}, handler.EnqueueRequestsFromMapFunc(newServicesFromCIDRFuncMap(r.Client, r.CidrResolver.Annotation())))
	}
	return build.Complete(r)
}

func newServicesFromCIDRFuncMap(c client.Client, annotation string) handler.MapFunc {
	return newObjectsFromCIDRFuncMap(c, func() client.ObjectList { return &corev1.ServiceList{} }, annotation)
}
