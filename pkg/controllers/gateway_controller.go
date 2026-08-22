package controllers

import (
	"context"
	"strings"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	istiosecurityv1 "istio.io/client-go/pkg/apis/security/v1"
	gatewayApiv1 "sigs.k8s.io/gateway-api/apis/v1"

	log "github.com/adevinta/go-log-toolkit"
	ipamv1alpha1 "github.com/adevinta/ingress-allowlisting-controller/pkg/apis/ipam.adevinta.com/v1alpha1"
	ipamv1alpha1_legacy "github.com/adevinta/ingress-allowlisting-controller/pkg/apis/legacy/v1alpha1"
	"github.com/adevinta/ingress-allowlisting-controller/pkg/controllers/writers"
	"github.com/adevinta/ingress-allowlisting-controller/pkg/resolvers"
)

type GatewayAllowlistingReconciler struct {
	client.Client
	Scheme             *runtime.Scheme
	LegacyGroupVersion string
	Prefix             string
	CidrResolver       resolvers.CidrResolver
	L4Writers          writers.L4WriterRegistry
}

// +kubebuilder:rbac:groups=ipam.adevinta.com,resources=cidrs,verbs=get;list;watch
// +kubebuilder:rbac:groups=ipam.adevinta.com,resources=clustercidrs,verbs=get;list;watch
// +kubebuilder:rbac:groups=gateway.networking.k8s.io,resources=gateways,verbs=get;list;watch
// +kubebuilder:rbac:groups=gateway.networking.k8s.io,resources=gatewayclasses,verbs=get;list;watch
// +kubebuilder:rbac:groups=security.istio.io,resources=authorizationpolicies,verbs=get;list;watch;create;update;patch;delete

func (r *GatewayAllowlistingReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := log.DefaultLogger.WithContext(ctx).WithField("gateway", req.NamespacedName)
	gateway := gatewayApiv1.Gateway{}
	if err := r.Get(ctx, req.NamespacedName, &gateway); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	log.Infof("Gateway %s being reconciled. Creating/updating writers...", gateway.GetName())

	// Resolve GatewayClass and writer first — needed for both apply and delete paths.
	gwClass := &gatewayApiv1.GatewayClass{}
	if err := r.Get(ctx, types.NamespacedName{Name: string(gateway.Spec.GatewayClassName)}, gwClass); err != nil {
		if client.IgnoreNotFound(err) != nil {
			return ctrl.Result{}, err
		}
		// GatewayClass was deleted — attempt cleanup with all registered writers to avoid orphaned APs.
		for _, w := range r.L4Writers {
			if err := w.Delete(ctx, &gateway); err != nil {
				return ctrl.Result{}, err
			}
		}
		log.Infof("GatewayClass %s not found, cleaned up gateway %s", gateway.Spec.GatewayClassName, gateway.Name)
		return ctrl.Result{}, nil
	}

	writer, ok := r.L4Writers[string(gwClass.Spec.ControllerName)]
	if !ok {
		log.Infof("no L4 writer registered for controller %s, skipping gateway %s", gwClass.Spec.ControllerName, gateway.Name)
		return ctrl.Result{}, nil
	}

	var allowedIps []string
	var err error
	allowedIps, err = r.CidrResolver.GetCidrsFromObject(ctx, &gateway)
	if err == r.CidrResolver.AnnotationNotFoundError() {
		// Annotation removed — delete any previously created L4 AP.
		if err := writer.Delete(ctx, &gateway); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{}, nil
	}
	if err != nil {
		return ctrl.Result{}, err
	}

	if err := writer.Apply(ctx, r.Scheme, &gateway, allowedIps); err != nil {
		return ctrl.Result{}, err
	}
	log.Infof("AuthorizationPolicy created/updated for gateway %s", gateway.GetName())

	return ctrl.Result{}, nil
}

func (r *GatewayAllowlistingReconciler) SetupWithManager(mgr ctrl.Manager, namePrefix string) error {
	build := ctrl.NewControllerManagedBy(mgr).
		For(&gatewayApiv1.Gateway{})
	if isCRDInstalled(mgr.GetRESTMapper(), "security.istio.io", "v1", "AuthorizationPolicy") {
		build = build.Owns(&istiosecurityv1.AuthorizationPolicy{})
	}
	build = build.
		Watches(
			&ipamv1alpha1.CIDRs{},
			handler.EnqueueRequestsFromMapFunc(newGatewaysFromCIDRFuncMap(r.Client, r.CidrResolver.Annotation()))).
		Watches(
			&ipamv1alpha1.ClusterCIDRs{},
			handler.EnqueueRequestsFromMapFunc(newGatewaysFromCIDRFuncMap(r.Client, r.CidrResolver.ClusterAnnotation())))
	if namePrefix != "" {
		build = build.Named(namePrefix + "-gateway")
	}
	if r.LegacyGroupVersion != "" {
		build = build.Watches(&ipamv1alpha1_legacy.ClusterCIDRs{}, handler.EnqueueRequestsFromMapFunc(newGatewaysFromCIDRFuncMap(r.Client, r.CidrResolver.ClusterAnnotation()))).
			Watches(&ipamv1alpha1_legacy.CIDRs{}, handler.EnqueueRequestsFromMapFunc(newGatewaysFromCIDRFuncMap(r.Client, r.CidrResolver.Annotation())))
	}
	return build.Complete(r)
}

func newGatewaysFromCIDRFuncMap(c client.Client, annotation string) handler.MapFunc {
	return func(ctx context.Context, cidr client.Object) []reconcile.Request {
		gateways := &gatewayApiv1.GatewayList{}
		options := client.ListOptions{
			Namespace: cidr.GetNamespace(),
		}
		err := c.List(ctx, gateways, &options)
		if err != nil {
			return []reconcile.Request{}
		}
		var requests []reconcile.Request
		for _, gateway := range gateways.Items {
			val, ok := gateway.Annotations[annotation]
			if !ok {
				continue
			}
			cidrsFound := map[string]struct{}{}
			for _, cidr := range strings.Split(val, ",") {
				cidrsFound[strings.TrimSpace(cidr)] = struct{}{}
			}
			if _, found := cidrsFound[cidr.GetName()]; found {
				requests = append(requests, reconcile.Request{NamespacedName: types.NamespacedName{Namespace: gateway.Namespace, Name: gateway.Name}})
			}
		}
		return requests
	}
}
