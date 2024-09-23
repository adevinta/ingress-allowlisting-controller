package controllers

import (
	"context"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
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

type GatewayAllowlistingReconciler struct {
	client.Client
	Scheme             *runtime.Scheme
	LegacyGroupVersion string
	Prefix             string
	CidrResolver       resolvers.CidrResolver
}

// +kubebuilder:rbac:groups=ipam.adevinta.com,resources=cidrs,verbs=get;list;watch
// +kubebuilder:rbac:groups=gateway.networking.k8s.io,resources=gateways,verbs=get;list;watch
// +kubebuilder:rbac:groups=security.istio.io,resources=authorizationpolicies,verbs=get;list;watch;create;update;patch;delete

func (r *GatewayAllowlistingReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := log.DefaultLogger.WithContext(ctx).WithField("gateway", req.NamespacedName)
	gateway := gatewayApiv1.Gateway{}
	if err := r.Get(ctx, req.NamespacedName, &gateway); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	log.Infof("Gateway %s being reconciled. Creating/updating allowlist...", gateway.GetName())
	var allowedIps []string
	var err error
	allowedIps, err = r.CidrResolver.GetCidrsFromObject(ctx, &gateway)
	if err == r.CidrResolver.AnnotationNotFoundError() {
		return ctrl.Result{}, nil
	}
	if err != nil {
		return ctrl.Result{}, err
	}

	generatedAuthorizationPolicy := &istiosecurityv1.AuthorizationPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      gateway.Name,
			Namespace: gateway.Namespace,
		},
	}

	_, err = ctrl.CreateOrUpdate(ctx, r.Client, generatedAuthorizationPolicy, func() error {
		generatedAuthorizationPolicy.Spec = istioApiSecurityV1.AuthorizationPolicy{
			Action: istioApiSecurityV1.AuthorizationPolicy_ALLOW, // ALLOW is the default action; somehow, the action field is empty when examining the resource after creation
			Rules: []*istioApiSecurityV1.Rule{
				{
					From: []*istioApiSecurityV1.Rule_From{
						{
							Source: &istioApiSecurityV1.Source{
								RemoteIpBlocks: allowedIps,
							},
						},
					},
				},
			},
			TargetRef: &istioApiTypeV1beta1.PolicyTargetReference{
				Name:  gateway.Name,
				Kind:  "Gateway",
				Group: "gateway.networking.k8s.io",
			},
		}
		return nil
	})
	if err != nil {
		return ctrl.Result{}, err
	}
	log.Infof("AuthorizationPolicy %s created/updated for gateway %s", generatedAuthorizationPolicy.Name, gateway.GetName())

	return ctrl.Result{}, nil
}

func (r *GatewayAllowlistingReconciler) SetupWithManager(mgr ctrl.Manager, namePrefix string) error {
	build := ctrl.NewControllerManagedBy(mgr).
		For(&gatewayApiv1.Gateway{}).
		Owns(&istiosecurityv1.AuthorizationPolicy{}).
		Watches(
			&ipamv1alpha1.CIDRs{},
			handler.EnqueueRequestsFromMapFunc(newGatewaysFromCIDRFuncMap(r.Client, r.CidrResolver.Annotation()))).
		Watches(
			&ipamv1alpha1.ClusterCIDRs{},
			handler.EnqueueRequestsFromMapFunc(newGatewaysFromCIDRFuncMap(r.Client, r.CidrResolver.ClusterAnnotation())))
	if namePrefix != "" {
		build = build.Named(namePrefix + "-gaetway")
	}
	if r.LegacyGroupVersion != "" {
		build.Watches(&ipamv1alpha1_legacy.ClusterCIDRs{}, handler.EnqueueRequestsFromMapFunc(newGatewaysFromCIDRFuncMap(r.Client, r.CidrResolver.ClusterAnnotation()))).
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
		err := c.List(context.Background(), gateways, &options)
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
