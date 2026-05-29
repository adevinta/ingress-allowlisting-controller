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

type HTTPRouteAllowlistingReconciler struct {
	client.Client
	Scheme             *runtime.Scheme
	LegacyGroupVersion string
	Prefix             string
	CidrResolver       resolvers.CidrResolver
}

// +kubebuilder:rbac:groups=ipam.adevinta.com,resources=cidrs,verbs=get;list;watch
// +kubebuilder:rbac:groups=gateway.networking.k8s.io,resources=httproutes,verbs=get;list;watch
// +kubebuilder:rbac:groups=security.istio.io,resources=authorizationpolicies,verbs=get;list;watch;create;update;patch;delete

func (r *HTTPRouteAllowlistingReconciler) gatewayAnnotation() string {
	return r.CidrResolver.AnnotationPrefix + "/gateway"
}

func (r *HTTPRouteAllowlistingReconciler) namespaceAnnotation() string {
	return r.CidrResolver.AnnotationPrefix + "/namespace"
}

func (r *HTTPRouteAllowlistingReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := log.DefaultLogger.WithContext(ctx).WithField("httproute", req.NamespacedName)
	httproute := gatewayApiv1.HTTPRoute{}
	if err := r.Get(ctx, req.NamespacedName, &httproute); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	log.Infof("HTTPRoute %s being reconciled. Creating/updating allowlist...", httproute.GetName())

	allowedIps, err := r.CidrResolver.GetCidrsFromObject(ctx, &httproute)
	if err == r.CidrResolver.AnnotationNotFoundError() {
		return ctrl.Result{}, nil
	}
	if err != nil {
		return ctrl.Result{}, err
	}

	annotations := httproute.GetAnnotations()
	gatewayName, ok := annotations[r.gatewayAnnotation()]
	if !ok || gatewayName == "" {
		log.Infof("HTTPRoute %s has no %s annotation, skipping", httproute.GetName(), r.gatewayAnnotation())
		return ctrl.Result{}, nil
	}

	targetNamespace := httproute.Namespace
	if ns, ok := annotations[r.namespaceAnnotation()]; ok && ns != "" {
		targetNamespace = ns
	}

	var hostnames []string
	for _, h := range httproute.Spec.Hostnames {
		hostnames = append(hostnames, string(h))
	}

	policyName := httproute.Name
	generatedAuthorizationPolicy := &istiosecurityv1.AuthorizationPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      policyName,
			Namespace: targetNamespace,
		},
	}

	rules := []*istioApiSecurityV1.Rule{
		{
			From: []*istioApiSecurityV1.Rule_From{
				{
					Source: &istioApiSecurityV1.Source{
						RemoteIpBlocks: allowedIps,
					},
				},
			},
		},
	}
	if len(hostnames) > 0 {
		rules[0].To = []*istioApiSecurityV1.Rule_To{
			{
				Operation: &istioApiSecurityV1.Operation{
					Hosts: hostnames,
				},
			},
		}
	}

	_, err = ctrl.CreateOrUpdate(ctx, r.Client, generatedAuthorizationPolicy, func() error {
		generatedAuthorizationPolicy.Spec = istioApiSecurityV1.AuthorizationPolicy{
			Action: istioApiSecurityV1.AuthorizationPolicy_ALLOW,
			Rules:  rules,
			TargetRefs: []*istioApiTypeV1beta1.PolicyTargetReference{
				{
					Name:  gatewayName,
					Kind:  "Gateway",
					Group: "gateway.networking.k8s.io",
				},
			},
		}
		return nil
	})
	if err != nil {
		return ctrl.Result{}, err
	}
	log.Infof("AuthorizationPolicy %s/%s created/updated for HTTPRoute %s", targetNamespace, policyName, httproute.GetName())

	return ctrl.Result{}, nil
}

func (r *HTTPRouteAllowlistingReconciler) SetupWithManager(mgr ctrl.Manager, namePrefix string) error {
	build := ctrl.NewControllerManagedBy(mgr).
		For(&gatewayApiv1.HTTPRoute{}).
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
