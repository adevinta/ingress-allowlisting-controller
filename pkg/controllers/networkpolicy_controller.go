package controllers

import (
	"context"
	"strings"

	istiosecurityv1 "istio.io/client-go/pkg/apis/security/v1"
	netv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	log "github.com/adevinta/go-log-toolkit"
	ipamv1alpha1 "github.com/adevinta/ingress-allowlisting-controller/pkg/apis/ipam.adevinta.com/v1alpha1"
	ipamv1alpha1_legacy "github.com/adevinta/ingress-allowlisting-controller/pkg/apis/legacy/v1alpha1"
	"github.com/adevinta/ingress-allowlisting-controller/pkg/resolvers"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

type NetworkPolicyReconciler struct {
	client.Client
	Scheme             *runtime.Scheme
	LegacyGroupVersion string
	CidrResolver       resolvers.CidrResolver
}

// +kubebuilder:rbac:groups=networking.k8s.io,resources=networkpolicies,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=ipam.adevinta.com,resources=cidrs,verbs=get;list;watch

func (r *NetworkPolicyReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := log.DefaultLogger.WithContext(ctx).WithField("networkpolicy", req.NamespacedName)

	var networkPolicyMetadata metav1.ObjectMeta

	networkpolicy := netv1.NetworkPolicy{}

	if err := r.Get(ctx, req.NamespacedName, &networkpolicy); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	networkPolicyMetadata = networkpolicy.ObjectMeta

	if !networkPolicyMetadata.DeletionTimestamp.IsZero() { // np being deleted
		return ctrl.Result{}, nil
	}

	log.Infof("Networkpolicy %s being reconciled. Creating/updating allowlist...", networkPolicyMetadata.GetName())

	updatedNetworkPolicy, err := r.reconcileNetworkPolicy(ctx, networkpolicy)
	if err != nil {
		if err == r.CidrResolver.AnnotationNotFoundError() {
			return ctrl.Result{}, nil
		}
		log.Error(err, "Error creating or updating networkpolicy")
		return ctrl.Result{}, err
	}

	networkpolicy = updatedNetworkPolicy
	if err := r.Client.Update(ctx, &networkpolicy); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	return ctrl.Result{}, nil
}
func (r *NetworkPolicyReconciler) reconcileNetworkPolicy(ctx context.Context, networkPolicy netv1.NetworkPolicy) (netv1.NetworkPolicy, error) {
	cidrs, err := r.CidrResolver.GetCidrsFromObject(ctx, &networkPolicy)
	if err == r.CidrResolver.AnnotationNotFoundError() {
		return networkPolicy, err
	}
	if err != nil {
		return netv1.NetworkPolicy{}, err
	}
	var peers []netv1.NetworkPolicyPeer
	for _, cidr := range cidrs {
		block := netv1.IPBlock{CIDR: cidr}
		peers = append(peers, netv1.NetworkPolicyPeer{IPBlock: &block})
	}

	policyTypes := networkPolicy.Spec.PolicyTypes
	if len(policyTypes) == 0 {
		policyTypes = []netv1.PolicyType{netv1.PolicyTypeEgress}
	}
	networkPolicy.Spec.PolicyTypes = policyTypes
	networkPolicy.Spec.Egress = nil
	networkPolicy.Spec.Ingress = nil

	for _, t := range policyTypes {
		switch t {
		case netv1.PolicyTypeEgress:
			networkPolicy.Spec.Egress = []netv1.NetworkPolicyEgressRule{
				{To: peers},
			}
		case netv1.PolicyTypeIngress:
			networkPolicy.Spec.Ingress = []netv1.NetworkPolicyIngressRule{
				{From: peers},
			}
		}
	}

	return networkPolicy, nil
}

// +kubebuilder:rbac:groups=ipam.adevinta.com,resources=cidrs,verbs=get;list;watch
// +kubebuilder:rbac:groups=ipam.adevinta.com,resources=clustercidrs,verbs=get;list;watch

func (r *NetworkPolicyReconciler) SetupWithManager(mgr ctrl.Manager, namePrefix string) error {
	build := ctrl.NewControllerManagedBy(mgr).
		For(&netv1.NetworkPolicy{}).
		Owns(&istiosecurityv1.AuthorizationPolicy{}).
		Watches(
			&ipamv1alpha1.CIDRs{},
			handler.EnqueueRequestsFromMapFunc(newNetworkPoliciesFromCIDRFuncMap(r.Client, r.CidrResolver.Annotation()))).
		Watches(
			&ipamv1alpha1.ClusterCIDRs{},
			handler.EnqueueRequestsFromMapFunc(newNetworkPoliciesFromCIDRFuncMap(r.Client, r.CidrResolver.ClusterAnnotation())))
	if namePrefix != "" {
		build = build.Named(namePrefix + "-networkpolicy")
	}
	if r.LegacyGroupVersion != "" {
		build.Watches(&ipamv1alpha1_legacy.ClusterCIDRs{}, handler.EnqueueRequestsFromMapFunc(newNetworkPoliciesFromCIDRFuncMap(r.Client, r.CidrResolver.ClusterAnnotation()))).
			Watches(&ipamv1alpha1_legacy.CIDRs{}, handler.EnqueueRequestsFromMapFunc(newNetworkPoliciesFromCIDRFuncMap(r.Client, r.CidrResolver.Annotation())))
	}
	return build.Complete(r)
}

func newNetworkPoliciesFromCIDRFuncMap(c client.Client, annotation string) handler.MapFunc {
	return func(ctx context.Context, cidr client.Object) []reconcile.Request {
		networkpolicies := &netv1.NetworkPolicyList{}
		options := client.ListOptions{
			Namespace: cidr.GetNamespace(),
		}
		err := c.List(context.Background(), networkpolicies, &options)
		if err != nil {
			return []reconcile.Request{}
		}
		var requests []reconcile.Request
		for _, np := range networkpolicies.Items {
			val, ok := np.Annotations[annotation]
			if !ok {
				continue
			}
			cidrsFound := map[string]struct{}{}
			for _, cidr := range strings.Split(val, ",") {
				cidrsFound[strings.TrimSpace(cidr)] = struct{}{}
			}
			if _, found := cidrsFound[cidr.GetName()]; found {
				requests = append(requests, reconcile.Request{NamespacedName: types.NamespacedName{Namespace: np.Namespace, Name: np.Name}})
			}
		}
		return requests
	}
}
