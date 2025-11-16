package controllers

import (
	"context"
	"strings"

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

// IngressReconciler reconciles a Ingress object
type IngressReconciler struct {
	client.Client
	Scheme             *runtime.Scheme
	LegacyGroupVersion string
	CidrResolver       resolvers.CidrResolver
}

// +kubebuilder:rbac:groups=networking,resources=ingresses,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=networking,resources=ingresses/status,verbs=get;update;patch

func (r *IngressReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := log.DefaultLogger.WithContext(ctx).WithField("ingress", req.NamespacedName)

	var ingressMetadata metav1.ObjectMeta

	netV1Ingress := netv1.Ingress{}

	if err := r.Get(ctx, req.NamespacedName, &netV1Ingress); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	ingressMetadata = netV1Ingress.ObjectMeta

	if !ingressMetadata.DeletionTimestamp.IsZero() { // ingress being deleted
		return ctrl.Result{}, nil
	}

	log.Infof("Ingress %s being reconciled. Creating/updating allowlist...", ingressMetadata.GetName())

	updatedIngress, err := r.reconcileIngress(ctx, netV1Ingress)
	if err != nil {
		if err == r.CidrResolver.AnnotationNotFoundError() || err == r.CidrResolver.HashAlreadyMatchError() {
			return ctrl.Result{}, nil
		}
		log.Error(err, "Error creating or updating allowlist")
		return ctrl.Result{}, err
	}

	netV1Ingress.Annotations = updatedIngress.Annotations
	if err := r.Client.Update(ctx, &netV1Ingress); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	return ctrl.Result{}, nil
}

func (r *IngressReconciler) reconcileIngress(ctx context.Context, ingressMeta netv1.Ingress) (netv1.Ingress, error) {
	//TODO: find annotation: ipam.adevinta.com/allowlist-group
	// if annotation is present: resolve the name->CIDRs list.
	// and create/update nginx.ingress-kubernetes.io/whitelist-source-range

	// TODO: check format of the annotation values.
	allowedIps, err := r.CidrResolver.GetCidrsFromObject(ctx, &ingressMeta)
	if err == r.CidrResolver.AnnotationNotFoundError() {
		return ingressMeta, err
	}
	if err != nil {
		return netv1.Ingress{}, err
	}

	// calculate new hash from while comparing hashes
	// hash is generated based on cidrs only
	newHash, err := r.CidrResolver.CompareHashWithObject(ctx, &ingressMeta, allowedIps)
	if err == r.CidrResolver.HashAlreadyMatchError() {
		// bingo, we dont have to do anything
		return ingressMeta, err
	}
	// inject hash annotation
	ingressMeta.Annotations[r.CidrResolver.Hash()] = newHash

	ipCsv := strings.Join(allowedIps, ",")
	ingressMeta.Annotations["nginx.ingress.kubernetes.io/whitelist-source-range"] = ipCsv
	return ingressMeta, nil
}

// +kubebuilder:rbac:groups=ipam.adevinta.com,resources=cidrs,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=ipam.adevinta.com,resources=clustercidrs,verbs=get;list;watch;create;update;patch;delete

func (r *IngressReconciler) SetupWithManager(mgr ctrl.Manager, namePrefix string) error {
	var ing client.Object = &netv1.Ingress{}

	build := ctrl.NewControllerManagedBy(mgr).For(ing)
	if namePrefix != "" {
		build = build.Named(namePrefix + "-ingress")
	}
	build.Watches(&ipamv1alpha1.CIDRs{}, handler.EnqueueRequestsFromMapFunc(newIngressesFromCIDRFuncMap(r.Client, r.CidrResolver.Annotation())))
	build.Watches(&ipamv1alpha1.ClusterCIDRs{}, handler.EnqueueRequestsFromMapFunc(newIngressesFromCIDRFuncMap(r.Client, r.CidrResolver.ClusterAnnotation())))
	if r.LegacyGroupVersion != "" {
		build.Watches(&ipamv1alpha1_legacy.CIDRs{}, handler.EnqueueRequestsFromMapFunc(newIngressesFromCIDRFuncMap(r.Client, r.CidrResolver.Annotation())))
		build.Watches(&ipamv1alpha1_legacy.ClusterCIDRs{}, handler.EnqueueRequestsFromMapFunc(newIngressesFromCIDRFuncMap(r.Client, r.CidrResolver.ClusterAnnotation())))
	}
	return build.Complete(r)
}

func newIngressesFromCIDRFuncMap(c client.Client, annotation string) handler.MapFunc {
	return func(ctx context.Context, cidr client.Object) []reconcile.Request {
		ingresses := &netv1.IngressList{}
		options := client.ListOptions{
			Namespace: cidr.GetNamespace(),
		}
		err := c.List(context.Background(), ingresses, &options)
		if err != nil {
			return []reconcile.Request{}
		}
		var requests []reconcile.Request
		for _, ingress := range ingresses.Items {
			val, ok := ingress.Annotations[annotation]
			if !ok {
				continue
			}
			cidrsFound := map[string]struct{}{}
			for _, cidr := range strings.Split(val, ",") {
				cidrsFound[strings.TrimSpace(cidr)] = struct{}{}
			}
			if _, found := cidrsFound[cidr.GetName()]; found {
				requests = append(requests, reconcile.Request{NamespacedName: types.NamespacedName{Namespace: ingress.Namespace, Name: ingress.Name}})
			}
		}
		return requests
	}
}
