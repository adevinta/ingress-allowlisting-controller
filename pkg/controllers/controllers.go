package controllers

import (
	"context"
	"fmt"
	"strings"

	log "github.com/adevinta/go-log-toolkit"
	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	netv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	ipamv1alpha1 "github.com/adevinta/ingress-allowlisting-controller/pkg/apis/ipam.adevinta.com/v1alpha1"
	"github.com/adevinta/ingress-allowlisting-controller/pkg/controllers/writers"
	"github.com/adevinta/ingress-allowlisting-controller/pkg/resolvers"

	clientgoscheme "k8s.io/client-go/kubernetes/scheme"

	istiosecurityv1 "istio.io/client-go/pkg/apis/security/v1"
	gatewayApiv1 "sigs.k8s.io/gateway-api/apis/v1"
)

var setupLog = log.DefaultLogger.WithField("setup", "controllers")

// isCRDInstalled returns true when the given GVK exists in the cluster's REST API.
// Used at startup to auto-detect optional dependencies (Istio, Traefik) — any
// combination is supported: neither, either, or both.
func isCRDInstalled(mapper meta.RESTMapper, group, version, kind string) bool {
	_, err := mapper.RESTMapping(schema.GroupKind{Group: group, Kind: kind}, version)
	return err == nil
}

type setupError struct {
	error
	controllerType string
}

func (e *setupError) Log(logger logr.Logger) {
	logger.Error(e, "unable to create controller", "controller", e.controllerType)
}

// BuildWriterRegistries constructs the L4 and L7 writer registries for the CRDs that are
// actually installed on the cluster. Called from main.go before the manager starts so
// permissions can be checked. Pass the REST mapper from the pre-flight client.
func BuildWriterRegistries(c client.Client, mapper meta.RESTMapper, managedBy string, cidrResolver resolvers.CidrResolver) (writers.L4WriterRegistry, writers.L7WriterRegistry) {
	l4 := writers.L4WriterRegistry{}
	l7 := writers.L7WriterRegistry{}
	if isCRDInstalled(mapper, "security.istio.io", "v1", "AuthorizationPolicy") {
		l4[writers.IstioControllerName] = writers.NewIstioL4Writer(c, managedBy, cidrResolver.AnnotationPrefix)
		l7[writers.IstioControllerName] = writers.NewIstioL7Writer(c, managedBy, cidrResolver)
	}
	if isCRDInstalled(mapper, "traefik.io", "v1alpha1", "Middleware") {
		l7[writers.TraefikControllerName] = writers.NewTraefikL7Writer(c, managedBy, cidrResolver)
	}
	// The AWS Load Balancer Controller: one writer for its ALB and NLB GatewayClasses, both read
	// sourceRanges from the Gateway's LoadBalancerConfiguration.
	if isCRDInstalled(mapper, "gateway.k8s.aws", "v1beta1", "LoadBalancerConfiguration") {
		aws := writers.NewAWSLBL4Writer(c, cidrResolver.AnnotationPrefix)
		l4[writers.AWSALBControllerName] = aws
		l4[writers.AWSNLBControllerName] = aws
	}
	return l4, l7
}

// Events for missing CIDRs objects, written by the shared resolver's recorder (events.k8s.io/v1).
// +kubebuilder:rbac:groups=events.k8s.io,resources=events,verbs=create;patch
// The lease for --enable-leader-election; leader election records its own Events with the core API.
// +kubebuilder:rbac:groups=coordination.k8s.io,resources=leases,verbs=get;create;update
// +kubebuilder:rbac:groups="",resources=events,verbs=create;patch

// logAnnotationRemoval logs when an in-place kind (Ingress, Service, NetworkPolicy) loses its
// allowlist annotation. The controller then stops managing the object and leaves the last value it
// wrote: the object belongs to someone else, and clearing the field would open it to everyone.
// That value no longer follows CIDRs changes, so say so once, at the removal. It filters nothing.
func logAnnotationRemoval(kind, annotationPrefix string) predicate.Funcs {
	return predicate.Funcs{
		UpdateFunc: func(e event.UpdateEvent) bool {
			// A Gateway's Service was never managed (see gatewayOwnerName): nothing to stop.
			if hasAllowlistAnnotation(annotationPrefix, e.ObjectOld) && !hasAllowlistAnnotation(annotationPrefix, e.ObjectNew) && gatewayOwnerName(e.ObjectNew) == "" {
				log.DefaultLogger.Warnf("%s %s/%s: allowlist annotation removed, the controller stopped managing it; the last allowlist it wrote stays in place and no longer follows CIDRs changes",
					kind, e.ObjectNew.GetNamespace(), e.ObjectNew.GetName())
			}
			return true
		},
	}
}

// gatewayNameLabel is the Gateway API label implementations put on the resources they create for a
// Gateway (Istio on the Service and Deployment of the gateway).
const gatewayNameLabel = gatewayApiv1.GroupName + "/gateway-name"

// gatewayOwnerName returns the name of the Gateway obj was generated for, from its ownerReferences
// or else the standard gateway-name label, or "" if it doesn't belong to a Gateway.
func gatewayOwnerName(obj client.Object) string {
	for _, ref := range obj.GetOwnerReferences() {
		if ref.Kind == "Gateway" && strings.HasPrefix(ref.APIVersion, gatewayApiv1.GroupName+"/") {
			return ref.Name
		}
	}
	return obj.GetLabels()[gatewayNameLabel]
}

// managedByLabel is the app.kubernetes.io/managed-by value on the objects the writers create, for
// a controller instance with the given name prefix. The writers set it and the HTTPRoute
// controller lists by it to find them again, so both must use this one function.
func managedByLabel(namePrefix string) string {
	if namePrefix != "" {
		return namePrefix + "-ingress-allowlisting-controller"
	}
	return "ingress-allowlisting-controller"
}

// SetupOptions selects which controllers SetupControllersWithManager starts, and how they work.
type SetupOptions struct {
	// The kinds allowlists are written to, as the --<kind>-support-enabled flags.
	IngressEnabled, GatewayEnabled, NetworkPolicyEnabled, ServiceEnabled, HTTPRouteEnabled bool
	// HTTPHeadersEnabled lets remote CIDR sources read headers from Secrets and ConfigMaps.
	HTTPHeadersEnabled bool
	// NamePrefix tells several controller instances apart (controller names, managed-by label).
	NamePrefix string
	// AnnotationPrefix is the prefix of the allowlist annotations, e.g. ipam.adevinta.com.
	AnnotationPrefix string
	// CIDRSource are the guardrails for remote CIDR sources; unset fields take the defaults.
	CIDRSource CIDRSourceOptions
}

func SetupControllersWithManager(mgr ctrl.Manager, opts SetupOptions) error {
	// Unset fields mean "default"; anything explicitly set must be in range, so a bad value stops
	// startup instead of silently weakening (or disabling) a protection.
	cidrSource := opts.CIDRSource.withDefaults()
	if err := cidrSource.Validate(); err != nil {
		return fmt.Errorf("invalid CIDR source options: %w", err)
	}

	cidrResolver := resolvers.CidrResolver{
		AnnotationPrefix: opts.AnnotationPrefix,
		Client:           mgr.GetClient(),
		Recorder:         mgr.GetEventRecorder("ingress-allowlisting-controller"),
	}

	if opts.IngressEnabled {
		if err := (&IngressReconciler{
			Client:       mgr.GetClient(),
			Scheme:       mgr.GetScheme(),
			CidrResolver: cidrResolver,
		}).SetupWithManager(mgr, opts.NamePrefix); err != nil {
			return &setupError{error: err, controllerType: "Ingress"}
		}
	}

	if err := (&CIDRReconciler{
		Client:             mgr.GetClient(),
		CIDRs:              &ipamv1alpha1.CIDRs{},
		CIDRsList:          &ipamv1alpha1.CIDRsList{},
		HTTPHeadersEnabled: opts.HTTPHeadersEnabled,
		SourceOptions:      cidrSource,
	}).SetupWithManager(mgr, opts.NamePrefix); err != nil {
		return &setupError{error: err, controllerType: "CIDRs"}
	}
	if err := (&CIDRReconciler{
		Client:             mgr.GetClient(),
		CIDRs:              &ipamv1alpha1.ClusterCIDRs{},
		CIDRsList:          &ipamv1alpha1.ClusterCIDRsList{},
		HTTPHeadersEnabled: opts.HTTPHeadersEnabled,
		SourceOptions:      cidrSource,
	}).SetupWithManager(mgr, opts.NamePrefix); err != nil {
		return &setupError{error: err, controllerType: "ClusterCIDRs"}
	}

	managedBy := managedByLabel(opts.NamePrefix)

	mapper := mgr.GetRESTMapper()
	l4Writers, l7Writers := BuildWriterRegistries(mgr.GetClient(), mapper, managedBy, cidrResolver)

	if _, ok := l4Writers[writers.IstioControllerName]; ok {
		setupLog.Infof("detected Istio: enabling Istio writers")
	}
	if _, ok := l7Writers[writers.TraefikControllerName]; ok {
		setupLog.Infof("detected Traefik: enabling Traefik writer")
	}
	if _, ok := l4Writers[writers.AWSALBControllerName]; ok {
		setupLog.Infof("detected the AWS Load Balancer Controller: enabling the LoadBalancerConfiguration writer for its ALB and NLB Gateways")
	}

	if opts.HTTPRouteEnabled && len(l7Writers) == 0 {
		setupLog.Warnf("httproute support is enabled but no L7 writer was detected (neither Istio nor Traefik CRDs found); HTTPRoutes will be reconciled but no allowlist resources will be written")
	}

	if opts.GatewayEnabled {
		gatewayReconciler := GatewayAllowlistingReconciler{
			Client:       mgr.GetClient(),
			Scheme:       mgr.GetScheme(),
			CidrResolver: cidrResolver,
			L4Writers:    l4Writers,
		}
		if err := gatewayReconciler.SetupWithManager(mgr, opts.NamePrefix); err != nil {
			return &setupError{error: err, controllerType: "Gateway"}
		}
	}
	if opts.NetworkPolicyEnabled {
		networkPolicyReconciler := NetworkPolicyReconciler{
			Client:       mgr.GetClient(),
			Scheme:       mgr.GetScheme(),
			CidrResolver: cidrResolver,
		}
		if err := networkPolicyReconciler.SetupWithManager(mgr, opts.NamePrefix); err != nil {
			return &setupError{error: err, controllerType: "NetworkPolicy"}
		}
	}
	if opts.ServiceEnabled {
		serviceReconciler := ServiceReconciler{
			Client:       mgr.GetClient(),
			Scheme:       mgr.GetScheme(),
			CidrResolver: cidrResolver,
		}
		if err := serviceReconciler.SetupWithManager(mgr, opts.NamePrefix); err != nil {
			return &setupError{error: err, controllerType: "Service"}
		}
	}

	if opts.HTTPRouteEnabled {
		httpRouteReconciler := HTTPRouteAllowlistingReconciler{
			Client:       mgr.GetClient(),
			Scheme:       mgr.GetScheme(),
			CidrResolver: cidrResolver,
			L7Writers:    l7Writers,
		}
		if err := httpRouteReconciler.SetupWithManager(mgr, opts.NamePrefix); err != nil {
			return &setupError{error: err, controllerType: "HTTPRoute"}
		}
	}

	return nil
}

func Scheme() (*runtime.Scheme, error) {
	scheme := runtime.NewScheme()

	if err := clientgoscheme.AddToScheme(scheme); err != nil {
		return nil, err
	}

	if err := ipamv1alpha1.AddToScheme(scheme); err != nil {
		return nil, err
	}
	if err := netv1.AddToScheme(scheme); err != nil {
		return nil, err
	}
	if err := corev1.AddToScheme(scheme); err != nil {
		return nil, err
	}
	if err := gatewayApiv1.Install(scheme); err != nil {
		return nil, err
	}
	if err := istiosecurityv1.AddToScheme(scheme); err != nil {
		return nil, err
	}
	if err := writers.AddTraefikToScheme(scheme); err != nil {
		return nil, err
	}

	return scheme, nil
}

// newObjectsFromCIDRFuncMap is the shared core behind the per-type watch mappers
// (newServicesFromCIDRFuncMap and its ingress/networkpolicy/gateway/httproute siblings).
// When a watched CIDRs/ClusterCIDRs object changes, it enqueues every object of the list
// type produced by newList — in the same namespace as the changed object — whose
// annotation lists the changed object by name.
//
// newList must return a fresh, empty list each call; the closure is reused across events.
// Only the listed object type differs between the per-type mappers, so they are thin shims
// over this function.
func newObjectsFromCIDRFuncMap(c client.Client, newList func() client.ObjectList, annotation string) handler.MapFunc {
	return func(ctx context.Context, cidr client.Object) []reconcile.Request {
		list := newList()
		options := client.ListOptions{
			Namespace: cidr.GetNamespace(),
		}
		if err := c.List(ctx, list, &options); err != nil {
			// The change can't be mapped to the objects referencing the CIDRs object, so they keep
			// their current allowlist until their next change or the resync.
			log.DefaultLogger.WithContext(ctx).Errorf("dropped change of %T %s: listing %T in namespace %q failed, objects referencing it are not updated until their next change or the resync: %v",
				cidr, client.ObjectKeyFromObject(cidr), list, cidr.GetNamespace(), err)
			return []reconcile.Request{}
		}
		var requests []reconcile.Request
		_ = meta.EachListItem(list, func(o runtime.Object) error {
			obj, ok := o.(client.Object)
			if !ok {
				return nil
			}
			val, ok := obj.GetAnnotations()[annotation]
			if !ok {
				return nil
			}
			for _, name := range strings.Split(val, ",") {
				if strings.TrimSpace(name) == cidr.GetName() {
					requests = append(requests, reconcile.Request{NamespacedName: types.NamespacedName{Namespace: obj.GetNamespace(), Name: obj.GetName()}})
					break
				}
			}
			return nil
		})
		return requests
	}
}
