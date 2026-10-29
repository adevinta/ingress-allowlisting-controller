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
	"sigs.k8s.io/controller-runtime/pkg/handler"
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
func BuildWriterRegistries(c client.Client, mapper meta.RESTMapper, managedBy, annotationPrefix string) (writers.L4WriterRegistry, writers.L7WriterRegistry) {
	cidrResolver := resolvers.CidrResolver{AnnotationPrefix: annotationPrefix, Client: c}
	l4 := writers.L4WriterRegistry{}
	l7 := writers.L7WriterRegistry{}
	if isCRDInstalled(mapper, "security.istio.io", "v1", "AuthorizationPolicy") {
		l4[writers.IstioControllerName] = writers.NewIstioL4Writer(c)
		l7[writers.IstioControllerName] = writers.NewIstioL7Writer(c, managedBy, cidrResolver)
	}
	if isCRDInstalled(mapper, "traefik.io", "v1alpha1", "Middleware") {
		l7[writers.TraefikControllerName] = writers.NewTraefikL7Writer(c, managedBy, cidrResolver)
	}
	return l4, l7
}

// Events for missing CIDRs objects (the resolver writes them with CreateOrUpdate through the
// cached client), and the lease for --enable-leader-election.
// +kubebuilder:rbac:groups="",resources=events,verbs=get;list;watch;create;update
// +kubebuilder:rbac:groups=coordination.k8s.io,resources=leases,verbs=get;create;update

func SetupControllersWithManager(mgr ctrl.Manager, ingressSupportEnabled bool, gatewaySupportEnabled bool, networkPolicySupportEnabled bool, serviceSupportEnabled bool, httpRouteSupportEnabled bool, namePrefix string, annotationPrefix string, httpHeadersEnabled bool, cidrSource CIDRSourceOptions) error {
	// Unset fields mean "default"; anything explicitly set must be in range, so a bad value stops
	// startup instead of silently weakening (or disabling) a protection.
	cidrSource = cidrSource.withDefaults()
	if err := cidrSource.Validate(); err != nil {
		return fmt.Errorf("invalid CIDR source options: %w", err)
	}

	cidrResolver := resolvers.CidrResolver{AnnotationPrefix: annotationPrefix, Client: mgr.GetClient()}

	if ingressSupportEnabled {
		if err := (&IngressReconciler{
			Client:       mgr.GetClient(),
			Scheme:       mgr.GetScheme(),
			CidrResolver: cidrResolver,
		}).SetupWithManager(mgr, namePrefix); err != nil {
			return &setupError{error: err, controllerType: "Ingress"}
		}
	}

	if err := (&CIDRReconciler{
		Client:             mgr.GetClient(),
		CIDRs:              &ipamv1alpha1.CIDRs{},
		CIDRsList:          &ipamv1alpha1.CIDRsList{},
		HTTPHeadersEnabled: httpHeadersEnabled,
		SourceOptions:      cidrSource,
	}).SetupWithManager(mgr, namePrefix); err != nil {
		return &setupError{error: err, controllerType: "CIDRs"}
	}
	if err := (&CIDRReconciler{
		Client:             mgr.GetClient(),
		CIDRs:              &ipamv1alpha1.ClusterCIDRs{},
		CIDRsList:          &ipamv1alpha1.ClusterCIDRsList{},
		HTTPHeadersEnabled: httpHeadersEnabled,
		SourceOptions:      cidrSource,
	}).SetupWithManager(mgr, namePrefix); err != nil {
		return &setupError{error: err, controllerType: "ClusterCIDRs"}
	}

	managedBy := "ingress-allowlisting-controller"
	if namePrefix != "" {
		managedBy = namePrefix + "-ingress-allowlisting-controller"
	}

	mapper := mgr.GetRESTMapper()
	l4Writers, l7Writers := BuildWriterRegistries(mgr.GetClient(), mapper, managedBy, annotationPrefix)

	if _, ok := l4Writers[writers.IstioControllerName]; ok {
		setupLog.Infof("detected Istio: enabling Istio writers")
	}
	if _, ok := l7Writers[writers.TraefikControllerName]; ok {
		setupLog.Infof("detected Traefik: enabling Traefik writer")
	}

	if httpRouteSupportEnabled && len(l7Writers) == 0 {
		setupLog.Warnf("httproute support is enabled but no L7 writer was detected (neither Istio nor Traefik CRDs found); HTTPRoutes will be reconciled but no allowlist resources will be written")
	}

	if gatewaySupportEnabled {
		gatewayReconciler := GatewayAllowlistingReconciler{
			Client:       mgr.GetClient(),
			Scheme:       mgr.GetScheme(),
			CidrResolver: cidrResolver,
			L4Writers:    l4Writers,
		}
		if err := gatewayReconciler.SetupWithManager(mgr, namePrefix); err != nil {
			return &setupError{error: err, controllerType: "Gateway"}
		}
	}
	if networkPolicySupportEnabled {
		networkPolicyReconciler := NetworkPolicyReconciler{
			Client:       mgr.GetClient(),
			Scheme:       mgr.GetScheme(),
			CidrResolver: cidrResolver,
		}
		if err := networkPolicyReconciler.SetupWithManager(mgr, namePrefix); err != nil {
			return &setupError{error: err, controllerType: "NetworkPolicy"}
		}
	}
	if serviceSupportEnabled {
		serviceReconciler := ServiceReconciler{
			Client:       mgr.GetClient(),
			Scheme:       mgr.GetScheme(),
			CidrResolver: cidrResolver,
		}
		if err := serviceReconciler.SetupWithManager(mgr, namePrefix); err != nil {
			return &setupError{error: err, controllerType: "Service"}
		}
	}

	if httpRouteSupportEnabled {
		httpRouteReconciler := HTTPRouteAllowlistingReconciler{
			Client:       mgr.GetClient(),
			Scheme:       mgr.GetScheme(),
			CidrResolver: cidrResolver,
			L7Writers:    l7Writers,
		}
		if err := httpRouteReconciler.SetupWithManager(mgr, namePrefix); err != nil {
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
