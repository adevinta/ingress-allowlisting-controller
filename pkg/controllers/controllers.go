package controllers

import (
	"github.com/go-logr/logr"
	log "github.com/adevinta/go-log-toolkit"
	corev1 "k8s.io/api/core/v1"
	netv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	ipamv1alpha1 "github.com/adevinta/ingress-allowlisting-controller/pkg/apis/ipam.adevinta.com/v1alpha1"
	ipamv1alpha1_legacy "github.com/adevinta/ingress-allowlisting-controller/pkg/apis/legacy/v1alpha1"
	"github.com/adevinta/ingress-allowlisting-controller/pkg/controllers/writers"
	"github.com/adevinta/ingress-allowlisting-controller/pkg/resolvers"

	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrlscheme "sigs.k8s.io/controller-runtime/pkg/scheme"

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

func SetupControllersWithManager(mgr ctrl.Manager, ingressSupportEnabled bool, gatewaySupportEnabled bool, networkPolicySupportEnabled bool, httpRouteSupportEnabled bool, legacyGroupVersion, namePrefix string, annotationPrefix string, httpHeadersEnabled bool) error {
	cidrResolver := resolvers.CidrResolver{AnnotationPrefix: annotationPrefix, Client: mgr.GetClient()}

	if ingressSupportEnabled {
		if err := (&IngressReconciler{
			Client:             mgr.GetClient(),
			Scheme:             mgr.GetScheme(),
			LegacyGroupVersion: legacyGroupVersion,
			CidrResolver:       cidrResolver,
		}).SetupWithManager(mgr, namePrefix); err != nil {
			return &setupError{error: err, controllerType: "Ingress"}
		}
	}

	if err := (&CIDRReconciler{
		Client:             mgr.GetClient(),
		CIDRs:              &ipamv1alpha1.CIDRs{},
		CIDRsList:          &ipamv1alpha1.CIDRsList{},
		HTTPHeadersEnabled: httpHeadersEnabled,
	}).SetupWithManager(mgr, namePrefix); err != nil {
		return &setupError{error: err, controllerType: "CIDRs"}
	}
	if err := (&CIDRReconciler{
		Client:             mgr.GetClient(),
		CIDRs:              &ipamv1alpha1.ClusterCIDRs{},
		CIDRsList:          &ipamv1alpha1.ClusterCIDRsList{},
		HTTPHeadersEnabled: httpHeadersEnabled,
	}).SetupWithManager(mgr, namePrefix); err != nil {
		return &setupError{error: err, controllerType: "ClusterCIDRs"}
	}

	if legacyGroupVersion != "" {
		if err := (&CIDRReconciler{
			Client:             mgr.GetClient(),
			CIDRs:              &ipamv1alpha1_legacy.CIDRs{},
			CIDRsList:          &ipamv1alpha1_legacy.CIDRsList{},
			HTTPHeadersEnabled: httpHeadersEnabled,
		}).SetupWithManager(mgr, namePrefix); err != nil {
			return &setupError{error: err, controllerType: "LegacyCIDRs"}
		}
		if err := (&CIDRReconciler{
			Client:             mgr.GetClient(),
			CIDRs:              &ipamv1alpha1_legacy.ClusterCIDRs{},
			CIDRsList:          &ipamv1alpha1_legacy.ClusterCIDRsList{},
			HTTPHeadersEnabled: httpHeadersEnabled,
		}).SetupWithManager(mgr, namePrefix); err != nil {
			return &setupError{error: err, controllerType: "LegacyClusterCIDRs"}
		}
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
			Client:             mgr.GetClient(),
			Scheme:             mgr.GetScheme(),
			LegacyGroupVersion: legacyGroupVersion,
			CidrResolver:       cidrResolver,
			L4Writers:          l4Writers,
		}
		if err := gatewayReconciler.SetupWithManager(mgr, namePrefix); err != nil {
			return &setupError{error: err, controllerType: "Gateway"}
		}
	}
	if networkPolicySupportEnabled {
		networkPolicyReconciler := NetworkPolicyReconciler{
			Client:             mgr.GetClient(),
			Scheme:             mgr.GetScheme(),
			LegacyGroupVersion: legacyGroupVersion,
			CidrResolver:       cidrResolver,
		}
		if err := networkPolicyReconciler.SetupWithManager(mgr, namePrefix); err != nil {
			return &setupError{error: err, controllerType: "NetworkPolicy"}
		}
	}

	if httpRouteSupportEnabled {
		httpRouteReconciler := HTTPRouteAllowlistingReconciler{
			Client:             mgr.GetClient(),
			Scheme:             mgr.GetScheme(),
			LegacyGroupVersion: legacyGroupVersion,
			CidrResolver:       cidrResolver,
			L7Writers:          l7Writers,
		}
		if err := httpRouteReconciler.SetupWithManager(mgr, namePrefix); err != nil {
			return &setupError{error: err, controllerType: "HTTPRoute"}
		}
	}

	return nil
}

func LegacyScheme(legacyGroupVersion string, scheme *runtime.Scheme) (*runtime.Scheme, error) {
	// groupVersion is group version used to register these objects
	groupVersion, err := schema.ParseGroupVersion(legacyGroupVersion)
	if err != nil {
		return nil, err
	}

	// SchemeBuilder is used to add go types to the GroupVersionKind scheme
	schemeBuilder := &ctrlscheme.Builder{GroupVersion: groupVersion}
	schemeBuilder.Register(&ipamv1alpha1_legacy.CIDRs{}, &ipamv1alpha1_legacy.ClusterCIDRs{}, &ipamv1alpha1_legacy.CIDRsList{}, &ipamv1alpha1_legacy.ClusterCIDRsList{})

	// AddToScheme adds the types in this group-version to the given scheme.
	if err := schemeBuilder.AddToScheme(scheme); err != nil {
		return nil, err
	}

	return scheme, nil
}

func Scheme(legacyGroupVersion string) (*runtime.Scheme, error) {
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

	if legacyGroupVersion != "" {
		var err error
		scheme, err = LegacyScheme(legacyGroupVersion, scheme)
		if err != nil {
			return nil, err
		}
	}

	return scheme, nil
}
