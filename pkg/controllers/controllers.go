package controllers

import (
	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	netv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	ctrl "sigs.k8s.io/controller-runtime"

	ipamv1alpha1 "github.com/adevinta/ingress-allowlisting-controller/pkg/apis/ipam.adevinta.com/v1alpha1"
	ipamv1alpha1_legacy "github.com/adevinta/ingress-allowlisting-controller/pkg/apis/legacy/v1alpha1"
	"github.com/adevinta/ingress-allowlisting-controller/pkg/resolvers"

	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrlscheme "sigs.k8s.io/controller-runtime/pkg/scheme"

	istiosecurityv1 "istio.io/client-go/pkg/apis/security/v1"
	gatewayApiv1 "sigs.k8s.io/gateway-api/apis/v1"
)

type setupError struct {
	error
	controllerType string
}

func (e *setupError) Log(logger logr.Logger) {
	logger.Error(e, "unable to create controller", "controller", "Ingress")
}

func SetupControllersWithManager(mgr ctrl.Manager, gatewaySupportEnabled bool, legacyGroupVersion, namePrefix string, annotationPrefix string) error {
	cidrResolver := resolvers.CidrResolver{AnnotationPrefix: annotationPrefix, Client: mgr.GetClient()}

	if err := (&IngressReconciler{
		Client:             mgr.GetClient(),
		Scheme:             mgr.GetScheme(),
		LegacyGroupVersion: legacyGroupVersion,
		CidrResolver:       cidrResolver,
	}).SetupWithManager(mgr, namePrefix); err != nil {
		return &setupError{error: err, controllerType: "Ingress"}
	}

	if err := (&CIDRReconciler{
		Client:    mgr.GetClient(),
		CIDRs:     &ipamv1alpha1.CIDRs{},
		CIDRsList: &ipamv1alpha1.CIDRsList{},
	}).SetupWithManager(mgr, namePrefix); err != nil {
		return &setupError{error: err, controllerType: "CIDRs"}
	}
	if err := (&CIDRReconciler{
		Client:    mgr.GetClient(),
		CIDRs:     &ipamv1alpha1.ClusterCIDRs{},
		CIDRsList: &ipamv1alpha1.ClusterCIDRsList{},
	}).SetupWithManager(mgr, namePrefix); err != nil {
		return &setupError{error: err, controllerType: "ClusterCIDRs"}
	}

	if legacyGroupVersion != "" {
		if err := (&CIDRReconciler{
			Client:    mgr.GetClient(),
			CIDRs:     &ipamv1alpha1_legacy.CIDRs{},
			CIDRsList: &ipamv1alpha1_legacy.CIDRsList{},
		}).SetupWithManager(mgr, namePrefix); err != nil {
			return &setupError{error: err, controllerType: "LegacyCIDRs"}
		}
		if err := (&CIDRReconciler{
			Client:    mgr.GetClient(),
			CIDRs:     &ipamv1alpha1_legacy.ClusterCIDRs{},
			CIDRsList: &ipamv1alpha1_legacy.ClusterCIDRsList{},
		}).SetupWithManager(mgr, namePrefix); err != nil {
			return &setupError{error: err, controllerType: "LegacyClusterCIDRs"}
		}
	}

	if gatewaySupportEnabled {
		gatewayReconciler := GatewayAllowlistingReconciler{
			Client:             mgr.GetClient(),
			Scheme:             mgr.GetScheme(),
			LegacyGroupVersion: legacyGroupVersion,
			CidrResolver:       cidrResolver,
		}
		if err := gatewayReconciler.SetupWithManager(mgr, namePrefix); err != nil {
			return &setupError{error: err, controllerType: "Gateway"}
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

	if legacyGroupVersion != "" {
		var err error
		scheme, err = LegacyScheme(legacyGroupVersion, scheme)
		if err != nil {
			return nil, err
		}
	}

	return scheme, nil
}
