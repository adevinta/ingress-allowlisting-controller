package controllers

import (
	"context"
	"errors"
	"testing"

	istioApiSecurityV1 "istio.io/api/security/v1"
	istiosecurityv1 "istio.io/client-go/pkg/apis/security/v1"

	ipamv1alpha1 "github.com/adevinta/ingress-allowlisting-controller/pkg/apis/ipam.adevinta.com/v1alpha1"
	"github.com/adevinta/ingress-allowlisting-controller/pkg/resolvers"
	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	gatewayApiv1 "sigs.k8s.io/gateway-api/apis/v1"
)

func newHTTPRouteReconciler(t *testing.T, k8sClient client.Client, scheme *runtime.Scheme) *HTTPRouteAllowlistingReconciler {
	t.Helper()
	resolver := resolvers.CidrResolver{Client: k8sClient, AnnotationPrefix: resolvers.DefaultPrefix}
	return &HTTPRouteAllowlistingReconciler{Client: k8sClient, CidrResolver: resolver, Scheme: scheme}
}

// cases:
// v - HTTPRoute has annotations and ipamv1alpha1.CIDRs exists — creates AuthorizationPolicy in same namespace
// v - HTTPRoute has cluster-allowlist-group annotation — resolves cluster CIDRs
// v - HTTPRoute has no allowlist annotation — no AuthorizationPolicy created
// v - HTTPRoute has allowlist annotation but no gateway annotation — no AuthorizationPolicy created
// v - HTTPRoute has spec.hostnames — To rule included in policy
// v - HTTPRoute has no spec.hostnames — no To rule in policy
// v - HTTPRoute has ipam.adevinta.com/namespace annotation — AuthorizationPolicy created in cross namespace
// v - CIDRs partially not found — policy created with found CIDRs
// v - ALL CIDRs not found — policy created with deny-all 127.0.0.2/32
// v - TargetRefs points to gateway named in annotation
// v - Error from k8s API propagates
func TestReconcileHTTPRoute(t *testing.T) {
	localnetCidrs := &ipamv1alpha1.CIDRs{
		ObjectMeta: v1.ObjectMeta{Name: "localnet", Namespace: "mynamespace"},
		Status:     ipamv1alpha1.CIDRsStatus{CIDRs: []string{"192.168.0.0/16", "172.16.0.0/12", "10.0.0.0/8"}},
	}
	globalCidrs := &ipamv1alpha1.ClusterCIDRs{
		ObjectMeta: v1.ObjectMeta{Name: "globalnet"},
		Status:     ipamv1alpha1.CIDRsStatus{CIDRs: []string{"15.13.12.0/24"}},
	}
	httproute := &gatewayApiv1.HTTPRoute{
		ObjectMeta: v1.ObjectMeta{Namespace: "mynamespace", Name: "test", Annotations: map[string]string{
			"ipam.adevinta.com/cluster-allowlist-group": "globalnet",
			"ipam.adevinta.com/allowlist-group":         "localnet",
			"ipam.adevinta.com/gateway":                 "my-gateway",
		}},
		Spec: gatewayApiv1.HTTPRouteSpec{
			Hostnames: []gatewayApiv1.Hostname{"example.com", "www.example.com"},
		},
	}
	k8sClient := fake.NewClientBuilder().WithScheme(extendedScheme).WithObjects(localnetCidrs, httproute, globalCidrs).Build()
	reconciler := newHTTPRouteReconciler(t, k8sClient, extendedScheme)

	_, err := reconciler.Reconcile(context.Background(), reconcile.Request{NamespacedName: client.ObjectKey{Name: "test", Namespace: "mynamespace"}})
	assert.NoError(t, err)

	generatedPolicy := &istiosecurityv1.AuthorizationPolicy{}
	err = k8sClient.Get(context.Background(), client.ObjectKey{Name: "test", Namespace: "mynamespace"}, generatedPolicy)
	assert.NoError(t, err)

	assert.Equal(t, istioApiSecurityV1.AuthorizationPolicy_ALLOW, generatedPolicy.Spec.Action)
	assert.ElementsMatch(t,
		[]string{"192.168.0.0/16", "172.16.0.0/12", "10.0.0.0/8", "15.13.12.0/24"},
		generatedPolicy.Spec.Rules[0].From[0].Source.RemoteIpBlocks,
	)
	assert.ElementsMatch(t,
		[]string{"example.com", "www.example.com"},
		generatedPolicy.Spec.Rules[0].To[0].Operation.Hosts,
	)
	assert.Len(t, generatedPolicy.Spec.TargetRefs, 1)
	assert.Equal(t, "my-gateway", generatedPolicy.Spec.TargetRefs[0].Name)
	assert.Equal(t, "Gateway", generatedPolicy.Spec.TargetRefs[0].Kind)
	assert.Equal(t, "gateway.networking.k8s.io", generatedPolicy.Spec.TargetRefs[0].Group)

	events := &corev1.EventList{}
	assert.NoError(t, k8sClient.List(context.Background(), events, &client.ListOptions{Namespace: "mynamespace"}))
	assert.Empty(t, events.Items)
}

func TestReconcileHTTPRouteNoHostnames(t *testing.T) {
	localnetCidrs := &ipamv1alpha1.CIDRs{
		ObjectMeta: v1.ObjectMeta{Name: "localnet", Namespace: "mynamespace"},
		Status:     ipamv1alpha1.CIDRsStatus{CIDRs: []string{"10.0.0.0/8"}},
	}
	httproute := &gatewayApiv1.HTTPRoute{
		ObjectMeta: v1.ObjectMeta{Namespace: "mynamespace", Name: "test", Annotations: map[string]string{
			"ipam.adevinta.com/allowlist-group": "localnet",
			"ipam.adevinta.com/gateway":         "my-gateway",
		}},
		// no Spec.Hostnames
	}
	k8sClient := fake.NewClientBuilder().WithScheme(extendedScheme).WithObjects(localnetCidrs, httproute).Build()
	reconciler := newHTTPRouteReconciler(t, k8sClient, extendedScheme)

	_, err := reconciler.Reconcile(context.Background(), reconcile.Request{NamespacedName: client.ObjectKey{Name: "test", Namespace: "mynamespace"}})
	assert.NoError(t, err)

	generatedPolicy := &istiosecurityv1.AuthorizationPolicy{}
	err = k8sClient.Get(context.Background(), client.ObjectKey{Name: "test", Namespace: "mynamespace"}, generatedPolicy)
	assert.NoError(t, err)
	assert.Nil(t, generatedPolicy.Spec.Rules[0].To, "To rule should be absent when no hostnames")
}

func TestReconcileHTTPRouteNoAllowlistAnnotation(t *testing.T) {
	httproute := &gatewayApiv1.HTTPRoute{
		ObjectMeta: v1.ObjectMeta{Namespace: "mynamespace", Name: "test", Annotations: map[string]string{
			"ipam.adevinta.com/gateway": "my-gateway",
		}},
	}
	k8sClient := fake.NewClientBuilder().WithScheme(extendedScheme).WithObjects(httproute).Build()
	reconciler := newHTTPRouteReconciler(t, k8sClient, extendedScheme)

	_, err := reconciler.Reconcile(context.Background(), reconcile.Request{NamespacedName: client.ObjectKey{Name: "test", Namespace: "mynamespace"}})
	assert.NoError(t, err)

	generatedPolicy := &istiosecurityv1.AuthorizationPolicy{}
	err = k8sClient.Get(context.Background(), client.ObjectKey{Name: "test", Namespace: "mynamespace"}, generatedPolicy)
	assert.True(t, apierrors.IsNotFound(err), "no AuthorizationPolicy should be created without allowlist annotation")
}

func TestReconcileHTTPRouteNoGatewayAnnotation(t *testing.T) {
	localnetCidrs := &ipamv1alpha1.CIDRs{
		ObjectMeta: v1.ObjectMeta{Name: "localnet", Namespace: "mynamespace"},
		Status:     ipamv1alpha1.CIDRsStatus{CIDRs: []string{"10.0.0.0/8"}},
	}
	httproute := &gatewayApiv1.HTTPRoute{
		ObjectMeta: v1.ObjectMeta{Namespace: "mynamespace", Name: "test", Annotations: map[string]string{
			"ipam.adevinta.com/allowlist-group": "localnet",
			// no gateway annotation
		}},
	}
	k8sClient := fake.NewClientBuilder().WithScheme(extendedScheme).WithObjects(localnetCidrs, httproute).Build()
	reconciler := newHTTPRouteReconciler(t, k8sClient, extendedScheme)

	_, err := reconciler.Reconcile(context.Background(), reconcile.Request{NamespacedName: client.ObjectKey{Name: "test", Namespace: "mynamespace"}})
	assert.NoError(t, err)

	generatedPolicy := &istiosecurityv1.AuthorizationPolicy{}
	err = k8sClient.Get(context.Background(), client.ObjectKey{Name: "test", Namespace: "mynamespace"}, generatedPolicy)
	assert.True(t, apierrors.IsNotFound(err), "no AuthorizationPolicy should be created without gateway annotation")
}

func TestReconcileHTTPRouteCrossNamespace(t *testing.T) {
	localnetCidrs := &ipamv1alpha1.CIDRs{
		ObjectMeta: v1.ObjectMeta{Name: "localnet", Namespace: "mynamespace"},
		Status:     ipamv1alpha1.CIDRsStatus{CIDRs: []string{"10.0.0.0/8"}},
	}
	httproute := &gatewayApiv1.HTTPRoute{
		ObjectMeta: v1.ObjectMeta{Namespace: "mynamespace", Name: "test", Annotations: map[string]string{
			"ipam.adevinta.com/allowlist-group": "localnet",
			"ipam.adevinta.com/gateway":         "my-gateway",
			"ipam.adevinta.com/namespace":       "gateway-namespace",
		}},
		Spec: gatewayApiv1.HTTPRouteSpec{
			Hostnames: []gatewayApiv1.Hostname{"example.com"},
		},
	}
	k8sClient := fake.NewClientBuilder().WithScheme(extendedScheme).WithObjects(localnetCidrs, httproute).Build()
	reconciler := newHTTPRouteReconciler(t, k8sClient, extendedScheme)

	_, err := reconciler.Reconcile(context.Background(), reconcile.Request{NamespacedName: client.ObjectKey{Name: "test", Namespace: "mynamespace"}})
	assert.NoError(t, err)

	// Policy should be in gateway-namespace, not mynamespace
	generatedPolicy := &istiosecurityv1.AuthorizationPolicy{}
	err = k8sClient.Get(context.Background(), client.ObjectKey{Name: "test", Namespace: "gateway-namespace"}, generatedPolicy)
	assert.NoError(t, err, "AuthorizationPolicy should be created in cross-namespace")
	assert.ElementsMatch(t, []string{"10.0.0.0/8"}, generatedPolicy.Spec.Rules[0].From[0].Source.RemoteIpBlocks)
	assert.Equal(t, "my-gateway", generatedPolicy.Spec.TargetRefs[0].Name)

	// Should NOT be in the httproute's namespace
	notExpectedPolicy := &istiosecurityv1.AuthorizationPolicy{}
	err = k8sClient.Get(context.Background(), client.ObjectKey{Name: "test", Namespace: "mynamespace"}, notExpectedPolicy)
	assert.True(t, apierrors.IsNotFound(err), "AuthorizationPolicy should NOT be in the HTTPRoute namespace")
}

func TestReconcileHTTPRouteWithClusterCIDR(t *testing.T) {
	globalNet := &ipamv1alpha1.ClusterCIDRs{
		ObjectMeta: v1.ObjectMeta{Name: "globalnet"},
		Status:     ipamv1alpha1.CIDRsStatus{CIDRs: []string{"192.168.0.0/16", "172.16.0.0/12", "10.0.0.0/8"}},
	}
	anotherGlobalNet := &ipamv1alpha1.ClusterCIDRs{
		ObjectMeta: v1.ObjectMeta{Name: "anotherglobalnet"},
		Status:     ipamv1alpha1.CIDRsStatus{CIDRs: []string{"15.13.12.0/24"}},
	}
	httproute := &gatewayApiv1.HTTPRoute{
		ObjectMeta: v1.ObjectMeta{Namespace: "mynamespace", Name: "test", Annotations: map[string]string{
			"ipam.adevinta.com/cluster-allowlist-group": "globalnet,anotherglobalnet",
			"ipam.adevinta.com/gateway":                 "my-gateway",
		}},
	}
	k8sClient := fake.NewClientBuilder().WithScheme(extendedScheme).WithObjects(httproute, globalNet, anotherGlobalNet).Build()
	reconciler := newHTTPRouteReconciler(t, k8sClient, extendedScheme)

	_, err := reconciler.Reconcile(context.Background(), reconcile.Request{NamespacedName: client.ObjectKey{Name: "test", Namespace: "mynamespace"}})
	assert.NoError(t, err)

	generatedPolicy := &istiosecurityv1.AuthorizationPolicy{}
	err = k8sClient.Get(context.Background(), client.ObjectKey{Name: "test", Namespace: "mynamespace"}, generatedPolicy)
	assert.NoError(t, err)
	assert.ElementsMatch(t,
		[]string{"192.168.0.0/16", "172.16.0.0/12", "10.0.0.0/8", "15.13.12.0/24"},
		generatedPolicy.Spec.Rules[0].From[0].Source.RemoteIpBlocks,
	)
	assert.Equal(t, istioApiSecurityV1.AuthorizationPolicy_ALLOW, generatedPolicy.Spec.Action)
	assert.Len(t, generatedPolicy.Spec.TargetRefs, 1)
	assert.Equal(t, "my-gateway", generatedPolicy.Spec.TargetRefs[0].Name)
}

func TestReconcileHTTPRoutePartialCIDRsNotFound(t *testing.T) {
	localnetCidrs := &ipamv1alpha1.CIDRs{
		ObjectMeta: v1.ObjectMeta{Name: "localnet", Namespace: "mynamespace"},
		Status:     ipamv1alpha1.CIDRsStatus{CIDRs: []string{"192.168.0.0/16", "172.16.0.0/12", "10.0.0.0/8"}},
	}
	httproute := &gatewayApiv1.HTTPRoute{
		ObjectMeta: v1.ObjectMeta{Namespace: "mynamespace", Name: "test", Annotations: map[string]string{
			"ipam.adevinta.com/allowlist-group": "localnet,notexisting",
			"ipam.adevinta.com/gateway":         "my-gateway",
		}},
	}
	k8sClient := fake.NewClientBuilder().WithScheme(extendedScheme).WithObjects(localnetCidrs, httproute).Build()
	reconciler := newHTTPRouteReconciler(t, k8sClient, extendedScheme)

	_, err := reconciler.Reconcile(context.Background(), reconcile.Request{NamespacedName: client.ObjectKey{Name: "test", Namespace: "mynamespace"}})
	assert.NoError(t, err)

	generatedPolicy := &istiosecurityv1.AuthorizationPolicy{}
	err = k8sClient.Get(context.Background(), client.ObjectKey{Name: "test", Namespace: "mynamespace"}, generatedPolicy)
	assert.NoError(t, err)
	assert.ElementsMatch(t,
		[]string{"192.168.0.0/16", "172.16.0.0/12", "10.0.0.0/8"},
		generatedPolicy.Spec.Rules[0].From[0].Source.RemoteIpBlocks,
	)
}

func TestReconcileHTTPRouteAllCIDRsNotFound(t *testing.T) {
	httproute := &gatewayApiv1.HTTPRoute{
		ObjectMeta: v1.ObjectMeta{Name: "test", Namespace: "mynamespace", Annotations: map[string]string{
			"ipam.adevinta.com/allowlist-group": "notexisting,alsonotexisting",
			"ipam.adevinta.com/gateway":         "my-gateway",
		}},
	}
	k8sClient := fake.NewClientBuilder().WithScheme(extendedScheme).WithObjects(httproute).Build()
	reconciler := newHTTPRouteReconciler(t, k8sClient, extendedScheme)

	_, err := reconciler.Reconcile(context.Background(), reconcile.Request{NamespacedName: client.ObjectKey{Name: "test", Namespace: "mynamespace"}})
	assert.NoError(t, err)

	generatedPolicy := &istiosecurityv1.AuthorizationPolicy{}
	err = k8sClient.Get(context.Background(), client.ObjectKey{Name: "test", Namespace: "mynamespace"}, generatedPolicy)
	assert.NoError(t, err)
	assert.ElementsMatch(t, []string{"127.0.0.2/32"}, generatedPolicy.Spec.Rules[0].From[0].Source.RemoteIpBlocks)

	events := &corev1.EventList{}
	k8sClient.List(context.Background(), events, &client.ListOptions{Namespace: "mynamespace"})
	assert.NotEmpty(t, events.Items)
	assert.Equal(t, "LookupAllowListingGroup", events.Items[0].Action)
}

func TestReconcileHTTPRouteTargetRefs(t *testing.T) {
	localnetCidrs := &ipamv1alpha1.CIDRs{
		ObjectMeta: v1.ObjectMeta{Name: "localnet", Namespace: "mynamespace"},
		Status:     ipamv1alpha1.CIDRsStatus{CIDRs: []string{"10.0.0.0/8"}},
	}
	httproute := &gatewayApiv1.HTTPRoute{
		ObjectMeta: v1.ObjectMeta{Namespace: "mynamespace", Name: "test", Annotations: map[string]string{
			"ipam.adevinta.com/allowlist-group": "localnet",
			"ipam.adevinta.com/gateway":         "specific-gateway",
		}},
	}
	k8sClient := fake.NewClientBuilder().WithScheme(extendedScheme).WithObjects(localnetCidrs, httproute).Build()
	reconciler := newHTTPRouteReconciler(t, k8sClient, extendedScheme)

	_, err := reconciler.Reconcile(context.Background(), reconcile.Request{NamespacedName: client.ObjectKey{Name: "test", Namespace: "mynamespace"}})
	assert.NoError(t, err)

	generatedPolicy := &istiosecurityv1.AuthorizationPolicy{}
	err = k8sClient.Get(context.Background(), client.ObjectKey{Name: "test", Namespace: "mynamespace"}, generatedPolicy)
	assert.NoError(t, err)
	assert.Len(t, generatedPolicy.Spec.TargetRefs, 1)
	ref := generatedPolicy.Spec.TargetRefs[0]
	assert.Equal(t, "specific-gateway", ref.Name)
	assert.Equal(t, "Gateway", ref.Kind)
	assert.Equal(t, "gateway.networking.k8s.io", ref.Group)
}

func TestReconcileHTTPRouteError(t *testing.T) {
	k8sClient := &testfunc{WithWatch: fake.NewClientBuilder().WithScheme(extendedScheme).Build()}
	k8sClient.getfunc = func(ctx context.Context, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
		return errors.New("error that is not a NOTFOUND")
	}

	reconciler := newHTTPRouteReconciler(t, k8sClient, extendedScheme)

	_, err := reconciler.Reconcile(context.Background(), reconcile.Request{NamespacedName: client.ObjectKey{Name: "test", Namespace: "mynamespace"}})
	assert.Error(t, err)
}

func TestReconcileHTTPRouteWithAnnotationSpaces(t *testing.T) {
	localnetCidrs := &ipamv1alpha1.CIDRs{
		ObjectMeta: v1.ObjectMeta{Name: "localnet", Namespace: "mynamespace"},
		Status:     ipamv1alpha1.CIDRsStatus{CIDRs: []string{"192.168.0.0/16"}},
	}
	dnssourceCidrs := &ipamv1alpha1.CIDRs{
		ObjectMeta: v1.ObjectMeta{Name: "dnssource", Namespace: "mynamespace"},
		Status:     ipamv1alpha1.CIDRsStatus{CIDRs: []string{"1.1.1.1/32"}},
	}
	httproute := &gatewayApiv1.HTTPRoute{
		ObjectMeta: v1.ObjectMeta{Namespace: "mynamespace", Name: "test", Annotations: map[string]string{
			"ipam.adevinta.com/allowlist-group": "localnet, dnssource",
			"ipam.adevinta.com/gateway":         "my-gateway",
		}},
	}
	k8sClient := fake.NewClientBuilder().WithScheme(extendedScheme).WithObjects(localnetCidrs, dnssourceCidrs, httproute).Build()
	reconciler := newHTTPRouteReconciler(t, k8sClient, extendedScheme)

	_, err := reconciler.Reconcile(context.Background(), reconcile.Request{NamespacedName: client.ObjectKey{Name: "test", Namespace: "mynamespace"}})
	assert.NoError(t, err)

	generatedPolicy := &istiosecurityv1.AuthorizationPolicy{}
	err = k8sClient.Get(context.Background(), client.ObjectKey{Name: "test", Namespace: "mynamespace"}, generatedPolicy)
	assert.NoError(t, err)
	assert.ElementsMatch(t, []string{"192.168.0.0/16", "1.1.1.1/32"}, generatedPolicy.Spec.Rules[0].From[0].Source.RemoteIpBlocks)
}

func TestCidrToHTTPRouteMapper(t *testing.T) {
	t.Run("CIDR is being used in the httproute, should return the httproute", func(t *testing.T) {
		httproute := &gatewayApiv1.HTTPRoute{
			ObjectMeta: v1.ObjectMeta{Name: "test", Namespace: "mynamespace", Annotations: map[string]string{"ipam.adevinta.com/allowlist-group": "localnet,dnssource"}},
		}
		k8sClient := fake.NewClientBuilder().WithScheme(extendedScheme).WithObjects(httproute).Build()
		cidr := ipamv1alpha1.CIDRs{
			ObjectMeta: v1.ObjectMeta{Name: "localnet", Namespace: "mynamespace"},
		}
		requests := newHTTPRoutesFromCIDRFuncMap(k8sClient, "ipam.adevinta.com/allowlist-group")(context.Background(), &cidr)
		assert.Len(t, requests, 1)
		assert.Equal(t, "test", requests[0].Name)
	})

	t.Run("CIDR is not being used in the httproute, should return an empty list", func(t *testing.T) {
		httproute := &gatewayApiv1.HTTPRoute{
			ObjectMeta: v1.ObjectMeta{Name: "test", Namespace: "mynamespace", Annotations: map[string]string{"ipam.adevinta.com/allowlist-group": "dnssource"}},
		}
		k8sClient := fake.NewClientBuilder().WithScheme(extendedScheme).WithObjects(httproute).Build()
		cidr := ipamv1alpha1.CIDRs{
			ObjectMeta: v1.ObjectMeta{Name: "localnet", Namespace: "mynamespace"},
		}
		cidrResolver := resolvers.CidrResolver{Client: k8sClient, AnnotationPrefix: resolvers.DefaultPrefix}
		requests := newHTTPRoutesFromCIDRFuncMap(k8sClient, cidrResolver.Annotation())(context.Background(), &cidr)
		assert.Len(t, requests, 0)
	})

	t.Run("One CIDR is being used in one httproute, should return just that one", func(t *testing.T) {
		httproute1 := &gatewayApiv1.HTTPRoute{
			ObjectMeta: v1.ObjectMeta{Name: "test", Namespace: "mynamespace"},
		}
		httproute2 := &gatewayApiv1.HTTPRoute{
			ObjectMeta: v1.ObjectMeta{Name: "test2", Namespace: "mynamespace", Annotations: map[string]string{"ipam.adevinta.com/allowlist-group": "dnssource"}},
		}
		k8sClient := fake.NewClientBuilder().WithScheme(extendedScheme).WithObjects(httproute1, httproute2).Build()
		cidr := ipamv1alpha1.CIDRs{
			ObjectMeta: v1.ObjectMeta{Name: "dnssource", Namespace: "mynamespace"},
		}
		cidrResolver := resolvers.CidrResolver{Client: k8sClient, AnnotationPrefix: resolvers.DefaultPrefix}
		requests := newHTTPRoutesFromCIDRFuncMap(k8sClient, cidrResolver.Annotation())(context.Background(), &cidr)
		assert.Len(t, requests, 1)
		assert.Equal(t, "test2", requests[0].Name)
	})
}

func TestClusterCidrToHTTPRouteMapper(t *testing.T) {
	t.Run("ClusterCIDR is being used in the httproute, should return the httproute", func(t *testing.T) {
		httproute := &gatewayApiv1.HTTPRoute{
			ObjectMeta: v1.ObjectMeta{Name: "test", Namespace: "mynamespace", Annotations: map[string]string{"ipam.adevinta.com/cluster-allowlist-group": "localnet,dnssource"}},
		}
		k8sClient := fake.NewClientBuilder().WithScheme(extendedScheme).WithObjects(httproute).Build()
		cidr := ipamv1alpha1.ClusterCIDRs{
			ObjectMeta: v1.ObjectMeta{Name: "localnet"},
		}
		cidrResolver := resolvers.CidrResolver{Client: k8sClient, AnnotationPrefix: resolvers.DefaultPrefix}
		requests := newHTTPRoutesFromCIDRFuncMap(k8sClient, cidrResolver.ClusterAnnotation())(context.Background(), &cidr)
		assert.Len(t, requests, 1)
		assert.Equal(t, "test", requests[0].Name)
	})

	t.Run("ClusterCIDR is not being used in the httproute, should return an empty list", func(t *testing.T) {
		httproute := &gatewayApiv1.HTTPRoute{
			ObjectMeta: v1.ObjectMeta{Name: "test", Namespace: "mynamespace", Annotations: map[string]string{"ipam.adevinta.com/cluster-allowlist-group": "dnssource"}},
		}
		k8sClient := fake.NewClientBuilder().WithScheme(extendedScheme).WithObjects(httproute).Build()
		cidr := ipamv1alpha1.ClusterCIDRs{
			ObjectMeta: v1.ObjectMeta{Name: "localnet", Namespace: "mynamespace"},
		}
		cidrResolver := resolvers.CidrResolver{Client: k8sClient, AnnotationPrefix: resolvers.DefaultPrefix}
		requests := newHTTPRoutesFromCIDRFuncMap(k8sClient, cidrResolver.ClusterAnnotation())(context.Background(), &cidr)
		assert.Len(t, requests, 0)
	})
}

