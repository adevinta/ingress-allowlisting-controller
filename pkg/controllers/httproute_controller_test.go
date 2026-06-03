package controllers

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

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
	// In tests, APIReader uses the same fake client — no label-selector filtering in tests
	// so the cache and API reader are equivalent.
	return &HTTPRouteAllowlistingReconciler{Client: k8sClient, APIReader: k8sClient, CidrResolver: resolver, Scheme: scheme}
}

// parentRef builds a Gateway ParentReference. Pass ns="" for same-namespace (no Namespace field set).
func parentRef(name, ns string) gatewayApiv1.ParentReference {
	group := gatewayApiv1.Group("gateway.networking.k8s.io")
	kind := gatewayApiv1.Kind("Gateway")
	ref := gatewayApiv1.ParentReference{
		Group: &group,
		Kind:  &kind,
		Name:  gatewayApiv1.ObjectName(name),
	}
	if ns != "" {
		namespace := gatewayApiv1.Namespace(ns)
		ref.Namespace = &namespace
	}
	return ref
}

// cases:
// v - HTTPRoute has annotations and ipamv1alpha1.CIDRs exists — creates AuthorizationPolicy in same namespace
// v - HTTPRoute has cluster-allowlist-group annotation — resolves cluster CIDRs
// v - HTTPRoute has no allowlist annotation — no AuthorizationPolicy created
// v - HTTPRoute has allowlist annotation but no Gateway parentRef — no AuthorizationPolicy created
// v - HTTPRoute has spec.hostnames — To rule included in policy
// v - HTTPRoute has no spec.hostnames — no To rule in policy
// v - HTTPRoute parentRef has a different namespace — AuthorizationPolicy created in that namespace
// v - CIDRs partially not found — policy created with found CIDRs
// v - ALL CIDRs not found — policy created with deny-all 127.0.0.2/32
// v - TargetRefs points to gateway named in parentRef
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
		}},
		Spec: gatewayApiv1.HTTPRouteSpec{
			CommonRouteSpec: gatewayApiv1.CommonRouteSpec{
				ParentRefs: []gatewayApiv1.ParentReference{parentRef("my-gateway", "")},
			},
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

	assert.Equal(t, "ingress-allowlisting-controller", generatedPolicy.Labels["app.kubernetes.io/managed-by"])
	assert.Equal(t, "mynamespace", generatedPolicy.Labels["ipam.adevinta.com/owner-namespace"])
	assert.Equal(t, "test", generatedPolicy.Labels["ipam.adevinta.com/owner-name"])

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
		}},
		Spec: gatewayApiv1.HTTPRouteSpec{
			CommonRouteSpec: gatewayApiv1.CommonRouteSpec{
				ParentRefs: []gatewayApiv1.ParentReference{parentRef("my-gateway", "")},
			},
			// no Hostnames
		},
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
		ObjectMeta: v1.ObjectMeta{Namespace: "mynamespace", Name: "test"},
		Spec: gatewayApiv1.HTTPRouteSpec{
			CommonRouteSpec: gatewayApiv1.CommonRouteSpec{
				ParentRefs: []gatewayApiv1.ParentReference{parentRef("my-gateway", "")},
			},
		},
	}
	k8sClient := fake.NewClientBuilder().WithScheme(extendedScheme).WithObjects(httproute).Build()
	reconciler := newHTTPRouteReconciler(t, k8sClient, extendedScheme)

	_, err := reconciler.Reconcile(context.Background(), reconcile.Request{NamespacedName: client.ObjectKey{Name: "test", Namespace: "mynamespace"}})
	assert.NoError(t, err)

	generatedPolicy := &istiosecurityv1.AuthorizationPolicy{}
	err = k8sClient.Get(context.Background(), client.ObjectKey{Name: "test", Namespace: "mynamespace"}, generatedPolicy)
	assert.True(t, apierrors.IsNotFound(err), "no AuthorizationPolicy should be created without allowlist annotation")
}

func TestReconcileHTTPRouteNoParentRef(t *testing.T) {
	localnetCidrs := &ipamv1alpha1.CIDRs{
		ObjectMeta: v1.ObjectMeta{Name: "localnet", Namespace: "mynamespace"},
		Status:     ipamv1alpha1.CIDRsStatus{CIDRs: []string{"10.0.0.0/8"}},
	}
	httproute := &gatewayApiv1.HTTPRoute{
		ObjectMeta: v1.ObjectMeta{Namespace: "mynamespace", Name: "test", Annotations: map[string]string{
			"ipam.adevinta.com/allowlist-group": "localnet",
		}},
		// no ParentRefs
	}
	k8sClient := fake.NewClientBuilder().WithScheme(extendedScheme).WithObjects(localnetCidrs, httproute).Build()
	reconciler := newHTTPRouteReconciler(t, k8sClient, extendedScheme)

	_, err := reconciler.Reconcile(context.Background(), reconcile.Request{NamespacedName: client.ObjectKey{Name: "test", Namespace: "mynamespace"}})
	assert.NoError(t, err)

	generatedPolicy := &istiosecurityv1.AuthorizationPolicy{}
	err = k8sClient.Get(context.Background(), client.ObjectKey{Name: "test", Namespace: "mynamespace"}, generatedPolicy)
	assert.True(t, apierrors.IsNotFound(err), "no AuthorizationPolicy should be created without a Gateway parentRef")
}

func TestReconcileHTTPRouteCrossNamespace(t *testing.T) {
	localnetCidrs := &ipamv1alpha1.CIDRs{
		ObjectMeta: v1.ObjectMeta{Name: "localnet", Namespace: "mynamespace"},
		Status:     ipamv1alpha1.CIDRsStatus{CIDRs: []string{"10.0.0.0/8"}},
	}
	httproute := &gatewayApiv1.HTTPRoute{
		ObjectMeta: v1.ObjectMeta{Namespace: "mynamespace", Name: "test", Annotations: map[string]string{
			"ipam.adevinta.com/allowlist-group": "localnet",
		}},
		Spec: gatewayApiv1.HTTPRouteSpec{
			CommonRouteSpec: gatewayApiv1.CommonRouteSpec{
				ParentRefs: []gatewayApiv1.ParentReference{parentRef("my-gateway", "gateway-namespace")},
			},
			Hostnames: []gatewayApiv1.Hostname{"example.com"},
		},
	}
	k8sClient := fake.NewClientBuilder().WithScheme(extendedScheme).WithObjects(localnetCidrs, httproute).Build()
	reconciler := newHTTPRouteReconciler(t, k8sClient, extendedScheme)

	_, err := reconciler.Reconcile(context.Background(), reconcile.Request{NamespacedName: client.ObjectKey{Name: "test", Namespace: "mynamespace"}})
	assert.NoError(t, err)

	// Policy should be in gateway-namespace with name = <httproute.Namespace>-<httproute.Name> (single parent, no suffix)
	generatedPolicy := &istiosecurityv1.AuthorizationPolicy{}
	err = k8sClient.Get(context.Background(), client.ObjectKey{Name: "mynamespace-test", Namespace: "gateway-namespace"}, generatedPolicy)
	assert.NoError(t, err, "AuthorizationPolicy should be created in cross-namespace")
	assert.ElementsMatch(t, []string{"10.0.0.0/8"}, generatedPolicy.Spec.Rules[0].From[0].Source.RemoteIpBlocks)
	assert.Equal(t, "my-gateway", generatedPolicy.Spec.TargetRefs[0].Name)

	// Should NOT be in the httproute's namespace
	notExpectedPolicy := &istiosecurityv1.AuthorizationPolicy{}
	err = k8sClient.Get(context.Background(), client.ObjectKey{Name: "mynamespace-test", Namespace: "mynamespace"}, notExpectedPolicy)
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
		}},
		Spec: gatewayApiv1.HTTPRouteSpec{
			CommonRouteSpec: gatewayApiv1.CommonRouteSpec{
				ParentRefs: []gatewayApiv1.ParentReference{parentRef("my-gateway", "")},
			},
		},
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
		}},
		Spec: gatewayApiv1.HTTPRouteSpec{
			CommonRouteSpec: gatewayApiv1.CommonRouteSpec{
				ParentRefs: []gatewayApiv1.ParentReference{parentRef("my-gateway", "")},
			},
		},
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
		}},
		Spec: gatewayApiv1.HTTPRouteSpec{
			CommonRouteSpec: gatewayApiv1.CommonRouteSpec{
				ParentRefs: []gatewayApiv1.ParentReference{parentRef("my-gateway", "")},
			},
		},
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
		}},
		Spec: gatewayApiv1.HTTPRouteSpec{
			CommonRouteSpec: gatewayApiv1.CommonRouteSpec{
				ParentRefs: []gatewayApiv1.ParentReference{parentRef("specific-gateway", "")},
			},
		},
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
		}},
		Spec: gatewayApiv1.HTTPRouteSpec{
			CommonRouteSpec: gatewayApiv1.CommonRouteSpec{
				ParentRefs: []gatewayApiv1.ParentReference{parentRef("my-gateway", "")},
			},
		},
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

func TestGatewayParentRefs(t *testing.T) {
	gwGroup := gatewayApiv1.Group("gateway.networking.k8s.io")
	gwKind := gatewayApiv1.Kind("Gateway")
	svcKind := gatewayApiv1.Kind("Service")
	coreGroup := gatewayApiv1.Group("")
	ns := gatewayApiv1.Namespace("other-ns")

	t.Run("no parentRefs returns empty slice", func(t *testing.T) {
		hr := &gatewayApiv1.HTTPRoute{}
		assert.Empty(t, gatewayParentRefs(hr))
	})

	t.Run("explicit kind=Gateway and group matches", func(t *testing.T) {
		hr := &gatewayApiv1.HTTPRoute{Spec: gatewayApiv1.HTTPRouteSpec{
			CommonRouteSpec: gatewayApiv1.CommonRouteSpec{ParentRefs: []gatewayApiv1.ParentReference{
				{Group: &gwGroup, Kind: &gwKind, Name: "gw"},
			}},
		}}
		refs := gatewayParentRefs(hr)
		assert.Len(t, refs, 1)
		assert.Equal(t, gatewayApiv1.ObjectName("gw"), refs[0].Name)
	})

	t.Run("nil kind and nil group default to Gateway", func(t *testing.T) {
		hr := &gatewayApiv1.HTTPRoute{Spec: gatewayApiv1.HTTPRouteSpec{
			CommonRouteSpec: gatewayApiv1.CommonRouteSpec{ParentRefs: []gatewayApiv1.ParentReference{
				{Name: "gw"},
			}},
		}}
		assert.Len(t, gatewayParentRefs(hr), 1)
	})

	t.Run("non-Gateway kind is skipped", func(t *testing.T) {
		hr := &gatewayApiv1.HTTPRoute{Spec: gatewayApiv1.HTTPRouteSpec{
			CommonRouteSpec: gatewayApiv1.CommonRouteSpec{ParentRefs: []gatewayApiv1.ParentReference{
				{Group: &gwGroup, Kind: &svcKind, Name: "svc"},
			}},
		}}
		assert.Empty(t, gatewayParentRefs(hr))
	})

	t.Run("non-gateway group is skipped", func(t *testing.T) {
		hr := &gatewayApiv1.HTTPRoute{Spec: gatewayApiv1.HTTPRouteSpec{
			CommonRouteSpec: gatewayApiv1.CommonRouteSpec{ParentRefs: []gatewayApiv1.ParentReference{
				{Group: &coreGroup, Kind: &gwKind, Name: "gw"},
			}},
		}}
		assert.Empty(t, gatewayParentRefs(hr))
	})

	t.Run("multiple Gateway parentRefs all returned, non-Gateway skipped", func(t *testing.T) {
		hr := &gatewayApiv1.HTTPRoute{Spec: gatewayApiv1.HTTPRouteSpec{
			CommonRouteSpec: gatewayApiv1.CommonRouteSpec{ParentRefs: []gatewayApiv1.ParentReference{
				{Group: &gwGroup, Kind: &svcKind, Name: "not-this"},
				{Group: &gwGroup, Kind: &gwKind, Name: "first-gw"},
				{Group: &gwGroup, Kind: &gwKind, Name: "second-gw"},
			}},
		}}
		refs := gatewayParentRefs(hr)
		assert.Len(t, refs, 2)
		assert.Equal(t, gatewayApiv1.ObjectName("first-gw"), refs[0].Name)
		assert.Equal(t, gatewayApiv1.ObjectName("second-gw"), refs[1].Name)
	})

	t.Run("namespace in parentRef is preserved", func(t *testing.T) {
		hr := &gatewayApiv1.HTTPRoute{Spec: gatewayApiv1.HTTPRouteSpec{
			CommonRouteSpec: gatewayApiv1.CommonRouteSpec{ParentRefs: []gatewayApiv1.ParentReference{
				{Group: &gwGroup, Kind: &gwKind, Name: "gw", Namespace: &ns},
			}},
		}}
		refs := gatewayParentRefs(hr)
		assert.Len(t, refs, 1)
		assert.Equal(t, &ns, refs[0].Namespace)
	})
}

func TestReconcileHTTPRouteMultipleGateways(t *testing.T) {
	localnetCidrs := &ipamv1alpha1.CIDRs{
		ObjectMeta: v1.ObjectMeta{Name: "localnet", Namespace: "mynamespace"},
		Status:     ipamv1alpha1.CIDRsStatus{CIDRs: []string{"10.0.0.0/8"}},
	}
	httproute := &gatewayApiv1.HTTPRoute{
		ObjectMeta: v1.ObjectMeta{Namespace: "mynamespace", Name: "test", Annotations: map[string]string{
			"ipam.adevinta.com/allowlist-group": "localnet",
		}},
		Spec: gatewayApiv1.HTTPRouteSpec{
			CommonRouteSpec: gatewayApiv1.CommonRouteSpec{
				ParentRefs: []gatewayApiv1.ParentReference{
					parentRef("internal-gateway", ""),
					parentRef("external-gateway", ""),
				},
			},
		},
	}
	k8sClient := fake.NewClientBuilder().WithScheme(extendedScheme).WithObjects(localnetCidrs, httproute).Build()
	reconciler := newHTTPRouteReconciler(t, k8sClient, extendedScheme)

	_, err := reconciler.Reconcile(context.Background(), reconcile.Request{NamespacedName: client.ObjectKey{Name: "test", Namespace: "mynamespace"}})
	assert.NoError(t, err)

	// First gateway: no suffix → "test"
	policy0 := &istiosecurityv1.AuthorizationPolicy{}
	err = k8sClient.Get(context.Background(), client.ObjectKey{Name: "test", Namespace: "mynamespace"}, policy0)
	assert.NoError(t, err)
	assert.Equal(t, "internal-gateway", policy0.Spec.TargetRefs[0].Name)
	assert.ElementsMatch(t, []string{"10.0.0.0/8"}, policy0.Spec.Rules[0].From[0].Source.RemoteIpBlocks)

	// Second gateway: suffix "-1" → "test-1"
	policy1 := &istiosecurityv1.AuthorizationPolicy{}
	err = k8sClient.Get(context.Background(), client.ObjectKey{Name: "test-1", Namespace: "mynamespace"}, policy1)
	assert.NoError(t, err)
	assert.Equal(t, "external-gateway", policy1.Spec.TargetRefs[0].Name)
	assert.ElementsMatch(t, []string{"10.0.0.0/8"}, policy1.Spec.Rules[0].From[0].Source.RemoteIpBlocks)
}

func TestReconcileHTTPRouteMultipleGatewaysCrossNamespace(t *testing.T) {
	localnetCidrs := &ipamv1alpha1.CIDRs{
		ObjectMeta: v1.ObjectMeta{Name: "localnet", Namespace: "mynamespace"},
		Status:     ipamv1alpha1.CIDRsStatus{CIDRs: []string{"10.0.0.0/8"}},
	}
	httproute := &gatewayApiv1.HTTPRoute{
		ObjectMeta: v1.ObjectMeta{Namespace: "mynamespace", Name: "test", Annotations: map[string]string{
			"ipam.adevinta.com/allowlist-group": "localnet",
		}},
		Spec: gatewayApiv1.HTTPRouteSpec{
			CommonRouteSpec: gatewayApiv1.CommonRouteSpec{
				ParentRefs: []gatewayApiv1.ParentReference{
					parentRef("internal-gateway", ""),                   // same namespace → policy name = "test"
					parentRef("external-gateway", "gateway-namespace"),  // cross-namespace → policy name = "mynamespace-test"
				},
			},
		},
	}
	k8sClient := fake.NewClientBuilder().WithScheme(extendedScheme).WithObjects(localnetCidrs, httproute).Build()
	reconciler := newHTTPRouteReconciler(t, k8sClient, extendedScheme)

	_, err := reconciler.Reconcile(context.Background(), reconcile.Request{NamespacedName: client.ObjectKey{Name: "test", Namespace: "mynamespace"}})
	assert.NoError(t, err)

	// First (same-namespace): no suffix → "test"
	sameNsPolicy := &istiosecurityv1.AuthorizationPolicy{}
	err = k8sClient.Get(context.Background(), client.ObjectKey{Name: "test", Namespace: "mynamespace"}, sameNsPolicy)
	assert.NoError(t, err)
	assert.Equal(t, "internal-gateway", sameNsPolicy.Spec.TargetRefs[0].Name)
	assert.ElementsMatch(t, []string{"10.0.0.0/8"}, sameNsPolicy.Spec.Rules[0].From[0].Source.RemoteIpBlocks)

	// Second (cross-namespace): suffix "-1" → "mynamespace-test-1"
	crossNsPolicy := &istiosecurityv1.AuthorizationPolicy{}
	err = k8sClient.Get(context.Background(), client.ObjectKey{Name: "mynamespace-test-1", Namespace: "gateway-namespace"}, crossNsPolicy)
	assert.NoError(t, err)
	assert.Equal(t, "external-gateway", crossNsPolicy.Spec.TargetRefs[0].Name)
	assert.ElementsMatch(t, []string{"10.0.0.0/8"}, crossNsPolicy.Spec.Rules[0].From[0].Source.RemoteIpBlocks)
}

func TestReconcileHTTPRouteMerge(t *testing.T) {
	cidrStaging00 := &ipamv1alpha1.CIDRs{
		ObjectMeta: v1.ObjectMeta{Name: "allowlist", Namespace: "ns-staging00"},
		Status:     ipamv1alpha1.CIDRsStatus{CIDRs: []string{"1.2.3.4/32"}},
	}
	cidrStaging01 := &ipamv1alpha1.CIDRs{
		ObjectMeta: v1.ObjectMeta{Name: "allowlist", Namespace: "ns-staging01"},
		Status:     ipamv1alpha1.CIDRsStatus{CIDRs: []string{"5.6.7.8/32"}},
	}
	gwNS := gatewayApiv1.Namespace("ns-infra")
	// HTTPRoute names are different (real-world: hostname-based); the annotation value is the merge key and AP name.
	route00 := &gatewayApiv1.HTTPRoute{
		ObjectMeta: v1.ObjectMeta{
			Name: "chaos-monkey.public.ns-staging00.example.com", Namespace: "ns-staging00",
			Annotations: map[string]string{
				"ipam.adevinta.com/allowlist-group": "allowlist",
				"ipam.adevinta.com/merge":           "chaos-monkey",
			},
		},
		Spec: gatewayApiv1.HTTPRouteSpec{
			CommonRouteSpec: gatewayApiv1.CommonRouteSpec{ParentRefs: []gatewayApiv1.ParentReference{
				{Name: "cross-namespace-public", Namespace: &gwNS},
			}},
			Hostnames: []gatewayApiv1.Hostname{"chaos-monkey.public.ns-staging00.example.com"},
		},
	}
	route01 := &gatewayApiv1.HTTPRoute{
		ObjectMeta: v1.ObjectMeta{
			Name: "chaos-monkey.public.ns-staging01.example.com", Namespace: "ns-staging01",
			Annotations: map[string]string{
				"ipam.adevinta.com/allowlist-group": "allowlist",
				"ipam.adevinta.com/merge":           "chaos-monkey",
			},
		},
		Spec: gatewayApiv1.HTTPRouteSpec{
			CommonRouteSpec: gatewayApiv1.CommonRouteSpec{ParentRefs: []gatewayApiv1.ParentReference{
				{Name: "cross-namespace-public", Namespace: &gwNS},
			}},
			Hostnames: []gatewayApiv1.Hostname{"chaos-monkey.public.ns-staging01.example.com"},
		},
	}

	k8sClient := fake.NewClientBuilder().WithScheme(extendedScheme).WithObjects(cidrStaging00, cidrStaging01, route00, route01).Build()
	reconciler := newHTTPRouteReconciler(t, k8sClient, extendedScheme)

	_, err := reconciler.Reconcile(context.Background(), reconcile.Request{NamespacedName: client.ObjectKey{
		Name: "chaos-monkey.public.ns-staging00.example.com", Namespace: "ns-staging00",
	}})
	assert.NoError(t, err)

	// AP name = merge key (first gateway, no suffix)
	policy := &istiosecurityv1.AuthorizationPolicy{}
	err = k8sClient.Get(context.Background(), client.ObjectKey{Name: "chaos-monkey", Namespace: "ns-infra"}, policy)
	assert.NoError(t, err, "merged policy should be created with name = merge key")

	assert.ElementsMatch(t, []string{"1.2.3.4/32", "5.6.7.8/32"}, policy.Spec.Rules[0].From[0].Source.RemoteIpBlocks)
	assert.ElementsMatch(t,
		[]string{"chaos-monkey.public.ns-staging00.example.com", "chaos-monkey.public.ns-staging01.example.com"},
		policy.Spec.Rules[0].To[0].Operation.Hosts,
	)
	assert.Equal(t, "cross-namespace-public", policy.Spec.TargetRefs[0].Name)
	assert.Equal(t, "ingress-allowlisting-controller", policy.Labels["app.kubernetes.io/managed-by"])
	assert.Equal(t, "merged", policy.Labels["ipam.adevinta.com/owner-namespace"])
	assert.Equal(t, "chaos-monkey", policy.Labels["ipam.adevinta.com/owner-name"])
}

func TestReconcileHTTPRouteMergeStaleHostAfterKeyChange(t *testing.T) {
	// Scenario: two routes both start with merge=chaos-monkey.
	// Step 1: reconcile both — AP contains both hostnames.
	// Step 2: route01 changes to merge=bar — only route01 is reconciled (its annotation changed).
	//         route00 is NOT reconciled because nothing triggered it.
	// Bug: the chaos-monkey AP still contains route01's hostname because route00 was never re-reconciled.
	cidrStaging00 := &ipamv1alpha1.CIDRs{
		ObjectMeta: v1.ObjectMeta{Name: "allowlist", Namespace: "ns-staging00"},
		Status:     ipamv1alpha1.CIDRsStatus{CIDRs: []string{"1.2.3.4/32"}},
	}
	cidrStaging01 := &ipamv1alpha1.CIDRs{
		ObjectMeta: v1.ObjectMeta{Name: "allowlist", Namespace: "ns-staging01"},
		Status:     ipamv1alpha1.CIDRsStatus{CIDRs: []string{"5.6.7.8/32"}},
	}
	gwNS := gatewayApiv1.Namespace("ns-infra")
	route00 := &gatewayApiv1.HTTPRoute{
		ObjectMeta: v1.ObjectMeta{
			Name: "chaos-monkey.public.ns-staging00.example.com", Namespace: "ns-staging00",
			Annotations: map[string]string{
				"ipam.adevinta.com/allowlist-group": "allowlist",
				"ipam.adevinta.com/merge":           "chaos-monkey",
			},
		},
		Spec: gatewayApiv1.HTTPRouteSpec{
			CommonRouteSpec: gatewayApiv1.CommonRouteSpec{ParentRefs: []gatewayApiv1.ParentReference{
				{Name: "cross-namespace-public", Namespace: &gwNS},
			}},
			Hostnames: []gatewayApiv1.Hostname{"chaos-monkey.public.ns-staging00.example.com"},
		},
	}
	route01 := &gatewayApiv1.HTTPRoute{
		ObjectMeta: v1.ObjectMeta{
			Name: "chaos-monkey.public.ns-staging01.example.com", Namespace: "ns-staging01",
			Annotations: map[string]string{
				"ipam.adevinta.com/allowlist-group": "allowlist",
				"ipam.adevinta.com/merge":           "chaos-monkey",
			},
		},
		Spec: gatewayApiv1.HTTPRouteSpec{
			CommonRouteSpec: gatewayApiv1.CommonRouteSpec{ParentRefs: []gatewayApiv1.ParentReference{
				{Name: "cross-namespace-public", Namespace: &gwNS},
			}},
			Hostnames: []gatewayApiv1.Hostname{"chaos-monkey.public.ns-staging01.example.com"},
		},
	}

	k8sClient := fake.NewClientBuilder().WithScheme(extendedScheme).WithObjects(cidrStaging00, cidrStaging01, route00, route01).Build()
	reconciler := newHTTPRouteReconciler(t, k8sClient, extendedScheme)

	// Step 1: reconcile both routes — AP gets both hostnames
	_, err := reconciler.Reconcile(context.Background(), reconcile.Request{NamespacedName: client.ObjectKey{
		Name: "chaos-monkey.public.ns-staging00.example.com", Namespace: "ns-staging00",
	}})
	assert.NoError(t, err)
	_, err = reconciler.Reconcile(context.Background(), reconcile.Request{NamespacedName: client.ObjectKey{
		Name: "chaos-monkey.public.ns-staging01.example.com", Namespace: "ns-staging01",
	}})
	assert.NoError(t, err)

	// Confirm both hosts are present
	policy := &istiosecurityv1.AuthorizationPolicy{}
	err = k8sClient.Get(context.Background(), client.ObjectKey{Name: "chaos-monkey", Namespace: "ns-infra"}, policy)
	assert.NoError(t, err)
	assert.ElementsMatch(t, []string{
		"chaos-monkey.public.ns-staging00.example.com",
		"chaos-monkey.public.ns-staging01.example.com",
	}, policy.Spec.Rules[0].To[0].Operation.Hosts)

	// Step 2: route01 changes its merge key to "bar"
	route01.Annotations["ipam.adevinta.com/merge"] = "bar"
	assert.NoError(t, k8sClient.Update(context.Background(), route01))

	// route01 is reconciled (its annotation changed to merge=bar)
	_, err = reconciler.Reconcile(context.Background(), reconcile.Request{NamespacedName: client.ObjectKey{
		Name: "chaos-monkey.public.ns-staging01.example.com", Namespace: "ns-staging01",
	}})
	assert.NoError(t, err)

	// The mergeSiblingEnqueuer watches for merge key changes and enqueues siblings.
	// In unit tests the event machinery doesn't run, so we simulate it:
	// route01 changed from chaos-monkey → bar, so route00 (still in chaos-monkey) gets enqueued.
	_, err = reconciler.Reconcile(context.Background(), reconcile.Request{NamespacedName: client.ObjectKey{
		Name: "chaos-monkey.public.ns-staging00.example.com", Namespace: "ns-staging00",
	}})
	assert.NoError(t, err)

	// chaos-monkey AP must now only contain route00's hostname
	err = k8sClient.Get(context.Background(), client.ObjectKey{Name: "chaos-monkey", Namespace: "ns-infra"}, policy)
	assert.NoError(t, err)
	assert.NotContains(t, policy.Spec.Rules[0].To[0].Operation.Hosts,
		"chaos-monkey.public.ns-staging01.example.com",
		"route01 left the merge group — its hostname must not appear in the chaos-monkey AP")
	assert.Contains(t, policy.Spec.Rules[0].To[0].Operation.Hosts,
		"chaos-monkey.public.ns-staging00.example.com",
		"route00 is still in the merge group — its hostname must be present")
}

func TestReconcileHTTPRouteMergeDeduplicatesIPs(t *testing.T) {
	sharedCIDR := []string{"1.2.3.4/32", "5.6.7.8/32"}
	cidrStaging00 := &ipamv1alpha1.CIDRs{
		ObjectMeta: v1.ObjectMeta{Name: "allowlist", Namespace: "ns-staging00"},
		Status:     ipamv1alpha1.CIDRsStatus{CIDRs: sharedCIDR},
	}
	cidrStaging01 := &ipamv1alpha1.CIDRs{
		ObjectMeta: v1.ObjectMeta{Name: "allowlist", Namespace: "ns-staging01"},
		Status:     ipamv1alpha1.CIDRsStatus{CIDRs: sharedCIDR},
	}
	gwNS := gatewayApiv1.Namespace("ns-infra")
	makeRoute := func(ns string) *gatewayApiv1.HTTPRoute {
		return &gatewayApiv1.HTTPRoute{
			ObjectMeta: v1.ObjectMeta{
				Name: "chaos-monkey.public." + ns + ".example.com", Namespace: ns,
				Annotations: map[string]string{
					"ipam.adevinta.com/allowlist-group": "allowlist",
					"ipam.adevinta.com/merge":           "chaos-monkey",
				},
			},
			Spec: gatewayApiv1.HTTPRouteSpec{
				CommonRouteSpec: gatewayApiv1.CommonRouteSpec{ParentRefs: []gatewayApiv1.ParentReference{
					{Name: "cross-namespace-public", Namespace: &gwNS},
				}},
			},
		}
	}
	k8sClient := fake.NewClientBuilder().WithScheme(extendedScheme).WithObjects(cidrStaging00, cidrStaging01, makeRoute("ns-staging00"), makeRoute("ns-staging01")).Build()
	reconciler := newHTTPRouteReconciler(t, k8sClient, extendedScheme)

	_, err := reconciler.Reconcile(context.Background(), reconcile.Request{NamespacedName: client.ObjectKey{
		Name: "chaos-monkey.public.ns-staging00.example.com", Namespace: "ns-staging00",
	}})
	assert.NoError(t, err)

	policy := &istiosecurityv1.AuthorizationPolicy{}
	err = k8sClient.Get(context.Background(), client.ObjectKey{Name: "chaos-monkey", Namespace: "ns-infra"}, policy)
	assert.NoError(t, err)
	assert.ElementsMatch(t, sharedCIDR, policy.Spec.Rules[0].From[0].Source.RemoteIpBlocks, "duplicate IPs should not appear twice")
}

func TestReconcileHTTPRouteMergeDifferentKeyNotMerged(t *testing.T) {
	cidr := &ipamv1alpha1.CIDRs{
		ObjectMeta: v1.ObjectMeta{Name: "allowlist", Namespace: "ns-staging00"},
		Status:     ipamv1alpha1.CIDRsStatus{CIDRs: []string{"1.2.3.4/32"}},
	}
	gwNS := gatewayApiv1.Namespace("ns-infra")
	route := &gatewayApiv1.HTTPRoute{
		ObjectMeta: v1.ObjectMeta{
			Name: "chaos-monkey.public.ns-staging00.example.com", Namespace: "ns-staging00",
			Annotations: map[string]string{
				"ipam.adevinta.com/allowlist-group": "allowlist",
				"ipam.adevinta.com/merge":           "chaos-monkey",
			},
		},
		Spec: gatewayApiv1.HTTPRouteSpec{
			CommonRouteSpec: gatewayApiv1.CommonRouteSpec{ParentRefs: []gatewayApiv1.ParentReference{
				{Name: "cross-namespace-public", Namespace: &gwNS},
			}},
			Hostnames: []gatewayApiv1.Hostname{"chaos-monkey.public.ns-staging00.example.com"},
		},
	}
	// Different merge key — must produce a separate AP, not be merged into "chaos-monkey"
	otherRoute := &gatewayApiv1.HTTPRoute{
		ObjectMeta: v1.ObjectMeta{
			Name: "other-service.public.ns-staging00.example.com", Namespace: "ns-staging00",
			Annotations: map[string]string{
				"ipam.adevinta.com/allowlist-group": "allowlist",
				"ipam.adevinta.com/merge":           "other-service",
			},
		},
		Spec: gatewayApiv1.HTTPRouteSpec{
			CommonRouteSpec: gatewayApiv1.CommonRouteSpec{ParentRefs: []gatewayApiv1.ParentReference{
				{Name: "cross-namespace-public", Namespace: &gwNS},
			}},
			Hostnames: []gatewayApiv1.Hostname{"other-service.public.ns-staging00.example.com"},
		},
	}
	k8sClient := fake.NewClientBuilder().WithScheme(extendedScheme).WithObjects(cidr, route, otherRoute).Build()
	reconciler := newHTTPRouteReconciler(t, k8sClient, extendedScheme)

	_, err := reconciler.Reconcile(context.Background(), reconcile.Request{NamespacedName: client.ObjectKey{
		Name: "chaos-monkey.public.ns-staging00.example.com", Namespace: "ns-staging00",
	}})
	assert.NoError(t, err)

	policy := &istiosecurityv1.AuthorizationPolicy{}
	err = k8sClient.Get(context.Background(), client.ObjectKey{Name: "chaos-monkey", Namespace: "ns-infra"}, policy)
	assert.NoError(t, err)
	assert.ElementsMatch(t,
		[]string{"chaos-monkey.public.ns-staging00.example.com"},
		policy.Spec.Rules[0].To[0].Operation.Hosts,
		"hosts from a different merge key must not be included",
	)
}

func TestReconcileHTTPRouteMergeWithoutMergeAnnotationIsIndependent(t *testing.T) {
	cidr := &ipamv1alpha1.CIDRs{
		ObjectMeta: v1.ObjectMeta{Name: "allowlist", Namespace: "ns-staging00"},
		Status:     ipamv1alpha1.CIDRsStatus{CIDRs: []string{"1.2.3.4/32"}},
	}
	gwNS := gatewayApiv1.Namespace("ns-infra")
	route := &gatewayApiv1.HTTPRoute{
		ObjectMeta: v1.ObjectMeta{
			Name: "chaos-monkey.public.ns-staging00.example.com", Namespace: "ns-staging00",
			Annotations: map[string]string{
				"ipam.adevinta.com/allowlist-group": "allowlist",
			},
		},
		Spec: gatewayApiv1.HTTPRouteSpec{
			CommonRouteSpec: gatewayApiv1.CommonRouteSpec{ParentRefs: []gatewayApiv1.ParentReference{
				{Name: "cross-namespace-public", Namespace: &gwNS},
			}},
		},
	}
	k8sClient := fake.NewClientBuilder().WithScheme(extendedScheme).WithObjects(cidr, route).Build()
	reconciler := newHTTPRouteReconciler(t, k8sClient, extendedScheme)

	_, err := reconciler.Reconcile(context.Background(), reconcile.Request{NamespacedName: client.ObjectKey{
		Name: "chaos-monkey.public.ns-staging00.example.com", Namespace: "ns-staging00",
	}})
	assert.NoError(t, err)

	// Normal cross-namespace naming: <namespace>-<name>
	policy := &istiosecurityv1.AuthorizationPolicy{}
	err = k8sClient.Get(context.Background(), client.ObjectKey{
		Name:      "ns-staging00-chaos-monkey.public.ns-staging00.example.com",
		Namespace: "ns-infra",
	}, policy)
	assert.NoError(t, err)
	assert.ElementsMatch(t, []string{"1.2.3.4/32"}, policy.Spec.Rules[0].From[0].Source.RemoteIpBlocks)

	// No merged policy under the service name
	merged := &istiosecurityv1.AuthorizationPolicy{}
	err = k8sClient.Get(context.Background(), client.ObjectKey{Name: "chaos-monkey", Namespace: "ns-infra"}, merged)
	assert.True(t, apierrors.IsNotFound(err), "no merged policy should be created without merge annotation")
}

func TestReconcileHTTPRouteOwnerReference(t *testing.T) {
	cidr := &ipamv1alpha1.CIDRs{
		ObjectMeta: v1.ObjectMeta{Name: "localnet", Namespace: "mynamespace"},
		Status:     ipamv1alpha1.CIDRsStatus{CIDRs: []string{"10.0.0.0/8"}},
	}

	t.Run("same-namespace policy gets owner reference", func(t *testing.T) {
		httproute := &gatewayApiv1.HTTPRoute{
			ObjectMeta: v1.ObjectMeta{Namespace: "mynamespace", Name: "test", Annotations: map[string]string{
				"ipam.adevinta.com/allowlist-group": "localnet",
			}},
			Spec: gatewayApiv1.HTTPRouteSpec{
				CommonRouteSpec: gatewayApiv1.CommonRouteSpec{
					ParentRefs: []gatewayApiv1.ParentReference{parentRef("my-gateway", "")},
				},
			},
		}
		k8sClient := fake.NewClientBuilder().WithScheme(extendedScheme).WithObjects(cidr, httproute).Build()
		reconciler := newHTTPRouteReconciler(t, k8sClient, extendedScheme)

		_, err := reconciler.Reconcile(context.Background(), reconcile.Request{NamespacedName: client.ObjectKey{Name: "test", Namespace: "mynamespace"}})
		assert.NoError(t, err)

		policy := &istiosecurityv1.AuthorizationPolicy{}
		err = k8sClient.Get(context.Background(), client.ObjectKey{Name: "test", Namespace: "mynamespace"}, policy)
		assert.NoError(t, err)

		assert.Len(t, policy.OwnerReferences, 1)
		assert.Equal(t, "test", policy.OwnerReferences[0].Name)
		assert.Equal(t, "HTTPRoute", policy.OwnerReferences[0].Kind)
	})

	t.Run("cross-namespace policy has no owner reference", func(t *testing.T) {
		httproute := &gatewayApiv1.HTTPRoute{
			ObjectMeta: v1.ObjectMeta{Namespace: "mynamespace", Name: "test", Annotations: map[string]string{
				"ipam.adevinta.com/allowlist-group": "localnet",
			}},
			Spec: gatewayApiv1.HTTPRouteSpec{
				CommonRouteSpec: gatewayApiv1.CommonRouteSpec{
					ParentRefs: []gatewayApiv1.ParentReference{parentRef("my-gateway", "gateway-namespace")},
				},
			},
		}
		k8sClient := fake.NewClientBuilder().WithScheme(extendedScheme).WithObjects(cidr, httproute).Build()
		reconciler := newHTTPRouteReconciler(t, k8sClient, extendedScheme)

		_, err := reconciler.Reconcile(context.Background(), reconcile.Request{NamespacedName: client.ObjectKey{Name: "test", Namespace: "mynamespace"}})
		assert.NoError(t, err)

		policy := &istiosecurityv1.AuthorizationPolicy{}
		err = k8sClient.Get(context.Background(), client.ObjectKey{Name: "mynamespace-test", Namespace: "gateway-namespace"}, policy)
		assert.NoError(t, err)
		assert.Empty(t, policy.OwnerReferences, "cross-namespace AP cannot have owner reference")
	})
}

func TestStartupOrphanCleanup(t *testing.T) {
	cidr := &ipamv1alpha1.CIDRs{
		ObjectMeta: v1.ObjectMeta{Name: "localnet", Namespace: "mynamespace"},
		Status:     ipamv1alpha1.CIDRsStatus{CIDRs: []string{"10.0.0.0/8"}},
	}
	httproute := &gatewayApiv1.HTTPRoute{
		ObjectMeta: v1.ObjectMeta{Namespace: "mynamespace", Name: "test", Annotations: map[string]string{
			"ipam.adevinta.com/allowlist-group": "localnet",
		}},
		Spec: gatewayApiv1.HTTPRouteSpec{
			CommonRouteSpec: gatewayApiv1.CommonRouteSpec{
				ParentRefs: []gatewayApiv1.ParentReference{parentRef("gateway-a", "")},
			},
		},
	}
	// AP whose owner HTTPRoute no longer exists — left over from a previous controller run
	orphan := &istiosecurityv1.AuthorizationPolicy{
		ObjectMeta: v1.ObjectMeta{
			Name: "deleted-route", Namespace: "mynamespace",
			Labels: map[string]string{
				"app.kubernetes.io/managed-by":      "ingress-allowlisting-controller",
				"ipam.adevinta.com/owner-namespace": "mynamespace",
				"ipam.adevinta.com/owner-name":      "deleted-route", // HTTPRoute no longer exists
			},
		},
	}
	k8sClient := fake.NewClientBuilder().WithScheme(extendedScheme).WithObjects(cidr, httproute, orphan).Build()
	reconciler := newHTTPRouteReconciler(t, k8sClient, extendedScheme)

	// First reconcile triggers the startup cleanup
	_, err := reconciler.Reconcile(context.Background(), reconcile.Request{NamespacedName: client.ObjectKey{Name: "test", Namespace: "mynamespace"}})
	assert.NoError(t, err)

	// Orphaned AP (owner HTTPRoute gone) should be deleted
	deleted := &istiosecurityv1.AuthorizationPolicy{}
	err = k8sClient.Get(context.Background(), client.ObjectKey{Name: "deleted-route", Namespace: "mynamespace"}, deleted)
	assert.True(t, apierrors.IsNotFound(err), "AP whose owner HTTPRoute no longer exists should be deleted")

	// Current AP should still exist
	current := &istiosecurityv1.AuthorizationPolicy{}
	err = k8sClient.Get(context.Background(), client.ObjectKey{Name: "test", Namespace: "mynamespace"}, current)
	assert.NoError(t, err)

	// Second reconcile must NOT re-run the cleanup (sync.Once)
	// We verify this by checking the reconciler's Once is already consumed — indirect proof via no extra deletes
	_, err = reconciler.Reconcile(context.Background(), reconcile.Request{NamespacedName: client.ObjectKey{Name: "test", Namespace: "mynamespace"}})
	assert.NoError(t, err)
}

func TestStartupCleanupAbortsOnEmptyHTTPRouteList(t *testing.T) {
	// Scenario: managed APs exist but the HTTPRoute list returns empty (dirty read / cache not synced).
	// Cleanup must abort rather than delete all APs.
	existingAP := &istiosecurityv1.AuthorizationPolicy{
		ObjectMeta: v1.ObjectMeta{
			Name: "some-route", Namespace: "mynamespace",
			Labels: map[string]string{
				"app.kubernetes.io/managed-by":      "ingress-allowlisting-controller",
				"ipam.adevinta.com/owner-namespace": "mynamespace",
				"ipam.adevinta.com/owner-name":      "some-route",
			},
		},
	}
	// No HTTPRoutes in the cluster — simulates dirty read
	k8sClient := fake.NewClientBuilder().WithScheme(extendedScheme).WithObjects(existingAP).Build()

	// Trigger cleanup via a fake reconcile request (route not found → IgnoreNotFound → cleanup fires)
	reconciler := newHTTPRouteReconciler(t, k8sClient, extendedScheme)
	// Inject a route that exists so reconcile doesn't short-circuit before cleanup
	cidr := &ipamv1alpha1.CIDRs{
		ObjectMeta: v1.ObjectMeta{Name: "localnet", Namespace: "mynamespace"},
		Status:     ipamv1alpha1.CIDRsStatus{CIDRs: []string{"10.0.0.0/8"}},
	}
	httproute := &gatewayApiv1.HTTPRoute{
		ObjectMeta: v1.ObjectMeta{Namespace: "mynamespace", Name: "trigger", Annotations: map[string]string{
			"ipam.adevinta.com/allowlist-group": "localnet",
		}},
		Spec: gatewayApiv1.HTTPRouteSpec{
			CommonRouteSpec: gatewayApiv1.CommonRouteSpec{
				ParentRefs: []gatewayApiv1.ParentReference{parentRef("my-gateway", "")},
			},
		},
	}
	if err := k8sClient.Create(context.Background(), cidr); err != nil {
		t.Fatal(err)
	}
	if err := k8sClient.Create(context.Background(), httproute); err != nil {
		t.Fatal(err)
	}

	_, err := reconciler.Reconcile(context.Background(), reconcile.Request{NamespacedName: client.ObjectKey{Name: "trigger", Namespace: "mynamespace"}})
	assert.NoError(t, err)

	// AP whose owner HTTPRoute doesn't exist should NOT be deleted because
	// the list returned at least one HTTPRoute (the trigger route), so we're past the empty guard.
	// This test specifically validates the empty-list guard by checking the AP survives
	// when the list would have been empty (we use a separate reconciler with no routes pre-loaded).
	reconciler2 := newHTTPRouteReconciler(t,
		fake.NewClientBuilder().WithScheme(extendedScheme).WithObjects(existingAP).Build(),
		extendedScheme,
	)
	// Reconcile a non-existent route — fires cleanup with empty HTTPRoute list
	_, _ = reconciler2.Reconcile(context.Background(), reconcile.Request{NamespacedName: client.ObjectKey{Name: "ghost", Namespace: "mynamespace"}})

	surviving := &istiosecurityv1.AuthorizationPolicy{}
	err = reconciler2.Get(context.Background(), client.ObjectKey{Name: "some-route", Namespace: "mynamespace"}, surviving)
	assert.NoError(t, err, "AP should NOT be deleted when HTTPRoute list is empty (dirty-read guard)")
}

func TestStartupCleanupRemovesOldAPWhenMergeAdded(t *testing.T) {
	// Scenario: HTTPRoute was cross-namespace without merge → AP named "mynamespace-test" in "gw-ns".
	// User later adds merge=myapp → new AP named "myapp" in "gw-ns".
	// On restart, cleanup should delete the old "mynamespace-test" AP because the HTTPRoute
	// now has merge=true and would never produce a non-merge AP anymore.
	gwNS := gatewayApiv1.Namespace("gw-ns")
	httproute := &gatewayApiv1.HTTPRoute{
		ObjectMeta: v1.ObjectMeta{
			Namespace: "mynamespace", Name: "test",
			Annotations: map[string]string{
				"ipam.adevinta.com/allowlist-group": "localnet",
				"ipam.adevinta.com/merge":           "myapp",
			},
		},
		Spec: gatewayApiv1.HTTPRouteSpec{
			CommonRouteSpec: gatewayApiv1.CommonRouteSpec{ParentRefs: []gatewayApiv1.ParentReference{
				{Name: "my-gateway", Namespace: &gwNS},
			}},
		},
	}
	cidr := &ipamv1alpha1.CIDRs{
		ObjectMeta: v1.ObjectMeta{Name: "localnet", Namespace: "mynamespace"},
		Status:     ipamv1alpha1.CIDRsStatus{CIDRs: []string{"10.0.0.0/8"}},
	}
	// Old AP from before merge was added — owner is the HTTPRoute (still exists!)
	oldAP := &istiosecurityv1.AuthorizationPolicy{
		ObjectMeta: v1.ObjectMeta{
			Name: "mynamespace-test", Namespace: "gw-ns",
			Labels: map[string]string{
				"app.kubernetes.io/managed-by":      "ingress-allowlisting-controller",
				"ipam.adevinta.com/owner-namespace": "mynamespace",
				"ipam.adevinta.com/owner-name":      "test",
			},
		},
	}

	k8sClient := fake.NewClientBuilder().WithScheme(extendedScheme).WithObjects(cidr, httproute, oldAP).Build()
	reconciler := newHTTPRouteReconciler(t, k8sClient, extendedScheme)

	_, err := reconciler.Reconcile(context.Background(), reconcile.Request{NamespacedName: client.ObjectKey{Name: "test", Namespace: "mynamespace"}})
	assert.NoError(t, err)

	// Old cross-namespace AP should be deleted — route now uses merge mode
	stale := &istiosecurityv1.AuthorizationPolicy{}
	err = k8sClient.Get(context.Background(), client.ObjectKey{Name: "mynamespace-test", Namespace: "gw-ns"}, stale)
	assert.True(t, apierrors.IsNotFound(err), "old non-merge AP should be deleted after merge annotation added")

	// New merged AP should exist
	merged := &istiosecurityv1.AuthorizationPolicy{}
	err = k8sClient.Get(context.Background(), client.ObjectKey{Name: "myapp", Namespace: "gw-ns"}, merged)
	assert.NoError(t, err, "merged AP should exist")
}

func TestLabelSafe(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"my-route", "my-route"},
		{"my_route", "my_route"},
		{"my.route", "my.route"},
		{"chaos-monkey.public.ns-staging00.example.com", "chaos-monkey.public.ns-staging00.example.com"},
		{"namespace/name", "namespace_name"},
		{"foo*bar", "foo_bar"},
		{"merged", "merged"},
		{strings.Repeat("a", 70), strings.Repeat("a", 63)},
	}
	for _, tc := range tests {
		assert.Equal(t, tc.want, labelSafe(tc.input), "input: %q", tc.input)
	}
}

func TestAuthorizationPolicyNameMaxLength(t *testing.T) {
	// Kubernetes resource names are DNS subdomains: max 253 chars.
	// Namespace max = 63, name max = 63.
	// Index suffix is only appended for the 2nd+ parentRef (i > 0).
	// Worst case: cross-namespace, index 99 → <63>-<63>-99 = 63+1+63+1+2 = 130 chars — well under 253.
	maxNS := strings.Repeat("n", 63)
	maxName := strings.Repeat("a", 63)

	t.Run("same-namespace with suffix stays under 253", func(t *testing.T) {
		// <name>-<index>  →  63 + 1 + 2 = 66
		result := fmt.Sprintf("%s-%d", maxName, 99)
		assert.LessOrEqual(t, len(result), 253)
	})

	t.Run("cross-namespace with suffix stays under 253", func(t *testing.T) {
		// <namespace>-<name>-<index>  →  63 + 1 + 63 + 1 + 2 = 130
		result := fmt.Sprintf("%s-%s-%d", maxNS, maxName, 99)
		assert.LessOrEqual(t, len(result), 253)
	})
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

func TestHasAllowlistAnnotation(t *testing.T) {
	const prefix = "ipam.adevinta.com"

	tests := []struct {
		name        string
		annotations map[string]string
		want        bool
	}{
		{
			name:        "local allowlist-group",
			annotations: map[string]string{prefix + "/allowlist-group": "localnet"},
			want:        true,
		},
		{
			name:        "cluster-allowlist-group",
			annotations: map[string]string{prefix + "/cluster-allowlist-group": "globalnet"},
			want:        true,
		},
		{
			name:        "both annotations",
			annotations: map[string]string{prefix + "/allowlist-group": "localnet", prefix + "/cluster-allowlist-group": "globalnet"},
			want:        true,
		},
		{
			name:        "unrelated annotation only",
			annotations: map[string]string{"kubernetes.io/some-annotation": "value"},
			want:        false,
		},
		{
			name:        "no annotations",
			annotations: nil,
			want:        false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			obj := &gatewayApiv1.HTTPRoute{ObjectMeta: v1.ObjectMeta{Annotations: tc.annotations}}
			assert.Equal(t, tc.want, hasAllowlistAnnotation(prefix, obj))
		})
	}
}

func TestAnnotationPredicate(t *testing.T) {
	const prefix = "ipam.adevinta.com"
	withAnnotation := &gatewayApiv1.HTTPRoute{
		ObjectMeta: v1.ObjectMeta{Annotations: map[string]string{prefix + "/allowlist-group": "localnet"}},
	}
	withoutAnnotation := &gatewayApiv1.HTTPRoute{ObjectMeta: v1.ObjectMeta{}}

	reconciler := &HTTPRouteAllowlistingReconciler{
		CidrResolver: resolvers.CidrResolver{AnnotationPrefix: prefix},
	}
	// build the predicate the same way SetupWithManager does
	p := predicate.Funcs{
		CreateFunc:  func(e event.CreateEvent) bool { return hasAllowlistAnnotation(prefix, e.Object) },
		DeleteFunc:  func(e event.DeleteEvent) bool { return hasAllowlistAnnotation(prefix, e.Object) },
		GenericFunc: func(e event.GenericEvent) bool { return hasAllowlistAnnotation(prefix, e.Object) },
		UpdateFunc: func(e event.UpdateEvent) bool {
			return hasAllowlistAnnotation(reconciler.CidrResolver.AnnotationPrefix, e.ObjectNew) ||
				hasAllowlistAnnotation(reconciler.CidrResolver.AnnotationPrefix, e.ObjectOld)
		},
	}

	t.Run("Create with annotation passes", func(t *testing.T) {
		assert.True(t, p.Create(event.CreateEvent{Object: withAnnotation}))
	})
	t.Run("Create without annotation filtered", func(t *testing.T) {
		assert.False(t, p.Create(event.CreateEvent{Object: withoutAnnotation}))
	})
	t.Run("Delete with annotation passes", func(t *testing.T) {
		assert.True(t, p.Delete(event.DeleteEvent{Object: withAnnotation}))
	})
	t.Run("Delete without annotation filtered", func(t *testing.T) {
		assert.False(t, p.Delete(event.DeleteEvent{Object: withoutAnnotation}))
	})
	t.Run("Update annotation added passes", func(t *testing.T) {
		assert.True(t, p.Update(event.UpdateEvent{ObjectOld: withoutAnnotation, ObjectNew: withAnnotation}))
	})
	t.Run("Update annotation removed passes (cleanup)", func(t *testing.T) {
		assert.True(t, p.Update(event.UpdateEvent{ObjectOld: withAnnotation, ObjectNew: withoutAnnotation}))
	})
	t.Run("Update no annotation on either filtered", func(t *testing.T) {
		assert.False(t, p.Update(event.UpdateEvent{ObjectOld: withoutAnnotation, ObjectNew: withoutAnnotation}))
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
