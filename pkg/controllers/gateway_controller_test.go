package controllers

import (
	"context"
	"errors"
	"testing"

	istioApiSecurityV1 "istio.io/api/security/v1"
	istioApiTypeV1beta1 "istio.io/api/type/v1beta1"
	istiosecurityv1 "istio.io/client-go/pkg/apis/security/v1"

	ipamv1alpha1 "github.com/adevinta/ingress-allowlisting-controller/pkg/apis/ipam.adevinta.com/v1alpha1"
	"github.com/adevinta/ingress-allowlisting-controller/pkg/controllers/writers"
	"github.com/adevinta/ingress-allowlisting-controller/pkg/resolvers"
	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	gatewayApiv1 "sigs.k8s.io/gateway-api/apis/v1"
)

func init() {
	var err error
	extendedScheme, err = Scheme("legacy.ipam.com/v1alpha1")
	if err != nil {
		panic(err)
	}
}

// newGatewayClass creates an Istio GatewayClass with the given name.
func newGatewayClass(name string) *gatewayApiv1.GatewayClass {
	return &gatewayApiv1.GatewayClass{
		ObjectMeta: v1.ObjectMeta{Name: name},
		Spec: gatewayApiv1.GatewayClassSpec{
			ControllerName: gatewayApiv1.GatewayController(writers.IstioControllerName),
		},
	}
}

func newGatewayReconciler(t *testing.T, k8sClient client.Client, scheme *runtime.Scheme) *GatewayAllowlistingReconciler {
	t.Helper()
	resolver := resolvers.CidrResolver{Client: k8sClient, AnnotationPrefix: resolvers.DefaultPrefix}
	l4Writers := writers.L4WriterRegistry{
		writers.IstioControllerName: writers.NewIstioL4Writer(k8sClient),
	}
	return &GatewayAllowlistingReconciler{Client: k8sClient, CidrResolver: resolver, Scheme: scheme, L4Writers: l4Writers}
}

// cases:
// v - Gateway has annotations and ipamv1alpha1.CIDRs exists and has a valid format.
// v - Gateway has no annotation
// v - Gateway has annotations and some ipamv1alpha1.CIDRs doesn't exist.
// v - ResolveCidrs returns an unexpected error
// v - Gateway has annotations and ALL ipamv1alpha1.CIDRS don't exist (ensure ingress reject all traffic) empty allowlist is rejected, so using 127.0.0.2/32
// - Error case: annotation has invalid format (i.e: is not comma-separated string)
//   - annotation = ",,"
//   - annotation = ""
//   - annotation = " "
//   - annotation = ",something"
//
// v    - annotation = "something1 , something2" // use: strings.TrimSpace
// v - ingress has already an allowed list it is overwritten
func TestReconcileGateway(t *testing.T) {
	localnetCidrs := &ipamv1alpha1.CIDRs{
		ObjectMeta: v1.ObjectMeta{Name: "localnet", Namespace: "mynamespace"},
		Status:     ipamv1alpha1.CIDRsStatus{CIDRs: []string{"192.168.0.0/16", "172.16.0.0/12", "10.0.0.0/8"}},
	}
	globalCidrs := &ipamv1alpha1.ClusterCIDRs{
		ObjectMeta: v1.ObjectMeta{Name: "globalnet"},
		Status:     ipamv1alpha1.CIDRsStatus{CIDRs: []string{"15.13.12.0/24"}},
	}
	dnssourceCidrs := &ipamv1alpha1.CIDRs{
		ObjectMeta: v1.ObjectMeta{Name: "dnssource", Namespace: "mynamespace"},
		Status:     ipamv1alpha1.CIDRsStatus{CIDRs: []string{"1.1.1.1/32", "8.8.8.8/32"}},
	}
	gwClass := newGatewayClass("istio")
	gateway := &gatewayApiv1.Gateway{
		ObjectMeta: v1.ObjectMeta{Namespace: "mynamespace", Name: "test", Annotations: map[string]string{
			"ipam.adevinta.com/cluster-allowlist-group": "globalnet",
			"ipam.adevinta.com/allowlist-group":         "localnet,dnssource",
		}},
		Spec: gatewayApiv1.GatewaySpec{GatewayClassName: "istio"},
	}
	k8sClient := fake.NewClientBuilder().WithScheme(extendedScheme).WithObjects(localnetCidrs, dnssourceCidrs, gateway, globalCidrs, gwClass).Build()
	reconciler := newGatewayReconciler(t, k8sClient, extendedScheme)

	expectedPolicy := istiosecurityv1.AuthorizationPolicy{
		ObjectMeta: v1.ObjectMeta{
			Namespace: "mynamespace",
			// https://github.com/kubernetes-sigs/controller-runtime/blob/master/pkg/client/fake/client.go#L196
			ResourceVersion: "999",
			Name:            "test",
		},
		Spec: istioApiSecurityV1.AuthorizationPolicy{
			Action: istioApiSecurityV1.AuthorizationPolicy_ALLOW, // ALLOW is the default action; somehow, the action field is empty when examining the resource after creation
			Rules: []*istioApiSecurityV1.Rule{
				{
					From: []*istioApiSecurityV1.Rule_From{
						{
							Source: &istioApiSecurityV1.Source{
								RemoteIpBlocks: []string{"1.1.1.1/32", "8.8.8.8/32", "192.168.0.0/16", "172.16.0.0/12", "10.0.0.0/8", "15.13.12.0/24"},
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
		},
	}
	_, err := reconciler.Reconcile(context.Background(), reconcile.Request{NamespacedName: client.ObjectKey{Name: "test", Namespace: "mynamespace"}})
	assert.NoError(t, err)
	generatedAuthorizationPolicy := &istiosecurityv1.AuthorizationPolicy{}
	err = k8sClient.Get(context.Background(), client.ObjectKey{Name: "test", Namespace: "mynamespace"}, generatedAuthorizationPolicy)
	assert.NoError(t, err)
	assert.ElementsMatch(t, expectedPolicy.Spec.Rules[0].From[0].Source.RemoteIpBlocks, generatedAuthorizationPolicy.Spec.Rules[0].From[0].Source.RemoteIpBlocks)
	assert.Equal(t, expectedPolicy.Spec.Action, generatedAuthorizationPolicy.Spec.Action)

	events := &corev1.EventList{}
	assert.NoError(t, k8sClient.List(context.Background(), events, &client.ListOptions{Namespace: "mynamespace"}))
	assert.Empty(t, events.Items)
}

func TestReconcileGatewayWithClusterCIDR(t *testing.T) {
	globalNet := &ipamv1alpha1.ClusterCIDRs{
		ObjectMeta: v1.ObjectMeta{Name: "globalnet"},
		Status:     ipamv1alpha1.CIDRsStatus{CIDRs: []string{"192.168.0.0/16", "172.16.0.0/12", "10.0.0.0/8"}},
	}
	anotherGlobalNet := &ipamv1alpha1.ClusterCIDRs{
		ObjectMeta: v1.ObjectMeta{Name: "anotherglobalnet"},
		Status:     ipamv1alpha1.CIDRsStatus{CIDRs: []string{"15.13.12.0/24"}},
	}
	gwClass := newGatewayClass("istio")
	gateway := &gatewayApiv1.Gateway{
		ObjectMeta: v1.ObjectMeta{Namespace: "mynamespace", Name: "test", Annotations: map[string]string{
			"ipam.adevinta.com/cluster-allowlist-group": "globalnet,anotherglobalnet",
		}},
		Spec: gatewayApiv1.GatewaySpec{GatewayClassName: "istio"},
	}
	k8sClient := fake.NewClientBuilder().WithScheme(extendedScheme).WithObjects(gateway, globalNet, anotherGlobalNet, gwClass).Build()
	reconciler := newGatewayReconciler(t, k8sClient, extendedScheme)
	expectedPolicy := istiosecurityv1.AuthorizationPolicy{
		ObjectMeta: v1.ObjectMeta{
			Namespace: "mynamespace",
			// https://github.com/kubernetes-sigs/controller-runtime/blob/master/pkg/client/fake/client.go#L196
			ResourceVersion: "999",
			Name:            "test",
		},
		Spec: istioApiSecurityV1.AuthorizationPolicy{
			Action: istioApiSecurityV1.AuthorizationPolicy_ALLOW, // ALLOW is the default action; somehow, the action field is empty when examining the resource after creation
			Rules: []*istioApiSecurityV1.Rule{
				{
					From: []*istioApiSecurityV1.Rule_From{
						{
							Source: &istioApiSecurityV1.Source{
								RemoteIpBlocks: []string{"192.168.0.0/16", "172.16.0.0/12", "10.0.0.0/8", "15.13.12.0/24"},
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
		},
	}

	_, err := reconciler.Reconcile(context.Background(), reconcile.Request{NamespacedName: client.ObjectKey{Name: "test", Namespace: "mynamespace"}})
	assert.NoError(t, err)
	generatedAuthorizationPolicy := &istiosecurityv1.AuthorizationPolicy{}
	err = k8sClient.Get(context.Background(), client.ObjectKey{Name: "test", Namespace: "mynamespace"}, generatedAuthorizationPolicy)
	assert.NoError(t, err)
	assert.ElementsMatch(t, expectedPolicy.Spec.Rules[0].From[0].Source.RemoteIpBlocks, generatedAuthorizationPolicy.Spec.Rules[0].From[0].Source.RemoteIpBlocks)
	assert.Equal(t, expectedPolicy.Spec.Action, generatedAuthorizationPolicy.Spec.Action)

	events := &corev1.EventList{}
	assert.NoError(t, k8sClient.List(context.Background(), events, &client.ListOptions{Namespace: "mynamespace"}))
	assert.Empty(t, events.Items)
}

func TestReconcileGatewayNoAnnotations(t *testing.T) {
	gateway := &gatewayApiv1.Gateway{
		ObjectMeta: v1.ObjectMeta{Namespace: "mynamespace", Name: "test"},
	}

	k8sClient := fake.NewClientBuilder().WithScheme(extendedScheme).WithObjects(gateway).Build()

	reconciler := newGatewayReconciler(t, k8sClient, extendedScheme)
	// Note: no GatewayClass needed here because the reconciler returns early on AnnotationNotFoundError

	_, err := reconciler.Reconcile(context.Background(), reconcile.Request{NamespacedName: client.ObjectKey{Name: "test", Namespace: "mynamespace"}})
	assert.NoError(t, err)
	generatedAuthorizationPolicy := &istiosecurityv1.AuthorizationPolicy{}
	err = k8sClient.Get(context.Background(), client.ObjectKey{Name: "test", Namespace: "mynamespace"}, generatedAuthorizationPolicy)
	assert.True(t, apierrors.IsNotFound(err))

	events := &corev1.EventList{}
	assert.NoError(t, k8sClient.List(context.Background(), events, &client.ListOptions{Namespace: "mynamespace"}))
	assert.Empty(t, events.Items)
}

func TestReconcileGatewayPartialNotFound(t *testing.T) {
	localnetCidrs := &ipamv1alpha1.CIDRs{
		ObjectMeta: v1.ObjectMeta{Name: "localnet", Namespace: "mynamespace"},
		Status:     ipamv1alpha1.CIDRsStatus{CIDRs: []string{"192.168.0.0/16", "172.16.0.0/12", "10.0.0.0/8"}},
	}

	gwClass := newGatewayClass("istio")
	gateway := &gatewayApiv1.Gateway{
		ObjectMeta: v1.ObjectMeta{Namespace: "mynamespace", Name: "test", Annotations: map[string]string{"ipam.adevinta.com/allowlist-group": "localnet,notexisting"}},
		Spec:       gatewayApiv1.GatewaySpec{GatewayClassName: "istio"},
	}
	k8sClient := fake.NewClientBuilder().WithScheme(extendedScheme).WithObjects(localnetCidrs, gateway, gwClass).Build()

	reconciler := newGatewayReconciler(t, k8sClient, extendedScheme)
	expectedPolicy := istiosecurityv1.AuthorizationPolicy{
		ObjectMeta: v1.ObjectMeta{
			Namespace: "mynamespace",
			// https://github.com/kubernetes-sigs/controller-runtime/blob/master/pkg/client/fake/client.go#L196
			ResourceVersion: "999",
			Name:            "test",
		},
		Spec: istioApiSecurityV1.AuthorizationPolicy{
			Action: istioApiSecurityV1.AuthorizationPolicy_ALLOW, // ALLOW is the default action; somehow, the action field is empty when examining the resource after creation
			Rules: []*istioApiSecurityV1.Rule{
				{
					From: []*istioApiSecurityV1.Rule_From{
						{
							Source: &istioApiSecurityV1.Source{
								RemoteIpBlocks: []string{"192.168.0.0/16", "172.16.0.0/12", "10.0.0.0/8"},
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
		},
	}

	_, err := reconciler.Reconcile(context.Background(), reconcile.Request{NamespacedName: client.ObjectKey{Name: "test", Namespace: "mynamespace"}})

	assert.NoError(t, err)
	generatedAuthorizationPolicy := &istiosecurityv1.AuthorizationPolicy{}
	err = k8sClient.Get(context.Background(), client.ObjectKey{Name: "test", Namespace: "mynamespace"}, generatedAuthorizationPolicy)
	assert.NoError(t, err)
	assert.ElementsMatch(t, expectedPolicy.Spec.Rules[0].From[0].Source.RemoteIpBlocks, generatedAuthorizationPolicy.Spec.Rules[0].From[0].Source.RemoteIpBlocks)
	assert.Equal(t, expectedPolicy.Spec.Action, generatedAuthorizationPolicy.Spec.Action)
}

func TestReconcileGatewayWithInvalidCIDRIpsNoError(t *testing.T) {
	localnetCidrs := &ipamv1alpha1.CIDRs{
		ObjectMeta: v1.ObjectMeta{Name: "localnet", Namespace: "mynamespace"},
		Status:     ipamv1alpha1.CIDRsStatus{CIDRs: []string{"192.168.0/16", "172.16.0.0/12", "10.0.0.0/8", "10.0.0.0"}},
	}
	dnssourceCidrs := &ipamv1alpha1.CIDRs{
		ObjectMeta: v1.ObjectMeta{Name: "dnssource", Namespace: "mynamespace"},
		Status:     ipamv1alpha1.CIDRsStatus{CIDRs: []string{"1.1.1.1/32", "8.8.8.8/32"}},
	}
	gwClass := newGatewayClass("istio")
	gateway := &gatewayApiv1.Gateway{
		ObjectMeta: v1.ObjectMeta{Namespace: "mynamespace", Name: "test", Annotations: map[string]string{"ipam.adevinta.com/allowlist-group": "localnet,dnssource"}},
		Spec:       gatewayApiv1.GatewaySpec{GatewayClassName: "istio"},
	}
	k8sClient := fake.NewClientBuilder().WithScheme(extendedScheme).WithObjects(localnetCidrs, dnssourceCidrs, gateway, gwClass).Build()

	reconciler := newGatewayReconciler(t, k8sClient, extendedScheme)
	expectedPolicy := istiosecurityv1.AuthorizationPolicy{
		ObjectMeta: v1.ObjectMeta{
			Namespace: "mynamespace",
			// https://github.com/kubernetes-sigs/controller-runtime/blob/master/pkg/client/fake/client.go#L196
			ResourceVersion: "999",
			Name:            "test",
		},
		Spec: istioApiSecurityV1.AuthorizationPolicy{
			Action: istioApiSecurityV1.AuthorizationPolicy_ALLOW, // ALLOW is the default action; somehow, the action field is empty when examining the resource after creation
			Rules: []*istioApiSecurityV1.Rule{
				{
					From: []*istioApiSecurityV1.Rule_From{
						{
							Source: &istioApiSecurityV1.Source{
								RemoteIpBlocks: []string{"1.1.1.1/32", "172.16.0.0/12", "10.0.0.0/8", "8.8.8.8/32"},
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
		},
	}

	_, err := reconciler.Reconcile(context.Background(), reconcile.Request{NamespacedName: client.ObjectKey{Name: "test", Namespace: "mynamespace"}})

	assert.NoError(t, err)

	generatedAuthorizationPolicy := &istiosecurityv1.AuthorizationPolicy{}
	err = k8sClient.Get(context.Background(), client.ObjectKey{Name: "test", Namespace: "mynamespace"}, generatedAuthorizationPolicy)
	assert.NoError(t, err)
	assert.ElementsMatch(t, expectedPolicy.Spec.Rules[0].From[0].Source.RemoteIpBlocks, generatedAuthorizationPolicy.Spec.Rules[0].From[0].Source.RemoteIpBlocks)
	assert.Equal(t, expectedPolicy.Spec.Action, generatedAuthorizationPolicy.Spec.Action)
	events := &corev1.EventList{}
	assert.NoError(t, k8sClient.List(context.Background(), events, &client.ListOptions{Namespace: "mynamespace"}))
	assert.Empty(t, events.Items)
}

func TestReconcileGatewayCIDRsNotFound(t *testing.T) {
	t.Run("Namespace CIDR not found", func(t *testing.T) {
		gwClass := newGatewayClass("istio")
		gateway := &gatewayApiv1.Gateway{
			ObjectMeta: v1.ObjectMeta{Name: "test", Namespace: "mynamespace", Annotations: map[string]string{"ipam.adevinta.com/allowlist-group": "notexisting,alsonotexisting"}},
			Spec:       gatewayApiv1.GatewaySpec{GatewayClassName: "istio"},
		}
		k8sClient := fake.NewClientBuilder().WithScheme(extendedScheme).WithObjects(gateway, gwClass).Build()
		reconciler := newGatewayReconciler(t, k8sClient, extendedScheme)
		expectedPolicy := istiosecurityv1.AuthorizationPolicy{
			ObjectMeta: v1.ObjectMeta{
				Namespace: "mynamespace",
				// https://github.com/kubernetes-sigs/controller-runtime/blob/master/pkg/client/fake/client.go#L196
				ResourceVersion: "999",
				Name:            "test",
			},
			Spec: istioApiSecurityV1.AuthorizationPolicy{
				Action: istioApiSecurityV1.AuthorizationPolicy_ALLOW, // ALLOW is the default action; somehow, the action field is empty when examining the resource after creation
				Rules: []*istioApiSecurityV1.Rule{
					{
						From: []*istioApiSecurityV1.Rule_From{
							{
								Source: &istioApiSecurityV1.Source{
									RemoteIpBlocks: []string{"127.0.0.2/32"},
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
			},
		}

		_, err := reconciler.Reconcile(context.Background(), reconcile.Request{NamespacedName: client.ObjectKey{Name: "test", Namespace: "mynamespace"}})

		assert.NoError(t, err)
		generatedAuthorizationPolicy := &istiosecurityv1.AuthorizationPolicy{}
		err = k8sClient.Get(context.Background(), client.ObjectKey{Name: "test", Namespace: "mynamespace"}, generatedAuthorizationPolicy)
		assert.NoError(t, err)
		assert.ElementsMatch(t, expectedPolicy.Spec.Rules[0].From[0].Source.RemoteIpBlocks, generatedAuthorizationPolicy.Spec.Rules[0].From[0].Source.RemoteIpBlocks)
		assert.Equal(t, expectedPolicy.Spec.Action, generatedAuthorizationPolicy.Spec.Action)

		events := &corev1.EventList{}
		k8sClient.List(context.Background(), events, &client.ListOptions{Namespace: "mynamespace"})

		expectedEvents := &corev1.EventList{
			Items: []corev1.Event{
				{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "mynamespace",
						Name:      "test-allowlist-cidrs-not-found",
					},
					Action: "LookupAllowListingGroup",
				},
			},
		}

		assert.NotEmpty(t, events.Items)
		assert.Equal(t, events.Items[0].Action, expectedEvents.Items[0].Action)
	})

	t.Run("Cluster CIDR not found", func(t *testing.T) {
		gwClass := newGatewayClass("istio")
		gateway := &gatewayApiv1.Gateway{
			ObjectMeta: v1.ObjectMeta{Name: "test", Namespace: "mynamespace", Annotations: map[string]string{"ipam.adevinta.com/cluster-allowlist-group": "notexisting,alsonotexisting"}},
			Spec:       gatewayApiv1.GatewaySpec{GatewayClassName: "istio"},
		}
		k8sClient := fake.NewClientBuilder().WithScheme(extendedScheme).WithObjects(gateway, gwClass).Build()
		reconciler := newGatewayReconciler(t, k8sClient, extendedScheme)
		expectedPolicy := istiosecurityv1.AuthorizationPolicy{
			ObjectMeta: v1.ObjectMeta{
				Namespace: "mynamespace",
				// https://github.com/kubernetes-sigs/controller-runtime/blob/master/pkg/client/fake/client.go#L196
				ResourceVersion: "999",
				Name:            "test",
			},
			Spec: istioApiSecurityV1.AuthorizationPolicy{
				Action: istioApiSecurityV1.AuthorizationPolicy_ALLOW, // ALLOW is the default action; somehow, the action field is empty when examining the resource after creation
				Rules: []*istioApiSecurityV1.Rule{
					{
						From: []*istioApiSecurityV1.Rule_From{
							{
								Source: &istioApiSecurityV1.Source{
									RemoteIpBlocks: []string{"127.0.0.2/32"},
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
			},
		}

		_, err := reconciler.Reconcile(context.Background(), reconcile.Request{NamespacedName: client.ObjectKey{Name: "test", Namespace: "mynamespace"}})

		assert.NoError(t, err)
		generatedAuthorizationPolicy := &istiosecurityv1.AuthorizationPolicy{}
		err = k8sClient.Get(context.Background(), client.ObjectKey{Name: "test", Namespace: "mynamespace"}, generatedAuthorizationPolicy)
		assert.NoError(t, err)
		assert.ElementsMatch(t, expectedPolicy.Spec.Rules[0].From[0].Source.RemoteIpBlocks, generatedAuthorizationPolicy.Spec.Rules[0].From[0].Source.RemoteIpBlocks)
		assert.Equal(t, expectedPolicy.Spec.Action, generatedAuthorizationPolicy.Spec.Action)

		events := &corev1.EventList{}
		k8sClient.List(context.Background(), events, &client.ListOptions{Namespace: "mynamespace"})

		expectedEvents := &corev1.EventList{
			Items: []corev1.Event{
				{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "mynamespace",
						Name:      "ingresstest-allowlist-cidrs-not-found",
					},
					Action: "LookupAllowListingGroup",
				},
			},
		}
		assert.Len(t, events.Items, 2)
		assert.Equal(t, events.Items[0].Action, expectedEvents.Items[0].Action)
	})
}

func TestReconcileGatewayError(t *testing.T) {
	k8sClient := &testfunc{WithWatch: fake.NewClientBuilder().WithScheme(extendedScheme).Build()}
	k8sClient.getfunc = func(ctx context.Context, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
		return errors.New("error that is not a NOTFOUND")
	}

	reconciler := newGatewayReconciler(t, k8sClient, extendedScheme)

	_, err := reconciler.Reconcile(context.Background(), reconcile.Request{NamespacedName: client.ObjectKey{Name: "test", Namespace: "mynamespace"}})
	assert.Error(t, err)
}

func TestReconcileGatewayInvalidAnnotationFormat(t *testing.T) {
	localnetCidrs := &ipamv1alpha1.CIDRs{
		ObjectMeta: v1.ObjectMeta{Name: "localnet", Namespace: "mynamespace"},
		Status:     ipamv1alpha1.CIDRsStatus{CIDRs: []string{"192.168.0.0/16", "172.16.0.0/12", "10.0.0.0/8"}},
	}
	dnssourceCidrs := &ipamv1alpha1.CIDRs{
		ObjectMeta: v1.ObjectMeta{Name: "dnssource", Namespace: "mynamespace"},
		Status:     ipamv1alpha1.CIDRsStatus{CIDRs: []string{"1.1.1.1/32", "8.8.8.8/32"}},
	}
	gwClass := newGatewayClass("istio")
	gateway := &gatewayApiv1.Gateway{
		ObjectMeta: v1.ObjectMeta{Namespace: "mynamespace", Name: "test", Annotations: map[string]string{"ipam.adevinta.com/allowlist-group": "localnet, dnssource"}},
		Spec:       gatewayApiv1.GatewaySpec{GatewayClassName: "istio"},
	}
	k8sClient := fake.NewClientBuilder().WithScheme(extendedScheme).WithObjects(localnetCidrs, dnssourceCidrs, gateway, gwClass).Build()

	reconciler := newGatewayReconciler(t, k8sClient, extendedScheme)
	expectedPolicy := istiosecurityv1.AuthorizationPolicy{
		ObjectMeta: v1.ObjectMeta{
			Namespace: "mynamespace",
			// https://github.com/kubernetes-sigs/controller-runtime/blob/master/pkg/client/fake/client.go#L196
			ResourceVersion: "999",
			Name:            "test",
		},
		Spec: istioApiSecurityV1.AuthorizationPolicy{
			Action: istioApiSecurityV1.AuthorizationPolicy_ALLOW, // ALLOW is the default action; somehow, the action field is empty when examining the resource after creation
			Rules: []*istioApiSecurityV1.Rule{
				{
					From: []*istioApiSecurityV1.Rule_From{
						{
							Source: &istioApiSecurityV1.Source{
								RemoteIpBlocks: []string{"192.168.0.0/16", "172.16.0.0/12", "10.0.0.0/8", "1.1.1.1/32", "8.8.8.8/32"},
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
		},
	}

	_, err := reconciler.Reconcile(context.Background(), reconcile.Request{NamespacedName: client.ObjectKey{Name: "test", Namespace: "mynamespace"}})
	assert.NoError(t, err)
	generatedAuthorizationPolicy := &istiosecurityv1.AuthorizationPolicy{}
	err = k8sClient.Get(context.Background(), client.ObjectKey{Name: "test", Namespace: "mynamespace"}, generatedAuthorizationPolicy)
	assert.NoError(t, err)
	assert.ElementsMatch(t, expectedPolicy.Spec.Rules[0].From[0].Source.RemoteIpBlocks, generatedAuthorizationPolicy.Spec.Rules[0].From[0].Source.RemoteIpBlocks)
	assert.Equal(t, expectedPolicy.Spec.Action, generatedAuthorizationPolicy.Spec.Action)
	assert.NoError(t, err)
}

func TestCidrToGatewayMapper(t *testing.T) {
	t.Run("CIDR is being used in the ingress, should return the ingress", func(t *testing.T) {
		gateway := &gatewayApiv1.Gateway{
			ObjectMeta: v1.ObjectMeta{Name: "test", Namespace: "mynamespace", Annotations: map[string]string{"ipam.adevinta.com/allowlist-group": "localnet,dnssource"}},
		}
		k8sClient := fake.NewClientBuilder().WithScheme(extendedScheme).WithObjects(gateway).Build()
		cidr := ipamv1alpha1.CIDRs{
			ObjectMeta: v1.ObjectMeta{Name: "localnet", Namespace: "mynamespace"},
		}
		requests := newGatewaysFromCIDRFuncMap(k8sClient, "ipam.adevinta.com/allowlist-group")(context.Background(), &cidr)
		assert.Len(t, requests, 1)
		assert.Equal(t, requests[0].Name, "test")
	})

	t.Run("CIDR is not being used in the ingress, should return an empty list", func(t *testing.T) {
		gateway := &gatewayApiv1.Gateway{
			ObjectMeta: v1.ObjectMeta{Name: "test", Namespace: "mynamespace", Annotations: map[string]string{"ipam.adevinta.com/allowlist-group": "dnssource"}},
		}
		k8sClient := fake.NewClientBuilder().WithScheme(extendedScheme).WithObjects(gateway).Build()
		cidr := ipamv1alpha1.CIDRs{
			ObjectMeta: v1.ObjectMeta{Name: "localnet", Namespace: "mynamespace"},
		}
		cidrResolver := resolvers.CidrResolver{Client: k8sClient, AnnotationPrefix: resolvers.DefaultPrefix}
		requests := newGatewaysFromCIDRFuncMap(k8sClient, cidrResolver.Annotation())(context.Background(), &cidr)
		assert.Len(t, requests, 0)
	})
	t.Run("One CIDR is being used in the ingress, should return just that one", func(t *testing.T) {
		gateway1 := &gatewayApiv1.Gateway{
			ObjectMeta: v1.ObjectMeta{Name: "test", Namespace: "mynamespace"},
		}
		gateway2 := &gatewayApiv1.Gateway{
			ObjectMeta: v1.ObjectMeta{Name: "test2", Namespace: "mynamespace", Annotations: map[string]string{"ipam.adevinta.com/allowlist-group": "dnssource"}},
		}
		k8sClient := fake.NewClientBuilder().WithScheme(extendedScheme).WithObjects(gateway1, gateway2).Build()
		cidr := ipamv1alpha1.CIDRs{
			ObjectMeta: v1.ObjectMeta{Name: "dnssource", Namespace: "mynamespace"},
		}
		cidrResolver := resolvers.CidrResolver{Client: k8sClient, AnnotationPrefix: resolvers.DefaultPrefix}
		requests := newGatewaysFromCIDRFuncMap(k8sClient, cidrResolver.Annotation())(context.Background(), &cidr)
		assert.Len(t, requests, 1)
		assert.Equal(t, requests[0].Name, "test2")
	})
}

func TestClusterCidrToGatewayMapper(t *testing.T) {
	t.Run("ClusterCIDR is being used in the ingress, should return the ingress", func(t *testing.T) {
		gateway := &gatewayApiv1.Gateway{
			ObjectMeta: v1.ObjectMeta{Name: "test", Namespace: "mynamespace", Annotations: map[string]string{"ipam.adevinta.com/cluster-allowlist-group": "localnet,dnssource"}},
		}
		k8sClient := fake.NewClientBuilder().WithScheme(extendedScheme).WithObjects(gateway).Build()
		cidr := ipamv1alpha1.ClusterCIDRs{
			ObjectMeta: v1.ObjectMeta{Name: "localnet"},
		}
		cidrResolver := resolvers.CidrResolver{Client: k8sClient, AnnotationPrefix: resolvers.DefaultPrefix}
		requests := newGatewaysFromCIDRFuncMap(k8sClient, cidrResolver.ClusterAnnotation())(context.Background(), &cidr)
		assert.Len(t, requests, 1)
		assert.Equal(t, requests[0].Name, "test")
	})

	t.Run("ClusterCIDR is not being used in the ingress, should return an empty list", func(t *testing.T) {
		gateway := &gatewayApiv1.Gateway{
			ObjectMeta: v1.ObjectMeta{Name: "test", Namespace: "mynamespace", Annotations: map[string]string{"ipam.adevinta.com/cluster-allowlist-group": "dnssource"}},
		}
		k8sClient := fake.NewClientBuilder().WithScheme(extendedScheme).WithObjects(gateway).Build()
		cidr := ipamv1alpha1.ClusterCIDRs{
			ObjectMeta: v1.ObjectMeta{Name: "localnet", Namespace: "mynamespace"},
		}
		cidrResolver := resolvers.CidrResolver{Client: k8sClient, AnnotationPrefix: resolvers.DefaultPrefix}
		requests := newGatewaysFromCIDRFuncMap(k8sClient, cidrResolver.ClusterAnnotation())(context.Background(), &cidr)
		assert.Len(t, requests, 0)
	})
}

// TestGatewayAnnotationRemovalDeletesAP verifies end-to-end that removing the allowlist
// annotation from a Gateway triggers deletion of its AuthorizationPolicy.
func TestGatewayAnnotationRemovalDeletesAP(t *testing.T) {
	cidr := &ipamv1alpha1.CIDRs{
		ObjectMeta: v1.ObjectMeta{Name: "localnet", Namespace: "ns"},
		Status:     ipamv1alpha1.CIDRsStatus{CIDRs: []string{"10.0.0.0/8"}},
	}
	gwClass := newGatewayClass("istio")
	gateway := &gatewayApiv1.Gateway{
		ObjectMeta: v1.ObjectMeta{Namespace: "ns", Name: "my-gw", Annotations: map[string]string{
			"ipam.adevinta.com/allowlist-group": "localnet",
		}},
		Spec: gatewayApiv1.GatewaySpec{GatewayClassName: "istio"},
	}
	k8sClient := fake.NewClientBuilder().WithScheme(extendedScheme).WithObjects(cidr, gwClass, gateway).Build()
	reconciler := newGatewayReconciler(t, k8sClient, extendedScheme)

	// First reconcile — AP is created.
	_, err := reconciler.Reconcile(context.Background(), reconcile.Request{NamespacedName: client.ObjectKey{Name: "my-gw", Namespace: "ns"}})
	assert.NoError(t, err)
	ap := &istiosecurityv1.AuthorizationPolicy{}
	assert.NoError(t, k8sClient.Get(context.Background(), client.ObjectKey{Name: "my-gw", Namespace: "ns"}, ap))

	// Remove the allowlist annotation.
	gateway.Annotations = map[string]string{}
	assert.NoError(t, k8sClient.Update(context.Background(), gateway))

	// Second reconcile — AP must be deleted.
	_, err = reconciler.Reconcile(context.Background(), reconcile.Request{NamespacedName: client.ObjectKey{Name: "my-gw", Namespace: "ns"}})
	assert.NoError(t, err)
	err = k8sClient.Get(context.Background(), client.ObjectKey{Name: "my-gw", Namespace: "ns"}, ap)
	assert.True(t, apierrors.IsNotFound(err), "AP must be deleted after gateway annotation is removed")
}

// TestReconcileGatewayClassDeletedCleansUpAP verifies that when a GatewayClass is deleted,
// the gateway controller still cleans up the AuthorizationPolicy rather than leaving it orphaned.
func TestReconcileGatewayClassDeletedCleansUpAP(t *testing.T) {
	localnetCidrs := &ipamv1alpha1.CIDRs{
		ObjectMeta: v1.ObjectMeta{Name: "localnet", Namespace: "mynamespace"},
		Status:     ipamv1alpha1.CIDRsStatus{CIDRs: []string{"10.0.0.0/8"}},
	}
	gwClass := newGatewayClass("istio")
	gateway := &gatewayApiv1.Gateway{
		ObjectMeta: v1.ObjectMeta{Namespace: "mynamespace", Name: "test", Annotations: map[string]string{
			"ipam.adevinta.com/allowlist-group": "localnet",
		}},
		Spec: gatewayApiv1.GatewaySpec{GatewayClassName: "istio"},
	}
	k8sClient := fake.NewClientBuilder().WithScheme(extendedScheme).WithObjects(localnetCidrs, gateway, gwClass).Build()
	reconciler := newGatewayReconciler(t, k8sClient, extendedScheme)

	// First reconcile — AP is created.
	_, err := reconciler.Reconcile(context.Background(), reconcile.Request{NamespacedName: client.ObjectKey{Name: "test", Namespace: "mynamespace"}})
	assert.NoError(t, err)
	ap := &istiosecurityv1.AuthorizationPolicy{}
	assert.NoError(t, k8sClient.Get(context.Background(), client.ObjectKey{Name: "test", Namespace: "mynamespace"}, ap))

	// Delete the GatewayClass.
	assert.NoError(t, k8sClient.Delete(context.Background(), gwClass))

	// Second reconcile — AP must be cleaned up even though GatewayClass is gone.
	_, err = reconciler.Reconcile(context.Background(), reconcile.Request{NamespacedName: client.ObjectKey{Name: "test", Namespace: "mynamespace"}})
	assert.NoError(t, err)

	err = k8sClient.Get(context.Background(), client.ObjectKey{Name: "test", Namespace: "mynamespace"}, ap)
	assert.True(t, apierrors.IsNotFound(err), "AP must be deleted when GatewayClass is removed")
}
