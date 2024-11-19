package controllers

import (
	"context"
	"errors"
	"testing"

	"sigs.k8s.io/controller-runtime/pkg/client"

	ipamv1alpha1 "github.com/adevinta/ingress-allowlisting-controller/pkg/apis/ipam.adevinta.com/v1alpha1"
	"github.com/adevinta/ingress-allowlisting-controller/pkg/resolvers"
	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
	netv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

type erroredReader struct{}

func (e erroredReader) Get(ctx context.Context, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
	return errors.New("Nobody expects the spanish inquisition")
}

func (e erroredReader) List(ctx context.Context, list client.ObjectList, opts ...client.ListOption) error {
	return errors.New("Nobody expects the spanish inquisition")
}

var extendedScheme = runtime.NewScheme()

func init() {
	var err error
	extendedScheme, err = LegacyScheme("legacy.ipam.com/v1alpha1", extendedScheme)
	if err != nil {
		panic(err)
	}
}

func newIngressReconciler(t *testing.T, k8sClient client.Client) *IngressReconciler {
	t.Helper()
	resolver := resolvers.CidrResolver{Client: k8sClient, AnnotationPrefix: resolvers.DefaultPrefix}
	return &IngressReconciler{Client: k8sClient, CidrResolver: resolver}
}

// cases:
// v - ingress has annotations and ipamv1alpha1.CIDRs exists and has a valid format.
// v - ingress has no annotation
// v - ingress has annotations and some ipamv1alpha1.CIDRs doesn't exist.
// v - ResolveCidrs returns an unexpected error
// v - ingress has annotations and ALL ipamv1alpha1.CIDRS don't exist (ensure ingress reject all traffic) empty allowlist is rejected, so using 127.0.0.2/32
// - Error case: annotation has invalid format (i.e: is not comma-separated string)
//   - annotation = ",,"
//   - annotation = ""
//   - annotation = " "
//   - annotation = ",something"
//
// v    - annotation = "something1 , something2" // use: strings.TrimSpace
// v - ingress has already an allowed list it is overwritten
func TestReconcileIngress(t *testing.T) {
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
	ingress := &netv1.Ingress{
		ObjectMeta: v1.ObjectMeta{Namespace: "mynamespace", Annotations: map[string]string{
			"ipam.adevinta.com/cluster-allowlist-group": "globalnet",
			"ipam.adevinta.com/allowlist-group":         "localnet,dnssource",
		}},
	}
	k8sClient := fake.NewClientBuilder().WithScheme(extendedScheme).WithObjects(localnetCidrs, dnssourceCidrs, ingress, globalCidrs).Build()
	reconciler := newIngressReconciler(t, k8sClient)

	expectedIngress := netv1.Ingress{
		ObjectMeta: v1.ObjectMeta{
			Namespace: "mynamespace",
			// https://github.com/kubernetes-sigs/controller-runtime/blob/master/pkg/client/fake/client.go#L196
			ResourceVersion: "999",
			Annotations: map[string]string{
				"ipam.adevinta.com/allowlist-group":                  "localnet,dnssource",
				"ipam.adevinta.com/cluster-allowlist-group":          "globalnet",
				"nginx.ingress.kubernetes.io/whitelist-source-range": "192.168.0.0/16,172.16.0.0/12,10.0.0.0/8,1.1.1.1/32,8.8.8.8/32,15.13.12.0/24",
			},
		},
	}

	result, err := reconciler.reconcileIngress(context.Background(), *ingress)

	assert.NoError(t, err)
	assert.Equal(t, expectedIngress.ObjectMeta, result.ObjectMeta)

	events := &corev1.EventList{}
	assert.NoError(t, k8sClient.List(context.Background(), events, &client.ListOptions{Namespace: "mynamespace"}))
	assert.Empty(t, events.Items)
}

func TestReconcileIngressWithClusterCIDR(t *testing.T) {
	globalNet := &ipamv1alpha1.ClusterCIDRs{
		ObjectMeta: v1.ObjectMeta{Name: "globalnet"},
		Status:     ipamv1alpha1.CIDRsStatus{CIDRs: []string{"192.168.0.0/16", "172.16.0.0/12", "10.0.0.0/8"}},
	}
	anotherGlobalNet := &ipamv1alpha1.ClusterCIDRs{
		ObjectMeta: v1.ObjectMeta{Name: "anotherglobalnet"},
		Status:     ipamv1alpha1.CIDRsStatus{CIDRs: []string{"15.13.12.0/24"}},
	}
	ingress := &netv1.Ingress{
		ObjectMeta: v1.ObjectMeta{Namespace: "mynamespace", Annotations: map[string]string{
			"ipam.adevinta.com/cluster-allowlist-group": "globalnet,anotherglobalnet",
		}},
	}
	k8sClient := fake.NewClientBuilder().WithScheme(extendedScheme).WithObjects(ingress, globalNet, anotherGlobalNet).Build()
	reconciler := newIngressReconciler(t, k8sClient)

	expectedIngress := netv1.Ingress{
		ObjectMeta: v1.ObjectMeta{
			Namespace: "mynamespace",
			// https://github.com/kubernetes-sigs/controller-runtime/blob/master/pkg/client/fake/client.go#L196
			ResourceVersion: "999",
			Annotations: map[string]string{
				"ipam.adevinta.com/cluster-allowlist-group":          "globalnet,anotherglobalnet",
				"nginx.ingress.kubernetes.io/whitelist-source-range": "192.168.0.0/16,172.16.0.0/12,10.0.0.0/8,15.13.12.0/24",
			},
		},
	}

	result, err := reconciler.reconcileIngress(context.Background(), *ingress)

	assert.NoError(t, err)
	assert.Equal(t, expectedIngress.ObjectMeta, result.ObjectMeta)

	events := &corev1.EventList{}
	assert.NoError(t, k8sClient.List(context.Background(), events, &client.ListOptions{Namespace: "mynamespace"}))
	assert.Empty(t, events.Items)
}

func TestReconcileIngressNoAnnotations(t *testing.T) {
	ingress := &netv1.Ingress{
		ObjectMeta: v1.ObjectMeta{Namespace: "mynamespace", Annotations: map[string]string{}},
	}

	k8sClient := fake.NewClientBuilder().WithScheme(extendedScheme).WithObjects(ingress).Build()
	reconciler := newIngressReconciler(t, k8sClient)

	_, err := reconciler.reconcileIngress(context.Background(), *ingress)
	assert.Equal(t, reconciler.CidrResolver.AnnotationNotFoundError(), err)

	events := &corev1.EventList{}
	assert.NoError(t, k8sClient.List(context.Background(), events, &client.ListOptions{Namespace: "mynamespace"}))
	assert.Empty(t, events.Items)
}

func TestReconcileIngressPartialNotFound(t *testing.T) {
	localnetCidrs := &ipamv1alpha1.CIDRs{
		ObjectMeta: v1.ObjectMeta{Name: "localnet", Namespace: "mynamespace"},
		Status:     ipamv1alpha1.CIDRsStatus{CIDRs: []string{"192.168.0.0/16", "172.16.0.0/12", "10.0.0.0/8"}},
	}

	ingress := &netv1.Ingress{
		ObjectMeta: v1.ObjectMeta{Namespace: "mynamespace", Annotations: map[string]string{"ipam.adevinta.com/allowlist-group": "localnet,notexisting"}},
	}
	k8sClient := fake.NewClientBuilder().WithScheme(extendedScheme).WithObjects(localnetCidrs, ingress).Build()

	reconciler := newIngressReconciler(t, k8sClient)

	expectedIngress := netv1.Ingress{
		ObjectMeta: v1.ObjectMeta{
			Namespace: "mynamespace",
			// https://github.com/kubernetes-sigs/controller-runtime/blob/master/pkg/client/fake/client.go#L196
			ResourceVersion: "999",
			Annotations: map[string]string{
				"ipam.adevinta.com/allowlist-group":                  "localnet,notexisting",
				"nginx.ingress.kubernetes.io/whitelist-source-range": "192.168.0.0/16,172.16.0.0/12,10.0.0.0/8",
			},
		},
	}

	result, err := reconciler.reconcileIngress(context.Background(), *ingress)

	assert.NoError(t, err)
	assert.Equal(t, expectedIngress.ObjectMeta, result.ObjectMeta)
}

func TestReconcileIngressWithInvalidCIDRIpsNoError(t *testing.T) {
	localnetCidrs := &ipamv1alpha1.CIDRs{
		ObjectMeta: v1.ObjectMeta{Name: "localnet", Namespace: "mynamespace"},
		Status:     ipamv1alpha1.CIDRsStatus{CIDRs: []string{"192.168.0/16", "172.16.0.0/12", "10.0.0.0/8", "10.0.0.0"}},
	}
	dnssourceCidrs := &ipamv1alpha1.CIDRs{
		ObjectMeta: v1.ObjectMeta{Name: "dnssource", Namespace: "mynamespace"},
		Status:     ipamv1alpha1.CIDRsStatus{CIDRs: []string{"1.1.1.1/32", "8.8.8.8/32"}},
	}
	ingress := &netv1.Ingress{
		ObjectMeta: v1.ObjectMeta{Namespace: "mynamespace", Annotations: map[string]string{"ipam.adevinta.com/allowlist-group": "localnet,dnssource"}},
	}
	k8sClient := fake.NewClientBuilder().WithScheme(extendedScheme).WithObjects(localnetCidrs, dnssourceCidrs, ingress).Build()

	reconciler := newIngressReconciler(t, k8sClient)

	expectedIngress := netv1.Ingress{
		ObjectMeta: v1.ObjectMeta{
			Namespace:       "mynamespace",
			ResourceVersion: "999",
			Annotations: map[string]string{
				"ipam.adevinta.com/allowlist-group":                  "localnet,dnssource",
				"nginx.ingress.kubernetes.io/whitelist-source-range": "172.16.0.0/12,10.0.0.0/8,1.1.1.1/32,8.8.8.8/32",
			},
		},
	}

	result, err := reconciler.reconcileIngress(context.Background(), *ingress)

	assert.NoError(t, err)
	assert.Equal(t, expectedIngress.ObjectMeta, result.ObjectMeta)

	events := &corev1.EventList{}
	assert.NoError(t, k8sClient.List(context.Background(), events, &client.ListOptions{Namespace: "mynamespace"}))
	assert.Empty(t, events.Items)
}

func TestReconcileIngressCIDRsNotFound(t *testing.T) {
	t.Run("Namespace CIDR not found", func(t *testing.T) {
		ingress := &netv1.Ingress{
			ObjectMeta: v1.ObjectMeta{Name: "ingresstest", Namespace: "mynamespace", Annotations: map[string]string{"ipam.adevinta.com/allowlist-group": "notexisting,alsonotexisting"}},
		}
		k8sClient := fake.NewClientBuilder().WithScheme(extendedScheme).WithObjects(ingress).Build()
		reconciler := newIngressReconciler(t, k8sClient)

		expectedIngress := netv1.Ingress{
			ObjectMeta: v1.ObjectMeta{
				Namespace: "mynamespace",
				Name:      "ingresstest",
				// https://github.com/kubernetes-sigs/controller-runtime/blob/master/pkg/client/fake/client.go#L196
				ResourceVersion: "999",
				Annotations: map[string]string{
					"ipam.adevinta.com/allowlist-group":                  "notexisting,alsonotexisting",
					"nginx.ingress.kubernetes.io/whitelist-source-range": "127.0.0.2/32",
				},
			},
		}

		result, err := reconciler.reconcileIngress(context.Background(), *ingress)

		assert.NoError(t, err)
		assert.Equal(t, expectedIngress.ObjectMeta, result.ObjectMeta)

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

		assert.NotEmpty(t, events.Items)
		assert.Equal(t, events.Items[0].Action, expectedEvents.Items[0].Action)
	})

	t.Run("Cluster CIDR not found", func(t *testing.T) {
		ingress := &netv1.Ingress{
			ObjectMeta: v1.ObjectMeta{Name: "ingresstest", Namespace: "mynamespace", Annotations: map[string]string{"ipam.adevinta.com/cluster-allowlist-group": "notexisting,alsonotexisting"}},
		}
		k8sClient := fake.NewClientBuilder().WithScheme(extendedScheme).WithObjects(ingress).Build()

		reconciler := newIngressReconciler(t, k8sClient)

		expectedIngress := netv1.Ingress{
			ObjectMeta: v1.ObjectMeta{
				Namespace: "mynamespace",
				Name:      "ingresstest",
				// https://github.com/kubernetes-sigs/controller-runtime/blob/master/pkg/client/fake/client.go#L196
				ResourceVersion: "999",
				Annotations: map[string]string{
					"ipam.adevinta.com/cluster-allowlist-group":          "notexisting,alsonotexisting",
					"nginx.ingress.kubernetes.io/whitelist-source-range": "127.0.0.2/32",
				},
			},
		}

		result, err := reconciler.reconcileIngress(context.Background(), *ingress)

		assert.NoError(t, err)
		assert.Equal(t, expectedIngress.ObjectMeta, result.ObjectMeta)

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

// - ingress has already a allowlist it is overwritten
func TestReconcileIngressOverwriteAllowlist(t *testing.T) {
	localnetCidrs := &ipamv1alpha1.CIDRs{
		ObjectMeta: v1.ObjectMeta{Name: "localnet", Namespace: "mynamespace"},
		Status:     ipamv1alpha1.CIDRsStatus{CIDRs: []string{"192.168.0.0/16", "172.16.0.0/12", "10.0.0.0/8"}},
	}
	globalnetCidrs := &ipamv1alpha1.ClusterCIDRs{
		ObjectMeta: v1.ObjectMeta{Name: "globalnet"},
		Status:     ipamv1alpha1.CIDRsStatus{CIDRs: []string{"1.2.3.0/24"}},
	}

	ingress := &netv1.Ingress{
		ObjectMeta: v1.ObjectMeta{Namespace: "mynamespace", Annotations: map[string]string{
			"ipam.adevinta.com/allowlist-group":                  "localnet",
			"ipam.adevinta.com/cluster-allowlist-group":          "globalnet",
			"nginx.ingress.kubernetes.io/whitelist-source-range": "1.1.1.1/32,8.8.8.8/32",
		}},
	}
	k8sClient := fake.NewClientBuilder().WithScheme(extendedScheme).WithObjects(localnetCidrs, globalnetCidrs, ingress).Build()

	reconciler := newIngressReconciler(t, k8sClient)

	expectedIngress := netv1.Ingress{
		ObjectMeta: v1.ObjectMeta{
			Namespace: "mynamespace",
			// https://github.com/kubernetes-sigs/controller-runtime/blob/master/pkg/client/fake/client.go#L196
			ResourceVersion: "999",
			Annotations: map[string]string{
				"ipam.adevinta.com/allowlist-group":                  "localnet",
				"ipam.adevinta.com/cluster-allowlist-group":          "globalnet",
				"nginx.ingress.kubernetes.io/whitelist-source-range": "192.168.0.0/16,172.16.0.0/12,10.0.0.0/8,1.2.3.0/24",
			},
		},
	}

	result, err := reconciler.reconcileIngress(context.Background(), *ingress)

	assert.NoError(t, err)
	assert.Equal(t, expectedIngress.ObjectMeta, result.ObjectMeta)
}

type testfunc struct {
	client.WithWatch
	getfunc func(ctx context.Context, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error
}

func (t *testfunc) Get(ctx context.Context, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
	if t.getfunc != nil {
		return t.getfunc(ctx, key, obj, opts...)
	}
	return errors.New("not implemented")
}

func TestReconcileIngressApiError(t *testing.T) {
	k8sClient := &testfunc{WithWatch: fake.NewClientBuilder().WithScheme(extendedScheme).Build()}
	k8sClient.getfunc = func(ctx context.Context, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
		return errors.New("error that is not a NOTFOUND")
	}

	ingress := &netv1.Ingress{
		ObjectMeta: v1.ObjectMeta{Namespace: "mynamespace", Annotations: map[string]string{"ipam.adevinta.com/allowlist-group": "notexisting"}},
	}

	reconciler := newIngressReconciler(t, k8sClient)

	_, err := reconciler.reconcileIngress(context.Background(), *ingress)

	assert.Error(t, err)
}

func TestReconcileIngressInvalidAnnotationFormat(t *testing.T) {
	localnetCidrs := &ipamv1alpha1.CIDRs{
		ObjectMeta: v1.ObjectMeta{Name: "localnet", Namespace: "mynamespace"},
		Status:     ipamv1alpha1.CIDRsStatus{CIDRs: []string{"192.168.0.0/16", "172.16.0.0/12", "10.0.0.0/8"}},
	}
	dnssourceCidrs := &ipamv1alpha1.CIDRs{
		ObjectMeta: v1.ObjectMeta{Name: "dnssource", Namespace: "mynamespace"},
		Status:     ipamv1alpha1.CIDRsStatus{CIDRs: []string{"1.1.1.1/32", "8.8.8.8/32"}},
	}
	ingress := &netv1.Ingress{
		ObjectMeta: v1.ObjectMeta{Namespace: "mynamespace", Annotations: map[string]string{"ipam.adevinta.com/allowlist-group": "localnet, dnssource"}},
	}
	k8sClient := fake.NewClientBuilder().WithScheme(extendedScheme).WithObjects(localnetCidrs, dnssourceCidrs, ingress).Build()

	reconciler := newIngressReconciler(t, k8sClient)

	expectedIngress := netv1.Ingress{
		ObjectMeta: v1.ObjectMeta{
			Namespace: "mynamespace",
			// https://github.com/kubernetes-sigs/controller-runtime/blob/master/pkg/client/fake/client.go#L196
			ResourceVersion: "999",
			Annotations: map[string]string{
				"ipam.adevinta.com/allowlist-group":                  "localnet, dnssource",
				"nginx.ingress.kubernetes.io/whitelist-source-range": "192.168.0.0/16,172.16.0.0/12,10.0.0.0/8,1.1.1.1/32,8.8.8.8/32",
			},
		},
	}

	result, err := reconciler.reconcileIngress(context.Background(), *ingress)

	assert.NoError(t, err)
	assert.Equal(t, expectedIngress.ObjectMeta, result.ObjectMeta)
}

func TestReconcileIngressV1(t *testing.T) {
	localnetCidrs := &ipamv1alpha1.CIDRs{
		ObjectMeta: v1.ObjectMeta{Name: "localnet", Namespace: "mynamespace"},
		Status:     ipamv1alpha1.CIDRsStatus{CIDRs: []string{"192.168.0.0/16", "172.16.0.0/12", "10.0.0.0/8"}},
	}
	dnssourceCidrs := &ipamv1alpha1.CIDRs{
		ObjectMeta: v1.ObjectMeta{Name: "dnssource", Namespace: "mynamespace"},
		Status:     ipamv1alpha1.CIDRsStatus{CIDRs: []string{"1.1.1.1/32", "8.8.8.8/32"}},
	}
	ingress := &netv1.Ingress{
		ObjectMeta: v1.ObjectMeta{Namespace: "mynamespace", Annotations: map[string]string{"ipam.adevinta.com/allowlist-group": "localnet,dnssource"}},
	}
	k8sClient := fake.NewClientBuilder().WithScheme(extendedScheme).WithObjects(localnetCidrs, dnssourceCidrs, ingress).Build()

	reconciler := newIngressReconciler(t, k8sClient)
	expectedIngress := netv1.Ingress{
		ObjectMeta: v1.ObjectMeta{
			Namespace: "mynamespace",
			// https://github.com/kubernetes-sigs/controller-runtime/blob/master/pkg/client/fake/client.go#L196
			ResourceVersion: "999",
			Annotations: map[string]string{
				"ipam.adevinta.com/allowlist-group":                  "localnet,dnssource",
				"nginx.ingress.kubernetes.io/whitelist-source-range": "192.168.0.0/16,172.16.0.0/12,10.0.0.0/8,1.1.1.1/32,8.8.8.8/32",
			},
		},
	}

	result, err := reconciler.reconcileIngress(context.Background(), *ingress)

	assert.NoError(t, err)
	assert.Equal(t, expectedIngress.ObjectMeta, result.ObjectMeta)
}

func TestCidrToIngressMapper(t *testing.T) {
	t.Run("CIDR is being used in the ingress, should return the ingress", func(t *testing.T) {
		ingress := &netv1.Ingress{
			ObjectMeta: v1.ObjectMeta{Name: "test", Namespace: "mynamespace", Annotations: map[string]string{"ipam.adevinta.com/allowlist-group": "localnet,dnssource"}},
		}
		k8sClient := fake.NewClientBuilder().WithScheme(extendedScheme).WithObjects(ingress).Build()
		cidr := ipamv1alpha1.CIDRs{
			ObjectMeta: v1.ObjectMeta{Name: "localnet", Namespace: "mynamespace"},
		}
		requests := newIngressesFromCIDRFuncMap(k8sClient, "ipam.adevinta.com/allowlist-group")(context.Background(), &cidr)
		assert.Len(t, requests, 1)
		assert.Equal(t, requests[0].Name, "test")
	})

	t.Run("CIDR is not being used in the ingress, should return an empty list", func(t *testing.T) {
		ingress := &netv1.Ingress{
			ObjectMeta: v1.ObjectMeta{Name: "test", Namespace: "mynamespace", Annotations: map[string]string{"ipam.adevinta.com/allowlist-group": "dnssource"}},
		}
		k8sClient := fake.NewClientBuilder().WithScheme(extendedScheme).WithObjects(ingress).Build()
		cidr := ipamv1alpha1.CIDRs{
			ObjectMeta: v1.ObjectMeta{Name: "localnet", Namespace: "mynamespace"},
		}
		requests := newIngressesFromCIDRFuncMap(k8sClient, "ipam.adevinta.com/allowlist-group")(context.Background(), &cidr)
		assert.Len(t, requests, 0)
	})
	t.Run("One CIDR is being used in the ingress, should return just that one", func(t *testing.T) {
		ingress1 := &netv1.Ingress{
			ObjectMeta: v1.ObjectMeta{Name: "test", Namespace: "mynamespace"},
		}
		ingress2 := &netv1.Ingress{
			ObjectMeta: v1.ObjectMeta{Name: "test2", Namespace: "mynamespace", Annotations: map[string]string{"ipam.adevinta.com/allowlist-group": "dnssource"}},
		}
		k8sClient := fake.NewClientBuilder().WithScheme(extendedScheme).WithObjects(ingress1, ingress2).Build()
		cidr := ipamv1alpha1.CIDRs{
			ObjectMeta: v1.ObjectMeta{Name: "dnssource", Namespace: "mynamespace"},
		}
		requests := newIngressesFromCIDRFuncMap(k8sClient, "ipam.adevinta.com/allowlist-group")(context.Background(), &cidr)
		assert.Len(t, requests, 1)
		assert.Equal(t, requests[0].Name, "test2")
	})
}

func TestClusterCidrToIngressMapper(t *testing.T) {
	t.Run("ClusterCIDR is being used in the ingress, should return the ingress", func(t *testing.T) {
		ingress := &netv1.Ingress{
			ObjectMeta: v1.ObjectMeta{Name: "test", Namespace: "mynamespace", Annotations: map[string]string{"ipam.adevinta.com/cluster-allowlist-group": "localnet,dnssource"}},
		}
		k8sClient := fake.NewClientBuilder().WithScheme(extendedScheme).WithObjects(ingress).Build()
		cidr := ipamv1alpha1.ClusterCIDRs{
			ObjectMeta: v1.ObjectMeta{Name: "localnet"},
		}
		cidrResolver := resolvers.CidrResolver{Client: k8sClient, AnnotationPrefix: resolvers.DefaultPrefix}
		requests := newIngressesFromCIDRFuncMap(k8sClient, cidrResolver.ClusterAnnotation())(context.Background(), &cidr)
		assert.Len(t, requests, 1)
		assert.Equal(t, requests[0].Name, "test")
	})

	t.Run("ClusterCIDR is not being used in the ingress, should return an empty list", func(t *testing.T) {
		ingress := &netv1.Ingress{
			ObjectMeta: v1.ObjectMeta{Name: "test", Namespace: "mynamespace", Annotations: map[string]string{"ipam.adevinta.com/cluster-allowlist-group": "dnssource"}},
		}
		k8sClient := fake.NewClientBuilder().WithScheme(extendedScheme).WithObjects(ingress).Build()
		cidr := ipamv1alpha1.ClusterCIDRs{
			ObjectMeta: v1.ObjectMeta{Name: "localnet", Namespace: "mynamespace"},
		}
		cidrResolver := resolvers.CidrResolver{Client: k8sClient, AnnotationPrefix: resolvers.DefaultPrefix}
		requests := newIngressesFromCIDRFuncMap(k8sClient, cidrResolver.ClusterAnnotation())(context.Background(), &cidr)
		assert.Len(t, requests, 0)
	})
}
