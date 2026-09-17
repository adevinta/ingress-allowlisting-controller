package controllers

import (
	"context"
	"errors"
	"testing"

	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	ipamv1alpha1 "github.com/adevinta/ingress-allowlisting-controller/pkg/apis/ipam.adevinta.com/v1alpha1"
	"github.com/adevinta/ingress-allowlisting-controller/pkg/resolvers"
	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func newServiceReconciler(t *testing.T, k8sClient client.Client) *ServiceReconciler {
	t.Helper()
	resolver := resolvers.CidrResolver{Client: k8sClient, AnnotationPrefix: resolvers.DefaultPrefix}
	return &ServiceReconciler{Client: k8sClient, CidrResolver: resolver}
}

func loadBalancerService(annotations map[string]string) *corev1.Service {
	return &corev1.Service{
		ObjectMeta: v1.ObjectMeta{
			Name:        "test-service",
			Namespace:   "mynamespace",
			Annotations: annotations,
		},
		Spec: corev1.ServiceSpec{
			Type: corev1.ServiceTypeLoadBalancer,
		},
	}
}

func TestReconcileService(t *testing.T) {
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
	service := loadBalancerService(map[string]string{
		"ipam.adevinta.com/cluster-allowlist-group": "globalnet",
		"ipam.adevinta.com/allowlist-group":         "localnet,dnssource",
	})

	k8sClient := fake.NewClientBuilder().WithScheme(extendedScheme).WithObjects(localnetCidrs, dnssourceCidrs, globalCidrs, service).Build()
	reconciler := newServiceReconciler(t, k8sClient)

	result, err := reconciler.reconcileService(context.Background(), *service)

	assert.NoError(t, err)
	assert.Len(t, result.Spec.LoadBalancerSourceRanges, 6) // 3 localnet + 2 dnssource + 1 globalnet
	assert.Contains(t, result.Spec.LoadBalancerSourceRanges, "192.168.0.0/16")
	assert.Contains(t, result.Spec.LoadBalancerSourceRanges, "172.16.0.0/12")
	assert.Contains(t, result.Spec.LoadBalancerSourceRanges, "10.0.0.0/8")
	assert.Contains(t, result.Spec.LoadBalancerSourceRanges, "1.1.1.1/32")
	assert.Contains(t, result.Spec.LoadBalancerSourceRanges, "8.8.8.8/32")
	assert.Contains(t, result.Spec.LoadBalancerSourceRanges, "15.13.12.0/24")
}

func TestReconcileServiceWithClusterCIDR(t *testing.T) {
	globalNet := &ipamv1alpha1.ClusterCIDRs{
		ObjectMeta: v1.ObjectMeta{Name: "globalnet"},
		Status:     ipamv1alpha1.CIDRsStatus{CIDRs: []string{"192.168.0.0/16", "172.16.0.0/12", "10.0.0.0/8"}},
	}
	anotherGlobalNet := &ipamv1alpha1.ClusterCIDRs{
		ObjectMeta: v1.ObjectMeta{Name: "anotherglobalnet"},
		Status:     ipamv1alpha1.CIDRsStatus{CIDRs: []string{"15.13.12.0/24"}},
	}
	service := loadBalancerService(map[string]string{
		"ipam.adevinta.com/cluster-allowlist-group": "globalnet,anotherglobalnet",
	})

	k8sClient := fake.NewClientBuilder().WithScheme(extendedScheme).WithObjects(globalNet, anotherGlobalNet, service).Build()
	reconciler := newServiceReconciler(t, k8sClient)

	result, err := reconciler.reconcileService(context.Background(), *service)

	assert.NoError(t, err)
	assert.Len(t, result.Spec.LoadBalancerSourceRanges, 4)
	assert.Contains(t, result.Spec.LoadBalancerSourceRanges, "192.168.0.0/16")
	assert.Contains(t, result.Spec.LoadBalancerSourceRanges, "172.16.0.0/12")
	assert.Contains(t, result.Spec.LoadBalancerSourceRanges, "10.0.0.0/8")
	assert.Contains(t, result.Spec.LoadBalancerSourceRanges, "15.13.12.0/24")
}

func TestReconcileServiceNonLoadBalancerSkipped(t *testing.T) {
	localnetCidrs := &ipamv1alpha1.CIDRs{
		ObjectMeta: v1.ObjectMeta{Name: "localnet", Namespace: "mynamespace"},
		Status:     ipamv1alpha1.CIDRsStatus{CIDRs: []string{"192.168.0.0/16"}},
	}
	service := &corev1.Service{
		ObjectMeta: v1.ObjectMeta{
			Name:      "test-service",
			Namespace: "mynamespace",
			Annotations: map[string]string{
				"ipam.adevinta.com/allowlist-group": "localnet",
			},
		},
		Spec: corev1.ServiceSpec{
			Type: corev1.ServiceTypeClusterIP,
		},
	}

	k8sClient := fake.NewClientBuilder().WithScheme(extendedScheme).WithObjects(localnetCidrs, service).Build()
	reconciler := newServiceReconciler(t, k8sClient)

	result, err := reconciler.reconcileService(context.Background(), *service)

	assert.NoError(t, err)
	// Non-LoadBalancer Services must not get loadBalancerSourceRanges set.
	assert.Nil(t, result.Spec.LoadBalancerSourceRanges)
}

func TestReconcileServiceNoAnnotations(t *testing.T) {
	service := loadBalancerService(map[string]string{})

	k8sClient := fake.NewClientBuilder().WithScheme(extendedScheme).WithObjects(service).Build()
	reconciler := newServiceReconciler(t, k8sClient)

	_, err := reconciler.reconcileService(context.Background(), *service)
	assert.Equal(t, reconciler.CidrResolver.AnnotationNotFoundError(), err)
}

func TestReconcileServicePartialNotFound(t *testing.T) {
	localnetCidrs := &ipamv1alpha1.CIDRs{
		ObjectMeta: v1.ObjectMeta{Name: "localnet", Namespace: "mynamespace"},
		Status:     ipamv1alpha1.CIDRsStatus{CIDRs: []string{"192.168.0.0/16", "172.16.0.0/12", "10.0.0.0/8"}},
	}
	service := loadBalancerService(map[string]string{
		"ipam.adevinta.com/allowlist-group": "localnet,notexisting",
	})

	k8sClient := fake.NewClientBuilder().WithScheme(extendedScheme).WithObjects(localnetCidrs, service).Build()
	reconciler := newServiceReconciler(t, k8sClient)

	result, err := reconciler.reconcileService(context.Background(), *service)

	assert.NoError(t, err)
	assert.Len(t, result.Spec.LoadBalancerSourceRanges, 3) // Only the found CIDRs
	assert.Contains(t, result.Spec.LoadBalancerSourceRanges, "192.168.0.0/16")
	assert.Contains(t, result.Spec.LoadBalancerSourceRanges, "172.16.0.0/12")
	assert.Contains(t, result.Spec.LoadBalancerSourceRanges, "10.0.0.0/8")
}

func TestReconcileServiceWithInvalidCIDRIpsNoError(t *testing.T) {
	localnetCidrs := &ipamv1alpha1.CIDRs{
		ObjectMeta: v1.ObjectMeta{Name: "localnet", Namespace: "mynamespace"},
		Status:     ipamv1alpha1.CIDRsStatus{CIDRs: []string{"192.168.0/16", "172.16.0.0/12", "10.0.0.0/8", "10.0.0.0"}},
	}
	dnssourceCidrs := &ipamv1alpha1.CIDRs{
		ObjectMeta: v1.ObjectMeta{Name: "dnssource", Namespace: "mynamespace"},
		Status:     ipamv1alpha1.CIDRsStatus{CIDRs: []string{"1.1.1.1/32", "8.8.8.8/32"}},
	}
	service := loadBalancerService(map[string]string{
		"ipam.adevinta.com/allowlist-group": "localnet,dnssource",
	})

	k8sClient := fake.NewClientBuilder().WithScheme(extendedScheme).WithObjects(localnetCidrs, dnssourceCidrs, service).Build()
	reconciler := newServiceReconciler(t, k8sClient)

	result, err := reconciler.reconcileService(context.Background(), *service)

	assert.NoError(t, err)
	// Should only include valid CIDRs
	assert.Len(t, result.Spec.LoadBalancerSourceRanges, 4)
	assert.Contains(t, result.Spec.LoadBalancerSourceRanges, "172.16.0.0/12")
	assert.Contains(t, result.Spec.LoadBalancerSourceRanges, "10.0.0.0/8")
	assert.Contains(t, result.Spec.LoadBalancerSourceRanges, "1.1.1.1/32")
	assert.Contains(t, result.Spec.LoadBalancerSourceRanges, "8.8.8.8/32")
	assert.NotContains(t, result.Spec.LoadBalancerSourceRanges, "192.168.0/16")
	assert.NotContains(t, result.Spec.LoadBalancerSourceRanges, "10.0.0.0")
}

func TestReconcileServiceAllCIDRsNotFound(t *testing.T) {
	t.Run("Namespace CIDR not found", func(t *testing.T) {
		service := loadBalancerService(map[string]string{
			"ipam.adevinta.com/allowlist-group": "notexisting,alsonotexisting",
		})

		k8sClient := fake.NewClientBuilder().WithScheme(extendedScheme).WithObjects(service).Build()
		reconciler := newServiceReconciler(t, k8sClient)

		result, err := reconciler.reconcileService(context.Background(), *service)

		assert.NoError(t, err)
		// Should only include fallback CIDR
		assert.Equal(t, []string{"127.0.0.2/32"}, result.Spec.LoadBalancerSourceRanges)
	})

	t.Run("Cluster CIDR not found", func(t *testing.T) {
		service := loadBalancerService(map[string]string{
			"ipam.adevinta.com/cluster-allowlist-group": "notexisting,alsonotexisting",
		})

		k8sClient := fake.NewClientBuilder().WithScheme(extendedScheme).WithObjects(service).Build()
		reconciler := newServiceReconciler(t, k8sClient)

		result, err := reconciler.reconcileService(context.Background(), *service)

		assert.NoError(t, err)
		assert.Equal(t, []string{"127.0.0.2/32"}, result.Spec.LoadBalancerSourceRanges)
	})
}

func TestReconcileServiceOverwriteExistingRanges(t *testing.T) {
	localnetCidrs := &ipamv1alpha1.CIDRs{
		ObjectMeta: v1.ObjectMeta{Name: "localnet", Namespace: "mynamespace"},
		Status:     ipamv1alpha1.CIDRsStatus{CIDRs: []string{"192.168.0.0/16", "172.16.0.0/12"}},
	}
	service := loadBalancerService(map[string]string{
		"ipam.adevinta.com/allowlist-group": "localnet",
	})
	service.Spec.LoadBalancerSourceRanges = []string{"1.1.1.1/32"}

	k8sClient := fake.NewClientBuilder().WithScheme(extendedScheme).WithObjects(localnetCidrs, service).Build()
	reconciler := newServiceReconciler(t, k8sClient)

	result, err := reconciler.reconcileService(context.Background(), *service)

	assert.NoError(t, err)
	assert.Len(t, result.Spec.LoadBalancerSourceRanges, 2)
	assert.Contains(t, result.Spec.LoadBalancerSourceRanges, "192.168.0.0/16")
	assert.Contains(t, result.Spec.LoadBalancerSourceRanges, "172.16.0.0/12")
	assert.NotContains(t, result.Spec.LoadBalancerSourceRanges, "1.1.1.1/32") // Old range should be gone
}

func TestReconcileServiceApiError(t *testing.T) {
	k8sClient := &testfunc{WithWatch: fake.NewClientBuilder().WithScheme(extendedScheme).Build()}
	k8sClient.getfunc = func(ctx context.Context, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
		return errors.New("error that is not a NOTFOUND")
	}

	service := loadBalancerService(map[string]string{
		"ipam.adevinta.com/allowlist-group": "notexisting",
	})

	reconciler := newServiceReconciler(t, k8sClient)

	_, err := reconciler.reconcileService(context.Background(), *service)

	assert.Error(t, err)
}

func TestReconcileServiceInvalidAnnotationFormat(t *testing.T) {
	localnetCidrs := &ipamv1alpha1.CIDRs{
		ObjectMeta: v1.ObjectMeta{Name: "localnet", Namespace: "mynamespace"},
		Status:     ipamv1alpha1.CIDRsStatus{CIDRs: []string{"192.168.0.0/16", "172.16.0.0/12"}},
	}
	dnssourceCidrs := &ipamv1alpha1.CIDRs{
		ObjectMeta: v1.ObjectMeta{Name: "dnssource", Namespace: "mynamespace"},
		Status:     ipamv1alpha1.CIDRsStatus{CIDRs: []string{"1.1.1.1/32"}},
	}
	service := loadBalancerService(map[string]string{
		"ipam.adevinta.com/allowlist-group": "localnet, dnssource", // Space after comma
	})

	k8sClient := fake.NewClientBuilder().WithScheme(extendedScheme).WithObjects(localnetCidrs, dnssourceCidrs, service).Build()
	reconciler := newServiceReconciler(t, k8sClient)

	result, err := reconciler.reconcileService(context.Background(), *service)

	// Should handle spaces gracefully
	assert.NoError(t, err)
	assert.Len(t, result.Spec.LoadBalancerSourceRanges, 3)
	assert.Contains(t, result.Spec.LoadBalancerSourceRanges, "192.168.0.0/16")
	assert.Contains(t, result.Spec.LoadBalancerSourceRanges, "172.16.0.0/12")
	assert.Contains(t, result.Spec.LoadBalancerSourceRanges, "1.1.1.1/32")
}

func TestReconcileServiceSkipsUpdateWhenUnchanged(t *testing.T) {
	localnetCidrs := &ipamv1alpha1.CIDRs{
		ObjectMeta: v1.ObjectMeta{Name: "localnet", Namespace: "mynamespace"},
		Status:     ipamv1alpha1.CIDRsStatus{CIDRs: []string{"192.168.0.0/16"}},
	}
	service := loadBalancerService(map[string]string{
		"ipam.adevinta.com/allowlist-group": "localnet",
	})
	service.Spec.LoadBalancerSourceRanges = []string{"192.168.0.0/16"}

	k8sClient := fake.NewClientBuilder().WithScheme(extendedScheme).WithObjects(localnetCidrs, service).Build()
	reconciler := newServiceReconciler(t, k8sClient)

	_, err := reconciler.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Namespace: "mynamespace", Name: "test-service"}})
	assert.NoError(t, err)

	updated := &corev1.Service{}
	assert.NoError(t, k8sClient.Get(context.Background(), types.NamespacedName{Namespace: "mynamespace", Name: "test-service"}, updated))
	assert.Equal(t, "999", updated.ResourceVersion, "Update should not have been called when loadBalancerSourceRanges is already correct")
}

func TestServiceToServicesMapper(t *testing.T) {
	t.Run("CIDR is being used in the Service, should return the Service", func(t *testing.T) {
		service := &corev1.Service{
			ObjectMeta: v1.ObjectMeta{
				Name:      "test",
				Namespace: "mynamespace",
				Annotations: map[string]string{
					"ipam.adevinta.com/allowlist-group": "localnet,dnssource",
				},
			},
		}
		k8sClient := fake.NewClientBuilder().WithScheme(extendedScheme).WithObjects(service).Build()
		cidr := ipamv1alpha1.CIDRs{
			ObjectMeta: v1.ObjectMeta{Name: "localnet", Namespace: "mynamespace"},
		}
		requests := newServicesFromCIDRFuncMap(k8sClient, "ipam.adevinta.com/allowlist-group")(context.Background(), &cidr)
		assert.Len(t, requests, 1)
		assert.Equal(t, requests[0].Name, "test")
	})

	t.Run("CIDR is not being used in the Service, should return an empty list", func(t *testing.T) {
		service := &corev1.Service{
			ObjectMeta: v1.ObjectMeta{
				Name:      "test",
				Namespace: "mynamespace",
				Annotations: map[string]string{
					"ipam.adevinta.com/allowlist-group": "dnssource",
				},
			},
		}
		k8sClient := fake.NewClientBuilder().WithScheme(extendedScheme).WithObjects(service).Build()
		cidr := ipamv1alpha1.CIDRs{
			ObjectMeta: v1.ObjectMeta{Name: "localnet", Namespace: "mynamespace"},
		}
		requests := newServicesFromCIDRFuncMap(k8sClient, "ipam.adevinta.com/allowlist-group")(context.Background(), &cidr)
		assert.Len(t, requests, 0)
	})
}

func TestClusterCidrToServicesMapper(t *testing.T) {
	t.Run("ClusterCIDR is being used in the Service, should return the Service", func(t *testing.T) {
		service := &corev1.Service{
			ObjectMeta: v1.ObjectMeta{
				Name:      "test",
				Namespace: "mynamespace",
				Annotations: map[string]string{
					"ipam.adevinta.com/cluster-allowlist-group": "localnet,dnssource",
				},
			},
		}
		k8sClient := fake.NewClientBuilder().WithScheme(extendedScheme).WithObjects(service).Build()
		cidr := ipamv1alpha1.ClusterCIDRs{
			ObjectMeta: v1.ObjectMeta{Name: "localnet"},
		}
		cidrResolver := resolvers.CidrResolver{Client: k8sClient, AnnotationPrefix: resolvers.DefaultPrefix}
		requests := newServicesFromCIDRFuncMap(k8sClient, cidrResolver.ClusterAnnotation())(context.Background(), &cidr)
		assert.Len(t, requests, 1)
		assert.Equal(t, requests[0].Name, "test")
	})
}
