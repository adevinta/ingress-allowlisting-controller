package resolvers_test

import (
	"context"
	"testing"

	ipamv1alpha1 "github.com/adevinta/ingress-allowlisting-controller/pkg/apis/ipam.adevinta.com/v1alpha1"
	"github.com/adevinta/ingress-allowlisting-controller/pkg/controllers"
	"github.com/adevinta/ingress-allowlisting-controller/pkg/resolvers"
	"github.com/stretchr/testify/assert"
	netv1 "k8s.io/api/networking/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

var extendedScheme = runtime.NewScheme()

func init() {
	var err error
	extendedScheme, err = controllers.Scheme()
	if err != nil {
		panic(err)
	}
}

func TestResolveCidrs(t *testing.T) {
	t.Run("Namespaced CIDRs", func(t *testing.T) {
		cidrs := &ipamv1alpha1.CIDRs{
			ObjectMeta: v1.ObjectMeta{Name: "localnet", Namespace: "mynamespace"},
			Status:     ipamv1alpha1.CIDRsStatus{CIDRs: []string{"192.168.0.0/16", "172.16.0.0/12", "10.0.0.0/8"}},
		}
		k8sClient := fake.NewClientBuilder().WithScheme(extendedScheme).WithObjects(cidrs).Build()
		reconciller := controllers.IngressReconciler{Client: k8sClient}
		name := "localnet"
		namespace := "mynamespace"
		expected := []string{"192.168.0.0/16", "172.16.0.0/12", "10.0.0.0/8"}

		resolver := resolvers.NamespacedCIDRResolver{reconciller.Client}

		result, err := resolver.ResolveCidrs(context.Background(), namespace, name)

		assert.NoError(t, err)
		assert.Equal(t, expected, result)
	})

	t.Run("Cluster CIDRs", func(t *testing.T) {
		cidrs := &ipamv1alpha1.ClusterCIDRs{
			ObjectMeta: v1.ObjectMeta{Name: "localnet"},
			Status:     ipamv1alpha1.CIDRsStatus{CIDRs: []string{"192.168.0.0/16", "172.16.0.0/12", "10.0.0.0/8"}},
		}
		k8sClient := fake.NewClientBuilder().WithScheme(extendedScheme).WithObjects(cidrs).Build()
		reconciller := controllers.IngressReconciler{Client: k8sClient}
		name := "localnet"
		namespace := "mynamespace"
		expected := []string{"192.168.0.0/16", "172.16.0.0/12", "10.0.0.0/8"}

		resolver := resolvers.ClusterCIDRResolver{reconciller.Client}

		result, err := resolver.ResolveCidrs(context.Background(), namespace, name)

		assert.NoError(t, err)
		assert.Equal(t, expected, result)
	})
}

func TestGetCidrsFromObject(t *testing.T) {
	cidrs1 := &ipamv1alpha1.CIDRs{
		ObjectMeta: v1.ObjectMeta{Name: "localnet", Namespace: "mynamespace"},
		Status:     ipamv1alpha1.CIDRsStatus{CIDRs: []string{"192.168.0.0/16", "172.16.0.0/12", "10.0.0.0/8"}},
	}
	cidrs2 := &ipamv1alpha1.CIDRs{
		ObjectMeta: v1.ObjectMeta{Name: "dnslocal", Namespace: "mynamespace"},
		Status:     ipamv1alpha1.CIDRsStatus{CIDRs: []string{"8.8.8.8/32", "1.1.1.1/32"}},
	}
	k8sClient := fake.NewClientBuilder().WithScheme(extendedScheme).WithObjects(cidrs1, cidrs2).Build()
	ingress := &netv1.Ingress{
		ObjectMeta: v1.ObjectMeta{Name: "myingress", Namespace: "mynamespace", Annotations: map[string]string{"ipam.adevinta.com/allowlist-group": "localnet, dnslocal"}},
	}
	expected := []string{"1.1.1.1/32", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "8.8.8.8/32"}

	cidrResolver := resolvers.CidrResolver{Client: k8sClient, AnnotationPrefix: resolvers.DefaultPrefix}

	ips, err := cidrResolver.GetCidrsFromObject(context.Background(), ingress)

	assert.NoError(t, err)
	assert.Equal(t, expected, ips)
}

func TestGetCidrsFromObjectNotFound(t *testing.T) {
	cidrs1 := &ipamv1alpha1.CIDRs{
		ObjectMeta: v1.ObjectMeta{Name: "localnet", Namespace: "mynamespace"},
		Status:     ipamv1alpha1.CIDRsStatus{CIDRs: []string{"192.168.0.0/16", "172.16.0.0/12", "10.0.0.0/8"}},
	}
	cidrs2 := &ipamv1alpha1.CIDRs{
		ObjectMeta: v1.ObjectMeta{Name: "dnslocal", Namespace: "mynamespace"},
		Status:     ipamv1alpha1.CIDRsStatus{CIDRs: []string{"8.8.8.8/32", "1.1.1.1/32"}},
	}
	k8sClient := fake.NewClientBuilder().WithScheme(extendedScheme).WithObjects(cidrs1, cidrs2).Build()
	ingress := &netv1.Ingress{
		ObjectMeta: v1.ObjectMeta{Name: "myingress", Namespace: "mynamespace", Annotations: map[string]string{"ipam.adevinta.com/allowlist-group": "bad"}},
	}
	expected := []string{"127.0.0.2/32"}

	cidrResolver := resolvers.CidrResolver{Client: k8sClient, AnnotationPrefix: resolvers.DefaultPrefix}

	ips, err := cidrResolver.GetCidrsFromObject(context.Background(), ingress)

	assert.NoError(t, err)
	assert.Equal(t, expected, ips)
}

func TestGetCidrsFromObjectWithCidrsAndClusterCidrs(t *testing.T) {
	cidrs1 := &ipamv1alpha1.CIDRs{
		ObjectMeta: v1.ObjectMeta{Name: "localnet", Namespace: "mynamespace"},
		Status:     ipamv1alpha1.CIDRsStatus{CIDRs: []string{"192.168.0.0/16", "172.16.0.0/12", "10.0.0.0/8"}},
	}
	cidrs2 := &ipamv1alpha1.ClusterCIDRs{
		ObjectMeta: v1.ObjectMeta{Name: "dnslocal"},
		Status:     ipamv1alpha1.CIDRsStatus{CIDRs: []string{"8.8.8.8/32", "1.1.1.1/32"}},
	}
	k8sClient := fake.NewClientBuilder().WithScheme(extendedScheme).WithObjects(cidrs1, cidrs2).Build()
	ingress := &netv1.Ingress{
		ObjectMeta: v1.ObjectMeta{Name: "myingress", Namespace: "mynamespace", Annotations: map[string]string{"ipam.adevinta.com/allowlist-group": "localnet", "ipam.adevinta.com/cluster-allowlist-group": "dnslocal"}},
	}
	expected := []string{"1.1.1.1/32", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "8.8.8.8/32"}

	cidrResolver := resolvers.CidrResolver{Client: k8sClient, AnnotationPrefix: resolvers.DefaultPrefix}

	ips, err := cidrResolver.GetCidrsFromObject(context.Background(), ingress)

	assert.NoError(t, err)
	assert.Equal(t, expected, ips)
}

// TestGetCidrsFromObjectNotFoundFallsBackToDenyAll verifies that a reference to a missing CIDRs or
// ClusterCIDRs object falls back to deny-all instead of failing the resolution (which would leave
// the object with its previous allowlist).
func TestGetCidrsFromObjectNotFoundFallsBackToDenyAll(t *testing.T) {
	defaultScheme, err := controllers.Scheme()
	assert.NoError(t, err)

	for _, annotation := range []string{"ipam.adevinta.com/allowlist-group", "ipam.adevinta.com/cluster-allowlist-group"} {
		t.Run(annotation, func(t *testing.T) {
			k8sClient := fake.NewClientBuilder().WithScheme(defaultScheme).Build()
			ingress := &netv1.Ingress{
				ObjectMeta: v1.ObjectMeta{Name: "myingress", Namespace: "mynamespace", Annotations: map[string]string{annotation: "missing"}},
			}
			cidrResolver := resolvers.CidrResolver{Client: k8sClient, AnnotationPrefix: resolvers.DefaultPrefix}

			ips, err := cidrResolver.GetCidrsFromObject(context.Background(), ingress)

			assert.NoError(t, err)
			assert.Equal(t, []string{"127.0.0.2/32"}, ips)
		})
	}
}
