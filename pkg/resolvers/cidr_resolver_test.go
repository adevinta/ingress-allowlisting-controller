package resolvers_test

import (
	"context"
	"testing"

	ipamv1alpha1 "github.com/adevinta/ingress-allowlisting-controller/pkg/apis/ipam.adevinta.com/v1alpha1"
	ipamv1alpha1_legacy "github.com/adevinta/ingress-allowlisting-controller/pkg/apis/legacy/v1alpha1"
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
	extendedScheme, err = controllers.Scheme("legacy.ipam.com/v1alpha1")
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

		result, err := resolver.ResolveCidrs(namespace, name)

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

		result, err := resolver.ResolveCidrs(namespace, name)

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
	expected := []string{"192.168.0.0/16", "172.16.0.0/12", "10.0.0.0/8", "8.8.8.8/32", "1.1.1.1/32"}

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
	expected := []string{"192.168.0.0/16", "172.16.0.0/12", "10.0.0.0/8", "8.8.8.8/32", "1.1.1.1/32"}

	cidrResolver := resolvers.CidrResolver{Client: k8sClient, AnnotationPrefix: resolvers.DefaultPrefix}

	ips, err := cidrResolver.GetCidrsFromObject(context.Background(), ingress)

	assert.NoError(t, err)
	assert.Equal(t, expected, ips)
}

func TestGetCidrsFromMixedVersions(t *testing.T) {
	cidrs1 := &ipamv1alpha1.CIDRs{
		ObjectMeta: v1.ObjectMeta{Name: "localnet", Namespace: "mynamespace"},
		Status:     ipamv1alpha1.CIDRsStatus{CIDRs: []string{"192.168.0.0/16"}},
	}
	cidrs2 := &ipamv1alpha1_legacy.CIDRs{
		CIDRs: ipamv1alpha1.CIDRs{
			ObjectMeta: v1.ObjectMeta{Name: "legacy-localnet", Namespace: "mynamespace"},
			Status:     ipamv1alpha1.CIDRsStatus{CIDRs: []string{"172.16.0.0/12"}},
		},
	}

	cidrs3 := &ipamv1alpha1_legacy.ClusterCIDRs{
		ClusterCIDRs: ipamv1alpha1.ClusterCIDRs{
			ObjectMeta: v1.ObjectMeta{Name: "legacy-dnslocal"},
			Status:     ipamv1alpha1.CIDRsStatus{CIDRs: []string{"1.1.1.1/32"}},
		},
	}
	cidrs4 := &ipamv1alpha1.ClusterCIDRs{
		ObjectMeta: v1.ObjectMeta{Name: "dnslocal"},
		Status:     ipamv1alpha1.CIDRsStatus{CIDRs: []string{"8.8.8.8/32"}},
	}

	k8sClient := fake.NewClientBuilder().WithScheme(extendedScheme).WithObjects(cidrs1, cidrs2, cidrs3, cidrs4).Build()
	ingress := &netv1.Ingress{
		ObjectMeta: v1.ObjectMeta{Name: "myingress", Namespace: "mynamespace", Annotations: map[string]string{"ipam.adevinta.com/allowlist-group": "localnet,legacy-localnet", "ipam.adevinta.com/cluster-allowlist-group": "legacy-dnslocal,dnslocal"}},
	}
	expected := []string{"192.168.0.0/16", "172.16.0.0/12", "1.1.1.1/32", "8.8.8.8/32"}

	cidrResolver := resolvers.CidrResolver{Client: k8sClient, AnnotationPrefix: resolvers.DefaultPrefix}

	ips, err := cidrResolver.GetCidrsFromObject(context.Background(), ingress)

	assert.NoError(t, err)
	assert.ElementsMatch(t, expected, ips)
}
