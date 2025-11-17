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
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func newNetworkPolicyReconciler(t *testing.T, k8sClient client.Client) *NetworkPolicyReconciler {
	t.Helper()
	resolver := resolvers.CidrResolver{Client: k8sClient, AnnotationPrefix: resolvers.DefaultPrefix}
	return &NetworkPolicyReconciler{Client: k8sClient, CidrResolver: resolver}
}

func TestReconcileNetworkPolicy(t *testing.T) {
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
	networkPolicy := &netv1.NetworkPolicy{
		ObjectMeta: v1.ObjectMeta{
			Name:      "test-policy",
			Namespace: "mynamespace",
			Annotations: map[string]string{
				"ipam.adevinta.com/cluster-allowlist-group": "globalnet",
				"ipam.adevinta.com/allowlist-group":         "localnet,dnssource",
			},
		},
		Spec: netv1.NetworkPolicySpec{
			PolicyTypes: []netv1.PolicyType{netv1.PolicyTypeEgress},
		},
	}

	k8sClient := fake.NewClientBuilder().WithScheme(extendedScheme).WithObjects(localnetCidrs, dnssourceCidrs, globalCidrs, networkPolicy).Build()
	reconciler := newNetworkPolicyReconciler(t, k8sClient)

	result, err := reconciler.reconcileNetworkPolicy(context.Background(), *networkPolicy)

	assert.NoError(t, err)
	assert.NotNil(t, result.Spec.Egress)
	assert.Len(t, result.Spec.Egress, 1)
	assert.Len(t, result.Spec.Egress[0].To, 6) // 3 from localnet + 2 from dnssource + 1 from globalnet

	// Verify CIDRs are present in egress rules
	cidrsFound := extractCIDRs(result.Spec.Egress)
	assert.True(t, cidrsFound["192.168.0.0/16"])
	assert.True(t, cidrsFound["172.16.0.0/12"])
	assert.True(t, cidrsFound["10.0.0.0/8"])
	assert.True(t, cidrsFound["1.1.1.1/32"])
	assert.True(t, cidrsFound["8.8.8.8/32"])
	assert.True(t, cidrsFound["15.13.12.0/24"])
}

func TestReconcileNetworkPolicyWithClusterCIDR(t *testing.T) {
	globalNet := &ipamv1alpha1.ClusterCIDRs{
		ObjectMeta: v1.ObjectMeta{Name: "globalnet"},
		Status:     ipamv1alpha1.CIDRsStatus{CIDRs: []string{"192.168.0.0/16", "172.16.0.0/12", "10.0.0.0/8"}},
	}
	anotherGlobalNet := &ipamv1alpha1.ClusterCIDRs{
		ObjectMeta: v1.ObjectMeta{Name: "anotherglobalnet"},
		Status:     ipamv1alpha1.CIDRsStatus{CIDRs: []string{"15.13.12.0/24"}},
	}
	networkPolicy := &netv1.NetworkPolicy{
		ObjectMeta: v1.ObjectMeta{
			Name:      "test-policy",
			Namespace: "mynamespace",
			Annotations: map[string]string{
				"ipam.adevinta.com/cluster-allowlist-group": "globalnet,anotherglobalnet",
			},
		},
		Spec: netv1.NetworkPolicySpec{
			PolicyTypes: []netv1.PolicyType{netv1.PolicyTypeEgress},
		},
	}

	k8sClient := fake.NewClientBuilder().WithScheme(extendedScheme).WithObjects(globalNet, anotherGlobalNet, networkPolicy).Build()
	reconciler := newNetworkPolicyReconciler(t, k8sClient)

	result, err := reconciler.reconcileNetworkPolicy(context.Background(), *networkPolicy)

	assert.NoError(t, err)
	assert.NotNil(t, result.Spec.Egress)
	assert.Len(t, result.Spec.Egress, 1)
	assert.Len(t, result.Spec.Egress[0].To, 4)

	cidrsFound := extractCIDRs(result.Spec.Egress)
	assert.True(t, cidrsFound["192.168.0.0/16"])
	assert.True(t, cidrsFound["172.16.0.0/12"])
	assert.True(t, cidrsFound["10.0.0.0/8"])
	assert.True(t, cidrsFound["15.13.12.0/24"])
}

func TestReconcileNetworkPolicyIngressType(t *testing.T) {
	localnetCidrs := &ipamv1alpha1.CIDRs{
		ObjectMeta: v1.ObjectMeta{Name: "localnet", Namespace: "mynamespace"},
		Status:     ipamv1alpha1.CIDRsStatus{CIDRs: []string{"192.168.0.0/16", "172.16.0.0/12"}},
	}
	networkPolicy := &netv1.NetworkPolicy{
		ObjectMeta: v1.ObjectMeta{
			Name:      "test-policy",
			Namespace: "mynamespace",
			Annotations: map[string]string{
				"ipam.adevinta.com/allowlist-group": "localnet",
			},
		},
		Spec: netv1.NetworkPolicySpec{
			PolicyTypes: []netv1.PolicyType{netv1.PolicyTypeIngress},
		},
	}

	k8sClient := fake.NewClientBuilder().WithScheme(extendedScheme).WithObjects(localnetCidrs, networkPolicy).Build()
	reconciler := newNetworkPolicyReconciler(t, k8sClient)

	result, err := reconciler.reconcileNetworkPolicy(context.Background(), *networkPolicy)

	assert.NoError(t, err)
	assert.NotNil(t, result.Spec.Ingress)
	assert.Len(t, result.Spec.Ingress, 1)
	assert.Len(t, result.Spec.Ingress[0].From, 2)
	assert.Nil(t, result.Spec.Egress)

	cidrsFound := extractCIDRs(result.Spec.Ingress)
	assert.True(t, cidrsFound["192.168.0.0/16"])
	assert.True(t, cidrsFound["172.16.0.0/12"])
}

func TestReconcileNetworkPolicyBothIngressAndEgress(t *testing.T) {
	localnetCidrs := &ipamv1alpha1.CIDRs{
		ObjectMeta: v1.ObjectMeta{Name: "localnet", Namespace: "mynamespace"},
		Status:     ipamv1alpha1.CIDRsStatus{CIDRs: []string{"192.168.0.0/16"}},
	}
	networkPolicy := &netv1.NetworkPolicy{
		ObjectMeta: v1.ObjectMeta{
			Name:      "test-policy",
			Namespace: "mynamespace",
			Annotations: map[string]string{
				"ipam.adevinta.com/allowlist-group": "localnet",
			},
		},
		Spec: netv1.NetworkPolicySpec{
			PolicyTypes: []netv1.PolicyType{netv1.PolicyTypeIngress, netv1.PolicyTypeEgress},
		},
	}

	k8sClient := fake.NewClientBuilder().WithScheme(extendedScheme).WithObjects(localnetCidrs, networkPolicy).Build()
	reconciler := newNetworkPolicyReconciler(t, k8sClient)

	result, err := reconciler.reconcileNetworkPolicy(context.Background(), *networkPolicy)

	assert.NoError(t, err)
	assert.NotNil(t, result.Spec.Ingress)
	assert.Len(t, result.Spec.Ingress, 1)
	assert.Len(t, result.Spec.Ingress[0].From, 1)
	assert.NotNil(t, result.Spec.Egress)
	assert.Len(t, result.Spec.Egress, 1)
	assert.Len(t, result.Spec.Egress[0].To, 1)

	assert.Equal(t, "192.168.0.0/16", result.Spec.Ingress[0].From[0].IPBlock.CIDR)
	assert.Equal(t, "192.168.0.0/16", result.Spec.Egress[0].To[0].IPBlock.CIDR)
}

func TestReconcileNetworkPolicyDefaultPolicyType(t *testing.T) {
	localnetCidrs := &ipamv1alpha1.CIDRs{
		ObjectMeta: v1.ObjectMeta{Name: "localnet", Namespace: "mynamespace"},
		Status:     ipamv1alpha1.CIDRsStatus{CIDRs: []string{"192.168.0.0/16"}},
	}
	networkPolicy := &netv1.NetworkPolicy{
		ObjectMeta: v1.ObjectMeta{
			Name:      "test-policy",
			Namespace: "mynamespace",
			Annotations: map[string]string{
				"ipam.adevinta.com/allowlist-group": "localnet",
			},
		},
		Spec: netv1.NetworkPolicySpec{
			// No PolicyTypes specified - should default to Egress
		},
	}

	k8sClient := fake.NewClientBuilder().WithScheme(extendedScheme).WithObjects(localnetCidrs, networkPolicy).Build()
	reconciler := newNetworkPolicyReconciler(t, k8sClient)

	result, err := reconciler.reconcileNetworkPolicy(context.Background(), *networkPolicy)

	assert.NoError(t, err)
	assert.Equal(t, []netv1.PolicyType{netv1.PolicyTypeEgress}, result.Spec.PolicyTypes)
	assert.NotNil(t, result.Spec.Egress)
	assert.Len(t, result.Spec.Egress, 1)
	assert.Nil(t, result.Spec.Ingress)
}

func TestReconcileNetworkPolicyNoAnnotations(t *testing.T) {
	networkPolicy := &netv1.NetworkPolicy{
		ObjectMeta: v1.ObjectMeta{
			Name:        "test-policy",
			Namespace:   "mynamespace",
			Annotations: map[string]string{},
		},
		Spec: netv1.NetworkPolicySpec{
			PolicyTypes: []netv1.PolicyType{netv1.PolicyTypeEgress},
		},
	}

	k8sClient := fake.NewClientBuilder().WithScheme(extendedScheme).WithObjects(networkPolicy).Build()
	reconciler := newNetworkPolicyReconciler(t, k8sClient)

	_, err := reconciler.reconcileNetworkPolicy(context.Background(), *networkPolicy)
	assert.Equal(t, reconciler.CidrResolver.AnnotationNotFoundError(), err)
}

func TestReconcileNetworkPolicyPartialNotFound(t *testing.T) {
	localnetCidrs := &ipamv1alpha1.CIDRs{
		ObjectMeta: v1.ObjectMeta{Name: "localnet", Namespace: "mynamespace"},
		Status:     ipamv1alpha1.CIDRsStatus{CIDRs: []string{"192.168.0.0/16", "172.16.0.0/12", "10.0.0.0/8"}},
	}

	networkPolicy := &netv1.NetworkPolicy{
		ObjectMeta: v1.ObjectMeta{
			Name:      "test-policy",
			Namespace: "mynamespace",
			Annotations: map[string]string{
				"ipam.adevinta.com/allowlist-group": "localnet,notexisting",
			},
		},
		Spec: netv1.NetworkPolicySpec{
			PolicyTypes: []netv1.PolicyType{netv1.PolicyTypeEgress},
		},
	}

	k8sClient := fake.NewClientBuilder().WithScheme(extendedScheme).WithObjects(localnetCidrs, networkPolicy).Build()
	reconciler := newNetworkPolicyReconciler(t, k8sClient)

	result, err := reconciler.reconcileNetworkPolicy(context.Background(), *networkPolicy)

	assert.NoError(t, err)
	assert.NotNil(t, result.Spec.Egress)
	assert.Len(t, result.Spec.Egress, 1)
	assert.Len(t, result.Spec.Egress[0].To, 3) // Only the found CIDRs

	cidrsFound := extractCIDRs(result.Spec.Egress)
	assert.True(t, cidrsFound["192.168.0.0/16"])
	assert.True(t, cidrsFound["172.16.0.0/12"])
	assert.True(t, cidrsFound["10.0.0.0/8"])
}

func TestReconcileNetworkPolicyWithInvalidCIDRIpsNoError(t *testing.T) {
	localnetCidrs := &ipamv1alpha1.CIDRs{
		ObjectMeta: v1.ObjectMeta{Name: "localnet", Namespace: "mynamespace"},
		Status:     ipamv1alpha1.CIDRsStatus{CIDRs: []string{"192.168.0/16", "172.16.0.0/12", "10.0.0.0/8", "10.0.0.0"}},
	}
	dnssourceCidrs := &ipamv1alpha1.CIDRs{
		ObjectMeta: v1.ObjectMeta{Name: "dnssource", Namespace: "mynamespace"},
		Status:     ipamv1alpha1.CIDRsStatus{CIDRs: []string{"1.1.1.1/32", "8.8.8.8/32"}},
	}
	networkPolicy := &netv1.NetworkPolicy{
		ObjectMeta: v1.ObjectMeta{
			Name:      "test-policy",
			Namespace: "mynamespace",
			Annotations: map[string]string{
				"ipam.adevinta.com/allowlist-group": "localnet,dnssource",
			},
		},
		Spec: netv1.NetworkPolicySpec{
			PolicyTypes: []netv1.PolicyType{netv1.PolicyTypeEgress},
		},
	}

	k8sClient := fake.NewClientBuilder().WithScheme(extendedScheme).WithObjects(localnetCidrs, dnssourceCidrs, networkPolicy).Build()
	reconciler := newNetworkPolicyReconciler(t, k8sClient)

	result, err := reconciler.reconcileNetworkPolicy(context.Background(), *networkPolicy)

	assert.NoError(t, err)
	assert.NotNil(t, result.Spec.Egress)
	// Should only include valid CIDRs
	assert.Len(t, result.Spec.Egress[0].To, 4)

	cidrsFound := extractCIDRs(result.Spec.Egress)
	assert.True(t, cidrsFound["172.16.0.0/12"])
	assert.True(t, cidrsFound["10.0.0.0/8"])
	assert.True(t, cidrsFound["1.1.1.1/32"])
	assert.True(t, cidrsFound["8.8.8.8/32"])
	assert.False(t, cidrsFound["192.168.0/16"])
	assert.False(t, cidrsFound["10.0.0.0"])
}

func TestReconcileNetworkPolicyAllCIDRsNotFound(t *testing.T) {
	t.Run("Namespace CIDR not found", func(t *testing.T) {
		networkPolicy := &netv1.NetworkPolicy{
			ObjectMeta: v1.ObjectMeta{
				Name:      "test-policy",
				Namespace: "mynamespace",
				Annotations: map[string]string{
					"ipam.adevinta.com/allowlist-group": "notexisting,alsonotexisting",
				},
			},
			Spec: netv1.NetworkPolicySpec{
				PolicyTypes: []netv1.PolicyType{netv1.PolicyTypeEgress},
			},
		}

		k8sClient := fake.NewClientBuilder().WithScheme(extendedScheme).WithObjects(networkPolicy).Build()
		reconciler := newNetworkPolicyReconciler(t, k8sClient)

		result, err := reconciler.reconcileNetworkPolicy(context.Background(), *networkPolicy)

		assert.NoError(t, err)
		assert.NotNil(t, result.Spec.Egress)

		// Should only include falback CIDR
		assert.Equal(t, "127.0.0.2/32", result.Spec.Egress[0].To[0].IPBlock.CIDR)
	})

	t.Run("Cluster CIDR not found", func(t *testing.T) {
		networkPolicy := &netv1.NetworkPolicy{
			ObjectMeta: v1.ObjectMeta{
				Name:      "test-policy",
				Namespace: "mynamespace",
				Annotations: map[string]string{
					"ipam.adevinta.com/cluster-allowlist-group": "notexisting,alsonotexisting",
				},
			},
			Spec: netv1.NetworkPolicySpec{
				PolicyTypes: []netv1.PolicyType{netv1.PolicyTypeEgress},
			},
		}

		k8sClient := fake.NewClientBuilder().WithScheme(extendedScheme).WithObjects(networkPolicy).Build()
		reconciler := newNetworkPolicyReconciler(t, k8sClient)

		result, err := reconciler.reconcileNetworkPolicy(context.Background(), *networkPolicy)

		assert.NoError(t, err)
		assert.NotNil(t, result.Spec.Egress)

		// Should only include falback CIDR
		assert.Equal(t, "127.0.0.2/32", result.Spec.Egress[0].To[0].IPBlock.CIDR)
	})
}

func TestReconcileNetworkPolicyOverwriteExistingRules(t *testing.T) {
	localnetCidrs := &ipamv1alpha1.CIDRs{
		ObjectMeta: v1.ObjectMeta{Name: "localnet", Namespace: "mynamespace"},
		Status:     ipamv1alpha1.CIDRsStatus{CIDRs: []string{"192.168.0.0/16", "172.16.0.0/12"}},
	}

	existingPeer := netv1.NetworkPolicyPeer{
		IPBlock: &netv1.IPBlock{CIDR: "1.1.1.1/32"},
	}

	networkPolicy := &netv1.NetworkPolicy{
		ObjectMeta: v1.ObjectMeta{
			Name:      "test-policy",
			Namespace: "mynamespace",
			Annotations: map[string]string{
				"ipam.adevinta.com/allowlist-group": "localnet",
			},
		},
		Spec: netv1.NetworkPolicySpec{
			PolicyTypes: []netv1.PolicyType{netv1.PolicyTypeEgress},
			Egress: []netv1.NetworkPolicyEgressRule{
				{To: []netv1.NetworkPolicyPeer{existingPeer}},
			},
		},
	}

	k8sClient := fake.NewClientBuilder().WithScheme(extendedScheme).WithObjects(localnetCidrs, networkPolicy).Build()
	reconciler := newNetworkPolicyReconciler(t, k8sClient)

	result, err := reconciler.reconcileNetworkPolicy(context.Background(), *networkPolicy)

	assert.NoError(t, err)
	assert.NotNil(t, result.Spec.Egress)
	assert.Len(t, result.Spec.Egress, 1)
	assert.Len(t, result.Spec.Egress[0].To, 2)

	// Verify existing rules were overwritten
	cidrsFound := extractCIDRs(result.Spec.Egress)
	assert.True(t, cidrsFound["192.168.0.0/16"])
	assert.True(t, cidrsFound["172.16.0.0/12"])
	assert.False(t, cidrsFound["1.1.1.1/32"]) // Old rule should be gone
}

func TestReconcileNetworkPolicyOverwriteExistingRulesWithPort(t *testing.T) {

	port := intstr.FromInt(443)
	proto := corev1.ProtocolTCP

	localnetCidrs := &ipamv1alpha1.CIDRs{
		ObjectMeta: v1.ObjectMeta{Name: "localnet", Namespace: "mynamespace"},
		Status:     ipamv1alpha1.CIDRsStatus{CIDRs: []string{"192.168.0.0/16", "172.16.0.0/12"}},
	}

	existingPeer := netv1.NetworkPolicyPeer{
		IPBlock: &netv1.IPBlock{CIDR: "1.1.1.1/32"},
	}

	networkPolicy := &netv1.NetworkPolicy{
		ObjectMeta: v1.ObjectMeta{
			Name:      "test-policy",
			Namespace: "mynamespace",
			Annotations: map[string]string{
				"ipam.adevinta.com/allowlist-group": "localnet",
			},
		},
		Spec: netv1.NetworkPolicySpec{
			PolicyTypes: []netv1.PolicyType{netv1.PolicyTypeEgress},
			Egress: []netv1.NetworkPolicyEgressRule{
				{
					To: []netv1.NetworkPolicyPeer{existingPeer},
					Ports: []netv1.NetworkPolicyPort{
						{
							Protocol: &proto,
							Port:     &port,
						},
					},
				},
			},
		},
	}

	k8sClient := fake.NewClientBuilder().WithScheme(extendedScheme).WithObjects(localnetCidrs, networkPolicy).Build()
	reconciler := newNetworkPolicyReconciler(t, k8sClient)

	result, err := reconciler.reconcileNetworkPolicy(context.Background(), *networkPolicy)

	assert.NoError(t, err)
	assert.NotNil(t, result.Spec.Egress)
	assert.Len(t, result.Spec.Egress, 1)
	assert.Len(t, result.Spec.Egress[0].To, 2)

	// Verify existing rules were overwritten
	cidrsFound := extractCIDRs(result.Spec.Egress)
	assert.True(t, cidrsFound["192.168.0.0/16"])
	assert.True(t, cidrsFound["172.16.0.0/12"])
	assert.False(t, cidrsFound["1.1.1.1/32"]) // Old rule should be gone

	assert.NotNil(t, result.Spec.Egress[0].Ports)
	assert.NotNil(t, result.Spec.Egress[0].Ports[0].Port)

	portVal := result.Spec.Egress[0].Ports[0].Port
	portProto := result.Spec.Egress[0].Ports[0].Protocol
	assert.Equal(t, intstr.Int, portVal.Type)
	assert.Equal(t, 443, int(portVal.IntVal))
	assert.Equal(t, "TCP", string(*portProto))

}

func TestReconcileNetworkPolicyOverwriteExistingRulesWithPortsBadSpec(t *testing.T) {

	port := intstr.FromInt(443)
	proto := corev1.ProtocolTCP

	localnetCidrs := &ipamv1alpha1.CIDRs{
		ObjectMeta: v1.ObjectMeta{Name: "localnet", Namespace: "mynamespace"},
		Status:     ipamv1alpha1.CIDRsStatus{CIDRs: []string{"192.168.0.0/16", "172.16.0.0/12"}},
	}

	existingPeer := netv1.NetworkPolicyPeer{
		IPBlock: &netv1.IPBlock{CIDR: "1.1.1.1/32"},
	}

	networkPolicy := &netv1.NetworkPolicy{
		ObjectMeta: v1.ObjectMeta{
			Name:      "test-policy",
			Namespace: "mynamespace",
			Annotations: map[string]string{
				"ipam.adevinta.com/allowlist-group": "localnet",
			},
		},
		Spec: netv1.NetworkPolicySpec{
			PolicyTypes: []netv1.PolicyType{netv1.PolicyTypeEgress},
			Egress: []netv1.NetworkPolicyEgressRule{
				{
					To: []netv1.NetworkPolicyPeer{existingPeer},
					Ports: []netv1.NetworkPolicyPort{
						{
							Protocol: &proto,
							Port:     &port,
						},
					},
				},
				{
					To: []netv1.NetworkPolicyPeer{existingPeer},
					Ports: []netv1.NetworkPolicyPort{
						{
							Protocol: &proto,
							Port:     &port,
						},
					},
				},
			},
		},
	}

	k8sClient := fake.NewClientBuilder().WithScheme(extendedScheme).WithObjects(localnetCidrs, networkPolicy).Build()
	reconciler := newNetworkPolicyReconciler(t, k8sClient)

	_, err := reconciler.reconcileNetworkPolicy(context.Background(), *networkPolicy)

	assert.Error(t, err)

}

func TestReconcileNetworkPolicyApiError(t *testing.T) {
	k8sClient := &testfunc{WithWatch: fake.NewClientBuilder().WithScheme(extendedScheme).Build()}
	k8sClient.getfunc = func(ctx context.Context, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
		return errors.New("error that is not a NOTFOUND")
	}

	networkPolicy := &netv1.NetworkPolicy{
		ObjectMeta: v1.ObjectMeta{
			Name:      "test-policy",
			Namespace: "mynamespace",
			Annotations: map[string]string{
				"ipam.adevinta.com/allowlist-group": "notexisting",
			},
		},
		Spec: netv1.NetworkPolicySpec{
			PolicyTypes: []netv1.PolicyType{netv1.PolicyTypeEgress},
		},
	}

	reconciler := newNetworkPolicyReconciler(t, k8sClient)

	_, err := reconciler.reconcileNetworkPolicy(context.Background(), *networkPolicy)

	assert.Error(t, err)
}

func TestReconcileNetworkPolicyInvalidAnnotationFormat(t *testing.T) {
	localnetCidrs := &ipamv1alpha1.CIDRs{
		ObjectMeta: v1.ObjectMeta{Name: "localnet", Namespace: "mynamespace"},
		Status:     ipamv1alpha1.CIDRsStatus{CIDRs: []string{"192.168.0.0/16", "172.16.0.0/12"}},
	}
	dnssourceCidrs := &ipamv1alpha1.CIDRs{
		ObjectMeta: v1.ObjectMeta{Name: "dnssource", Namespace: "mynamespace"},
		Status:     ipamv1alpha1.CIDRsStatus{CIDRs: []string{"1.1.1.1/32"}},
	}
	networkPolicy := &netv1.NetworkPolicy{
		ObjectMeta: v1.ObjectMeta{
			Name:      "test-policy",
			Namespace: "mynamespace",
			Annotations: map[string]string{
				"ipam.adevinta.com/allowlist-group": "localnet, dnssource", // Space after comma
			},
		},
		Spec: netv1.NetworkPolicySpec{
			PolicyTypes: []netv1.PolicyType{netv1.PolicyTypeEgress},
		},
	}

	k8sClient := fake.NewClientBuilder().WithScheme(extendedScheme).WithObjects(localnetCidrs, dnssourceCidrs, networkPolicy).Build()
	reconciler := newNetworkPolicyReconciler(t, k8sClient)

	result, err := reconciler.reconcileNetworkPolicy(context.Background(), *networkPolicy)

	// Should handle spaces gracefully
	assert.NoError(t, err)
	assert.NotNil(t, result.Spec.Egress)
	assert.Len(t, result.Spec.Egress[0].To, 3)

	cidrsFound := extractCIDRs(result.Spec.Egress)
	assert.True(t, cidrsFound["192.168.0.0/16"])
	assert.True(t, cidrsFound["172.16.0.0/12"])
	assert.True(t, cidrsFound["1.1.1.1/32"])
}

func TestNetworkPolicyToNetworkPoliciesMapper(t *testing.T) {
	t.Run("CIDR is being used in the NetworkPolicy, should return the NetworkPolicy", func(t *testing.T) {
		networkPolicy := &netv1.NetworkPolicy{
			ObjectMeta: v1.ObjectMeta{
				Name:      "test",
				Namespace: "mynamespace",
				Annotations: map[string]string{
					"ipam.adevinta.com/allowlist-group": "localnet,dnssource",
				},
			},
		}
		k8sClient := fake.NewClientBuilder().WithScheme(extendedScheme).WithObjects(networkPolicy).Build()
		cidr := ipamv1alpha1.CIDRs{
			ObjectMeta: v1.ObjectMeta{Name: "localnet", Namespace: "mynamespace"},
		}
		requests := newNetworkPoliciesFromCIDRFuncMap(k8sClient, "ipam.adevinta.com/allowlist-group")(context.Background(), &cidr)
		assert.Len(t, requests, 1)
		assert.Equal(t, requests[0].Name, "test")
	})

	t.Run("CIDR is not being used in the NetworkPolicy, should return an empty list", func(t *testing.T) {
		networkPolicy := &netv1.NetworkPolicy{
			ObjectMeta: v1.ObjectMeta{
				Name:      "test",
				Namespace: "mynamespace",
				Annotations: map[string]string{
					"ipam.adevinta.com/allowlist-group": "dnssource",
				},
			},
		}
		k8sClient := fake.NewClientBuilder().WithScheme(extendedScheme).WithObjects(networkPolicy).Build()
		cidr := ipamv1alpha1.CIDRs{
			ObjectMeta: v1.ObjectMeta{Name: "localnet", Namespace: "mynamespace"},
		}
		requests := newNetworkPoliciesFromCIDRFuncMap(k8sClient, "ipam.adevinta.com/allowlist-group")(context.Background(), &cidr)
		assert.Len(t, requests, 0)
	})

	t.Run("One CIDR is being used in the NetworkPolicy, should return just that one", func(t *testing.T) {
		networkPolicy1 := &netv1.NetworkPolicy{
			ObjectMeta: v1.ObjectMeta{Name: "test", Namespace: "mynamespace"},
		}
		networkPolicy2 := &netv1.NetworkPolicy{
			ObjectMeta: v1.ObjectMeta{
				Name:      "test2",
				Namespace: "mynamespace",
				Annotations: map[string]string{
					"ipam.adevinta.com/allowlist-group": "dnssource",
				},
			},
		}
		k8sClient := fake.NewClientBuilder().WithScheme(extendedScheme).WithObjects(networkPolicy1, networkPolicy2).Build()
		cidr := ipamv1alpha1.CIDRs{
			ObjectMeta: v1.ObjectMeta{Name: "dnssource", Namespace: "mynamespace"},
		}
		requests := newNetworkPoliciesFromCIDRFuncMap(k8sClient, "ipam.adevinta.com/allowlist-group")(context.Background(), &cidr)
		assert.Len(t, requests, 1)
		assert.Equal(t, requests[0].Name, "test2")
	})
}

func TestClusterCidrToNetworkPoliciesMapper(t *testing.T) {
	t.Run("ClusterCIDR is being used in the NetworkPolicy, should return the NetworkPolicy", func(t *testing.T) {
		networkPolicy := &netv1.NetworkPolicy{
			ObjectMeta: v1.ObjectMeta{
				Name:      "test",
				Namespace: "mynamespace",
				Annotations: map[string]string{
					"ipam.adevinta.com/cluster-allowlist-group": "localnet,dnssource",
				},
			},
		}
		k8sClient := fake.NewClientBuilder().WithScheme(extendedScheme).WithObjects(networkPolicy).Build()
		cidr := ipamv1alpha1.ClusterCIDRs{
			ObjectMeta: v1.ObjectMeta{Name: "localnet"},
		}
		cidrResolver := resolvers.CidrResolver{Client: k8sClient, AnnotationPrefix: resolvers.DefaultPrefix}
		requests := newNetworkPoliciesFromCIDRFuncMap(k8sClient, cidrResolver.ClusterAnnotation())(context.Background(), &cidr)
		assert.Len(t, requests, 1)
		assert.Equal(t, requests[0].Name, "test")
	})

	t.Run("ClusterCIDR is not being used in the NetworkPolicy, should return an empty list", func(t *testing.T) {
		networkPolicy := &netv1.NetworkPolicy{
			ObjectMeta: v1.ObjectMeta{
				Name:      "test",
				Namespace: "mynamespace",
				Annotations: map[string]string{
					"ipam.adevinta.com/cluster-allowlist-group": "dnssource",
				},
			},
		}
		k8sClient := fake.NewClientBuilder().WithScheme(extendedScheme).WithObjects(networkPolicy).Build()
		cidr := ipamv1alpha1.ClusterCIDRs{
			ObjectMeta: v1.ObjectMeta{Name: "localnet", Namespace: "mynamespace"},
		}
		cidrResolver := resolvers.CidrResolver{Client: k8sClient, AnnotationPrefix: resolvers.DefaultPrefix}
		requests := newNetworkPoliciesFromCIDRFuncMap(k8sClient, cidrResolver.ClusterAnnotation())(context.Background(), &cidr)
		assert.Len(t, requests, 0)
	})

	t.Run("Multiple NetworkPolicies use the same ClusterCIDR", func(t *testing.T) {
		networkPolicy1 := &netv1.NetworkPolicy{
			ObjectMeta: v1.ObjectMeta{
				Name:      "test1",
				Namespace: "namespace1",
				Annotations: map[string]string{
					"ipam.adevinta.com/cluster-allowlist-group": "globalnet",
				},
			},
		}
		networkPolicy2 := &netv1.NetworkPolicy{
			ObjectMeta: v1.ObjectMeta{
				Name:      "test2",
				Namespace: "namespace1",
				Annotations: map[string]string{
					"ipam.adevinta.com/cluster-allowlist-group": "globalnet,other",
				},
			},
		}
		k8sClient := fake.NewClientBuilder().WithScheme(extendedScheme).WithObjects(networkPolicy1, networkPolicy2).Build()
		cidr := ipamv1alpha1.ClusterCIDRs{
			ObjectMeta: v1.ObjectMeta{Name: "globalnet"},
		}
		cidrResolver := resolvers.CidrResolver{Client: k8sClient, AnnotationPrefix: resolvers.DefaultPrefix}
		requests := newNetworkPoliciesFromCIDRFuncMap(k8sClient, cidrResolver.ClusterAnnotation())(context.Background(), &cidr)
		assert.Len(t, requests, 2)

		names := make(map[string]bool)
		for _, req := range requests {
			names[req.Name] = true
		}
		assert.True(t, names["test1"])
		assert.True(t, names["test2"])
	})
}
