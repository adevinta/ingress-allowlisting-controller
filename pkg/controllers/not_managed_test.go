package controllers

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	istiosecurityv1 "istio.io/client-go/pkg/apis/security/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	gatewayApiv1 "sigs.k8s.io/gateway-api/apis/v1"

	ipamv1alpha1 "github.com/adevinta/ingress-allowlisting-controller/pkg/apis/ipam.adevinta.com/v1alpha1"
)

// TestGatewayWithOthersPolicyGetsAWarningNotARetry verifies that when the policy a Gateway needs
// already exists and isn't ours, the reconcile leaves it alone, records a Warning Event on the
// Gateway and returns no error: a retry can't fix the conflict, so it isn't retried endlessly.
func TestGatewayWithOthersPolicyGetsAWarningNotARetry(t *testing.T) {
	ctx := context.Background()
	cidrs := &ipamv1alpha1.CIDRs{
		ObjectMeta: metav1.ObjectMeta{Name: "localnet", Namespace: "ns"},
		Status:     ipamv1alpha1.CIDRsStatus{CIDRs: []string{"10.0.0.0/8"}},
	}
	gateway := &gatewayApiv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "my-gw", Annotations: map[string]string{"ipam.adevinta.com/allowlist-group": "localnet"}},
		Spec:       gatewayApiv1.GatewaySpec{GatewayClassName: "istio"},
	}
	theirs := &istiosecurityv1.AuthorizationPolicy{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "my-gw", Labels: map[string]string{
		"app.kubernetes.io/managed-by": "ingress-allowlisting-controller",
		"other.example.com/owner-name": "my-gw",
	}}}
	c := fake.NewClientBuilder().WithScheme(extendedScheme).WithObjects(cidrs, newGatewayClass("istio"), gateway, theirs).Build()
	r := newGatewayReconciler(t, c, extendedScheme)

	result, err := r.Reconcile(ctx, reconcile.Request{NamespacedName: client.ObjectKeyFromObject(gateway)})
	require.NoError(t, err)
	assert.Equal(t, reconcile.Result{}, result, "no requeue")

	got := &istiosecurityv1.AuthorizationPolicy{}
	require.NoError(t, c.Get(ctx, client.ObjectKeyFromObject(theirs), got))
	assert.Equal(t, theirs.Labels, got.Labels, "left as it is")
	assert.Empty(t, got.OwnerReferences)

	events := recordedEvents(t, r.CidrResolver)
	require.Len(t, events, 1)
	assert.Contains(t, events[0], "Warning AllowlistPolicyConflict")
	assert.Contains(t, events[0], "AuthorizationPolicy ns/my-gw already exists and doesn't belong to Gateway my-gw")
}
