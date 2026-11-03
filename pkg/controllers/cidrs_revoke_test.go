package controllers

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	ipamv1alpha1 "github.com/adevinta/ingress-allowlisting-controller/pkg/apis/ipam.adevinta.com/v1alpha1"
	"github.com/adevinta/ingress-allowlisting-controller/pkg/resolvers"
)

// reconcileInline reconciles a CIDRs object without a source, with the given inline spec.cidrs and
// status, and returns it as stored.
func reconcileInline(t *testing.T, inline []string, status ipamv1alpha1.CIDRsStatus) *ipamv1alpha1.CIDRs {
	t.Helper()
	ctx := context.Background()
	cidrs := &ipamv1alpha1.CIDRs{
		ObjectMeta: metav1.ObjectMeta{Name: "my-net", Namespace: "team-a"},
		Spec:       ipamv1alpha1.CIDRsSpec{CIDRsSource: ipamv1alpha1.CIDRsSource{CIDRs: inline}},
		Status:     status,
	}
	scheme, err := Scheme()
	require.NoError(t, err)
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(cidrs).WithStatusSubresource(cidrs).Build()
	r := &CIDRReconciler{CIDRs: &ipamv1alpha1.CIDRs{}, CIDRsList: &ipamv1alpha1.CIDRsList{}, Client: c}
	result, err := r.Reconcile(ctx, reconcile.Request{NamespacedName: client.ObjectKeyFromObject(cidrs)})
	require.NoError(t, err)
	assert.Equal(t, reconcile.Result{}, result, "inline only: nothing to retry")
	stored := &ipamv1alpha1.CIDRs{}
	require.NoError(t, c.Get(ctx, client.ObjectKeyFromObject(cidrs), stored))
	return stored
}

// TestEmptiedInlineCIDRsRevokeAccess verifies that emptying spec.cidrs of an object without a source
// revokes access: the status gets the deny-all address, instead of keeping the old list as a
// refused "removing all CIDRs" update did.
func TestEmptiedInlineCIDRsRevokeAccess(t *testing.T) {
	stored := reconcileInline(t, nil, ipamv1alpha1.CIDRsStatus{CIDRs: []string{"198.51.100.7/32", "203.0.113.0/24"}})

	assert.Equal(t, []string{resolvers.DenyAllCIDR}, stored.Status.CIDRs)
	assert.Equal(t, ipamv1alpha1.CIDRsStateReady, stored.Status.State)
	require.Len(t, stored.Status.Conditions, 1)
	assert.Equal(t, v1.ConditionTrue, stored.Status.Conditions[0].Status)
	assert.Equal(t, "spec.cidrs has no valid entry and there is no source: nothing is allowed (127.0.0.2/32)", stored.Status.Conditions[0].Message)
	assert.Empty(t, stored.Spec.CIDRsSource.CIDRs, "the spec stays as written")
}

// TestInvalidOnlyInlineCIDRsRevokeAccess verifies the same when every inline entry is invalid, e.g.
// a typo in a one-entry list: deny-all, with the invalid entries named.
func TestInvalidOnlyInlineCIDRsRevokeAccess(t *testing.T) {
	stored := reconcileInline(t, []string{"198.51.100.300"}, ipamv1alpha1.CIDRsStatus{CIDRs: []string{"198.51.100.7/32"}})

	assert.Equal(t, []string{resolvers.DenyAllCIDR}, stored.Status.CIDRs)
	require.Len(t, stored.Status.Conditions, 1)
	assert.Equal(t, `spec.cidrs has no valid entry and there is no source: nothing is allowed (127.0.0.2/32) (invalid entries in spec.cidrs ignored: "198.51.100.300")`, stored.Status.Conditions[0].Message)
}

// TestNewInlineCIDRsReplaceDenyAll verifies that the deny-all address is only a stand-in: once
// spec.cidrs has entries again, the status is just those.
func TestNewInlineCIDRsReplaceDenyAll(t *testing.T) {
	stored := reconcileInline(t, []string{"192.0.2.0/24"}, ipamv1alpha1.CIDRsStatus{CIDRs: []string{resolvers.DenyAllCIDR}})
	assert.Equal(t, []string{"192.0.2.0/24"}, stored.Status.CIDRs)
}

// TestSourceAddedToEmptyObject verifies the other way: an object created empty (deny-all) that then
// gets a source has the source's CIDRs only, not merged with the deny-all address; while the source
// gives nothing usable, it stays deny-all.
func TestSourceAddedToEmptyObject(t *testing.T) {
	denyAll := ipamv1alpha1.CIDRsStatus{CIDRs: []string{resolvers.DenyAllCIDR}}

	stored := reconcileRemote(t, `["192.0.2.0/24"]`, nil, denyAll)
	assert.Equal(t, []string{"192.0.2.0/24"}, stored.Status.CIDRs)

	stored = reconcileRemote(t, `[]`, nil, denyAll)
	assert.Equal(t, []string{resolvers.DenyAllCIDR}, stored.Status.CIDRs, "an empty feed is refused, deny-all stays")
	assert.Equal(t, ipamv1alpha1.CIDRsStateUpdateFailed, stored.Status.State)
}

// TestFetchFailureSaysInlineEditsWait verifies that a failed fetch of an object with inline entries
// says that changes to them wait for the source: the last good status is kept whole.
func TestFetchFailureSaysInlineEditsWait(t *testing.T) {
	err := errors.New("503 Service Unavailable")
	assert.Equal(t, "Failed to get CIDRs from http source: 503 Service Unavailable", fetchFailedMessage(err, false))
	assert.Contains(t, fetchFailedMessage(err, true), "spec.cidrs changes apply once the source works again")
}
