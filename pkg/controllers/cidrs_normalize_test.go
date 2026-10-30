package controllers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	ipamv1alpha1 "github.com/adevinta/ingress-allowlisting-controller/pkg/apis/ipam.adevinta.com/v1alpha1"
)

func TestNormalizeCIDR(t *testing.T) {
	cases := []struct {
		in   string
		want string
		ok   bool
	}{
		{"10.0.0.0/8", "10.0.0.0/8", true},
		{"10.0.0.5/8", "10.0.0.5/8", true}, // kept as written, not turned into its network
		{"1.2.3.4", "1.2.3.4/32", true},
		{" 1.2.3.4 ", "1.2.3.4/32", true},
		{"2001:db8::/32", "2001:db8::/32", true},
		{"2001:db8::1", "2001:db8::1/128", true},
		{"1.2.3x4", "", false}, // the old ipv4RegExp accepted this as 1.2.3x4/32
		{"999.1.1.1", "", false},
		{"10.0.0.0/33", "", false},
		{"Bearer secret-token", "", false},
		{"", "", false},
	}
	for _, tc := range cases {
		got, ok := normalizeCIDR(tc.in)
		assert.Equal(t, tc.ok, ok, tc.in)
		assert.Equal(t, tc.want, got, tc.in)
	}
}

// reconcileRemote reconciles a CIDRs object whose remote source answers with body, starting from
// the given status, and returns the stored object.
func reconcileRemote(t *testing.T, body string, inline []string, status ipamv1alpha1.CIDRsStatus) *ipamv1alpha1.CIDRs {
	t.Helper()
	ctx := context.Background()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(server.Close)

	cidrs := &ipamv1alpha1.CIDRs{
		ObjectMeta: metav1.ObjectMeta{Name: "my-net", Namespace: "team-a"},
		Spec: ipamv1alpha1.CIDRsSpec{CIDRsSource: ipamv1alpha1.CIDRsSource{
			CIDRs:    inline,
			Location: ipamv1alpha1.CIDRsLocation{URI: server.URL},
		}},
		Status: status,
	}
	scheme, err := Scheme()
	require.NoError(t, err)
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(cidrs).WithStatusSubresource(cidrs).Build()
	reconciler := &CIDRReconciler{
		SourceOptions: CIDRSourceOptions{AllowPrivateDestinations: true}, // the test server is on 127.0.0.1
		CIDRs:         &ipamv1alpha1.CIDRs{},
		CIDRsList:     &ipamv1alpha1.CIDRsList{},
		Client:        fakeClient,
	}
	_, err = reconciler.Reconcile(ctx, reconcile.Request{NamespacedName: client.ObjectKeyFromObject(cidrs)})
	require.NoError(t, err)
	stored := &ipamv1alpha1.CIDRs{}
	require.NoError(t, fakeClient.Get(ctx, client.ObjectKeyFromObject(cidrs), stored))
	return stored
}

// TestCIDRsReconcileRemoteKeepsOnlyCIDRs verifies that only CIDRs and IPs from a remote source
// reach status.cidrs, and that the condition reports how many entries were dropped without
// showing them.
func TestCIDRsReconcileRemoteKeepsOnlyCIDRs(t *testing.T) {
	// A non-string element (the map) is skipped by the processor itself, so only the two strings
	// count as dropped.
	stored := reconcileRemote(t,
		`["10.0.0.1/24", "1.2.3.4", "2001:db8::1", "2001:db8::/32", "Bearer secret-token", "1.2.3x4", {"token": "s3cr3t"}]`,
		nil, ipamv1alpha1.CIDRsStatus{})

	assert.Equal(t, []string{"1.2.3.4/32", "10.0.0.1/24", "2001:db8::/32", "2001:db8::1/128"}, stored.Status.CIDRs)
	require.Len(t, stored.Status.Conditions, 1)
	assert.Equal(t, v1.ConditionTrue, stored.Status.Conditions[0].Status)
	assert.Equal(t, "All CIDRs are up to date (2 invalid entries ignored)", stored.Status.Conditions[0].Message)
	for _, c := range stored.Status.CIDRs {
		assert.NotContains(t, c, "secret-token")
		assert.NotContains(t, c, "s3cr3t")
	}
}

// TestCIDRsReconcileRemoteAllInvalidKeepsLastKnownGood verifies that a response with nothing usable
// doesn't wipe the allowlist: the previous CIDRs stay, and the update is refused.
func TestCIDRsReconcileRemoteAllInvalidKeepsLastKnownGood(t *testing.T) {
	stored := reconcileRemote(t, `["not-a-cidr", "Bearer secret-token"]`, nil,
		ipamv1alpha1.CIDRsStatus{CIDRs: []string{"10.0.0.0/8"}})

	assert.Equal(t, []string{"10.0.0.0/8"}, stored.Status.CIDRs)
	assert.Equal(t, ipamv1alpha1.CIDRsStateUpdateFailed, stored.Status.State)
	require.Len(t, stored.Status.Conditions, 1)
	assert.Equal(t, "Refusing to update removing all CIDRs", stored.Status.Conditions[0].Message)
}

// TestCIDRsReconcileInlineValues verifies that inline spec.cidrs are kept as typed: bare IPs become
// host routes (IPv6 included), anything else is left alone.
func TestCIDRsReconcileInlineValues(t *testing.T) {
	stored := reconcileRemote(t, `["192.168.0.0/16"]`, []string{"10.0.0.5/8", "1.2.3.4", "2001:db8::1", "typo"}, ipamv1alpha1.CIDRsStatus{})

	assert.Equal(t, []string{"1.2.3.4/32", "10.0.0.5/8", "192.168.0.0/16", "2001:db8::1/128", "typo"}, stored.Status.CIDRs)
	assert.Equal(t, "All CIDRs are up to date", stored.Status.Conditions[0].Message, "inline values are not counted as dropped")
}
