package controllers

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	ipamv1alpha1 "github.com/adevinta/ingress-allowlisting-controller/pkg/apis/ipam.adevinta.com/v1alpha1"
)

// TestCIDRsLastUpdate verifies that status.lastUpdate is when status.cidrs last changed: set when
// the list changes, kept when a reconcile gives the same list, and set once on an object that has
// CIDRs from before the field was set.
func TestCIDRsLastUpdate(t *testing.T) {
	ctx := context.Background()
	scheme, err := Scheme()
	require.NoError(t, err)
	t1 := time.Date(2026, 11, 6, 10, 0, 0, 0, time.UTC)
	t2, t3 := t1.Add(time.Hour), t1.Add(2*time.Hour)

	setup := func(t *testing.T, obj *ipamv1alpha1.CIDRs) (*CIDRReconciler, func(now time.Time) ipamv1alpha1.CIDRsStatus) {
		c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(obj).WithStatusSubresource(obj).Build()
		r := &CIDRReconciler{Client: c, CIDRs: &ipamv1alpha1.CIDRs{}, CIDRsList: &ipamv1alpha1.CIDRsList{}}
		return r, func(now time.Time) ipamv1alpha1.CIDRsStatus {
			t.Helper()
			r.now = func() time.Time { return now }
			_, err := r.Reconcile(ctx, reconcile.Request{NamespacedName: client.ObjectKeyFromObject(obj)})
			require.NoError(t, err)
			got := &ipamv1alpha1.CIDRs{}
			require.NoError(t, c.Get(ctx, client.ObjectKeyFromObject(obj), got))
			return got.Status
		}
	}
	inline := func(cidrs ...string) *ipamv1alpha1.CIDRs {
		return &ipamv1alpha1.CIDRs{
			ObjectMeta: metav1.ObjectMeta{Name: "office", Namespace: "team-a"},
			Spec:       ipamv1alpha1.CIDRsSpec{CIDRsSource: ipamv1alpha1.CIDRsSource{CIDRs: cidrs}},
		}
	}

	t.Run("set when the list changes, kept when it doesn't", func(t *testing.T) {
		obj := inline("192.0.2.0/24")
		r, reconcileAt := setup(t, obj)

		status := reconcileAt(t1)
		assert.Equal(t, []string{"192.0.2.0/24"}, status.CIDRs)
		assert.True(t, status.LastUpdate.Time.Equal(t1), "first list: %v", status.LastUpdate)

		assert.True(t, reconcileAt(t2).LastUpdate.Time.Equal(t1), "same list: unchanged")

		current := &ipamv1alpha1.CIDRs{}
		require.NoError(t, r.Get(ctx, client.ObjectKeyFromObject(obj), current))
		current.Spec.CIDRs = append(current.Spec.CIDRs, "198.51.100.0/24")
		require.NoError(t, r.Update(ctx, current))
		status = reconcileAt(t3)
		assert.Equal(t, []string{"192.0.2.0/24", "198.51.100.0/24"}, status.CIDRs)
		assert.True(t, status.LastUpdate.Time.Equal(t3), "changed list: %v", status.LastUpdate)
	})

	t.Run("set once on CIDRs written before the field was set", func(t *testing.T) {
		obj := inline("192.0.2.0/24")
		obj.Status.CIDRs = []string{"192.0.2.0/24"}
		_, reconcileAt := setup(t, obj)
		assert.True(t, reconcileAt(t1).LastUpdate.Time.Equal(t1))
		assert.True(t, reconcileAt(t2).LastUpdate.Time.Equal(t1))
	})
}
