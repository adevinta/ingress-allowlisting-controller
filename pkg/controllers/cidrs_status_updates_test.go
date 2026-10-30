package controllers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	ipamv1alpha1 "github.com/adevinta/ingress-allowlisting-controller/pkg/apis/ipam.adevinta.com/v1alpha1"
)

func TestIgnoreStatusOnlyUpdates(t *testing.T) {
	obj := func(rv string, generation int64, labels, annotations map[string]string) *ipamv1alpha1.CIDRs {
		return &ipamv1alpha1.CIDRs{ObjectMeta: metav1.ObjectMeta{Name: "my-net", ResourceVersion: rv, Generation: generation, Labels: labels, Annotations: annotations}}
	}
	cases := []struct {
		name     string
		old, new *ipamv1alpha1.CIDRs
		want     bool
	}{
		{"status only (the controller's own write)", obj("1", 1, nil, nil), obj("2", 1, nil, nil), false},
		{"spec change", obj("1", 1, nil, nil), obj("2", 2, nil, nil), true},
		{"label change", obj("1", 1, nil, nil), obj("2", 1, map[string]string{"a": "b"}, nil), true},
		{"annotation change", obj("1", 1, nil, nil), obj("2", 1, nil, map[string]string{"a": "b"}), true},
		{"periodic resync", obj("1", 1, nil, nil), obj("1", 1, nil, nil), true},
	}
	for _, tc := range cases {
		assert.Equal(t, tc.want, ignoreStatusOnlyUpdates.Update(event.UpdateEvent{ObjectOld: tc.old, ObjectNew: tc.new}), tc.name)
	}
	assert.True(t, ignoreStatusOnlyUpdates.Create(event.CreateEvent{Object: obj("1", 1, nil, nil)}))
	assert.True(t, ignoreStatusOnlyUpdates.Delete(event.DeleteEvent{Object: obj("1", 1, nil, nil)}))
}

// TestCIDRsReconcileConditionShowsLatestError verifies that a second, different failure replaces
// the first one in the condition instead of the first staying forever.
func TestCIDRsReconcileConditionShowsLatestError(t *testing.T) {
	ctx := context.Background()
	status := http.StatusForbidden
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(status) }))
	defer server.Close()

	cidrs := &ipamv1alpha1.CIDRs{
		ObjectMeta: metav1.ObjectMeta{Name: "my-net", Namespace: "team-a"},
		Spec:       ipamv1alpha1.CIDRsSpec{CIDRsSource: ipamv1alpha1.CIDRsSource{Location: ipamv1alpha1.CIDRsLocation{URI: server.URL}}},
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
	req := reconcile.Request{NamespacedName: client.ObjectKeyFromObject(cidrs)}
	message := func() string {
		stored := &ipamv1alpha1.CIDRs{}
		require.NoError(t, fakeClient.Get(ctx, req.NamespacedName, stored))
		require.Len(t, stored.Status.Conditions, 1)
		return stored.Status.Conditions[0].Message
	}

	_, err = reconciler.Reconcile(ctx, req)
	require.NoError(t, err)
	assert.Contains(t, message(), "403")

	status = http.StatusInternalServerError
	_, err = reconciler.Reconcile(ctx, req)
	require.NoError(t, err)
	assert.Contains(t, message(), "500", "the condition must show the latest error, not the first")
}

// TestCIDRsStatusWriteDoesNotLoop simulates the watch: every update of the object triggers another
// reconcile unless the predicate drops it. The feed fails with a different error on every request,
// so every status write changes the condition message. With ignoreStatusOnlyUpdates the
// controller's own status write doesn't come back as a reconcile; without a predicate it does, and
// the controller would refetch in a loop without waiting for the retry interval.
func TestCIDRsStatusWriteDoesNotLoop(t *testing.T) {
	const maxReconciles = 10
	run := func(t *testing.T, triggers func(event.UpdateEvent) bool) (fetches int, message string) {
		t.Helper()
		ctx := context.Background()
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fetches++
			w.WriteHeader(500 + fetches) // a different error each time: 501, 502, ...
		}))
		defer server.Close()

		cidrs := &ipamv1alpha1.CIDRs{
			ObjectMeta: metav1.ObjectMeta{Name: "my-net", Namespace: "team-a"},
			Spec:       ipamv1alpha1.CIDRsSpec{CIDRsSource: ipamv1alpha1.CIDRsSource{Location: ipamv1alpha1.CIDRsLocation{URI: server.URL}}},
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
		req := reconcile.Request{NamespacedName: client.ObjectKeyFromObject(cidrs)}
		get := func() *ipamv1alpha1.CIDRs {
			obj := &ipamv1alpha1.CIDRs{}
			require.NoError(t, fakeClient.Get(ctx, req.NamespacedName, obj))
			return obj
		}

		// One reconcile for the create event, then one more for each update event let through.
		pending := 1
		for i := 0; pending > 0 && i < maxReconciles; i++ {
			pending--
			before := get()
			_, err := reconciler.Reconcile(ctx, req)
			require.NoError(t, err)
			after := get()
			if after.ResourceVersion != before.ResourceVersion && triggers(event.UpdateEvent{ObjectOld: before, ObjectNew: after}) {
				pending++
			}
		}
		after := get()
		require.Len(t, after.Status.Conditions, 1)
		return fetches, after.Status.Conditions[0].Message
	}

	t.Run("with ignoreStatusOnlyUpdates", func(t *testing.T) {
		fetches, message := run(t, ignoreStatusOnlyUpdates.Update)
		assert.Equal(t, 1, fetches, "the controller's own status write must not trigger another fetch")
		assert.Contains(t, message, "501")
	})

	t.Run("without a predicate, as before", func(t *testing.T) {
		fetches, message := run(t, func(event.UpdateEvent) bool { return true })
		assert.Equal(t, maxReconciles, fetches, "every status write comes back as a reconcile and fetch")
		assert.Contains(t, message, "510", "the condition shows the latest error")
	})
}
