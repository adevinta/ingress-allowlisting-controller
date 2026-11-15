package controllers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	ipamv1alpha1 "github.com/adevinta/ingress-allowlisting-controller/pkg/apis/ipam.adevinta.com/v1alpha1"
)

func TestHoldAdditions(t *testing.T) {
	t0 := time.Date(2026, 11, 10, 10, 0, 0, 0, time.UTC)
	delay := time.Hour
	pending := func(since time.Time, cidrs ...string) ipamv1alpha1.PendingCIDRs {
		return ipamv1alpha1.PendingCIDRs{FirstSeen: metav1.NewTime(since), ApplyAfter: metav1.NewTime(since.Add(delay)), CIDRs: cidrs}
	}

	t.Run("no delay: everything is used", func(t *testing.T) {
		got := holdAdditions([]string{"10.0.0.0/8", "11.0.0.0/8"}, nil, []string{"10.0.0.0/8"}, nil, 0, t0, false)
		assert.Equal(t, []string{"10.0.0.0/8", "11.0.0.0/8"}, got.use)
		assert.Empty(t, got.pending)
		assert.Zero(t, got.next)
	})

	t.Run("first list of an object: used right away", func(t *testing.T) {
		got := holdAdditions([]string{"10.0.0.0/8"}, nil, nil, nil, delay, t0, false)
		assert.Equal(t, []string{"10.0.0.0/8"}, got.use)
		assert.Empty(t, got.pending)
	})

	t.Run("a new CIDR waits, the ones in use stay, a removed one goes", func(t *testing.T) {
		got := holdAdditions([]string{"10.0.0.0/8", "12.0.0.0/8"}, nil, []string{"10.0.0.0/8", "11.0.0.0/8"}, nil, delay, t0, false)
		assert.Equal(t, []string{"10.0.0.0/8"}, got.use)
		assert.Equal(t, []ipamv1alpha1.PendingCIDRs{pending(t0, "12.0.0.0/8")}, got.pending)
		assert.Equal(t, []string{"12.0.0.0/8"}, got.added)
		assert.Equal(t, delay, got.next)
	})

	t.Run("a CIDR also in spec.cidrs doesn't wait", func(t *testing.T) {
		got := holdAdditions([]string{"12.0.0.0/8"}, []string{"12.0.0.0/8"}, []string{"10.0.0.0/8"}, nil, delay, t0, false)
		assert.Equal(t, []string{"12.0.0.0/8"}, got.use)
		assert.Empty(t, got.pending)
	})

	t.Run("first-seen time is kept, and the CIDR is used once it is due", func(t *testing.T) {
		old := []ipamv1alpha1.PendingCIDRs{pending(t0, "12.0.0.0/8")}
		got := holdAdditions([]string{"12.0.0.0/8", "13.0.0.0/8"}, nil, []string{"10.0.0.0/8"}, old, delay, t0.Add(40*time.Minute), false)
		assert.Empty(t, got.use)
		assert.Equal(t, []ipamv1alpha1.PendingCIDRs{pending(t0, "12.0.0.0/8"), pending(t0.Add(40*time.Minute), "13.0.0.0/8")}, got.pending)
		assert.Equal(t, []string{"13.0.0.0/8"}, got.added, "only the new one is logged as added")
		assert.Equal(t, 20*time.Minute, got.next, "the oldest is due first")

		got = holdAdditions([]string{"12.0.0.0/8", "13.0.0.0/8"}, nil, []string{"10.0.0.0/8"}, got.pending, delay, t0.Add(delay), false)
		assert.Equal(t, []string{"12.0.0.0/8"}, got.use)
		assert.Equal(t, []string{"12.0.0.0/8"}, got.applied)
		assert.Equal(t, []ipamv1alpha1.PendingCIDRs{pending(t0.Add(40*time.Minute), "13.0.0.0/8")}, got.pending)
	})

	t.Run("a pending CIDR the source drops is forgotten, and waits again if it comes back", func(t *testing.T) {
		old := []ipamv1alpha1.PendingCIDRs{pending(t0, "12.0.0.0/8")}
		got := holdAdditions([]string{"10.0.0.0/8"}, nil, []string{"10.0.0.0/8"}, old, delay, t0.Add(30*time.Minute), false)
		assert.Empty(t, got.pending)
		got = holdAdditions([]string{"10.0.0.0/8", "12.0.0.0/8"}, nil, []string{"10.0.0.0/8"}, got.pending, delay, t0.Add(2*time.Hour), false)
		assert.Equal(t, []ipamv1alpha1.PendingCIDRs{pending(t0.Add(2*time.Hour), "12.0.0.0/8")}, got.pending)
	})

	t.Run("a first-seen time in the future waits from now", func(t *testing.T) {
		old := []ipamv1alpha1.PendingCIDRs{pending(t0.Add(24*time.Hour), "12.0.0.0/8")}
		got := holdAdditions([]string{"12.0.0.0/8"}, nil, []string{"10.0.0.0/8"}, old, delay, t0, false)
		assert.Equal(t, []ipamv1alpha1.PendingCIDRs{pending(t0, "12.0.0.0/8")}, got.pending)
	})

	t.Run("a duplicate from the source counts once", func(t *testing.T) {
		got := holdAdditions([]string{"12.0.0.0/8", "12.0.0.0/8"}, nil, []string{"10.0.0.0/8"}, nil, delay, t0, false)
		assert.Equal(t, []ipamv1alpha1.PendingCIDRs{pending(t0, "12.0.0.0/8")}, got.pending)
	})
}

// TestCIDRsApplyDelay runs the delay through Reconcile: what is in the status, the condition, the
// metric and when the object is reconciled again.
func TestCIDRsApplyDelay(t *testing.T) {
	ctx := context.Background()
	scheme, err := Scheme()
	require.NoError(t, err)
	t0 := time.Date(2026, 11, 10, 10, 0, 0, 0, time.UTC)
	delay := time.Hour

	var mu sync.Mutex
	feed := []string{"10.0.0.0/8"}
	setFeed := func(cidrs ...string) { mu.Lock(); defer mu.Unlock(); feed = cidrs }
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		_, _ = w.Write([]byte("- " + strings.Join(feed, "\n- ") + "\n"))
	}))
	defer server.Close()

	obj := &ipamv1alpha1.CIDRs{
		ObjectMeta: metav1.ObjectMeta{Name: "partner", Namespace: "team-a"},
		Spec:       ipamv1alpha1.CIDRsSpec{CIDRsSource: ipamv1alpha1.CIDRsSource{Location: ipamv1alpha1.CIDRsLocation{URI: server.URL}}},
	}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(obj).WithStatusSubresource(obj).Build()
	r := &CIDRReconciler{
		Client:        c,
		CIDRs:         &ipamv1alpha1.CIDRs{},
		CIDRsList:     &ipamv1alpha1.CIDRsList{},
		SourceOptions: CIDRSourceOptions{AllowPrivateDestinations: true, ApplyDelay: delay}, // the test server is on 127.0.0.1
	}
	req := reconcile.Request{NamespacedName: client.ObjectKeyFromObject(obj)}
	reconcileAt := func(now time.Time) (ipamv1alpha1.CIDRsStatus, time.Duration) {
		t.Helper()
		r.now = func() time.Time { return now }
		result, err := r.Reconcile(ctx, req)
		require.NoError(t, err)
		got := &ipamv1alpha1.CIDRs{}
		require.NoError(t, c.Get(ctx, req.NamespacedName, got))
		return got.Status, result.RequeueAfter
	}
	metric := func() float64 {
		return testutil.ToFloat64(pendingCIDRs.WithLabelValues("CIDRs", "team-a", "partner"))
	}

	status, _ := reconcileAt(t0)
	assert.Equal(t, []string{"10.0.0.0/8"}, status.CIDRs, "the first list is used right away")
	assert.Empty(t, status.Pending)
	assert.Zero(t, metric())

	setFeed("10.0.0.0/8", "12.0.0.0/8")
	status, after := reconcileAt(t0.Add(10 * time.Minute))
	assert.Equal(t, []string{"10.0.0.0/8"}, status.CIDRs, "an addition waits")
	require.Len(t, status.Pending, 1)
	assert.Equal(t, []string{"12.0.0.0/8"}, status.Pending[0].CIDRs)
	assert.Equal(t, ipamv1alpha1.CIDRsStateReady, status.State)
	assert.Contains(t, status.Conditions[0].Message, "1 new CIDRs from the source wait for --cidr-source-apply-delay 1h0m0s, the first until 2026-11-10T11:10:00Z")
	assert.Equal(t, delay, after, "reconciled again when it is due, even without requeueAfter")
	assert.Equal(t, 1.0, metric())

	setFeed("12.0.0.0/8", "13.0.0.0/8")
	status, after = reconcileAt(t0.Add(20 * time.Minute))
	assert.Equal(t, []string{"10.0.0.0/8"}, status.CIDRs, "only new CIDRs left: never empty, the last CIDRs are kept")
	assert.Equal(t, []string{"12.0.0.0/8", "13.0.0.0/8"}, pendingOf(status), "and the new ones still wait")
	assert.True(t, status.Pending[0].FirstSeen.Time.Equal(t0.Add(10*time.Minute)), "with their clocks running")
	assert.Equal(t, ipamv1alpha1.CIDRsStateUpdateFailed, status.State)
	assert.Contains(t, status.Conditions[0].Message, "Refusing to update removing all CIDRs: every CIDR from the source is new, the last CIDRs are kept until then")
	assert.Equal(t, 5*time.Minute, after, "retried like a failed fetch")
	assert.Equal(t, 2.0, metric())

	status, after = reconcileAt(t0.Add(70 * time.Minute))
	assert.Equal(t, []string{"12.0.0.0/8"}, status.CIDRs, "once one is due it is used, and the old one goes")
	assert.Equal(t, ipamv1alpha1.CIDRsStateReady, status.State)
	require.Len(t, status.Pending, 1)
	assert.Equal(t, []string{"13.0.0.0/8"}, status.Pending[0].CIDRs)
	assert.Equal(t, 10*time.Minute, after)

	status, after = reconcileAt(t0.Add(80 * time.Minute))
	assert.Equal(t, []string{"12.0.0.0/8", "13.0.0.0/8"}, status.CIDRs)
	assert.Empty(t, status.Pending)
	assert.Equal(t, "All CIDRs are up to date", status.Conditions[0].Message)
	assert.Zero(t, after)
	assert.Zero(t, metric())

	t.Run("a failed fetch keeps what is pending", func(t *testing.T) {
		setFeed("12.0.0.0/8", "13.0.0.0/8", "14.0.0.0/8")
		status, _ := reconcileAt(t0.Add(90 * time.Minute))
		require.Len(t, status.Pending, 1)
		server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusInternalServerError) })
		status, _ = reconcileAt(t0.Add(3 * time.Hour))
		assert.Equal(t, []string{"12.0.0.0/8", "13.0.0.0/8"}, status.CIDRs, "not used without a fetch that still returns it")
		require.Len(t, status.Pending, 1)
		assert.True(t, status.Pending[0].FirstSeen.Time.Equal(t0.Add(90*time.Minute)))
	})

	t.Run("the series goes with the object", func(t *testing.T) {
		require.NoError(t, c.Delete(ctx, obj))
		_, err := r.Reconcile(ctx, req)
		require.NoError(t, err)
		assert.False(t, pendingCIDRs.DeleteLabelValues("CIDRs", "team-a", "partner"), "no series left")
	})
}

func pendingOf(status ipamv1alpha1.CIDRsStatus) []string {
	var out []string
	for _, p := range status.Pending {
		out = append(out, p.CIDRs...)
	}
	return out
}

func TestCIDRSourceOptionsApplyDelayValidation(t *testing.T) {
	opts := DefaultCIDRSourceOptions()
	opts.ApplyDelay = -time.Second
	assert.ErrorContains(t, opts.Validate(), "apply-delay must not be negative")
	opts.ApplyDelay = 0
	assert.NoError(t, opts.Validate())
}

func TestSourceHash(t *testing.T) {
	loc := ipamv1alpha1.CIDRsLocation{URI: "https://example.com/ips"}
	assert.Empty(t, sourceHash(ipamv1alpha1.CIDRsLocation{}), "no source, no hash")
	assert.Equal(t, sourceHash(loc), sourceHash(ipamv1alpha1.CIDRsLocation{URI: loc.URI, Processing: ipamv1alpha1.Processing{Format: ipamv1alpha1.YAML}}), "unset format is YAML")

	withHeaders := loc
	withHeaders.HeadersFrom = []ipamv1alpha1.HeadersFrom{{SecretRef: ipamv1alpha1.ObjectRef{Name: "token"}}}
	assert.Equal(t, sourceHash(loc), sourceHash(withHeaders), "headersFrom is not part of it")

	for name, changed := range map[string]ipamv1alpha1.CIDRsLocation{
		"uri":      {URI: "https://example.com/other"},
		"cel":      {URI: loc.URI, Processing: ipamv1alpha1.Processing{CEL: "data.ips"}},
		"jsonPath": {URI: loc.URI, Processing: ipamv1alpha1.Processing{JSONPath: "$.ips"}},
		"format":   {URI: loc.URI, Processing: ipamv1alpha1.Processing{Format: ipamv1alpha1.CSV}},
	} {
		assert.NotEqual(t, sourceHash(loc), sourceHash(changed), name)
	}

	assert.False(t, sourceChangedInSpec(ipamv1alpha1.CIDRsStatus{}, loc), "no hash yet: not a change")
	assert.False(t, sourceChangedInSpec(ipamv1alpha1.CIDRsStatus{SourceHash: sourceHash(loc)}, loc))
	assert.True(t, sourceChangedInSpec(ipamv1alpha1.CIDRsStatus{SourceHash: "0123456789abcdef"}, loc))
}

// TestCIDRsApplyDelaySpecChange verifies that a source changed in the spec is used right away,
// while a change only in what the same uri returns (here a redirect) waits.
func TestCIDRsApplyDelaySpecChange(t *testing.T) {
	ctx := context.Background()
	scheme, err := Scheme()
	require.NoError(t, err)
	t0 := time.Date(2026, 11, 10, 10, 0, 0, 0, time.UTC)
	delay := time.Hour

	var mu sync.Mutex
	redirect := false
	mux := http.NewServeMux()
	mux.HandleFunc("/a", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if redirect {
			http.Redirect(w, r, "/c", http.StatusFound)
			return
		}
		_, _ = w.Write([]byte("- 10.0.0.0/8\n"))
	})
	mux.HandleFunc("/b", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("- 11.0.0.0/8\n")) })
	mux.HandleFunc("/c", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("- 12.0.0.0/8\n")) })
	mux.HandleFunc("/obj", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"ips": ["10.0.0.0/8"], "other": ["13.0.0.0/8"]}`))
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	setup := func(t *testing.T, location ipamv1alpha1.CIDRsLocation, status ipamv1alpha1.CIDRsStatus) (func(now time.Time) ipamv1alpha1.CIDRsStatus, func(func(*ipamv1alpha1.CIDRsLocation))) {
		obj := &ipamv1alpha1.CIDRs{
			ObjectMeta: metav1.ObjectMeta{Name: "partner-spec", Namespace: "team-a"},
			Spec:       ipamv1alpha1.CIDRsSpec{CIDRsSource: ipamv1alpha1.CIDRsSource{Location: location}},
			Status:     status,
		}
		c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(obj).WithStatusSubresource(obj).Build()
		r := &CIDRReconciler{
			Client:        c,
			CIDRs:         &ipamv1alpha1.CIDRs{},
			CIDRsList:     &ipamv1alpha1.CIDRsList{},
			SourceOptions: CIDRSourceOptions{AllowPrivateDestinations: true, ApplyDelay: delay}, // the test server is on 127.0.0.1
		}
		key := client.ObjectKeyFromObject(obj)
		reconcileAt := func(now time.Time) ipamv1alpha1.CIDRsStatus {
			t.Helper()
			r.now = func() time.Time { return now }
			_, err := r.Reconcile(ctx, reconcile.Request{NamespacedName: key})
			require.NoError(t, err)
			got := &ipamv1alpha1.CIDRs{}
			require.NoError(t, c.Get(ctx, key, got))
			return got.Status
		}
		editLocation := func(edit func(*ipamv1alpha1.CIDRsLocation)) {
			t.Helper()
			got := &ipamv1alpha1.CIDRs{}
			require.NoError(t, c.Get(ctx, key, got))
			edit(&got.Spec.CIDRsSource.Location)
			require.NoError(t, c.Update(ctx, got))
		}
		t.Cleanup(func() { forgetPending("CIDRs", key.Namespace, key.Name) })
		return reconcileAt, editLocation
	}

	t.Run("uri changed in the spec: used right away", func(t *testing.T) {
		reconcileAt, editLocation := setup(t, ipamv1alpha1.CIDRsLocation{URI: server.URL + "/a"}, ipamv1alpha1.CIDRsStatus{})
		status := reconcileAt(t0)
		assert.Equal(t, []string{"10.0.0.0/8"}, status.CIDRs)
		assert.Equal(t, sourceHash(ipamv1alpha1.CIDRsLocation{URI: server.URL + "/a"}), status.SourceHash)

		editLocation(func(l *ipamv1alpha1.CIDRsLocation) { l.URI = server.URL + "/b" })
		status = reconcileAt(t0.Add(time.Minute))
		assert.Equal(t, []string{"11.0.0.0/8"}, status.CIDRs, "not deny-all, not held")
		assert.Empty(t, status.Pending)
	})

	t.Run("same uri now redirects: waits", func(t *testing.T) {
		reconcileAt, _ := setup(t, ipamv1alpha1.CIDRsLocation{URI: server.URL + "/a"}, ipamv1alpha1.CIDRsStatus{})
		assert.Equal(t, []string{"10.0.0.0/8"}, reconcileAt(t0).CIDRs)

		mu.Lock()
		redirect = true
		mu.Unlock()
		defer func() { mu.Lock(); redirect = false; mu.Unlock() }()
		status := reconcileAt(t0.Add(time.Minute))
		assert.Equal(t, []string{"10.0.0.0/8"}, status.CIDRs, "12.0.0.0/8 waits, and 10.0.0.0/8 stays: never empty")
		require.Len(t, status.Pending, 1)
		assert.Equal(t, []string{"12.0.0.0/8"}, status.Pending[0].CIDRs)
	})

	t.Run("cel changed in the spec: used right away, and what was pending is dropped", func(t *testing.T) {
		reconcileAt, editLocation := setup(t, ipamv1alpha1.CIDRsLocation{URI: server.URL + "/obj", Processing: ipamv1alpha1.Processing{CEL: "data.ips"}}, ipamv1alpha1.CIDRsStatus{})
		assert.Equal(t, []string{"10.0.0.0/8"}, reconcileAt(t0).CIDRs)

		editLocation(func(l *ipamv1alpha1.CIDRsLocation) { l.CEL = "data.ips + data.other" })
		status := reconcileAt(t0.Add(time.Minute))
		assert.Equal(t, []string{"10.0.0.0/8", "13.0.0.0/8"}, status.CIDRs)
		assert.Empty(t, status.Pending)
	})

	t.Run("an object from before the hash: additions wait, the hash is recorded", func(t *testing.T) {
		reconcileAt, _ := setup(t, ipamv1alpha1.CIDRsLocation{URI: server.URL + "/b"}, ipamv1alpha1.CIDRsStatus{CIDRs: []string{"10.0.0.0/8"}})
		status := reconcileAt(t0)
		assert.Equal(t, []string{"10.0.0.0/8"}, status.CIDRs)
		require.Len(t, status.Pending, 1)
		assert.NotEmpty(t, status.SourceHash)
	})
}
