package controllers

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	ipamv1alpha1 "github.com/adevinta/ingress-allowlisting-controller/pkg/apis/ipam.adevinta.com/v1alpha1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

func TestCappedBody(t *testing.T) {
	read := func(t *testing.T, body string, limit int64) (string, *cappedBody, error) {
		t.Helper()
		c := newCappedBody(io.NopCloser(strings.NewReader(body)), limit)
		out, err := io.ReadAll(c)
		return string(out), c, err
	}

	t.Run("body below the limit is read fully", func(t *testing.T) {
		out, c, err := read(t, "hello", 10)
		require.NoError(t, err)
		assert.Equal(t, "hello", out)
		assert.NoError(t, c.exceeded())
	})

	t.Run("body exactly at the limit is accepted", func(t *testing.T) {
		out, c, err := read(t, "0123456789", 10)
		require.NoError(t, err)
		assert.Equal(t, "0123456789", out)
		assert.NoError(t, c.exceeded())
	})

	t.Run("one byte over the limit fails and never hands out more than the limit", func(t *testing.T) {
		out, c, err := read(t, "0123456789X", 10)
		require.ErrorIs(t, err, errResponseTooLarge)
		assert.Equal(t, "0123456789", out)
		assert.ErrorIs(t, c.exceeded(), errResponseTooLarge)
	})

	t.Run("far over the limit stops early", func(t *testing.T) {
		out, c, err := read(t, strings.Repeat("a", 1<<20), 100)
		require.ErrorIs(t, err, errResponseTooLarge)
		assert.Len(t, out, 100)
		assert.Error(t, c.exceeded())
	})

	t.Run("once exceeded, further reads keep failing", func(t *testing.T) {
		c := newCappedBody(io.NopCloser(strings.NewReader("0123456789X")), 10)
		_, _ = io.ReadAll(c)
		n, err := c.Read(make([]byte, 4))
		assert.Zero(t, n)
		assert.ErrorIs(t, err, errResponseTooLarge)
	})
}

// reconcileFromServer reconciles a CIDRs object that already holds a last-known-good status and
// whose source is the given server, and returns the object afterwards.
func reconcileFromServer(t *testing.T, serverURL string, processing ipamv1alpha1.Processing, opts CIDRSourceOptions) *ipamv1alpha1.CIDRs {
	t.Helper()
	opts.AllowPrivateDestinations = true // the test servers listen on 127.0.0.1
	return reconcileWithGuards(t, serverURL, processing, opts)
}

// reconcileWithGuards is reconcileFromServer without touching the options, for tests of the
// destination guard and the allowlist themselves.
func reconcileWithGuards(t *testing.T, serverURL string, processing ipamv1alpha1.Processing, opts CIDRSourceOptions) *ipamv1alpha1.CIDRs {
	t.Helper()
	ctx := context.TODO()
	scheme, err := Scheme("")
	require.NoError(t, err)

	cidrs := &ipamv1alpha1.CIDRs{
		ObjectMeta: metav1.ObjectMeta{Name: "my-net", Namespace: "mynamespace"},
		Spec: ipamv1alpha1.CIDRsSpec{CIDRsSource: ipamv1alpha1.CIDRsSource{
			Location: ipamv1alpha1.CIDRsLocation{URI: serverURL, Processing: processing},
		}},
		Status: ipamv1alpha1.CIDRsStatus{CIDRs: []string{"127.0.0.1/32"}},
	}
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(cidrs).WithStatusSubresource(cidrs).Build()
	reconciler := &CIDRReconciler{CIDRs: &ipamv1alpha1.CIDRs{}, CIDRsList: &ipamv1alpha1.CIDRsList{}, Client: fakeClient, SourceOptions: opts}

	_, err = reconciler.Reconcile(ctx, reconcile.Request{NamespacedName: client.ObjectKeyFromObject(cidrs)})
	require.NoError(t, err)
	require.NoError(t, fakeClient.Get(ctx, client.ObjectKeyFromObject(cidrs), cidrs))
	return cidrs
}

func requireFailedKeepingLastGood(t *testing.T, cidrs *ipamv1alpha1.CIDRs, wantMessage string) {
	t.Helper()
	assert.Equal(t, ipamv1alpha1.CIDRsStateUpdateFailed, cidrs.Status.State)
	assert.Equal(t, []string{"127.0.0.1/32"}, cidrs.Status.CIDRs, "last-known-good allowlist must be kept")
	require.Len(t, cidrs.Status.Conditions, 1)
	assert.Equal(t, v1.ConditionFalse, cidrs.Status.Conditions[0].Status)
	assert.Contains(t, cidrs.Status.Conditions[0].Message, wantMessage)
}

func TestFetchTimeout(t *testing.T) {
	opts := CIDRSourceOptions{FetchTimeout: 150 * time.Millisecond}

	// A server that accepts the request and then never answers.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-time.After(5 * time.Second):
		}
	}))
	defer server.Close()

	start := time.Now()
	cidrs := reconcileFromServer(t, server.URL, ipamv1alpha1.Processing{}, opts)
	assert.Less(t, time.Since(start), 3*time.Second, "reconcile must not wait for the stalled server")
	requireFailedKeepingLastGood(t, cidrs, "deadline exceeded")
}

func TestFetchTimeoutWhileBodyStalls(t *testing.T) {
	opts := CIDRSourceOptions{FetchTimeout: 150 * time.Millisecond}

	// Headers arrive at once, then the body trickles forever.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("- 10.0.0.0/8\n"))
		w.(http.Flusher).Flush()
		select {
		case <-r.Context().Done():
		case <-time.After(5 * time.Second):
		}
	}))
	defer server.Close()

	start := time.Now()
	cidrs := reconcileFromServer(t, server.URL, ipamv1alpha1.Processing{Format: ipamv1alpha1.CSV}, opts)
	assert.Less(t, time.Since(start), 3*time.Second)
	assert.Equal(t, ipamv1alpha1.CIDRsStateUpdateFailed, cidrs.Status.State)
	assert.Equal(t, []string{"127.0.0.1/32"}, cidrs.Status.CIDRs)
}

func TestResponseSizeCap(t *testing.T) {
	// 50 bytes is enough for a couple of entries but far below the body served below.
	opts := CIDRSourceOptions{MaxResponseBytes: 50}

	serve := func(body string) *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = io.WriteString(w, body)
		}))
	}

	var big strings.Builder
	for i := 0; i < 100; i++ {
		fmt.Fprintf(&big, "- 10.%d.0.0/16\n", i)
	}

	t.Run("oversized yaml list is rejected, not truncated", func(t *testing.T) {
		server := serve(big.String())
		defer server.Close()
		cidrs := reconcileFromServer(t, server.URL, ipamv1alpha1.Processing{}, opts)
		requireFailedKeepingLastGood(t, cidrs, "response body too large")
	})

	t.Run("oversized csv is rejected, not truncated", func(t *testing.T) {
		// Truncating this mid-record would silently drop CIDRs from the allowlist.
		server := serve(strings.ReplaceAll(strings.ReplaceAll(big.String(), "- ", ""), "\n", ","))
		defer server.Close()
		cidrs := reconcileFromServer(t, server.URL, ipamv1alpha1.Processing{Format: ipamv1alpha1.CSV}, opts)
		requireFailedKeepingLastGood(t, cidrs, "response body too large")
	})

	t.Run("body within the cap still works", func(t *testing.T) {
		server := serve("- 10.1.0.0/16\n- 10.2.0.0/16\n")
		defer server.Close()
		cidrs := reconcileFromServer(t, server.URL, ipamv1alpha1.Processing{}, opts)
		assert.Equal(t, []string{"10.1.0.0/16", "10.2.0.0/16"}, cidrs.Status.CIDRs)
		assert.NotEqual(t, ipamv1alpha1.CIDRsStateUpdateFailed, cidrs.Status.State)
	})
}

func TestCELCostLimit(t *testing.T) {
	// A feed of a few thousand prefixes, like a real provider list.
	const entries = 3000
	feed := make([]string, entries)
	for i := range feed {
		feed[i] = fmt.Sprintf("10.%d.%d.0/24", i/256, i%256)
	}
	yamlOf := func() io.Reader {
		var b strings.Builder
		for _, c := range feed {
			fmt.Fprintf(&b, "- %s\n", c)
		}
		return strings.NewReader(b.String())
	}

	t.Run("a normal filter over a real-size feed stays within the default limit", func(t *testing.T) {
		got, err := applyProcessorWithCostLimit(yamlOf(), ipamv1alpha1.Processing{CEL: `data.filter(c, c.startsWith("10.1."))`}, defaultCELCostLimit)
		require.NoError(t, err)
		assert.NotEmpty(t, got)
	})

	t.Run("the documented AWS expression over an AWS-sized feed stays within the default limit", func(t *testing.T) {
		// ~10,000 prefixes as objects, like ip-ranges.json. Guards against lowering the default
		// below what a legitimate feed needs (measured cost is ~130,000 against a 1,000,000 limit).
		var b strings.Builder
		b.WriteString("prefixes:\n")
		for i := 0; i < 10000; i++ {
			fmt.Fprintf(&b, "- ip_prefix: 10.%d.%d.0/24\n  region: eu-west-1\n  service: %s\n",
				i/256, i%256, []string{"EC2", "AMAZON", "S3"}[i%3])
		}
		got, err := applyProcessorWithCostLimit(strings.NewReader(b.String()), ipamv1alpha1.Processing{
			CEL: `data.prefixes.filter(p, p.service == "EC2" && has(p.ip_prefix)).map(p, p.ip_prefix)`,
		}, defaultCELCostLimit)
		require.NoError(t, err)
		assert.Len(t, got, 3334)
	})

	t.Run("nested comprehensions are aborted by the cost limit", func(t *testing.T) {
		start := time.Now()
		// O(n^3) over 3000 entries would be ~27 billion operations.
		_, err := applyProcessorWithCostLimit(yamlOf(), ipamv1alpha1.Processing{
			CEL: `data.map(a, data.map(b, data.map(c, a + b + c)))[0][0]`,
		}, defaultCELCostLimit)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "cost limit")
		assert.Less(t, time.Since(start), 3*time.Second, "must be aborted early, not run to completion")
	})

	t.Run("limit is enforced from the configured value", func(t *testing.T) {
		_, err := applyProcessorWithCostLimit(yamlOf(), ipamv1alpha1.Processing{CEL: `data.filter(c, c.startsWith("10.1."))`}, 100)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "cost limit")
	})
}

func TestCIDRSourceOptionsValidate(t *testing.T) {
	valid := DefaultCIDRSourceOptions()
	require.NoError(t, valid.Validate())

	tests := []struct {
		name   string
		mutate func(*CIDRSourceOptions)
		want   string
	}{
		{"ipv4 mask zero", func(o *CIDRSourceOptions) { o.MinMaskIPv4 = 0 }, "min-mask-ipv4"},
		{"ipv4 mask too long", func(o *CIDRSourceOptions) { o.MinMaskIPv4 = 33 }, "min-mask-ipv4"},
		{"ipv4 mask negative", func(o *CIDRSourceOptions) { o.MinMaskIPv4 = -1 }, "min-mask-ipv4"},
		{"ipv6 mask zero", func(o *CIDRSourceOptions) { o.MinMaskIPv6 = 0 }, "min-mask-ipv6"},
		{"ipv6 mask too long", func(o *CIDRSourceOptions) { o.MinMaskIPv6 = 129 }, "min-mask-ipv6"},
		{"timeout zero", func(o *CIDRSourceOptions) { o.FetchTimeout = 0 }, "fetch-timeout"},
		{"timeout negative", func(o *CIDRSourceOptions) { o.FetchTimeout = -time.Second }, "fetch-timeout"},
		{"max bytes zero", func(o *CIDRSourceOptions) { o.MaxResponseBytes = 0 }, "max-response-bytes"},
		{"max bytes negative", func(o *CIDRSourceOptions) { o.MaxResponseBytes = -5 }, "max-response-bytes"},
		{"cost limit zero", func(o *CIDRSourceOptions) { o.CELCostLimit = 0 }, "cel-cost-limit"},
		{"retry interval zero", func(o *CIDRSourceOptions) { o.RetryInterval = 0 }, "retry-interval"},
		{"retry interval negative", func(o *CIDRSourceOptions) { o.RetryInterval = -time.Minute }, "retry-interval"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			o := DefaultCIDRSourceOptions()
			tt.mutate(&o)
			err := o.Validate()
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.want)
		})
	}

	t.Run("all problems are reported together", func(t *testing.T) {
		err := CIDRSourceOptions{}.Validate()
		require.Error(t, err)
		for _, name := range []string{"min-mask-ipv4", "min-mask-ipv6", "fetch-timeout", "max-response-bytes", "cel-cost-limit", "retry-interval"} {
			assert.Contains(t, err.Error(), name)
		}
	})

	t.Run("boundary values are accepted", func(t *testing.T) {
		o := DefaultCIDRSourceOptions()
		o.MinMaskIPv4, o.MinMaskIPv6 = 1, 1
		require.NoError(t, o.Validate())
		o.MinMaskIPv4, o.MinMaskIPv6 = 32, 128
		require.NoError(t, o.Validate())
	})
}

func TestCIDRSourceOptionsDefaults(t *testing.T) {
	assert.Equal(t, DefaultCIDRSourceOptions(), CIDRSourceOptions{}.withDefaults(), "zero value means all defaults")

	custom := CIDRSourceOptions{MinMaskIPv4: 16, FetchTimeout: time.Minute}
	got := custom.withDefaults()
	assert.Equal(t, 16, got.MinMaskIPv4, "explicit values are kept")
	assert.Equal(t, time.Minute, got.FetchTimeout)
	assert.Equal(t, defaultMinMaskIPv6, got.MinMaskIPv6, "unset fields get the default")
	assert.Equal(t, defaultMaxResponseBytes, got.MaxResponseBytes)
	assert.Equal(t, defaultCELCostLimit, got.CELCostLimit)
	assert.Equal(t, defaultRetryInterval, got.RetryInterval)

	// Documented defaults — changing them is a behaviour change for every deployment.
	d := DefaultCIDRSourceOptions()
	assert.Equal(t, 8, d.MinMaskIPv4)
	assert.Equal(t, 20, d.MinMaskIPv6)
	assert.Equal(t, 30*time.Second, d.FetchTimeout)
	assert.Equal(t, int64(5<<20), d.MaxResponseBytes)
	assert.Equal(t, uint64(1_000_000), d.CELCostLimit)
	assert.Equal(t, 5*time.Minute, d.RetryInterval)
}

func TestConfiguredMinMaskIsHonouredOnFetch(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "- 10.0.0.0/8\n")
	}))
	defer server.Close()

	t.Run("a /8 passes the default minimum mask", func(t *testing.T) {
		cidrs := reconcileFromServer(t, server.URL, ipamv1alpha1.Processing{}, CIDRSourceOptions{})
		assert.Equal(t, []string{"10.0.0.0/8"}, cidrs.Status.CIDRs)
	})

	t.Run("a stricter configured minimum mask rejects it and keeps the last good list", func(t *testing.T) {
		cidrs := reconcileFromServer(t, server.URL, ipamv1alpha1.Processing{}, CIDRSourceOptions{MinMaskIPv4: 16})
		requireFailedKeepingLastGood(t, cidrs, "too broad")
	})
}

func TestSetupRejectsInvalidCIDRSourceOptions(t *testing.T) {
	// SetupControllersWithManager must refuse options that would silently weaken a protection.
	err := SetupControllersWithManager(nil, false, false, false, false, false, "", "", "ipam.adevinta.com", false,
		CIDRSourceOptions{MinMaskIPv4: 99})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "min-mask-ipv4")
}

func TestCELCostLimitKeepsLastGoodOnFetch(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, strings.Repeat("- 10.1.0.0/16\n", 50))
	}))
	defer server.Close()

	cidrs := reconcileFromServer(t, server.URL,
		ipamv1alpha1.Processing{CEL: `data.filter(c, c.startsWith("10."))`},
		CIDRSourceOptions{CELCostLimit: 10})

	requireFailedKeepingLastGood(t, cidrs, "cost limit")
}

func TestFetchLimitTripped(t *testing.T) {
	opts := DefaultCIDRSourceOptions()
	live := context.Background()

	expired, cancel := context.WithTimeout(context.Background(), time.Nanosecond)
	defer cancel()
	<-expired.Done()

	t.Run("size, including when wrapped by a parser", func(t *testing.T) {
		limit, configured, ok := fetchLimitTripped(live, fmt.Errorf("failed to decode yaml: %w", errResponseTooLarge), opts)
		assert.True(t, ok)
		assert.Equal(t, "max-response-bytes", limit)
		assert.Equal(t, int64(5242880), configured)
	})

	t.Run("timeout is read from the fetch context", func(t *testing.T) {
		limit, configured, ok := fetchLimitTripped(expired, io.ErrUnexpectedEOF, opts)
		assert.True(t, ok)
		assert.Equal(t, "fetch-timeout", limit)
		assert.Equal(t, "30s", configured)
	})

	t.Run("an unrelated error is not a limit", func(t *testing.T) {
		_, _, ok := fetchLimitTripped(live, fmt.Errorf("unexpected status code: %d", 403), opts)
		assert.False(t, ok)
	})

	t.Run("a cancelled parent context is not reported as a timeout", func(t *testing.T) {
		cancelled, cancelNow := context.WithCancel(context.Background())
		cancelNow()
		_, _, ok := fetchLimitTripped(cancelled, io.ErrUnexpectedEOF, opts)
		assert.False(t, ok, "controller shutdown must not look like a slow source")
	})
}

func TestFailedFetchIsRetried(t *testing.T) {
	failing := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer failing.Close()
	healthy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "- 10.0.0.0/16\n")
	}))
	defer healthy.Close()
	empty := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "[]\n")
	}))
	defer empty.Close()

	tests := []struct {
		name         string
		serverURL    string
		requeueAfter time.Duration
		opts         CIDRSourceOptions
		want         reconcile.Result
	}{
		{"failure without requeueAfter uses the default retry interval", failing.URL, 0, CIDRSourceOptions{}, reconcile.Result{RequeueAfter: defaultRetryInterval}},
		{"failure uses the configured retry interval", failing.URL, 0, CIDRSourceOptions{RetryInterval: 2 * time.Minute}, reconcile.Result{RequeueAfter: 2 * time.Minute}},
		{"failure with a longer requeueAfter is retried sooner", failing.URL, 30 * time.Minute, CIDRSourceOptions{}, reconcile.Result{RequeueAfter: defaultRetryInterval}},
		{"failure with a shorter requeueAfter keeps it", failing.URL, time.Minute, CIDRSourceOptions{}, reconcile.Result{RequeueAfter: time.Minute}},
		{"an empty list refused as removing all CIDRs is retried", empty.URL, 0, CIDRSourceOptions{}, reconcile.Result{RequeueAfter: defaultRetryInterval}},
		{"an empty list with a shorter requeueAfter keeps it", empty.URL, time.Minute, CIDRSourceOptions{}, reconcile.Result{RequeueAfter: time.Minute}},
		{"success without requeueAfter is not requeued", healthy.URL, 0, CIDRSourceOptions{}, reconcile.Result{}},
		{"success keeps the normal requeueAfter", healthy.URL, 30 * time.Minute, CIDRSourceOptions{}, reconcile.Result{RequeueAfter: 30 * time.Minute, Requeue: true}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.TODO()
			scheme, err := Scheme("")
			require.NoError(t, err)

			cidrs := &ipamv1alpha1.CIDRs{
				ObjectMeta: metav1.ObjectMeta{Name: "my-net", Namespace: "mynamespace"},
				Spec: ipamv1alpha1.CIDRsSpec{CIDRsSource: ipamv1alpha1.CIDRsSource{
					Location: ipamv1alpha1.CIDRsLocation{URI: tt.serverURL},
				}},
				Status: ipamv1alpha1.CIDRsStatus{CIDRs: []string{"127.0.0.1/32"}},
			}
			if tt.requeueAfter > 0 {
				cidrs.Spec.RequeueAfter = &metav1.Duration{Duration: tt.requeueAfter}
			}
			fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(cidrs).WithStatusSubresource(cidrs).Build()
			tt.opts.AllowPrivateDestinations = true // the test servers listen on 127.0.0.1
			reconciler := &CIDRReconciler{CIDRs: &ipamv1alpha1.CIDRs{}, CIDRsList: &ipamv1alpha1.CIDRsList{}, Client: fakeClient, SourceOptions: tt.opts}

			result, err := reconciler.Reconcile(ctx, reconcile.Request{NamespacedName: client.ObjectKeyFromObject(cidrs)})
			require.NoError(t, err, "a failed fetch is reported in the status, not returned as an error")
			assert.Equal(t, tt.want, result)
		})
	}
}
