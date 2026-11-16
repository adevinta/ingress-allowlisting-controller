package controllers

import (
	"context"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"runtime"
	"runtime/debug"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	ipamv1alpha1 "github.com/adevinta/ingress-allowlisting-controller/pkg/apis/ipam.adevinta.com/v1alpha1"
)

// setMemoryLimit sets the Go memory limit for the test (math.MaxInt64 is "none", as when GOMEMLIMIT
// is not set), and puts the old one back.
func setMemoryLimit(t *testing.T, limit int64) {
	t.Helper()
	old := debug.SetMemoryLimit(limit)
	t.Cleanup(func() { debug.SetMemoryLimit(old) })
}

// tinyNodes is a body of about size bytes of tiny nested lists: [[],[],[],...]. A real feed takes
// about 13x its size to decode, this takes 70-110x.
func tinyNodes(size int) string {
	return "[" + strings.Repeat("[],", size/3) + "[]]"
}

// awsLike is a body of about size bytes like the AWS feed: many small objects, all different.
func awsLike(size int) (body string, prefixes int) {
	var b strings.Builder
	b.WriteString(`{"prefixes": [`)
	for b.Len() < size {
		if prefixes > 0 {
			b.WriteString(", ")
		}
		fmt.Fprintf(&b, `{"ip_prefix": "%d.%d.%d.0/24", "region": "us-east-1", "service": "AMAZON", "network_border_group": "us-east-1"}`,
			1+prefixes/65536, (prefixes/256)%256, prefixes%256)
		prefixes++
	}
	b.WriteString(`]}`)
	return b.String(), prefixes
}

type bytesReadCounter struct {
	r io.Reader
	n int64
}

func (c *bytesReadCounter) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	return n, err
}

func TestProcessingMemoryBudget(t *testing.T) {
	t.Run("without a memory limit it is 30x the size cap", func(t *testing.T) {
		setMemoryLimit(t, math.MaxInt64)
		budget, byMemory := processingMemoryBudget(5 << 20)
		assert.Equal(t, uint64(30*(5<<20)), budget)
		assert.False(t, byMemory, "the factor sets it")
	})

	t.Run("a memory limit lowers it to half of what is free", func(t *testing.T) {
		runtime.GC()
		setMemoryLimit(t, 128<<20)
		budget, byMemory := processingMemoryBudget(5 << 20)
		assert.LessOrEqual(t, budget, uint64(64<<20), "half of the limit at most, less the heap in use")
		assert.GreaterOrEqual(t, budget, uint64(minProcessingMemoryBudget))
		assert.True(t, byMemory, "the memory limit sets it")

		setMemoryLimit(t, 4<<30)
		budget, byMemory = processingMemoryBudget(5 << 20)
		assert.Equal(t, uint64(30*(5<<20)), budget, "a roomy limit leaves the factor")
		assert.False(t, byMemory)
	})

	t.Run("it is never below the minimum, whatever the limit and the cap", func(t *testing.T) {
		setMemoryLimit(t, 1<<20) // below what is in use already
		budget, _ := processingMemoryBudget(5 << 20)
		assert.Equal(t, uint64(minProcessingMemoryBudget), budget)
		setMemoryLimit(t, math.MaxInt64)
		budget, _ = processingMemoryBudget(1 << 10)
		assert.Equal(t, uint64(minProcessingMemoryBudget), budget)
	})
}

// TestProcessingMemoryMessages verifies what each reader is told: the person who wrote the object
// (the condition) and the admin (the log).
func TestProcessingMemoryMessages(t *testing.T) {
	t.Run("the condition text sends the creator to a smaller source or the admin", func(t *testing.T) {
		text := (&processingMemoryError{budget: 30 << 20}).Error()
		assert.Contains(t, text, "needs too much memory")
		assert.Contains(t, text, "more than 30 MiB")
		assert.Contains(t, text, "Use a smaller source, or ask the cluster admin")
		assert.NotContains(t, text, "GOMEMLIMIT", "no settings of the controller in what a tenant reads")
	})

	t.Run("the admin hint depends on what sets the budget", func(t *testing.T) {
		byMemory := (&processingMemoryError{limitedByMemory: true}).adminHint()
		assert.Contains(t, byMemory, "give the controller more memory")
		assert.NotContains(t, byMemory, "--cidr-source-max-response-bytes")

		byFactor := (&processingMemoryError{}).adminHint()
		assert.Contains(t, byFactor, "raise --cidr-source-max-response-bytes together with the memory limit")
		assert.Contains(t, byFactor, "30x")
	})

	t.Run("a startup warning when there is no memory limit", func(t *testing.T) {
		setMemoryLimit(t, math.MaxInt64)
		logs := captureLogs(t)
		warnIfNoMemoryLimit()
		assert.Contains(t, logs.String(), "GOMEMLIMIT is not set")
		assert.Contains(t, logs.String(), "Set GOMEMLIMIT to the container's memory limit")

		setMemoryLimit(t, 256<<20)
		logs = captureLogs(t)
		warnIfNoMemoryLimit()
		assert.Empty(t, logs.String(), "with a limit there is nothing to warn about")
	})
}

// TestProcessingMemoryGuardStopsTinyNodes verifies that a body that costs far more memory than its
// size is stopped while it is being read, not after the memory is used.
func TestProcessingMemoryGuardStopsTinyNodes(t *testing.T) {
	setMemoryLimit(t, math.MaxInt64)
	runtime.GC()
	body := tinyNodes(4 << 20)
	counted := &bytesReadCounter{r: strings.NewReader(body)}
	guard := newProcessingMemoryGuard(counted, 1<<20) // a budget of 30 MiB

	var data interface{}
	err := yaml.NewDecoder(guard).Decode(&data)

	require.Error(t, err, "the decoder fails")
	require.Error(t, guard.exceeded(), "and the guard says why, whatever the decoder made of the error")
	assert.ErrorIs(t, guard.exceeded(), errProcessingMemory)
	assert.Contains(t, guard.exceeded().Error(), "more than 30 MiB")
	// At 70-110x, 30 MiB is less than half a MiB of the body.
	assert.Less(t, counted.n, int64(len(body)/2), "it stopped early: %d of %d bytes were read", counted.n, len(body))
}

func TestProcessingMemoryGuardLetsRealFeedsThrough(t *testing.T) {
	setMemoryLimit(t, math.MaxInt64)
	runtime.GC()
	body, prefixes := awsLike(1 << 20)
	guard := newProcessingMemoryGuard(strings.NewReader(body), 1<<20) // a budget of 30 MiB; this needs about 15

	var data map[string]interface{}
	require.NoError(t, yaml.NewDecoder(guard).Decode(&data))
	assert.NoError(t, guard.exceeded())
	assert.Len(t, data["prefixes"], prefixes)
}

// TestCIDRsProcessingMemoryBudget runs it through Reconcile: the fetch fails, the previous list
// stays, the condition says so and the log names the limit.
func TestCIDRsProcessingMemoryBudget(t *testing.T) {
	setMemoryLimit(t, math.MaxInt64)
	ctx := context.Background()
	scheme, err := Scheme()
	require.NoError(t, err)

	reconcileBody := func(t *testing.T, body string, processing ipamv1alpha1.Processing) (*ipamv1alpha1.CIDRs, string) {
		t.Helper()
		runtime.GC()
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(body)) }))
		t.Cleanup(server.Close)
		cidrs := &ipamv1alpha1.CIDRs{
			ObjectMeta: metav1.ObjectMeta{Name: "feed", Namespace: "team-a"},
			Spec: ipamv1alpha1.CIDRsSpec{CIDRsSource: ipamv1alpha1.CIDRsSource{Location: ipamv1alpha1.CIDRsLocation{
				URI: server.URL, Processing: processing,
			}}},
			Status: ipamv1alpha1.CIDRsStatus{CIDRs: []string{"192.0.2.0/24"}},
		}
		c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(cidrs).WithStatusSubresource(cidrs).Build()
		r := &CIDRReconciler{
			Client: c, CIDRs: &ipamv1alpha1.CIDRs{}, CIDRsList: &ipamv1alpha1.CIDRsList{},
			// The test server is on 127.0.0.1. A cap of 1 MiB makes the budget 30 MiB.
			SourceOptions: CIDRSourceOptions{AllowPrivateDestinations: true, MaxResponseBytes: 1 << 20},
		}
		logs := captureLogs(t)
		_, err := r.Reconcile(ctx, reconcile.Request{NamespacedName: client.ObjectKeyFromObject(cidrs)})
		require.NoError(t, err)
		got := &ipamv1alpha1.CIDRs{}
		require.NoError(t, c.Get(ctx, client.ObjectKeyFromObject(cidrs), got))
		return got, logs.String()
	}

	t.Run("a body of tiny values within the size cap is refused, and the last list stays", func(t *testing.T) {
		body := tinyNodes(1<<20 - 16) // just within the size cap
		got, logs := reconcileBody(t, body, ipamv1alpha1.Processing{})
		assert.Equal(t, ipamv1alpha1.CIDRsStateUpdateFailed, got.Status.State)
		assert.Equal(t, []string{"192.0.2.0/24"}, got.Status.CIDRs)
		require.Len(t, got.Status.Conditions, 1)
		assert.Contains(t, got.Status.Conditions[0].Message, "needs too much memory")
		assert.Contains(t, got.Status.Conditions[0].Message, "more than 30 MiB")
		assert.Contains(t, got.Status.Conditions[0].Message, "Use a smaller source, or ask the cluster admin", "the creator is told what to do")
		assert.Contains(t, logs, "processing-memory", "the log names the limit")
		// The admin is told what to change. Here no memory limit is set, so the factor set the budget.
		assert.Contains(t, logs, "raise --cidr-source-max-response-bytes together with the memory limit")
		assert.Contains(t, logs, "none (GOMEMLIMIT is not set)")
		assert.Contains(t, logs, "maxResponseBytes")
	})

	t.Run("with a small memory limit the admin is told to give it more memory", func(t *testing.T) {
		setMemoryLimit(t, 48<<20) // half of what is free is below 30 MiB, so the limit sets the budget
		got, logs := reconcileBody(t, tinyNodes(1<<20-16), ipamv1alpha1.Processing{})
		assert.Equal(t, ipamv1alpha1.CIDRsStateUpdateFailed, got.Status.State)
		assert.Equal(t, []string{"192.0.2.0/24"}, got.Status.CIDRs)
		assert.Contains(t, logs, "give the controller more memory")
		assert.Contains(t, logs, "48 MiB", "the log shows the memory limit")
	})

	t.Run("a real feed of the same size is fine", func(t *testing.T) {
		body, prefixes := awsLike(1<<20 - 256)
		got, _ := reconcileBody(t, body, ipamv1alpha1.Processing{CEL: `data.prefixes.map(p, p.ip_prefix)`})
		assert.Equal(t, ipamv1alpha1.CIDRsStateReady, got.Status.State)
		assert.Len(t, got.Status.CIDRs, prefixes)
	})
}
