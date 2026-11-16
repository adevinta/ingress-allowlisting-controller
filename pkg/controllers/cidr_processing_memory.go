package controllers

import (
	"errors"
	"fmt"
	"io"
	"math"
	"runtime"
	"runtime/debug"
	"runtime/metrics"
)

// A guard on the memory that processing one response may use.
//
// The size cap (--cidr-source-max-response-bytes) bounds the bytes of a response, not what it costs
// to decode: the YAML decoder builds a node tree and then the Go values, and that is about 13x the
// body for a real feed (AWS ip-ranges.json), but 70-110x for a body of many tiny values such as
// [[],[],[],...] (2-3 bytes per node, about 200 bytes of memory each). At the default 5 MiB cap
// that is 350-550 MiB, more than the pod has, and the pod is killed and killed again: every source
// is fetched at startup, so a single such object stops all allowlist updates until it is removed.
//
// GOMEMLIMIT can't help: it only makes the GC work harder, and the data is live. So the body is
// read through a guard that watches the heap while the decoder reads, and stops the fetch when
// processing needs more than a budget. It doesn't depend on the syntax of the body, which a count
// of values would. The budget is the smaller of
//
//   - processingMemoryFactor times the size cap: the "25-30x" the docs have always asked the pod to
//     have, now enforced, and
//   - half of the memory still free under the Go memory limit (GOMEMLIMIT, which the chart sets
//     from the container's limit): so a pod with little memory is protected too, and a feed that
//     doesn't fit it fails with a clear message instead of killing the pod.
//
// The guard sees the decoder read, so it bounds the node tree. The decoded values are allocated
// after the last read, about a fifth more, which the factor leaves room for.
const (
	// processingMemoryFactor is how many times the size cap the live heap may grow while a
	// response is processed.
	processingMemoryFactor = 30

	// minProcessingMemoryBudget is the smallest budget: a small feed must keep working when the
	// memory is nearly used up, as it needs a few MiB.
	minProcessingMemoryBudget = 16 << 20

	// processingMemoryCheckInterval is how many bytes the decoder reads between looks at the heap.
	// Between two looks the heap grows by at most this times about 110.
	processingMemoryCheckInterval = 64 << 10
)

var errProcessingMemory = errors.New("processing the response needs too much memory")

// processingMemoryError is the error of a response that needed more than its memory budget.
//
// Its text goes into the UpToDate condition, which is read by whoever wrote the object: it says
// what that person can do (a smaller source) and that the cluster admin can change the rest. The
// admin reads the log, which has what to change and the numbers (see reportLimitTripped): the
// fields below are for it.
type processingMemoryError struct {
	budget uint64
	// limitedByMemory says the budget is what the memory limit leaves (more memory raises it),
	// not 30 times the size cap (a higher --cidr-source-max-response-bytes raises it).
	limitedByMemory bool
	// memoryLimit is the Go memory limit, 0 when there is none; responseCap is the size cap.
	memoryLimit int64
	responseCap int64
}

func (e *processingMemoryError) Error() string {
	return fmt.Sprintf("%v: more than %d MiB of memory to decode (the response is too large, or has too many small values, for the memory of the controller). Use a smaller source, or ask the cluster admin: the controller log says what to change",
		errProcessingMemory, e.budget>>20)
}

// adminHint says what the admin of the controller can change to let this source through. It goes
// into the log, with memoryLimit and responseCap.
func (e *processingMemoryError) adminHint() string {
	if e.limitedByMemory {
		return "the memory limit leaves too little for it: give the controller more memory (the chart sets GOMEMLIMIT from the container's limit), or use a smaller source"
	}
	return fmt.Sprintf("it needs more than %dx the size of the response: use a smaller source, or raise --cidr-source-max-response-bytes together with the memory limit of the controller", processingMemoryFactor)
}

// memoryLimitText is the Go memory limit as shown in the log.
func (e *processingMemoryError) memoryLimitText() string {
	if e.memoryLimit <= 0 {
		return "none (GOMEMLIMIT is not set)"
	}
	return fmt.Sprintf("%d MiB", e.memoryLimit>>20)
}

func (e *processingMemoryError) Unwrap() error { return errProcessingMemory }

// readHeapMetric reads one uint64 metric of the runtime, 0 if this runtime doesn't have it (the
// guard is then off, never wrong).
func readHeapMetric(name string) uint64 {
	sample := []metrics.Sample{{Name: name}}
	metrics.Read(sample)
	if sample[0].Value.Kind() != metrics.KindUint64 {
		return 0
	}
	return sample[0].Value.Uint64()
}

// heapObjectsBytes is the memory of the heap objects now: the live ones and the dead ones the GC
// has not freed yet. It is current, unlike liveHeapBytes.
func heapObjectsBytes() uint64 { return readHeapMetric("/memory/classes/heap/objects:bytes") }

// liveHeapBytes is the memory of the objects the last GC found live; 0 before the first GC.
func liveHeapBytes() uint64 { return readHeapMetric("/gc/heap/live:bytes") }

// currentMemoryLimit is the Go memory limit, 0 when there is none (GOMEMLIMIT is not set).
func currentMemoryLimit() int64 {
	if limit := debug.SetMemoryLimit(-1); limit > 0 && limit < math.MaxInt64 { // -1 only reads it
		return limit
	}
	return 0
}

// processingMemoryBudget is how much the live heap may grow while a response of at most
// maxResponseBytes is processed, and whether it is the memory limit that sets it (and not the
// factor of the size cap).
func processingMemoryBudget(maxResponseBytes int64) (budget uint64, limitedByMemory bool) {
	budget = uint64(max(maxResponseBytes, 0)) * processingMemoryFactor
	if limit := currentMemoryLimit(); limit > 0 {
		inUse := liveHeapBytes()
		if inUse == 0 {
			inUse = heapObjectsBytes()
		}
		free := uint64(0)
		if uint64(limit) > inUse {
			free = uint64(limit) - inUse
		}
		if free/2 < budget {
			budget, limitedByMemory = free/2, true
		}
	}
	return max(budget, minProcessingMemoryBudget), limitedByMemory
}

// warnIfNoMemoryLimit warns at startup that the memory guard has only the factor of the size cap
// to go by. Called from LogEffective.
func warnIfNoMemoryLimit() {
	if currentMemoryLimit() == 0 {
		setupLog.Warnf("GOMEMLIMIT is not set: the guard on the memory a remote CIDR source may use counts only %dx --cidr-source-max-response-bytes, so a pod with less memory than that can still be killed by a source that needs more. Set GOMEMLIMIT to the container's memory limit (the chart does), and the guard adapts to it.", processingMemoryFactor)
	}
}

// processingMemoryGuard is a reader that fails once the heap has grown by more than the budget
// since it was made. See the comment at the top of the file. Like cappedBody, it keeps the failure
// in a flag as well, because a decoder may flatten the error of its reader into a string: the
// caller checks exceeded() after processing, whatever the parser returned.
type processingMemoryGuard struct {
	r      io.Reader
	budget uint64

	limitedByMemory bool
	memoryLimit     int64
	responseCap     int64

	baseLive   uint64 // live heap when the guard was made
	armAt      uint64 // the heap objects size from which to look closer
	sinceCheck int    // bytes read since the last look
	over       *processingMemoryError
}

func newProcessingMemoryGuard(r io.Reader, maxResponseBytes int64) *processingMemoryGuard {
	g := &processingMemoryGuard{r: r, memoryLimit: currentMemoryLimit(), responseCap: maxResponseBytes}
	g.budget, g.limitedByMemory = processingMemoryBudget(maxResponseBytes)
	objects := heapObjectsBytes()
	g.baseLive = liveHeapBytes()
	if g.baseLive == 0 {
		g.baseLive = objects // no GC has run yet: all that is there is an upper bound
	}
	g.armAt = objects + g.budget
	return g
}

func (g *processingMemoryGuard) Read(p []byte) (int, error) {
	if g.over != nil {
		return 0, g.over
	}
	n, err := g.r.Read(p)
	g.sinceCheck += n
	if g.sinceCheck >= processingMemoryCheckInterval {
		g.sinceCheck = 0
		if over := g.check(); over != nil {
			g.over = over
			return 0, over
		}
	}
	return n, err
}

// exceeded returns the error if the budget was used up.
func (g *processingMemoryGuard) exceeded() error {
	if g.over == nil {
		return nil
	}
	return g.over
}

// check looks at the heap. The size of the heap objects is cheap and current, but counts garbage
// the GC has not freed yet; the live size is exact, but only as of the last GC. So the garbage is
// not mistaken for data: only when the objects have grown by the budget does it run a GC and look
// at the live size. When that is below the budget, it was garbage, and the look is armed again for
// when what could be live reaches the budget (after an eighth of the budget at the earliest, so a
// body that makes much garbage doesn't make a GC every few KiB).
func (g *processingMemoryGuard) check() *processingMemoryError {
	if heapObjectsBytes() <= g.armAt {
		return nil
	}
	runtime.GC()
	var growth uint64
	if live := liveHeapBytes(); live > g.baseLive {
		growth = live - g.baseLive
	}
	if growth > g.budget {
		return &processingMemoryError{budget: g.budget, limitedByMemory: g.limitedByMemory, memoryLimit: g.memoryLimit, responseCap: g.responseCap}
	}
	g.armAt = heapObjectsBytes() + max(g.budget-growth, g.budget/8)
	return nil
}
