package controllers

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"slices"
	"sort"
	"time"

	log "github.com/adevinta/go-log-toolkit"
	"github.com/prometheus/client_golang/prometheus"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/metrics"

	ipamv1alpha1 "github.com/adevinta/ingress-allowlisting-controller/pkg/apis/ipam.adevinta.com/v1alpha1"
)

// The apply delay (--cidr-source-apply-delay) is a defence against a compromised remote source,
// e.g. a feed whose host, repository or CDN was taken over to add the attacker's addresses. A CIDR
// new to the source is held in status.pending and only used once the delay has passed since it was
// first seen, and only if the source still returns it then. That leaves time to see the change
// (status.pending, the log, the pending_cidrs metric) and stop it before it opens access.
//
// Only additions wait. A CIDR the source drops is removed from status.cidrs right away: removing
// tightens access, and a range a provider gives up can soon belong to someone else.
//
// Only changes of the source's response wait. A change of the source in the spec (uri, cel,
// jsonPath, format) was made by whoever can edit the object, like spec.cidrs, so the new source's
// CIDRs are used right away. status.sourceHash tells the two apart: a redirect or new content
// behind the same uri is still a change of the response.
//
// The state is in the status, not in memory, so a restart or a new leader doesn't reset the clock
// and whoever can read the object can see what is waiting.

// pendingCIDRs is one series per CIDRs or ClusterCIDRs object with a remote source: how many CIDRs
// it holds back for --cidr-source-apply-delay.
var pendingCIDRs = prometheus.NewGaugeVec(
	prometheus.GaugeOpts{
		Namespace: "ingress_allowlisting_controller",
		Name:      "cidr_source_pending_cidrs",
		Help:      "Number of CIDRs the remote source of a CIDRs/ClusterCIDRs object added that wait for --cidr-source-apply-delay. status.pending lists them.",
	},
	[]string{"kind", "namespace", "name"})

func init() {
	metrics.Registry.MustRegister(pendingCIDRs)
}

// recordPending writes the series of one object: the number of CIDRs in pending. An object without
// a remote source has no series.
func recordPending(kind, namespace, name string, hasSource bool, pending []ipamv1alpha1.PendingCIDRs) {
	labels := prometheus.Labels{"kind": kind, "namespace": namespace, "name": name}
	if !hasSource {
		pendingCIDRs.Delete(labels)
		return
	}
	n := 0
	for _, p := range pending {
		n += len(p.CIDRs)
	}
	pendingCIDRs.With(labels).Set(float64(n))
}

// forgetPending removes the series of a deleted object.
func forgetPending(kind, namespace, name string) {
	pendingCIDRs.Delete(prometheus.Labels{"kind": kind, "namespace": namespace, "name": name})
}

// sourceHash is the hash stored in status.sourceHash: of the spec.location fields that say what is
// fetched and how it becomes CIDRs. headersFrom is left out: it says how to authenticate, and the
// Secrets it reads can change without the spec changing. Empty without a source.
func sourceHash(location ipamv1alpha1.CIDRsLocation) string {
	if location.URI == "" {
		return ""
	}
	format := location.Format
	if format == "" {
		format = ipamv1alpha1.YAML // the processor's default: unset and YAML are the same source
	}
	b, _ := json.Marshal([]string{location.URI, location.CEL, location.JSONPath, string(format)})
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:8])
}

// sourceChangedInSpec says whether the source in the spec is not the one status.cidrs was fetched
// with. An object without a hash yet (from before the field) has not changed: its next fetch
// records the hash, and its additions wait as usual.
func sourceChangedInSpec(old ipamv1alpha1.CIDRsStatus, location ipamv1alpha1.CIDRsLocation) bool {
	return old.SourceHash != "" && old.SourceHash != sourceHash(location)
}

// holdResult is what holdAdditions decided for one fetch.
type holdResult struct {
	// use are the CIDRs from the source to put in status.cidrs now.
	use []string
	// pending are the ones held back, grouped by when they were first seen, oldest first.
	pending []ipamv1alpha1.PendingCIDRs
	// added are the CIDRs held for the first time in this fetch, and applied the held ones whose
	// delay has passed: both for the log.
	added, applied []string
	// bySpec are the new CIDRs used right away because the source changed in the spec.
	bySpec []string
	// next is how soon the first pending CIDR is due; 0 when nothing is pending.
	next time.Duration
}

// holdAdditions splits the CIDRs a source returned into the ones used now and the ones held back
// for delay.
//
// A CIDR is used now if it is already in use (inUse, the current status.cidrs) or in spec.cidrs
// (inline), or if delay has passed since it was first seen. Its first-seen time comes from
// oldPending, or is now if it is new. A pending CIDR the source no longer returns is dropped: if it
// comes back, it waits again from then.
//
// Nothing is held when delay is 0, or for the first list of an object (inUse empty): there is
// nothing yet to compare with, and whoever just created the object is looking at it. Nothing is
// held either when specChanged: the source was changed in the spec, so its CIDRs are used like
// spec.cidrs, and what was pending for the old source is dropped.
func holdAdditions(remote, inline, inUse []string, oldPending []ipamv1alpha1.PendingCIDRs, delay time.Duration, now time.Time, specChanged bool) holdResult {
	if delay <= 0 || len(inUse) == 0 {
		return holdResult{use: remote}
	}
	if specChanged {
		result := holdResult{use: remote}
		known := map[string]bool{}
		for _, c := range append(slices.Clone(inUse), inline...) {
			known[c] = true
		}
		for _, c := range remote {
			if !known[c] {
				known[c] = true
				result.bySpec = append(result.bySpec, c)
			}
		}
		return result
	}
	// metav1.Time is stored to the second: truncate, so a time read back is the time written.
	now = now.Truncate(time.Second)

	known := make(map[string]bool, len(inUse)+len(inline))
	for _, c := range inUse {
		known[c] = true
	}
	for _, c := range inline {
		known[c] = true
	}
	firstSeen := map[string]time.Time{}
	for _, p := range oldPending {
		for _, c := range p.CIDRs {
			firstSeen[c] = p.FirstSeen.Time
		}
	}

	var result holdResult
	held := map[time.Time][]string{}
	seen := map[string]bool{}
	for _, c := range remote {
		if seen[c] {
			continue
		}
		seen[c] = true
		if known[c] {
			result.use = append(result.use, c)
			continue
		}
		since, ok := firstSeen[c]
		if !ok || since.After(now) {
			// New, or a first-seen time in the future (a clock that went back): it waits from now.
			since = now
			result.added = append(result.added, c)
		}
		if !now.Before(since.Add(delay)) {
			result.use = append(result.use, c)
			result.applied = append(result.applied, c)
			continue
		}
		held[since] = append(held[since], c)
	}

	for since, cidrs := range held {
		sort.Strings(cidrs)
		result.pending = append(result.pending, ipamv1alpha1.PendingCIDRs{
			FirstSeen:  metav1.NewTime(since),
			ApplyAfter: metav1.NewTime(since.Add(delay)),
			CIDRs:      cidrs,
		})
	}
	sort.Slice(result.pending, func(i, j int) bool {
		return result.pending[i].FirstSeen.Before(&result.pending[j].FirstSeen)
	})
	if len(result.pending) > 0 {
		result.next = result.pending[0].ApplyAfter.Sub(now)
	}
	return result
}

// pendingMessage is added to the UpToDate condition when CIDRs are held back.
func pendingMessage(pending []ipamv1alpha1.PendingCIDRs, delay time.Duration) string {
	n := 0
	for _, p := range pending {
		n += len(p.CIDRs)
	}
	return fmt.Sprintf("%d new CIDRs from the source wait for --cidr-source-apply-delay %s, the first until %s: see status.pending",
		n, delay, pending[0].ApplyAfter.UTC().Format(time.RFC3339))
}

// logHeld logs the CIDRs held for the first time and the ones used once their delay passed, so
// that a change of a source can be seen, and alerted on, before it is used.
func logHeld(ctx context.Context, fields map[string]interface{}, result holdResult, delay time.Duration) {
	logger := log.DefaultLogger.WithContext(ctx).WithFields(fields)
	if len(result.added) > 0 {
		logger.WithField("delay", delay.String()).
			Warnf("the CIDR source added %d CIDRs, held for --cidr-source-apply-delay: %s", len(result.added), quoteFirst(result.added, 20))
	}
	if len(result.applied) > 0 {
		logger.Infof("using %d CIDRs held for --cidr-source-apply-delay: %s", len(result.applied), quoteFirst(result.applied, 20))
	}
	if len(result.bySpec) > 0 {
		logger.Infof("the source changed in spec.location: using its %d new CIDRs without --cidr-source-apply-delay: %s", len(result.bySpec), quoteFirst(result.bySpec, 20))
	}
}
