package resolvers

import (
	"github.com/prometheus/client_golang/prometheus"
	"sigs.k8s.io/controller-runtime/pkg/metrics"
)

// missingCIDRs is one series per annotated object: how many of the groups it names are missing
// or have no CIDRs. Which ones is in the object's AllowlistGroupNotFound Events, not in a
// label: label values must not come from user input.
var missingCIDRs = prometheus.NewGaugeVec(
	prometheus.GaugeOpts{
		Namespace: "ingress_allowlisting_controller",
		Name:      "missing_cidrs",
		Help:      "Number of CIDRs/ClusterCIDRs groups named in the object's allowlist annotations that are missing or have no CIDRs. The object's AllowlistGroupNotFound Events name them.",
	},
	[]string{"namespace", "kind", "name"})

// The per-group metric namespace_ingress_IpAllowlistingGroup_missing was removed in v0.3.0 (its
// cidrs_name label came from annotation values): see docs/metrics.md for the replacement queries.

func init() {
	metrics.Registry.MustRegister(missingCIDRs)
}

// groupResult is how one group named in an object's annotations resolved.
type groupResult struct {
	kind, name string // kind of the group (NamespacedCIDRs or ClusterCIDRs) and its name
	missing    bool   // missing, empty, or failed to resolve
}

// recordGroupMetrics writes the series of one object from the groups its annotations name.
func recordGroupMetrics(namespace, kind, name string, groups []groupResult) {
	missing := 0
	seen := map[groupResult]bool{}
	for _, g := range groups {
		if seen[g] {
			continue // the same group named twice
		}
		seen[g] = true
		if g.missing {
			missing++
		}
	}
	missingCIDRs.With(prometheus.Labels{"namespace": namespace, "kind": kind, "name": name}).Set(float64(missing))
}

// ForgetObject removes the series of one object (kind as in the "kind" label, e.g. "Ingress").
// Call it when the object is deleted: no reconcile would update its series any more, so they would
// otherwise stay until a restart, e.g. as a missing-group alert that never clears.
func ForgetObject(namespace, kind, name string) {
	missingCIDRs.DeletePartialMatch(prometheus.Labels{"namespace": namespace, "kind": kind, "name": name})
}
