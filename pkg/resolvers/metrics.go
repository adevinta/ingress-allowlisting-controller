package resolvers

import (
	"github.com/prometheus/client_golang/prometheus"
	"sigs.k8s.io/controller-runtime/pkg/metrics"
)

// legacyMetricMaxGroups caps the series of the deprecated metric per object: its cidrs_name label
// comes from annotation values, so an annotation listing hundreds of names would otherwise create
// hundreds of series.
const legacyMetricMaxGroups = 10

var (
	// missingCIDRs is one series per annotated object: how many of the groups it names are missing
	// or have no CIDRs. Which ones is in the object's AllowlistGroupNotFound Events, not in a
	// label: label values must not come from user input.
	missingCIDRs = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: "ingress_allowlisting_controller",
			Name:      "missing_cidrs",
			Help:      "Number of CIDRs/ClusterCIDRs groups named in the object's allowlist annotations that are missing or have no CIDRs. The object's AllowlistGroupNotFound Events name them.",
		},
		[]string{"namespace", "kind", "name"})

	// cidrsNotFound is the deprecated per-group metric, kept for existing dashboards and alerts
	// until v0.3.0. At most legacyMetricMaxGroups series per object, missing groups first.
	cidrsNotFound = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: "namespace",
			Subsystem: "ingress",
			Name:      "IpAllowlistingGroup_missing",
			Help:      "Deprecated, removed in v0.3.0: use ingress_allowlisting_controller_missing_cidrs. 1 if the named CIDRs group is missing or empty, else 0; at most 10 groups per object, missing ones first.",
		},
		[]string{"namespace", "object", "name", "cidrs_name"})
)

func init() {
	metrics.Registry.MustRegister(missingCIDRs, cidrsNotFound)
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
	var missingNames, foundNames []string
	for _, g := range groups {
		if seen[g] {
			continue // the same group named twice
		}
		seen[g] = true
		if g.missing {
			missing++
			missingNames = append(missingNames, g.name)
		} else {
			foundNames = append(foundNames, g.name)
		}
	}
	missingCIDRs.With(prometheus.Labels{"namespace": namespace, "kind": kind, "name": name}).Set(float64(missing))

	// The legacy series: missing groups first, so a missing-group alert is never capped away.
	written := 0
	for _, set := range []struct {
		names []string
		value float64
	}{{missingNames, 1}, {foundNames, 0}} {
		for _, n := range set.names {
			if written == legacyMetricMaxGroups {
				return
			}
			cidrsNotFound.With(prometheus.Labels{"namespace": namespace, "object": kind, "name": name, "cidrs_name": n}).Set(set.value)
			written++
		}
	}
}

// ForgetObject removes the series of one object (kind as in the "object" label, e.g. "Ingress").
// Call it when the object is deleted: no reconcile would update its series any more, so they would
// otherwise stay until a restart, e.g. as a missing-group alert that never clears.
func ForgetObject(namespace, kind, name string) {
	missingCIDRs.DeletePartialMatch(prometheus.Labels{"namespace": namespace, "kind": kind, "name": name})
	cidrsNotFound.DeletePartialMatch(prometheus.Labels{"namespace": namespace, "object": kind, "name": name})
}
