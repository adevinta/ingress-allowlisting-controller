package resolvers

import (
	"github.com/prometheus/client_golang/prometheus"
	"sigs.k8s.io/controller-runtime/pkg/metrics"
)

var (
	cidrsNotFound = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: "namespace",
			Subsystem: "ingress",
			Name:      "IpAllowlistingGroup_missing",
			Help:      "Number of missing IpAllowlistingGroup objects. >0 implies expected objects were not found",
		},
		[]string{"namespace", "object", "name", "cidrs_name"})
)

func init() {
	metrics.Registry.MustRegister(cidrsNotFound)
}

// ForgetObject removes the cidrsNotFound series of one object (kind as in the "object" label, e.g.
// "Ingress"). Call it when the object is deleted: no reconcile would update its series any more, so
// they would otherwise stay until a restart, e.g. as a missing-group alert that never clears.
func ForgetObject(namespace, kind, name string) {
	cidrsNotFound.DeletePartialMatch(prometheus.Labels{"namespace": namespace, "object": kind, "name": name})
}
