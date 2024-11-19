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
