package controllers

import (
	"github.com/adevinta/ingress-allowlisting-controller/pkg/controllers/writers"
	"github.com/adevinta/ingress-allowlisting-controller/pkg/resolvers"
)

// crossName is the name of the policy of route routeNS/route on Gateway gw of another namespace,
// for a rule with paths (see writers.CrossNamespacePolicyName).
func crossName(routeNS, gw, route string, paths ...string) string {
	return writers.CrossNamespacePolicyName(resolvers.DefaultPrefix, routeNS, gw, route, paths)
}

// mergedName is the name of the merged policy of group key on Gateway gw.
func mergedName(gw, key string) string {
	return writers.MergedPolicyName(resolvers.DefaultPrefix, gw, key)
}
