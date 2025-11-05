package controllers

import (
	netv1 "k8s.io/api/networking/v1"
)

func extractCIDRs(rules interface{}) map[string]bool {
	cidrsFound := make(map[string]bool)

	switch v := rules.(type) {
	case []netv1.NetworkPolicyIngressRule:
		for _, rule := range v {
			for _, peer := range rule.From {
				if peer.IPBlock != nil {
					cidrsFound[peer.IPBlock.CIDR] = true
				}
			}
		}
	case []netv1.NetworkPolicyEgressRule:
		for _, rule := range v {
			for _, peer := range rule.To {
				if peer.IPBlock != nil {
					cidrsFound[peer.IPBlock.CIDR] = true
				}
			}
		}
	default:
		panic("extractCIDRs: unsupported type")
	}

	return cidrsFound
}
