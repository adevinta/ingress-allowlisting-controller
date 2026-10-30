package main

import (
	"bytes"
	"errors"
	"io"
	"os/exec"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	networkingv1 "k8s.io/api/networking/v1"
	utilyaml "k8s.io/apimachinery/pkg/util/yaml"
)

// chartNetworkPolicies renders the chart with the given --set/--set-json arguments and returns its
// NetworkPolicies.
func chartNetworkPolicies(t *testing.T, args ...string) []networkingv1.NetworkPolicy {
	t.Helper()
	if _, err := exec.LookPath("helm"); err != nil {
		t.Skip("helm not installed")
	}
	out, err := exec.Command("helm", append([]string{"template", "test", "../../helm-chart/ingress-allowlisting-controller"}, args...)...).Output()
	require.NoError(t, err)
	decoder := utilyaml.NewYAMLOrJSONDecoder(bytes.NewReader(out), 4096)
	var policies []networkingv1.NetworkPolicy
	for {
		var np networkingv1.NetworkPolicy
		err := decoder.Decode(&np)
		if errors.Is(err, io.EOF) {
			return policies
		}
		require.NoError(t, err)
		if np.Kind == "NetworkPolicy" {
			policies = append(policies, np)
		}
	}
}

func ports(rule networkingv1.NetworkPolicyIngressRule) []int32 {
	var out []int32
	for _, p := range rule.Ports {
		out = append(out, p.Port.IntVal)
	}
	return out
}

// TestChartPodNetworkPolicy verifies the opt-in NetworkPolicy of the controller pod: off by default,
// probes always reachable, metrics only from podNetworkPolicy.metricsFrom.
func TestChartPodNetworkPolicy(t *testing.T) {
	t.Run("off by default", func(t *testing.T) {
		assert.Empty(t, chartNetworkPolicies(t))
	})

	t.Run("on without metricsFrom: only the probes are reachable", func(t *testing.T) {
		policies := chartNetworkPolicies(t, "--set", "podNetworkPolicy.enabled=true")
		require.Len(t, policies, 1)
		np := policies[0]
		assert.Equal(t, []networkingv1.PolicyType{networkingv1.PolicyTypeIngress}, np.Spec.PolicyTypes, "ingress only")
		assert.Equal(t, map[string]string{"app.kubernetes.io/name": "test"}, np.Spec.PodSelector.MatchLabels)
		require.Len(t, np.Spec.Ingress, 1)
		assert.Equal(t, []int32{8081}, ports(np.Spec.Ingress[0]))
		assert.Empty(t, np.Spec.Ingress[0].From, "probes from anywhere")
	})

	t.Run("on with metricsFrom: metrics only from those peers", func(t *testing.T) {
		policies := chartNetworkPolicies(t, "--set", "podNetworkPolicy.enabled=true",
			"--set-json", `podNetworkPolicy.metricsFrom=[{"namespaceSelector":{"matchLabels":{"kubernetes.io/metadata.name":"monitoring"}}}]`)
		require.Len(t, policies, 1)
		require.Len(t, policies[0].Spec.Ingress, 2)
		metrics := policies[0].Spec.Ingress[1]
		assert.Equal(t, []int32{8080}, ports(metrics))
		require.Len(t, metrics.From, 1)
		assert.Equal(t, map[string]string{"kubernetes.io/metadata.name": "monitoring"}, metrics.From[0].NamespaceSelector.MatchLabels)
	})
}
