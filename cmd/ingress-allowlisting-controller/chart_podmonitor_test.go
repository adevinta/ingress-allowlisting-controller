package main

import (
	"os/exec"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"sigs.k8s.io/yaml"
)

// TestChartPodMonitorAdditionalLabels verifies that podMonitor.additionalLabels renders valid YAML
// and lands next to the name label, for one label and for several.
func TestChartPodMonitorAdditionalLabels(t *testing.T) {
	if _, err := exec.LookPath("helm"); err != nil {
		t.Skip("helm not installed")
	}
	out, err := exec.Command("helm", "template", "test", "../../helm-chart/ingress-allowlisting-controller",
		"--api-versions", "monitoring.coreos.com/v1/PodMonitor",
		"--show-only", "templates/podmonitor.yaml",
		"--set", "podMonitor.additionalLabels.release=prometheus-operator",
		"--set", "podMonitor.additionalLabels.team=platform",
	).Output()
	require.NoError(t, err)

	var podMonitor struct {
		Metadata struct {
			Labels map[string]string `json:"labels"`
		} `json:"metadata"`
	}
	require.NoError(t, yaml.Unmarshal(out, &podMonitor))
	assert.Equal(t, map[string]string{
		"app.kubernetes.io/name": "test",
		"release":                "prometheus-operator",
		"team":                   "platform",
	}, podMonitor.Metadata.Labels)
}
