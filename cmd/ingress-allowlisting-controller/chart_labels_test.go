package main

import (
	"os/exec"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	appsv1 "k8s.io/api/apps/v1"
	"sigs.k8s.io/yaml"
)

// TestChartLabels verifies that the labels value reaches the Deployment and its pods, and leaves the
// selector alone.
func TestChartLabels(t *testing.T) {
	if _, err := exec.LookPath("helm"); err != nil {
		t.Skip("helm not installed")
	}
	out, err := exec.Command("helm", "template", "test", "../../helm-chart/ingress-allowlisting-controller",
		"--show-only", "templates/deployment.yaml",
		"--set", "labels.team=platform",
	).Output()
	require.NoError(t, err)

	var deployment appsv1.Deployment
	require.NoError(t, yaml.Unmarshal(out, &deployment))
	assert.Equal(t, "platform", deployment.Labels["team"])
	assert.Equal(t, "platform", deployment.Spec.Template.Labels["team"])
	assert.Equal(t, map[string]string{"app.kubernetes.io/name": "test"}, deployment.Spec.Selector.MatchLabels)
}
