package main

import (
	"bytes"
	"errors"
	"io"
	"os/exec"
	"testing"

	log "github.com/adevinta/go-log-toolkit"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	appsv1 "k8s.io/api/apps/v1"
	utilyaml "k8s.io/apimachinery/pkg/util/yaml"
)

// TestWarnIfNoDestination verifies the startup warning when no kind the controller writes
// allowlists to is enabled, and that one enabled kind is enough to silence it.
func TestWarnIfNoDestination(t *testing.T) {
	var buf bytes.Buffer
	out := log.DefaultLogger.Out
	log.DefaultLogger.SetOutput(&buf)
	t.Cleanup(func() { log.DefaultLogger.SetOutput(out) })

	warnIfNoDestination(rbacFeatures{httpHeaders: true, leaderElection: true})
	assert.Contains(t, buf.String(), `"level":"warning"`)
	assert.Contains(t, buf.String(), "no allowlist destination is enabled")

	for name, f := range map[string]rbacFeatures{
		"ingress":       {ingress: true},
		"gateway":       {gateway: true},
		"httpRoute":     {httpRoute: true},
		"networkPolicy": {networkPolicy: true},
		"service":       {service: true},
	} {
		buf.Reset()
		warnIfNoDestination(f)
		assert.Empty(t, buf.String(), "%s enabled: no warning", name)
	}
}

// TestChartDefaultsEnableNoDestination verifies that the chart, with its default values, enables
// no destination and no headersFrom (only CIDRs and ClusterCIDRs are reconciled), and so grants
// no access to the kinds they need, Secrets and ConfigMaps in particular.
func TestChartDefaultsEnableNoDestination(t *testing.T) {
	if _, err := exec.LookPath("helm"); err != nil {
		t.Skip("helm not installed")
	}
	out, err := exec.Command("helm", "template", "test", "../../helm-chart/ingress-allowlisting-controller").Output()
	require.NoError(t, err)

	decoder := utilyaml.NewYAMLOrJSONDecoder(bytes.NewReader(out), 4096)
	deployments := 0
	for {
		var deploy appsv1.Deployment
		err := decoder.Decode(&deploy)
		if errors.Is(err, io.EOF) {
			break
		}
		require.NoError(t, err)
		if deploy.Kind != "Deployment" {
			continue
		}
		deployments++
		require.NotEmpty(t, deploy.Spec.Template.Spec.Containers, "the Deployment has no containers")
		for _, arg := range deploy.Spec.Template.Spec.Containers[0].Args {
			assert.NotRegexp(t, `support-enabled|http-headers-enabled|label-selector`, arg)
		}
	}
	require.Equal(t, 1, deployments)

	for _, r := range parseRoles(t, out).cluster {
		for _, resource := range []string{"ingresses", "gateways", "httproutes", "networkpolicies", "services", "secrets", "configmaps", "authorizationpolicies", "middlewares"} {
			assert.NotContains(t, r.Resources, resource, "granted with the default values: %+v", r)
		}
	}
}
