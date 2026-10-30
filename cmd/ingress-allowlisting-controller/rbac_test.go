package main

import (
	"bytes"
	"errors"
	"io"
	"os"
	"os/exec"
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	rbacv1 "k8s.io/api/rbac/v1"
	utilyaml "k8s.io/apimachinery/pkg/util/yaml"

	"github.com/adevinta/ingress-allowlisting-controller/pkg/controllers/writers"
	"github.com/adevinta/ingress-allowlisting-controller/pkg/resolvers"
)

var allFeatures = rbacFeatures{ingress: true, gateway: true, networkPolicy: true, service: true, httpRoute: true, httpHeaders: true, leaderElection: true}

// allWriters is every writer, as registered when both Istio and Traefik are installed.
func allWriters() (writers.L4WriterRegistry, writers.L7WriterRegistry) {
	resolver := resolvers.CidrResolver{AnnotationPrefix: resolvers.DefaultPrefix}
	return writers.L4WriterRegistry{writers.IstioControllerName: writers.NewIstioL4Writer(nil)},
		writers.L7WriterRegistry{
			writers.IstioControllerName:   writers.NewIstioL7Writer(nil, "test", resolver),
			writers.TraefikControllerName: writers.NewTraefikL7Writer(nil, "test", resolver),
		}
}

// clusterRoleRules decodes a YAML stream and returns the rules of its ClusterRoles.
func clusterRoleRules(t *testing.T, stream []byte) []rbacv1.PolicyRule {
	t.Helper()
	decoder := utilyaml.NewYAMLOrJSONDecoder(bytes.NewReader(stream), 4096)
	var rules []rbacv1.PolicyRule
	for {
		var role rbacv1.ClusterRole
		err := decoder.Decode(&role)
		if errors.Is(err, io.EOF) {
			return rules
		}
		require.NoError(t, err)
		if role.Kind == "ClusterRole" {
			rules = append(rules, role.Rules...)
		}
	}
}

func granted(rules []rbacv1.PolicyRule, p writers.Permission) bool {
	resource := p.Resource
	if p.Subresource != "" {
		resource += "/" + p.Subresource
	}
	for _, r := range rules {
		if (slices.Contains(r.APIGroups, p.Group) || slices.Contains(r.APIGroups, "*")) &&
			(slices.Contains(r.Resources, resource) || slices.Contains(r.Resources, "*")) &&
			(slices.Contains(r.Verbs, p.Verb) || slices.Contains(r.Verbs, "*")) {
			return true
		}
	}
	return false
}

func assertAllGranted(t *testing.T, rules []rbacv1.PolicyRule) {
	t.Helper()
	l4, l7 := allWriters()
	for _, p := range requiredPermissions(allFeatures, l4, l7) {
		assert.True(t, granted(rules, p), "not granted: %+v", p)
	}
}

// TestRequiredPermissionsGrantedByGeneratedRole verifies that the role generated from the
// kubebuilder markers (config/rbac, the kustomize path) grants everything the preflight checks.
func TestRequiredPermissionsGrantedByGeneratedRole(t *testing.T) {
	role, err := os.ReadFile("../../config/rbac/role.yaml")
	require.NoError(t, err)
	assertAllGranted(t, clusterRoleRules(t, role))
}

// TestRequiredPermissionsGrantedByChart verifies that the chart's ClusterRole, with every feature
// on, grants everything the preflight checks.
func TestRequiredPermissionsGrantedByChart(t *testing.T) {
	if _, err := exec.LookPath("helm"); err != nil {
		t.Skip("helm not installed")
	}
	out, err := exec.Command("helm", "template", "test", "../../helm-chart/ingress-allowlisting-controller",
		"--set", "ingress.enabled=true,gateway.enabled=true,httproute.enabled=true,networkpolicy.enabled=true,service.enabled=true,httpHeadersEnabled=true").Output()
	require.NoError(t, err)

	rules := clusterRoleRules(t, out)
	l4, l7 := allWriters()
	for _, p := range requiredPermissions(allFeatures, l4, l7) {
		if p.Resource == "leases" {
			continue // the chart doesn't support --enable-leader-election (single replica)
		}
		assert.True(t, granted(rules, p), "not granted by the chart: %+v", p)
	}
}

// TestRequiredPermissionsFollowFeatures verifies that disabled features add no permissions, and
// that watched resources need list and watch, not only get.
func TestRequiredPermissionsFollowFeatures(t *testing.T) {
	l4, l7 := allWriters()
	none := requiredPermissions(rbacFeatures{}, l4, l7)
	for _, p := range none {
		assert.NotContains(t, []string{"ingresses", "services", "networkpolicies", "httproutes", "gateways", "secrets", "leases", "authorizationpolicies", "middlewares"}, p.Resource, "%+v needs its feature", p)
	}

	all := requiredPermissions(allFeatures, l4, l7)
	for _, verb := range []string{"get", "list", "watch"} {
		assert.Contains(t, all, writers.Permission{Group: "networking.k8s.io", Resource: "ingresses", Verb: verb})
		assert.Contains(t, all, writers.Permission{Group: "ipam.adevinta.com", Resource: "cidrs", Verb: verb})
	}
	assert.Contains(t, all, writers.Permission{Group: "ipam.adevinta.com", Resource: "cidrs", Subresource: "status", Verb: "update"})
	assert.Contains(t, all, writers.Permission{Group: "gateway.networking.k8s.io", Resource: "httproutes", Verb: "patch"}, "the Traefik writer patches routes")
}
