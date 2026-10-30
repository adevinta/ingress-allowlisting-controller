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

// roleRules are the rules of the ClusterRoles (valid everywhere) and Roles (per namespace) of a
// YAML stream.
type roleRules struct {
	cluster    []rbacv1.PolicyRule
	namespaced map[string][]rbacv1.PolicyRule
}

func parseRoles(t *testing.T, stream []byte) roleRules {
	t.Helper()
	decoder := utilyaml.NewYAMLOrJSONDecoder(bytes.NewReader(stream), 4096)
	rr := roleRules{namespaced: map[string][]rbacv1.PolicyRule{}}
	for {
		var role rbacv1.ClusterRole // a Role has the same fields
		err := decoder.Decode(&role)
		if errors.Is(err, io.EOF) {
			return rr
		}
		require.NoError(t, err)
		switch role.Kind {
		case "ClusterRole":
			rr.cluster = append(rr.cluster, role.Rules...)
		case "Role":
			rr.namespaced[role.Namespace] = append(rr.namespaced[role.Namespace], role.Rules...)
		}
	}
}

// granted reports whether a ClusterRole grants p, or, for a permission needed in one namespace, a
// Role in that namespace.
func granted(rr roleRules, p writers.Permission) bool {
	resource := p.Resource
	if p.Subresource != "" {
		resource += "/" + p.Subresource
	}
	rules := rr.cluster
	if p.Namespace != "" {
		rules = append(slices.Clone(rules), rr.namespaced[p.Namespace]...)
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

func assertAllGranted(t *testing.T, rules roleRules) {
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
	assertAllGranted(t, parseRoles(t, role))
}

// TestRequiredPermissionsGrantedByChart verifies that the chart's ClusterRole and Roles, with every
// feature on, grant everything the preflight checks, the leader election lease and Events in the
// release namespace.
func TestRequiredPermissionsGrantedByChart(t *testing.T) {
	if _, err := exec.LookPath("helm"); err != nil {
		t.Skip("helm not installed")
	}
	const ns = "iac-test"
	out, err := exec.Command("helm", "template", "test", "../../helm-chart/ingress-allowlisting-controller", "--namespace", ns,
		"--set", "ingress.enabled=true,gateway.enabled=true,httproute.enabled=true,networkpolicy.enabled=true,service.enabled=true,httpHeadersEnabled=true,leaderElection.enabled=true").Output()
	require.NoError(t, err)

	rules := parseRoles(t, out)
	l4, l7 := allWriters()
	features := allFeatures
	features.leaderElectionNamespace = ns
	for _, p := range requiredPermissions(features, l4, l7) {
		assert.True(t, granted(rules, p), "not granted by the chart: %+v", p)
	}
	for _, r := range rules.cluster {
		assert.NotContains(t, r.Resources, "leases", "leases are granted per namespace, not cluster-wide")
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
