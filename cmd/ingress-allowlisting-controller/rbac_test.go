package main

import (
	"bytes"
	"errors"
	"io"
	"maps"
	"os"
	"os/exec"
	"slices"
	"strings"
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
	return writers.L4WriterRegistry{writers.IstioControllerName: writers.NewIstioL4Writer(nil, "ingress-allowlisting-controller", "ipam.adevinta.com")},
		writers.L7WriterRegistry{
			writers.IstioControllerName:   writers.NewIstioL7Writer(nil, "test", resolver),
			writers.TraefikControllerName: writers.NewTraefikL7Writer(nil, "test", resolver),
		}
}

// roleRules are the rules of the ClusterRoles (valid everywhere) and Roles (per namespace) of a
// YAML stream. The user roles (see isUserRole) are not the controller's: they are kept apart, by
// name.
type roleRules struct {
	cluster    []rbacv1.PolicyRule
	namespaced map[string][]rbacv1.PolicyRule
	users      map[string]rbacv1.ClusterRole
}

func parseRoles(t *testing.T, stream []byte) roleRules {
	t.Helper()
	decoder := utilyaml.NewYAMLOrJSONDecoder(bytes.NewReader(stream), 4096)
	rr := roleRules{namespaced: map[string][]rbacv1.PolicyRule{}, users: map[string]rbacv1.ClusterRole{}}
	for {
		var role rbacv1.ClusterRole // a Role has the same fields
		err := decoder.Decode(&role)
		if errors.Is(err, io.EOF) {
			return rr
		}
		require.NoError(t, err)
		switch {
		case role.Kind == "ClusterRole" && isUserRole(role):
			rr.users[role.Name] = role
		case role.Kind == "ClusterRole":
			rr.cluster = append(rr.cluster, role.Rules...)
		case role.Kind == "Role":
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
// kubebuilder markers (config/rbac/role.yaml, the reference for the chart's ClusterRole) grants
// everything the preflight checks.
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
		"--set", "ingress.enabled=true,gateway.enabled=true,httproute.enabled=true,networkpolicy.enabled=true,service.enabled=true,httpHeadersEnabled=true,cidrSource.allowlist={https://a.example.com},leaderElection.enabled=true").Output()
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

// isAggregated reports whether a ClusterRole is aggregated into a default role (edit, view, ...).
// isUserRole reports whether role is one of the chart's roles for users: aggregated into the
// default roles (edit, view, ...), or the ClusterCIDRs viewer, which is bound explicitly.
func isUserRole(role rbacv1.ClusterRole) bool {
	return isAggregated(role) || strings.HasSuffix(role.Name, "-clustercidrs-viewer")
}

func isAggregated(role rbacv1.ClusterRole) bool {
	for label := range role.Labels {
		if strings.HasPrefix(label, "rbac.authorization.k8s.io/aggregate-to-") {
			return true
		}
	}
	return false
}

// TestChartAggregatesOnlyCIDRsIntoDefaultRoles verifies that, with every feature on, the chart
// gives the holders of edit/admin only the CIDRs of their namespace and view only read access to
// them: none of the controller's own permissions (AuthorizationPolicies, Middlewares, CIDRs status,
// ClusterCIDRs, Secrets). Reading ClusterCIDRs is a separate role, not aggregated.
func TestChartAggregatesOnlyCIDRsIntoDefaultRoles(t *testing.T) {
	if _, err := exec.LookPath("helm"); err != nil {
		t.Skip("helm not installed")
	}
	out, err := exec.Command("helm", "template", "test", "../../helm-chart/ingress-allowlisting-controller",
		"--set", "ingress.enabled=true,gateway.enabled=true,httproute.enabled=true,networkpolicy.enabled=true,service.enabled=true,httpHeadersEnabled=true,cidrSource.allowlist={https://a.example.com},leaderElection.enabled=true").Output()
	require.NoError(t, err)

	users := parseRoles(t, out).users
	require.ElementsMatch(t, []string{"test-cidrs-editor", "test-cidrs-viewer", "test-clustercidrs-viewer"}, slices.Collect(maps.Keys(users)),
		"only the user roles are aggregated, not the controller's")

	editor := users["test-cidrs-editor"]
	assert.Equal(t, map[string]string{
		"rbac.authorization.k8s.io/aggregate-to-admin": "true",
		"rbac.authorization.k8s.io/aggregate-to-edit":  "true",
	}, editor.Labels)
	assert.Equal(t, []rbacv1.PolicyRule{{
		APIGroups: []string{"ipam.adevinta.com"},
		Resources: []string{"cidrs"},
		Verbs:     []string{"get", "list", "watch", "create", "update", "patch", "delete"},
	}}, editor.Rules)

	viewer := users["test-cidrs-viewer"]
	assert.Equal(t, map[string]string{"rbac.authorization.k8s.io/aggregate-to-view": "true"}, viewer.Labels)
	assert.Equal(t, []rbacv1.PolicyRule{{
		APIGroups: []string{"ipam.adevinta.com"},
		Resources: []string{"cidrs", "cidrs/status"},
		Verbs:     []string{"get", "list", "watch"},
	}}, viewer.Rules)

	// The admins' ClusterCIDRs: view bound cluster-wide must not show them to every reader.
	clusterViewer := users["test-clustercidrs-viewer"]
	assert.False(t, isAggregated(clusterViewer), "not aggregated, bound explicitly")
	assert.Equal(t, []rbacv1.PolicyRule{{
		APIGroups: []string{"ipam.adevinta.com"},
		Resources: []string{"clustercidrs", "clustercidrs/status"},
		Verbs:     []string{"get", "list", "watch"},
	}}, clusterViewer.Rules)
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

// grantedBeyond lists the group/resource/verb combinations the rules grant but the preflight never
// checks, so the code never uses them. Namespaces are not compared here: that the lease is granted
// per namespace is tested separately.
func grantedBeyond(rules []rbacv1.PolicyRule, required []writers.Permission) []string {
	need := map[string]bool{}
	for _, p := range required {
		resource := p.Resource
		if p.Subresource != "" {
			resource += "/" + p.Subresource
		}
		need[p.Group+" "+resource+" "+p.Verb] = true
	}
	var extra []string
	for _, r := range rules {
		for _, g := range r.APIGroups {
			for _, res := range r.Resources {
				for _, v := range r.Verbs {
					if !need[g+" "+res+" "+v] {
						extra = append(extra, g+" "+res+" "+v)
					}
				}
			}
		}
	}
	return extra
}

// TestRBACGrantsNothingBeyondWhatIsUsed verifies, the other way round from the tests above, that
// the chart's controller roles and the role generated from the kubebuilder markers grant nothing
// the controller doesn't use: least privilege, and no "just in case" rule creeping back in.
func TestRBACGrantsNothingBeyondWhatIsUsed(t *testing.T) {
	l4, l7 := allWriters()
	features := allFeatures
	features.leaderElectionNamespace = "iac-test"
	required := requiredPermissions(features, l4, l7)

	t.Run("generated role", func(t *testing.T) {
		role, err := os.ReadFile("../../config/rbac/role.yaml")
		require.NoError(t, err)
		assert.Empty(t, grantedBeyond(parseRoles(t, role).cluster, required))
	})

	t.Run("chart", func(t *testing.T) {
		if _, err := exec.LookPath("helm"); err != nil {
			t.Skip("helm not installed")
		}
		out, err := exec.Command("helm", "template", "test", "../../helm-chart/ingress-allowlisting-controller", "--namespace", "iac-test",
			"--set", "ingress.enabled=true,gateway.enabled=true,httproute.enabled=true,networkpolicy.enabled=true,service.enabled=true,httpHeadersEnabled=true,cidrSource.allowlist={https://a.example.com},leaderElection.enabled=true").Output()
		require.NoError(t, err)
		rules := parseRoles(t, out)
		all := slices.Clone(rules.cluster)
		for _, namespaced := range rules.namespaced {
			all = append(all, namespaced...)
		}
		assert.Empty(t, grantedBeyond(all, required))
	})
}
