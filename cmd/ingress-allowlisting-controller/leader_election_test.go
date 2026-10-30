package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	rbacv1 "k8s.io/api/rbac/v1"

	"github.com/adevinta/ingress-allowlisting-controller/pkg/controllers/writers"
)

// TestLeaderElectionPermissionsAreNamespaced verifies that the lease and leader election Events are
// checked in the leader election namespace only, and that a Role elsewhere doesn't count.
func TestLeaderElectionPermissionsAreNamespaced(t *testing.T) {
	l4, l7 := allWriters()
	features := allFeatures
	features.leaderElectionNamespace = "iac"
	var lease []writers.Permission
	for _, p := range requiredPermissions(features, l4, l7) {
		if p.Resource == "leases" {
			lease = append(lease, p)
		}
	}
	require.Len(t, lease, 3)
	for _, p := range lease {
		assert.Equal(t, "iac", p.Namespace, "%+v", p)
	}

	roleIn := func(ns string) roleRules {
		return roleRules{namespaced: map[string][]rbacv1.PolicyRule{ns: {{
			APIGroups: []string{"coordination.k8s.io"}, Resources: []string{"leases"}, Verbs: []string{"get", "create", "update"},
		}}}}
	}
	assert.True(t, granted(roleIn("iac"), lease[0]))
	assert.False(t, granted(roleIn("other"), lease[0]), "a Role in another namespace doesn't grant it")
}

func TestResolveLeaderElectionNamespace(t *testing.T) {
	file := filepath.Join(t.TempDir(), "namespace")
	require.NoError(t, os.WriteFile(file, []byte("iac-controller\n"), 0o600))
	orig := inClusterNamespaceFile
	inClusterNamespaceFile = file
	t.Cleanup(func() { inClusterNamespaceFile = orig })

	assert.Equal(t, "", resolveLeaderElectionNamespace(false, ""), "not needed without leader election")
	assert.Equal(t, "explicit", resolveLeaderElectionNamespace(true, "explicit"), "the flag wins")
	assert.Equal(t, "iac-controller", resolveLeaderElectionNamespace(true, ""), "the pod's own namespace")
}

func helmTemplate(t *testing.T, args ...string) (string, error) {
	t.Helper()
	if _, err := exec.LookPath("helm"); err != nil {
		t.Skip("helm not installed")
	}
	out, err := exec.Command("helm", append([]string{"template", "test", "../../helm-chart/ingress-allowlisting-controller"}, args...)...).CombinedOutput()
	return string(out), err
}

// TestChartHighAvailability verifies the chart's HA options: nothing extra by default, several
// replicas only with leader election, and then a Role for the lease and a PodDisruptionBudget.
func TestChartHighAvailability(t *testing.T) {
	t.Run("default: one replica, no leader election", func(t *testing.T) {
		out, err := helmTemplate(t)
		require.NoError(t, err)
		assert.NotContains(t, out, "--enable-leader-election")
		assert.NotContains(t, out, "kind: PodDisruptionBudget")
		assert.NotContains(t, out, "-leader-election")
	})

	t.Run("several replicas without leader election are refused", func(t *testing.T) {
		out, err := helmTemplate(t, "--set", "replicaCount=2")
		require.Error(t, err)
		assert.Contains(t, out, "all replicas would reconcile at the same time")
	})

	t.Run("leader election with one replica: no PodDisruptionBudget", func(t *testing.T) {
		out, err := helmTemplate(t, "--set", "leaderElection.enabled=true")
		require.NoError(t, err)
		assert.Contains(t, out, `- "--enable-leader-election"`)
		assert.Contains(t, out, "kind: Role\n")
		assert.NotContains(t, out, "kind: PodDisruptionBudget", "with one replica a PDB would block node drains")
	})

	t.Run("several replicas with leader election", func(t *testing.T) {
		out, err := helmTemplate(t, "--namespace", "iac", "--set", "replicaCount=2,leaderElection.enabled=true")
		require.NoError(t, err)
		assert.Contains(t, out, "kind: PodDisruptionBudget")
		assert.Contains(t, out, "maxUnavailable: 1")
		assert.Equal(t, 1, strings.Count(out, "kind: RoleBinding"))
	})
}
