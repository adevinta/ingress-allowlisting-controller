package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestValidateHTTPHeaders verifies that --http-headers-enabled is refused without an origin
// allowlist.
func TestValidateHTTPHeaders(t *testing.T) {
	assert.NoError(t, validateHTTPHeaders(false, nil), "nothing is required while it is off")
	assert.NoError(t, validateHTTPHeaders(true, []string{"https://ip-ranges.amazonaws.com"}))
	assert.EqualError(t, validateHTTPHeaders(true, nil),
		"--http-headers-enabled requires --cidr-source-allowlist (header values only go to listed origins)")
}

// TestDefaultSecretLabelSelector verifies that the Secrets and ConfigMaps readable as headers are
// always restricted by a label, by default one under the annotation prefix.
func TestDefaultSecretLabelSelector(t *testing.T) {
	assert.Equal(t, "example.com/cidr-header-source=true", defaultSecretLabelSelector(true, "", "example.com"), "follows --annotation-prefix")
	assert.Equal(t, "ipam.adevinta.com/cidr-header-source=true", defaultSecretLabelSelector(true, "  ", "ipam.adevinta.com"), "blank is unset")
	assert.Equal(t, "team=platform", defaultSecretLabelSelector(true, "team=platform", "example.com"), "the flag wins")
	assert.Equal(t, "", defaultSecretLabelSelector(false, "", "example.com"), "unused while headers are off")
}

// TestResolveClusterHeadersNamespace verifies that ClusterCIDRs read headersFrom from the flag
// value, or else from the controller's own namespace, and from none outside a cluster.
func TestResolveClusterHeadersNamespace(t *testing.T) {
	file := filepath.Join(t.TempDir(), "namespace")
	orig := inClusterNamespaceFile
	inClusterNamespaceFile = file
	t.Cleanup(func() { inClusterNamespaceFile = orig })

	assert.Equal(t, "", resolveClusterHeadersNamespace(true, ""), "not in a cluster: no namespace")

	assert.NoError(t, os.WriteFile(file, []byte("ingress-allowlisting\n"), 0o600))
	assert.Equal(t, "ingress-allowlisting", resolveClusterHeadersNamespace(true, ""), "the controller's own namespace")
	assert.Equal(t, "team-x", resolveClusterHeadersNamespace(true, "team-x"), "the flag wins")
	assert.Equal(t, "", resolveClusterHeadersNamespace(false, ""), "unused while headers are off")
	assert.Equal(t, "", resolveClusterHeadersNamespace(false, "team-x"), "even when the flag is set")
}
