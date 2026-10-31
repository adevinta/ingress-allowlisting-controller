package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestValidateHTTPHeaders verifies that --http-headers-enabled is refused without a Secret label
// selector or an origin allowlist, and names what is missing.
func TestValidateHTTPHeaders(t *testing.T) {
	allowlist := []string{"https://ip-ranges.amazonaws.com"}

	assert.NoError(t, validateHTTPHeaders(false, "", nil), "nothing is required while it is off")
	assert.NoError(t, validateHTTPHeaders(true, "ipam.adevinta.com/cidr-header-source=true", allowlist))

	assert.EqualError(t, validateHTTPHeaders(true, "", allowlist),
		"--http-headers-enabled requires --secret-label-selector (only labelled Secrets and ConfigMaps can be read)")
	assert.EqualError(t, validateHTTPHeaders(true, "  ", allowlist),
		"--http-headers-enabled requires --secret-label-selector (only labelled Secrets and ConfigMaps can be read)", "blank is empty")
	assert.EqualError(t, validateHTTPHeaders(true, "a=b", nil),
		"--http-headers-enabled requires --cidr-source-allowlist (header values only go to listed origins)")
	assert.EqualError(t, validateHTTPHeaders(true, "", nil),
		"--http-headers-enabled requires --secret-label-selector (only labelled Secrets and ConfigMaps can be read) and --cidr-source-allowlist (header values only go to listed origins)")
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
