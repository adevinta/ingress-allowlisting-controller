//go:build functional

package functional

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// These tests cover the suite's own helpers and need no cluster:
//   go test -tags functional -run 'Flag|Origin|Expected' ./test/functional/

func TestControllerFlagValues(t *testing.T) {
	c := controllerInfo{Args: []string{
		"/manager",
		"--networkpolicy-support-enabled",
		"--ingress-support-enabled=false",
		"--annotation-prefix", "ipam.example.com",
		"-cidr-source-allowlist=https://a.example.com,b.example.com",
		"--cidr-source-allowlist=c.example.com",
		"--http-headers-enabled", "not-a-value-of-a-bool-flag",
	}}

	assert.True(t, c.enabled("networkpolicy-support-enabled", false), "bare bool flag")
	assert.False(t, c.enabled("ingress-support-enabled", true), "=false")
	assert.True(t, c.enabled("service-support-enabled", true), "unset flag keeps its default")
	assert.False(t, c.enabled("gateway-support-enabled", false))
	assert.Equal(t, "ipam.example.com", c.flag("annotation-prefix", defaultAnnotationPrefix), "separate value")
	assert.Equal(t, []string{"https://a.example.com,b.example.com", "c.example.com"}, c.flagValues("cidr-source-allowlist"), "single dash and repeats")
	assert.True(t, c.enabled("http-headers-enabled", false), "a bool flag never takes the next argument")
}

func TestControllerAllowsOrigin(t *testing.T) {
	open := controllerInfo{}
	assert.True(t, open.allowsOrigin("https://ip-ranges.amazonaws.com/ip-ranges.json"), "empty allowlist allows any host")

	c := controllerInfo{Args: []string{"--cidr-source-allowlist=ip-ranges.amazonaws.com,http://plain.example.com", "--cidr-source-allowlist=https://feeds.example.com:443"}}
	assert.True(t, c.allowsOrigin("https://ip-ranges.amazonaws.com/ip-ranges.json"), "bare host means https")
	assert.True(t, c.allowsOrigin("https://feeds.example.com/?x=1"), "default port is ignored")
	assert.True(t, c.allowsOrigin("http://plain.example.com/list.csv"))
	assert.False(t, c.allowsOrigin("http://ip-ranges.amazonaws.com/ip-ranges.json"), "the scheme is part of the origin")
	assert.False(t, c.allowsOrigin("https://techdocs.akamai.com/x.csv"))
}

func TestExpectedAllowlist(t *testing.T) {
	assert.Equal(t,
		[]string{"10.0.0.0/8", "192.0.2.0/24", "198.51.100.7/32"},
		expectedAllowlist([]string{"198.51.100.7/32", "10.1.2.3/8", "not-a-cidr"}, []string{"192.0.2.0/24", "10.0.0.0/8"}),
		"normalised to the network address, deduplicated across objects, sorted, invalid entries dropped")
	assert.Equal(t, []string{denyAll}, expectedAllowlist(), "nothing valid means deny-all")
	assert.Equal(t, []string{denyAll}, expectedAllowlist([]string{"junk"}))
}
