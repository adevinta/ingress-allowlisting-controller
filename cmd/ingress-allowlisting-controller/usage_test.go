package main

import (
	"bytes"
	"flag"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFlagGroupRecordsOnlyTheFlagsItRegisters(t *testing.T) {
	flag.Bool("usage-test-before", false, "registered outside any group")
	flagGroup("Test group", func() {
		flag.Bool("usage-test-inside-b", false, "")
		flag.String("usage-test-inside-a", "", "")
	})

	assert.Equal(t, "Test group", flagGroups["usage-test-inside-a"])
	assert.Equal(t, "Test group", flagGroups["usage-test-inside-b"])
	assert.NotContains(t, flagGroups, "usage-test-before")
}

func TestPrintUsage(t *testing.T) {
	var out bytes.Buffer
	fs := flag.NewFlagSet("controller", flag.ContinueOnError)
	fs.SetOutput(&out)
	fs.Bool("service-support-enabled", false, "Enable Service support")
	fs.Duration("cidr-source-fetch-timeout", 30*time.Second, "Fetch timeout")
	fs.Bool("http-headers-enabled", true, "Enable headers")
	fs.String("metrics-addr", ":8080", "Metrics address")
	fs.String("kubeconfig", "", "Not grouped, like the controller-runtime flag")
	groups := map[string]string{
		"service-support-enabled":   "Service",
		"cidr-source-fetch-timeout": "CIDRs",
		"http-headers-enabled":      "CIDRs",
	}

	printUsage(fs, groups)
	got := out.String()

	t.Run("General first, then groups alphabetically, flags alphabetically within a group", func(t *testing.T) {
		assertInOrder(t, got,
			"# General", "-kubeconfig", "-metrics-addr",
			"# CIDRs", "-cidr-source-fetch-timeout", "-http-headers-enabled",
			"# Service", "-service-support-enabled",
		)
	})

	t.Run("each flag keeps the flag package format, including defaults", func(t *testing.T) {
		assert.Contains(t, got, "  -cidr-source-fetch-timeout duration\n    \tFetch timeout (default 30s)\n")
		assert.Contains(t, got, "  -http-headers-enabled\n    \tEnable headers (default true)\n")
		assert.Contains(t, got, "  -service-support-enabled\n    \tEnable Service support\n", "zero defaults are not printed")
	})

	t.Run("the default is printed even after the flag was set", func(t *testing.T) {
		out.Reset()
		require.NoError(t, fs.Set("cidr-source-fetch-timeout", "1m"))
		printUsage(fs, groups)
		assert.Contains(t, out.String(), "Fetch timeout (default 30s)")
	})
}

func assertInOrder(t *testing.T, s string, parts ...string) {
	t.Helper()
	pos := 0
	for _, p := range parts {
		i := strings.Index(s[pos:], p)
		if !assert.GreaterOrEqual(t, i, 0, "%q missing or out of order in:\n%s", p, s) {
			return
		}
		pos += i + len(p)
	}
}
