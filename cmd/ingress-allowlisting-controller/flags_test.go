package main

import (
	"flag"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStringListFlag(t *testing.T) {
	parse := func(t *testing.T, args ...string) stringListFlag {
		t.Helper()
		var list stringListFlag
		fs := flag.NewFlagSet("test", flag.ContinueOnError)
		fs.Var(&list, "cidr-source-allowlist", "")
		require.NoError(t, fs.Parse(args))
		return list
	}

	t.Run("the flag can be repeated", func(t *testing.T) {
		got := parse(t,
			"--cidr-source-allowlist=https://ip-ranges.amazonaws.com",
			"--cidr-source-allowlist=http://ip-ranges.amazonaws.com")
		assert.Equal(t, stringListFlag{"https://ip-ranges.amazonaws.com", "http://ip-ranges.amazonaws.com"}, got)
	})

	t.Run("values can be comma-separated", func(t *testing.T) {
		got := parse(t, "--cidr-source-allowlist=https://ip-ranges.amazonaws.com,http://ip-ranges.amazonaws.com")
		assert.Equal(t, stringListFlag{"https://ip-ranges.amazonaws.com", "http://ip-ranges.amazonaws.com"}, got)
	})

	t.Run("both forms combine and whitespace and empty parts are ignored", func(t *testing.T) {
		got := parse(t, "--cidr-source-allowlist= a.example.com , ,b.example.com,", "--cidr-source-allowlist=c.example.com")
		assert.Equal(t, stringListFlag{"a.example.com", "b.example.com", "c.example.com"}, got)
	})

	t.Run("not setting it leaves the list empty", func(t *testing.T) {
		assert.Empty(t, parse(t))
	})
}
