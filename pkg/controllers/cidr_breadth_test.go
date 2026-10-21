package controllers

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestGuardExternalBreadth_AllowsRealFeedMasks verifies the widest real prefixes from
// the AWS and Akamai feeds pass. The widest observed is /11 (IPv4, AWS & Akamai) and
// /24 (IPv6, Akamai; AWS tops out at /32) — all narrower than the /8 and /20 defaults.
func TestGuardExternalBreadth_AllowsRealFeedMasks(t *testing.T) {
	assert.NoError(t, guardExternalBreadth([]string{
		"44.192.0.0/11",  // AWS's widest IPv4 block
		"2406:da1e::/32", // AWS's widest IPv6 block
		"2600:1400::/24", // Akamai's widest IPv6 block
		"52.94.0.0/16",
		"2600:1f00::/40",
	}, 0, 0))
}

// TestGuardExternalBreadth_AllowsTypicalAllowlist verifies ordinary narrow allowlists pass.
func TestGuardExternalBreadth_AllowsTypicalAllowlist(t *testing.T) {
	assert.NoError(t, guardExternalBreadth([]string{
		"10.0.0.0/8",     // exactly at the v4 limit
		"192.168.0.0/16",
		"203.0.113.5/32",
		"2001:db8::/48",
	}, 0, 0))
}

// TestGuardExternalBreadth_BareIPs verifies bare addresses count as /32 or /128 and pass.
func TestGuardExternalBreadth_BareIPs(t *testing.T) {
	assert.NoError(t, guardExternalBreadth([]string{"203.0.113.5", "2001:db8::1"}, 0, 0))
}

// TestGuardExternalBreadth_RejectsDefaultRoute verifies the whole-space blunder is rejected.
func TestGuardExternalBreadth_RejectsDefaultRoute(t *testing.T) {
	assert.Error(t, guardExternalBreadth([]string{"0.0.0.0/0"}, 0, 0),
		"0.0.0.0/0 must be rejected")
	assert.Error(t, guardExternalBreadth([]string{"::/0"}, 0, 0),
		"::/0 must be rejected")
}

// TestGuardExternalBreadth_RejectsTooWide verifies any single prefix wider than the
// limit is rejected, including the split-range blocks (/1, /3) since their masks are
// themselves too wide.
func TestGuardExternalBreadth_RejectsTooWide(t *testing.T) {
	for _, c := range []string{"0.0.0.0/1", "0.0.0.0/3", "10.0.0.0/7", "2000::/3", "2001:db8::/19"} {
		assert.Error(t, guardExternalBreadth([]string{c}, 0, 0), "%s must be rejected", c)
	}
}

// TestGuardExternalBreadth_RejectsOneBadEntryAmongGood verifies a single over-broad
// entry mixed into an otherwise-fine set trips the guard.
func TestGuardExternalBreadth_RejectsOneBadEntryAmongGood(t *testing.T) {
	assert.Error(t, guardExternalBreadth([]string{
		"10.0.0.0/8", "192.168.0.0/16", "0.0.0.0/2", "172.16.0.0/12",
	}, 0, 0))
}

// TestGuardExternalBreadth_RejectsV4Mapped verifies IPv4-mapped IPv6 prefixes are measured in
// IPv4 space, so a mapped block that covers all of IPv4 is rejected rather than read as a narrow
// /96. ::ffff:0.0.0.0/96 covers the entire IPv4 range; ::ffff:0.0.0.0/104 is the mapped /8 limit.
func TestGuardExternalBreadth_RejectsV4Mapped(t *testing.T) {
	assert.Error(t, guardExternalBreadth([]string{"::ffff:0.0.0.0/96"}, 0, 0),
		"::ffff:0.0.0.0/96 covers all of IPv4 and must be rejected")
	assert.Error(t, guardExternalBreadth([]string{"::ffff:0.0.0.0/100"}, 0, 0),
		"::ffff:0.0.0.0/100 (mapped /4) must be rejected")
	assert.NoError(t, guardExternalBreadth([]string{"::ffff:10.0.0.0/104"}, 0, 0),
		"::ffff:10.0.0.0/104 (mapped /8) is exactly at the limit and must pass")
}

// TestGuardExternalBreadth_IgnoresInvalidEntries verifies non-CIDR, non-IP entries are skipped.
func TestGuardExternalBreadth_IgnoresInvalidEntries(t *testing.T) {
	assert.NoError(t, guardExternalBreadth([]string{"not-a-cidr", "", "10.0.0.0/8"}, 0, 0))
}

// TestGuardExternalBreadth_CustomMasks verifies operator-supplied limits override defaults.
func TestGuardExternalBreadth_CustomMasks(t *testing.T) {
	// Tighten IPv4 to /16: a /8 now fails, a /16 passes.
	assert.Error(t, guardExternalBreadth([]string{"10.0.0.0/8"}, 16, 0),
		"/8 must fail a /16 minimum")
	assert.NoError(t, guardExternalBreadth([]string{"10.1.0.0/16"}, 16, 0),
		"/16 must pass a /16 minimum")
	// v6 limit is independent.
	assert.Error(t, guardExternalBreadth([]string{"2001:db8::/40"}, 0, 48),
		"/40 must fail a /48 minimum")
}

// TestPrefixLen verifies mask/family extraction for CIDRs and bare IPs.
func TestPrefixLen(t *testing.T) {
	cases := []struct {
		in   string
		ones int
		is4  bool
		ok   bool
	}{
		{"10.0.0.0/8", 8, true, true},
		{"0.0.0.0/0", 0, true, true},
		{"203.0.113.5", 32, true, true},
		{"203.0.113.5/32", 32, true, true},
		{"2001:db8::/48", 48, false, true},
		{"::/0", 0, false, true},
		{"2001:db8::1", 128, false, true},
		{"::ffff:0.0.0.0/96", 0, true, true},    // mapped: all of IPv4 → /0 in v4 space
		{"::ffff:10.0.0.0/104", 8, true, true},  // mapped: /8 in v4 space
		{"garbage", 0, false, false},
	}
	for _, c := range cases {
		ones, is4, ok := prefixLen(c.in)
		assert.Equal(t, c.ok, ok, "ok mismatch for %q", c.in)
		if c.ok {
			assert.Equal(t, c.ones, ones, "ones mismatch for %q", c.in)
			assert.Equal(t, c.is4, is4, "family mismatch for %q", c.in)
		}
	}
}
