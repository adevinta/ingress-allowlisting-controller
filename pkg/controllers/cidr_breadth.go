package controllers

import (
	"fmt"
	"net"
)

// Breadth guard for EXTERNAL (HTTP-fetched) CIDR sources.
//
// We trust the sources we fetch from (AWS, Akamai, ...). This guard is NOT an
// attacker defence: a well-tailored /32 from a trusted feed is allowed by design,
// and there is no defending against a source you have chosen to trust. What it
// protects against is human mistakes — a source that breaks or changes format, a
// CEL/JSONPath expression that misfires, or a feed misconfigured to hand back a
// far broader range than intended (0.0.0.0/0, a /1, a /3, ...).
//
// To catch that, every externally-fetched prefix must be no wider than a minimum
// mask, per address family; anything wider is rejected.
//
// This is deliberately a per-entry mask check, not an address-count/union
// computation: it is O(n) with no sorting and no big-integer math, and it
// catches every single-block blunder — the realistic failure mode. It does NOT
// sum coverage, so it will not catch an aggregate built from many individually-
// narrow blocks; that is an accepted trade-off.
//
// This applies ONLY to CIDRs fetched from a remote source. Inline spec.cidrs
// authored by a cluster admin is never subject to this cap — an admin may
// deliberately allow 0.0.0.0/0.
//
// Defaults are calibrated against real provider feeds. The widest single prefix
// observed is /11 for IPv4 (both AWS and Akamai) and /24 for IPv6 (Akamai; AWS
// tops out at /32). The defaults sit a few bits wider than that to leave headroom
// while still rejecting internet-scale blocks.
const (
	// defaultMinMaskIPv4 rejects any external IPv4 prefix wider than a /8
	// (~16.7M addresses). The widest observed is /11, so this leaves 3 bits of headroom.
	defaultMinMaskIPv4 = 8
	// defaultMinMaskIPv6 rejects any external IPv6 prefix wider than a /20.
	// The widest observed is /24 (Akamai), so this leaves 4 bits of headroom.
	defaultMinMaskIPv6 = 20
)

// guardExternalBreadth returns an error if any externally-fetched CIDR is wider
// than the minimum mask allowed for its address family. A non-positive
// minMaskV4/minMaskV6 falls back to the package default.
//
// Invalid entries are ignored here; they are filtered out downstream by
// net.ParseCIDR in the resolver. A bare IP is treated as a full-length host
// route (/32 or /128) and always passes.
func guardExternalBreadth(cidrs []string, minMaskV4, minMaskV6 int) error {
	if minMaskV4 <= 0 {
		minMaskV4 = defaultMinMaskIPv4
	}
	if minMaskV6 <= 0 {
		minMaskV6 = defaultMinMaskIPv6
	}

	for _, c := range cidrs {
		ones, is4, ok := prefixLen(c)
		if !ok {
			continue
		}
		if is4 && ones < minMaskV4 {
			return fmt.Errorf("external CIDR %q is too broad: /%d is wider than the minimum IPv4 mask /%d", c, ones, minMaskV4)
		}
		if !is4 && ones < minMaskV6 {
			return fmt.Errorf("external CIDR %q is too broad: /%d is wider than the minimum IPv6 mask /%d", c, ones, minMaskV6)
		}
	}
	return nil
}

// prefixLen returns the mask length and address family of a CIDR string, treating
// a bare IPv4/IPv6 address as a full-length prefix (/32 or /128). ok is false if
// the value is neither a CIDR nor an IP.
func prefixLen(s string) (ones int, is4 bool, ok bool) {
	if _, ipNet, err := net.ParseCIDR(s); err == nil {
		o, _ := ipNet.Mask.Size()
		return o, ipNet.IP.To4() != nil, true
	}
	if ip := net.ParseIP(s); ip != nil {
		if ip.To4() != nil {
			return 32, true, true
		}
		return 128, false, true
	}
	return 0, false, false
}
