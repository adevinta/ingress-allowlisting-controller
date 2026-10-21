package controllers

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"syscall"
	"time"

	log "github.com/adevinta/go-log-toolkit"
)

// Access control for EXTERNAL (HTTP-fetched) CIDR sources.
//
// spec.cidrsSource.location.uri is user-supplied, and the request is made from the controller pod,
// which can reach things its author cannot: cluster-internal services, the node's cloud metadata
// endpoint, the kubelet. Two independent controls narrow where a fetch may go:
//
//   - a destination guard, ON by default: the connection is refused if the address it resolves to
//     is not a public one (loopback, link-local incl. cloud metadata, private, CGNAT, multicast,
//     reserved, and IPv6 forms that embed such an IPv4). It is checked when the connection is made,
//     on the address actually being dialled, so DNS tricks and redirects cannot get around it.
//     AllowPrivateDestinations switches it off for feeds that really are internal.
//   - an optional allowlist of origins (scheme + host + port). Empty means any host is allowed.
//
// Like the other guardrails these are defences for a trusted operator's deployment against a
// mis-set or malicious `uri`; they do not make an untrusted feed trustworthy.

var (
	// errSourceNotAllowed is returned when the request URL (or a redirect target) is not in the
	// allowlist.
	errSourceNotAllowed = errors.New("source not in allowlist")
	// errDestinationNotAllowed is returned when a connection would go to a non-public address.
	errDestinationNotAllowed = errors.New("destination address not allowed")
)

// allowedOrigin is one allowlist entry: an exact scheme, host and port. There are no wildcards and
// no path/prefix matching — the host is compared after parsing, never as a string prefix.
type allowedOrigin struct {
	scheme string
	host   string
	port   string
}

func (o allowedOrigin) String() string { return o.scheme + "://" + net.JoinHostPort(o.host, o.port) }

// parseAllowlist parses allowlist entries. An entry is `scheme://host[:port]`; a bare `host[:port]`
// means https. The scheme must be http or https and is matched exactly, so allowing both schemes
// for a host takes two entries. The port defaults to the scheme's (80/443).
func parseAllowlist(entries []string) ([]allowedOrigin, error) {
	var origins []allowedOrigin
	var errs []error
	for _, e := range entries {
		o, err := parseAllowlistEntry(e)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		origins = append(origins, o)
	}
	return origins, errors.Join(errs...)
}

func parseAllowlistEntry(entry string) (allowedOrigin, error) {
	raw := strings.TrimSpace(entry)
	if raw == "" {
		return allowedOrigin{}, errors.New("allowlist entry is empty")
	}
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil {
		return allowedOrigin{}, fmt.Errorf("allowlist entry %q is not a valid URL: %w", entry, err)
	}
	switch {
	case u.Scheme != "http" && u.Scheme != "https":
		return allowedOrigin{}, fmt.Errorf("allowlist entry %q: scheme must be http or https", entry)
	case u.User != nil:
		return allowedOrigin{}, fmt.Errorf("allowlist entry %q must not contain credentials", entry)
	case u.Path != "" && u.Path != "/", u.RawQuery != "", u.ForceQuery, u.Fragment != "":
		return allowedOrigin{}, fmt.Errorf("allowlist entry %q must be scheme://host[:port] only, without a path, query or fragment", entry)
	case u.Hostname() == "":
		return allowedOrigin{}, fmt.Errorf("allowlist entry %q has no host", entry)
	case strings.ContainsAny(u.Hostname(), "*?[]"):
		return allowedOrigin{}, fmt.Errorf("allowlist entry %q: wildcards and patterns are not supported, list each host explicitly", entry)
	}
	return originOf(u), nil
}

// originOf normalises a URL to the (scheme, host, port) it would connect to.
func originOf(u *url.URL) allowedOrigin {
	scheme := strings.ToLower(u.Scheme)
	port := u.Port()
	if port == "" {
		port = "443"
		if scheme == "http" {
			port = "80"
		}
	}
	return allowedOrigin{
		scheme: scheme,
		host:   strings.TrimSuffix(strings.ToLower(u.Hostname()), "."),
		port:   port,
	}
}

// checkAllowed returns an error if the allowlist is set and does not contain the URL's origin.
// An empty allowlist allows everything.
func checkAllowed(origins []allowedOrigin, u *url.URL) error {
	if len(origins) == 0 {
		return nil
	}
	got := originOf(u)
	for _, o := range origins {
		if o == got {
			return nil
		}
	}
	return fmt.Errorf("%w: %s", errSourceNotAllowed, got)
}

// Ranges that are not covered by the net.IP predicates but are not public internet either.
var nonPublicNets = func() []*net.IPNet {
	var nets []*net.IPNet
	for _, c := range []string{
		"0.0.0.0/8",     // "this network"
		"100.64.0.0/10", // carrier-grade NAT (also used by some clouds for node/pod networks)
		"192.0.0.0/24",  // IETF protocol assignments
		"198.18.0.0/15", // benchmarking
		"240.0.0.0/4",   // reserved + broadcast
		"::/96",         // deprecated IPv4-compatible IPv6 (also covers :: and ::1)
		"100::/64",      // discard-only
		"fec0::/10",     // deprecated site-local
	} {
		_, n, err := net.ParseCIDR(c)
		if err != nil {
			panic(err)
		}
		nets = append(nets, n)
	}
	return nets
}()

// isPublicIP reports whether ip is an address a public internet feed could legitimately live at.
func isPublicIP(ip net.IP) bool {
	if ip == nil {
		return false
	}
	if v4 := ip.To4(); v4 != nil {
		ip = v4 // also unwraps ::ffff:a.b.c.d
	} else if embedded := embeddedIPv4(ip); embedded != nil {
		return isPublicIP(embedded)
	}
	if ip.IsUnspecified() || ip.IsLoopback() || ip.IsPrivate() || ip.IsMulticast() ||
		ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsInterfaceLocalMulticast() {
		return false
	}
	for _, n := range nonPublicNets {
		if n.Contains(ip) {
			return false
		}
	}
	return true
}

// embeddedIPv4 returns the IPv4 address carried inside the IPv6 translation forms that route to an
// IPv4 destination (NAT64 64:ff9b::/96 and 6to4 2002::/16), so they are judged like the IPv4 they
// point at. It returns nil for anything else.
func embeddedIPv4(ip net.IP) net.IP {
	ip = ip.To16()
	if ip == nil {
		return nil
	}
	if ip[0] == 0x00 && ip[1] == 0x64 && ip[2] == 0xff && ip[3] == 0x9b && allZero(ip[4:12]) {
		return net.IPv4(ip[12], ip[13], ip[14], ip[15])
	}
	if ip[0] == 0x20 && ip[1] == 0x02 {
		return net.IPv4(ip[2], ip[3], ip[4], ip[5])
	}
	return nil
}

func allZero(b []byte) bool {
	for _, x := range b {
		if x != 0 {
			return false
		}
	}
	return true
}

// publicOnlyControl is a net.Dialer Control hook. It runs for every connection attempt with the
// address the dialer has already resolved and is about to connect to, which is why it holds up
// against DNS rebinding and against redirects to internal addresses.
func publicOnlyControl(_, address string, _ syscall.RawConn) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("%w: cannot parse %q", errDestinationNotAllowed, address)
	}
	if !isPublicIP(net.ParseIP(host)) {
		return fmt.Errorf("%w: %s is not a public address (set --cidr-source-allow-private-destinations to permit internal sources)", errDestinationNotAllowed, host)
	}
	return nil
}

const maxSourceRedirects = 10

// newSourceHTTPClient builds the client used to fetch one remote source. Connections are not
// reused: fetches are infrequent, and a fresh client per fetch keeps the allowlist and destination
// policy trivially correct with no shared state.
//
// Proxy settings from the environment are honoured as before. When a proxy is used, the destination
// guard applies to the connection to the proxy, so a proxy on a private address needs
// AllowPrivateDestinations; the allowlist is still checked against the request URL either way.
func newSourceHTTPClient(opts CIDRSourceOptions, origins []allowedOrigin) *http.Client {
	var transport *http.Transport
	if base, ok := http.DefaultTransport.(*http.Transport); ok {
		transport = base.Clone()
	} else {
		transport = &http.Transport{Proxy: http.ProxyFromEnvironment}
	}
	transport.DisableKeepAlives = true
	if !opts.AllowPrivateDestinations {
		dialer := &net.Dialer{Timeout: 30 * time.Second, Control: publicOnlyControl}
		transport.DialContext = dialer.DialContext
	}
	return &http.Client{
		Transport: transport,
		// Every hop is checked, otherwise an allowed host could redirect to one that is not.
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= maxSourceRedirects {
				return fmt.Errorf("stopped after %d redirects", maxSourceRedirects)
			}
			log.DefaultLogger.WithContext(req.Context()).
				WithField("from", via[len(via)-1].URL.Redacted()).
				WithField("to", req.URL.Redacted()).
				Debug("external CIDR source redirected")
			return checkAllowed(origins, req.URL)
		},
	}
}

// fetchPolicyDenied reports which access control, if any, refused a fetch.
func fetchPolicyDenied(err error) (guard string, ok bool) {
	switch {
	case errors.Is(err, errSourceNotAllowed):
		return "cidr-source-allowlist", true
	case errors.Is(err, errDestinationNotAllowed):
		return "private-destinations", true
	}
	return "", false
}

// reportPolicyDenial logs a fetch that was refused by the allowlist or the destination guard, naming
// the control, and reports whether it was one. fields identify the source. The error itself is still
// returned to the caller, which records it in the object's condition.
func reportPolicyDenial(logCtx context.Context, err error, fields map[string]interface{}) bool {
	guard, denied := fetchPolicyDenied(err)
	if !denied {
		return false
	}
	log.DefaultLogger.WithContext(logCtx).
		WithFields(fields).
		WithField("guard", guard).
		Error(err, "; rejecting external CIDR source: access refused, keeping last-known-good allowlist")
	return true
}

// warnIfPermissive warns about settings that leave the SSRF exposure of location.uri wider than
// necessary. Called once at startup from LogEffective.
func (o CIDRSourceOptions) warnIfPermissive() {
	if len(o.Allowlist) == 0 {
		setupLog.Warn("--cidr-source-allowlist is empty: remote CIDR sources may be fetched from ANY host. Set it to the feeds you use to limit what anyone who can create a CIDRs object can make the controller request.")
	}
	if o.AllowPrivateDestinations {
		setupLog.Warn("--cidr-source-allow-private-destinations is set: remote CIDR sources may connect to loopback, link-local (cloud metadata), private and other internal addresses.")
	}
}
