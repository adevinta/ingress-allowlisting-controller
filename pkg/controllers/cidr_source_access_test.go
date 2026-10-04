package controllers

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"

	ipamv1alpha1 "github.com/adevinta/ingress-allowlisting-controller/pkg/apis/ipam.adevinta.com/v1alpha1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

func TestParseAllowlistEntry(t *testing.T) {
	valid := []struct {
		entry string
		want  allowedOrigin
	}{
		{"https://ip-ranges.amazonaws.com", allowedOrigin{"https", "ip-ranges.amazonaws.com", "443"}},
		{"http://ip-ranges.amazonaws.com", allowedOrigin{"http", "ip-ranges.amazonaws.com", "80"}},
		{"ip-ranges.amazonaws.com", allowedOrigin{"https", "ip-ranges.amazonaws.com", "443"}}, // bare host = https
		{"ip-ranges.amazonaws.com:8443", allowedOrigin{"https", "ip-ranges.amazonaws.com", "8443"}},
		{"http://feeds.internal:8080", allowedOrigin{"http", "feeds.internal", "8080"}},
		{"  https://api.github.com  ", allowedOrigin{"https", "api.github.com", "443"}},
		{"HTTPS://API.GitHub.COM.", allowedOrigin{"https", "api.github.com", "443"}}, // case + trailing dot
		{"https://api.github.com/", allowedOrigin{"https", "api.github.com", "443"}}, // bare slash is fine
		{"https://10.1.2.3:9443", allowedOrigin{"https", "10.1.2.3", "9443"}},
		{"https://[2001:db8::1]:8443", allowedOrigin{"https", "2001:db8::1", "8443"}},
	}
	for _, tt := range valid {
		t.Run("valid "+tt.entry, func(t *testing.T) {
			got, err := parseAllowlistEntry(tt.entry)
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}

	invalid := map[string]string{
		"":                           "empty",
		"   ":                        "empty",
		"ftp://files.example.com":    "scheme",
		"file:///etc/passwd":         "scheme",
		"https://user@example.com":   "credentials",
		"https://u:p@example.com":    "credentials",
		"https://example.com/feed":   "without a path",
		"https://example.com/feed/":  "without a path",
		"https://example.com?x=1":    "without a path",
		"https://example.com#frag":   "without a path",
		"https://example.com?":       "without a path",
		"https://*.example.com":      "wildcards",
		"*.example.com":              "wildcards",
		"https://exa*mple.com":       "wildcards",
		"https://":                   "no host",
		"https://:8443":              "no host",
		"https://example.com:notnum": "not a valid URL",
	}
	for entry, want := range invalid {
		t.Run("invalid "+entry, func(t *testing.T) {
			_, err := parseAllowlistEntry(entry)
			require.Error(t, err)
			assert.Contains(t, err.Error(), want)
		})
	}
}

func TestParseAllowlistReportsEveryBadEntry(t *testing.T) {
	origins, err := parseAllowlist([]string{"https://ok.example.com", "ftp://bad1.example.com", "https://*.bad2.example.com"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "bad1")
	assert.Contains(t, err.Error(), "bad2")
	assert.Len(t, origins, 1)
}

func TestCheckAllowed(t *testing.T) {
	both, err := parseAllowlist([]string{"https://ip-ranges.amazonaws.com", "http://ip-ranges.amazonaws.com"})
	require.NoError(t, err)
	httpsOnly, err := parseAllowlist([]string{"https://ip-ranges.amazonaws.com"})
	require.NoError(t, err)

	check := func(t *testing.T, origins []allowedOrigin, raw string) error {
		t.Helper()
		u, err := url.Parse(raw)
		require.NoError(t, err)
		return checkAllowed(origins, u)
	}

	t.Run("https and http are both allowed when both are listed", func(t *testing.T) {
		assert.NoError(t, check(t, both, "https://ip-ranges.amazonaws.com/ip-ranges.json"))
		assert.NoError(t, check(t, both, "http://ip-ranges.amazonaws.com/ip-ranges.json"))
	})

	t.Run("the scheme must match the entry", func(t *testing.T) {
		assert.NoError(t, check(t, httpsOnly, "https://ip-ranges.amazonaws.com/x"))
		assert.ErrorIs(t, check(t, httpsOnly, "http://ip-ranges.amazonaws.com/x"), errSourceNotAllowed)
	})

	t.Run("matching ignores the path, query, case and a trailing dot", func(t *testing.T) {
		assert.NoError(t, check(t, httpsOnly, "https://IP-Ranges.AmazonAWS.com./a/b?c=d"))
		assert.NoError(t, check(t, httpsOnly, "https://ip-ranges.amazonaws.com:443/"))
	})

	t.Run("the port must match", func(t *testing.T) {
		assert.ErrorIs(t, check(t, httpsOnly, "https://ip-ranges.amazonaws.com:8443/"), errSourceNotAllowed)
		assert.ErrorIs(t, check(t, both, "http://ip-ranges.amazonaws.com:8080/"), errSourceNotAllowed)
	})

	t.Run("string-prefix and URL tricks do not match", func(t *testing.T) {
		for _, raw := range []string{
			"https://ip-ranges.amazonaws.com.evil.com/",           // allowed name as a label prefix
			"https://evil-ip-ranges.amazonaws.com/",               // allowed name as a suffix
			"https://sub.ip-ranges.amazonaws.com/",                // no implicit subdomains
			"https://ip-ranges.amazonaws.com@evil.com/",           // allowed name is the userinfo
			"https://ip-ranges.amazonaws.com:pw@evil.com/",        // same, with password
			"https://evil.com/?u=https://ip-ranges.amazonaws.com", // allowed name in the query
			"https://evil.com/ip-ranges.amazonaws.com",            // allowed name in the path
			"https://evil.com#@ip-ranges.amazonaws.com",           // allowed name in the fragment
			"https://evil.com\\@ip-ranges.amazonaws.com/",         // backslash confusion
		} {
			u, err := url.Parse(raw)
			if err != nil {
				continue // an unparsable URL is rejected earlier; it can never match
			}
			assert.ErrorIs(t, checkAllowed(httpsOnly, u), errSourceNotAllowed, raw)
		}
	})

	t.Run("an empty allowlist allows every host", func(t *testing.T) {
		assert.NoError(t, check(t, nil, "https://anything.example.org/x"))
		assert.NoError(t, check(t, nil, "http://10.0.0.1/x"))
	})
}

func TestIsPublicIP(t *testing.T) {
	public := []string{
		"8.8.8.8", "1.1.1.1", "52.94.0.1", "151.101.1.1", "2001:4860:4860::8888", "2606:4700::1111",
		"::ffff:8.8.8.8", // v4-mapped public
	}
	for _, s := range public {
		assert.True(t, isPublicIP(net.ParseIP(s)), "%s should be public", s)
	}

	nonPublic := map[string]string{
		"127.0.0.1":              "loopback",
		"127.1.2.3":              "loopback",
		"::1":                    "loopback v6",
		"0.0.0.0":                "unspecified",
		"0.1.2.3":                "this network",
		"::":                     "unspecified v6",
		"10.0.0.1":               "private",
		"172.16.0.1":             "private",
		"172.31.255.255":         "private",
		"192.168.1.1":            "private",
		"fd00::1":                "unique local",
		"fc00::1":                "unique local",
		"169.254.169.254":        "cloud metadata",
		"169.254.0.1":            "link-local",
		"fe80::1":                "link-local v6",
		"fd00:ec2::254":          "aws ipv6 metadata (unique local)",
		"100.64.0.1":             "cgnat",
		"100.127.255.255":        "cgnat",
		"192.0.0.1":              "ietf assignments",
		"198.18.0.1":             "benchmarking",
		"224.0.0.1":              "multicast",
		"ff02::1":                "multicast v6",
		"240.0.0.1":              "reserved",
		"255.255.255.255":        "broadcast",
		"::ffff:127.0.0.1":       "v4-mapped loopback",
		"::ffff:169.254.169.254": "v4-mapped metadata",
		"::ffff:10.0.0.1":        "v4-mapped private",
		"::127.0.0.1":            "v4-compatible loopback",
		"64:ff9b::7f00:1":        "nat64 to 127.0.0.1",
		"64:ff9b::a9fe:a9fe":     "nat64 to 169.254.169.254",
		"2002:7f00:1::":          "6to4 to 127.0.0.1",
		"2002:a9fe:a9fe::1":      "6to4 to 169.254.169.254",
		"fec0::1":                "site-local",
	}
	for s, why := range nonPublic {
		assert.False(t, isPublicIP(net.ParseIP(s)), "%s (%s) must not be public", s, why)
	}

	assert.False(t, isPublicIP(nil), "an unparsable address is never public")

	t.Run("translation forms of a public IPv4 stay public", func(t *testing.T) {
		assert.True(t, isPublicIP(net.ParseIP("64:ff9b::808:808"))) // NAT64 to 8.8.8.8
		assert.True(t, isPublicIP(net.ParseIP("2002:808:808::1")))  // 6to4 to 8.8.8.8
	})
}

func TestPublicOnlyControl(t *testing.T) {
	assert.NoError(t, publicOnlyControl("tcp", "8.8.8.8:443", nil))
	assert.NoError(t, publicOnlyControl("tcp", "[2001:4860:4860::8888]:443", nil))

	for _, addr := range []string{"169.254.169.254:80", "127.0.0.1:8080", "[::1]:80", "10.0.0.5:443", "[fe80::1%eth0]:80", "not-an-address", "example.com:443"} {
		err := publicOnlyControl("tcp", addr, nil)
		require.Error(t, err, addr)
		assert.ErrorIs(t, err, errDestinationNotAllowed, addr)
	}
}

func TestFetchPolicyDenied(t *testing.T) {
	guard, ok := fetchPolicyDenied(errSourceNotAllowed)
	assert.True(t, ok)
	assert.Equal(t, "cidr-source-allowlist", guard)

	guard, ok = fetchPolicyDenied(errDestinationNotAllowed)
	assert.True(t, ok)
	assert.Equal(t, "private-destinations", guard)

	_, ok = fetchPolicyDenied(errResponseTooLarge)
	assert.False(t, ok)
}

// countingServer counts how many requests actually reached it. A refused fetch must leave it at 0.
func countingServer(t *testing.T, h http.HandlerFunc) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var hits atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		h(w, r)
	}))
	t.Cleanup(server.Close)
	return server, &hits
}

func yamlList(entries ...string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		for _, e := range entries {
			_, _ = w.Write([]byte("- " + e + "\n"))
		}
	}
}

func TestPrivateDestinationGuardOnRealConnections(t *testing.T) {
	t.Run("blocked by default, and nothing reaches the server", func(t *testing.T) {
		server, hits := countingServer(t, yamlList("10.1.0.0/16"))

		cidrs := reconcileWithGuards(t, server.URL, ipamv1alpha1.Processing{}, CIDRSourceOptions{})

		requireFailedKeepingLastGood(t, cidrs, "destination address not allowed")
		assert.Zero(t, hits.Load(), "the connection must be refused before any request is sent")
	})

	t.Run("the address is checked after name resolution, not on the URL text", func(t *testing.T) {
		// The URL names "localhost", which looks harmless as text but resolves to loopback.
		server, hits := countingServer(t, yamlList("10.1.0.0/16"))
		u, err := url.Parse(server.URL)
		require.NoError(t, err)
		byName := "http://localhost:" + u.Port()

		cidrs := reconcileWithGuards(t, byName, ipamv1alpha1.Processing{}, CIDRSourceOptions{})

		requireFailedKeepingLastGood(t, cidrs, "destination address not allowed")
		assert.Zero(t, hits.Load())
	})

	t.Run("the opt-out allows internal sources", func(t *testing.T) {
		server, hits := countingServer(t, yamlList("10.1.0.0/16"))

		cidrs := reconcileWithGuards(t, server.URL, ipamv1alpha1.Processing{}, CIDRSourceOptions{AllowPrivateDestinations: true})

		assert.Equal(t, []string{"10.1.0.0/16"}, cidrs.Status.CIDRs)
		assert.EqualValues(t, 1, hits.Load())
	})
}

func TestAllowlistOnRealConnections(t *testing.T) {
	originOf := func(s *httptest.Server) string { return s.URL } // http://127.0.0.1:PORT

	t.Run("a listed origin is fetched", func(t *testing.T) {
		server, hits := countingServer(t, yamlList("10.1.0.0/16"))

		cidrs := reconcileFromServer(t, server.URL, ipamv1alpha1.Processing{}, CIDRSourceOptions{Allowlist: []string{originOf(server)}})

		assert.Equal(t, []string{"10.1.0.0/16"}, cidrs.Status.CIDRs)
		assert.EqualValues(t, 1, hits.Load())
	})

	t.Run("an unlisted origin is refused before any request", func(t *testing.T) {
		server, hits := countingServer(t, yamlList("10.1.0.0/16"))

		cidrs := reconcileFromServer(t, server.URL, ipamv1alpha1.Processing{}, CIDRSourceOptions{Allowlist: []string{"https://ip-ranges.amazonaws.com"}})

		requireFailedKeepingLastGood(t, cidrs, "source not in allowlist")
		assert.Zero(t, hits.Load())
	})

	t.Run("the scheme in the entry must match the request", func(t *testing.T) {
		server, hits := countingServer(t, yamlList("10.1.0.0/16"))
		u, err := url.Parse(server.URL)
		require.NoError(t, err)

		// Same host and port, but the entry says https while the server speaks http.
		cidrs := reconcileFromServer(t, server.URL, ipamv1alpha1.Processing{}, CIDRSourceOptions{Allowlist: []string{"https://" + u.Host}})

		requireFailedKeepingLastGood(t, cidrs, "source not in allowlist")
		assert.Zero(t, hits.Load())
	})

	t.Run("listing both schemes allows both", func(t *testing.T) {
		server, _ := countingServer(t, yamlList("10.1.0.0/16"))
		u, err := url.Parse(server.URL)
		require.NoError(t, err)

		cidrs := reconcileFromServer(t, server.URL, ipamv1alpha1.Processing{},
			CIDRSourceOptions{Allowlist: []string{"https://" + u.Host, "http://" + u.Host}})

		assert.Equal(t, []string{"10.1.0.0/16"}, cidrs.Status.CIDRs)
	})

	t.Run("a redirect to an unlisted origin is not followed", func(t *testing.T) {
		target, targetHits := countingServer(t, yamlList("192.168.0.0/16"))
		entry, _ := countingServer(t, func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, target.URL, http.StatusFound)
		})

		cidrs := reconcileFromServer(t, entry.URL, ipamv1alpha1.Processing{}, CIDRSourceOptions{Allowlist: []string{originOf(entry)}})

		requireFailedKeepingLastGood(t, cidrs, "source not in allowlist")
		assert.Zero(t, targetHits.Load(), "the redirect target must never be contacted")
	})

	t.Run("a redirect to a listed origin is followed", func(t *testing.T) {
		target, targetHits := countingServer(t, yamlList("192.168.0.0/16"))
		entry, _ := countingServer(t, func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, target.URL, http.StatusFound)
		})

		cidrs := reconcileFromServer(t, entry.URL, ipamv1alpha1.Processing{}, CIDRSourceOptions{Allowlist: []string{originOf(entry), originOf(target)}})

		assert.Equal(t, []string{"192.168.0.0/16"}, cidrs.Status.CIDRs)
		assert.EqualValues(t, 1, targetHits.Load())
	})

	t.Run("without an allowlist a redirect is followed, as before", func(t *testing.T) {
		target, _ := countingServer(t, yamlList("192.168.0.0/16"))
		entry, _ := countingServer(t, func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, target.URL, http.StatusFound)
		})

		cidrs := reconcileFromServer(t, entry.URL, ipamv1alpha1.Processing{}, CIDRSourceOptions{})

		assert.Equal(t, []string{"192.168.0.0/16"}, cidrs.Status.CIDRs)
	})

	t.Run("a redirect loop is stopped", func(t *testing.T) {
		var self string
		server, hits := countingServer(t, func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, self, http.StatusFound)
		})
		self = server.URL

		cidrs := reconcileFromServer(t, server.URL, ipamv1alpha1.Processing{}, CIDRSourceOptions{})

		requireFailedKeepingLastGood(t, cidrs, "redirects")
		assert.LessOrEqual(t, int(hits.Load()), maxSourceRedirects+1)
	})

	t.Run("an allowlisted private address is still refused without the opt-out", func(t *testing.T) {
		// The two controls are independent: being on the allowlist does not switch the
		// destination guard off.
		server, hits := countingServer(t, yamlList("10.1.0.0/16"))

		cidrs := reconcileWithGuards(t, server.URL, ipamv1alpha1.Processing{}, CIDRSourceOptions{Allowlist: []string{originOf(server)}})

		requireFailedKeepingLastGood(t, cidrs, "destination address not allowed")
		assert.Zero(t, hits.Load(), "an allowlisted private address is still refused unless the opt-out is set")
	})
}

func TestRefusedSourceDoesNotReadSecrets(t *testing.T) {
	// If headersFrom were resolved before the allowlist check, this would fail with "not found" for
	// the Secret. It must fail on the allowlist instead, i.e. a refused source never reads Secrets.
	server, hits := countingServer(t, yamlList("10.1.0.0/16"))
	ctx := context.TODO()
	scheme, err := Scheme("")
	require.NoError(t, err)

	cidrs := &ipamv1alpha1.CIDRs{
		ObjectMeta: metav1.ObjectMeta{Name: "my-net", Namespace: "mynamespace"},
		Spec: ipamv1alpha1.CIDRsSpec{CIDRsSource: ipamv1alpha1.CIDRsSource{
			Location: ipamv1alpha1.CIDRsLocation{
				URI:         server.URL,
				HeadersFrom: []ipamv1alpha1.HeadersFrom{{SecretRef: ipamv1alpha1.ObjectRef{Name: "does-not-exist"}}},
			},
		}},
		Status: ipamv1alpha1.CIDRsStatus{CIDRs: []string{"127.0.0.1/32"}},
	}
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(cidrs).WithStatusSubresource(cidrs).Build()
	reconciler := &CIDRReconciler{
		CIDRs: &ipamv1alpha1.CIDRs{}, CIDRsList: &ipamv1alpha1.CIDRsList{}, Client: fakeClient,
		HTTPHeadersEnabled: true,
		SourceOptions:      CIDRSourceOptions{AllowPrivateDestinations: true, Allowlist: []string{"https://example.org"}},
	}

	_, err = reconciler.Reconcile(ctx, reconcile.Request{NamespacedName: client.ObjectKeyFromObject(cidrs)})
	require.NoError(t, err)
	require.NoError(t, fakeClient.Get(ctx, client.ObjectKeyFromObject(cidrs), cidrs))

	require.Len(t, cidrs.Status.Conditions, 1)
	msg := cidrs.Status.Conditions[0].Message
	assert.Contains(t, msg, "source not in allowlist")
	assert.NotContains(t, msg, "does-not-exist", "the Secret must not even be looked up")
	assert.Zero(t, hits.Load())
}

func TestCIDRSourceOptionsValidateAllowlist(t *testing.T) {
	o := DefaultCIDRSourceOptions()
	o.Allowlist = []string{"https://ip-ranges.amazonaws.com", "http://ip-ranges.amazonaws.com", "api.github.com"}
	require.NoError(t, o.Validate())

	o.Allowlist = []string{"https://ok.example.com", "https://*.example.com"}
	err := o.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "allowlist")
	assert.Contains(t, err.Error(), "wildcards")

	assert.NoError(t, DefaultCIDRSourceOptions().Validate(), "an empty allowlist is valid: it means any host")

	// The zero value must keep the destination guard ON.
	assert.False(t, CIDRSourceOptions{}.withDefaults().AllowPrivateDestinations)
	assert.False(t, DefaultCIDRSourceOptions().AllowPrivateDestinations)
}
