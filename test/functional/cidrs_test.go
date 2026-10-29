//go:build functional

package functional

import (
	"context"
	"fmt"
	"net"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/util/retry"
	"sigs.k8s.io/controller-runtime/pkg/client"

	ipamv1alpha1 "github.com/adevinta/ingress-allowlisting-controller/pkg/apis/ipam.adevinta.com/v1alpha1"
	"github.com/adevinta/ingress-allowlisting-controller/pkg/util"
)

const (
	defaultAnnotationPrefix = "ipam.adevinta.com"
	// namespaceLabel marks every namespace the suite creates, so leftovers of interrupted runs can
	// be found and deleted (make functional-clean).
	namespaceLabel = "iac-functional"
	// denyAll is what the controller writes when none of the referenced CIDRs exist
	// (see getIpsFromAnnotation in pkg/resolvers/cidr_resolver.go).
	denyAll = "127.0.0.2/32"
)

// remoteSource is a real, public CIDR feed. The controller fetches it; this test only checks the
// result, so it never needs network access itself.
type remoteSource struct {
	name       string
	uri        string
	processing ipamv1alpha1.Processing
}

func remoteSources() []remoteSource {
	return []remoteSource{
		{
			name:       "gp-exit-ips",
			uri:        "https://api.gp-exit-ips.network-landing-zone.advgo.net/?countries=DE,NL",
			processing: ipamv1alpha1.Processing{CEL: "data.ips"},
		},
		{
			// The whole feed is ~2.7 MB; one small service keeps the resulting allowlists short.
			name:       "aws-r53-health",
			uri:        "https://ip-ranges.amazonaws.com/ip-ranges.json",
			processing: ipamv1alpha1.Processing{CEL: `data.prefixes.filter(p, p.service == "ROUTE53_HEALTHCHECKS").map(p, p.ip_prefix)`},
		},
		{
			// CSV with a byte order mark and trailing spaces.
			name:       "akamai",
			uri:        "https://techdocs.akamai.com/property-manager/pdfs/akamai_ipv4_CIDRs.csv",
			processing: ipamv1alpha1.Processing{Format: ipamv1alpha1.CSV},
		},
	}
}

func createCIDRs(ctx context.Context, c client.Client, ns, name string, spec ipamv1alpha1.CIDRsSpec) error {
	return c.Create(ctx, &ipamv1alpha1.CIDRs{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
		Spec:       spec,
	})
}

func setInlineCIDRs(ctx context.Context, c client.Client, ns, name string, cidrs []string) error {
	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		obj := &ipamv1alpha1.CIDRs{}
		if err := c.Get(ctx, client.ObjectKey{Namespace: ns, Name: name}, obj); err != nil {
			return err
		}
		obj.Spec.CIDRs = cidrs
		return c.Update(ctx, obj)
	})
}

func getCIDRs(ctx context.Context, c client.Client, ns, name string) (*ipamv1alpha1.CIDRs, error) {
	obj := &ipamv1alpha1.CIDRs{}
	return obj, c.Get(ctx, client.ObjectKey{Namespace: ns, Name: name}, obj)
}

// expectedAllowlist is what the controller should write for objects referencing CIDRs with these
// statuses: valid entries normalised to their network address, deduplicated and sorted, or the
// deny-all fallback when nothing valid is left. It mirrors pkg/resolvers on purpose — the suite
// states the expected behaviour rather than calling the code under test.
func expectedAllowlist(statuses ...[]string) []string {
	var out []string
	for _, status := range statuses {
		for _, entry := range status {
			if _, n, err := net.ParseCIDR(entry); err == nil {
				out = append(out, n.String())
			}
		}
	}
	out = util.DedupSorted(out)
	if len(out) == 0 {
		return []string{denyAll}
	}
	return out
}

func upToDate(obj *ipamv1alpha1.CIDRs) (bool, string) {
	for _, cond := range obj.Status.Conditions {
		if cond.Type == ipamv1alpha1.CIDRsStatusConditionTypeUpToDate {
			return cond.Status == v1.ConditionTrue, fmt.Sprintf("UpToDate=%s: %s", cond.Status, cond.Message)
		}
	}
	return false, "no UpToDate condition yet"
}

// waitUpToDate waits until the controller reports the CIDRs object up to date and returns it.
func waitUpToDate(t *testing.T, ctx context.Context, c client.Client, ns, name string) *ipamv1alpha1.CIDRs {
	t.Helper()
	var obj *ipamv1alpha1.CIDRs
	eventually(t, fmt.Sprintf("CIDRs %s/%s up to date", ns, name), func() (bool, string) {
		got, err := getCIDRs(ctx, c, ns, name)
		if err != nil {
			return false, err.Error()
		}
		obj = got
		ok, detail := upToDate(got)
		return ok, fmt.Sprintf("%s, status.cidrs=%v", detail, got.Status.CIDRs)
	})
	return obj
}

// invalidCIDRs returns the entries that are not valid CIDRs.
func invalidCIDRs(cidrs []string) []string {
	var bad []string
	for _, entry := range cidrs {
		if _, _, err := net.ParseCIDR(entry); err != nil {
			bad = append(bad, entry)
		}
	}
	return bad
}

func pollTimeout() time.Duration {
	if v := os.Getenv("IAC_TIMEOUT"); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			return d
		}
	}
	// The controller has a single CIDR worker and a remote fetch may take up to its 30s timeout,
	// so give each wait a few fetches worth of time.
	return 3 * time.Minute
}

const pollInterval = 2 * time.Second

// eventually polls check until it reports ok, failing the test with the last detail on timeout.
func eventually(t *testing.T, what string, check func() (ok bool, detail string)) {
	t.Helper()
	deadline := time.Now().Add(pollTimeout())
	var detail string
	for {
		var ok bool
		ok, detail = check()
		if ok {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out after %s waiting for %s; last state: %s", pollTimeout(), what, detail)
		}
		time.Sleep(pollInterval)
	}
}

// expectAllowlist waits until observe returns exactly the expected allowlist. expected is
// re-evaluated on every poll, so it can follow remote feeds that change during the run.
func expectAllowlist(t *testing.T, what string, observe func() ([]string, error), expected func() ([]string, error)) {
	t.Helper()
	eventually(t, what, func() (bool, string) {
		want, err := expected()
		if err != nil {
			return false, "computing expected allowlist: " + err.Error()
		}
		got, err := observe()
		if err != nil {
			return false, err.Error()
		}
		if got == nil {
			return false, fmt.Sprintf("not written yet; want %v", want)
		}
		return slices.Equal(got, want), fmt.Sprintf("got %v, want %v", got, want)
	})
}

func splitList(s string) []string {
	var out []string
	for _, part := range strings.Split(s, ",") {
		if part = strings.TrimSpace(part); part != "" {
			out = append(out, part)
		}
	}
	return out
}
