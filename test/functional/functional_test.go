//go:build functional

// Package functional runs the controller's main use cases against a REAL cluster: the current kube
// context, with the controller already installed. It is local-only — excluded from `go test ./...`
// by the build tag and skipped in CI — and a dry run unless CONFIRM names the current context.
// See docs/functional-tests.md.
package functional

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"testing"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/client"

	ipamv1alpha1 "github.com/adevinta/ingress-allowlisting-controller/pkg/apis/ipam.adevinta.com/v1alpha1"
	"github.com/adevinta/ingress-allowlisting-controller/pkg/controllers"
)

func TestFunctional(t *testing.T) {
	if os.Getenv("CI") != "" || os.Getenv("GITHUB_ACTIONS") != "" {
		t.Skip("functional tests run against a real cluster and are local-only; skipped in CI")
	}
	ctx := context.Background()

	cluster, err := loadClusterTarget()
	if err != nil {
		t.Fatal(err)
	}
	scheme, err := controllers.Scheme()
	if err != nil {
		t.Fatal(err)
	}
	c, err := client.New(cluster.Config, client.Options{Scheme: scheme})
	if err != nil {
		t.Fatalf("connecting to %s: %v", cluster.Server, err)
	}

	p := buildPlan(ctx, c, cluster)
	p.print(os.Stdout)

	switch confirm := os.Getenv("CONFIRM"); {
	case confirm == "":
		t.Skipf("dry run, nothing was created. To run against this cluster: make functional CONFIRM=%s", cluster.Context)
	case confirm != cluster.Context:
		t.Fatalf("CONFIRM=%q does not match the current context %q; nothing was created", confirm, cluster.Context)
	}
	if b := p.blockers(); len(b) > 0 {
		t.Fatalf("cannot run: %s", strings.Join(b, "; "))
	}

	createNamespace(t, ctx, c, p.Namespace)
	createNamespace(t, ctx, c, p.PeerNamespace)
	ns := p.Namespace
	annotation := p.Controller.flag("annotation-prefix", defaultAnnotationPrefix) + "/allowlist-group"

	// A CIDRs object that exists only in the peer namespace: objects in the main namespace that
	// reference it by name must not get its CIDRs (see the isolation scenario).
	t.Run("peer-cidrs", func(t *testing.T) {
		spec := ipamv1alpha1.CIDRsSpec{CIDRsSource: ipamv1alpha1.CIDRsSource{CIDRs: []string{sharedCIDR}}}
		if err := createCIDRs(ctx, c, p.PeerNamespace, sharedCIDRsName, spec); err != nil {
			t.Fatalf("creating CIDRs %s/%s: %v", p.PeerNamespace, sharedCIDRsName, err)
		}
		waitUpToDate(t, ctx, c, p.PeerNamespace, sharedCIDRsName)
	})

	var readySources []string
	t.Run("remote-sources", func(t *testing.T) {
		for _, s := range p.Sources {
			if s.Skip != "" {
				continue
			}
			spec := ipamv1alpha1.CIDRsSpec{CIDRsSource: ipamv1alpha1.CIDRsSource{
				Location: ipamv1alpha1.CIDRsLocation{URI: s.uri, Processing: s.processing},
			}}
			if err := createCIDRs(ctx, c, ns, s.name, spec); err != nil {
				t.Fatalf("creating CIDRs %s: %v", s.name, err)
			}
		}
		for _, s := range p.Sources {
			if s.Skip != "" {
				continue
			}
			t.Run(s.name, func(t *testing.T) {
				obj := waitUpToDate(t, ctx, c, ns, s.name)
				if len(obj.Status.CIDRs) == 0 {
					t.Fatalf("status.cidrs is empty")
				}
				if bad := invalidCIDRs(obj.Status.CIDRs); len(bad) > 0 {
					t.Fatalf("status.cidrs contains invalid entries: %v", bad)
				}
				t.Logf("%d CIDRs fetched from %s", len(obj.Status.CIDRs), s.uri)
				readySources = append(readySources, s.name)
			})
		}
	})

	for _, tg := range p.Targets {
		if tg.Skip != "" {
			continue
		}
		env := scenarioEnv{ctx: ctx, c: c, ns: ns, peerNS: p.PeerNamespace, annotation: annotation, readySources: readySources}
		t.Run(tg.name, func(t *testing.T) {
			runTargetScenarios(t, env, tg.target)
		})
	}
}

const (
	// sharedCIDRsName is a CIDRs object that exists only in the peer namespace.
	sharedCIDRsName = "shared"
	sharedCIDR      = "192.0.2.128/25"
)

// scenarioEnv is what every scenario needs: the client, the main namespace (where objects under
// test live), the peer namespace, the allowlist annotation and the remote sources that are ready.
type scenarioEnv struct {
	ctx          context.Context
	c            client.Client
	ns           string
	peerNS       string
	annotation   string
	readySources []string
}

func exactly(cidrs ...string) func() ([]string, error) {
	return func() ([]string, error) { return cidrs, nil }
}

// runTargetScenarios runs the use cases shared by every resource kind, then the target's own.
func runTargetScenarios(t *testing.T, env scenarioEnv, tg target) {
	ctx, c, ns, annotation, readySources := env.ctx, env.c, env.ns, env.annotation, env.readySources
	observe := func(name string) func() ([]string, error) {
		return func() ([]string, error) { return tg.observe(ctx, c, ns, name) }
	}

	if tg.setup != nil {
		if err := tg.setup(ctx, c, ns); err != nil {
			t.Fatalf("setting up %s: %v", tg.name, err)
		}
	}

	inline := tg.name + "-inline"
	t.Run("inline", func(t *testing.T) {
		// A bare IP must become a /32 and the result must be sorted.
		spec := ipamv1alpha1.CIDRsSpec{CIDRsSource: ipamv1alpha1.CIDRsSource{CIDRs: []string{"203.0.113.0/24", "198.51.100.7"}}}
		if err := createCIDRs(ctx, c, ns, inline, spec); err != nil {
			t.Fatalf("creating CIDRs: %v", err)
		}
		if err := tg.create(ctx, c, ns, inline, map[string]string{annotation: inline}); err != nil {
			t.Fatalf("creating %s: %v", tg.name, err)
		}
		expectAllowlist(t, tg.name+" allowlist from inline CIDRs", observe(inline), exactly("198.51.100.7/32", "203.0.113.0/24"))
	})

	t.Run("update-add", func(t *testing.T) {
		if err := setInlineCIDRs(ctx, c, ns, inline, []string{"203.0.113.0/24", "198.51.100.7", "192.0.2.0/24"}); err != nil {
			t.Fatalf("updating CIDRs: %v", err)
		}
		expectAllowlist(t, "added CIDR to propagate", observe(inline), exactly("192.0.2.0/24", "198.51.100.7/32", "203.0.113.0/24"))
	})

	t.Run("update-remove", func(t *testing.T) {
		if err := setInlineCIDRs(ctx, c, ns, inline, []string{"198.51.100.7", "192.0.2.0/24"}); err != nil {
			t.Fatalf("updating CIDRs: %v", err)
		}
		expectAllowlist(t, "removed CIDR to propagate", observe(inline), exactly("192.0.2.0/24", "198.51.100.7/32"))
	})

	t.Run("remote", func(t *testing.T) {
		if len(readySources) == 0 {
			t.Skip("no remote source is up to date")
		}
		name := tg.name + "-remote"
		if err := tg.create(ctx, c, ns, name, map[string]string{annotation: strings.Join(readySources, ",")}); err != nil {
			t.Fatalf("creating %s: %v", tg.name, err)
		}
		// Feeds change over time, so the expectation is whatever the CIDRs statuses hold right now.
		expectAllowlist(t, tg.name+" allowlist from remote sources "+strings.Join(readySources, ","), observe(name), func() ([]string, error) {
			var statuses [][]string
			for _, s := range readySources {
				obj, err := getCIDRs(ctx, c, ns, s)
				if err != nil {
					return nil, err
				}
				statuses = append(statuses, obj.Status.CIDRs)
			}
			return expectedAllowlist(statuses...), nil
		})
	})

	t.Run("missing-cidrs", func(t *testing.T) {
		name := tg.name + "-missing"
		if err := tg.create(ctx, c, ns, name, map[string]string{annotation: namespaceLabel + "-does-not-exist"}); err != nil {
			t.Fatalf("creating %s: %v", tg.name, err)
		}
		expectAllowlist(t, "deny-all fallback for a missing CIDRs object", observe(name), exactly(denyAll))
	})

	t.Run("isolation", func(t *testing.T) {
		// "shared" exists in the peer namespace only. Annotations resolve in the object's own
		// namespace, so this must be treated as missing: deny-all, never the peer's CIDRs.
		name := tg.name + "-isolation"
		if err := tg.create(ctx, c, ns, name, map[string]string{annotation: sharedCIDRsName}); err != nil {
			t.Fatalf("creating %s: %v", tg.name, err)
		}
		expectAllowlist(t, "CIDRs of namespace "+env.peerNS+" not to be used in "+ns, observe(name), exactly(denyAll))
	})

	if tg.extraScenarios != nil {
		tg.extraScenarios(t, env)
	}
}

func buildPlan(ctx context.Context, c client.Client, cluster clusterTarget) plan {
	base := namespaceLabel + "-" + randomSuffix()
	p := plan{Cluster: cluster, Namespace: base + "-a", PeerNamespace: base + "-b"}
	p.Controller, p.ControllerErr = detectController(ctx, c)

	gk := schema.GroupKind{Group: ipamv1alpha1.GroupVersion.Group, Kind: "CIDRs"}
	if _, err := c.RESTMapper().RESTMapping(gk); err != nil {
		p.CRDErr = fmt.Errorf("%s CRD not installed: %v", gk, err)
	}

	annotationPrefix := p.Controller.flag("annotation-prefix", defaultAnnotationPrefix)
	for _, tg := range targets(discover(ctx, c, p.Controller, annotationPrefix)) {
		planned := plannedTarget{target: tg}
		switch {
		case tg.unavailable != "":
			planned.Skip = tg.unavailable
		case p.ControllerErr == nil && !p.Controller.enabled(tg.flag, tg.flagDefault):
			planned.Skip = fmt.Sprintf("--%s is off on the controller", tg.flag)
		}
		p.Targets = append(p.Targets, planned)
	}
	for _, s := range remoteSources() {
		planned := plannedSource{remoteSource: s}
		if p.ControllerErr == nil && !p.Controller.allowsOrigin(s.uri) {
			planned.Skip = "not in the controller's --cidr-source-allowlist"
		}
		p.Sources = append(p.Sources, planned)
	}
	return p
}

func createNamespace(t *testing.T, ctx context.Context, c client.Client, name string) {
	t.Helper()
	ns := &v1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: name, Labels: map[string]string{namespaceLabel: "true"}}}
	if err := c.Create(ctx, ns); err != nil {
		t.Fatalf("creating namespace %s: %v", name, err)
	}
	t.Logf("created namespace %s", name)
	t.Cleanup(func() {
		if os.Getenv("KEEP") != "" {
			t.Logf("KEEP is set: namespace %s was kept; delete it with make functional-clean", name)
			return
		}
		if err := c.Delete(context.Background(), ns); client.IgnoreNotFound(err) != nil {
			t.Errorf("deleting namespace %s: %v (delete it with make functional-clean)", name, err)
			return
		}
		t.Logf("deleted namespace %s", name)
	})
}

func randomSuffix() string {
	b := make([]byte, 3)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
