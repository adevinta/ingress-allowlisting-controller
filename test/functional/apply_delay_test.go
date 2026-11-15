//go:build functional

package functional

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/client-go/util/retry"
	"sigs.k8s.io/controller-runtime/pkg/client"

	ipamv1alpha1 "github.com/adevinta/ingress-allowlisting-controller/pkg/apis/ipam.adevinta.com/v1alpha1"
	"github.com/adevinta/ingress-allowlisting-controller/pkg/controllers"
)

// TestApplyDelay checks --cidr-source-apply-delay against a real cluster, with a feed that
// changes: a small Python HTTP server on this machine, whose files the test rewrites.
//
// Like TestRestart, it runs the controller itself, built from this tree, on this machine, so that
// it can reach the feed on 127.0.0.1. No other controller may run meanwhile: the CIDRs controller
// is not tied to an annotation prefix, so any instance would reconcile the test's object too.
// See docs/functional-tests.md.
func TestApplyDelay(t *testing.T) {
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

	p := buildApplyDelayPlan(ctx, c, cluster)
	p.print(os.Stdout)
	switch confirm := os.Getenv("CONFIRM"); {
	case confirm == "":
		t.Skipf("dry run, nothing was created. To run against this cluster: make functional-apply-delay CONFIRM=%s", cluster.Context)
	case confirm != cluster.Context:
		t.Fatalf("CONFIRM=%q does not match the current context %q; nothing was created", confirm, cluster.Context)
	}
	if len(p.blockers) > 0 {
		t.Fatalf("cannot run: %s", strings.Join(p.blockers, "; "))
	}

	feed := startFeed(t)
	bin := buildController(t)
	kubeconfig := writeKubeconfig(t, cluster.Context)
	createNamespace(t, ctx, c, p.run, p.ns)
	startController(t, bin, p.args, kubeconfig, "apply-delay")

	s := &applyDelayScenario{ctx: ctx, c: c, ns: p.ns, delay: p.delay, feed: feed}
	for _, step := range []struct {
		name string
		run  func(t *testing.T)
	}{
		{"first-list", s.firstList},
		{"addition-waits", s.additionWaits},
		{"applied-when-due", s.appliedWhenDue},
		{"removal-immediate", s.removalImmediate},
		{"redirect-waits", s.redirectWaits},
		{"uri-change-immediate", s.uriChangeImmediate},
		{"cel-change-immediate", s.celChangeImmediate},
		{"inline-immediate", s.inlineImmediate},
	} {
		// Each step builds on the state the previous one left.
		if !t.Run(step.name, step.run) {
			return
		}
	}
}

const (
	defaultTestApplyDelay = 60 * time.Second
	applyDelayCIDRs       = "apply-delay"
	pokeAnnotation        = "iac-functional/poke"
)

// applyDelayPlan is what TestApplyDelay would do, printed before anything is created.
type applyDelayPlan struct {
	cluster  clusterTarget
	run, ns  string
	delay    time.Duration
	args     []string
	others   int // CIDRs and ClusterCIDRs already in the cluster
	blockers []string
}

func buildApplyDelayPlan(ctx context.Context, c client.Client, cluster clusterTarget) applyDelayPlan {
	run := randomSuffix()
	p := applyDelayPlan{cluster: cluster, run: run, ns: namespaceLabel + "-" + run + "-a", delay: defaultTestApplyDelay}
	if v := os.Getenv("IAC_APPLY_DELAY"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil || d < 20*time.Second {
			p.blockers = append(p.blockers, fmt.Sprintf("IAC_APPLY_DELAY=%q must be a duration of at least 20s, so that waiting and not waiting can be told apart", v))
		} else {
			p.delay = d
		}
	}
	// The feed is on 127.0.0.1: allow private destinations. Extra arguments (e.g. writers) come
	// first, so that ours win.
	p.args = append(strings.Fields(os.Getenv("IAC_CONTROLLER_ARGS")),
		"--cidr-source-apply-delay="+p.delay.String(),
		"--cidr-source-allow-private-destinations")

	if _, err := exec.LookPath("python3"); err != nil {
		p.blockers = append(p.blockers, "python3 is not in PATH: it serves the feed")
	}
	deployments, err := controllerDeployments(ctx, c)
	if err != nil {
		p.blockers = append(p.blockers, err.Error())
	}
	for _, d := range deployments {
		if info := deploymentInfo(d); info.Ready {
			p.blockers = append(p.blockers, fmt.Sprintf("controller %s runs in the cluster: scale it to 0 first (it would reconcile the test's CIDRs object too, whatever its annotation prefix)", info.Location))
		}
	}
	for _, crd := range []string{"cidrs.ipam.adevinta.com", "clustercidrs.ipam.adevinta.com"} {
		if missing, err := crdStatusFieldsMissing(ctx, c, crd, "pending", "sourceHash"); err != nil {
			p.blockers = append(p.blockers, err.Error())
		} else if len(missing) > 0 {
			p.blockers = append(p.blockers, fmt.Sprintf("CRD %s has no status.%s: the API server would drop them. Install the CRDs of this tree first: kubectl apply -f config/crd/bases", crd, strings.Join(missing, ", status.")))
		}
	}
	for _, list := range []client.ObjectList{&ipamv1alpha1.CIDRsList{}, &ipamv1alpha1.ClusterCIDRsList{}} {
		if err := c.List(ctx, list); err == nil {
			p.others += len(list.(ipamv1alpha1.CIDRsGetterList).GetCIDRsItems())
		}
	}
	return p
}

// crdStatusFieldsMissing returns the fields of the CRD's status schema that are not there.
func crdStatusFieldsMissing(ctx context.Context, c client.Client, name string, fields ...string) ([]string, error) {
	crd := &unstructured.Unstructured{}
	crd.SetAPIVersion("apiextensions.k8s.io/v1")
	crd.SetKind("CustomResourceDefinition")
	if err := c.Get(ctx, client.ObjectKey{Name: name}, crd); err != nil {
		return nil, fmt.Errorf("reading CRD %s: %w", name, err)
	}
	versions, _, _ := unstructured.NestedSlice(crd.Object, "spec", "versions")
	for _, v := range versions {
		version, _ := v.(map[string]interface{})
		if version["name"] != ipamv1alpha1.GroupVersion.Version {
			continue
		}
		props, _, _ := unstructured.NestedMap(version, "schema", "openAPIV3Schema", "properties", "status", "properties")
		var missing []string
		for _, f := range fields {
			if _, ok := props[f]; !ok {
				missing = append(missing, f)
			}
		}
		return missing, nil
	}
	return nil, fmt.Errorf("CRD %s has no version %s", name, ipamv1alpha1.GroupVersion.Version)
}

func (p applyDelayPlan) print(w *os.File) {
	fmt.Fprintf(w, "\nTarget cluster\n  context:  %s\n  cluster:  %s\n  server:   %s\n  user:     %s\n", p.cluster.Context, p.cluster.Cluster, p.cluster.Server, p.cluster.User)
	fmt.Fprintf(w, "\nController\n  built from this tree and run on this machine with: %s\n", strings.Join(p.args, " "))
	fmt.Fprintf(w, "  no other controller may run meanwhile (in the cluster, or a go run of yours)\n")
	fmt.Fprintf(w, "  it also reconciles the %d CIDRs and ClusterCIDRs already in the cluster: it fetches their sources and\n", p.others)
	fmt.Fprintf(w, "  writes their status, as the controller in the cluster would; their new CIDRs wait %s too\n", p.delay)
	fmt.Fprintf(w, "\nFeed\n  a Python HTTP server on 127.0.0.1, files rewritten by the test\n")
	fmt.Fprintf(w, "\nWould create namespace %s (labels %s=true, %s=%s), deleted at the end unless KEEP=1\n", p.ns, namespaceLabel, runLabel, p.run)
	fmt.Fprintf(w, "\nScenario (CIDRs %s, delay %s)\n", applyDelayCIDRs, p.delay)
	fmt.Fprintf(w, "  1. first-list            the first list of a new object is used at once\n")
	fmt.Fprintf(w, "  2. addition-waits        a CIDR added to the feed waits in status.pending; a refetch keeps its firstSeen\n")
	fmt.Fprintf(w, "  3. applied-when-due      it is used once the delay has passed, with no change to the object\n")
	fmt.Fprintf(w, "  4. removal-immediate     a CIDR removed from the feed goes at once\n")
	fmt.Fprintf(w, "  5. redirect-waits        the same uri now redirects to another list: its CIDRs wait, the last ones stay\n")
	fmt.Fprintf(w, "  6. uri-change-immediate  spec.location.uri (and cel) changed: used at once, pending dropped\n")
	fmt.Fprintf(w, "  7. cel-change-immediate  spec.location.cel changed: used at once\n")
	fmt.Fprintf(w, "  8. inline-immediate      spec.cidrs changed: used at once\n")
	if len(p.blockers) > 0 {
		fmt.Fprintf(w, "\nCannot run:\n")
		for _, b := range p.blockers {
			fmt.Fprintf(w, "  - %s\n", b)
		}
	}
	fmt.Fprintln(w)
}

// feedServer is the Python HTTP server the controller fetches from. GET /<name> returns the file
// <name> of its directory, or, when <name>.redirect exists, redirects to the URL in it.
type feedServer struct {
	dir, url string
}

const feedScript = `import http.server, os, sys
root = sys.argv[2]
class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        path = os.path.join(root, os.path.basename(self.path.split("?")[0]))
        if os.path.isfile(path + ".redirect"):
            with open(path + ".redirect") as f:
                location = f.read().strip()
            self.send_response(302)
            self.send_header("Location", location)
            self.end_headers()
            return
        if not os.path.isfile(path):
            self.send_response(404)
            self.end_headers()
            return
        with open(path, "rb") as f:
            body = f.read()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, *args):
        pass
http.server.ThreadingHTTPServer(("127.0.0.1", int(sys.argv[1])), Handler).serve_forever()
`

func startFeed(t *testing.T) *feedServer {
	t.Helper()
	scriptDir, dir := t.TempDir(), t.TempDir()
	script := filepath.Join(scriptDir, "feed.py")
	if err := os.WriteFile(script, []byte(feedScript), 0o600); err != nil {
		t.Fatal(err)
	}
	addr := freeAddress(t)
	port := addr[strings.LastIndex(addr, ":")+1:]
	cmd := exec.Command("python3", "-I", script, port, dir)
	cmd.Stdout, cmd.Stderr = os.Stderr, os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("starting the feed: %v", err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	f := &feedServer{dir: dir, url: "http://" + addr}
	f.write(t, "ready", "ok")
	eventually(t, "the feed to answer on "+f.url, func() (bool, string) {
		resp, err := http.Get(f.url + "/ready")
		if err != nil {
			return false, err.Error()
		}
		_ = resp.Body.Close()
		return resp.StatusCode == http.StatusOK, resp.Status
	})
	t.Logf("feed serving %s on %s", dir, f.url)
	return f
}

// write replaces the file name of the feed, at once: the server never sees half of it.
func (f *feedServer) write(t *testing.T, name, content string) {
	t.Helper()
	tmp := filepath.Join(f.dir, "."+name+".tmp")
	if err := os.WriteFile(tmp, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmp, filepath.Join(f.dir, name)); err != nil {
		t.Fatal(err)
	}
}

// list writes name as a YAML list of CIDRs.
func (f *feedServer) list(t *testing.T, name string, cidrs ...string) {
	t.Helper()
	b, _ := json.Marshal(cidrs) // JSON is YAML
	f.write(t, name, string(b))
}

type applyDelayScenario struct {
	ctx   context.Context
	c     client.Client
	ns    string
	delay time.Duration
	feed  *feedServer
	// applyAfter is when the CIDR held in addition-waits is due.
	applyAfter time.Time
}

const (
	cidrA = "192.0.2.0/24"
	cidrB = "198.51.100.0/24"
	cidrC = "203.0.113.0/24"
)

func (s *applyDelayScenario) get(t *testing.T) *ipamv1alpha1.CIDRs {
	t.Helper()
	obj, err := getCIDRs(s.ctx, s.c, s.ns, applyDelayCIDRs)
	if err != nil {
		t.Fatalf("reading CIDRs %s/%s: %v", s.ns, applyDelayCIDRs, err)
	}
	return obj
}

// edit changes the object, retried on conflicts with the controller's status writes.
func (s *applyDelayScenario) edit(t *testing.T, change func(*ipamv1alpha1.CIDRs)) {
	t.Helper()
	err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		obj, err := getCIDRs(s.ctx, s.c, s.ns, applyDelayCIDRs)
		if err != nil {
			return err
		}
		change(obj)
		return s.c.Update(s.ctx, obj)
	})
	if err != nil {
		t.Fatalf("updating CIDRs %s/%s: %v", s.ns, applyDelayCIDRs, err)
	}
}

// poke changes an annotation: the controller reconciles, so fetches the feed again, without any
// change of the spec.
func (s *applyDelayScenario) poke(t *testing.T) {
	t.Helper()
	s.edit(t, func(obj *ipamv1alpha1.CIDRs) {
		if obj.Annotations == nil {
			obj.Annotations = map[string]string{}
		}
		obj.Annotations[pokeAnnotation] = time.Now().Format(time.RFC3339Nano)
	})
}

// waitStatus waits, at most within, until the status has exactly cidrs and pending (both sorted),
// and returns the object.
func (s *applyDelayScenario) waitStatus(t *testing.T, within time.Duration, cidrs, pending []string) *ipamv1alpha1.CIDRs {
	t.Helper()
	deadline := time.Now().Add(within)
	for {
		obj := s.get(t)
		gotPending := pendingCIDRsOf(obj)
		if slices.Equal(obj.Status.CIDRs, cidrs) && slices.Equal(gotPending, pending) {
			return obj
		}
		if time.Now().After(deadline) {
			_, cond := upToDate(obj)
			t.Fatalf("timed out after %s waiting for status.cidrs=%v, pending=%v; got cidrs=%v, pending=%v, %s", within, cidrs, pending, obj.Status.CIDRs, gotPending, cond)
		}
		time.Sleep(pollInterval)
	}
}

func pendingCIDRsOf(obj *ipamv1alpha1.CIDRs) []string {
	var out []string
	for _, p := range obj.Status.Pending {
		out = append(out, p.CIDRs...)
	}
	slices.Sort(out)
	return out
}

// immediate is how soon a change that must not wait has to show: well under the delay.
func (s *applyDelayScenario) immediate() time.Duration { return s.delay / 2 }

func (s *applyDelayScenario) firstList(t *testing.T) {
	s.feed.list(t, "feed", cidrA)
	err := createCIDRs(s.ctx, s.c, s.ns, applyDelayCIDRs, ipamv1alpha1.CIDRsSpec{
		CIDRsSource: ipamv1alpha1.CIDRsSource{Location: ipamv1alpha1.CIDRsLocation{URI: s.feed.url + "/feed"}},
	})
	if err != nil {
		t.Fatalf("creating CIDRs: %v", err)
	}
	obj := s.waitStatus(t, s.immediate(), []string{cidrA}, nil)
	if obj.Status.SourceHash == "" {
		t.Errorf("status.sourceHash is empty after a successful fetch")
	}
}

func (s *applyDelayScenario) additionWaits(t *testing.T) {
	s.feed.list(t, "feed", cidrA, cidrB)
	s.poke(t)
	obj := s.waitStatus(t, s.immediate(), []string{cidrA}, []string{cidrB})
	first := obj.Status.Pending[0]
	s.applyAfter = first.ApplyAfter.Time
	if got := first.ApplyAfter.Sub(first.FirstSeen.Time); got != s.delay {
		t.Errorf("applyAfter - firstSeen = %s, want the delay %s", got, s.delay)
	}
	if _, cond := upToDate(obj); !strings.Contains(cond, "--cidr-source-apply-delay") {
		t.Errorf("the UpToDate condition doesn't say CIDRs wait: %s", cond)
	}

	// A refetch before it is due neither uses it nor restarts its clock.
	time.Sleep(s.delay / 4)
	s.poke(t)
	until := s.applyAfter.Add(-5 * time.Second)
	for time.Now().Before(until) {
		obj = s.get(t)
		if !slices.Equal(obj.Status.CIDRs, []string{cidrA}) {
			t.Fatalf("status.cidrs=%v %s before %s: the addition didn't wait", obj.Status.CIDRs, time.Until(s.applyAfter).Round(time.Second), s.applyAfter.Format(time.RFC3339))
		}
		if len(obj.Status.Pending) != 1 || !obj.Status.Pending[0].FirstSeen.Equal(&first.FirstSeen) {
			t.Fatalf("pending changed after a refetch: %+v, was firstSeen %s", obj.Status.Pending, first.FirstSeen)
		}
		time.Sleep(pollInterval)
	}
}

func (s *applyDelayScenario) appliedWhenDue(t *testing.T) {
	// No change to the object: the controller comes back on its own when the CIDR is due.
	s.waitStatus(t, time.Until(s.applyAfter)+pollTimeout(), []string{cidrA, cidrB}, nil)
	if early := time.Until(s.applyAfter); early > time.Second {
		t.Errorf("used %s before applyAfter %s", early, s.applyAfter.Format(time.RFC3339))
	}
}

func (s *applyDelayScenario) removalImmediate(t *testing.T) {
	s.feed.list(t, "feed", cidrB)
	s.poke(t)
	s.waitStatus(t, s.immediate(), []string{cidrB}, nil)
}

func (s *applyDelayScenario) redirectWaits(t *testing.T) {
	s.feed.list(t, "other", cidrC)
	s.feed.write(t, "feed.redirect", s.feed.url+"/other")
	s.poke(t)
	// Only cidrC, new, is left: it waits, and as the list must never go empty, cidrB stays.
	obj := s.waitStatus(t, s.immediate(), []string{cidrB}, []string{cidrC})
	if obj.Status.State != ipamv1alpha1.CIDRsStateUpdateFailed {
		t.Errorf("status.state=%s, want %s: the update removing all CIDRs is refused", obj.Status.State, ipamv1alpha1.CIDRsStateUpdateFailed)
	}
}

func (s *applyDelayScenario) uriChangeImmediate(t *testing.T) {
	s.feed.write(t, "json", fmt.Sprintf(`{"a": [%q], "b": [%q]}`, cidrA, cidrB))
	s.edit(t, func(obj *ipamv1alpha1.CIDRs) {
		obj.Spec.CIDRsSource.Location.URI = s.feed.url + "/json"
		obj.Spec.CIDRsSource.Location.CEL = "data.a"
	})
	// cidrA is not in use (cidrB is), yet used at once; what was pending for the old uri goes.
	s.waitStatus(t, s.immediate(), []string{cidrA}, nil)
}

func (s *applyDelayScenario) celChangeImmediate(t *testing.T) {
	s.edit(t, func(obj *ipamv1alpha1.CIDRs) { obj.Spec.CIDRsSource.Location.CEL = "data.a + data.b" })
	s.waitStatus(t, s.immediate(), []string{cidrA, cidrB}, nil)
}

func (s *applyDelayScenario) inlineImmediate(t *testing.T) {
	s.edit(t, func(obj *ipamv1alpha1.CIDRs) { obj.Spec.CIDRs = []string{"203.0.113.7"} })
	s.waitStatus(t, s.immediate(), []string{cidrA, cidrB, "203.0.113.7/32"}, nil)

	s.edit(t, func(obj *ipamv1alpha1.CIDRs) { obj.Spec.CIDRs = nil })
	s.waitStatus(t, s.immediate(), []string{cidrA, cidrB}, nil)
}
