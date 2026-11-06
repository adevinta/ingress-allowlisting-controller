//go:build functional

package functional

import (
	"bytes"
	"context"
	"fmt"
	"maps"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	istiosecurityv1 "istio.io/client-go/pkg/apis/security/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/retry"
	"sigs.k8s.io/controller-runtime/pkg/client"
	gatewayApiv1 "sigs.k8s.io/gateway-api/apis/v1"

	ipamv1alpha1 "github.com/adevinta/ingress-allowlisting-controller/pkg/apis/ipam.adevinta.com/v1alpha1"
	"github.com/adevinta/ingress-allowlisting-controller/pkg/controllers"
	"github.com/adevinta/ingress-allowlisting-controller/pkg/controllers/writers"
)

// TestRestart checks the startup cleanup against a real cluster: the HTTPRoute AuthorizationPolicies
// that are still wanted survive a restart of the controller untouched (same UID: not deleted and
// written again), and only those whose route or merge group is gone are deleted.
//
// Unlike TestFunctional, it runs the controller itself, built from this tree, on this machine with
// IAC_CONTROLLER_ARGS: once to write the policies, then, after changes made while it is down, again
// to run the startup cleanup. No other controller with the same prefix may run meanwhile.
// See docs/functional-tests.md.
func TestRestart(t *testing.T) {
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

	p := buildRestartPlan(ctx, c, cluster)
	p.print(os.Stdout)
	switch confirm := os.Getenv("CONFIRM"); {
	case confirm == "":
		t.Skipf("dry run, nothing was created. To run against this cluster: make functional-restart CONFIRM=%s IAC_CONTROLLER_ARGS=...", cluster.Context)
	case confirm != cluster.Context:
		t.Fatalf("CONFIRM=%q does not match the current context %q; nothing was created", confirm, cluster.Context)
	}
	if len(p.blockers) > 0 {
		t.Fatalf("cannot run: %s", strings.Join(p.blockers, "; "))
	}

	bin := buildController(t)
	kubeconfig := writeKubeconfig(t, cluster.Context)
	createNamespace(t, ctx, c, p.run, p.ns)
	createNamespace(t, ctx, c, p.run, p.peerNS)
	s := newRestartScenario(ctx, c, p)

	first := startController(t, bin, p.args, kubeconfig, "first")
	t.Run("before-restart", s.setup)
	if t.Failed() {
		first.stop(t)
		return
	}
	first.stop(t)
	t.Run("while-down", s.changeWhileDown)
	if t.Failed() {
		return
	}
	second := startController(t, bin, p.args, kubeconfig, "second")
	t.Run("after-restart", s.checkAfterRestart)
	second.stop(t)
}

// restartPlan is what TestRestart would do, printed before anything is created.
type restartPlan struct {
	cluster          clusterTarget
	run, ns, peerNS  string
	args             []string
	annotationPrefix string
	d                discovery
	l4               bool // --gateway-support-enabled: a Gateway's own policy is checked too
	blockers         []string
}

func buildRestartPlan(ctx context.Context, c client.Client, cluster clusterTarget) restartPlan {
	run := randomSuffix()
	base := namespaceLabel + "-" + run
	p := restartPlan{cluster: cluster, run: run, ns: base + "-a", peerNS: base + "-b"}
	ctrl := controllerInfo{Args: strings.Fields(os.Getenv("IAC_CONTROLLER_ARGS"))}
	p.args = ctrl.Args
	p.annotationPrefix = ctrl.flag("annotation-prefix", defaultAnnotationPrefix)
	p.d = discover(ctx, c, ctrl, p.annotationPrefix)
	p.l4 = ctrl.enabled("gateway-support-enabled", false)

	if len(p.args) == 0 {
		p.blockers = append(p.blockers, "IAC_CONTROLLER_ARGS is empty: the test runs the controller itself, with these arguments (at least --httproute-support-enabled)")
	} else if !ctrl.enabled("httproute-support-enabled", false) {
		p.blockers = append(p.blockers, "IAC_CONTROLLER_ARGS must enable --httproute-support-enabled")
	}
	if reason := firstNonEmpty(istioUnavailable(p.d), httpRouteLabelsUnavailable(p.d)); reason != "" {
		p.blockers = append(p.blockers, reason)
	}
	if want := os.Getenv("IAC_ANNOTATION_PREFIX"); want != "" && want != p.annotationPrefix {
		p.blockers = append(p.blockers, fmt.Sprintf("IAC_ANNOTATION_PREFIX is %s, but IAC_CONTROLLER_ARGS use --annotation-prefix %s", want, p.annotationPrefix))
	}
	// A controller in the cluster with the same prefix would reconcile while ours is down, and
	// the startup cleanup would never be what removes the policies.
	deployments, err := controllerDeployments(ctx, c)
	if err != nil {
		p.blockers = append(p.blockers, err.Error())
	}
	for _, d := range deployments {
		info := deploymentInfo(d)
		if info.Ready && info.flag("annotation-prefix", defaultAnnotationPrefix) == p.annotationPrefix {
			p.blockers = append(p.blockers, fmt.Sprintf("controller %s runs in the cluster with --annotation-prefix %s: scale it to 0 first", info.Location, p.annotationPrefix))
		}
	}
	return p
}

func (p restartPlan) print(w *os.File) {
	fmt.Fprintf(w, "\nTarget cluster\n  context:  %s\n  cluster:  %s\n  server:   %s\n  user:     %s\n", p.cluster.Context, p.cluster.Cluster, p.cluster.Server, p.cluster.User)
	fmt.Fprintf(w, "\nController\n  built from this tree and run on this machine, twice, with: %s\n", strings.Join(p.args, " "))
	fmt.Fprintf(w, "  annotation prefix: %s\n", p.annotationPrefix)
	fmt.Fprintf(w, "  no other controller with this prefix may run meanwhile (in the cluster, or a go run of yours)\n")
	fmt.Fprintf(w, "\nWould create namespaces %s and %s (labels %s=true, %s=%s), deleted at the end unless KEEP=1\n", p.ns, p.peerNS, namespaceLabel, runLabel, p.run)
	fmt.Fprintf(w, "\nScenario (Istio, GatewayClass %s)\n", orNone(p.d.istioClass))
	fmt.Fprintf(w, "  1. controller up: Gateways gw-a, gw-b, gw-c in %s, gw-same in %s; merge groups, same- and cross-namespace routes; wait for their policies\n", p.peerNS, p.ns)
	fmt.Fprintf(w, "  2. controller down: delete or change some routes (the members on gw-a and gw-c of a group also on gw-b, a group member, a route, an annotation, a route joining a group)\n")
	fmt.Fprintf(w, "  3. controller up again: only the policies of what is gone are deleted; the others keep their UID for %s\n", absenceWindow)
	if !p.l4 {
		fmt.Fprintf(w, "  (--gateway-support-enabled is off: a Gateway's own policy is not checked)\n")
	}
	if len(p.blockers) > 0 {
		fmt.Fprintf(w, "\nCannot run:\n")
		for _, b := range p.blockers {
			fmt.Fprintf(w, "  - %s\n", b)
		}
	}
	fmt.Fprintln(w)
}

// buildController builds the controller from this tree.
func buildController(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "ingress-allowlisting-controller")
	out, err := exec.Command("go", "build", "-o", bin, "../../cmd/ingress-allowlisting-controller").CombinedOutput()
	if err != nil {
		t.Fatalf("building the controller: %v\n%s", err, out)
	}
	return bin
}

// writeKubeconfig writes the kubeconfig with kubeContext as current context, so the controller
// talks to the cluster under test even when IAC_CONTEXT is not the current context.
func writeKubeconfig(t *testing.T, kubeContext string) string {
	t.Helper()
	raw, err := clientcmd.NewDefaultClientConfigLoadingRules().Load()
	if err != nil {
		t.Fatalf("loading kubeconfig: %v", err)
	}
	raw.CurrentContext = kubeContext
	path := filepath.Join(t.TempDir(), "kubeconfig")
	if err := clientcmd.WriteToFile(*raw, path); err != nil {
		t.Fatalf("writing kubeconfig: %v", err)
	}
	return path
}

// controllerProcess is the controller running on this machine.
type controllerProcess struct {
	name   string
	cmd    *exec.Cmd
	exited chan struct{} // closed once it exits; err is then its exit error
	err    error
}

// startController runs the controller and waits until its probe endpoint answers. Its output goes
// to a log file, kept when the test fails.
func startController(t *testing.T, bin string, args []string, kubeconfig, name string) *controllerProcess {
	t.Helper()
	probe := freeAddress(t)
	logPath := filepath.Join(os.TempDir(), fmt.Sprintf("iac-restart-%s-%d.log", name, time.Now().Unix()))
	logFile, err := os.Create(logPath)
	if err != nil {
		t.Fatal(err)
	}
	// Later flags win: our probe address, and no metrics endpoint, which would clash between runs.
	all := append(slices.Clone(args), "--health-probe-bind-address="+probe, "--metrics-addr=0")
	cmd := exec.Command(bin, all...)
	cmd.Env = append(os.Environ(), "KUBECONFIG="+kubeconfig)
	cmd.Stdout, cmd.Stderr = logFile, logFile
	if err := cmd.Start(); err != nil {
		t.Fatalf("starting the controller: %v", err)
	}
	p := &controllerProcess{name: name, cmd: cmd, exited: make(chan struct{})}
	go func() {
		p.err = cmd.Wait()
		_ = logFile.Close()
		close(p.exited)
	}()
	t.Cleanup(func() {
		p.stop(t)
		if t.Failed() {
			t.Logf("controller (%s run) log %s, last lines:\n%s", name, logPath, tail(logPath))
			return
		}
		_ = os.Remove(logPath)
	})
	t.Logf("controller (%s run) started, pid %d, log %s", name, cmd.Process.Pid, logPath)

	eventually(t, "the controller ("+name+" run) to answer on "+probe+"/readyz", func() (bool, string) {
		select {
		case <-p.exited:
			t.Fatalf("the controller (%s run) exited: %v; log %s:\n%s", name, p.err, logPath, tail(logPath))
		default:
		}
		resp, err := http.Get("http://" + probe + "/readyz")
		if err != nil {
			return false, err.Error()
		}
		_ = resp.Body.Close()
		return resp.StatusCode == http.StatusOK, resp.Status
	})
	return p
}

// stop interrupts the controller and waits for it to exit (killed after 30s). Calling it again
// does nothing. The log is kept if the test fails, and printed.
func (p *controllerProcess) stop(t *testing.T) {
	t.Helper()
	select {
	case <-p.exited:
		return
	default:
	}
	_ = p.cmd.Process.Signal(os.Interrupt)
	select {
	case <-p.exited:
	case <-time.After(30 * time.Second):
		_ = p.cmd.Process.Kill()
		<-p.exited
	}
}

func freeAddress(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	_ = l.Close()
	return addr
}

func tail(path string) string {
	data, _ := os.ReadFile(path)
	lines := bytes.Split(bytes.TrimRight(data, "\n"), []byte("\n"))
	if len(lines) > 40 {
		lines = lines[len(lines)-40:]
	}
	return string(bytes.Join(lines, []byte("\n")))
}

const (
	restartGwA, restartGwB, restartGwSame = "restart-gw-a", "restart-gw-b", "restart-gw-same"
	// restartGwC has only one route, in a group also on gw-b, deleted while the controller is down:
	// no route of the Gateway reconciles then, so only the startup cleanup can delete its policy.
	// On gw-a, the reconcile of its other routes would.
	restartGwC        = "restart-gw-c"
	restartGwL4       = "restart-gw-l4"
	restartCIDRs      = "restart"
	sharedKey, twoKey = "restart-shared", "restart-two"
)

// longKey is longer than a label value (63): the merged policy's owner-name label is shortened.
var longKey = "restart-long-" + strings.Repeat("k", 60)

// restartScenario holds the objects of TestRestart and the policies that must survive the restart.
type restartScenario struct {
	ctx        context.Context
	c          client.Client
	p          restartPlan
	annotation string
	merge      string
	kept       map[string]types.UID                 // namespace/name of each policy that must survive → its UID
	foreign    *istiosecurityv1.AuthorizationPolicy // another instance's policy, as created
}

func newRestartScenario(ctx context.Context, c client.Client, p restartPlan) *restartScenario {
	return &restartScenario{ctx: ctx, c: c, p: p, annotation: p.annotationPrefix + "/allowlist-group",
		merge: p.annotationPrefix + "/merge", kept: map[string]types.UID{}}
}

// route returns a route of the main namespace with the allowlist annotation, attached to gw: one
// of the peer namespace's Gateways, or gw-same in its own namespace. mergeKey "" means no group.
func (s *restartScenario) route(name, gw, mergeKey string) *gatewayApiv1.HTTPRoute {
	annotations := map[string]string{s.annotation: restartCIDRs}
	if mergeKey != "" {
		annotations[s.merge] = mergeKey
	}
	route := newHTTPRoute(s.p.d, s.p.ns, name, gw, annotations)
	if gw != restartGwSame {
		attachTo(route, s.p.peerNS, gw)
	}
	return route
}

func (s *restartScenario) setup(t *testing.T) {
	ctx, c, ns, peer := s.ctx, s.c, s.p.ns, s.p.peerNS
	spec := ipamv1alpha1.CIDRsSpec{CIDRsSource: ipamv1alpha1.CIDRsSource{CIDRs: []string{"203.0.113.0/24"}}}
	if err := createCIDRs(ctx, c, ns, restartCIDRs, spec); err != nil {
		t.Fatalf("creating CIDRs: %v", err)
	}
	gateways := []*gatewayApiv1.Gateway{
		allowRoutesFrom(newGateway(peer, restartGwA, s.p.d.istioClass, true, nil), gatewayApiv1.NamespacesFromAll),
		allowRoutesFrom(newGateway(peer, restartGwB, s.p.d.istioClass, true, nil), gatewayApiv1.NamespacesFromAll),
		allowRoutesFrom(newGateway(peer, restartGwC, s.p.d.istioClass, true, nil), gatewayApiv1.NamespacesFromAll),
		newGateway(ns, restartGwSame, s.p.d.istioClass, true, nil),
	}
	if s.p.l4 {
		gateways = append(gateways, newGateway(ns, restartGwL4, s.p.d.istioClass, true, map[string]string{s.annotation: restartCIDRs}))
	}
	paths := s.route("same-paths", restartGwSame, "")
	paths.Spec.Rules = []gatewayApiv1.HTTPRouteRule{pathRule("/api"), pathRule("/admin")}
	routes := []*gatewayApiv1.HTTPRoute{
		s.route("shared-a", restartGwA, sharedKey), // the only member on gw-a of a group also on gw-b
		s.route("shared-b", restartGwB, sharedKey),
		s.route("shared-c", restartGwC, sharedKey), // gw-c's only route
		s.route("two-1", restartGwA, twoKey),
		s.route("two-2", restartGwA, twoKey),
		s.route("long-1", restartGwB, longKey),
		s.route("same-1", restartGwSame, ""),
		paths, // two rules with paths: two policies
		s.route("cross-1", restartGwA, ""),
		s.route("cross-deleted", restartGwB, ""),
		s.route("cross-unannotated", restartGwA, ""),
		s.route("joins", restartGwA, ""),
	}
	for _, obj := range append(asObjects(gateways), asObjects(routes)...) {
		if err := c.Create(ctx, obj); err != nil {
			t.Fatalf("creating %T %s/%s: %v", obj, obj.GetNamespace(), obj.GetName(), err)
		}
	}
	// Another instance's policy on gw-a, as in the other-instance scenario: never touched.
	foreign := foreignPolicy(peer, "restart-foreign", foreignLabels(writers.OwnerKindHTTPRoute, ns, "cross-1"))
	if err := c.Create(ctx, foreign); err != nil {
		t.Fatalf("creating another instance's policy: %v", err)
	}
	s.foreign = foreign

	merged := func(gw, key string, hosts ...string) {
		name := writers.MergedPolicyName(s.p.annotationPrefix, gw, key)
		s.waitPolicy(t, peer, name, hosts)
	}
	merged(restartGwA, sharedKey, "shared-a")
	merged(restartGwB, sharedKey, "shared-b")
	merged(restartGwC, sharedKey, "shared-c")
	merged(restartGwA, twoKey, "two-1", "two-2")
	merged(restartGwB, longKey, "long-1")
	s.waitOwn(t, ns, "same-1", 1)
	s.waitOwn(t, ns, "same-paths", 2)
	for _, name := range []string{"cross-1", "cross-deleted", "cross-unannotated", "joins"} {
		s.waitOwn(t, peer, name, 1)
	}
	if s.p.l4 {
		eventually(t, "Gateway "+ns+"/"+restartGwL4+"'s own AuthorizationPolicy", func() (bool, string) {
			policy := &istiosecurityv1.AuthorizationPolicy{}
			if err := c.Get(ctx, client.ObjectKey{Namespace: ns, Name: restartGwL4}, policy); err != nil {
				return false, err.Error()
			}
			s.kept[ns+"/"+restartGwL4] = policy.UID
			return true, ""
		})
	}
	// Deleted at the restart, so not kept: gw-a's and gw-c's policies of the shared group, and the
	// policies of cross-deleted, cross-unannotated and joins.
	for _, gw := range []string{restartGwA, restartGwC} {
		delete(s.kept, peer+"/"+writers.MergedPolicyName(s.p.annotationPrefix, gw, sharedKey))
	}
	for _, name := range []string{"cross-deleted", "cross-unannotated", "joins"} {
		for key := range s.ownPolicies(t, peer, name) {
			delete(s.kept, key)
		}
	}
	t.Logf("%d policies must survive the restart", len(s.kept))
}

// changeWhileDown changes what the startup cleanup will meet: no reconcile sees these changes.
func (s *restartScenario) changeWhileDown(t *testing.T) {
	ctx, c, ns := s.ctx, s.c, s.p.ns
	for _, name := range []string{"shared-a", "shared-c", "two-2", "cross-deleted"} {
		if err := c.Delete(ctx, &gatewayApiv1.HTTPRoute{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name}}); err != nil {
			t.Fatalf("deleting HTTPRoute %s: %v", name, err)
		}
	}
	if err := removeAnnotation(ctx, c, &gatewayApiv1.HTTPRoute{}, ns, "cross-unannotated", s.annotation); err != nil {
		t.Fatalf("removing the allowlist annotation of cross-unannotated: %v", err)
	}
	err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		route := &gatewayApiv1.HTTPRoute{}
		if err := c.Get(ctx, client.ObjectKey{Namespace: ns, Name: "joins"}, route); err != nil {
			return err
		}
		route.Annotations[s.merge] = twoKey
		return c.Update(ctx, route)
	})
	if err != nil {
		t.Fatalf("adding joins to group %s: %v", twoKey, err)
	}
}

func (s *restartScenario) checkAfterRestart(t *testing.T) {
	ctx, c, peer := s.ctx, s.c, s.p.peerNS
	gone := func(what, policyNS, name string) {
		eventually(t, what, func() (bool, string) {
			err := c.Get(ctx, client.ObjectKey{Namespace: policyNS, Name: name}, &istiosecurityv1.AuthorizationPolicy{})
			return apierrors.IsNotFound(err), fmt.Sprintf("AuthorizationPolicy %s/%s: %v", policyNS, name, err)
		})
	}
	for _, gw := range []string{restartGwA, restartGwC} {
		gone(gw+"'s merged policy of group "+sharedKey+" deleted, though the key is still used on gw-b",
			peer, writers.MergedPolicyName(s.p.annotationPrefix, gw, sharedKey))
	}
	for _, name := range []string{"cross-deleted", "cross-unannotated", "joins"} {
		eventually(t, "the own policy of "+name+" deleted", func() (bool, string) {
			own := s.ownPolicies(t, peer, name)
			return len(own) == 0, fmt.Sprintf("%d left", len(own))
		})
	}
	s.waitPolicy(t, peer, writers.MergedPolicyName(s.p.annotationPrefix, restartGwA, twoKey), []string{"joins", "two-1"})

	// The startup cleanup has run. What must survive is still there, with the same UID, for a while.
	for deadline := time.Now().Add(absenceWindow); time.Now().Before(deadline); time.Sleep(pollInterval) {
		for key, uid := range s.kept {
			namespace, name, _ := strings.Cut(key, "/")
			policy := &istiosecurityv1.AuthorizationPolicy{}
			if err := c.Get(ctx, client.ObjectKey{Namespace: namespace, Name: name}, policy); err != nil {
				t.Fatalf("AuthorizationPolicy %s must survive the restart: %v", key, err)
			}
			if policy.UID != uid {
				t.Fatalf("AuthorizationPolicy %s was deleted and written again at the restart (UID %s, was %s)", key, policy.UID, uid)
			}
		}
		policy := &istiosecurityv1.AuthorizationPolicy{}
		if err := c.Get(ctx, client.ObjectKey{Namespace: peer, Name: "restart-foreign"}, policy); err != nil {
			t.Fatalf("another instance's policy: %v", err)
		}
		// Not the resourceVersion: Istio writes a status on policies. The spec (generation), the
		// labels and the owner references are what this controller would change.
		if policy.Generation != s.foreign.Generation || !maps.Equal(policy.Labels, s.foreign.Labels) ||
			len(policy.OwnerReferences) != len(s.foreign.OwnerReferences) {
			t.Fatalf("another instance's policy %s/restart-foreign was changed: generation %d (was %d), labels %v, owner references %v",
				peer, policy.Generation, s.foreign.Generation, policy.Labels, policy.OwnerReferences)
		}
	}
}

// waitPolicy waits for the policy policyNS/name with exactly the hosts of these routes, and keeps
// its UID as one that must survive.
func (s *restartScenario) waitPolicy(t *testing.T, policyNS, name string, routes []string) {
	t.Helper()
	var want []string
	for _, r := range routes {
		want = append(want, r+".functional.invalid")
	}
	slices.Sort(want)
	eventually(t, "AuthorizationPolicy "+policyNS+"/"+name+" with the hosts of "+strings.Join(routes, ", "), func() (bool, string) {
		policy := &istiosecurityv1.AuthorizationPolicy{}
		if err := s.c.Get(s.ctx, client.ObjectKey{Namespace: policyNS, Name: name}, policy); err != nil {
			return false, err.Error()
		}
		_, hosts := policyCIDRsAndHosts(policy)
		if !slices.Equal(hosts, want) {
			return false, fmt.Sprintf("hosts %v, want %v", hosts, want)
		}
		s.kept[policyNS+"/"+name] = policy.UID
		return true, ""
	})
}

// waitOwn waits for count policies of the route name in policyNS, and keeps their UIDs.
func (s *restartScenario) waitOwn(t *testing.T, policyNS, name string, count int) {
	t.Helper()
	eventually(t, fmt.Sprintf("%d AuthorizationPolicies of HTTPRoute %s in %s", count, name, policyNS), func() (bool, string) {
		own := s.ownPolicies(t, policyNS, name)
		if len(own) != count {
			return false, fmt.Sprintf("%d", len(own))
		}
		for key, uid := range own {
			s.kept[key] = uid
		}
		return true, ""
	})
}

// ownPolicies returns the policies in policyNS of the route name of the main namespace.
func (s *restartScenario) ownPolicies(t *testing.T, policyNS, name string) map[string]types.UID {
	t.Helper()
	list := &istiosecurityv1.AuthorizationPolicyList{}
	if err := s.c.List(s.ctx, list, client.InNamespace(policyNS), ownerLabels(s.p.d, s.p.ns, name)); err != nil {
		t.Fatal(err)
	}
	own := map[string]types.UID{}
	for _, policy := range list.Items {
		own[policy.Namespace+"/"+policy.Name] = policy.UID
	}
	return own
}

func pathRule(path string) gatewayApiv1.HTTPRouteRule {
	pathType := gatewayApiv1.PathMatchPathPrefix
	return gatewayApiv1.HTTPRouteRule{Matches: []gatewayApiv1.HTTPRouteMatch{{Path: &gatewayApiv1.HTTPPathMatch{Type: &pathType, Value: &path}}}}
}

func asObjects[T client.Object](objs []T) []client.Object {
	out := make([]client.Object, 0, len(objs))
	for _, o := range objs {
		out = append(out, o)
	}
	return out
}
