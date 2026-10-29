//go:build functional

package functional

import (
	"context"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"

	appsv1 "k8s.io/api/apps/v1"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// clusterTarget is the cluster the suite talks to: the current kube context, or IAC_CONTEXT.
type clusterTarget struct {
	Context string
	Cluster string
	User    string
	Server  string
	Config  *rest.Config
}

func loadClusterTarget() (clusterTarget, error) {
	overrides := &clientcmd.ConfigOverrides{CurrentContext: os.Getenv("IAC_CONTEXT")}
	loader := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(clientcmd.NewDefaultClientConfigLoadingRules(), overrides)

	raw, err := loader.RawConfig()
	if err != nil {
		return clusterTarget{}, fmt.Errorf("loading kubeconfig: %w", err)
	}
	name := raw.CurrentContext
	if overrides.CurrentContext != "" {
		name = overrides.CurrentContext
	}
	kubeContext, ok := raw.Contexts[name]
	if !ok {
		return clusterTarget{}, fmt.Errorf("kube context %q not found in kubeconfig", name)
	}
	cfg, err := loader.ClientConfig()
	if err != nil {
		return clusterTarget{}, fmt.Errorf("building client config for context %q: %w", name, err)
	}
	return clusterTarget{Context: name, Cluster: kubeContext.Cluster, User: kubeContext.AuthInfo, Server: cfg.Host, Config: cfg}, nil
}

// controllerInfo describes the controller the suite tests against. The suite never deploys or
// runs a controller itself: it checks what the one already in the cluster (or run locally, see
// IAC_CONTROLLER_ARGS) does.
type controllerInfo struct {
	Location string
	Ready    bool
	Args     []string
}

const controllerImageName = "ingress-allowlisting-controller"

// detectController finds the controller's Deployment, or takes its arguments from
// IAC_CONTROLLER_ARGS when the controller runs outside the cluster (e.g. `go run` on a laptop).
// IAC_CONTROLLER=namespace/name picks one Deployment when several match.
func detectController(ctx context.Context, c client.Client) (controllerInfo, error) {
	if args := os.Getenv("IAC_CONTROLLER_ARGS"); args != "" {
		return controllerInfo{Location: "outside the cluster (IAC_CONTROLLER_ARGS)", Ready: true, Args: strings.Fields(args)}, nil
	}

	var candidates []appsv1.Deployment
	list := &appsv1.DeploymentList{}
	if err := c.List(ctx, list, client.MatchingLabels{"chart": controllerImageName}); err != nil {
		return controllerInfo{}, fmt.Errorf("listing deployments: %w", err)
	}
	candidates = list.Items
	if len(candidates) == 0 {
		// Not installed with the Helm chart: fall back to the image name.
		if err := c.List(ctx, list); err != nil {
			return controllerInfo{}, fmt.Errorf("listing deployments: %w", err)
		}
		for _, d := range list.Items {
			if controllerContainerIndex(d) >= 0 {
				candidates = append(candidates, d)
			}
		}
	}
	if pick := os.Getenv("IAC_CONTROLLER"); pick != "" {
		var picked []appsv1.Deployment
		for _, d := range candidates {
			if d.Namespace+"/"+d.Name == pick {
				picked = append(picked, d)
			}
		}
		candidates = picked
	}

	switch len(candidates) {
	case 0:
		return controllerInfo{}, fmt.Errorf("no %s Deployment found; if the controller runs outside the cluster, set IAC_CONTROLLER_ARGS to its arguments", controllerImageName)
	case 1:
	default:
		var names []string
		for _, d := range candidates {
			names = append(names, d.Namespace+"/"+d.Name)
		}
		return controllerInfo{}, fmt.Errorf("several controller Deployments found (%s); pick one with IAC_CONTROLLER=namespace/name", strings.Join(names, ", "))
	}

	d := candidates[0]
	i := controllerContainerIndex(d)
	if i < 0 {
		i = 0
	}
	container := d.Spec.Template.Spec.Containers[i]
	return controllerInfo{
		Location: d.Namespace + "/" + d.Name,
		Ready:    d.Status.AvailableReplicas > 0,
		Args:     append(append([]string{}, container.Command...), container.Args...),
	}, nil
}

func controllerContainerIndex(d appsv1.Deployment) int {
	for i, c := range d.Spec.Template.Spec.Containers {
		if strings.Contains(c.Image, controllerImageName) {
			return i
		}
	}
	return -1
}

// boolFlags lists the controller's boolean flags, which never take the next argument as value.
var boolFlags = map[string]bool{
	"ingress-support-enabled": true, "gateway-support-enabled": true, "httproute-support-enabled": true,
	"networkpolicy-support-enabled": true, "service-support-enabled": true, "http-headers-enabled": true,
	"enable-leader-election": true, "cidr-source-allow-private-destinations": true,
}

// flagValues returns every value given for a controller flag, in order. It understands
// -name / --name, "=value" and, for non-boolean flags, a separate value argument.
func (c controllerInfo) flagValues(name string) []string {
	var values []string
	for i := 0; i < len(c.Args); i++ {
		arg := strings.TrimLeft(c.Args[i], "-")
		if arg == c.Args[i] { // not a flag
			continue
		}
		if key, value, found := strings.Cut(arg, "="); found {
			if key == name {
				values = append(values, value)
			}
			continue
		}
		if arg != name {
			continue
		}
		if !boolFlags[name] && i+1 < len(c.Args) && !strings.HasPrefix(c.Args[i+1], "-") {
			values = append(values, c.Args[i+1])
			i++
			continue
		}
		values = append(values, "true")
	}
	return values
}

func (c controllerInfo) flag(name, def string) string {
	if values := c.flagValues(name); len(values) > 0 {
		return values[len(values)-1]
	}
	return def
}

func (c controllerInfo) enabled(name string, def bool) bool {
	return c.flag(name, fmt.Sprint(def)) == "true"
}

// allowsOrigin reports whether the controller's --cidr-source-allowlist lets it fetch rawURL. An
// empty allowlist allows every host. Entries are scheme://host[:port]; a bare host means https.
func (c controllerInfo) allowsOrigin(rawURL string) bool {
	var entries []string
	for _, v := range c.flagValues("cidr-source-allowlist") {
		for _, e := range strings.Split(v, ",") {
			if e = strings.TrimSpace(e); e != "" {
				entries = append(entries, e)
			}
		}
	}
	if len(entries) == 0 {
		return true
	}
	want := normaliseOrigin(rawURL)
	for _, e := range entries {
		if normaliseOrigin(e) == want {
			return true
		}
	}
	return false
}

func normaliseOrigin(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	if !strings.Contains(s, "://") {
		s = "https://" + s
	}
	scheme, rest, _ := strings.Cut(s, "://")
	host, _, _ := strings.Cut(rest, "/")
	host, _, _ = strings.Cut(host, "?")
	if (scheme == "https" && strings.HasSuffix(host, ":443")) || (scheme == "http" && strings.HasSuffix(host, ":80")) {
		host = host[:strings.LastIndex(host, ":")]
	}
	return scheme + "://" + host
}

// plan is what a run would do, printed in full before anything is created.
type plan struct {
	Cluster    clusterTarget
	Controller controllerInfo
	// ControllerErr is set when no controller could be found; the run is then blocked.
	ControllerErr error
	// CRDErr is set when the CIDRs CRD is not installed; the run is then blocked.
	CRDErr    error
	Namespace string
	// PeerNamespace is the second namespace, for the cross-namespace scenarios.
	PeerNamespace string
	Targets       []plannedTarget
	Sources       []plannedSource
}

type plannedTarget struct {
	target
	Skip string // reason the target is skipped, empty when it runs
}

type plannedSource struct {
	remoteSource
	Skip string
}

func (p plan) blockers() []string {
	var b []string
	if p.ControllerErr != nil {
		b = append(b, p.ControllerErr.Error())
	} else if !p.Controller.Ready {
		b = append(b, fmt.Sprintf("controller %s has no available replica", p.Controller.Location))
	}
	if p.CRDErr != nil {
		b = append(b, p.CRDErr.Error())
	}
	if p.ControllerErr == nil && !slices.ContainsFunc(p.Targets, func(t plannedTarget) bool { return t.Skip == "" }) {
		b = append(b, "every scenario is skipped: enable at least one resource kind on the controller")
	}
	return b
}

func (p plan) print(w io.Writer) {
	fmt.Fprintf(w, "\nTarget cluster\n")
	fmt.Fprintf(w, "  context:  %s\n", p.Cluster.Context)
	fmt.Fprintf(w, "  cluster:  %s\n", p.Cluster.Cluster)
	fmt.Fprintf(w, "  server:   %s\n", p.Cluster.Server)
	fmt.Fprintf(w, "  user:     %s\n", p.Cluster.User)

	fmt.Fprintf(w, "\nController\n")
	if p.ControllerErr != nil {
		fmt.Fprintf(w, "  ✘ %v\n", p.ControllerErr)
	} else {
		state := "✔ available"
		if !p.Controller.Ready {
			state = "✘ no available replica"
		}
		fmt.Fprintf(w, "  %s  %s\n", p.Controller.Location, state)
		fmt.Fprintf(w, "  annotation prefix: %s\n", p.Controller.flag("annotation-prefix", defaultAnnotationPrefix))
	}
	if p.CRDErr != nil {
		fmt.Fprintf(w, "  ✘ %v\n", p.CRDErr)
	}

	fmt.Fprintf(w, "\nWould create namespaces %s and %s (label %s=true), deleted at the end unless KEEP=1\n", p.Namespace, p.PeerNamespace, namespaceLabel)

	fmt.Fprintf(w, "\nScenarios\n")
	for _, t := range p.Targets {
		printPlanned(w, t.name, t.kind, t.Skip)
	}
	fmt.Fprintf(w, "\nRemote CIDR sources (fetched by the controller, not by this test)\n")
	for _, s := range p.Sources {
		printPlanned(w, s.name, s.uri, s.Skip)
	}
	if b := p.blockers(); len(b) > 0 {
		fmt.Fprintf(w, "\nCannot run:\n")
		for _, reason := range b {
			fmt.Fprintf(w, "  - %s\n", reason)
		}
	}
	fmt.Fprintln(w)
}

func printPlanned(w io.Writer, name, detail, skip string) {
	if skip != "" {
		fmt.Fprintf(w, "  ✘ %-18s skipped: %s\n", name, skip)
		return
	}
	fmt.Fprintf(w, "  ✔ %-18s %s\n", name, detail)
}
