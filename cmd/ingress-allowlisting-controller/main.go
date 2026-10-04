/*


Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package main

import (
	"context"
	"flag"
	"fmt"
	"strings"

	_ "k8s.io/client-go/plugin/pkg/client/auth/gcp"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client/apiutil"
	"sigs.k8s.io/controller-runtime/pkg/manager/signals"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	"sigs.k8s.io/controller-runtime/pkg/webhook"

	authorizationv1 "k8s.io/api/authorization/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"
	gatewayApiv1 "sigs.k8s.io/gateway-api/apis/v1"

	log "github.com/adevinta/go-log-toolkit"
	"github.com/adevinta/ingress-allowlisting-controller/pkg/controllers"
	"github.com/adevinta/ingress-allowlisting-controller/pkg/controllers/writers"
	// +kubebuilder:scaffold:imports
)

var (
	setupLog           = log.DefaultLogger.WithField("setup", "bootstrap")
	legacyGroupVersion string
	mainContext        = signals.SetupSignalHandler()
)

func main() {
	ctx := mainContext
	var metricsAddr string
	var enableLeaderElection bool
	var ingressSupportEnabled bool
	var gatewaySupportEnabled bool
	var networkPolicySupportEnabled bool
	var serviceSupportEnabled bool
	var httpRouteSupportEnabled bool
	var httpRouteLabelSelector string
	var secretLabelSelector string
	var as string
	var annotationPrefix string
	var httpHeadersEnabled bool
	cidrSource := controllers.DefaultCIDRSourceOptions()
	var allowlist stringListFlag
	flag.StringVar(&metricsAddr, "metrics-addr", ":8080", "The address the metric endpoint binds to.")
	flag.BoolVar(&enableLeaderElection, "enable-leader-election", false,
		"Enable leader election for controller manager. "+
			"Enabling this will ensure there is only one active controller manager.")
	flag.StringVar(&legacyGroupVersion, "legacy-group-version", "", "Enables coexistence of two CRDS with different groups for CIDR objects.")
	flag.StringVar(&as, "as", "", "The user to impersonate to run this controller")
	flag.StringVar(&annotationPrefix, "annotation-prefix", "ipam.adevinta.com", "Enables coexistence of two CRDS with different groups for CIDR objects.")
	flagGroup("CIDRs / ClusterCIDRs", func() {
		flag.BoolVar(&httpHeadersEnabled, "http-headers-enabled", true, "Enable reading Secrets and ConfigMaps as HTTP header sources for CIDR URL fetches. Disabling removes secret/configmap access entirely and skips reactive re-reconciliation on their changes.")
		flag.StringVar(&secretLabelSelector, "secret-label-selector", "", "Label selector to restrict which Secrets and ConfigMaps are cached as HTTP header sources (e.g. 'ipam.adevinta.com/cidr-header-source=true'). Only effective when --http-headers-enabled=true.")
		flag.IntVar(&cidrSource.MinMaskIPv4, "cidr-source-min-mask-ipv4", cidrSource.MinMaskIPv4, "Widest IPv4 prefix (smallest mask length) accepted from a remote CIDR source. A fetch containing a wider prefix is rejected and the last-known-good allowlist is kept. Range 1-32.")
		flag.IntVar(&cidrSource.MinMaskIPv6, "cidr-source-min-mask-ipv6", cidrSource.MinMaskIPv6, "Widest IPv6 prefix (smallest mask length) accepted from a remote CIDR source. A fetch containing a wider prefix is rejected and the last-known-good allowlist is kept. Range 1-128.")
		flag.DurationVar(&cidrSource.FetchTimeout, "cidr-source-fetch-timeout", cidrSource.FetchTimeout, "Maximum time for fetching and processing one remote CIDR source (connect, response headers, body and processing).")
		flag.Int64Var(&cidrSource.MaxResponseBytes, "cidr-source-max-response-bytes", cidrSource.MaxResponseBytes, "Maximum size in bytes of a remote CIDR source response body. A larger response fails the fetch; it is never truncated.")
		flag.Uint64Var(&cidrSource.CELCostLimit, "cidr-source-cel-cost-limit", cidrSource.CELCostLimit, "Maximum estimated cost of one CEL expression evaluated on a remote CIDR source. Exceeding it fails the fetch.")
		flag.DurationVar(&cidrSource.RetryInterval, "cidr-source-retry-interval", cidrSource.RetryInterval, "How soon a failed remote CIDR source fetch is retried. An object with a shorter spec.requeueAfter is retried at that interval instead.")
		flag.Var(&allowlist, "cidr-source-allowlist", "Origin a remote CIDR source may be fetched from, as scheme://host[:port]; a bare host[:port] means https. Repeat the flag or comma-separate to allow several (e.g. https://ip-ranges.amazonaws.com,http://ip-ranges.amazonaws.com). Exact host match: no wildcards, no path or prefix matching. Redirect targets are checked too. When empty, any host is allowed (a warning is logged at startup).")
		flag.BoolVar(&cidrSource.AllowPrivateDestinations, "cidr-source-allow-private-destinations", cidrSource.AllowPrivateDestinations, "Allow remote CIDR sources to connect to non-public addresses (loopback, link-local incl. cloud metadata, private, CGNAT). By default such connections are refused. Enable only for feeds that are really internal.")
	})
	flagGroup("Gateway (Istio)", func() {
		flag.BoolVar(&gatewaySupportEnabled, "gateway-support-enabled", false, "Enable gateway support for the controller")
	})
	flagGroup("HTTPRoute (Istio / Traefik)", func() {
		flag.BoolVar(&httpRouteSupportEnabled, "httproute-support-enabled", false, "Enable HTTPRoute support for the controller")
		flag.StringVar(&httpRouteLabelSelector, "httproute-label-selector", "", "Label selector to filter HTTPRoutes watched by the controller (e.g. 'app.kubernetes.io/managed-by=my-team'). Restricts the informer cache at the API server level.")
	})
	flagGroup("Ingress (nginx)", func() {
		flag.BoolVar(&ingressSupportEnabled, "ingress-support-enabled", true, "Enable Ingress support for the controller")
	})
	flagGroup("NetworkPolicy", func() {
		flag.BoolVar(&networkPolicySupportEnabled, "networkpolicy-support-enabled", false, "Enable networkpolicy support for the controller")
	})
	flagGroup("Service (LoadBalancer)", func() {
		flag.BoolVar(&serviceSupportEnabled, "service-support-enabled", false, "Enable Service loadBalancerSourceRanges support for the controller")
	})
	flag.Usage = func() { printUsage(flag.CommandLine, flagGroups) }
	flag.Parse()
	cidrSource.Allowlist = allowlist
	ctrl.SetLogger(log.NewLogr(log.DefaultLogger))

	if err := cidrSource.Validate(); err != nil {
		setupLog.Fatal(err, " <- invalid --cidr-source-* flags, fix them and restart")
	}
	// These are protections: loosening them widens the blast radius of a broken feed, so the
	// effective values (and warnings about permissive ones) are always in the startup log.
	cidrSource.LogEffective()

	var err error
	scheme, err := controllers.Scheme(legacyGroupVersion)
	if err != nil {
		setupLog.Fatal(err, "unable to register Scheme")
	}

	restConfig := ctrl.GetConfigOrDie()

	if as != "" {
		restConfig.Impersonate.UserName = as
	}

	// Build a REST mapper from the rest config for pre-flight CRD detection.
	// This runs before the manager starts, so we can't use mgr.GetRESTMapper() yet.
	httpClient, err := rest.HTTPClientFor(restConfig)
	if err != nil {
		setupLog.Fatal(err, "unable to create http client for REST mapper")
	}
	preflightMapper, err := apiutil.NewDynamicRESTMapper(restConfig, httpClient)
	if err != nil {
		setupLog.Fatal(err, "unable to create REST mapper for preflight")
	}

	// nil client is fine here — writers are only used to call RequiredPermissions(), not for K8s ops.
	l4Writers, l7Writers := controllers.BuildWriterRegistries(nil, preflightMapper, "preflight", annotationPrefix)
	checkRBAC(restConfig, gatewaySupportEnabled, networkPolicySupportEnabled, serviceSupportEnabled, httpRouteSupportEnabled, httpHeadersEnabled, l4Writers, l7Writers)

	mgrOptions := ctrl.Options{
		Scheme: scheme,
		Metrics: metricsserver.Options{
			BindAddress: metricsAddr,
		},
		WebhookServer:    webhook.NewServer(webhook.Options{Port: 9443}),
		LeaderElection:   enableLeaderElection,
		LeaderElectionID: "c72663fe.github.com/adevinta/ingress-allowlisting-controller",
	}
	byObject := map[client.Object]cache.ByObject{}
	if httpRouteSupportEnabled && httpRouteLabelSelector != "" {
		selector, err := labels.Parse(httpRouteLabelSelector)
		if err != nil {
			setupLog.Fatal(err, "invalid --httproute-label-selector")
		}
		byObject[&gatewayApiv1.HTTPRoute{}] = cache.ByObject{Label: selector}
		setupLog.Infof("HTTPRoute informer cache restricted to label selector: %s", httpRouteLabelSelector)
	}
	if httpHeadersEnabled && secretLabelSelector != "" {
		selector, err := labels.Parse(secretLabelSelector)
		if err != nil {
			setupLog.Fatal(err, "invalid --secret-label-selector")
		}
		byObject[&corev1.Secret{}] = cache.ByObject{Label: selector}
		byObject[&corev1.ConfigMap{}] = cache.ByObject{Label: selector}
		setupLog.Infof("Secret/ConfigMap informer cache restricted to label selector: %s", secretLabelSelector)
	}
	if len(byObject) > 0 {
		mgrOptions.Cache = cache.Options{ByObject: byObject}
	}
	mgr, err := ctrl.NewManager(restConfig, mgrOptions)
	if err != nil {
		setupLog.Fatal(err, "unable to start manager")
	}

	if err = controllers.SetupControllersWithManager(mgr, ingressSupportEnabled, gatewaySupportEnabled, networkPolicySupportEnabled, serviceSupportEnabled, httpRouteSupportEnabled, legacyGroupVersion, "", annotationPrefix, httpHeadersEnabled, cidrSource); err != nil {
		setupLog.Fatal(err, "unable to setup controllers")
	}

	// +kubebuilder:scaffold:builder
	setupLog.Info("starting manager")
	if err := mgr.Start(ctx); err != nil {
		setupLog.Fatal(err, "problem running manager")
	}
}

// stringListFlag is a flag that can be repeated and also accepts comma-separated values.
type stringListFlag []string

func (f *stringListFlag) String() string { return strings.Join(*f, ",") }

func (f *stringListFlag) Set(value string) error {
	for _, part := range strings.Split(value, ",") {
		if part = strings.TrimSpace(part); part != "" {
			*f = append(*f, part)
		}
	}
	return nil
}

func checkRBAC(restConfig *rest.Config, gatewayEnabled, networkPolicyEnabled, serviceEnabled, httpRouteEnabled, httpHeadersEnabled bool, l4Writers writers.L4WriterRegistry, l7Writers writers.L7WriterRegistry) {
	cs := kubernetes.NewForConfigOrDie(restConfig)

	var perms []writers.Permission

	perms = append(perms,
		writers.Permission{Group: "ipam.adevinta.com", Resource: "cidrs", Verb: "get"},
		writers.Permission{Group: "ipam.adevinta.com", Resource: "clustercidrs", Verb: "get"},
	)
	if httpHeadersEnabled {
		perms = append(perms,
			writers.Permission{Group: "", Resource: "secrets", Verb: "get"},
			writers.Permission{Group: "", Resource: "configmaps", Verb: "get"},
		)
	}

	if gatewayEnabled {
		perms = append(perms,
			writers.Permission{Group: "gateway.networking.k8s.io", Resource: "gateways", Verb: "get"},
			writers.Permission{Group: "gateway.networking.k8s.io", Resource: "gatewayclasses", Verb: "get"},
		)
		for _, w := range l4Writers {
			if pp, ok := w.(writers.PermissionProvider); ok {
				perms = append(perms, pp.RequiredPermissions()...)
			}
		}
	}

	if httpRouteEnabled {
		perms = append(perms,
			writers.Permission{Group: "gateway.networking.k8s.io", Resource: "httproutes", Verb: "get"},
			writers.Permission{Group: "gateway.networking.k8s.io", Resource: "gateways", Verb: "get"},
			writers.Permission{Group: "gateway.networking.k8s.io", Resource: "gatewayclasses", Verb: "get"},
		)
		for _, w := range l7Writers {
			if pp, ok := w.(writers.PermissionProvider); ok {
				perms = append(perms, pp.RequiredPermissions()...)
			}
		}
	}

	if networkPolicyEnabled {
		perms = append(perms,
			writers.Permission{Group: "networking.k8s.io", Resource: "networkpolicies", Verb: "get"},
			writers.Permission{Group: "networking.k8s.io", Resource: "networkpolicies", Verb: "update"},
		)
	}

	if serviceEnabled {
		perms = append(perms,
			writers.Permission{Group: "", Resource: "services", Verb: "get"},
			writers.Permission{Group: "", Resource: "services", Verb: "update"},
		)
	}

	// Deduplicate before checking.
	seen := map[writers.Permission]struct{}{}
	for _, p := range perms {
		if _, already := seen[p]; already {
			continue
		}
		seen[p] = struct{}{}

		sar := &authorizationv1.SelfSubjectAccessReview{
			Spec: authorizationv1.SelfSubjectAccessReviewSpec{
				ResourceAttributes: &authorizationv1.ResourceAttributes{
					Verb:     p.Verb,
					Group:    p.Group,
					Resource: p.Resource,
				},
			},
		}
		result, err := cs.AuthorizationV1().SelfSubjectAccessReviews().Create(
			context.Background(), sar, metav1.CreateOptions{},
		)
		if err != nil {
			setupLog.Fatal(fmt.Errorf("RBAC preflight: cannot check %s %s/%s: %w", p.Verb, p.Group, p.Resource, err), "preflight failed")
		}
		if !result.Status.Allowed {
			setupLog.Fatal(fmt.Errorf("missing permission: cannot %s %s/%s — fix ClusterRole and redeploy", p.Verb, p.Group, p.Resource), "RBAC preflight failed")
		}
	}
}
