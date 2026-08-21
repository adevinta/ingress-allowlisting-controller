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

	_ "k8s.io/client-go/plugin/pkg/client/auth/gcp"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/manager/signals"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	"sigs.k8s.io/controller-runtime/pkg/webhook"

	authorizationv1 "k8s.io/api/authorization/v1"
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
	var gatewaySupportEnabled bool
	var networkPolicySupportEnabled bool
	var httpRouteSupportEnabled bool
	var httpRouteLabelSelector string
	var as string
	var annotationPrefix string
	flag.StringVar(&metricsAddr, "metrics-addr", ":8080", "The address the metric endpoint binds to.")
	flag.BoolVar(&enableLeaderElection, "enable-leader-election", false,
		"Enable leader election for controller manager. "+
			"Enabling this will ensure there is only one active controller manager.")
	flag.BoolVar(&gatewaySupportEnabled, "gateway-support-enabled", false, "Enable gateway support for the controller")
	flag.BoolVar(&networkPolicySupportEnabled, "networkpolicy-support-enabled", false, "Enable networkpolicy support for the controller")
	flag.BoolVar(&httpRouteSupportEnabled, "httproute-support-enabled", false, "Enable HTTPRoute support for the controller")
	flag.StringVar(&httpRouteLabelSelector, "httproute-label-selector", "", "Label selector to filter HTTPRoutes watched by the controller (e.g. 'app.kubernetes.io/managed-by=my-team'). Restricts the informer cache at the API server level.")
	flag.StringVar(&legacyGroupVersion, "legacy-group-version", "", "Enables coexistence of two CRDS with different groups for CIDR objects.")
	flag.StringVar(&as, "as", "", "The user to impersonate to run this controller")
	flag.StringVar(&annotationPrefix, "annotation-prefix", "ipam.adevinta.com", "Enables coexistence of two CRDS with different groups for CIDR objects.")
	flag.Parse()
	ctrl.SetLogger(log.NewLogr(log.DefaultLogger))

	var err error
	scheme, err := controllers.Scheme(legacyGroupVersion)
	if err != nil {
		setupLog.Fatal(err, "unable to register Scheme")
	}

	restConfig := ctrl.GetConfigOrDie()

	if as != "" {
		restConfig.Impersonate.UserName = as
	}

	// nil client is fine here — writers are only used to call RequiredPermissions(), not for K8s ops.
	l4Writers, l7Writers := controllers.BuildWriterRegistries(nil, "preflight", annotationPrefix)
	checkRBAC(restConfig, gatewaySupportEnabled, networkPolicySupportEnabled, httpRouteSupportEnabled, l4Writers, l7Writers)

	mgrOptions := ctrl.Options{
		Scheme: scheme,
		Metrics: metricsserver.Options{
			BindAddress: metricsAddr,
		},
		WebhookServer:    webhook.NewServer(webhook.Options{Port: 9443}),
		LeaderElection:   enableLeaderElection,
		LeaderElectionID: "c72663fe.github.com/adevinta/ingress-allowlisting-controller",
	}
	if httpRouteSupportEnabled && httpRouteLabelSelector != "" {
		selector, err := labels.Parse(httpRouteLabelSelector)
		if err != nil {
			setupLog.Fatal(err, "invalid --httproute-label-selector")
		}
		mgrOptions.Cache = cache.Options{
			ByObject: map[client.Object]cache.ByObject{
				&gatewayApiv1.HTTPRoute{}: {Label: selector},
			},
		}
		setupLog.Infof("HTTPRoute informer cache restricted to label selector: %s", httpRouteLabelSelector)
	}
	mgr, err := ctrl.NewManager(restConfig, mgrOptions)
	if err != nil {
		setupLog.Fatal(err, "unable to start manager")
	}

	if err = controllers.SetupControllersWithManager(mgr, gatewaySupportEnabled, networkPolicySupportEnabled, httpRouteSupportEnabled, legacyGroupVersion, "", annotationPrefix); err != nil {
		setupLog.Fatal(err, "unable to setup controllers")
	}

	// +kubebuilder:scaffold:builder
	setupLog.Info("starting manager")
	if err := mgr.Start(ctx); err != nil {
		setupLog.Fatal(err, "problem running manager")
	}
}

func checkRBAC(restConfig *rest.Config, gatewayEnabled, networkPolicyEnabled, httpRouteEnabled bool, l4Writers writers.L4WriterRegistry, l7Writers writers.L7WriterRegistry) {
	cs := kubernetes.NewForConfigOrDie(restConfig)

	var perms []writers.Permission

	// Always required — CIDRs and secret/configmap sources used by all controllers.
	perms = append(perms,
		writers.Permission{Group: "ipam.adevinta.com", Resource: "cidrs", Verb: "get"},
		writers.Permission{Group: "ipam.adevinta.com", Resource: "clustercidrs", Verb: "get"},
		writers.Permission{Group: "", Resource: "secrets", Verb: "get"},
		writers.Permission{Group: "", Resource: "configmaps", Verb: "get"},
	)

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
