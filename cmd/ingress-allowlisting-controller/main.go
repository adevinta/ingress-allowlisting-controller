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
	"flag"

	_ "k8s.io/client-go/plugin/pkg/client/auth/gcp"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/manager/signals"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	"sigs.k8s.io/controller-runtime/pkg/webhook"

	log "github.com/adevinta/go-log-toolkit"
	"github.com/adevinta/ingress-allowlisting-controller/pkg/controllers"
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
	var as string
	var annotationPrefix string
	flag.StringVar(&metricsAddr, "metrics-addr", ":8080", "The address the metric endpoint binds to.")
	flag.BoolVar(&enableLeaderElection, "enable-leader-election", false,
		"Enable leader election for controller manager. "+
			"Enabling this will ensure there is only one active controller manager.")
	flag.BoolVar(&gatewaySupportEnabled, "gateway-support-enabled", false, "Enable gateway support for the controller")
	flag.StringVar(&legacyGroupVersion, "legacy-group-version", "", "Enables coexistence of two CRDS with different groups for CIDR objects.")
	flag.StringVar(&as, "as", "", "The user to impersonate to run this controller")
	flag.StringVar(&annotationPrefix, "annotation-prefix", "ipam.adevinta.com", "Enables coexistence of two CRDS with different groups for CIDR objects.")
	flag.Parse()

	var err error
	scheme, err := controllers.Scheme(legacyGroupVersion)
	if err != nil {
		setupLog.Fatal(err, "unable to register Scheme")
	}

	restConfig := ctrl.GetConfigOrDie()

	if as != "" {
		restConfig.Impersonate.UserName = as
	}

	mgr, err := ctrl.NewManager(restConfig, ctrl.Options{
		Scheme: scheme,
		Metrics: metricsserver.Options{
			BindAddress: metricsAddr,
		},
		WebhookServer:    webhook.NewServer(webhook.Options{Port: 9443}),
		LeaderElection:   enableLeaderElection,
		LeaderElectionID: "c72663fe.github.com/adevinta/ingress-allowlisting-controller",
	})
	if err != nil {
		setupLog.Fatal(err, "unable to start manager")
	}

	if err = controllers.SetupControllersWithManager(mgr, gatewaySupportEnabled, legacyGroupVersion, "", annotationPrefix); err != nil {
		setupLog.Fatal(err, "unable to setup controllers")
	}

	// +kubebuilder:scaffold:builder
	setupLog.Info("starting manager")
	if err := mgr.Start(ctx); err != nil {
		setupLog.Fatal(err, "problem running manager")
	}
}
