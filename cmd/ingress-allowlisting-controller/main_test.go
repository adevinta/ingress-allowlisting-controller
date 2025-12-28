package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"slices"
	"strings"
	"testing"
	"time"

	k8s "github.com/adevinta/go-k8s-toolkit"
	"github.com/adevinta/go-testutils-toolkit"
	ipamv1alpha1 "github.com/adevinta/ingress-allowlisting-controller/pkg/apis/ipam.adevinta.com/v1alpha1"
	ipamv1alpha1_legacy "github.com/adevinta/ingress-allowlisting-controller/pkg/apis/legacy/v1alpha1"
	"github.com/adevinta/ingress-allowlisting-controller/pkg/controllers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	appsv1 "k8s.io/api/apps/v1"
	v1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/e2e-framework/pkg/env"
	"sigs.k8s.io/e2e-framework/pkg/envconf"
	"sigs.k8s.io/e2e-framework/pkg/envfuncs"
	"sigs.k8s.io/e2e-framework/support/kind"
	"sigs.k8s.io/e2e-framework/third_party/helm"
)

var (
	testenv               env.Environment
	releaseName           = "allow-listing-controller"
	kindClusterName       = envconf.RandomName("allowlisting", 16)
	allowListingNamespace = envconf.RandomName("controller", 16)
	testNamespace         = envconf.RandomName("ingress", 16)
)

func testCIDRsStatusIsUpdated(ctx context.Context, t *testing.T, k8sClient client.Client, cidr ipamv1alpha1.CIDRsGetter, expectedCIDRs []string) {
	t.Helper()
	require.NoError(t, k8sClient.Create(ctx, cidr))
	t.Cleanup(func() {
		k8sClient.Delete(ctx, cidr)
	})
	assert.Eventually(t, func() bool {
		err := k8sClient.Get(ctx, client.ObjectKeyFromObject(cidr), cidr)
		require.NoError(t, err)
		return slices.Compare(cidr.GetStatus().CIDRs, expectedCIDRs) == 0
	}, 10*time.Second, 10*time.Millisecond)
}

func deleteAllowlistingDeployment(t *testing.T, k8sClient client.Client) {
	t.Helper()

	require.NoError(t, k8sClient.Delete(context.Background(), &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      releaseName,
			Namespace: allowListingNamespace,
		},
	}))
}

func installAllowlistingController(ctx context.Context, t *testing.T, k8sClient client.Client, legacyGroupVersion string, args ...string) {
	t.Helper()
	helmClient := helm.New(testenv.EnvConf().KubeconfigFile())

	require.NoError(t, helmClient.RunUpgrade(
		helm.WithName(releaseName),
		helm.WithNamespace(allowListingNamespace),
		helm.WithChart("../../helm-chart/ingress-allowlisting-controller"),
		helm.WithArgs(
			"--install",
			"--set", "legacyGroupVersion="+legacyGroupVersion,
		),
		helm.WithArgs(args...),
	))
}

func startMain(t *testing.T, legacyGroupVersion, as string) {
	t.Helper()
	os.Args = []string{"ingress-allowlisting-controller", "--legacy-group-version", legacyGroupVersion, "--as", as}
	go func() {
		main()
	}()
}

func TestDockerImage(t *testing.T) {
	testutils.IntegrationTest(t)

	// Ensure we always have the latest version of the code compiled
	// This is crucial when running integration tests locally
	cmd := exec.Command("go", "mod", "vendor")
	cmd.Stderr = os.Stderr
	cmd.Stdout = os.Stdout
	cmd.Dir = "../../"
	require.NoError(t, cmd.Run())

	cmd = exec.Command("docker", "build", "-t", "ingress-allowlisting-controller:latest", ".")
	cmd.Stderr = os.Stderr
	cmd.Stdout = os.Stdout
	cmd.Dir = "../../"
	require.NoError(t, cmd.Run())

	cmd = exec.Command("kind", "load", "docker-image", "--name", kindClusterName, "ingress-allowlisting-controller:latest")
	cmd.Stderr = os.Stderr
	cmd.Stdout = os.Stdout
	cmd.Dir = "../../"
	require.NoError(t, cmd.Run())

	legacyGroupVersion := "ipam.example.com/v1alpha1"

	t.Setenv("KUBECONFIG", testenv.EnvConf().KubeconfigFile())
	ctx := context.Background()

	cfg, err := k8s.NewClientConfigBuilder().WithKubeConfigPath(testenv.EnvConf().KubeconfigFile()).Build()
	require.NoError(t, err)
	scheme, err := controllers.Scheme(
		legacyGroupVersion,
	)
	require.NoError(t, err)
	k8sClient, err := client.New(cfg, client.Options{Scheme: scheme})
	require.NoError(t, err)

	installAllowlistingController(ctx, t, k8sClient, legacyGroupVersion, "--set", "image.fullyQualifiedURL=ingress-allowlisting-controller:latest", "--set", "image.pullPolicy=Never")
	// Other tests are designed to run locally.
	// Ensure that there is no more controller running inside the cluster
	defer deleteAllowlistingDeployment(t, k8sClient)

	cidrs := &ipamv1alpha1.CIDRs{
		ObjectMeta: metav1.ObjectMeta{
			Name:      envconf.RandomName("cidrs", 16),
			Namespace: testNamespace,
		},
		Spec: ipamv1alpha1.CIDRsSpec{
			CIDRsSource: ipamv1alpha1.CIDRsSource{
				Location: ipamv1alpha1.CIDRsLocation{
					// use https to ensure ca-certificates are available and working
					URI: "https://ip-ranges.amazonaws.com/ip-ranges.json",
					Processing: ipamv1alpha1.Processing{
						CEL: `data.prefixes.filter(p, p.service == "EC2").map(p, p.ip_prefix)`,
					},
				},
			},
		},
	}

	assert.Eventually(t, func() bool {
		err := k8sClient.Create(ctx, cidrs)
		if err != nil {
			t.Log(err)
		}
		return err == nil
	},
		10*time.Second, 10*time.Millisecond,
		"The CIDRs should be created",
	)

	assert.Eventually(
		t,
		func() bool {
			err := k8sClient.Get(ctx, client.ObjectKeyFromObject(cidrs), cidrs)
			if err != nil {
				return false
			}
			return len(cidrs.GetStatus().CIDRs) > 0
		},
		30*time.Second, 10*time.Millisecond,
		"The CIDRs should be updated with the AWS IP ranges",
	)
}

func TestIngressAllowlistingController(t *testing.T) {
	testutils.IntegrationTest(t)

	t.Setenv("KUBECONFIG", testenv.EnvConf().KubeconfigFile())
	osArgs := os.Args
	originalContext := mainContext
	t.Cleanup(func() {
		mainContext = originalContext
		os.Args = osArgs
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	mainContext = ctx

	legacyGroupVersion := "ipam.example.com/v1alpha1"

	cfg, err := k8s.NewClientConfigBuilder().WithKubeConfigPath(testenv.EnvConf().KubeconfigFile()).Build()
	require.NoError(t, err)
	scheme, err := controllers.Scheme(
		legacyGroupVersion,
	)
	require.NoError(t, err)
	k8sClient, err := client.New(cfg, client.Options{Scheme: scheme})
	require.NoError(t, err)

	installAllowlistingController(ctx, t, k8sClient, legacyGroupVersion)
	deleteAllowlistingDeployment(t, k8sClient)

	sa := &v1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:      releaseName,
			Namespace: allowListingNamespace,
		},
	}
	assert.Eventually(t, func() bool {
		err := k8sClient.Get(ctx, client.ObjectKeyFromObject(sa), sa)
		return err == nil
	}, 5*time.Minute, 5*time.Second)

	startMain(t, legacyGroupVersion, fmt.Sprintf("system:serviceaccount:%s:%s", allowListingNamespace, releaseName))

	t.Run("Local CIDRs should provide CIDRs in status", func(t *testing.T) {
		testCIDRsStatusIsUpdated(
			ctx,
			t,
			k8sClient,
			&ipamv1alpha1.CIDRs{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "local",
					Namespace: testNamespace,
				},
				Spec: ipamv1alpha1.CIDRsSpec{
					CIDRsSource: ipamv1alpha1.CIDRsSource{
						CIDRs: []string{"10.0.0.1/32", "192.168.20.0/24"},
					},
				},
			},
			[]string{"10.0.0.1/32", "192.168.20.0/24"},
		)
	})

	t.Run("Remote CIDRs should provide CIDRs in status", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			require.NoError(t, json.NewEncoder(w).Encode([]string{"10.0.0.1/32", "192.168.20.0/24"}))
		}))
		testCIDRsStatusIsUpdated(
			ctx,
			t,
			k8sClient,
			&ipamv1alpha1.CIDRs{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "remote",
					Namespace: testNamespace,
				},
				Spec: ipamv1alpha1.CIDRsSpec{
					CIDRsSource: ipamv1alpha1.CIDRsSource{
						Location: ipamv1alpha1.CIDRsLocation{
							URI: server.URL,
						},
					},
				},
			},
			[]string{"10.0.0.1/32", "192.168.20.0/24"},
		)
	})

	t.Run("Local legacy CIDRs should provide CIDRs in status", func(t *testing.T) {
		testCIDRsStatusIsUpdated(
			ctx,
			t,
			k8sClient,
			&ipamv1alpha1_legacy.CIDRs{
				CIDRs: ipamv1alpha1.CIDRs{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "local",
						Namespace: testNamespace,
					},
					Spec: ipamv1alpha1.CIDRsSpec{
						CIDRsSource: ipamv1alpha1.CIDRsSource{
							CIDRs: []string{"10.0.0.1/32", "192.168.20.0/24"},
						},
					},
				},
			},
			[]string{"10.0.0.1/32", "192.168.20.0/24"},
		)
	})

	t.Run("Ingresses should be updated with CIDRs", func(t *testing.T) {
		for _, object := range []client.Object{
			newCIDRs(&ipamv1alpha1_legacy.CIDRs{}, "legacy-group", testNamespace, "1.2.3.4/32"),
			newCIDRs(&ipamv1alpha1_legacy.ClusterCIDRs{}, "legacy-group", testNamespace, "2.3.4.5/32"),
			newCIDRs(&ipamv1alpha1.CIDRs{}, "my-group", testNamespace, "3.4.5.6/32"),
			newCIDRs(&ipamv1alpha1.ClusterCIDRs{}, "my-group", testNamespace, "4.5.6.8/32"),
			newIngress(testNamespace, "ingress1", "my-group,legacy-group", "my-group,legacy-group"),
		} {
			require.NoError(t, k8sClient.Create(ctx, object))
		}
		lastAnnotations := []string{}
		assert.Eventually(t, func() bool {
			ingress := &networkingv1.Ingress{}
			err := k8sClient.Get(ctx, client.ObjectKey{Name: "ingress1", Namespace: testNamespace}, ingress)
			if err != nil {
				return false
			}
			lastAnnotations = strings.Split(ingress.Annotations["nginx.ingress.kubernetes.io/whitelist-source-range"], ",")
			expectedCIDRs := []string{"1.2.3.4/32", "2.3.4.5/32", "3.4.5.6/32", "4.5.6.8/32"}
			for _, expected := range expectedCIDRs {
				if !slices.Contains(lastAnnotations, expected) {
					return false
				}
			}
			return true
		}, 10*time.Second, 10*time.Millisecond)
		// Repeat ourselves to provide the exact list of resolved CIDRs
		assert.ElementsMatch(t, lastAnnotations, []string{"1.2.3.4/32", "2.3.4.5/32", "3.4.5.6/32", "4.5.6.8/32"})
	})
}

func newCIDRs(cidrs ipamv1alpha1.CIDRsGetter, name, namespace string, cidr string) ipamv1alpha1.CIDRsGetter {
	cidrs.SetName(name)
	cidrs.SetNamespace(namespace)
	cidrs.SetSpec(ipamv1alpha1.CIDRsSpec{
		CIDRsSource: ipamv1alpha1.CIDRsSource{
			CIDRs: []string{cidr},
		},
	})
	return cidrs
}

func newIngress(namespace, name, cidrs, clustercidrs string) *networkingv1.Ingress {
	pathTypePrefix := networkingv1.PathTypePrefix
	return &networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
			Annotations: map[string]string{
				"ipam.adevinta.com/cluster-allowlist-group": cidrs,
				"ipam.adevinta.com/allowlist-group":         clustercidrs,
			},
		},
		Spec: networkingv1.IngressSpec{
			Rules: []networkingv1.IngressRule{
				{
					Host: "example.com",
					IngressRuleValue: networkingv1.IngressRuleValue{
						HTTP: &networkingv1.HTTPIngressRuleValue{
							Paths: []networkingv1.HTTPIngressPath{
								{
									Path:     "/",
									PathType: &pathTypePrefix,
									Backend: networkingv1.IngressBackend{
										Service: &networkingv1.IngressServiceBackend{
											Name: "my-service",
											Port: networkingv1.ServiceBackendPort{
												Name: "http",
											},
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}
}

func TestMain(m *testing.M) {
	if os.Getenv("RUN_INTEGRATION_TESTS") == "true" {
		testenv = env.New()
		// Use pre-defined environment funcs to create a kind cluster prior to test run
		testenv.Setup(
			envfuncs.CreateCluster(kind.NewCluster(kindClusterName), kindClusterName),
			envfuncs.CreateNamespace(allowListingNamespace),
			envfuncs.CreateNamespace(testNamespace),
		)

		// Use pre-defined environment funcs to teardown kind cluster after tests
		testenv.Finish(
			envfuncs.DeleteNamespace(allowListingNamespace),
			// envfuncs.DestroyCluster(kindClusterName),
		)

		// launch package tests
		os.Exit(testenv.Run(m))
	} else {
		os.Exit(m.Run())
	}
}
