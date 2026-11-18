//go:build functional

package functional

import (
	"context"
	"fmt"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/client"
	gatewayApiv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/adevinta/ingress-allowlisting-controller/pkg/controllers/writers"
)

// The AWS Load Balancer Controller's Gateways get their allowlist in the sourceRanges of the
// LoadBalancerConfiguration they reference. The AWS controller provisions a real load balancer for
// each Gateway: always an internal one here (scheme: internal), so nothing is reachable from the
// internet, also for the Gateway annotated for another instance only. They are deleted with the
// namespace, by the AWS controller (its finalizers): it must keep running until the namespaces are gone.

var lbConfigGVK = schema.GroupVersionKind{Group: "gateway.k8s.aws", Version: "v1beta1", Kind: "LoadBalancerConfiguration"}

// awsProgrammedTimeout is how long the AWS controller may take to provision a load balancer.
const awsProgrammedTimeout = 10 * time.Minute

func awsGatewayTarget(d discovery, nlb bool) target {
	name, class, controller := "aws-alb-gateway", d.awsALBClass, writers.AWSALBControllerName
	if nlb {
		name, class, controller = "aws-nlb-gateway", d.awsNLBClass, writers.AWSNLBControllerName
	}
	unavailable := gatewayAPIUnavailable(d)
	switch {
	case unavailable != "":
	case !d.awsLBConfig:
		unavailable = "gateway.k8s.aws LoadBalancerConfiguration CRD not installed"
	case class == "":
		unavailable = "no GatewayClass with controller " + controller
	}
	return target{
		name:        name,
		kind:        "Gateway → AWS LoadBalancerConfiguration sourceRanges, internal load balancer, class " + orNone(class),
		flag:        "gateway-support-enabled",
		flagDefault: false,
		unavailable: unavailable,
		create: func(ctx context.Context, c client.Client, ns, name string, annotations map[string]string) error {
			if err := c.Create(ctx, internalLBConfig(ns, name)); err != nil {
				return fmt.Errorf("creating LoadBalancerConfiguration: %w", err)
			}
			return c.Create(ctx, newAWSGateway(ns, name, class, nlb, annotations))
		},
		observe: func(ctx context.Context, c client.Client, ns, name string) ([]string, error) {
			config := &unstructured.Unstructured{}
			config.SetGroupVersionKind(lbConfigGVK)
			if err := c.Get(ctx, client.ObjectKey{Namespace: ns, Name: name}, config); err != nil {
				return nil, client.IgnoreNotFound(err)
			}
			ranges, found, err := unstructured.NestedStringSlice(config.Object, "spec", "sourceRanges")
			if err != nil || !found {
				return nil, err
			}
			return ranges, nil
		},
		extraScenarios: func(t *testing.T, env scenarioEnv) {
			t.Run("programmed", func(t *testing.T) {
				// The AWS controller accepted the allowlist: the load balancer, with its security
				// group rules, was provisioned. The inline Gateway holds deny-all by now
				// (revoke-inline), a valid rule too.
				awsProgrammed(t, env, name+"-inline")
			})
		},
	}
}

// internalLBConfig is the LoadBalancerConfiguration of a test Gateway: an internal load balancer,
// and no sourceRanges until the controller writes them.
func internalLBConfig(ns, name string) *unstructured.Unstructured {
	config := &unstructured.Unstructured{Object: map[string]any{"spec": map[string]any{"scheme": "internal"}}}
	config.SetGroupVersionKind(lbConfigGVK)
	config.SetNamespace(ns)
	config.SetName(name)
	return config
}

// newAWSGateway returns a Gateway of the AWS class referencing the LoadBalancerConfiguration of the
// same name, with an HTTP listener for an ALB or a TCP one for an NLB.
func newAWSGateway(ns, name, class string, nlb bool, annotations map[string]string) *gatewayApiv1.Gateway {
	protocol := gatewayApiv1.HTTPProtocolType
	if nlb {
		protocol = gatewayApiv1.TCPProtocolType
	}
	return &gatewayApiv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns, Annotations: annotations},
		Spec: gatewayApiv1.GatewaySpec{
			GatewayClassName: gatewayApiv1.ObjectName(class),
			Infrastructure: &gatewayApiv1.GatewayInfrastructure{ParametersRef: &gatewayApiv1.LocalParametersReference{
				Group: gatewayApiv1.Group(lbConfigGVK.Group), Kind: gatewayApiv1.Kind(lbConfigGVK.Kind), Name: name,
			}},
			Listeners: []gatewayApiv1.Listener{{Name: "listener", Port: 80, Protocol: protocol}},
		},
	}
}

// awsProgrammed waits until the Gateway ns/name is Programmed, reporting the AWS controller's
// message while it isn't.
func awsProgrammed(t *testing.T, env scenarioEnv, name string) {
	t.Helper()
	deadline := time.Now().Add(awsProgrammedTimeout)
	detail := "no Programmed condition yet"
	for time.Now().Before(deadline) {
		gw := &gatewayApiv1.Gateway{}
		if err := env.c.Get(env.ctx, client.ObjectKey{Namespace: env.ns, Name: name}, gw); err != nil {
			t.Fatalf("getting Gateway %s/%s: %v", env.ns, name, err)
		}
		for _, cond := range gw.Status.Conditions {
			if cond.Type != string(gatewayApiv1.GatewayConditionProgrammed) {
				continue
			}
			if cond.Status == metav1.ConditionTrue {
				return
			}
			detail = fmt.Sprintf("%s: %s", cond.Reason, cond.Message)
		}
		time.Sleep(pollInterval)
	}
	t.Fatalf("Gateway %s/%s not Programmed after %s; last: %s", env.ns, name, awsProgrammedTimeout, detail)
}
