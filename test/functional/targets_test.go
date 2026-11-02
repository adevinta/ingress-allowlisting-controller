//go:build functional

package functional

import (
	"context"
	"fmt"
	"slices"
	"testing"

	netv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// target is one kind of resource the controller writes allowlists into. Adding a scenario for a
// new kind (Service, Istio, Traefik, ...) means adding a target here; the scenarios are shared.
type target struct {
	name string
	kind string // shown in the plan
	// flag is the controller flag that enables this kind, flagDefault its default.
	flag        string
	flagDefault bool
	// unavailable, when set, is why the cluster cannot run this target (missing CRD, GatewayClass, ...).
	unavailable string
	// setup, when set, creates what every scenario of the target needs, e.g. a parent Gateway.
	setup func(ctx context.Context, c client.Client, ns string) error
	// extraScenarios, when set, runs scenarios specific to this target after the shared ones.
	extraScenarios func(t *testing.T, env scenarioEnv)
	// create creates an object of this kind referencing CIDRs through annotations.
	create func(ctx context.Context, c client.Client, ns, name string, annotations map[string]string) error
	// observe returns the allowlist the controller wrote, or nil, nil if it has not written one yet.
	observe func(ctx context.Context, c client.Client, ns, name string) ([]string, error)
}

func targets(d discovery) []target {
	return []target{
		ingressTarget(),
		networkPolicyTarget(),
		serviceTarget(),
		istioGatewayTarget(d),
		istioHTTPRouteTarget(d),
		traefikHTTPRouteTarget(d),
	}
}

const whitelistAnnotation = "nginx.ingress.kubernetes.io/whitelist-source-range"

func ingressTarget() target {
	return target{
		name:        "ingress",
		kind:        "networking.k8s.io/v1 Ingress (nginx whitelist-source-range annotation)",
		flag:        "ingress-support-enabled",
		flagDefault: false,
		create: func(ctx context.Context, c client.Client, ns, name string, annotations map[string]string) error {
			pathType := netv1.PathTypePrefix
			return c.Create(ctx, &netv1.Ingress{
				ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns, Annotations: annotations},
				Spec: netv1.IngressSpec{
					// No ingressClassName and an .invalid host: no real ingress controller serves it.
					Rules: []netv1.IngressRule{{
						Host: name + ".functional.invalid",
						IngressRuleValue: netv1.IngressRuleValue{HTTP: &netv1.HTTPIngressRuleValue{
							Paths: []netv1.HTTPIngressPath{{
								Path:     "/",
								PathType: &pathType,
								Backend: netv1.IngressBackend{Service: &netv1.IngressServiceBackend{
									Name: "none",
									Port: netv1.ServiceBackendPort{Number: 80},
								}},
							}},
						}},
					}},
				},
			})
		},
		observe: func(ctx context.Context, c client.Client, ns, name string) ([]string, error) {
			obj := &netv1.Ingress{}
			if err := c.Get(ctx, client.ObjectKey{Namespace: ns, Name: name}, obj); err != nil {
				return nil, err
			}
			value, ok := obj.Annotations[whitelistAnnotation]
			if !ok {
				return nil, nil
			}
			return splitList(value), nil
		},
	}
}

func networkPolicyTarget() target {
	return target{
		name:        "networkpolicy",
		kind:        "networking.k8s.io/v1 NetworkPolicy (ingress and egress ipBlocks)",
		flag:        "networkpolicy-support-enabled",
		flagDefault: false,
		create: func(ctx context.Context, c client.Client, ns, name string, annotations map[string]string) error {
			return c.Create(ctx, &netv1.NetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns, Annotations: annotations},
				Spec: netv1.NetworkPolicySpec{
					// Selects no pods, so the policy has no effect on anything running.
					PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{namespaceLabel + "-none": "true"}},
					PolicyTypes: []netv1.PolicyType{netv1.PolicyTypeIngress, netv1.PolicyTypeEgress},
				},
			})
		},
		observe: func(ctx context.Context, c client.Client, ns, name string) ([]string, error) {
			obj := &netv1.NetworkPolicy{}
			if err := c.Get(ctx, client.ObjectKey{Namespace: ns, Name: name}, obj); err != nil {
				return nil, err
			}
			if len(obj.Spec.Ingress) == 0 && len(obj.Spec.Egress) == 0 {
				return nil, nil
			}
			if len(obj.Spec.Ingress) != 1 || len(obj.Spec.Egress) != 1 {
				return nil, fmt.Errorf("want exactly one ingress and one egress rule, got %d and %d", len(obj.Spec.Ingress), len(obj.Spec.Egress))
			}
			from := peerCIDRs(obj.Spec.Ingress[0].From)
			to := peerCIDRs(obj.Spec.Egress[0].To)
			if !slices.Equal(from, to) {
				return nil, fmt.Errorf("ingress and egress ipBlocks differ: from=%v to=%v", from, to)
			}
			return from, nil
		},
	}
}

func peerCIDRs(peers []netv1.NetworkPolicyPeer) []string {
	out := []string{}
	for _, p := range peers {
		if p.IPBlock != nil {
			out = append(out, p.IPBlock.CIDR)
		}
	}
	return out
}
