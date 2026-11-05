//go:build functional

package functional

import (
	"fmt"
	"slices"
	"testing"
	"time"

	istiosecurityv1 "istio.io/client-go/pkg/apis/security/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	gatewayApiv1 "sigs.k8s.io/gateway-api/apis/v1"

	ipamv1alpha1 "github.com/adevinta/ingress-allowlisting-controller/pkg/apis/ipam.adevinta.com/v1alpha1"
	"github.com/adevinta/ingress-allowlisting-controller/pkg/controllers/writers"
)

// mergeScenario checks Istio merge mode: two HTTPRoutes of two namespaces with the same merge key,
// on a Gateway of the peer namespace, share one merged AuthorizationPolicy, named
// merge.{gw}.{key}.{hash8}, with both routes' hosts and CIDRs; neither gets a policy of its own.
func mergeScenario(t *testing.T, env scenarioEnv, d discovery) {
	ctx, c, ns, peer := env.ctx, env.c, env.ns, env.peerNS
	const gwName, key = "istio-merge-gw", "istio-merge"
	mergeAnnotation := d.annotationPrefix + "/merge"

	if err := c.Create(ctx, allowRoutesFrom(newGateway(peer, gwName, d.istioClass, true, nil), gatewayApiv1.NamespacesFromAll)); err != nil {
		t.Fatalf("creating Gateway %s/%s: %v", peer, gwName, err)
	}
	// One route in the main namespace (cross-namespace), one in the Gateway's: each with its own
	// CIDRs object, in its own namespace.
	members := []struct {
		ns, name, cidr string
	}{
		{ns, "istio-merge-a", "203.0.113.0/24"},
		{peer, "istio-merge-b", "198.51.100.0/24"},
	}
	for _, m := range members {
		spec := ipamv1alpha1.CIDRsSpec{CIDRsSource: ipamv1alpha1.CIDRsSource{CIDRs: []string{m.cidr}}}
		if err := createCIDRs(ctx, c, m.ns, m.name, spec); err != nil {
			t.Fatalf("creating CIDRs %s/%s: %v", m.ns, m.name, err)
		}
		route := newHTTPRoute(d, m.ns, m.name, gwName, map[string]string{env.annotation: m.name, mergeAnnotation: key})
		if m.ns != peer {
			attachTo(route, peer, gwName)
		}
		if err := c.Create(ctx, route); err != nil {
			t.Fatalf("creating HTTPRoute %s/%s: %v", m.ns, m.name, err)
		}
	}

	name := writers.MergedPolicyName(d.annotationPrefix, gwName, key)
	eventually(t, "merged AuthorizationPolicy "+peer+"/"+name+" with both routes", func() (bool, string) {
		policy := &istiosecurityv1.AuthorizationPolicy{}
		if err := c.Get(ctx, client.ObjectKey{Namespace: peer, Name: name}, policy); err != nil {
			return false, err.Error()
		}
		cidrs, hosts := policyCIDRsAndHosts(policy)
		want := []string{"198.51.100.0/24", "203.0.113.0/24"}
		wantHosts := []string{"istio-merge-a.functional.invalid", "istio-merge-b.functional.invalid"}
		return slices.Equal(cidrs, want) && slices.Equal(hosts, wantHosts),
			fmt.Sprintf("CIDRs %v (want %v), hosts %v (want %v)", cidrs, want, hosts, wantHosts)
	})

	// The members don't keep policies of their own next to the merged one. Watched for a while:
	// they would only appear if the merge were ignored.
	for deadline := time.Now().Add(absenceWindow); time.Now().Before(deadline); time.Sleep(pollInterval) {
		for _, m := range members {
			for _, policyNS := range []string{ns, peer} {
				list := &istiosecurityv1.AuthorizationPolicyList{}
				if err := c.List(ctx, list, client.InNamespace(policyNS), ownerLabels(d, m.ns, m.name)); err != nil {
					t.Fatal(err)
				}
				if len(list.Items) > 0 {
					t.Fatalf("HTTPRoute %s/%s is in merge group %s but has its own AuthorizationPolicy %s/%s", m.ns, m.name, key, policyNS, list.Items[0].Name)
				}
			}
		}
	}
}

// policyCIDRsAndHosts returns the sorted remoteIpBlocks and hosts of every rule of policy.
func policyCIDRsAndHosts(policy *istiosecurityv1.AuthorizationPolicy) (cidrs, hosts []string) {
	for _, rule := range policy.Spec.GetRules() {
		for _, from := range rule.GetFrom() {
			cidrs = append(cidrs, from.GetSource().GetRemoteIpBlocks()...)
		}
		for _, to := range rule.GetTo() {
			hosts = append(hosts, to.GetOperation().GetHosts()...)
		}
	}
	slices.Sort(cidrs)
	slices.Sort(hosts)
	return slices.Compact(cidrs), slices.Compact(hosts)
}

// listenerHostnamesScenario checks that a route's AuthorizationPolicy gets only the hostnames its
// listeners match: the test Gateways listen on *.functional.invalid, so a second hostname outside it
// is left out. An Istio policy targets the whole Gateway by host: with that hostname it would allow
// the route's CIDRs on another route's host.
func listenerHostnamesScenario(t *testing.T, env scenarioEnv, d discovery) {
	ctx, c, ns := env.ctx, env.c, env.ns
	const name = "istio-listener-hostnames"
	spec := ipamv1alpha1.CIDRsSpec{CIDRsSource: ipamv1alpha1.CIDRsSource{CIDRs: []string{"203.0.113.0/24"}}}
	if err := createCIDRs(ctx, c, ns, name, spec); err != nil {
		t.Fatalf("creating CIDRs: %v", err)
	}
	route := newHTTPRoute(d, ns, name, parentGateway(istioHTTPRouteName), map[string]string{env.annotation: name})
	route.Spec.Hostnames = append(route.Spec.Hostnames, gatewayApiv1.Hostname(name+".other.invalid"))
	if err := c.Create(ctx, route); err != nil {
		t.Fatalf("creating HTTPRoute: %v", err)
	}
	want := []string{name + ".functional.invalid"}
	eventually(t, "AuthorizationPolicy of "+ns+"/"+name+" with only the hostnames its listener matches", func() (bool, string) {
		list := &istiosecurityv1.AuthorizationPolicyList{}
		if err := c.List(ctx, list, client.InNamespace(ns), ownerLabels(d, ns, name)); err != nil {
			return false, err.Error()
		}
		if len(list.Items) != 1 {
			return false, fmt.Sprintf("%d AuthorizationPolicies, want 1", len(list.Items))
		}
		_, hosts := policyCIDRsAndHosts(list.Items[0])
		return slices.Equal(hosts, want), fmt.Sprintf("hosts %v, want %v", hosts, want)
	})
}
