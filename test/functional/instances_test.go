//go:build functional

package functional

import (
	"context"
	"fmt"
	"maps"
	"strings"
	"testing"
	"time"

	istioApiSecurityV1 "istio.io/api/security/v1"
	istioApiTypeV1beta1 "istio.io/api/type/v1beta1"
	istiosecurityv1 "istio.io/client-go/pkg/apis/security/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/util/retry"
	"sigs.k8s.io/controller-runtime/pkg/client"
	gatewayApiv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/adevinta/ingress-allowlisting-controller/pkg/controllers/writers"
)

// Several instances of the controller can run in one cluster, each with its own
// --annotation-prefix. The other-instance scenario checks that the instance under test leaves
// alone what belongs to another one. foreignPrefix plays that other instance: .invalid, so no real
// controller runs with it.
const foreignPrefix = "other.iac-functional.invalid"

// otherInstanceHooks is set on the kinds whose objects the controller creates (AuthorizationPolicies,
// Middlewares), as opposed to the kinds it only modifies (Ingress, NetworkPolicy, Service).
type otherInstanceHooks struct {
	// taken returns the object the controller would create for an object of this kind named name,
	// labelled as another instance's. It runs after the shared scenarios, whose objects it may use.
	taken func(ctx context.Context, c client.Client, ns, name string) (client.Object, error)
	// empty returns an empty object of the kind the target's create makes (Gateway, HTTPRoute).
	empty func() client.Object
}

// foreignLabels are the ownership labels another instance puts on what it creates.
func foreignLabels(kind, ns, name string) map[string]string {
	return map[string]string{
		"app.kubernetes.io/managed-by":     "ingress-allowlisting-controller",
		foreignPrefix + "/owner-kind":      kind,
		foreignPrefix + "/owner-namespace": ns,
		foreignPrefix + "/owner-name":      name,
	}
}

// foreignPolicy is another instance's AuthorizationPolicy. Its selector matches no pod, so it has
// no effect on traffic.
func foreignPolicy(ns, name string, labels map[string]string) *istiosecurityv1.AuthorizationPolicy {
	return &istiosecurityv1.AuthorizationPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns, Labels: labels},
		Spec: istioApiSecurityV1.AuthorizationPolicy{
			Selector: &istioApiTypeV1beta1.WorkloadSelector{MatchLabels: map[string]string{namespaceLabel + "/selects": "nothing"}},
			Action:   istioApiSecurityV1.AuthorizationPolicy_ALLOW,
			Rules: []*istioApiSecurityV1.Rule{{
				From: []*istioApiSecurityV1.Rule_From{{Source: &istioApiSecurityV1.Source{RemoteIpBlocks: []string{"192.0.2.1/32"}}}},
			}},
		},
	}
}

func istioGatewayOtherInstance() *otherInstanceHooks {
	return &otherInstanceHooks{
		// The Gateway's policy is named after it.
		taken: func(_ context.Context, _ client.Client, ns, name string) (client.Object, error) {
			return foreignPolicy(ns, name, foreignLabels(writers.OwnerKindGateway, ns, name)), nil
		},
		empty: func() client.Object { return &gatewayApiv1.Gateway{} },
	}
}

func istioHTTPRouteOtherInstance(d discovery) *otherInstanceHooks {
	return &otherInstanceHooks{
		// A route's policy is named <gateway>-<route>-<hash of the rule's paths>. Every test route
		// has the same one rule, so the hash is that of the inline scenario's policy.
		taken: func(ctx context.Context, c client.Client, ns, name string) (client.Object, error) {
			inline := istioHTTPRouteName + "-inline"
			list := &istiosecurityv1.AuthorizationPolicyList{}
			if err := c.List(ctx, list, client.InNamespace(ns), ownerLabels(d, ns, inline)); err != nil {
				return nil, err
			}
			base := parentGateway(istioHTTPRouteName) + "-"
			if len(list.Items) != 1 || !strings.HasPrefix(list.Items[0].Name, base+inline) {
				return nil, fmt.Errorf("want the one policy %s<hash> of HTTPRoute %s/%s, got %d", base+inline, ns, inline, len(list.Items))
			}
			hash := strings.TrimPrefix(list.Items[0].Name, base+inline)
			return foreignPolicy(ns, base+name+hash, foreignLabels(writers.OwnerKindHTTPRoute, ns, name)), nil
		},
		empty: func() client.Object { return &gatewayApiv1.HTTPRoute{} },
	}
}

func traefikHTTPRouteOtherInstance() *otherInstanceHooks {
	return &otherInstanceHooks{
		// A route's Middleware is named after it. Nothing references this one, so it has no effect.
		taken: func(_ context.Context, _ client.Client, ns, name string) (client.Object, error) {
			return &writers.TraefikMiddleware{
				ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns, Labels: foreignLabels(writers.OwnerKindHTTPRoute, ns, name)},
				Spec:       writers.TraefikMiddlewareSpec{IPAllowList: &writers.TraefikIPAllowList{SourceRange: []string{"192.0.2.1/32"}}},
			}, nil
		},
		empty: func() client.Object { return &gatewayApiv1.HTTPRoute{} },
	}
}

// otherInstanceScenario checks that the controller leaves another instance's things alone:
//   - an object annotated only under another instance's prefix gets no allowlist from us;
//   - for the kinds the controller creates: when the object it would create already exists and
//     belongs to another instance, it is neither overwritten nor, once our object loses its
//     annotation, deleted.
//
// cidrsName is a CIDRs object in the test namespace, so a missing allowlist can only come from the
// prefix.
func otherInstanceScenario(t *testing.T, env scenarioEnv, tg target, cidrsName string) {
	ctx, c, ns := env.ctx, env.c, env.ns
	ignored := tg.name + "-foreign"
	if err := tg.create(ctx, c, ns, ignored, map[string]string{foreignPrefix + "/allowlist-group": cidrsName}); err != nil {
		t.Fatalf("creating %s: %v", tg.name, err)
	}

	var taken client.Object
	name := tg.name + "-taken"
	if tg.otherInstance != nil {
		var err error
		if taken, err = tg.otherInstance.taken(ctx, c, ns, name); err != nil {
			t.Fatalf("naming another instance's object for %s/%s: %v", ns, name, err)
		}
		if err := c.Create(ctx, taken); err != nil {
			t.Fatalf("creating another instance's %T %s/%s: %v", taken, ns, taken.GetName(), err)
		}
		if err := tg.create(ctx, c, ns, name, map[string]string{env.annotation: cidrsName}); err != nil {
			t.Fatalf("creating %s: %v", tg.name, err)
		}
	}

	// untouched compares what a controller would change: the spec (generation), the labels and the
	// owner references. Not the resourceVersion: e.g. Istio ambient writes status on policies.
	untouched := func() error {
		if taken == nil {
			return nil
		}
		got := taken.DeepCopyObject().(client.Object)
		if err := c.Get(ctx, client.ObjectKeyFromObject(taken), got); err != nil {
			return fmt.Errorf("another instance's %T %s/%s: %w", taken, ns, taken.GetName(), err)
		}
		switch {
		case got.GetGeneration() != taken.GetGeneration():
			return fmt.Errorf("another instance's %T %s/%s: spec changed (generation %d, was %d)", taken, ns, taken.GetName(), got.GetGeneration(), taken.GetGeneration())
		case !maps.Equal(got.GetLabels(), taken.GetLabels()):
			return fmt.Errorf("another instance's %T %s/%s: labels changed to %v", taken, ns, taken.GetName(), got.GetLabels())
		case len(got.GetOwnerReferences()) != len(taken.GetOwnerReferences()):
			return fmt.Errorf("another instance's %T %s/%s: owner references changed to %v", taken, ns, taken.GetName(), got.GetOwnerReferences())
		}
		return nil
	}
	watch := func(t *testing.T, check func() error) {
		t.Helper()
		for deadline := time.Now().Add(absenceWindow); time.Now().Before(deadline); time.Sleep(pollInterval) {
			if err := check(); err != nil {
				t.Fatal(err)
			}
		}
	}

	watch(t, func() error {
		if got, err := tg.observe(ctx, c, ns, ignored); err == nil && got != nil {
			return fmt.Errorf("allowlist %v written for %s/%s, annotated only under another instance's prefix %s", got, ns, ignored, foreignPrefix)
		}
		return untouched()
	})

	if taken == nil {
		return
	}
	// Without the annotation, the controller removes what it wrote for our object: only its own.
	if err := removeAnnotation(ctx, c, tg.otherInstance.empty(), ns, name, env.annotation); err != nil {
		t.Fatalf("removing the annotation of %s/%s: %v", ns, name, err)
	}
	watch(t, untouched)
}

// removeAnnotation removes one annotation from the object ns/name; obj is an empty object of its kind.
func removeAnnotation(ctx context.Context, c client.Client, obj client.Object, ns, name, key string) error {
	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		if err := c.Get(ctx, client.ObjectKey{Namespace: ns, Name: name}, obj); err != nil {
			return err
		}
		annotations := obj.GetAnnotations()
		delete(annotations, key)
		obj.SetAnnotations(annotations)
		return c.Update(ctx, obj)
	})
}
