package writers

import (
	"context"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	gatewayApiv1 "sigs.k8s.io/gateway-api/apis/v1"

	istioApiSecurityV1 "istio.io/api/security/v1"
	istioApiTypeV1beta1 "istio.io/api/type/v1beta1"
	istiosecurityv1 "istio.io/client-go/pkg/apis/security/v1"
)

// IstioL4Writer creates/deletes Istio AuthorizationPolicies for Gateway-level (L4) allowlisting.
type IstioL4Writer struct {
	client client.Client
}

// NewIstioL4Writer returns a new IstioL4Writer using the provided client.
func NewIstioL4Writer(c client.Client) *IstioL4Writer {
	return &IstioL4Writer{client: c}
}

// Apply creates or updates an AuthorizationPolicy for the given Gateway and IPs.
func (w *IstioL4Writer) Apply(ctx context.Context, gateway *gatewayApiv1.Gateway, ips []string) error {
	policy := &istiosecurityv1.AuthorizationPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      gateway.Name,
			Namespace: gateway.Namespace,
		},
	}
	_, err := ctrl.CreateOrUpdate(ctx, w.client, policy, func() error {
		policy.Spec = istioApiSecurityV1.AuthorizationPolicy{
			Action: istioApiSecurityV1.AuthorizationPolicy_ALLOW,
			Rules: []*istioApiSecurityV1.Rule{
				{
					From: []*istioApiSecurityV1.Rule_From{
						{
							Source: &istioApiSecurityV1.Source{
								RemoteIpBlocks: ips,
							},
						},
					},
				},
			},
			TargetRef: &istioApiTypeV1beta1.PolicyTargetReference{
				Name:  gateway.Name,
				Kind:  "Gateway",
				Group: "gateway.networking.k8s.io",
			},
		}
		return nil
	})
	return err
}

// Delete removes the AuthorizationPolicy associated with the given Gateway.
func (w *IstioL4Writer) Delete(ctx context.Context, gateway *gatewayApiv1.Gateway) error {
	policy := &istiosecurityv1.AuthorizationPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      gateway.Name,
			Namespace: gateway.Namespace,
		},
	}
	return client.IgnoreNotFound(w.client.Delete(ctx, policy))
}
