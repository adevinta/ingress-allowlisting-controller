# Security considerations

## Gateway vs HTTPRoute allowlisting — do not mix (Istio)

The Gateway controller creates an `AuthorizationPolicy` with `action: ALLOW` targeting the
Gateway directly — **L4-level** protection (IP-only, no hostname matching).

The HTTPRoute controller creates `AuthorizationPolicy` resources scoped per-hostname —
**L7-level** protection.

**Istio evaluates multiple ALLOW policies with OR logic.** A request is allowed if it matches
ANY ALLOW policy targeting that resource:

```
Request from 5.5.5.5 → app.example.com

Gateway AP:   ALLOW from [10.0.0.0/8]                        → no match
HTTPRoute AP: ALLOW from [5.5.5.5/32] host app.example.com   → match → ALLOWED
```

The HTTPRoute AP bypasses the Gateway AP entirely. **Do not annotate both a Gateway and its
HTTPRoutes.** Pick one level:

- **Gateway-level** — uniform allowlist for all traffic through the gateway, regardless of hostname.
- **HTTPRoute-level** — per-route control with different CIDRs per service.

---

## Protecting a cross-namespace Gateway with a DENY policy (Istio)

When using HTTPRoute-level allowlisting on a cross-namespace gateway, each HTTPRoute produces
an ALLOW policy scoped to its hostnames. Any hostname without an ALLOW policy defaults to
Istio's implicit deny — **unless another policy creates a gap**.

Add an explicit DENY policy to block anything not matching expected hostname patterns:

```yaml
apiVersion: security.istio.io/v1
kind: AuthorizationPolicy
metadata:
  name: protect-gateway-hostnames
  namespace: infra
spec:
  action: DENY
  rules:
  - to:
    - operation:
        notHosts:
        - '*.public.ns-staging00.example.com'
        - '*.public.ns-staging01.example.com'
  targetRefs:
  - group: gateway.networking.k8s.io
    kind: Gateway
    name: cross-namespace-gateway
```

DENY rules take precedence over all ALLOW rules in Istio — this ensures traffic to unexpected
hostnames is blocked even if an ALLOW policy is misconfigured or overly broad.

---

## Restricting which namespaces can attach to a cross-namespace Gateway

A cross-namespace Gateway accepting routes from arbitrary namespaces is a lateral movement
risk. Restrict attachment using the Gateway's `allowedRoutes` listener configuration:

```yaml
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata:
  name: cross-namespace-gateway
  namespace: infra
spec:
  gatewayClassName: istio
  listeners:
  - name: http
    port: 80
    protocol: HTTP
    allowedRoutes:
      namespaces:
        from: Selector
        selector:
          matchLabels:
            cross-gateway-access: "true"
```

Only namespaces with `cross-gateway-access: "true"` can attach HTTPRoutes. All other routes
are rejected by the Gateway controller (`Accepted=False`) and no traffic flows regardless of
any `AuthorizationPolicy` that may exist.

**Defence in depth — combine all three layers:**

1. **Namespace label selector** on the Gateway listener — controls who can attach
2. **HTTPRoute-level ALLOW policies** — controls which IPs can reach each service
3. **Gateway-level DENY policy** on unexpected hostnames — prevents gaps from missing ALLOW policies

---

## AWS: preserving client IP for IP-based filtering (Istio)

`AuthorizationPolicy` rules match on `remoteIpBlocks` — this requires the **original client
IP** to reach the Istio proxy. On AWS, NLBs replace the source IP with the LB's own address
unless Proxy Protocol is enabled.

Without this, all requests appear to come from the load balancer's IP and no allowlist rule
matches correctly — making the allowlist useless.

**Solution: Proxy Protocol**

```yaml
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata:
  name: my-gateway
  annotations:
    service.beta.kubernetes.io/aws-load-balancer-proxy-protocol: '*'
    proxy.istio.io/config: '{"gatewayTopology": {"proxyProtocol": {}}}'
```

Both annotations are required — the first enables Proxy Protocol on the AWS NLB, the second
tells Envoy to parse the header and extract the real client IP for `remoteIpBlocks` matching.

---

## Merge mode security warning

Merge mode (`ipam.adevinta.com/merge`) is designed for staging environments only. Any
namespace in the cluster that sets the same merge key and points to the same gateway is pulled
into the shared `AuthorizationPolicy`. A team controlling a different namespace could add
their application's hostnames and CIDRs to your policy, potentially opening access to their
service through your allowlist.

**Do not use merge mode in production.**

---

## Stale cross-namespace resources

Kubernetes does not support cross-namespace owner references, so cross-namespace
`AuthorizationPolicy` resources cannot be garbage-collected automatically when their
`HTTPRoute` is deleted.

**Automatic cleanup on restart:** every time the controller starts it runs a one-time sweep
over all resources it owns (identified by `app.kubernetes.io/managed-by=ingress-allowlisting-controller`).
Any resource whose owner no longer exists is deleted. Restarting the controller is sufficient
to clean up orphans.

**Hard reset:**
```bash
kubectl delete authorizationpolicies -A -l app.kubernetes.io/managed-by=ingress-allowlisting-controller
kubectl rollout restart deployment/ingress-allowlisting-controller -n <namespace>
```

---

## Declarative tooling conflict — intermittent allowlist disable

**Applies to:** Traefik Middleware only.

The Traefik writer mutates `spec.rules[].filters` at runtime by injecting an `extensionRef`
entry pointing to the Middleware. If the HTTPRoute is managed by a declarative tool —
**ArgoCD, Flux, a Helm release, or any CI/CD pipeline that applies manifests** — the tool may
detect this field as drift from the declared manifest and revert it on the next reconcile or
`helm upgrade`.

> **Note:** In practice, most modern tools do not revert fields that are absent from the
> declared manifest. Verify the behaviour of your specific tooling and version.

**The result is a recurring security gap:** the allowlist filter is absent and the route is
unprotected during every reconcile window. Because reconciles can be triggered automatically
(by a push, a webhook, or a scheduled refresh), the firewall can be disabled frequently and
silently.

This is not a theoretical edge case — any team using declarative tooling to manage HTTPRoutes
with Traefik will hit this loop unless an ignore rule is configured.

**Fix:** configure your tooling to ignore the controller-injected `extensionRef` filters. See
[Declarative tooling conflict](gateway-api.md#declarative-tooling-conflict-argocd-flux-helm)
in the Gateway API docs for the exact configuration for ArgoCD, Flux, and Helm.
