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

---

## Breadth limit on remote CIDR sources

**Applies to:** `CIDRs`/`ClusterCIDRs` objects with a remote `location.uri` source.

A remote source can silently widen an allowlist to the entire internet if it breaks, changes
format, or is fed a bad transform expression. The controller requires every externally-fetched
prefix to be **no wider than a minimum mask** — `/8` for IPv4 and `/20` for IPv6 by default. If
any entry is wider (`0.0.0.0/0`, any `/1`, `/3`, …), the fetch is rejected wholesale, the object
keeps its last-known-good status, and the breach is logged.

**This is a guardrail against human mistakes, not a security control.** We trust the sources we
fetch from (AWS, Akamai, …); a well-tailored single `/32` from a trusted feed is allowed by
design, and there is no defending against a source you have chosen to trust. What the check
prevents is the common accident where a feed breaks, a transform expression misfires, or a feed
is misconfigured to return `0.0.0.0/0` — and the firewall effectively turns off without anyone
noticing. Treat it as blast-radius containment for misconfiguration, alongside the trust you
already place in the source.

Notes:

- It is a **per-entry mask check**, not an address-count sum. It catches every single over-broad
  block (including the `/1`/`/3` splits, whose masks are themselves too wide) but does not add up
  coverage across many narrow blocks — an accepted trade-off for a fast, allocation-light check.
- It applies **only** to remotely fetched CIDRs. Inline `spec.cidrs` is trusted; an admin may
  deliberately allow `0.0.0.0/0` there.
- **Known gap — deprecated v4-in-v6 notations.** A prefix is scored by its IPv6 mask width, and
  only the v4-mapped form (`::ffff:0.0.0.0/96`) is re-scored in IPv4 space. The deprecated 6to4
  (`2002::/16`) and IPv4-compatible (`::/96`) forms are not, so a block like `::/96` or
  `2002:c000::/20` reads as a narrow IPv6 prefix and passes even though it encodes a broad IPv4
  range. `::/0` and `::/16`-scale blunders are still caught (their IPv6 mask is below the limit).
  This is left as-is on purpose: both notations are deprecated (RFC 7526, RFC 4291) and no trusted
  feed emits them, so it is not a realistic human mistake.
- Defaults are calibrated against real feeds: the widest prefix observed is `/11` for IPv4 (AWS
  `ip-ranges.json` and Akamai) and `/24` for IPv6 (Akamai; AWS tops out at `/32`), so the `/8` and
  `/20` defaults do not reject legitimate feeds and keep headroom above the widest real block.

See [CIDRs — Breadth limit on remote sources](cidrs.md#breadth-limit-on-remote-sources) for
the full behaviour.
