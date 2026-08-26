# Gateway API — Gateway & HTTPRoute

**Requires:** [Kubernetes Gateway API CRDs](https://gateway-api.sigs.k8s.io/) + Istio or Traefik

The controller supports `Gateway` and `HTTPRoute` resources from the Kubernetes Gateway API.
The output depends on which ingress controller is installed:

| Gateway controller | Gateway annotation → | HTTPRoute annotation → |
|---|---|---|
| Istio (`istio.io/gateway-controller`) | `AuthorizationPolicy` (L4) | `AuthorizationPolicy` (L7) |
| Traefik (`traefik.io/gateway-controller`) | _(not applicable)_ | `Middleware` (IPAllowList) |

**Auto-detection:** the controller checks at startup which CRDs are present (`AuthorizationPolicy`,
`Middleware`) and registers only the relevant writers. No flags are needed; both can be active
simultaneously on a cluster that runs both Istio and Traefik.

Enable Gateway API support:
```yaml
# Helm
gateway:
  enabled: true
httproute:
  enabled: true
```
Or directly: `--gateway-support-enabled --httproute-support-enabled`.

---

## Annotations (same for all gateway controllers)

| Annotation | Scope | Description |
|---|---|---|
| `ipam.adevinta.com/allowlist-group` | namespace | Reference a `CIDRs` object in the same namespace |
| `ipam.adevinta.com/cluster-allowlist-group` | cluster | Reference a `ClusterCIDRs` object |

Both accept a comma-separated list. Apply them to the `Gateway` or `HTTPRoute` object.

---

## Gateway → Istio AuthorizationPolicy (L4)

The controller creates one `AuthorizationPolicy` per annotated Gateway, targeting the gateway
at the IP level (no hostname matching). Enable with `--gateway-support-enabled`.

```yaml
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata:
  name: my-gateway
  namespace: my-app
  annotations:
    ipam.adevinta.com/cluster-allowlist-group: office-ips
```

Generated in `my-app`:

```yaml
apiVersion: security.istio.io/v1
kind: AuthorizationPolicy
metadata:
  name: my-gateway
  namespace: my-app
spec:
  action: ALLOW
  rules:
  - from:
    - source:
        remoteIpBlocks:
        - 10.0.0.0/8
        - 192.168.0.0/16
  targetRef:
    group: gateway.networking.k8s.io
    kind: Gateway
    name: my-gateway
```

The AP is owned by the Gateway and garbage-collected automatically when the Gateway is deleted.

> **Do not mix Gateway-level and HTTPRoute-level allowlisting for Istio.** Istio evaluates
> multiple ALLOW policies with OR logic — an HTTPRoute AP would bypass the Gateway AP entirely.
> See [security considerations](security.md#gateway-vs-httproute-allowlisting--do-not-mix-istio).

---

## HTTPRoute → Istio AuthorizationPolicy (L7)

The controller creates one `AuthorizationPolicy` per HTTPRoute rule, scoped to the route's
hostnames and paths. Enable with `--httproute-support-enabled`.

```yaml
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata:
  name: my-route
  namespace: my-app
  annotations:
    ipam.adevinta.com/cluster-allowlist-group: office-ips
spec:
  parentRefs:
  - name: my-gateway
  hostnames:
  - app.example.com
```

**Same-namespace** (parentRef has no `namespace`): AP created in the HTTPRoute's namespace,
named `{gateway.Name}-{httproute.Name}`, with an ownerReference for automatic cleanup.

**Cross-namespace** (parentRef has a different `namespace`): AP created in the gateway's
namespace, named `{gateway.Name}-{httproute.Namespace}-{httproute.Name}`. No ownerReference
(Kubernetes does not support cross-namespace owner refs). Orphaned APs are cleaned up at
controller startup.

**Multiple gateways**: one AP is created per parentRef, each prefixed with the gateway name.

### Granularity

By default one AP is created per HTTPRoute rule (per path set). Use the
`ipam.adevinta.com/granularity` annotation to change this:

| Value | AP count | `to` block |
|---|---|---|
| absent / `rule` | one per rule | hosts + paths from that rule |
| `host` | one per route | hosts only, no path restriction |

### Merge mode

For staging environments where multiple namespace-isolated instances of the same application
share a cross-namespace gateway, set `ipam.adevinta.com/merge` to a shared key. All HTTPRoutes
with the same key and the same target gateway are merged into a single AP.

Routes with the same sorted CIDR set share one `from` block; routes with different CIDR sets
each get their own `rule` (security isolation preserved).

```yaml
# ns-staging00
metadata:
  annotations:
    ipam.adevinta.com/cluster-allowlist-group: office-ips
    ipam.adevinta.com/merge: chaos-monkey
spec:
  parentRefs:
  - name: cross-namespace-public
    namespace: ns-infra
  hostnames:
  - chaos-monkey.public.ns-staging00.example.com
---
# ns-staging01
metadata:
  annotations:
    ipam.adevinta.com/cluster-allowlist-group: office-ips
    ipam.adevinta.com/merge: chaos-monkey   # same key → merged into one AP
spec:
  parentRefs:
  - name: cross-namespace-public
    namespace: ns-infra
  hostnames:
  - chaos-monkey.public.ns-staging01.example.com
```

> **Security warning:** merge mode is designed for staging only. Any namespace that uses the
> same merge key and gateway is pulled into the shared AP. Do not use in production.

### Label selector (performance)

To restrict the informer cache to only opted-in HTTPRoutes:

```yaml
httproute:
  enabled: true
  labelSelector: "ipam.adevinta.com/allowlisting=enabled"
```

Or: `--httproute-label-selector=ipam.adevinta.com/allowlisting=enabled`.

---

## HTTPRoute → Traefik Middleware (IPAllowList)

The controller creates one Traefik `Middleware` per HTTPRoute and patches the HTTPRoute's rules
to reference it via an `extensionRef` filter. Enable with `--httproute-support-enabled`.

The Middleware is always created in the **route's own namespace** (required because
`extensionRef` uses `LocalObjectReference` — no cross-namespace field).

```yaml
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata:
  name: my-route
  namespace: my-app
  labels:
    common-platform.io/allowlisting: enabled   # required if --httproute-label-selector is set
  annotations:
    ipam.adevinta.com/cluster-allowlist-group: office-ips
spec:
  parentRefs:
  - name: traefik-gateway
    namespace: traefik
  hostnames:
  - app.example.com
  rules:
  - matches:
    - path:
        type: PathPrefix
        value: /
```

The controller generates in `my-app`:

```yaml
apiVersion: traefik.io/v1alpha1
kind: Middleware
metadata:
  name: my-route      # same as the HTTPRoute name
  namespace: my-app
  ownerReferences:
  - kind: HTTPRoute
    name: my-route
spec:
  ipAllowList:
    sourceRange:
    - 10.0.0.0/8
    - 192.168.0.0/16
```

And patches the HTTPRoute so every rule references it:

```yaml
spec:
  rules:
  - matches:
    - path:
        type: PathPrefix
        value: /
    filters:
    - type: ExtensionRef
      extensionRef:
        group: traefik.io
        kind: Middleware
        name: my-route   # ← injected by the controller
```

Removing the allowlist annotation deletes the Middleware **and** removes the `extensionRef`
filter from the HTTPRoute rules.

### Important: Traefik IPAllowList middleware chaining

When multiple IPAllowList Middlewares are stacked on the same route via separate `extensionRef`
filters, Traefik evaluates them **sequentially** — the order matters. If the first middleware
rejects the request (source IP not in its allowlist), the request is blocked immediately
regardless of subsequent middlewares. This is AND logic, not OR.

**Consequence:** do not stack independent IPAllowList Middlewares to achieve "allow either
set". The CIDRs must be merged into a single Middleware. The controller always writes one
Middleware per route containing the full union of all relevant CIDR sources.

---

### Declarative tooling conflict (ArgoCD, Flux, Helm)

The controller mutates `spec.rules[].filters` at runtime by injecting an `extensionRef` entry:

```yaml
filters:
- type: ExtensionRef
  extensionRef:
    group: traefik.io
    kind: Middleware
    name: my-route
```

If the HTTPRoute is managed by a declarative tool — such as **ArgoCD, Flux, or a Helm release**
— the tool may detect the injected `extensionRef` as drift from the declared manifest and
revert it on the next reconcile or `helm upgrade`. The controller then re-injects it, and the
cycle repeats. **During every reconcile window the allowlist filter is absent and the route is
unprotected** — a recurring security gap.

> **Note:** In practice, most modern tools do not revert fields that are absent from the
> declared manifest. Verify the behaviour of your specific tooling and version before assuming
> a conflict exists.

#### Fix: configure ArgoCD to ignore the injected filters

Add an `ignoreDifferences` rule to the ArgoCD `Application` that owns the HTTPRoute:

```yaml
spec:
  ignoreDifferences:
  - group: gateway.networking.k8s.io
    kind: HTTPRoute
    jqPathExpressions:
    - >
      .spec.rules[].filters[]?
      | select(
          .type == "ExtensionRef" and
          .extensionRef.group == "traefik.io" and
          .extensionRef.kind == "Middleware"
        )
```

To apply this cluster-wide for all ArgoCD Applications, add it to `argocd-cm` instead:

```yaml
# argocd-cm ConfigMap
data:
  resource.customizations.ignoreDifferences.gateway.networking.k8s.io_HTTPRoute: |
    jqPathExpressions:
    - >
      .spec.rules[].filters[]?
      | select(
          .type == "ExtensionRef" and
          .extensionRef.group == "traefik.io" and
          .extensionRef.kind == "Middleware"
        )
```

This tells ArgoCD to ignore only the controller-injected Traefik `extensionRef` entries while
still tracking all other changes to `spec.rules`.

For **Flux**, use a `kustomization.yaml` patch or a `substituteFrom` field exclusion targeting
`spec.rules[*].filters`. For **Helm**, add the HTTPRoute to a `lookup` or manage it outside
the chart so `helm upgrade` does not overwrite the field.

> **Security note:** if this configuration is missing, the allowlist is silently disabled on
> every declarative reconcile. See [security considerations](security.md#declarative-tooling-conflict--intermittent-allowlist-disable)
> for the full risk analysis.
