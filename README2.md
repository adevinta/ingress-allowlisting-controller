# Ingress Allowlisting Controller — Deep Dive

## Architecture: Reconcilers vs Writers

The controller has two conceptually different types of components:

### Reconcilers (source-driven)
Watch a Kubernetes object that **already exists** and inject CIDRs into it.
The object is owned by someone else — the reconciler only mutates part of its spec.

| Reconciler | Watches | Mutates | Target |
|---|---|---|---|
| `IngressReconciler` | `networking.k8s.io/v1 Ingress` | `nginx.ingress.kubernetes.io/whitelist-source-range` annotation | Nginx / cloud LB controllers |
| `NetworkPolicyReconciler` | `networking.k8s.io/v1 NetworkPolicy` | `spec.ingress[].from[].ipBlock` | Any CNI enforcing standard NetworkPolicy |

### Writers (creator-driven, Gateway API)
Resolve a Gateway API object chain (`HTTPRoute → Gateway → GatewayClass → controllerName`) and **create a new enforcement object** specific to the ingress controller in use.
Writers are registered in a registry keyed by `GatewayClass.spec.controllerName`.

| Writer | Interface | Creates | Target Controller |
|---|---|---|---|
| `IstioL4Writer` | `L4PolicyWriter` | `security.istio.io/v1 AuthorizationPolicy` (TargetRef → Gateway) | Istio |
| `IstioL7Writer` | `L7PolicyWriter` + `MergeableL7PolicyWriter` | `security.istio.io/v1 AuthorizationPolicy` (TargetRef → Gateway, per HTTPRoute) | Istio |

### Resolution chain for writers

```
HTTPRoute
  └─ spec.parentRefs[].name/namespace
       └─ Gateway
            └─ spec.gatewayClassName
                 └─ GatewayClass
                      └─ spec.controllerName  ──► L4WriterRegistry / L7WriterRegistry
                                                        └─ Writer.Apply(...)
                                                             └─ creates enforcement object
```

### Why interfaces?

Writers are registered by controller name. Adding support for a new ingress controller (e.g. Envoy Gateway, Traefik) requires only:
1. Implement `L4PolicyWriter` or `L7PolicyWriter`
2. Add `RequiredPermissions()` so the RBAC preflight check covers it automatically
3. Register in `controllers.go` — nothing else changes

The reconciler (`HTTPRouteAllowlistingReconciler`, `GatewayAllowlistingReconciler`) is completely agnostic to the underlying enforcement technology.

---

## Controller Support Matrix

### Gateway API — L4 (Gateway level)

| Controller | `GatewayClass.controllerName` | Creates | Granularity | Implemented |
|---|---|---|---|---|
| Istio | `istio.io/gateway-controller` | `AuthorizationPolicy` (TargetRef → Gateway) | Gateway | ✅ |
| Envoy Gateway | `gateway.envoyproxy.io/gatewayclass-controller` | `SecurityPolicy` (TargetRef → Gateway) | Gateway | 🔲 TODO |
| Traefik | `traefik.io/gateway-controller` | — (no L4 Gateway-level policy) | — | 🔲 TODO |
| Cilium | `io.cilium/gateway-controller` | — (pod-selector based, not Gateway API aware) | — | ➖ N/A |

### Gateway API — L7 (HTTPRoute level)

| Controller | `GatewayClass.controllerName` | Creates | Granularity | Merge support | Path support | Implemented |
|---|---|---|---|---|---|---|
| Istio | `istio.io/gateway-controller` | `AuthorizationPolicy` (TargetRef → Gateway, per route) | HTTPRoute + host + path | ✅ (`MergeableL7PolicyWriter`) | ✅ (`granularity` annotation) | ✅ |
| Traefik | `traefik.io/gateway-controller` | `Middleware` (IPAllowList) | HTTPRoute | ➖ not supported | ➖ not applicable | 🔲 TODO |
| Envoy Gateway | `gateway.envoyproxy.io/gatewayclass-controller` | `SecurityPolicy` (TargetRef → HTTPRoute) | HTTPRoute + host + path | 🔲 TODO | 🔲 TODO | 🔲 TODO |

### Legacy / Non-Gateway API

| Reconciler | Watches | Enforced by | L4/L7 | Granularity | Notes |
|---|---|---|---|---|---|
| `IngressReconciler` | `networking.k8s.io/v1 Ingress` | Nginx, cloud LBs | L7 | Ingress object | Patches annotation in place |
| `NetworkPolicyReconciler` | `networking.k8s.io/v1 NetworkPolicy` | Any standard-compliant CNI | L3/L4 | Pod selector | See CNI support below |

### CNI support via `networking.k8s.io/v1 NetworkPolicy`

The `NetworkPolicyReconciler` writes standard `NetworkPolicy` objects with `ipBlock` rules.
Any CNI that enforces the standard spec picks them up automatically:

| CNI | Enforces `networking.k8s.io/v1 NetworkPolicy` | Notes |
|---|---|---|
| AWS VPC CNI | ✅ | Native, no extra config |
| Calico | ✅ | Also has own `crd.projectcalico.org` CRDs with richer expression language |
| Antrea | ✅ | Also has own `ClusterNetworkPolicy` with priority/tier system |
| Cilium | ✅ (deprecated) | Prefers `CiliumNetworkPolicy`; standard spec supported but being phased out |
| kube-router | ✅ | Standard spec only, no custom CRDs |
| Flannel | ❌ | No network policy enforcement — objects are created but silently ignored |

---

## Pod-Oriented vs Gateway-Oriented

A key architectural distinction:

```
Gateway API writers    → target Gateway/HTTPRoute objects (Istio, Traefik, Envoy Gateway)
                         enforcement object knows about the Gateway topology

Pod-oriented writers   → target pods via label selectors (Cilium CNP, Calico NP, Antrea NP)
                         enforcement object has no concept of Gateway or HTTPRoute
                         workload labels flow down: Deployment → ReplicaSet → Pod
```

Pod-oriented controllers are architecturally equivalent to the existing `NetworkPolicyReconciler` — a separate reconciler watching a pre-existing object, not a writer plugged into the Gateway API registry. If Cilium-native (`CiliumNetworkPolicy`) or Calico-native support is needed in the future, it should follow the same pattern as `NetworkPolicyReconciler`, not the writer interface.

---

## AuthorizationPolicy Naming

### Convention

All AP names follow a deterministic pattern derived from the objects involved. The gateway name is always the prefix — this prevents collisions when multiple gateways share the same namespace.

| Scenario | Pattern | Example |
|---|---|---|
| Same-namespace, no paths | `{gw}-{route}` | `my-gateway-my-route` |
| Same-namespace, single path | `{gw}-{route}-{pathSafe(path)}` | `my-gateway-my-route-api` |
| Same-namespace, multiple paths | `{gw}-{route}-{pathSafe(paths[0])}-{fnv32hex}` | `my-gateway-my-route-api-3d2a1f8c` |
| Cross-namespace, no paths | `{gw}-{routeNS}-{route}` | `my-gateway-app-ns-my-route` |
| Cross-namespace, single path | `{gw}-{routeNS}-{route}-{pathSafe(path)}` | `my-gateway-app-ns-my-route-api` |
| Cross-namespace, multiple paths | `{gw}-{routeNS}-{route}-{pathSafe(paths[0])}-{fnv32hex}` | `my-gateway-app-ns-my-route-api-3d2a1f8c` |
| Merge mode | `{mergeKey}` | `chaos-monkey` |

### `pathSafe` encoding

`pathSafe` converts a URL path to a valid Kubernetes name segment:

1. Escape `-` → `--` (so the separator `-` is never ambiguous)
2. Trim leading and trailing `/`
3. Replace remaining `/` with `-`

Examples:

| Path | `pathSafe` result |
|---|---|
| `/api` | `api` |
| `/admin/users` | `admin-users` |
| `/admin-users` | `admin--users` |
| `/` | `""` → caller uses sentinel `-root` → final name ends `--root` |

The double-dash prefix produced by `/` (`--root`) is unreachable by any real path, since `pathSafe` escapes all literal `-` first.

### Multi-path collision protection

When a rule has a single path the suffix is the plain readable `pathSafe` result. When a rule has **multiple paths** a hash is appended:

```
suffix = pathSafe(sorted_paths[0]) + "-" + hex8(fnv32a(sorted_paths))
```

- `sorted_paths[0]` gives a human-readable hint — operators can identify the rule at a glance
- The FNV-32a hash covers the **full sorted set**, so two rules sharing the same first path but differing elsewhere get different names
- Sorting makes the name order-independent — reordering matches in an HTTPRoute rule does not rename the AP
- FNV-32a output is hex digits only (`[0-9a-f]`) — always a valid Kubernetes name segment

Collision table:

| Input | Suffix | Notes |
|---|---|---|
| `["/api"]` | `api` | single path, readable, no hash |
| `["/api", "/health"]` | `api-3d2a1f8c` | multi-path, first + hash |
| `["/api", "/admin"]` | `api-7b2e41f0` | same first path, different hash |
| `["/api-v2"]` | `api--v2` | single path, dash escaped — never clashes with above |

A same-namespace gateway named `my-gw` with route `r` would produce:
```
gw-r-api            ← single path /api
gw-r-api-3d2a1f8c   ← paths [/api, /health]
gw-r-api-7b2e41f0   ← paths [/api, /admin]
gw-r-api--v2        ← single path /api-v2 (dash escaped)
```

None of these can ever collide.

---

## TODO

| Priority | Item | Notes |
|---|---|---|
| 🟡 Medium | Envoy Gateway `SecurityPolicy` writer (L4 + L7) | Closest Istio equivalent; `targetRef` model is nearly identical |
| 🟡 Medium | Traefik `Middleware` writer | IP allowlisting via `IPAllowList`; path filtering handled by HTTPRoute routing itself — no extra path restriction in the Middleware needed |
| 🟠 Low | Cilium-native `CiliumNetworkPolicy` reconciler | Pod-selector based; separate reconciler pattern, not a writer |
| 🟠 Low | Calico-native `NetworkPolicy` reconciler | Expression language differs from standard K8s; separate reconciler pattern |
