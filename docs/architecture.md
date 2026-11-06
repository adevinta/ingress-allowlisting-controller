# Ingress Allowlisting Controller — Architecture

## Reconcilers vs Writers

The controller has two conceptually different types of components:

### Reconcilers (source-driven)
Watch a Kubernetes object that **already exists** and inject CIDRs into it.
The object is owned by someone else — the reconciler only mutates part of its spec.

| Reconciler | Watches | Mutates | Target |
|---|---|---|---|
| `IngressReconciler` | `networking.k8s.io/v1 Ingress` | `nginx.ingress.kubernetes.io/whitelist-source-range` annotation | Nginx / cloud LB controllers |
| `NetworkPolicyReconciler` | `networking.k8s.io/v1 NetworkPolicy` | `spec.ingress[].from[].ipBlock` | Any CNI enforcing standard NetworkPolicy |
| `ServiceReconciler` | `v1 Service` (`type: LoadBalancer`) | `spec.loadBalancerSourceRanges` | Load balancers honouring source ranges (AWS, GCP, Azure, MetalLB) |

### Writers (creator-driven, Gateway API)
Resolve a Gateway API object chain (`HTTPRoute → Gateway → GatewayClass → controllerName`) and **create a new enforcement object** specific to the ingress controller in use.
Writers are registered in a registry keyed by `GatewayClass.spec.controllerName`.

| Writer | Interface | Creates | Target Controller |
|---|---|---|---|
| `IstioL4Writer` | `L4PolicyWriter` | `security.istio.io/v1 AuthorizationPolicy` (TargetRef → Gateway) | Istio |
| `IstioL7Writer` | `L7PolicyWriter` + `MergeableL7PolicyWriter` | `security.istio.io/v1 AuthorizationPolicy` (TargetRef → Gateway, per HTTPRoute) | Istio |
| `TraefikL7Writer` | `L7PolicyWriter` + `GatewayCIDRsMerger` | `traefik.io/v1alpha1 Middleware` (IPAllowList) + patches `HTTPRoute.spec.rules[].filters` | Traefik |

### Removing the allowlist annotation

When an object loses its `allowlist-group` / `cluster-allowlist-group` annotation, the controller
stops managing it and removes only what is clearly its own. The result depends on who owns the
object the allowlist lives in:

| Kind | What the controller wrote | On annotation removal |
|---|---|---|
| Ingress, Service, NetworkPolicy (reconcilers) | a field on **someone else's** object: the nginx `whitelist-source-range` annotation, `spec.loadBalancerSourceRanges`, the `ipBlock` entries | **the last value stays**, and a warning is logged |
| Gateway, HTTPRoute with Istio (writers) | its **own** AuthorizationPolicy | **the policy is deleted**: the allowlist is lifted |
| HTTPRoute with Traefik (writer) | its **own** Middleware, and an `extensionRef` filter on the route | **the Middleware is deleted** and only its own filter is removed from the route |

The reconcilers can't undo their change: they overwrote a whole field and don't know what the
owner had there before. Clearing it wouldn't be safe either: an empty field means "open to all" in
all three cases. So the field keeps the last allowlist the controller wrote, and it is **frozen**:
later changes to the CIDRs objects no longer reach it. An IP removed from a CIDRs object keeps
access to that object until its owner edits or clears the field. The controller logs
`<Kind> <ns>/<name>: allowlist annotation removed, the controller stopped managing it; …` once, at
the removal.

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

Writers are registered by controller name. Adding support for a new ingress controller (e.g. Envoy Gateway) requires only:
1. Implement `L4PolicyWriter` or `L7PolicyWriter`
2. Add `RequiredPermissions()` so the RBAC preflight check covers it automatically
3. Register in `controllers.go` — nothing else changes

The reconciler (`HTTPRouteAllowlistingReconciler`, `GatewayAllowlistingReconciler`) is completely agnostic to the underlying enforcement technology.

#### Optional interfaces

| Interface | Purpose |
|---|---|
| `MergeableL7PolicyWriter` | Merge multiple HTTPRoutes sharing a gateway into one policy (Istio only) |
| `GatewayCIDRsMerger` | Merge parent Gateway CIDRs into each child HTTPRoute's policy instead of writing a separate gateway-level policy (Traefik) |
| `PathTranslator` | Control how HTTPRoute path matches are translated before being passed to `Apply` |

---

## Controller Support Matrix

### Gateway API — L4 (Gateway level)

| Controller | `GatewayClass.controllerName` | Creates | Granularity | Implemented |
|---|---|---|---|---|
| Istio | `istio.io/gateway-controller` | `AuthorizationPolicy` (TargetRef → Gateway) | Gateway | ✅ |
| Traefik | `traefik.io/gateway-controller` | Merged into child HTTPRoute Middlewares (software) | HTTPRoute | ✅ via `GatewayCIDRsMerger` |
| Envoy Gateway | `gateway.envoyproxy.io/gatewayclass-controller` | `SecurityPolicy` (TargetRef → Gateway) | Gateway | 🔲 TODO |
| Cilium | `io.cilium/gateway-controller` | — (pod-selector based, not Gateway API aware) | — | ➖ N/A |

### Gateway API — L7 (HTTPRoute level)

| Controller | `GatewayClass.controllerName` | Creates | Granularity | Merge support | Path support | Implemented |
|---|---|---|---|---|---|---|
| Istio | `istio.io/gateway-controller` | `AuthorizationPolicy` (TargetRef → Gateway, per route) | HTTPRoute + host + path | ✅ (`MergeableL7PolicyWriter`) | ✅ (`granularity` annotation) | ✅ |
| Traefik | `traefik.io/gateway-controller` | `Middleware` (IPAllowList) | HTTPRoute | ➖ not supported | ➖ not applicable | ✅ |
| Envoy Gateway | `gateway.envoyproxy.io/gatewayclass-controller` | `SecurityPolicy` (TargetRef → HTTPRoute) | HTTPRoute + host + path | 🔲 TODO | 🔲 TODO | 🔲 TODO |

### Legacy / Non-Gateway API

| Reconciler | Watches | Enforced by | L4/L7 | Granularity | Notes |
|---|---|---|---|---|---|
| `IngressReconciler` | `networking.k8s.io/v1 Ingress` | Nginx, cloud LBs | L7 | Ingress object | Patches annotation in place |
| `NetworkPolicyReconciler` | `networking.k8s.io/v1 NetworkPolicy` | Any standard-compliant CNI | L3/L4 | Pod selector | See CNI support below |
| `ServiceReconciler` | `v1 Service` (`type: LoadBalancer`) | Cloud/LB implementation (AWS, GCP, Azure, MetalLB) | L3/L4 | Service object | Patches `spec.loadBalancerSourceRanges` in place |

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

All AP names follow a deterministic pattern derived from the objects involved
(`pkg/controllers/writers/policy_names.go`).

| Scenario | Pattern | Example |
|---|---|---|
| Gateway (L4) | `{gw}`, in the Gateway's namespace | `my-gateway` |
| Same-namespace, no paths | `{gw}-{route}` | `my-gateway-my-route` |
| Same-namespace, with paths | `{gw}-{route}-{fnv32hex}` | `my-gateway-my-route-3d2a1f8c` |
| Cross-namespace | `{routeNS}.{gw}.{route}.{hash8}` | `app-ns.my-gateway.my-route.61094ef9` |
| Merge mode | `merge.{gw}.{mergeKey}.{hash8}` | `merge.my-gateway.chaos-monkey.36b154f3` |

### Identity hash (cross-namespace and merge mode, since v0.3.0)

The APs in the Gateway's namespace come from routes of every namespace and from merge keys people
choose, so names built by joining parts collided: route `x` of namespace `team-a` and route `a-x`
of namespace `team` both gave `{gw}-team-a-x`, and a merge key was the whole name, so two Gateways
of one namespace using the same key shared one AP. These names now end with `hash8`, the first 8
hex digits of a SHA-256 over what identifies the AP, the parts separated by `\0`:

| AP | Hash input |
|---|---|
| Cross-namespace | annotation prefix, `route`, route namespace, Gateway, route, the rule's sorted paths |
| Merge mode | annotation prefix, `merged`, Gateway, merge key |

- **The kind** (`route` / `merged`): `merge` is a valid namespace name, so a route of namespace
  `merge` has the shape of a merged AP. The kind keeps them apart.
- **The annotation prefix**: two controller instances with different `--annotation-prefix` can use
  the same merge key on a shared Gateway for different groups; each gets its own AP.
- **The separators** keep `[/a, /b]` and `[/a/b]`, or Gateway `a.b` + route `c` and Gateway `a` +
  route `b.c`, apart.
- The hash is always there, also without paths. When a name would exceed 253 characters the
  readable part is cut; `.{hash8}` stays whole.

Same-namespace names keep their format, `{gw}-{route}-{fnv32hex}` (see below).

### Same-namespace names can collide

Same-namespace names join the parts with `-`, which Gateway and route names may contain, and have
no hash. They were kept as they are so that upgrading doesn't rename every route's AP. So in one
namespace:

- Gateway `a-b` with route `c`, and Gateway `a` with route `b-c`, both give `a-b-c`;
- Gateway `a` with route `b-c` gives `a-b-c`, the name of the L4 AP of a Gateway `a-b-c`;
- Gateway `a` with route `b`, for a rule with paths, gives `a-b-{fnv32hex}`, the name of the AP of a
  route `b-{fnv32hex}` on the same Gateway;
- two rules of one route with different paths can get the same `{fnv32hex}`: it is a 32-bit hash,
  so two given path sets collide with a chance of 1 in 2³², and a route has at most 16 rules. Found
  on purpose, a collision takes about 2¹⁶ tries, but only the route's owner can write its paths.
  The two rules then share one AP and, being the same route's, overwrite it in turn on every
  reconcile: only one rule's paths are allowed at a time. Only that route is affected. A longer
  hash would rename every AP with paths, so it stays.

Apart from the last case, it takes two Gateways in the routes' namespace, or a route named like a
path hash. Nothing is overwritten then: the first AP written keeps the name, and the other route or
Gateway gets no allowlist and a Warning Event `AllowlistPolicyConflict` (see
[security.md](security.md)). To fix it, rename
the route or the Gateway. Cross-namespace and merged APs can't collide this way: their names end
with the identity hash.

**Upgrading to v0.3.0 renames the cross-namespace and merged APs.** Nothing to do by hand: when a
route or merge group is reconciled (all are, right after the controller starts), the AP is written
under its new name first, then the controller's AP under the old name is deleted, so access has no
gap. Until then the orphan checks count the old name as the route's, so the startup cleanup
doesn't delete it early. An AP under the old name that isn't the controller's is left alone.
Anything that refers to these APs by name (runbooks, dashboards, `kubectl get` scripts) must use
the new names; select them by their labels instead (see [security.md](security.md)).

### Path-based collision protection

When a rule has paths, a FNV-32a hash of the **full sorted path set** is appended:

```
suffix = hex8(fnv32a(join(sorted_paths, "\0")))
```

- Sorting makes the name order-independent — reordering matches in an HTTPRoute rule does not rename the AP
- The paths are joined with `\0`, so two rules with `[/a, /b]` and `[/a/b]` get different names. Before
  (up to v0.3.0) they were written back to back: both rules got one name and overwrote each other's
  AP on every reconcile, allowing only the last rule's paths. A single path is hashed as before, so
  a rule with one path (`Exact /x`, `PathPrefix /`) keeps its name; a rule with several
  (`PathPrefix /x` gives `/x` and `/x/*`) gets a new one, and the route's stale cleanup deletes the
  old one after the new one is written
- FNV-32a output is hex digits only (`[0-9a-f]`) — always a valid Kubernetes name segment
- The human-readable part comes from the HTTPRoute name itself, not the path

Collision table:

| Input | Suffix | Notes |
|---|---|---|
| `["/api"]` | `3d2a1f8c` | single path, hash only |
| `["/api", "/health"]` | `5f1a9c2e` | multi-path, hash of full set |
| `["/api", "/admin"]` | `7b2e41f0` | different set, different hash |
| `["/api/*"]` | `8e4d3b1a` | glob path, same format |

A same-namespace gateway named `my-gw` with route `r` would produce:
```
gw-r                ← no paths (granularity=host)
gw-r-3d2a1f8c       ← paths [/api, /api/*]
gw-r-5f1a9c2e       ← paths [/admin, /admin/*]
```

None of these can ever collide.

---

## TODO

| Priority | Item | Notes |
|---|---|---|
| 🟡 Medium | Envoy Gateway `SecurityPolicy` writer (L4 + L7) | Closest Istio equivalent; `targetRef` model is nearly identical |
| 🟠 Low | Cilium-native `CiliumNetworkPolicy` reconciler | Pod-selector based; separate reconciler pattern, not a writer |
| 🟠 Low | Calico-native `NetworkPolicy` reconciler | Expression language differs from standard K8s; separate reconciler pattern |
