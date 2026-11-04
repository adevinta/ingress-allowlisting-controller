# Gateway API — Gateway & HTTPRoute

**Requires:** [Kubernetes Gateway API CRDs](https://gateway-api.sigs.k8s.io/) + Istio, Traefik or the
AWS Load Balancer Controller

The controller supports `Gateway` and `HTTPRoute` resources from the Kubernetes Gateway API.
The output depends on which ingress controller is installed:

| Gateway controller | Gateway annotation → | HTTPRoute annotation → |
|---|---|---|
| Istio (`istio.io/gateway-controller`) | `AuthorizationPolicy` (L4) | `AuthorizationPolicy` (L7) |
| Traefik (`traefik.io/gateway-controller`) | _(not applicable)_ | `Middleware` (IPAllowList) |
| AWS Load Balancer Controller (`gateway.k8s.aws/alb`, `gateway.k8s.aws/nlb`) | `sourceRanges` of its `LoadBalancerConfiguration` (L4, security group) | _(not supported, see [why](#no-per-route-allowlist-on-aws-gateways))_ |

**Auto-detection:** the controller checks at startup which CRDs are present (`AuthorizationPolicy`,
`Middleware`, `LoadBalancerConfiguration`) and registers only the relevant writers. No flags are
needed beyond the ones below; all can be active on one cluster.

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

Removing the annotation deletes the AuthorizationPolicy or Middleware the controller created for
the object, so its allowlist is lifted. For an AWS Gateway the last `sourceRanges` stay: the
controller only modifies that `LoadBalancerConfiguration`, and removing them would open the load
balancer to everyone (see [below](#gateway--aws-load-balancer-controller-l4)).

The Service the implementation creates for a Gateway inherits the Gateway's annotations (Istio),
but `--service-support-enabled` leaves it alone: `loadBalancerSourceRanges` there would apply at the
load balancer, before the HTTPRoutes' policies, and block what the routes allow. See
[Services generated for a Gateway](service.md#services-generated-for-a-gateway). See [Removing the allowlist annotation](architecture.md#removing-the-allowlist-annotation).

---

> **Istio checks the client IP as the gateway determines it.** Behind a load balancer that is only
> the real client IP with Proxy Protocol, or with a correct `numTrustedProxies`. A
> `numTrustedProxies` that is too high lets clients pass the allowlist with a forged
> `X-Forwarded-For` header. See
> [AWS: preserving client IP for IP-based filtering](security.md#aws-preserving-client-ip-for-ip-based-filtering-istio),
> including how to check it.

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

## Gateway → AWS Load Balancer Controller (L4)

For the Gateways of the [AWS Load Balancer Controller](https://kubernetes-sigs.github.io/aws-load-balancer-controller/latest/guide/gateway/gateway/)
(GatewayClass controllers `gateway.k8s.aws/alb` and `gateway.k8s.aws/nlb`), the allowlist goes
into the `sourceRanges` of the `LoadBalancerConfiguration` the Gateway references. The AWS
controller turns them into the inbound rules of the load balancer's security group: one rule per
CIDR and listener port, for an ALB and an NLB alike. Enable with `--gateway-support-enabled`; the
writer is registered when the `LoadBalancerConfiguration` CRD (`gateway.k8s.aws/v1beta1`) is
installed.

```yaml
apiVersion: gateway.k8s.aws/v1beta1
kind: LoadBalancerConfiguration
metadata:
  name: my-gateway
  namespace: my-app
spec:
  scheme: internet-facing
  # sourceRanges: written by the controller
---
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata:
  name: my-gateway
  namespace: my-app
  annotations:
    ipam.adevinta.com/cluster-allowlist-group: office-ips
spec:
  gatewayClassName: aws-alb
  infrastructure:
    parametersRef:
      group: gateway.k8s.aws
      kind: LoadBalancerConfiguration
      name: my-gateway
  listeners:
  - name: http
    port: 80
    protocol: HTTP
```

The controller then patches only `spec.sourceRanges` of `my-app/my-gateway`; every other setting
stays as you wrote it. The `LoadBalancerConfiguration` is read on demand and never watched: a
hand edit of `sourceRanges` is put back on the Gateway's next reconcile (a change to it or its
CIDRs).

**The Gateway must reference its own `LoadBalancerConfiguration`.** Like a Service's
`loadBalancerSourceRanges`, the field belongs to an object you own; the controller never changes
the Gateway itself (that would drift from Git). So:

| Situation | What happens | Event on the Gateway |
|---|---|---|
| No `spec.infrastructure.parametersRef`, or it names no existing `LoadBalancerConfiguration` | nothing written | Warning `AllowlistTargetMissing` |
| The `LoadBalancerConfiguration` is also used by another Gateway with another allowlist, or none | nothing written: it would set that Gateway's load balancer too | Warning `AllowlistPolicyConflict` |
| `securityGroups` is set (on it, or on the GatewayClass's `LoadBalancerConfiguration` and that one wins) | written, but the AWS controller uses those security groups as they are and ignores `sourceRanges` | Warning `AllowlistIneffective` |
| The GatewayClass's `LoadBalancerConfiguration` sets `sourceRanges` and wins the merge (its `mergingMode` is `prefer-gateway-class`, the default) | written, but the GatewayClass's apply | Warning `AllowlistIneffective` |
| Annotation removed | the last `sourceRanges` stay: removing them would open the load balancer to `0.0.0.0/0` and `::/0` | — |

None of these is retried: a person has to change the objects, and the next reconcile picks it up.
Several Gateways can share one `LoadBalancerConfiguration` when they carry the same allowlist
annotations.

> **Security group rule quota.** The AWS controller creates one inbound rule per CIDR and listener
> port (twice that with `enableICMP`), and AWS allows 60 inbound rules per security group by
> default (IPv4 and IPv6 counted separately; the quota can be raised). A feed of 31 CIDRs on a
> Gateway with ports 80 and 443 already needs 62. The controller doesn't check this; the AWS
> controller reports it in the Gateway's status. Keep the CIDR lists of AWS Gateways short, or raise
> the quota.

### No per-route allowlist on AWS Gateways

An annotation on an HTTPRoute attached to an AWS Gateway does nothing: no L7 writer is registered
for `gateway.k8s.aws/alb`, so the route is skipped. The allowlist of an AWS Gateway covers its
whole load balancer, every route on it.

**Why not per route.** The only per-route source-IP option of the AWS Load Balancer Controller is a
`ListenerRuleConfiguration` with a `source-ip` condition, referenced from a route rule. It doesn't
fit an allowlist:

- **At most 3–4 CIDRs per route rule, and that can't be raised.** An ALB listener rule holds 5
  condition values in total ([quotas](https://docs.aws.amazon.com/elasticloadbalancing/latest/application/load-balancer-limits.html):
  "Condition Values per Rule: 5", not adjustable), shared by the host, path and `source-ip`
  values. A rule always has a path (`PathPrefix /` becomes `/*`), so it's 4 CIDRs for a route
  without a hostname, 3 with one, fewer with more. A feed doesn't fit.
- **A list that is too long fails silently.** AWS rejects the rule (`ValidationError: A rule can
  only have '5' condition values and regex values`) and the ALB keeps the previous one: the new
  CIDRs never apply, removed ones stay allowed. The ListenerRuleConfiguration (`Accepted`), the
  HTTPRoute (`Accepted`) and the Gateway (`Programmed`) stay green; the error is only in the
  Gateway's `FailedDeployModel` Warning Events and the AWS controller's log.
- **It's a match condition, not a deny.** A client outside the list doesn't match the rule and
  gets the listener's default 404, unless another route on the Gateway matches the same host and
  path without the condition: then that route serves it.
- **One `ListenerRuleConfiguration` per route rule.** A second one makes the rule invalid, so it
  can't be added next to one a team already uses.

Splitting a list over several rules (100 rules per ALB, adjustable) would mean duplicating the
matches of the user's HTTPRoute, and uses up the rules shared by every route of the load balancer.

**What to do instead: one Gateway per audience.** Routes that need different allowlists go on
different Gateways, each with its own load balancer, security group and allowlist:

```yaml
# Open to everyone: no allowlist annotation
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata: {name: public-gw, namespace: team-a}
spec:
  gatewayClassName: aws-alb
  infrastructure:
    parametersRef: {group: gateway.k8s.aws, kind: LoadBalancerConfiguration, name: public-gw}
  listeners: [{name: https, port: 443, protocol: HTTPS}]   # plus TLS settings
---
# Office only
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata:
  name: office-gw
  namespace: team-a
  annotations:
    ipam.adevinta.com/allowlist-group: office
spec:
  gatewayClassName: aws-alb
  infrastructure:
    parametersRef: {group: gateway.k8s.aws, kind: LoadBalancerConfiguration, name: office-gw}
  listeners: [{name: https, port: 443, protocol: HTTPS}]
---
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata: {name: shop, namespace: team-a}
spec:
  parentRefs: [{name: public-gw}]
  hostnames: [shop.example.com]
  rules: [{backendRefs: [{name: shop, port: 80}]}]
---
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata: {name: admin, namespace: team-a}
spec:
  parentRefs: [{name: office-gw}]
  hostnames: [admin.example.com]
  rules: [{backendRefs: [{name: admin, port: 80}]}]
```

Each Gateway has its own `LoadBalancerConfiguration` (see above). `admin.example.com` then
resolves to a load balancer whose security group only lets the office in: a client outside it
can't even connect. This is a real deny and holds feeds, at the cost of one load balancer per
audience (an hourly fee each, 50 ALBs per region by default) and DNS per hostname (e.g.
external-dns). It suits a few audiences (public, office, partners), not one per route.

**Many CIDRs per route** are only possible with [AWS WAF](https://docs.aws.amazon.com/waf/latest/developerguide/waf-chapter.html):
a web ACL on the ALB (`wafV2` in the `LoadBalancerConfiguration`) with an IP set (up to 10,000
CIDRs) and rules combining it with a host or path match. The web ACL and IP sets are AWS
resources managed outside Kubernetes; this controller doesn't manage them.

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
namespace, named `{httproute.Namespace}.{gateway.Name}.{httproute.Name}.{hash8}` (see
[AP naming](architecture.md#authorizationpolicy-naming)). No ownerReference
(Kubernetes does not support cross-namespace owner refs). Orphaned APs are cleaned up at
controller startup.

**Multiple gateways**: one AP is created per parentRef, each prefixed with the gateway name.

**`hostnames` is required.** An HTTPRoute without `hostnames` gets no AP, with or without
paths, and an AP created for it earlier is deleted. Such an AP would have no `to.hosts`, and
paths alone don't limit it to a host. It would allow the route's CIDRs on every host of the
gateway, including hosts of other routes and namespaces. The controller logs a warning on each
reconcile of such a route. In merge mode, the route is left out of the merged AP, and the rest
of the group still applies. If the route's AP was the only ALLOW policy on that gateway, removing
it puts the gateway back to Istio's default, which allows all traffic.

**The Gateway must accept the route.** A policy is written only for a parentRef whose Gateway
accepts the route, as its listeners' `allowedRoutes` say. This applies to every route, in the
same namespace as the Gateway or not, and to Traefik too. Without the check, a route from any
namespace could get an AP into the gateway's namespace that applies to the gateway by host,
including other namespaces' hosts, even though the Gateway rejects the route itself. For the
listeners the parentRef targets (`sectionName`, `port`), the controller checks:

- `allowedRoutes.kinds`: must include `HTTPRoute`. Without kinds, only `HTTP` and `HTTPS`
  listeners accept HTTPRoutes.
- `allowedRoutes.namespaces`: `Same` (the default), `All`, `None`, or `Selector`. For `Selector`
  the controller reads the route namespace's labels, with no watch, and keeps them for 10 minutes.

A route the Gateway doesn't accept gets no AP or Middleware on that Gateway, and one written
earlier is deleted. The controller logs a warning, and in merge mode the route is left out of the
merged AP. Things to know:

- The check runs when the route reconciles: on a change to the route or its CIDRs, or the
  periodic resync. Changing a Gateway's `allowedRoutes` or a namespace's labels doesn't trigger
  it, so a revoked route keeps its policy until then (plus up to 10 minutes for labels).
- **An AP gets only the hostnames the Gateway routes for the route** (since v0.3.0): the route's
  hostnames that match the hostnames of the listeners accepting it (`allowedRoutes`, and the
  parentRef's `sectionName` / `port`), as Gateway API defines it. A listener without `hostname`
  matches all of them; a route wildcard on a more specific listener gives the listener's hostname.
  A route whose hostnames all fall outside its listeners isn't attached, so it gets no AP there,
  like a refused route. Before, an AP got every hostname of the route: on a shared Gateway with a
  listener per tenant (`*.team-a.example.com`, `*.team-b.example.com`), team-a could list
  `shop.team-b.example.com` on its route and allow its own CIDRs there, since Istio ORs ALLOW
  policies by host. A Gateway's listener hostnames are checked when the route reconciles, like
  `allowedRoutes`: changing them takes effect on the route's next reconcile.
- Routes on the **same** listener can still claim the same hostnames as each other, e.g. on a
  listener without `hostname` shared by tenants. Gateway API leaves hostname ownership to the
  implementation; give each tenant its own listener with a `hostname` (and `allowedRoutes` for its
  namespace), or protect the hostnames with a DENY policy (see
  [security.md](security.md#protecting-a-cross-namespace-gateway-with-a-deny-policy-istio)).

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

The merged AP is named `merge.{gateway.Name}.{key}.{hash8}` (see
[AP naming](architecture.md#authorizationpolicy-naming)), so the key must be a valid Kubernetes
name: lowercase letters, digits, `-` and `.`, and each `.`-separated part starts and ends with a
letter or digit (`a.b` is valid, `a..b` and `a-.b` are not). An invalid key is ignored, with an `InvalidMergeKey` Warning Event on the
HTTPRoute: the route keeps its own APs, as without a key, until the key is fixed. When a route
joins a merge group, its own APs are deleted once the merged AP is written. If the merged AP
can't be written (an AP with that name exists and isn't the controller's, see the
`AllowlistPolicyConflict` Event), the route keeps its own APs.

The Gateway is part of the merged AP's name, so the same key on two Gateways of a namespace gives
two merged APs, one per Gateway. So does the same key used by two controller instances with
different `--annotation-prefix` (the prefix is part of the hash). Each lives as long as routes of
the group point to its Gateway: the startup cleanup deletes a Gateway's merged AP once none do,
even if the key is still used on another Gateway. A route that leaves the group, by a new key, by being
deleted, or while it is being deleted (finalizers), is taken out at once: the group's other
members rebuild the merged AP without it, and the last one leaving deletes it.

> **A route annotated for two instances** (under both prefixes) gets an Istio AP from each, and
> Istio combines ALLOW policies with OR: the route allows the union of both allowlists. Annotate a
> route for one instance only.

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
    example.com/allowlisting: enabled   # required if --httproute-label-selector is set
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
