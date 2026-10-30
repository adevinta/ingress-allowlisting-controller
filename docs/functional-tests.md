# Functional tests (real cluster, local only)

The suite in `test/functional/` checks the controller's main use cases end to end, against a
**real cluster** with the controller **already installed**. It creates CIDRs objects and annotated
resources in a fresh namespace, and checks that the controller writes the expected allowlists.

Unlike the unit tests and the kind e2e test, it uses real remote CIDR feeds, and whatever
Ingress/NetworkPolicy setup your cluster really has.

> **Local only.** The suite is behind the `functional` build tag, so `go test ./...` (and the
> GitHub workflow) never compiles it, and it skips itself when `CI` or `GITHUB_ACTIONS` is set.

## Running it

```bash
make functional                  # dry run: shows the target cluster and the plan, creates nothing
make functional CONFIRM=<context> # runs it; CONFIRM must equal the current kube context name
make functional-clean            # deletes namespaces (both -a and -b) left by interrupted or KEEP=1 runs
```

The dry run prints everything a real run would do:

```
Target cluster
  context:  my-dev-cluster
  server:   https://ABC123.eks.amazonaws.com
  ...
Controller
  ingress-allowlisting/ingress-allowlisting-controller  ✔ available
  annotation prefix: ipam.adevinta.com

Would create namespaces iac-functional-3de74c-a and iac-functional-3de74c-b (label iac-functional=true), deleted at the end unless KEEP=1

Scenarios
  ✔ ingress          networking.k8s.io/v1 Ingress (nginx whitelist-source-range annotation)
  ✘ networkpolicy    skipped: --networkpolicy-support-enabled is off on the controller
...
```

`CONFIRM` takes the **context name**, not "yes": a run cannot hit a different cluster than the
one you reviewed because of a stale kubeconfig. A `CONFIRM` that does not match fails without
creating anything.

## What it checks

For every resource kind the controller has enabled (read from the controller's own flags):

| Scenario | Expectation |
|---|---|
| `inline` | CIDRs `[203.0.113.0/24, 198.51.100.7]` → exactly `198.51.100.7/32, 203.0.113.0/24` (bare IP becomes /32, sorted) |
| `update-add` | adding a CIDR to the object propagates |
| `update-remove` | removing a CIDR propagates |
| `remote` | an object referencing all remote sources gets exactly the union of their statuses |
| `missing-cidrs` | a reference to a CIDRs object that does not exist gives the deny-all `127.0.0.2/32` |
| `isolation` | a reference to a CIDRs object that exists only in the **other** test namespace gives deny-all, never that namespace's CIDRs |

Once per run, independent of the resource kinds, `conditions` checks the CIDRs object's
`UpToDate` condition with a source that keeps failing:

| Scenario | Expectation |
|---|---|
| `conditions/first-error` | a missing path on an allowlisted host (`ip-ranges.amazonaws.com`) → condition `False` with the `403` |
| `conditions/latest-error` | the source changed to a host outside `--cidr-source-allowlist` → the condition shows the new error (`source not in allowlist`), not the old `403` |
| `conditions/no-status-churn` | once settled, the object's `resourceVersion` stays unchanged for 20s: the controller doesn't reconcile on its own status writes |

It is skipped when the controller's allowlist doesn't allow `ip-ranges.amazonaws.com`, or is empty
(then no source is refused).

Each run uses two namespaces, `iac-functional-<id>-a` (objects under test) and `-b` (the peer,
holding the `shared` CIDRs object and the cross-namespace Gateways).

Istio HTTPRoute and Traefik HTTPRoute also run cross-namespace scenarios: an HTTPRoute in `-a`
attached to a Gateway in `-b`.

| Scenario | Gateway in `-b` | Expectation |
|---|---|---|
| `cross-namespace` | `allowedRoutes: All` | the route's allowlist is written: for **Traefik** a Middleware in `-a`, the route's namespace (`extensionRef` cannot cross namespaces), nothing in `-b`; for **Istio** an AuthorizationPolicy in `-b`, the Gateway's namespace, labelled with the route as owner, nothing in `-a` |
| `allowedroutes-same` | `allowedRoutes: Same` | the Gateway does not accept the route, so **nothing** is written for it, watched for 30s (NEW_IDEAS item 1). For Istio a policy would otherwise still apply to the Gateway by host, i.e. to other tenants' hosts |

Resource kinds covered so far:

| Kind | Controller flag | Where the allowlist is checked |
|---|---|---|
| Ingress | `--ingress-support-enabled` (default on) | `nginx.ingress.kubernetes.io/whitelist-source-range` annotation |
| NetworkPolicy | `--networkpolicy-support-enabled` | `spec.ingress[0].from` and `spec.egress[0].to` ipBlocks (must be identical) |
| Service | `--service-support-enabled` | `spec.loadBalancerSourceRanges` of a `type: LoadBalancer` Service |
| Istio Gateway | `--gateway-support-enabled` | `remoteIpBlocks` of the AuthorizationPolicy named after the Gateway |
| Istio HTTPRoute | `--httproute-support-enabled` | `remoteIpBlocks` of the one AuthorizationPolicy labelled as owned by the route |
| Traefik HTTPRoute | `--httproute-support-enabled` | `ipAllowList.sourceRange` of the Middleware named after the route, **and** an `ExtensionRef` filter to it on every route rule |

The Gateway API kinds also need their CRDs and a GatewayClass of the right controller
(`istio.io/gateway-controller`, `traefik.io/gateway-controller`); without them the kind is
skipped, with the reason in the plan. HTTPRoutes are attached to a `parent` Gateway the suite
creates in the test namespace (same-namespace only). If the controller runs with
`--httproute-label-selector`, the routes get those labels.

Remote sources, fetched by the **controller** (the test only checks the result):

| Name | Source | Processing |
|---|---|---|
| `gp-exit-ips` | `api.gp-exit-ips.network-landing-zone.advgo.net/?countries=DE,NL` | CEL `data.ips` |
| `aws-r53-health` | `ip-ranges.amazonaws.com/ip-ranges.json` | CEL, `ROUTE53_HEALTHCHECKS` only |
| `akamai` | `techdocs.akamai.com/.../akamai_ipv4_CIDRs.csv` | CSV (with a byte order mark) |

Each must become `UpToDate`, with a non-empty status holding only valid CIDRs. Feeds change over
time, so the `remote` scenario compares against the statuses at the time of the check rather than
fixed values.

Out of scope for now: `ClusterCIDRs`, `headersFrom`, and Istio merge mode.

## Prerequisites

- The controller is installed and has an available replica. It is found by the Helm chart label
  `chart=ingress-allowlisting-controller`, or by its image name.
- The resource kinds you want covered are enabled on it (e.g. `--networkpolicy-support-enabled`).
  Disabled kinds are skipped and shown as such in the plan.
- For the remote sources: the controller pod can reach the internet, and, if
  `--cidr-source-allowlist` is set, it lists the three hosts above. Sources it does not allow are
  skipped.
- Your kube user can create namespaces, CIDRs, Ingresses and NetworkPolicies.

The objects are harmless:

- the Ingress has no ingress class and an `.invalid` host;
- the NetworkPolicy and the Service select no pods;
- the Service uses a `loadBalancerClass` no load balancer controller implements, so no cloud
  load balancer is created;
- Gateways only listen for `*.functional.invalid`; the Istio ones ask for a `ClusterIP`
  Service (`networking.istio.io/service-type`), so the auto-deployed gateway gets no cloud load
  balancer either. Istio does deploy a gateway pod for each, removed with the namespace.

## Settings

| Variable | Meaning |
|---|---|
| `CONFIRM` | Name of the current kube context; required to create anything |
| `IAC_CONTEXT` | Use this kube context instead of the current one |
| `IAC_CONTROLLER` | `namespace/name` of the controller Deployment, when several are found |
| `IAC_CONTROLLER_ARGS` | The controller's arguments, when it runs outside the cluster (e.g. `go run` on your laptop). Replaces Deployment detection |
| `IAC_ISTIO_GATEWAYCLASS`, `IAC_TRAEFIK_GATEWAYCLASS` | GatewayClass to use when several exist for that controller (default: the first by name) |
| `IAC_TIMEOUT` | How long each wait may take (default `3m`) |
| `KEEP` | Any value keeps the test namespaces for inspection; remove it later with `make functional-clean` |

## Adding a resource kind

Add a `target` (`test/functional/targets_test.go`, Gateway API kinds in
`gateway_targets_test.go`): the controller flag that enables it, why the cluster cannot run it
(`unavailable`), optional `setup` (e.g. a parent Gateway), how to create an annotated object, and
how to read the allowlist the controller wrote. All scenarios then
run for it. The pure helpers have their own tests that need no cluster:

```bash
go test -tags functional -run 'Flag|Origin|Expected' ./test/functional/
```
