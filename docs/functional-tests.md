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
make functional-clean IAC_RUN=<id> # only those of run <id> (iac-functional-<id>-a/-b)
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

Would create namespaces iac-functional-3de74c-a and iac-functional-3de74c-b (labels iac-functional=true, iac-functional-run=3de74c), deleted at the end unless KEEP=1

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
| `other-instance` | another instance's things are left alone, watched for 30s each, see [Two instances](#two-instances) |
| `revoke-inline` | emptying the inline CIDRs of the `inline` object revokes access: deny-all `127.0.0.2/32`, not the old list |

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
| `cross-namespace` | `allowedRoutes: All` | the route's allowlist is written: for **Traefik** a Middleware in `-a`, the route's namespace (`extensionRef` cannot cross namespaces), nothing in `-b`; for **Istio** an AuthorizationPolicy in `-b`, the Gateway's namespace, labelled with the route as owner and named `{routeNS}.{gw}.{route}.{hash8}`, nothing in `-a` |
| `merge` (Istio only) | `allowedRoutes: All` | two HTTPRoutes, one in `-a` and one in `-b`, with the same `<prefix>/merge` key, share one AuthorizationPolicy in `-b` named `merge.{gw}.{key}.{hash8}`, with both routes' hosts and CIDRs; neither gets a policy of its own (watched for 30s) |
| `listener-hostnames` (Istio only) | (the target's own parent Gateway, `*.functional.invalid`) | a route with one hostname inside the listener's and one outside (`*.other.invalid`) gets an AP with only the inside one |
| `allowedroutes-same` | `allowedRoutes: Same` | the Gateway does not accept the route, so **nothing** is written for it, watched for 30s (NEW_IDEAS item 1). For Istio a policy would otherwise still apply to the Gateway by host, i.e. to other tenants' hosts |

Resource kinds covered so far:

| Kind | Controller flag | Where the allowlist is checked |
|---|---|---|
| Ingress | `--ingress-support-enabled` | `nginx.ingress.kubernetes.io/whitelist-source-range` annotation |
| NetworkPolicy | `--networkpolicy-support-enabled` | `spec.ingress[0].from` and `spec.egress[0].to` ipBlocks (must be identical) |
| Service | `--service-support-enabled` | `spec.loadBalancerSourceRanges` of a `type: LoadBalancer` Service |
| Istio Gateway | `--gateway-support-enabled` | `remoteIpBlocks` of the AuthorizationPolicy named after the Gateway |
| AWS ALB / NLB Gateway | `--gateway-support-enabled` | `spec.sourceRanges` of the Gateway's LoadBalancerConfiguration; plus `programmed`: the `inline` Gateway becomes `Programmed` (the AWS controller applied it, up to 10 minutes) |
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

Out of scope for now: `ClusterCIDRs` and `headersFrom`.

## Two instances

Several instances of the controller can run in one cluster, each with its own
`--annotation-prefix`. Each instance only acts on objects annotated under its prefix, and labels
what it creates with it (see [security.md](security.md)). The `other-instance` scenario checks
this from the side of the instance under test, with a made-up other instance whose prefix is
`other.iac-functional.invalid`:

- an object annotated only under the other prefix gets no allowlist;
- for Istio Gateway, Istio HTTPRoute and Traefik HTTPRoute: the AuthorizationPolicy or Middleware
  the controller would create for our object already exists, labelled as the other instance's.
  The controller must not change it, and must not delete it once our object loses its annotation.
  For Traefik, the route also has a filter to that Middleware, as a team may have to its own
  Middleware: the filter must stay.

To check two real instances side by side, run the suite once against each, at the same time. Each
run has its own namespaces, so the runs don't meet, and each controller must leave the other run's
objects alone, as they are annotated under the other prefix.

```bash
# A: the Deployment in the cluster
make functional CONFIRM=<context> IAC_CONTROLLER=ingress-allowlisting/ingress-allowlisting-controller \
  IAC_ANNOTATION_PREFIX=ipam.adevinta.com

# B: a second instance, e.g. run on your laptop with go run and another prefix
make functional CONFIRM=<context> \
  IAC_CONTROLLER_ARGS="--annotation-prefix=b.example.com --gateway-support-enabled --httproute-support-enabled" \
  IAC_ANNOTATION_PREFIX=b.example.com
```

`IAC_ANNOTATION_PREFIX` is optional: it states the prefix you mean to test, and blocks the run if
the controller found runs with another one. While a run is going on, clean up another one with
`make functional-clean IAC_RUN=<id>`: without `IAC_RUN` it deletes the namespaces of every run.

## Restart: the startup cleanup

When the controller starts, it deletes the HTTPRoute policies whose route or merge group is gone
(changes it missed while it was down). `make functional-restart` checks that it deletes only those,
and that the policies still wanted survive **untouched**: same UID, so not deleted and written
again, which would leave a gap in access.

It runs the controller **itself**: built from this tree, on your machine, with
`IAC_CONTROLLER_ARGS`, twice. So no other controller with the same annotation prefix may run
meanwhile: the run is blocked if one runs in the cluster (scale it to 0 first), and you must
stop your own `go run`. Istio and the Gateway API are needed.

```bash
make functional-restart IAC_CONTROLLER_ARGS="--httproute-support-enabled --gateway-support-enabled"   # dry run
make functional-restart CONFIRM=<context> IAC_CONTROLLER_ARGS="--httproute-support-enabled --gateway-support-enabled"
```

| Step | What happens |
|---|---|
| 1. controller up | In `-b`: Gateways `restart-gw-a`, `restart-gw-b` and `restart-gw-c`. In `-a`: Gateway `restart-gw-same`, and routes: merge group `restart-shared` with one route on each of gw-a, gw-b and gw-c (gw-c has no other route), group `restart-two` with two routes on gw-a, a group with a key longer than 63 characters on gw-b, a same-namespace route, one with two rules with paths, and cross-namespace routes. With `--gateway-support-enabled`, also a Gateway with its own allowlist. Plus another instance's policy. Waits for every policy |
| 2. controller down | Deletes the routes of `restart-shared` on gw-a and gw-c, one route of `restart-two` and a cross-namespace route; removes the allowlist annotation of another; puts a route into `restart-two` |
| 3. controller up | Deleted: gw-a's and gw-c's policies of `restart-shared` (the key is still used on gw-b; on gw-c, with no route left, only the startup cleanup can), and the own policies of the deleted, unannotated and joining routes. `restart-two`'s policy gets the hosts of its routes now. Every other policy keeps its UID for 30s, and the other instance's is not changed |

The controller's output goes to a log file in the temp directory, printed and kept when the test
fails.

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

**Except the AWS Gateways: they create real load balancers.** For each AWS ALB / NLB Gateway (about
five per class and run) the AWS Load Balancer Controller provisions a load balancer and a security
group. They are always **internal** (`scheme: internal` in every test `LoadBalancerConfiguration`,
also for the Gateway annotated for another instance only), so nothing is reachable from the
internet, but they cost a little and take minutes. They are deleted with the namespace, by the AWS
controller's finalizers: keep it running until the namespaces are gone, or they stay
`Terminating`. The AWS targets need a GatewayClass of `gateway.k8s.aws/alb` / `gateway.k8s.aws/nlb`
(with the `ALBGatewayAPI` / `NLBGatewayAPI` feature gates of the AWS controller) and the
`LoadBalancerConfiguration` CRD; otherwise they're skipped.

## Settings

| Variable | Meaning |
|---|---|
| `CONFIRM` | Name of the current kube context; required to create anything |
| `IAC_CONTEXT` | Use this kube context instead of the current one |
| `IAC_CONTROLLER` | `namespace/name` of the controller Deployment, when several are found |
| `IAC_CONTROLLER_ARGS` | The controller's arguments, when it runs outside the cluster (e.g. `go run` on your laptop). Replaces Deployment detection |
| `IAC_ANNOTATION_PREFIX` | The annotation prefix the controller must run with; the run is blocked if it doesn't (default: whatever it runs with) |
| `IAC_RUN` | For `make functional-clean`: delete only the namespaces of this run |
| `IAC_ISTIO_GATEWAYCLASS`, `IAC_TRAEFIK_GATEWAYCLASS`, `IAC_AWS_ALB_GATEWAYCLASS`, `IAC_AWS_NLB_GATEWAYCLASS` | GatewayClass to use when several exist for that controller (default: the first by name) |
| `IAC_TIMEOUT` | How long each wait may take (default `3m`) |
| `KEEP` | Any value keeps the test namespaces for inspection; remove it later with `make functional-clean` |
| `IAC_CONTROLLER_ARGS` (restart) | For `make functional-restart`: the arguments the test runs the controller with; must include `--httproute-support-enabled` |

## Adding a resource kind

Add a `target` (`test/functional/targets_test.go`, Gateway API kinds in
`gateway_targets_test.go`): the controller flag that enables it, why the cluster cannot run it
(`unavailable`), optional `setup` (e.g. a parent Gateway), how to create an annotated object, and
how to read the allowlist the controller wrote. All scenarios then
run for it. The pure helpers have their own tests that need no cluster:

```bash
go test -tags functional -run 'Flag|Origin|Expected' ./test/functional/
```
