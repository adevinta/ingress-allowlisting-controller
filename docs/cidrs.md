# CIDRs & ClusterCIDRs

CIDR objects are the data source that the controller resolves when it reads an allowlist
annotation. Two kinds exist:

| Kind | API group | Scope | Referenced by annotation |
|---|---|---|---|
| `CIDRs` | `ipam.adevinta.com/v1alpha1` | namespace | `ipam.adevinta.com/allowlist-group` |
| `ClusterCIDRs` | `ipam.adevinta.com/v1alpha1` | cluster | `ipam.adevinta.com/cluster-allowlist-group` |

## Static CIDRs

```yaml
apiVersion: ipam.adevinta.com/v1alpha1
kind: CIDRs
metadata:
  name: team-ips
  namespace: my-app
spec:
  cidrs:
  - 1.2.3.4/32
  - 5.6.7.8/32
```

```yaml
apiVersion: ipam.adevinta.com/v1alpha1
kind: ClusterCIDRs
metadata:
  name: cloudfront
spec:
  cidrs:
  - 120.52.22.96/27
  - 205.251.249.0/24
  - 180.163.57.128/26
```

The annotation value can be a comma-separated list of object names:
`ipam.adevinta.com/cluster-allowlist-group: office-ips,cloudfront,partner-cidrs`

## Remote sources

CIDR objects can fetch their IP list from a remote HTTP endpoint and refresh it periodically.

```yaml
apiVersion: ipam.adevinta.com/v1alpha1
kind: CIDRs
metadata:
  name: aws-ec2
  namespace: my-app
spec:
  requeueAfter: 30m
  location:
    uri: https://ip-ranges.amazonaws.com/ip-ranges.json
    cel: 'data.prefixes.filter(p, p.service == "EC2" && has(p.ip_prefix)).map(p, p.ip_prefix)'
    headersFrom:
      secretRef:
        name: aws-auth-headers
        namespace: my-app
      configMapRef:
        name: aws-extra-headers
        namespace: my-app
```

- `uri` — the remote URL to fetch
- `cel` — a [CEL](https://github.com/google/cel-spec) expression that transforms the HTTP
  response body into a `[]string` of CIDRs
- `requeueAfter` — how often to re-fetch (e.g. `30m`, `1h`)
- `headersFrom.secretRef` — all keys in the Secret are sent as HTTP request headers
- `headersFrom.configMapRef` — all keys in the ConfigMap are sent as HTTP request headers

### Fetching from GitHub

```yaml
spec:
  requeueAfter: 30m
  location:
    uri: https://api.github.com/repos/my-org/my-repo/contents/path/to/cidrs.json
```

The GitHub Contents API returns a JSON object; use a CEL expression to decode and extract the
list if needed.

### Breadth limit on remote sources

Every prefix from a remote fetch must be **no wider than a minimum mask**, per address family.
If any entry is wider, the fetch is **rejected wholesale** — the object keeps its previous
(last-known-good) status and the breach is logged.

| Family | Default minimum mask | Rejects anything wider than |
|---|---|---|
| IPv4 | `/8` | ~16.7 million addresses |
| IPv6 | `/20` | — |

This is a **guardrail against human mistakes, not an attacker defence.** We trust the sources we
fetch from (AWS, Akamai, …); a well-tailored single IP from a trusted feed is allowed by design,
and there is no defending against a source you have chosen to trust. What it catches is the far
more likely accident:

- a source that changes format or breaks and dumps the whole address space,
- a CEL/JSONPath expression that misfires and selects everything instead of a filtered subset,
- a feed that is simply misconfigured to return `0.0.0.0/0` (or a broad `/1`, `/3`, …).

In those cases the allowlist would silently widen to "the entire internet" and the firewall
would effectively be off. The check turns that failure into a rejected fetch that preserves the
last good allowlist instead.

Key properties:

- **Per-entry mask check.** Each prefix is compared against the minimum mask; nothing is summed.
  This catches every single-block blunder — including the `/1`/`/3` "split" blocks, whose masks
  are themselves too wide — but it does **not** add up coverage, so an aggregate built from many
  individually-narrow blocks is not caught. That is an accepted trade-off for a fast, simple,
  allocation-light check on the reconcile path.
- **Remote sources only.** The check applies exclusively to CIDRs fetched via `location.uri`.
  Inline `spec.cidrs` authored by a cluster admin is trusted and never limited — an admin may
  deliberately allow `0.0.0.0/0` there.
- **Calibrated against real feeds.** The widest prefix observed is `/11` for IPv4 (both AWS
  `ip-ranges.json` and Akamai) and `/24` for IPv6 (Akamai; AWS tops out at `/32`). The `/8` and
  `/20` defaults clear those with headroom while still rejecting internet-scale blocks.

### Resource limits on remote sources

The fetch and the processing of its result run inside the controller's single reconcile worker,
so one source that is slow, huge, or paired with an expensive expression would otherwise stall
**every** allowlist update in the cluster (and a large enough body would get the pod OOM-killed).
Three limits turn those cases into an ordinary failed fetch: the object keeps its last-known-good
status and the reason is reported in its `UpToDate` condition.

| Limit | Default | What it bounds |
|---|---|---|
| Fetch timeout | 30 s | The whole fetch: connecting, response headers, reading the body and processing it |
| Response size | 5 MiB | Bytes read from the response body |
| CEL cost | 1,000,000 | Estimated cost (roughly: operations) of one CEL evaluation |

Like the breadth guard, these are **guardrails against broken or misbehaving feeds, not a defence
against a hostile endpoint**. Pointing `location.uri` at a server you do not trust is still a
trust decision; see [Security considerations](security.md).

Key properties:

- **An oversized body is an error, never a truncation.** A truncated CSV or list would silently
  drop CIDRs from the allowlist, so a body larger than the cap fails the whole fetch.
- **Calibrated against real feeds.** AWS `ip-ranges.json` is about 2.7 MB, so the 5 MiB cap leaves
  roughly 2x headroom; Google's and GitHub's feeds are 0.1–0.2 MB. The documented AWS
  expression (`data.prefixes.filter(...).map(...)`) over ~10,000 prefixes costs about 130,000,
  so the cost limit leaves roughly 7x headroom. A nested comprehension over the same feed is
  aborted in well under a second instead of running for minutes.
- **The cost limit measures CPU, not memory.** Memory is bounded by the response size cap, which
  limits the data an expression can work on.
- **Memory needed is roughly 25–30x the body size.** Decoding and CEL processing peak at about
  50 MiB for the AWS feed and about 200 MiB for a 5 MiB body. The chart's 256Mi limit fits the
  default cap; if you raise `maxResponseBytes`, raise `resources.limits.memory` with it. The chart
  sets `GOMEMLIMIT` from the container limit so the GC works harder before the pod is OOM-killed.
- **Configurable, and validated at startup.** See [Configuring the guardrails](#configuring-the-guardrails).

### Retrying a failed fetch

When a fetch fails (network error, non-200 status, a tripped guardrail or access control), or
returns nothing usable so the update is refused as removing all CIDRs, the
object keeps its last-known-good status and is retried after **5 minutes**
(`--cidr-source-retry-interval`, Helm: `cidrSource.retryInterval`). If the object's
`spec.requeueAfter` is shorter, that interval is used instead. Once a fetch succeeds again, the
object goes back to its normal `requeueAfter` schedule (or, without one, to being reconciled only
on changes).

Without this, a failed fetch would only be retried on the next change to the object or the
periodic resync, which can be hours away, leaving the allowlist stale long after a short outage
of the feed. The fixed interval keeps the load on a broken feed to one request per object per
interval.

### Restricting where sources can be fetched from

`location.uri` is supplied by whoever creates the `CIDRs` object, but the request is made from the
controller pod, which can reach things that user cannot: cluster-internal services, the node's
cloud metadata endpoint, the kubelet. Two independent controls narrow where a fetch may go.

**1. Destination guard — on by default.** A connection is refused if the address it resolves to is
not a public one: loopback, private (RFC 1918 and IPv6 unique-local), link-local (which includes
the cloud metadata address `169.254.169.254`), carrier-grade NAT, multicast, reserved ranges, and
the IPv6 forms that embed such an IPv4 address (v4-mapped, NAT64, 6to4). The check runs on the
address actually being dialled, *after* name resolution, so a hostname that resolves to an
internal address, a DNS change between check and connect, and a redirect to an internal address
are all covered. Feeds that really are internal need `--cidr-source-allow-private-destinations`,
which is logged as a warning at startup.

**2. Origin allowlist — optional.** With `--cidr-source-allowlist`, only the listed origins may be
fetched. When the list is empty, any host is allowed and the controller logs a warning at startup.

```
--cidr-source-allowlist=https://ip-ranges.amazonaws.com
--cidr-source-allowlist=http://ip-ranges.amazonaws.com
--cidr-source-allowlist=api.github.com,https://feeds.example.org:8443
```

```yaml
# Helm
cidrSource:
  allowlist:
    - https://ip-ranges.amazonaws.com
    - api.github.com
```

How entries are matched:

- **An entry is `scheme://host[:port]`.** A bare `host[:port]` means `https`. The scheme is part of
  the entry, so allowing both `https` and `http` for a host takes two entries. The port defaults
  to 443 for `https` and 80 for `http`.
- **Exact match on the parsed host.** The URL is parsed and its host compared; nothing is matched
  as a string prefix. `https://ip-ranges.amazonaws.com.evil.com/`, `https://evil.com/?u=…`, and
  `https://ip-ranges.amazonaws.com@evil.com/` are all refused for an entry of
  `https://ip-ranges.amazonaws.com`.
- **No wildcards, patterns or path matching.** Every host is listed explicitly, a subdomain is a
  different host, and entries with a path, query, fragment or credentials are rejected at startup.
  Host names are compared case-insensitively, and a trailing dot is ignored.
- **Every redirect hop is checked** against the list, and a chain is stopped after 10 redirects.
- **A refused source is never contacted,** and its `headersFrom` Secrets are not read.

Notes:

- The failure is handled like the other guardrails: the object keeps its last-known-good status,
  the reason appears in its `UpToDate` condition, and the controller logs
  `…; rejecting external CIDR source: access refused…` with the `guard` field set to
  `cidr-source-allowlist` or `private-destinations`.
- **Proxies.** `HTTP_PROXY`/`HTTPS_PROXY` are still honoured. With a proxy, the destination guard
  applies to the connection to the proxy, so a proxy on a private address needs
  `--cidr-source-allow-private-destinations`; the allowlist is still checked against the request
  URL either way.
- **Custom headers on redirects.** Go drops `Authorization` and `Cookie` when a redirect leaves the
  host but forwards other headers. Values from `headersFrom` can therefore follow a redirect to
  another host. Setting an allowlist limits where that can happen.

### Configuring the guardrails

The breadth guard, the three resource limits and the retry interval are set with the `--cidr-source-*` flags listed
under [Controller flags](#controller-flags), or in the Helm chart under `cidrSource`:

```yaml
cidrSource:
  minMaskIPv4: 8
  minMaskIPv6: 20
  fetchTimeout: 30s
  maxResponseBytes: 5242880      # raise resources.limits.memory with it (~25-30x)
  celCostLimit: 1000000
  retryInterval: 5m
  allowlist: []                  # see "Restricting where sources can be fetched from"
  allowPrivateDestinations: false
```

Every key is optional; an unset key keeps the default. Things to know:

- **They apply only to remote sources.** Inline `spec.cidrs` is never checked, and they do not
  affect how Ingress, Service, NetworkPolicy or Gateway objects consume the result.
- **Invalid values stop the controller at startup.** A mask outside 1–32 (IPv4) or 1–128 (IPv6),
  a zero/negative timeout, size, cost limit or retry interval, or an allowlist entry that is not `scheme://host[:port]`
  (a wildcard, a path, credentials, another scheme) is rejected with a message naming the problem.
  Zero is *not* a way to switch a protection off, and it is not silently replaced by the default.
- **The effective values are logged at startup** as one `remote CIDR source guardrails` line with a field per setting (`minMaskIPv4`, `fetchTimeout`, `allowlist`, …).
- **A tripped limit is logged.** When the timeout, size cap or CEL cost limit rejects a fetch, the
  controller logs `…; rejecting external CIDR source: limit exceeded, keeping last-known-good
  allowlist` (preceded by the underlying error) with the fields `cidrs`, `namespace`, `uri`, `limit` (`fetch-timeout`,
  `max-response-bytes` or `cel-cost-limit`) and `configured` (the value that was exceeded). The
  reason is also written to the object's `UpToDate` condition.
- **Debug logging shows each fetch.** At `debug` level the controller logs one
  `fetched external CIDR source` line per successful fetch (`bytes`, `entries`, `elapsed`, plus
  the object's `cidrs`, `namespace` and `uri`) and one `external CIDR source redirected` line for
  every redirect hop (`from`, `to`). Nothing is logged at `info` for a healthy fetch.
- **Loosening them is a trade-off.** A smaller minimum mask accepts wider blocks, and larger size,
  time or cost limits let a broken feed consume more of the single reconcile worker before it is
  stopped. Raise them only for a feed you have measured.
- **They are global.** One set of values applies to all `CIDRs` and `ClusterCIDRs` objects; there
  is no per-object override.

## Controller flags

| Flag | Default | Description |
|---|---|---|
| `--annotation-prefix` | `ipam.adevinta.com` | Prefix for all controller annotations. Change this to run two instances of the controller side-by-side without annotation conflicts. |
| `--http-headers-enabled` | `true` | Enable reading Secrets and ConfigMaps as HTTP header sources for remote CIDR fetches (the `headersFrom` field). Disabling this removes Secret/ConfigMap RBAC requirements entirely and skips reactive re-reconciliation when those objects change. |
| `--cidr-source-min-mask-ipv4` | `8` | Widest IPv4 prefix accepted from a remote CIDR source (range 1–32). See [Breadth limit](#breadth-limit-on-remote-sources). |
| `--cidr-source-min-mask-ipv6` | `20` | Widest IPv6 prefix accepted from a remote CIDR source (range 1–128). |
| `--cidr-source-fetch-timeout` | `30s` | Maximum time for fetching and processing one remote source: connect, response headers, body and processing. See [Resource limits](#resource-limits-on-remote-sources). |
| `--cidr-source-max-response-bytes` | `5242880` | Maximum size of a remote source response body (5 MiB). A larger body fails the fetch; it is never truncated. Needs about 25–30x this in pod memory. |
| `--cidr-source-cel-cost-limit` | `1000000` | Maximum estimated cost of one CEL expression evaluated on a remote source. |
| `--cidr-source-retry-interval` | `5m` | How soon a failed remote fetch is retried. An object with a shorter `spec.requeueAfter` is retried at that interval instead. See [Retrying a failed fetch](#retrying-a-failed-fetch). |
| `--cidr-source-allowlist` | *(empty: any host)* | Origin a remote CIDR source may be fetched from, as `scheme://host[:port]`; a bare `host[:port]` means https. Repeat the flag or comma-separate to allow several. See [Restricting where sources can be fetched from](#restricting-where-sources-can-be-fetched-from). |
| `--cidr-source-allow-private-destinations` | `false` | Allow remote sources to connect to loopback, link-local (cloud metadata), private and other non-public addresses. By default such connections are refused. |
| `--secret-label-selector` | `""` | Label selector that restricts which Secrets and ConfigMaps are cached by the informer (e.g. `ipam.adevinta.com/cidr-header-source=true`). Only effective when `--http-headers-enabled=true`. Reduces memory usage on clusters with many Secrets. |

---

## Resolved CIDR behaviour

- The controller resolves all named objects, merges their `spec.cidrs` lists, deduplicates,
  and sorts the result before writing to any output resource.
- Invalid CIDR strings (e.g. `10.0.0` without a mask) are logged as warnings and skipped.
- If none of the named objects exist, the controller logs a warning and writes a deny-all
  policy (empty source range) to fail safe.

---

## Prefer `ClusterCIDRs` for CIDRs shared across namespaces if possible

If the same IP set is referenced by routes in more than one namespace, use a single `ClusterCIDRs`
object instead of duplicating `CIDRs` objects per namespace. This depends on your tenancy model:
`ClusterCIDRs` is cluster-scoped and requires a `ClusterRole` with write access, so teams that only
hold namespace-level RBAC cannot create them and must use per-namespace `CIDRs` objects instead.

The controller caches CIDR resolutions within a single reconcile. When all routes in a merge group
share the same `cluster-allowlist-group` value, the cluster object is fetched **once** regardless
of how many namespaces are involved. Namespace-scoped `CIDRs` objects with the same content but
different namespaces each require an independent lookup and do not benefit from this cache.

**Instead of this:**

```yaml
apiVersion: ipam.adevinta.com/v1alpha1
kind: CIDRs
metadata:
  name: vpn
  namespace: ns-team-a
spec:
  cidrs: ["10.0.0.0/8"]
---
apiVersion: ipam.adevinta.com/v1alpha1
kind: CIDRs
metadata:
  name: vpn
  namespace: ns-team-b
spec:
  cidrs: ["10.0.0.0/8"]
```

**Prefer this:**

```yaml
apiVersion: ipam.adevinta.com/v1alpha1
kind: ClusterCIDRs
metadata:
  name: vpn
spec:
  cidrs: ["10.0.0.0/8"]
```

And reference it with `ipam.adevinta.com/cluster-allowlist-group: vpn` on all HTTPRoutes.
