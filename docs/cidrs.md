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

## Controller flags

| Flag | Default | Description |
|---|---|---|
| `--annotation-prefix` | `ipam.adevinta.com` | Prefix for all controller annotations. Change this to run two instances of the controller side-by-side without annotation conflicts. |
| `--http-headers-enabled` | `true` | Enable reading Secrets and ConfigMaps as HTTP header sources for remote CIDR fetches (the `headersFrom` field). Disabling this removes Secret/ConfigMap RBAC requirements entirely and skips reactive re-reconciliation when those objects change. |
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
