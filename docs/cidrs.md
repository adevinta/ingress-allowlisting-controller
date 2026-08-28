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

## Prefer `ClusterCIDRs` for CIDRs shared across namespaces

If the same IP set is referenced by routes in more than one namespace, use a single `ClusterCIDRs`
object instead of duplicating `CIDRs` objects per namespace.

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
