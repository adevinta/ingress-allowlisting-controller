# Metrics

## `ingress_allowlisting_controller_missing_cidrs`

```
# HELP ingress_allowlisting_controller_missing_cidrs Number of CIDRs/ClusterCIDRs groups named in the object's allowlist annotations that are missing or have no CIDRs. The object's AllowlistGroupNotFound Events name them.
# TYPE ingress_allowlisting_controller_missing_cidrs gauge
ingress_allowlisting_controller_missing_cidrs{kind="Ingress",name="my-app",namespace="my-ns"} 0
```

One series per allowlisted resource (it has an allowlist annotation):

| Label | Value |
|---|---|
| `namespace`, `name` | the allowlisted resource |
| `kind` | its kind: `Ingress`, `Service`, `NetworkPolicy`, `Gateway` or `HTTPRoute` |

The value is how many of the groups named in its annotations are missing, have no CIDRs, or
could not be resolved; a group named twice counts once. Which ones the metric doesn't say: the
group names come from annotations, and label values must not come from user input (each name
would be one more series). The resource's Events name them:

```bash
kubectl get events -n my-ns --field-selector reason=AllowlistGroupNotFound
```

The series follow the resources: removing the annotation or deleting the resource removes it.

### Useful queries

Number of resources with allowlist annotations:
```promql
count(ingress_allowlisting_controller_missing_cidrs)
```

Resources with a missing group (an alert):
```promql
ingress_allowlisting_controller_missing_cidrs > 0
```

## `ingress_allowlisting_controller_cidr_source_pending_cidrs`

```
# HELP ingress_allowlisting_controller_cidr_source_pending_cidrs Number of CIDRs the remote source of a CIDRs/ClusterCIDRs object added that wait for --cidr-source-apply-delay. status.pending lists them.
# TYPE ingress_allowlisting_controller_cidr_source_pending_cidrs gauge
ingress_allowlisting_controller_cidr_source_pending_cidrs{kind="ClusterCIDRs",name="aws",namespace=""} 0
```

One series per `CIDRs` or `ClusterCIDRs` object with a remote source (`kind`, `namespace`,
`name`; `namespace` is empty for a `ClusterCIDRs`). The value is how many CIDRs the source added
that wait for `--cidr-source-apply-delay`; it is always `0` while the delay is off. Which ones is in
the object's `status.pending`. See
[CIDRs — Delaying new CIDRs from a source](cidrs.md#delaying-new-cidrs-from-a-source).

Removing the source or deleting the object removes the series.

### Useful queries

Objects whose source added CIDRs that wait (an alert, to review them before they are used):
```promql
ingress_allowlisting_controller_cidr_source_pending_cidrs > 0
```

## `namespace_ingress_IpAllowlistingGroup_missing` (removed in v0.3.0)

**Removed in v0.3.0**, deprecated since v0.2. Use `ingress_allowlisting_controller_missing_cidrs`
instead. The old metric had one series per allowlisted resource **and per group** (label
`cidrs_name`, and the kind in `object`): `1` if the group was missing, empty or could not be
resolved, `0` if found. Its group names came from annotation values, so it was capped at 10 groups
per resource; the new metric counts them all in one series per resource, and the
`AllowlistGroupNotFound` Events name the missing ones.

Moving queries over (dashboards, alerts):

| Old | New |
|---|---|
| `count(namespace_ingress_IpAllowlistingGroup_missing)` (group references) | `count(ingress_allowlisting_controller_missing_cidrs)` (resources) |
| `namespace_ingress_IpAllowlistingGroup_missing > 0` (missing groups) | `ingress_allowlisting_controller_missing_cidrs > 0` (resources with missing groups, the value is how many) |
| `sum(namespace_ingress_IpAllowlistingGroup_missing)` | `sum(ingress_allowlisting_controller_missing_cidrs)` |
| `count(sum(namespace_ingress_IpAllowlistingGroup_missing) by (namespace, object, name))` | `count(ingress_allowlisting_controller_missing_cidrs)` |
| `count(sum(namespace_ingress_IpAllowlistingGroup_missing) by (namespace, object, name) > 0)` | `count(ingress_allowlisting_controller_missing_cidrs > 0)` |

## Metrics endpoint

The metrics server binds to `:8080` by default. Override with `--metrics-addr`. It serves plain
HTTP without authentication, so anything that can reach the pod can read the metrics, including
namespace, resource and group names.

Limit who can reach it with a NetworkPolicy. Platform-managed namespaces often have one already
(check `kubectl get networkpolicy -n <namespace>`). Otherwise the chart can add one for the
controller pod, ingress only: the probe port (8081) stays open, and only `metricsFrom` can reach
the metrics port. With an empty `metricsFrom`, nobody can scrape it.

```yaml
podNetworkPolicy:
  enabled: true
  metricsFrom:
  - namespaceSelector:
      matchLabels:
        kubernetes.io/metadata.name: monitoring   # where Prometheus runs
```
