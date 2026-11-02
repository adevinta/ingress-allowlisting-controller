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

## `namespace_ingress_IpAllowlistingGroup_missing` (deprecated)

**Deprecated, removed in v0.3.0.** Use `ingress_allowlisting_controller_missing_cidrs` instead.

The old metric has one series per allowlisted resource **and per group** (label `cidrs_name`, and
the kind in `object`): `1` if the group is missing, empty or could not be resolved, `0` if found.
It records at most 10 groups per resource, missing ones first, so an annotation listing many
names can't create many series.

Moving queries over:

| Old | New |
|---|---|
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
