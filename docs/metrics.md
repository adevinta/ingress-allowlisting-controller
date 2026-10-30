# Metrics

The controller exposes a single Prometheus metric:

```
# HELP namespace_ingress_IpAllowlistingGroup_missing Number of missing IpAllowlistingGroup objects. >0 implies expected objects were not found
# TYPE namespace_ingress_IpAllowlistingGroup_missing gauge
namespace_ingress_IpAllowlistingGroup_missing{cidrs_name="my-cidrs",name="my-app",namespace="my-ns",object="Ingress"} 0
```

There is one series per allowlisted resource and per group in its annotation:

| Label | Value |
|---|---|
| `namespace`, `name` | the allowlisted resource |
| `object` | its kind: `Ingress`, `Service`, `NetworkPolicy`, `Gateway` or `HTTPRoute` |
| `cidrs_name` | a `CIDRs`/`ClusterCIDRs` group named in its annotation |

| Value | Meaning |
|---|---|
| `0` | The named CIDRs object was found and resolved successfully |
| `1` | The named CIDRs object was not found or could not be resolved |

The series follow the resources: removing a group from the annotation, removing the annotation,
or deleting the resource removes the matching series.

## Useful queries

Number of resources with allowlist annotations:
```promql
count(sum(namespace_ingress_IpAllowlistingGroup_missing) by (namespace, object, name))
```

Number of resources with resolution errors:
```promql
count(sum(namespace_ingress_IpAllowlistingGroup_missing) by (namespace, object, name) > 0)
```

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
