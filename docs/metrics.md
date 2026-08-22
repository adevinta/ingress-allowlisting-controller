# Metrics

The controller exposes a single Prometheus metric:

```
# HELP namespace_ingress_IpAllowlistingGroup_missing Number of missing IpAllowlistingGroup objects. >0 implies expected objects were not found
# TYPE namespace_ingress_IpAllowlistingGroup_missing gauge
namespace_ingress_IpAllowlistingGroup_missing{cidrs_name="my-cidrs",ingress="my-app",namespace="my-ns"} 0
```

| Value | Meaning |
|---|---|
| `0` | The named CIDRs object was found and resolved successfully |
| `1` | The named CIDRs object was not found or could not be resolved |

## Useful queries

Number of resources with allowlist annotations:
```promql
count(sum(namespace_ingress_IpAllowlistingGroup_missing) by (ingress))
```

Number of resources with resolution errors:
```promql
count(sum(namespace_ingress_IpAllowlistingGroup_missing) by (ingress) > 0)
```

## Metrics endpoint

The metrics server binds to `:8080` by default. Override with `--metrics-addr`.
