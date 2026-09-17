# Service (loadBalancerSourceRanges)

**Requires:** a `Service` of `type: LoadBalancer` backed by a cloud/load-balancer
implementation that honours `spec.loadBalancerSourceRanges` (e.g. AWS NLB/CLB, GCP,
Azure, MetalLB). The field is silently ignored by implementations that don't support it.

The controller watches `Service` resources and populates `spec.loadBalancerSourceRanges`
with the resolved CIDR set. Enable with `--service-support-enabled`.

Services that are **not** of `type: LoadBalancer` are skipped even if annotated — the
Kubernetes API server rejects `loadBalancerSourceRanges` on any other type.

## Annotations

| Annotation | Scope | Description |
|---|---|---|
| `ipam.adevinta.com/allowlist-group` | namespace | Reference a `CIDRs` object in the same namespace |
| `ipam.adevinta.com/cluster-allowlist-group` | cluster | Reference a `ClusterCIDRs` object |

## What you define vs what the controller manages

You define: the `Service` (`type: LoadBalancer`, `ports`, `selector`, …).
The controller manages: `spec.loadBalancerSourceRanges`. Any existing ranges in that
field are overwritten on each reconcile.

## Example

Allow inbound traffic to a LoadBalancer Service only from a named CIDR set:

```yaml
apiVersion: v1
kind: Service
metadata:
  name: my-app
  namespace: my-app
  annotations:
    ipam.adevinta.com/cluster-allowlist-group: office-ips
spec:
  type: LoadBalancer
  selector:
    app: my-app
  ports:
  - port: 443
    targetPort: 8443
```

The controller populates:

```yaml
spec:
  loadBalancerSourceRanges:
  - 10.0.0.0/8
  - 192.168.0.0/16
```

The annotation value can be a comma-separated list of group names, and both the
namespace-scoped and cluster-scoped annotations can be combined.
