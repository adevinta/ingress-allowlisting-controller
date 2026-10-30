# Service (loadBalancerSourceRanges)

**Requires:** a `Service` of `type: LoadBalancer` backed by a cloud/load-balancer
implementation that honours `spec.loadBalancerSourceRanges` (e.g. AWS NLB/CLB, GCP,
Azure, MetalLB). The field is silently ignored by implementations that don't support it.

The controller watches `Service` resources and populates `spec.loadBalancerSourceRanges`
with the resolved CIDR set. Enable with `--service-support-enabled`.

Services that are **not** of `type: LoadBalancer` are skipped even if annotated — the
Kubernetes API server rejects `loadBalancerSourceRanges` on any other type.

Services **generated for a Gateway API Gateway** are skipped too (see below), so
`--service-support-enabled` and `--gateway-support-enabled` can be used together.

## Services generated for a Gateway

A Gateway implementation creates a Service for each Gateway, and Istio copies the Gateway's
annotations onto it, including the allowlist annotation. The controller leaves such a Service alone:
it has an `ownerReference` to a `gateway.networking.k8s.io` Gateway, or the label
`gateway.networking.k8s.io/gateway-name`.

The Service belongs to the Gateway, and so does its allowlist: the Gateway's and its HTTPRoutes'
AuthorizationPolicies, which add up (Istio ORs ALLOW policies). `loadBalancerSourceRanges` would
instead apply first, at the load balancer, and drop every CIDR an HTTPRoute allows beyond the
Gateway's, so the route allowlists would silently stop working. Restrict a Gateway with its own
annotations, see [Gateway API](gateway-api.md).

Ranges written onto such a Service by an earlier version, or by hand, are left in place. To check
and clear them:

```bash
kubectl get svc -A -l gateway.networking.k8s.io/gateway-name \
  -o custom-columns=NS:.metadata.namespace,NAME:.metadata.name,RANGES:.spec.loadBalancerSourceRanges
kubectl patch svc <name> -n <ns> --type=merge -p '{"spec":{"loadBalancerSourceRanges":null}}'
```

## Annotations

| Annotation | Scope | Description |
|---|---|---|
| `ipam.adevinta.com/allowlist-group` | namespace | Reference a `CIDRs` object in the same namespace |
| `ipam.adevinta.com/cluster-allowlist-group` | cluster | Reference a `ClusterCIDRs` object |

## What you define vs what the controller manages

You define: the `Service` (`type: LoadBalancer`, `ports`, `selector`, …).
The controller manages: `spec.loadBalancerSourceRanges`. Any existing ranges in that
field are overwritten on each reconcile.

Removing the allowlist annotation leaves the last `loadBalancerSourceRanges` in place: the
controller stops managing the Service, and the ranges no longer follow CIDRs changes. Clear them
yourself if you want the load balancer open again. See [Removing the allowlist annotation](architecture.md#removing-the-allowlist-annotation).

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
