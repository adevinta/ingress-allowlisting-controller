# NetworkPolicy

**Requires:** a CNI that enforces `networking.k8s.io/v1 NetworkPolicy` (e.g. Calico, AWS VPC CNI, Antrea, Cilium). Flannel does not enforce NetworkPolicy — objects are created but silently ignored.

The controller watches `NetworkPolicy` resources and populates the `ipBlock` rules in the
`ingress` and/or `egress` sections. Enable with `--networkpolicy-support-enabled`.

## Annotations

| Annotation | Scope | Description |
|---|---|---|
| `ipam.adevinta.com/allowlist-group` | namespace | Reference a `CIDRs` object in the same namespace |
| `ipam.adevinta.com/cluster-allowlist-group` | cluster | Reference a `ClusterCIDRs` object |

## What you define vs what the controller manages

You define: `podSelector`, `policyTypes`, and optionally pre-configured `ports`.  
The controller manages: `ipBlock` entries in `spec.ingress[].from` and `spec.egress[].to`.
Any existing `ipBlock` rules in those sections are overwritten on each reconcile.

## Examples

**Ingress policy** — allow inbound traffic from a named CIDR set:

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-office-ingress
  namespace: my-app
  annotations:
    ipam.adevinta.com/cluster-allowlist-group: office-ips
spec:
  podSelector: {}   # applies to all pods in the namespace
  policyTypes:
  - Ingress
```

**Egress policy** — allow outbound traffic on specific ports:

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-https-egress
  namespace: my-app
  annotations:
    ipam.adevinta.com/cluster-allowlist-group: external-apis
spec:
  podSelector: {}
  policyTypes:
  - Egress
  egress:
  - ports:
    - port: 443
    - port: 80
```

The controller populates:

```yaml
spec:
  egress:
  - ports:
    - port: 443
    - port: 80
    to:
    - ipBlock:
        cidr: 10.0.0.0/8
    - ipBlock:
        cidr: 192.168.0.0/16
```

**Dual policy** — both `Ingress` and `Egress` in `policyTypes`: the controller populates
both `spec.ingress[0].from` and `spec.egress[0].to` with the same `ipBlock` set.
