# Ingress

> **⚠ Legacy — ingress-nginx is retiring**
>
> The Kubernetes project has [announced the retirement of ingress-nginx](https://www.kubernetes.dev/blog/2025/11/12/ingress-nginx-retirement/).
> Ingress support in this controller is considered **legacy** and will receive only critical fixes.
> **We strongly recommend migrating to the [Gateway API](gateway-api.md).**

**Requires:** [nginx Ingress Controller](https://kubernetes.github.io/ingress-nginx/)

The controller watches `Ingress` resources and maintains the
`nginx.ingress.kubernetes.io/whitelist-source-range` annotation with the resolved CIDR list.

## Annotations

| Annotation | Scope | Description |
|---|---|---|
| `ipam.adevinta.com/allowlist-group` | namespace | Reference a `CIDRs` object in the same namespace |
| `ipam.adevinta.com/cluster-allowlist-group` | cluster | Reference a `ClusterCIDRs` object |

Both annotations accept a comma-separated list of object names.

## Example

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: my-app
  namespace: my-app
  annotations:
    ipam.adevinta.com/cluster-allowlist-group: office-ips,cloudfront
spec:
  rules:
  - host: app.example.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: my-app
            port:
              number: 80
```

The controller sets:

```yaml
annotations:
  nginx.ingress.kubernetes.io/whitelist-source-range: "10.0.0.0/8,192.168.0.0/16"
```

The CIDR list is always sorted and deduplicated. Removing the allowlist annotation removes
the whitelist annotation.

## Controller flags

| Flag | Default | Description |
|---|---|---|
| `--ingress-support-enabled` | `true` | Enable or disable Ingress support. Unlike other reconcilers, Ingress is on by default and must be explicitly disabled if not needed. |
