# Ingress Allowlisting Controller

A Kubernetes controller that manages IP allowlisting for Ingress, Gateway API, and NetworkPolicy resources, driven by custom `CIDRs` / `ClusterCIDRs` CRDs and optional remote CIDR sources.

## Features

| Resource | Output | Requires |
|---|---|---|
| `Ingress` | `nginx.ingress.kubernetes.io/whitelist-source-range` annotation | — |
| `Gateway` | Istio `AuthorizationPolicy` (L4, gateway-scoped) | Istio |
| `HTTPRoute` | Istio `AuthorizationPolicy` (L7, per-route) | Istio |
| `HTTPRoute` | Traefik `Middleware` (IPAllowList, per-route) | Traefik |
| `NetworkPolicy` | `ipBlock` rules in `ingress`/`egress` sections | — |

Istio and Traefik support is **auto-detected** at startup — no flags needed. The controller checks which CRDs are installed and registers only the relevant writers.

## Installation

```bash
git clone https://github.com/adevinta/ingress-allowlisting-controller.git
cd ingress-allowlisting-controller/helm-charts/ingress-allowlisting-controller
helm install ingress-allowlisting-controller ./ --namespace ingress-allowlisting --create-namespace
```

Verify:
```bash
kubectl get pods -n ingress-allowlisting
```

## Documentation

- [Ingress](docs/ingress.md)
- [Gateway API — Gateway & HTTPRoute (Istio + Traefik)](docs/gateway-api.md)
- [NetworkPolicy](docs/networkpolicy.md)
- [CIDRs & ClusterCIDRs CRDs](docs/cidrs.md)
- [Security considerations](docs/security.md)
- [Metrics](docs/metrics.md)

## Quick start

Define your IP ranges as a `ClusterCIDRs` object:

```yaml
apiVersion: ipam.adevinta.com/v1alpha1
kind: ClusterCIDRs
metadata:
  name: office-ips
spec:
  cidrs:
  - 10.0.0.0/8
  - 192.168.0.0/16
```

Then reference it from any supported resource:

```yaml
metadata:
  annotations:
    ipam.adevinta.com/cluster-allowlist-group: office-ips
```

The annotation value can be a comma-separated list: `office-ips,partner-ips,cloudfront`.

See [CIDRs & ClusterCIDRs](docs/cidrs.md) for namespace-scoped CIDRs, remote HTTP sources, and GitHub-hosted lists.
