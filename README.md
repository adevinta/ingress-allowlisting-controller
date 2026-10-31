# Ingress Allowlisting Controller

A Kubernetes controller that manages IP allowlisting for Ingress, Gateway API, and NetworkPolicy resources, driven by custom `CIDRs` / `ClusterCIDRs` CRDs and optional remote CIDR sources.

## Features

| Source | Destination | Requires |
|---|---|---|
| `kind: Ingress` | `metadata.annotation:`<br>`nginx.ingress.kubernetes.io/whitelist-source-range` | nginx Ingress Controller |
| `kind: Gateway` | `kind: AuthorizationPolicy` (L4, gateway-scoped) | Gateway API + Istio |
| `kind: HTTPRoute` | `kind: AuthorizationPolicy` (L7, per-route) | Gateway API + Istio |
| `kind: HTTPRoute` | `kind: Middleware` (IPAllowList, per-route) | Gateway API + Traefik |
| `kind: NetworkPolicy` | `spec.ingress[].from[].ipBlock`<br>AND/OR<br>`spec.egress[].to[].ipBlock` | CNI with NetworkPolicy support (e.g. Calico, AWS VPC CNI) |
| `kind: Service` | `spec.loadBalancerSourceRanges` | `type: LoadBalancer` + a load balancer that honours source ranges |

Istio and Traefik support is **auto-detected** at startup — no flags needed. The controller checks which CRDs are installed and registers only the relevant writers.

## Installation

```bash
git clone --branch v0.1.6 https://github.com/adevinta/ingress-allowlisting-controller.git
cd ingress-allowlisting-controller/helm-chart/ingress-allowlisting-controller
helm install ingress-allowlisting-controller ./ --namespace ingress-allowlisting --create-namespace \
  --set image.fullyQualifiedURL=ghcr.io/adevinta/ingress-allowlisting-controller:0.1.6
```

Use the latest [release](https://github.com/adevinta/ingress-allowlisting-controller/releases)
instead of `v0.1.6`; see [Releases and versions](docs/releases.md), also for Argo CD.

Verify:
```bash
kubectl get pods -n ingress-allowlisting
```

By default the controller runs as a single replica. For more, enable leader election: only the
leader reconciles, the others take over within seconds. The chart then adds a Role for the lease
in the release namespace and a PodDisruptionBudget, and refuses several replicas without it.

```bash
helm upgrade --install ingress-allowlisting-controller ./ --namespace ingress-allowlisting \
  --set replicaCount=2 --set leaderElection.enabled=true
```

## Documentation

- [Ingress](docs/ingress.md)
- [Gateway API — Gateway & HTTPRoute (Istio + Traefik)](docs/gateway-api.md)
- [NetworkPolicy](docs/networkpolicy.md)
- [Service (loadBalancerSourceRanges)](docs/service.md)
- [CIDRs & ClusterCIDRs CRDs](docs/cidrs.md)
- [Security considerations](docs/security.md)
- [Architecture & support matrix](docs/architecture.md)
- [Metrics](docs/metrics.md)
- [Functional tests (real cluster, local only)](docs/functional-tests.md)
- [Releases and versions](docs/releases.md)

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
