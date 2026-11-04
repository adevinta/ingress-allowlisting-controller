# NetworkPolicy

**Requires:** a CNI that enforces `networking.k8s.io/v1 NetworkPolicy` (e.g. Calico, AWS VPC CNI, Antrea, Cilium). Flannel does not enforce NetworkPolicy — objects are created but silently ignored.

The controller watches `NetworkPolicy` resources and writes the allowlist as the `ipBlock` peers
of the `ingress` and/or `egress` rule. Enable with `--networkpolicy-support-enabled`.

## Annotations

| Annotation | Scope | Description |
|---|---|---|
| `ipam.adevinta.com/allowlist-group` | namespace | Reference a `CIDRs` object in the same namespace |
| `ipam.adevinta.com/cluster-allowlist-group` | cluster | Reference a `ClusterCIDRs` object |

## What you define vs what the controller manages

You define: `podSelector`, `policyTypes`, and optionally pre-configured `ports`.  
The controller manages: all the peers of the rule, `spec.ingress[0].from` and `spec.egress[0].to`.
On each reconcile they are replaced with one `ipBlock` per CIDR; only the rule's `ports` are kept.
Any other peer you add there (`podSelector`, `namespaceSelector`, another `ipBlock`) is removed.
Keep the annotated NetworkPolicy for the allowlist only, and put other peers in a NetworkPolicy of
their own (see [Several rules](#several-rules-split-them)).

A NetworkPolicy with more than one `ingress` or more than one `egress` rule is not managed: the
controller leaves it as it is and records a `MultipleRulesNotSupported` Warning Event on it. Split
it as shown below. Once it has at most one of each, the next reconcile (any change to it or its
CIDRs) writes the allowlist.

Removing the allowlist annotation leaves the last `ipBlock` entries in place: the controller
stops managing the NetworkPolicy, and they no longer follow CIDRs changes. See [Removing the allowlist annotation](architecture.md#removing-the-allowlist-annotation).

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

## Several rules: split them

NetworkPolicies add up: a connection is allowed if any NetworkPolicy selecting the pod allows it.
Rules inside one NetworkPolicy add up the same way. So several NetworkPolicies with one rule each,
with the same `podSelector` and `policyTypes`, allow exactly what one NetworkPolicy with all those
rules allows. Nothing is lost by splitting.

For example, monitoring on port 9090 and the office IPs on port 443:

```yaml
# Yours, not annotated: the controller doesn't touch it.
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: app-monitoring
  namespace: my-app
spec:
  podSelector:
    matchLabels:
      app: my-app
  policyTypes:
  - Ingress
  ingress:
  - from:
    - namespaceSelector:
        matchLabels:
          kubernetes.io/metadata.name: monitoring
    ports:
    - port: 9090
---
# Annotated, one rule: the controller writes the office IPs into it.
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: app-office
  namespace: my-app
  annotations:
    ipam.adevinta.com/cluster-allowlist-group: office-ips
spec:
  podSelector:
    matchLabels:
      app: my-app
  policyTypes:
  - Ingress
  ingress:
  - ports:
    - port: 443
```

Different allowlists on different ports work the same way: one annotated NetworkPolicy per
allowlist, each with its own `ports`.
