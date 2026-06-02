# Ingress Allowlisting Controller
The Ingress Allowlisting Controller is a Kubernetes controller designed to manage allowlisting rules for Kubernetes Ingress resources. It ensures that only trusted IPs or ranges can access specific ingress endpoints, enhancing security and compliance.
This k8s controller configures ingress allowlisting based on a custom CRD

## Installation 

### Helm Installation (Using Local Chart)
To install the ingress-allowlisting-controller using the Helm chart provided in the repository, follow these steps:

1. Clone the Repository
Clone the repository to your local machine:
```bash
git clone https://github.com/adevinta/ingress-allowlisting-controller.git
cd ingress-allowlisting-controller/helm-charts/ingress-allowlisting-controller
```
2. Install the Chart
Install the controller using the local Helm chart. Customize the installation by specifying the namespace and configuration if needed:

```bash
helm install ingress-allowlisting-controller ./ --namespace ingress-allowlisting --create-namespace
```
3. Verify the Installation
Ensure the controller is running in your cluster:

```bash
kubectl get pods -n ingress-allowlisting
```
You should see a pod named ingress-allowlisting-controller running.

## Usage

Once installed, the ingress-allowlisting-controller will monitor and apply allowlisting rules to Kubernetes Ingress resources.

### Example Ingress Resource
Below are examples of an Ingress resource with allowlisting annotations, using both the namespace level CIDR CRD as well
as the cluster level CRD

Namespaced version of CIDRs object
```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  annotations:
    ipam.adevinta.com/allowlist-group: MyCidrsObject
```

Cluster version of the CIDRs object

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  annotations:
    ipam.adevinta.com/cluster-allowlist-group: MyCidrsObject
```

The content of the annotations can be a comma-separated list: 

`MyCidrsObject,MyCidrsObject2,MyCidrsObject3`

### Example Gateway Resource

The controller can watch `Gateway` resources and create an `AuthorizationPolicy` in the same namespace targeting the gateway itself.

Enable the feature via Helm:
```yaml
gateway:
  enabled: true
```

Or directly with the flag: `--gateway-support-enabled`.

Required annotations:
- `ipam.adevinta.com/allowlist-group` and/or `ipam.adevinta.com/cluster-allowlist-group` - same as for Ingress

```yaml
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata:
  name: my-gateway
  namespace: my-app
  annotations:
    ipam.adevinta.com/cluster-allowlist-group: office-ips
```

The controller generates in `my-app`:

```yaml
apiVersion: security.istio.io/v1
kind: AuthorizationPolicy
metadata:
  name: my-gateway      # same as the Gateway name
  namespace: my-app
spec:
  action: ALLOW
  rules:
  - from:
    - source:
        remoteIpBlocks:
        - 10.0.0.0/8
        - 192.168.0.0/16
  targetRef:
    group: gateway.networking.k8s.io
    kind: Gateway
    name: my-gateway
```

The `AuthorizationPolicy` is created in the same namespace as the `Gateway` and uses `targetRef` (singular) pointing directly at the gateway - no cross-namespace support, no hostnames, no merge mode. The AP is owned by the `Gateway` resource and garbage-collected automatically when the `Gateway` is deleted.

### Example HTTPRoute Resource

The controller can also watch `HTTPRoute` resources and create an `AuthorizationPolicy` targeting the associated Istio Gateway.

Enable the feature via Helm:
```yaml
httproute:
  enabled: true
```

Or directly with the flag: `--httproute-support-enabled`.

Required annotations:
- `ipam.adevinta.com/allowlist-group` and/or `ipam.adevinta.com/cluster-allowlist-group` - same as for Ingress

The gateway name, gateway namespace, and target namespace for the `AuthorizationPolicy` are all derived automatically from `spec.parentRefs` - no extra annotations needed.

**Same-namespace case** - parentRef has no `namespace`, so the `AuthorizationPolicy` is created in the same namespace as the `HTTPRoute`:

```yaml
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata:
  name: my-route
  namespace: my-app
  annotations:
    ipam.adevinta.com/cluster-allowlist-group: office-ips
spec:
  parentRefs:
  - group: gateway.networking.k8s.io
    kind: Gateway
    name: my-gateway
  hostnames:
  - app.example.com
```

The controller generates in `my-app`:

```yaml
apiVersion: security.istio.io/v1
kind: AuthorizationPolicy
metadata:
  name: my-route          # httproute name
  namespace: my-app
  ownerReferences:        # automatically garbage-collected when the HTTPRoute is deleted
  - kind: HTTPRoute
    name: my-route
spec:
  action: ALLOW
  rules:
  - from:
    - source:
        remoteIpBlocks:
        - 10.0.0.0/8
        - 192.168.0.0/16
    to:
    - operation:
        hosts:
        - app.example.com
  targetRefs:
  - group: gateway.networking.k8s.io
    kind: Gateway
    name: my-gateway
```

**Cross-namespace case** - parentRef has a `namespace` that differs from the HTTPRoute namespace. The `AuthorizationPolicy` is created in the gateway namespace:

```yaml
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata:
  name: my-route
  namespace: my-app
  annotations:
    ipam.adevinta.com/cluster-allowlist-group: office-ips
spec:
  parentRefs:
  - group: gateway.networking.k8s.io
    kind: Gateway
    name: cross-namespace-gateway
    namespace: infra          # different from HTTPRoute namespace
  hostnames:
  - app.example.com
```

The controller generates in `infra`:

```yaml
apiVersion: security.istio.io/v1
kind: AuthorizationPolicy
metadata:
  name: my-app-my-route   # <httproute-namespace>-<httproute-name>
  namespace: infra
  # no ownerReference - cross-namespace owner references are not supported by Kubernetes
spec:
  action: ALLOW
  rules:
  - from:
    - source:
        remoteIpBlocks:
        - 10.0.0.0/8
        - 192.168.0.0/16
    to:
    - operation:
        hosts:
        - app.example.com
  targetRefs:
  - group: gateway.networking.k8s.io
    kind: Gateway
    name: cross-namespace-gateway
```

> **Note:** Cross-namespace `AuthorizationPolicy` resources are not garbage-collected automatically when the `HTTPRoute` is deleted. Kubernetes does not support cross-namespace owner references, so the controller cannot set one - the API server would silently strip it anyway. This means stale APs can accumulate when routes are deleted, have their `parentRefs` changed, or switch between normal and merge mode.
>
> **Automatic cleanup on restart:** every time the controller starts, it runs a one-time sweep over all `AuthorizationPolicy` resources it owns (identified by the `app.kubernetes.io/managed-by=ingress-allowlisting-controller` label). Any AP whose owner `HTTPRoute` no longer exists, or that the current route configuration would no longer produce, is deleted. Restarting the controller is therefore sufficient to clean up any accumulated orphans.
>
> **Hard reset:** to remove all APs managed by this controller and let it rebuild from scratch:
> ```bash
> kubectl delete authorizationpolicies -A -l app.kubernetes.io/managed-by=ingress-allowlisting-controller
> # then restart the controller
> kubectl rollout restart deployment/ingress-allowlisting-controller -n <namespace>
> ```

**Multiple gateways** - an HTTPRoute can reference more than one gateway. The controller creates one `AuthorizationPolicy` per gateway. The first gets no index suffix; subsequent ones get `-1`, `-2`, etc.:

```yaml
spec:
  parentRefs:
  - name: internal-gateway           # → AuthorizationPolicy: my-route (or my-app-my-route)
  - name: external-gateway           # → AuthorizationPolicy: my-route-1 (or my-app-my-route-1)
```

**Performance tuning** - if you have thousands of HTTPRoutes in a cluster, you can restrict the informer cache to only the ones opted into allowlisting using a label selector:

```yaml
httproute:
  enabled: true
  labelSelector: "ipam.adevinta.com/allowlisting=enabled"
```

Or via flag: `--httproute-label-selector=ipam.adevinta.com/allowlisting=enabled`.

This filters at the API server level, reducing both memory usage and reconcile load.

**Merge mode** - for staging environments where the same application is deployed across multiple namespaces (e.g. `ns-staging00`, `ns-staging01`, ...) and all point to a shared cross-namespace gateway, you can set `ipam.adevinta.com/merge` to a shared policy name to produce a single `AuthorizationPolicy` that covers all of them.

The annotation value is both the **merge key** (which routes belong together) and the **name of the generated `AuthorizationPolicy`**. HTTPRoute names can be anything - typically they are hostname-based - and do not need to match.

```yaml
# In namespace ns-staging00:
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata:
  name: chaos-monkey.public.ns-staging00.example.com
  namespace: ns-staging00
  annotations:
    ipam.adevinta.com/allowlist-group: allowlist
    ipam.adevinta.com/merge: chaos-monkey   # merge key = AP name
spec:
  parentRefs:
  - group: gateway.networking.k8s.io
    kind: Gateway
    name: cross-namespace-public
    namespace: ns-infra
  hostnames:
  - chaos-monkey.public.ns-staging00.example.com
---
# In namespace ns-staging01:
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata:
  name: chaos-monkey.public.ns-staging01.example.com
  namespace: ns-staging01
  annotations:
    ipam.adevinta.com/allowlist-group: allowlist
    ipam.adevinta.com/merge: chaos-monkey   # same merge key → same AP
spec:
  parentRefs:
  - group: gateway.networking.k8s.io
    kind: Gateway
    name: cross-namespace-public
    namespace: ns-infra
  hostnames:
  - chaos-monkey.public.ns-staging01.example.com
```

The controller generates a **single** `AuthorizationPolicy` in `ns-infra`:

```yaml
apiVersion: security.istio.io/v1
kind: AuthorizationPolicy
metadata:
  name: chaos-monkey      # = the merge key (first gateway, no suffix; second would be chaos-monkey-1)
  namespace: ns-infra
spec:
  action: ALLOW
  rules:
  - from:
    - source:
        remoteIpBlocks:
        - 1.2.3.4/32       # union of all sibling CIDRs
        - 5.6.7.8/32
    to:
    - operation:
        hosts:
        - chaos-monkey.public.ns-staging00.example.com
        - chaos-monkey.public.ns-staging01.example.com
  targetRefs:
  - group: gateway.networking.k8s.io
    kind: Gateway
    name: cross-namespace-public
```

Merge rules:
- All HTTPRoutes with the **same annotation value** and the **same target gateway** are merged together, regardless of their `metadata.name`.
- CIDRs and hostnames are deduplicated across all siblings.
- Reconciling any one sibling rebuilds the full merged policy.

> **Security warning:** Merge mode is **not recommended for production** environments. Any namespace in the cluster that sets the same merge key and points to the same gateway will be pulled into the same `AuthorizationPolicy`. This means a team controlling a different namespace could add their application's hostnames and CIDRs to your policy, potentially opening access to their service through your allowlist - or having their service inadvertently protected by your rules.
>
> Merge mode is designed for **staging environments** where multiple namespace-isolated instances of the same application exist under the same team's control and share a single gateway.

### Example NetworkPolicy Resource
Below are examples of NetworkPolicy resources with different `policyTypes` (Ingress or Egress).

NetworkPolicy with `ingress` with namespaced version of CIDRs object
```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: ingress-allow-myips
  annotations:
    ipam.adevinta.com/allowlist-group: MyCidrsObject
spec:
  podSelector: {} # Applies to all pods in namespace
  policyTypes:
  - Ingress
# Controller will populate spec.ingress[0] with ipBlock rules here
```
NetworkPolicy with `egress` using a cluster-scoped CIDRs object and predefined ports:

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: egress-allow-http
  annotations:
    ipam.adevinta.com/cluster-allowlist-group: http-allowed
spec:
  podSelector: {} # Applies to all pods in namespace
  policyTypes:
  - Egress
# Controller will populate spec.egress[0] with ipBlock rules here respecting the ports
  egress:
  - ports:
    - port: 443
    - port: 80
```

##### Key Points:

* You define: `podSelector` and `policyTypes`
* Controller manages: Automatically populates and maintains the `spec.ingress` or `spec.egress` sections with `ipBlock` rules
* Overwrite behavior: Any existing `ipBlock` rules in these sections will be overwritten by the controller
* Dual policyTypes: If both `Ingress` and `Egress` are specified, the controller will populate both sections

```yaml
spec:
  ingress:        # For Ingress policies
  - from:
    - ipBlock:
        cidr: x.x.x.x/y
  egress:         # For Egress policies  
  - to:
    - ipBlock:
        cidr: x.x.x.x/y
```

### Example CIDR and ClusterCIDR CRDs

```yaml
apiVersion: ipam.adevinta.com/v1alpha1
kind: CIDRs
metadata:
    name: MyCidrsObject
spec:
    cidrs:
    - 1.1.1.1/32
    - 2.2.2.2/32
```

```yaml
apiVersion: ipam.adevinta.com/v1alpha1
kind: ClusterCIDRs
metadata:
    name: Cloudfront
spec:
    cidrs:
    - 120.52.22.96/27
    - 205.251.249.0/24
    - 180.163.57.128/26
```

### Fetching CIDRs from remote sources

Ingress-allowlister supports synchronizing CIDRs from remote http sources.
To use this feature, configure the CIDRs or ClusterCIDRs object as follows

```yaml
apiVersion: ipam.adevinta.com/v1alpha1
kind: CIDRs
metadata:
  name: ec2
  namespace: test
spec:
  requeueAfter: 30m # Re-evaluate the remote URL every 30 minutes
  location:
    cel: 'data.prefixes.filter(p, p.service == "EC2" && has(p.ip_prefix)).map(p, p.ip_prefix)' # transform the AWS response into a list of strings using CEL expression
    uri: https://ip-ranges.amazonaws.com/ip-ranges.json # the remote URL responding all IPs
    headersFrom: # optional: inject CIDRs to the HTTP request (if the request needs to be authenticated)
      secretRef: # optional: inject all keys
        name: aws-authentication-headers # all aws-authentication-headers data will be used as http headers in the http request
        namespace: test # optional. For CIDRs, it must match the CIDRs namespace when not empty.
      configMapRef:
        name: aws-headers # all aws-headers data will be used as http headers in the http request
        namespace: test # optional. For CIDRs, it must match the CIDRs namespace when not empty.
---
# optional
apiVersion: v1
kind: ConfigMap
metadata:
  name: aws-headers
  namespace: test
data:
  My-Header: some-value
---
# optional
apiVersion: v1
kind: Secret
metadata:
  name: aws-authentication-headers
  namespace: test
data:
  Authentication: $(echo "Bearer $token" | base64)
```

#### Fetching CIDRs from github

To fetch CIDRs stored in github repositories, you can use the github API endpoint:

```yaml
apiVersion: ipam.adevinta.com/v1alpha1
kind: CIDRs
metadata:
  name: my-cidrs
  namespace: test
spec:
  requeueAfter: 30m
  location:
    uri: https://api.github.com/repos/my-org/my-repo/contents/path/to/cidrs/file.json
```

## Metrics
The operator exposes a single metric `namespace_ingress_IpAllowlistingGroup_missing` that, when operated appropiately, it offer several information:

```
# HELP namespace_ingress_IpAllowlistingGroup_missing Number of missing IpAllowlistingGroup objects. >0 implies expected objects were not found
# TYPE namespace_ingress_IpAllowlistingGroup_missing gauge
namespace_ingress_IpAllowlistingGroup_missing{cidrs_name="alvarocidr",ingress="kube-nurse-kubenurse",namespace="cre-system"} 0
```
When the metric exists and equals 0, it means that there are no errors; the given object in the given namespace associated to the given ingress exists and has been resolved adequately.

When the metric exists and equals 1 means that there was an error resolving the `cidr_name`, probably, because the object didn't exist in the namespace. 

### Common operations:
#### number of ingresses with allowlistGroup annotations: 
  `count(sum(namespace_ingress_IpAllowlistingGroup_missing) by (ingress))`
#### number of ingresses with failed annotations: 
  `count(sum(namespace_ingress_IpAllowlistingGroup_missing) by (ingress) > 0)`
  
