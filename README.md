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
    jsonPath: "{.prefixes[?(@.service == 'EC2')].ip_prefix}" # transform the AWS response into a list of strings, json format
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
  
