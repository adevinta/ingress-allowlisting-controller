
# Image URL to use all building/pushing image targets
IMG ?= controller:latest
# Produce CRDs that work back to Kubernetes 1.11 (no version conversion)
CRD_OPTIONS ?= "crd"

# Get the currently used golang install path (in GOPATH/bin, unless GOBIN is set)
ifeq (,$(shell go env GOBIN))
GOBIN=$(shell go env GOPATH)/bin
else
GOBIN=$(shell go env GOBIN)
endif

CONTROLLER_GEN=$(GOBIN)/controller-gen

all: manager

# Run tests
test: generate fmt vet manifests
	go test ./... -coverprofile cover.out

# Build manager binary
manager: generate fmt vet
	go build -o bin/manager ./cmd/ingress-allowlisting-controller

# Run against the configured Kubernetes cluster in ~/.kube/config
run: generate fmt vet manifests
	go run ./cmd/ingress-allowlisting-controller

# Install CRDs into a cluster
install: manifests
	kubectl apply -f config/crd/bases

# Uninstall CRDs from a cluster
uninstall: manifests
	kubectl delete -f config/crd/bases

# Generate manifests e.g. CRD, RBAC etc.
# The controller is installed with the Helm chart (see README.md), whose crds/ are symlinks to
# config/crd/bases. config/rbac/role.yaml, generated from the RBAC markers, is the reference for
# the chart's ClusterRole.
manifests: controller-gen
	$(CONTROLLER_GEN) $(CRD_OPTIONS) paths="./pkg/apis/..." output:crd:artifacts:config=config/crd/bases
	$(CONTROLLER_GEN) rbac:roleName=manager-role paths="./..." output:rbac:artifacts:config=config/rbac

# Verify that the committed manifests match the kubebuilder markers.
verify-manifests: manifests
	@status="$$(git status --porcelain --untracked-files=all -- config/crd/bases config/rbac/role.yaml)"; \
	if [ -n "$$status" ]; then \
		echo "Generated manifests are out of date. Run 'make manifests' and commit the changes:"; \
		git --no-pager diff -- config/crd/bases config/rbac/role.yaml; \
		printf '%s\n' "$$status"; \
		exit 1; \
	fi

# Run go fmt against code
fmt:
	go fmt ./...

# Run go vet against code
vet:
	go vet ./...

# Generate code
generate: controller-gen
	$(CONTROLLER_GEN) object:headerFile="${PWD}/hack/boilerplate.go.txt" paths="./..."

# Build the docker image
docker-build: 
	docker build . -t ${IMG}

# Push the docker image
docker-push:
	docker push ${IMG}

# Functional tests against a REAL cluster (the current kube context) — local only, never in CI.
# Dry run by default: prints the target cluster and the plan, creates nothing. To create objects:
#   make functional CONFIRM=<current-context-name>
# See docs/functional-tests.md for IAC_CONTEXT, IAC_CONTROLLER, IAC_CONTROLLER_ARGS, IAC_TIMEOUT, KEEP.
export CONFIRM KEEP IAC_CONTEXT IAC_CONTROLLER IAC_CONTROLLER_ARGS IAC_TIMEOUT
functional:
	go test -tags functional ./test/functional/ -run TestFunctional -v -count=1 -timeout 30m

# Delete namespaces left behind by interrupted or KEEP=1 functional runs.
functional-clean:
	@ctx="$${IAC_CONTEXT:-$$(kubectl config current-context)}"; \
	echo "context: $$ctx"; \
	kubectl --context "$$ctx" delete namespace -l iac-functional=true --wait=false

# find or download controller-gen
# download controller-gen if necessary
controller-gen:
	go install sigs.k8s.io/controller-tools/cmd/controller-gen@v0.16.4

.PHONY: all test manager run install uninstall manifests verify-manifests fmt vet generate docker-build docker-push controller-gen functional functional-clean
