# Build the manager binary
FROM golang:1.23.3 as builder

WORKDIR /workspace
# Copy the Go Modules manifests
COPY go.mod go.mod
COPY go.sum go.sum
COPY vendor/ vendor/

# Copy the go source
COPY cmd/ cmd/
COPY pkg/ pkg/

# Build
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GO111MODULE=on go build -mod=vendor -a -o manager cmd/ingress-allowlisting-controller/main.go

FROM ubuntu as ca-certificates

RUN apt-get update && apt-get install -y ca-certificates

# Use distroless as minimal base image to package the manager binary
# Refer to https://github.com/GoogleContainerTools/distroless for more details
FROM gcr.io/distroless/static:nonroot
WORKDIR /
COPY --from=ca-certificates /etc/ssl/certs /etc/ssl/certs
COPY --from=ca-certificates /usr/share/ca-certificates /usr/share/ca-certificates
COPY --from=builder /workspace/manager .
USER nonroot:nonroot

ENTRYPOINT ["/manager"]
