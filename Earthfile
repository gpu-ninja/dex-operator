VERSION 0.7
FROM golang:1.21-bookworm
WORKDIR /app

docker-all:
  BUILD --platform=linux/amd64 --platform=linux/arm64 +docker

docker:
  ARG TARGETARCH
  ARG VERSION
  FROM gcr.io/distroless/static:nonroot
  WORKDIR /
  COPY LICENSE /usr/local/share/dex-operator/
  COPY (+dex-operator/dex-operator --GOARCH=${TARGETARCH}) /manager
  USER 65532:65532
  ENTRYPOINT ["/manager"]
  SAVE IMAGE --push ghcr.io/gpu-ninja/dex-operator:${VERSION}
  SAVE IMAGE --push ghcr.io/gpu-ninja/dex-operator:latest

bundle:
  FROM +tools
  COPY config ./config
  COPY hack ./hack
  ARG VERSION
  RUN ytt --data-value version=${VERSION} -f config -f hack/set-version.yaml | kbld -f - > dex-operator.yaml
  SAVE ARTIFACT ./dex-operator.yaml AS LOCAL dist/dex-operator.yaml

dex-operator:
  ARG GOOS=linux
  ARG GOARCH=amd64
  COPY go.mod go.sum ./
  RUN go mod download
  COPY . .
  RUN CGO_ENABLED=0 go build -ldflags '-s' -o dex-operator cmd/dex-operator/main.go
  SAVE ARTIFACT ./dex-operator AS LOCAL dist/dex-operator-${GOOS}-${GOARCH}

generate:
  FROM +tools
  COPY . .
  RUN controller-gen object:headerFile="hack/boilerplate.go.txt" paths="./..."
  RUN controller-gen crd:generateEmbeddedObjectMeta=true rbac:roleName=dex-manager-role webhook paths="./..." output:crd:artifacts:config=config/crd/bases
  SAVE ARTIFACT ./api/zz_generated.deepcopy.go AS LOCAL api/zz_generated.deepcopy.go
  SAVE ARTIFACT ./api/v1alpha1/zz_generated.deepcopy.go AS LOCAL api/v1alpha1/zz_generated.deepcopy.go
  SAVE ARTIFACT ./config/crd/bases AS LOCAL config/crd/bases
  SAVE ARTIFACT ./config/rbac/role.yaml AS LOCAL config/rbac/role.yaml

tidy:
  LOCALLY
  RUN go mod tidy
  RUN go fmt ./...

lint:
  FROM golangci/golangci-lint:v1.54.2
  WORKDIR /app
  COPY . ./
  RUN golangci-lint run --timeout 5m ./...

test:
  COPY go.mod go.sum ./
  RUN go mod download
  COPY . .
  RUN go test -coverprofile=coverage.out -v ./...
  SAVE ARTIFACT ./coverage.out AS LOCAL coverage.out

integration-test:
  FROM +tools
  COPY . .
  WITH DOCKER --allow-privileged --load ghcr.io/gpu-ninja/dex-operator:latest-dev=(+docker --VERSION=latest-dev)
    RUN SKIP_BUILD=1 ./tests/integration.sh
  END

tools:
  ARG TARGETARCH
  RUN apt update && apt install -y git ca-certificates curl libdigest-sha-perl rhash jq
  RUN curl -fsSL https://get.docker.com | bash
  RUN curl -fsSL https://carvel.dev/install.sh | bash
  ARG K3D_VERSION=v5.6.0
  RUN curl -fsSL -o /usr/local/bin/k3d "https://github.com/k3d-io/k3d/releases/download/${K3D_VERSION}/k3d-linux-${TARGETARCH}" \
    && chmod +x /usr/local/bin/k3d
  ARG KUBECTL_VERSION=v1.28.2
  RUN curl -fsSL -o /usr/local/bin/kubectl "https://dl.k8s.io/release/${KUBECTL_VERSION}/bin/linux/${TARGETARCH}/kubectl" \
    && chmod +x /usr/local/bin/kubectl
  ARG CONTROLLER_TOOLS_VERSION=v0.12.0
  RUN go install sigs.k8s.io/controller-tools/cmd/controller-gen@${CONTROLLER_TOOLS_VERSION}