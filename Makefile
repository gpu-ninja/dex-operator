# Location to install dependencies to
LOCALBIN ?= $(shell pwd)/bin

# Tool Versions
CONTROLLER_TOOLS_VERSION ?= v0.12.0
KBLD_VERSION ?= 0.37.4

# Tool Binaries
CONTROLLER_GEN ?= $(LOCALBIN)/controller-gen
KBLD ?= $(LOCALBIN)/kbld

SRCS := $(shell find . -type f -name '*.go' -not -path "./vendor/*")

$(LOCALBIN)/manager: $(SRCS) $(LOCALBIN)
	CGO_ENABLED=0 go build -ldflags '-s' -o $@ cmd/main.go

generate: $(CONTROLLER_GEN)
	$(CONTROLLER_GEN) object:headerFile="hack/boilerplate.go.txt" paths="./..."
	$(CONTROLLER_GEN) rbac:roleName=dex-manager-role crd webhook paths="./..." output:crd:artifacts:config=config/crd/bases

tidy: $(SRCS)
	go mod tidy
	go fmt ./...

lint: $(SRCS)
	golangci-lint run ./...

test: $(SRCS)
	go test -coverprofile=coverage.out -v ./...

clean:
	-rm -rf bin bundle
	go clean -testcache

bundle: $(KBLD) bundle/dex-operator.yaml

bundle/dex-operator.yaml: $(KBLD) generate
	-mkdir -p bundle
	$(KBLD) -f config > $@

ifeq ($(shell uname -m),x86_64)
ARCH = amd64
else ifeq ($(shell uname -m),aarch64)
ARCH = arm64
else
$(error Unknown architecture detected. Update the Makefile to handle $(shell uname -m))
endif

$(LOCALBIN):
	mkdir -p $(LOCALBIN)

$(CONTROLLER_GEN): $(LOCALBIN)
	test -s $(LOCALBIN)/controller-gen && $(LOCALBIN)/controller-gen --version | grep -q $(CONTROLLER_TOOLS_VERSION) || \
	GOBIN=$(LOCALBIN) go install sigs.k8s.io/controller-tools/cmd/controller-gen@$(CONTROLLER_TOOLS_VERSION)

$(KBLD): $(LOCALBIN)
	test -s $(LOCALBIN)/kbld && $(LOCALBIN)/kbld --version | grep -q $(KBLD_VERSION) || \
	(curl -fsL -o $(LOCALBIN)/kbld https://github.com/carvel-dev/kbld/releases/download/v$(KBLD_VERSION)/kbld-linux-$(ARCH) \
	&& chmod +x $(LOCALBIN)/kbld)

.PHONY: generate tidy lint test clean bundle
