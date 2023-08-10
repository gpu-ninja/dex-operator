# Location to install dependencies to
LOCALBIN ?= $(shell pwd)/bin

# Tool Versions
CONTROLLER_TOOLS_VERSION ?= v0.12.0

# Tool Binaries
CONTROLLER_GEN ?= $(LOCALBIN)/controller-gen

SRCS := $(shell find . -type f -name '*.go' -not -path "./vendor/*")

$(LOCALBIN)/manager: $(SRCS) $(LOCALBIN)
	CGO_ENABLED=0 go build -ldflags '-s' -o $@ cmd/main.go

generate: $(CONTROLLER_GEN)
	$(CONTROLLER_GEN) object:headerFile="hack/boilerplate.go.txt" paths="./..."
	$(CONTROLLER_GEN) rbac:roleName=manager-role crd webhook paths="./..." output:crd:artifacts:config=config/crd/bases

tidy: $(SRCS)
	go mod tidy
	go fmt ./...

lint: $(SRCS)
	golangci-lint run ./...

test: $(SRCS)
	go test -coverprofile=coverage.out -v ./...

clean:
	-rm -rf bin
	go clean -testcache

$(LOCALBIN):
	mkdir -p $(LOCALBIN)

$(CONTROLLER_GEN): $(LOCALBIN)
	test -s $(LOCALBIN)/controller-gen && $(LOCALBIN)/controller-gen --version | grep -q $(CONTROLLER_TOOLS_VERSION) || \
	GOBIN=$(LOCALBIN) go install sigs.k8s.io/controller-tools/cmd/controller-gen@$(CONTROLLER_TOOLS_VERSION)

.PHONY: generate tidy lint test clean