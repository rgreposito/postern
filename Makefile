GO        ?= go
BIN       ?= bin
VERSION   ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS   := -s -w -X main.version=$(VERSION)

.PHONY: all build test vet race fmt ci clean run

all: build

build:
	@mkdir -p $(BIN)
	$(GO) build -ldflags "$(LDFLAGS)" -o $(BIN)/postern ./cmd/postern
	$(GO) build -ldflags "$(LDFLAGS)" -o $(BIN)/posternctl ./cmd/posternctl

test:
	$(GO) test ./...

vet:
	$(GO) vet ./...

race:
	$(GO) test -race -count=1 ./...

fmt:
	$(GO) fmt ./...

ci: fmt vet race

run: build
	POSTERN_POLICY=policies/examples/prod.yaml $(BIN)/postern -policy policies/examples/prod.yaml

clean:
	rm -rf $(BIN) cover.out
