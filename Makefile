# Ghost Server Autopsy — Linux-only Go agent (module github.com/ghostpsy/agent-linux)
# Run from this directory: make help

.PHONY: help tidy build install clean test test-linux vet lint fmt run-help run-version scan-dry scan install-git-hook pre-commit-check

GO       ?= go
# Default off: links a static binary so builds on newer glibc (e.g. GitHub ubuntu-latest) still run on older distros.
CGO_ENABLED ?= 0
export CGO_ENABLED
CMD      := ./cmd/ghostpsy
BIN_DIR  := bin
BINARY   := $(BIN_DIR)/ghostpsy
VERSION_PKG := github.com/ghostpsy/agent-linux/internal/version
VERSION_NUM := $(shell tr -d '[:space:]' < VERSION)
RELEASE_DATE := $(shell date -u +%Y-%m-%d)
LDFLAGS := -X $(VERSION_PKG).Version=$(VERSION_NUM) -X $(VERSION_PKG).ReleaseDate=$(RELEASE_DATE)

help:
	@echo "Ghostpsy agent-linux — Go binary (build, test, scan, scan-dry, …)"
	@echo ""
	@echo "Targets (run from this directory):"
	@echo "  make tidy        go mod tidy && go mod verify"
	@echo "  make build       build $(BINARY) (CGO_ENABLED=0 static binary by default)"
	@echo "  make install     go install $(CMD)  (uses GOBIN or GOPATH/bin)"
	@echo "  make run-help    go run $(CMD) help"
	@echo "  make run-version go run $(CMD) version"
	@echo "  make scan-dry    go run $(CMD) scan -dry-run"
	@echo "  make scan        go run $(CMD) scan (auto-registers on first run; needs token to POST)"
	@echo "  make test        go test ./..."
	@echo "  make test-linux  go test ./... under linux (docker on non-linux hosts so //go:build linux files compile)"
	@echo "  make vet         go vet ./..."
	@echo "  make lint        golangci-lint run ./...  (install: https://golangci-lint.run/welcome/install/)"
	@echo "  make pre-commit-check  make lint && make test-linux"
	@echo "  make install-git-hook  installs .git/hooks/pre-commit for this repo"
	@echo "  make fmt         go fmt ./..."
	@echo "  make clean       rm -rf $(BIN_DIR)"

tidy:
	$(GO) mod tidy
	$(GO) mod verify

$(BIN_DIR):
	mkdir -p $(BIN_DIR)

build: tidy $(BIN_DIR)
	$(GO) build -ldflags="$(LDFLAGS)" -o $(BINARY) $(CMD)

install: tidy
	$(GO) install -ldflags="$(LDFLAGS)" $(CMD)

clean:
	rm -rf $(BIN_DIR)

# golangci-lint and go vet skip //go:build linux packages unless GOOS=linux (e.g. on macOS).
LINUX_GO_ENV := GOOS=linux GOARCH=amd64

# go test needs to actually *run* the compiled binary, so GOOS=linux on
# macOS is not enough (wrong arch). host-os detection: on Linux we run
# tests natively; on anything else we shell out to docker so the linux-
# tagged files (//go:build linux) compile and run identically to CI.
UNAME_S := $(shell uname -s)
GO_IMAGE := golang:1.24

test:
	$(GO) test ./...

test-linux:
ifeq ($(UNAME_S),Linux)
	$(GO) test ./...
else
	@command -v docker >/dev/null 2>&1 || { echo >&2 "docker required to run linux tests on $(UNAME_S)"; exit 1; }
	docker run --rm -v $(CURDIR):/work -w /work -e CGO_ENABLED=$(CGO_ENABLED) $(GO_IMAGE) go test ./...
endif

vet:
	$(LINUX_GO_ENV) $(GO) vet ./...

lint:
	$(LINUX_GO_ENV) golangci-lint run ./...

pre-commit-check: lint test-linux

install-git-hook:
	@HOOKS_DIR="$$(git rev-parse --git-path hooks)"; mkdir -p "$$HOOKS_DIR"
	@HOOK_PATH="$$(git rev-parse --git-path hooks)/pre-commit"; cp scripts/pre-commit "$$HOOK_PATH"
	@HOOK_PATH="$$(git rev-parse --git-path hooks)/pre-commit"; chmod +x "$$HOOK_PATH"
	@echo "Installed pre-commit hook at $$(git rev-parse --git-path hooks)/pre-commit"

fmt:
	$(GO) fmt ./...

run-help:
	$(GO) run $(CMD) help

run-version:
	$(GO) run -ldflags="$(LDFLAGS)" $(CMD) version

scan-dry:
	$(GO) run -ldflags="$(LDFLAGS)" $(CMD) scan -dry-run

# Sends to API after interactive confirm (y).
scan:
	$(GO) run -ldflags="$(LDFLAGS)" $(CMD) scan
