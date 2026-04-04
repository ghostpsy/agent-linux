# Ghost Server Autopsy — Linux-only Go agent (module github.com/ghostpsy/agent-linux)
# Run from this directory: make help

.PHONY: help tidy build install clean test vet lint fmt run-help scan-dry scan

GO       ?= go
# Default off: links a static binary so builds on newer glibc (e.g. GitHub ubuntu-latest) still run on older distros.
CGO_ENABLED ?= 0
export CGO_ENABLED
CMD      := ./cmd/ghostpsy
BIN_DIR  := bin
BINARY   := $(BIN_DIR)/ghostpsy

help:
	@echo "Ghostpsy agent-linux — Go binary (build, test, scan, scan-dry, …)"
	@echo ""
	@echo "Targets (run from this directory):"
	@echo "  make tidy        go mod tidy && go mod verify"
	@echo "  make build       build $(BINARY) (CGO_ENABLED=0 static binary by default)"
	@echo "  make install     go install $(CMD)  (uses GOBIN or GOPATH/bin)"
	@echo "  make run-help    go run $(CMD) help"
	@echo "  make scan-dry    go run $(CMD) scan -dry-run"
	@echo "  make scan        go run $(CMD) scan (auto-registers on first run; needs token to POST)"
	@echo "  make test        go test ./..."
	@echo "  make vet         go vet ./..."
	@echo "  make lint        golangci-lint run ./...  (install: https://golangci-lint.run/welcome/install/)"
	@echo "  make fmt         go fmt ./..."
	@echo "  make clean       rm -rf $(BIN_DIR)"

tidy:
	$(GO) mod tidy
	$(GO) mod verify

$(BIN_DIR):
	mkdir -p $(BIN_DIR)

build: tidy $(BIN_DIR)
	$(GO) build -o $(BINARY) $(CMD)

install: tidy
	$(GO) install $(CMD)

clean:
	rm -rf $(BIN_DIR)

test:
	$(GO) test ./...

vet:
	$(GO) vet ./...

lint:
	golangci-lint run ./...

fmt:
	$(GO) fmt ./...

run-help:
	$(GO) run $(CMD) help

scan-dry:
	$(GO) run $(CMD) scan -dry-run

# Sends to API after interactive confirm (y).
scan:
	$(GO) run $(CMD) scan
