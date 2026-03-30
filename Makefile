# Ghost Server Autopsy — Linux-only Go agent (module ghostpsy/agent-linux)
# Run from this directory: make help

.PHONY: help tidy build install clean test vet fmt run-help scan-dry scan

GO       ?= go
CMD      := ./cmd/ghostpsy
BIN_DIR  := bin
BINARY   := $(BIN_DIR)/ghostpsy

help:
	@echo "Ghostpsy agent-linux — Go binary (build, test, scan, scan-dry, …)"
	@echo ""
	@echo "Targets (run from this directory):"
	@echo "  make tidy        go mod tidy && go mod verify"
	@echo "  make build       build $(BINARY)"
	@echo "  make install     go install $(CMD)  (uses GOBIN or GOPATH/bin)"
	@echo "  make run-help    go run $(CMD) help"
	@echo "  make scan-dry    go run $(CMD) scan -dry-run"
	@echo "  make scan        go run $(CMD) scan (auto-registers on first run; needs token to POST)"
	@echo "  make test        go test ./..."
	@echo "  make vet         go vet ./..."
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

fmt:
	$(GO) fmt ./...

run-help:
	$(GO) run $(CMD) help

scan-dry:
	$(GO) run $(CMD) scan -dry-run

# Sends to API after interactive confirm (y).
scan:
	$(GO) run $(CMD) scan
