# Variables
BINARY_NAME=dns-benchmark
CMD_DIR=./cmd
PKG_DIR=./pkg/...
DIST_DIR=dist
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
LDFLAGS=-ldflags "-s -w -X main.version=$(VERSION)"

# Colors for output
GREEN=\033[0;32m
YELLOW=\033[0;33m
RED=\033[0;31m
NC=\033[0m # No Color

.PHONY: help clean build test fmt lint vet mod-tidy mod-download run install uninstall
.PHONY: test-verbose test-race test-cover test-bench release build-all check-tools
.PHONY: docker docker-build docker-run pre-commit ci-check

# Default target
.DEFAULT_GOAL := help

## Help: Show this help message
help:
	@echo "DNS Benchmark Tool - Development Commands"
	@echo ""
	@echo "$(GREEN)Building:$(NC)"
	@echo "  build        Build the binary for current platform"
	@echo "  build-all    Build binaries for all supported platforms"
	@echo "  install      Install binary to GOPATH/bin"
	@echo "  uninstall    Remove binary from GOPATH/bin"
	@echo "  release      Build release binaries with checksums"
	@echo ""
	@echo "$(GREEN)Development:$(NC)"
	@echo "  run          Build and run the application"
	@echo "  clean        Remove build artifacts"
	@echo "  fmt          Format Go code"
	@echo "  lint         Run golangci-lint (requires installation)"
	@echo "  vet          Run go vet"
	@echo "  mod-tidy     Tidy and verify Go modules"
	@echo "  mod-download Download Go modules"
	@echo ""
	@echo "$(GREEN)Testing:$(NC)"
	@echo "  test         Run all tests"
	@echo "  test-verbose Run tests with verbose output"
	@echo "  test-race    Run tests with race detection"
	@echo "  test-cover   Run tests with coverage report"
	@echo "  test-bench   Run benchmark tests"
	@echo ""
	@echo "$(GREEN)Quality:$(NC)"
	@echo "  check        Run all quality checks (fmt, vet, lint, test)"
	@echo "  pre-commit   Run pre-commit checks"
	@echo "  ci-check     Run CI-style comprehensive checks"
	@echo ""
	@echo "$(GREEN)Docker:$(NC)"
	@echo "  docker-build Build Docker image"
	@echo "  docker-run   Run application in Docker container"
	@echo ""
	@echo "$(GREEN)Tools:$(NC)"
	@echo "  check-tools  Check if required tools are installed"

## Build: Build the binary for current platform
build:
	@echo "$(GREEN)Building $(BINARY_NAME)...$(NC)"
	go build $(LDFLAGS) -o $(BINARY_NAME) $(CMD_DIR)/main.go
	@echo "$(GREEN)Build complete: $(BINARY_NAME)$(NC)"

## Build All: Build binaries for all supported platforms
build-all: clean
	@echo "$(GREEN)Building for all platforms...$(NC)"
	@mkdir -p $(DIST_DIR)

	# Linux builds
	@echo "Building for Linux AMD64..."
	@CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build $(LDFLAGS) -o $(DIST_DIR)/$(BINARY_NAME)-linux-amd64 $(CMD_DIR)/main.go
	@echo "Building for Linux ARM64..."
	@CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build $(LDFLAGS) -o $(DIST_DIR)/$(BINARY_NAME)-linux-arm64 $(CMD_DIR)/main.go

	# Darwin (macOS) builds
	@echo "Building for macOS AMD64..."
	@CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build $(LDFLAGS) -o $(DIST_DIR)/$(BINARY_NAME)-darwin-amd64 $(CMD_DIR)/main.go
	@echo "Building for macOS ARM64..."
	@CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build $(LDFLAGS) -o $(DIST_DIR)/$(BINARY_NAME)-darwin-arm64 $(CMD_DIR)/main.go

	# Windows builds
	@echo "Building for Windows AMD64..."
	@CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build $(LDFLAGS) -o $(DIST_DIR)/$(BINARY_NAME)-windows-amd64.exe $(CMD_DIR)/main.go
	@echo "Building for Windows ARM64..."
	@CGO_ENABLED=0 GOOS=windows GOARCH=arm64 go build $(LDFLAGS) -o $(DIST_DIR)/$(BINARY_NAME)-windows-arm64.exe $(CMD_DIR)/main.go

	@echo "$(GREEN)Multi-platform build complete!$(NC)"

## Release: Build release binaries with checksums
release: build-all
	@echo "$(GREEN)Creating release checksums...$(NC)"
	@cd $(DIST_DIR) && sha256sum * > checksums.txt
	@echo "$(GREEN)Release build complete! Files in $(DIST_DIR)/$(NC)"

## Install: Install binary to GOPATH/bin
install:
	@echo "$(GREEN)Installing $(BINARY_NAME)...$(NC)"
	go install $(LDFLAGS) $(CMD_DIR)/main.go
	@echo "$(GREEN)Installed to $$(go env GOPATH)/bin/$(BINARY_NAME)$(NC)"

## Uninstall: Remove binary from GOPATH/bin
uninstall:
	@echo "$(YELLOW)Removing $(BINARY_NAME) from $$(go env GOPATH)/bin/$(NC)"
	@rm -f $$(go env GOPATH)/bin/$(BINARY_NAME)
	@echo "$(GREEN)Uninstalled$(NC)"

## Run: Build and run the application
run: build
	@echo "$(GREEN)Running $(BINARY_NAME)...$(NC)"
	./$(BINARY_NAME) --version
	@echo "$(YELLOW)Use './$(BINARY_NAME) -h' for help$(NC)"

## Clean: Remove build artifacts
clean:
	@echo "$(YELLOW)Cleaning build artifacts...$(NC)"
	@rm -f $(BINARY_NAME)
	@rm -rf $(DIST_DIR)
	@echo "$(GREEN)Clean complete$(NC)"

## Format: Format Go code
fmt:
	@echo "$(GREEN)Formatting Go code...$(NC)"
	go fmt ./...
	@echo "$(GREEN)Formatting complete$(NC)"

## Lint: Run golangci-lint
lint:
	@echo "$(GREEN)Running golangci-lint...$(NC)"
	@if command -v golangci-lint >/dev/null 2>&1; then \
		golangci-lint run; \
		echo "$(GREEN)Linting complete$(NC)"; \
	else \
		echo "$(RED)golangci-lint not found. Install with: go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest$(NC)"; \
		exit 1; \
	fi

## Vet: Run go vet
vet:
	@echo "$(GREEN)Running go vet...$(NC)"
	go vet ./...
	@echo "$(GREEN)Vet complete$(NC)"

## Mod Tidy: Tidy and verify Go modules
mod-tidy:
	@echo "$(GREEN)Tidying Go modules...$(NC)"
	go mod tidy
	go mod verify
	@echo "$(GREEN)Module tidy complete$(NC)"

## Mod Download: Download Go modules
mod-download:
	@echo "$(GREEN)Downloading Go modules...$(NC)"
	go mod download
	@echo "$(GREEN)Module download complete$(NC)"

## Test: Run all tests
test:
	@echo "$(GREEN)Running tests...$(NC)"
	go test ./...
	@echo "$(GREEN)Tests complete$(NC)"

## Test Verbose: Run tests with verbose output
test-verbose:
	@echo "$(GREEN)Running tests (verbose)...$(NC)"
	go test -v ./...

## Test Race: Run tests with race detection
test-race:
	@echo "$(GREEN)Running tests with race detection...$(NC)"
	go test -race ./...
	@echo "$(GREEN)Race tests complete$(NC)"

## Test Cover: Run tests with coverage report
test-cover:
	@echo "$(GREEN)Running tests with coverage...$(NC)"
	go test -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html
	@echo "$(GREEN)Coverage report generated: coverage.html$(NC)"

## Test Bench: Run benchmark tests
test-bench:
	@echo "$(GREEN)Running benchmark tests...$(NC)"
	go test -bench=. -benchmem ./...

## Check: Run all quality checks
check: fmt vet test
	@echo "$(GREEN)All quality checks passed!$(NC)"

## Pre-commit: Run pre-commit checks
pre-commit: fmt vet lint test-race
	@echo "$(GREEN)Pre-commit checks complete!$(NC)"

## CI Check: Run CI-style comprehensive checks
ci-check: mod-tidy fmt vet lint test-race test-cover
	@echo "$(GREEN)CI checks complete!$(NC)"

## Check Tools: Check if required tools are installed
check-tools:
	@echo "$(GREEN)Checking required tools...$(NC)"
	@echo -n "Go: "
	@if command -v go >/dev/null 2>&1; then \
		echo "$(GREEN)✓ $$(go version)$(NC)"; \
	else \
		echo "$(RED)✗ Not found$(NC)"; \
	fi
	@echo -n "Git: "
	@if command -v git >/dev/null 2>&1; then \
		echo "$(GREEN)✓ $$(git --version)$(NC)"; \
	else \
		echo "$(RED)✗ Not found$(NC)"; \
	fi
	@echo -n "golangci-lint: "
	@if command -v golangci-lint >/dev/null 2>&1; then \
		echo "$(GREEN)✓ $$(golangci-lint --version)$(NC)"; \
	else \
		echo "$(YELLOW)⚠ Not found (optional for linting)$(NC)"; \
		echo "  Install with: go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest"; \
	fi

## Docker Build: Build Docker image
docker-build:
	@echo "$(GREEN)Building Docker image...$(NC)"
	docker build -t $(BINARY_NAME):$(VERSION) .
	docker tag $(BINARY_NAME):$(VERSION) $(BINARY_NAME):latest
	@echo "$(GREEN)Docker image built: $(BINARY_NAME):$(VERSION)$(NC)"

## Docker Run: Run application in Docker container
docker-run: docker-build
	@echo "$(GREEN)Running in Docker container...$(NC)"
	docker run --rm $(BINARY_NAME):latest --version

# Development convenience targets
dev: check build run

# Quick test for development
quick: fmt vet test

.SUFFIXES:
