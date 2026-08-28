# Colors for terminal output
GREEN  := \033[1;32m
YELLOW := \033[1;33m
BLUE   := \033[1;34m
CYAN   := \033[1;36m
WHITE  := \033[1;37m
RESET  := \033[0m

# Default target - show help
.DEFAULT_GOAL := help

# Variables
# Git version information
GIT_BRANCH := $(shell git rev-parse --abbrev-ref HEAD 2>/dev/null || echo "unknown")
GIT_SHA := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
VERSION ?= "dev/$(GIT_BRANCH)/$(GIT_SHA)"
BUILD_TIME := $(shell date -u '+%Y-%m-%d_%H:%M:%S')
LDFLAGS := -X main.Version="$(VERSION)" -X main.BuildTime="$(BUILD_TIME)" -X main.GitCommit="$(GIT_SHA)"
BINARY_NAME := safe
GO_FILES := $(shell find . -name '*.go' -type f -not -path "./vendor/*")

# Release layout. ci/scripts/build runs `make clean release-all` and then tars
# $(RELEASE_ROOT)/$(PROJECT)-$(VERSION)-* into the build output, so both names
# are part of the CI contract.
PROJECT ?= safe
RELEASE_ROOT ?= release

# Integration suite. TEST_PATH is the suite script, SAFE_PATH the binary it
# drives, ENGINE the server to run against (vault or bao), and VERSIONS the
# space-separated engine versions to test. CI overrides all of them; the
# defaults run the in-tree suite against a freshly built binary over the
# suite's own default versions.
TEST_PATH ?= ci/scripts/tests
SAFE_PATH ?= ./$(BINARY_NAME)
ENGINE ?= vault
# VAULT_VERSIONS is the older, engine-specific spelling of VERSIONS, kept so
# existing invocations keep working.
VAULT_VERSIONS ?=
VERSIONS ?= $(VAULT_VERSIONS)

##@ General

.PHONY: help
help: ## Display this help message
	@echo "$(BLUE)safe Makefile$(RESET)"
	@echo ""
	@awk 'BEGIN {FS = ":.*##"; printf "Usage:\n  make $(CYAN)<target>$(RESET)\n"} /^[a-zA-Z_-]+:.*?##/ { printf "  $(CYAN)%-20s$(RESET) %s\n", $$1, $$2 } /^##@/ { printf "\n$(YELLOW)%s$(RESET)\n", substr($$0, 5) } ' $(MAKEFILE_LIST)

##@ Development

.PHONY: build
build: ## Build the safe binary for current OS/architecture
	@echo "$(GREEN)Building $(BINARY_NAME)...$(RESET)"
	@go build -ldflags="$(LDFLAGS)" -o $(BINARY_NAME) ./cmd/safe
	@echo "$(GREEN)✓ Build complete$(RESET)"

.PHONY: linux
linux: ## Build the safe binary for Linux AMD64
	@echo "$(GREEN)Building $(BINARY_NAME) for Linux AMD64...$(RESET)"
	@env GOOS=linux GOARCH=amd64 go build -ldflags="$(LDFLAGS)" -o $(BINARY_NAME)-linux-amd64 ./cmd/safe
	@echo "$(GREEN)✓ Linux build complete$(RESET)"

.PHONY: linux-arm64
linux-arm64: ## Build the safe binary for Linux ARM64
	@echo "$(GREEN)Building $(BINARY_NAME) for Linux ARM64...$(RESET)"
	@env GOOS=linux GOARCH=arm64 go build -ldflags="$(LDFLAGS)" -o $(BINARY_NAME)-linux-arm64 ./cmd/safe
	@echo "$(GREEN)✓ Linux ARM64 build complete$(RESET)"

.PHONY: darwin
darwin: ## Build the safe binary for macOS AMD64
	@echo "$(GREEN)Building $(BINARY_NAME) for macOS AMD64...$(RESET)"
	@env GOOS=darwin GOARCH=amd64 go build -ldflags="$(LDFLAGS)" -o $(BINARY_NAME)-darwin-amd64 ./cmd/safe
	@echo "$(GREEN)✓ macOS AMD64 build complete$(RESET)"

.PHONY: darwin-arm64
darwin-arm64: ## Build the safe binary for macOS ARM64 (Apple Silicon)
	@echo "$(GREEN)Building $(BINARY_NAME) for macOS ARM64...$(RESET)"
	@env GOOS=darwin GOARCH=arm64 go build -ldflags="$(LDFLAGS)" -o $(BINARY_NAME)-darwin-arm64 ./cmd/safe
	@echo "$(GREEN)✓ macOS ARM64 build complete$(RESET)"

.PHONY: windows
windows: ## Build the safe binary for Windows AMD64
	@echo "$(GREEN)Building $(BINARY_NAME) for Windows AMD64...$(RESET)"
	@env GOOS=windows GOARCH=amd64 go build -ldflags="$(LDFLAGS)" -o $(BINARY_NAME)-windows-amd64.exe ./cmd/safe
	@echo "$(GREEN)✓ Windows build complete$(RESET)"

.PHONY: build-all
build-all: linux linux-arm64 darwin darwin-arm64 windows ## Build binaries for all supported platforms
	@echo "$(GREEN)✓ All platform builds complete$(RESET)"

##@ Testing & Quality

.PHONY: test
test: ## Run all tests with race detector
	@echo "$(GREEN)Running tests...$(RESET)"
	@go test -race -v $(shell go list ./... | grep -v vendor)
	@echo "$(GREEN)✓ Tests complete$(RESET)"

.PHONY: test-integration
test-integration: ## Run the end-to-end suite against a real server (ENGINE=vault|bao VERSIONS="1.13.13")
	@echo "$(GREEN)Running integration suite (ENGINE=$(ENGINE))...$(RESET)"
	@test -x "$(TEST_PATH)" || { echo "$(YELLOW)No suite at $(TEST_PATH)$(RESET)"; exit 2; }
# Rebuild when driving the in-tree binary so the suite never runs against a
# stale build. An overridden SAFE_PATH is taken as-is: CI supplies the
# release artifact it means to test.
ifeq ($(SAFE_PATH),./$(BINARY_NAME))
	@$(MAKE) --no-print-directory build
else
	@test -x "$(SAFE_PATH)" || { echo "$(YELLOW)No safe binary at $(SAFE_PATH)$(RESET)"; exit 2; }
endif
	@ENGINE=$(ENGINE) $(TEST_PATH) $(SAFE_PATH) $(VERSIONS)
	@echo "$(GREEN)✓ Integration suite complete$(RESET)"

.PHONY: test-engine-lib
test-engine-lib: ## Run the engine helper unit tests (fast, offline)
	@echo "$(GREEN)Running engine helper unit tests...$(RESET)"
	@bash ci/scripts/t/engine_test.sh
	@echo "$(GREEN)✓ Engine helper tests passed$(RESET)"

.PHONY: test-short
test-short: ## Run tests in short mode (no race detector)
	@echo "$(GREEN)Running short tests...$(RESET)"
	@go test -short $(shell go list ./... | grep -v vendor)
	@echo "$(GREEN)✓ Short tests complete$(RESET)"

.PHONY: test-race
test-race: ## Run all tests with the race detector explicitly
	@echo "$(GREEN)Running tests with race detector...$(RESET)"
	@go test -race ./...
	@echo "$(GREEN)✓ Race detector tests complete$(RESET)"

.PHONY: coverage
coverage: ## Generate test coverage report
	@echo "$(GREEN)Generating coverage report...$(RESET)"
	@go test -coverprofile=coverage.out $(shell go list ./... | grep -v vendor)
	@go tool cover -func=coverage.out
	@echo "$(GREEN)✓ Coverage report generated$(RESET)"

.PHONY: coverage-html
coverage-html: coverage ## Generate and open HTML coverage report
	@echo "$(GREEN)Opening HTML coverage report...$(RESET)"
	@go tool cover -html=coverage.out

.PHONY: test-all
test-all: test coverage ## Run all tests and generate coverage report
	@echo "$(GREEN)✓ All tests and coverage complete$(RESET)"

.PHONY: report
report: coverage-html ## Alias for coverage-html (backwards compatibility)

##@ Code Quality

.PHONY: fmt
fmt: ## Format all Go source files
	@echo "$(GREEN)Formatting code...$(RESET)"
	@go fmt $(shell go list ./... | grep -v vendor)
	@echo "$(GREEN)✓ Code formatted$(RESET)"

.PHONY: vet
vet: ## Run go vet on all source files
	@echo "$(GREEN)Running go vet...$(RESET)"
	@go vet $(shell go list ./... | grep -v vendor)
	@echo "$(GREEN)✓ Vet analysis complete$(RESET)"

.PHONY: lint
lint: fmt vet ## Run fmt and vet

.PHONY: govulncheck
govulncheck: ## Run vulnerability check on dependencies
	@echo "$(GREEN)Checking for vulnerabilities...$(RESET)"
	@command -v govulncheck >/dev/null 2>&1 || { \
		echo "$(YELLOW)Installing govulncheck...$(RESET)"; \
		go install golang.org/x/vuln/cmd/govulncheck@latest; \
	}
	@govulncheck $(shell go list ./... | grep -v vendor)
	@echo "$(GREEN)✓ Vulnerability check complete$(RESET)"

.PHONY: gosec
gosec: ## Run security scanner on source code
	@echo "$(GREEN)Running security scan...$(RESET)"
	@command -v gosec >/dev/null 2>&1 || { \
		echo "$(YELLOW)Installing gosec...$(RESET)"; \
		go install github.com/securego/gosec/v2/cmd/gosec@latest; \
	}
	@gosec -fmt text ./...
	@echo "$(GREEN)✓ Security scan complete$(RESET)"

.PHONY: staticcheck
staticcheck: ## Run staticcheck static analysis
	@echo "$(GREEN)Running staticcheck...$(RESET)"
	@command -v staticcheck >/dev/null 2>&1 || { \
		echo "$(YELLOW)Installing staticcheck...$(RESET)"; \
		go install honnef.co/go/tools/cmd/staticcheck@latest; \
	}
	@staticcheck $(shell go list ./... | grep -v vendor)
	@echo "$(GREEN)✓ Staticcheck analysis complete$(RESET)"

.PHONY: trivy
trivy: ## Run Trivy container and dependency scanner
	@echo "$(GREEN)Running Trivy scan...$(RESET)"
	@command -v trivy >/dev/null 2>&1 || { \
		echo "$(YELLOW)Trivy not found. Please install it:$(RESET)"; \
		echo "$(CYAN)  brew install trivy$(RESET) (macOS)"; \
		echo "$(CYAN)  apt-get install trivy$(RESET) (Debian/Ubuntu)"; \
		echo "$(CYAN)  Or visit: https://aquasecurity.github.io/trivy$(RESET)"; \
		exit 1; \
	}
	@trivy fs --scanners vuln,misconfig,secret --severity HIGH,CRITICAL --skip-dirs vendor .
	@echo "$(GREEN)✓ Trivy scan complete$(RESET)"

.PHONY: security
security: govulncheck gosec trivy ## Run all security scans (govulncheck, gosec, trivy)
	@echo "$(GREEN)✓ All security scans complete$(RESET)"

.PHONY: check
check: lint vet staticcheck test test-engine-lib ## Run basic checks (lint, vet, staticcheck, tests)
	@echo "$(GREEN)✓ Basic checks passed$(RESET)"

.PHONY: check-all
check-all: lint vet test-all ## Run all checks (lint, vet, tests with coverage)
	@echo "$(GREEN)✓ All checks passed$(RESET)"

##@ Cleanup

.PHONY: clean
clean: ## Clean build artifacts and test cache
	@echo "$(YELLOW)Cleaning up...$(RESET)"
	@rm -f $(BINARY_NAME) $(BINARY_NAME)-*
	@rm -f coverage.out coverage.html test.cov
	@rm -rf artifacts/
	@rm -rf $(RELEASE_ROOT)/
	@rm -rf safe-*/
	@go clean -testcache
	@echo "$(GREEN)✓ Cleanup complete$(RESET)"

##@ Release

.PHONY: release-all
release-all: ## Build versioned binaries into release/ (requires VERSION; this is what ci/scripts/build calls)
	@echo "$(BLUE)Building $(PROJECT) $(VERSION) release binaries...$(RESET)"
	@case "$(VERSION)" in */*) \
		echo "$(RED)ERROR: VERSION must be a release version, not $(VERSION)$(RESET)"; exit 1;; \
	esac
	@mkdir -p $(RELEASE_ROOT)
	@GOOS=linux   GOARCH=amd64 go build -ldflags="$(LDFLAGS)" -o $(RELEASE_ROOT)/$(PROJECT)-$(VERSION)-linux-amd64 ./cmd/safe
	@GOOS=linux   GOARCH=arm64 go build -ldflags="$(LDFLAGS)" -o $(RELEASE_ROOT)/$(PROJECT)-$(VERSION)-linux-arm64 ./cmd/safe
	@GOOS=darwin  GOARCH=amd64 go build -ldflags="$(LDFLAGS)" -o $(RELEASE_ROOT)/$(PROJECT)-$(VERSION)-darwin-amd64 ./cmd/safe
	@GOOS=darwin  GOARCH=arm64 go build -ldflags="$(LDFLAGS)" -o $(RELEASE_ROOT)/$(PROJECT)-$(VERSION)-darwin-arm64 ./cmd/safe
	@GOOS=windows GOARCH=amd64 go build -ldflags="$(LDFLAGS)" -o $(RELEASE_ROOT)/$(PROJECT)-$(VERSION)-windows-amd64.exe ./cmd/safe
	@ls -la $(RELEASE_ROOT)
	@echo "$(GREEN)✓ Release binaries built in $(RELEASE_ROOT)/$(RESET)"

.PHONY: shipit
shipit: ## Build release artifacts (requires VERSION env var)
	@echo "$(BLUE)Preparing release...$(RESET)"
	@echo "Checking that VERSION was defined in the calling environment"
	@test -n "$(VERSION)" || { echo "$(RED)ERROR: VERSION not set$(RESET)"; exit 1; }
	@echo "$(GREEN)OK. VERSION=$(VERSION)$(RESET)"

	@echo "$(GREEN)Compiling safe binaries...$(RESET)"
	@rm -rf artifacts
	@mkdir artifacts
	@GOOS=linux  GOARCH=amd64 go build -ldflags="$(LDFLAGS)" -o artifacts/safe-linux-amd64 ./cmd/safe
	@GOOS=linux  GOARCH=arm64 go build -ldflags="$(LDFLAGS)" -o artifacts/safe-linux-arm64 ./cmd/safe
	@GOOS=darwin GOARCH=amd64 go build -ldflags="$(LDFLAGS)" -o artifacts/safe-darwin-amd64 ./cmd/safe
	@GOOS=darwin GOARCH=arm64 go build -ldflags="$(LDFLAGS)" -o artifacts/safe-darwin-arm64 ./cmd/safe
	@GOOS=windows GOARCH=amd64 go build -ldflags="$(LDFLAGS)" -o artifacts/safe-windows-amd64.exe ./cmd/safe

	@echo "$(GREEN)Assembling Distribution with platform binaries...$(RESET)"
	@rm -f artifacts/*.tar.gz artifacts/*.tar.bz2
	@rm -rf safe-$(VERSION)
	@mkdir -p safe-$(VERSION)
	@cp artifacts/safe-linux-amd64 safe-$(VERSION)/safe-linux-amd64
	@cp artifacts/safe-linux-arm64 safe-$(VERSION)/safe-linux-arm64
	@cp artifacts/safe-darwin-amd64 safe-$(VERSION)/safe-darwin-amd64
	@cp artifacts/safe-darwin-arm64 safe-$(VERSION)/safe-darwin-arm64
	@cp artifacts/safe-windows-amd64.exe safe-$(VERSION)/safe-windows-amd64.exe
	@tar -cf - safe-$(VERSION)/ | gzip -9 > artifacts/safe-$(VERSION).tar.gz
	@tar -cjf artifacts/safe-$(VERSION).tar.bz2 safe-$(VERSION)/
	@rm -rf safe-$(VERSION)
	@echo "$(GREEN)✓ Release artifacts built successfully$(RESET)"

.PHONY: version
version: ## Display the current version
	@echo "$(CYAN)Version: $(VERSION)$(RESET)"

##@ Installation

.PHONY: install
install: build ## Install safe binary to /usr/local/bin (requires sudo)
	@echo "$(GREEN)Installing $(BINARY_NAME) to /usr/local/bin...$(RESET)"
	@sudo cp $(BINARY_NAME) /usr/local/bin/$(BINARY_NAME)
	@sudo chmod +x /usr/local/bin/$(BINARY_NAME)
	@echo "$(GREEN)✓ Installation complete$(RESET)"

.PHONY: install-user
install-user: build ## Install safe binary to ~/bin
	@echo "$(GREEN)Installing $(BINARY_NAME) to ~/bin...$(RESET)"
	@mkdir -p ~/bin
	@cp $(BINARY_NAME) ~/bin/$(BINARY_NAME)
	@chmod +x ~/bin/$(BINARY_NAME)
	@echo "$(GREEN)✓ Installation complete to ~/bin$(RESET)"
	@echo "$(YELLOW)Make sure ~/bin is in your PATH$(RESET)"

##@ Dependencies

.PHONY: deps
deps: ## Download and verify dependencies
	@echo "$(GREEN)Downloading dependencies...$(RESET)"
	@go mod download
	@go mod verify
	@echo "$(GREEN)✓ Dependencies ready$(RESET)"

.PHONY: deps-update
deps-update: ## Update all dependencies to latest versions
	@echo "$(GREEN)Updating dependencies...$(RESET)"
	@go get -u ./...
	@go mod tidy
	@echo "$(GREEN)✓ Dependencies updated$(RESET)"

.PHONY: deps-tidy
deps-tidy: ## Clean up go.mod and go.sum
	@echo "$(GREEN)Tidying dependencies...$(RESET)"
	@go mod tidy
	@echo "$(GREEN)✓ Dependencies tidied$(RESET)"

# Include all phony targets
.PHONY: build linux linux-arm64 darwin darwin-arm64 windows build-all test test-short test-race test-integration test-engine-lib test-all coverage coverage-html report fmt vet lint \
        govulncheck gosec staticcheck trivy security check check-all clean shipit version install install-user deps deps-update deps-tidy help
