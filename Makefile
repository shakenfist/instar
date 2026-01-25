# Imago Project Makefile
#
# Usage: make <target> [PROTOTYPE=<name>]
#
# Examples:
#   make imago                            # Build the main imago project
#   make build-prototype PROTOTYPE=info   # Build a specific prototype
#   make clean-all
#   make lint
#

.PHONY: help list-prototypes build-prototype build-all clean-prototype clean-all \
        clean-devcontainers lint lint-fix build-lint-container \
        install-hooks run-prototype guest-protocol \
        imago imago-devcontainer clean-imago run-imago \
        test-venv test test-ci test-malicious test-report clean-tests \
        clean-cargo-cache

# Default target
help:
	@echo "Imago Project Makefile"
	@echo ""
	@echo "Usage: make <target> [PROTOTYPE=<name>]"
	@echo ""
	@echo "Targets:"
	@echo "  help                 Show this help message"
	@echo "  list-prototypes      List all available prototypes"
	@echo ""
	@echo "Main Project (src/):"
	@echo "  imago                Build the main imago project"
	@echo "  imago-devcontainer   Build devcontainer for main imago"
	@echo "  clean-imago          Clean the main imago build"
	@echo "  run-imago            Show how to run imago"
	@echo ""
	@echo "Prototypes:"
	@echo "  build-prototype              Build a prototype (requires PROTOTYPE=<name>)"
	@echo "  build-all                    Build all prototypes"
	@echo "  clean-prototype              Clean a prototype's build (requires PROTOTYPE=<name>)"
	@echo "  run-prototype                Run a prototype (requires PROTOTYPE=<name>)"
	@echo ""
	@echo "Shared:"
	@echo "  guest-protocol       Build the shared guest-protocol crate"
	@echo "  build-lint-container Build the rust-lint Docker container"
	@echo ""
	@echo "Cleaning:"
	@echo "  clean-all            Clean all build directories (main + prototypes)"
	@echo "  clean-devcontainers  Remove all devcontainer images"
	@echo "  clean-lint-container Remove the rust-lint Docker image"
	@echo "  clean-cargo-cache    Remove cached cargo registry directory"
	@echo "  distclean            Remove everything (all targets + all containers)"
	@echo ""
	@echo "Linting:"
	@echo "  lint                 Run rustfmt and clippy checks"
	@echo "  lint-fix             Run rustfmt and clippy with auto-fix"
	@echo "  install-hooks        Install pre-commit hooks"
	@echo ""
	@echo "Testing:"
	@echo "  test-venv            Create Python venv for tests"
	@echo "  test                 Run safe integration tests"
	@echo "  test-ci              Run CI-suitable tests (safe + caution)"
	@echo "  test-malicious       Run all tests including malicious images"
	@echo "  test-report          Show test differences without failing"
	@echo "  clean-tests          Clean test artifacts"
	@echo ""
	@echo "Examples:"
	@echo "  make imago"
	@echo "  make build-prototype PROTOTYPE=virtio-block5"
	@echo "  make run-prototype PROTOTYPE=virtio-block5"
	@echo "  make clean-prototype PROTOTYPE=helloworld"
	@echo "  make lint"

# List of all prototypes
PROTOTYPES := \
	helloworld \
	helloworld2 \
	virtio-block \
	virtio-block2 \
	virtio-block3 \
	virtio-block4 \
	virtio-block5 \
	virtio-block6 \
	pluggable \
	pluggable2 \
	info

# Docker image names
LINT_IMAGE := imago-rust-lint
IMAGO_IMAGE := imago-build

# Paths
SRC_DIR := src
PROTO_DIR := prototypes
SCRIPTS_DIR := scripts
DEVCONTAINER_DIR := .devcontainer
CARGO_CACHE_DIR := .cargo-cache

# =============================================================================
# Main Imago Project Targets
# =============================================================================

# Build the main imago project (runs inside devcontainer)
imago: imago-devcontainer
	@echo "Building imago..."
	@mkdir -p "$(CURDIR)/$(CARGO_CACHE_DIR)/registry" "$(CURDIR)/$(CARGO_CACHE_DIR)/git"
	docker run --rm \
		-u "$(shell id -u):$(shell id -g)" \
		-e HOME=/build \
		-e CARGO_HOME=/build/.cargo \
		-v "$(CURDIR):/workspace" \
		-v "$(CURDIR)/$(CARGO_CACHE_DIR)/registry:/build/.cargo/registry" \
		-v "$(CURDIR)/$(CARGO_CACHE_DIR)/git:/build/.cargo/git" \
		-w "/workspace/$(SRC_DIR)" \
		"$(IMAGO_IMAGE)" \
		bash build.sh

# Build the imago devcontainer
imago-devcontainer:
	@if ! docker image inspect "$(IMAGO_IMAGE)" >/dev/null 2>&1; then \
		echo "Building imago devcontainer image..."; \
		docker build -t "$(IMAGO_IMAGE)" "$(SRC_DIR)/$(DEVCONTAINER_DIR)"; \
	fi

# Clean the main imago build
clean-imago:
	@echo "Cleaning imago build..."
	@if docker image inspect "$(IMAGO_IMAGE)" >/dev/null 2>&1; then \
		echo "Using container to clean (handles root-owned files)..."; \
		docker run --rm \
			-v "$(CURDIR):/workspace" \
			-w "/workspace/$(SRC_DIR)" \
			"$(IMAGO_IMAGE)" \
			sh -c "rm -rf target *.bin"; \
	else \
		rm -rf "$(SRC_DIR)/target" 2>/dev/null || true; \
		find "$(SRC_DIR)" -maxdepth 1 -name "*.bin" -delete 2>/dev/null || true; \
	fi
	@echo "Clean complete."

# Show how to run imago
run-imago:
	@echo "Running imago"
	@echo ""
	@if [ ! -f "$(SRC_DIR)/target/release/imago" ]; then \
		echo "Error: imago not built. Run 'make imago' first."; \
		exit 1; \
	fi
	@echo "Note: Running requires KVM access (sudo or kvm group membership)"
	@echo ""
	@echo "Usage:"
	@echo "  sudo $(SRC_DIR)/target/release/imago info <IMAGE>"
	@echo "  sudo $(SRC_DIR)/target/release/imago copy <INPUT> <OUTPUT>"
	@echo ""
	@echo "For help:"
	@echo "  $(SRC_DIR)/target/release/imago --help"

# =============================================================================
# Prototype Targets
# =============================================================================

# List all available prototypes
list-prototypes:
	@echo "Available prototypes:"
	@for p in $(PROTOTYPES); do \
		if [ -d "$(PROTO_DIR)/$$p" ]; then \
			echo "  $$p"; \
		fi; \
	done

# Validate PROTOTYPE variable is set
.PHONY: check-prototype
check-prototype:
ifndef PROTOTYPE
	$(error PROTOTYPE is not set. Use: make <target> PROTOTYPE=<name>)
endif
ifeq ($(filter $(PROTOTYPE),$(PROTOTYPES)),)
	$(error Invalid PROTOTYPE '$(PROTOTYPE)'. Run 'make list-prototypes' to see available options)
endif

# Build a specific prototype (uses shared devcontainer)
build-prototype: check-prototype imago-devcontainer
	@echo "Building prototype: $(PROTOTYPE)"
	@if [ ! -f "$(PROTO_DIR)/$(PROTOTYPE)/build.sh" ]; then \
		echo "Error: build.sh not found for $(PROTOTYPE)"; \
		exit 1; \
	fi
	@mkdir -p "$(CURDIR)/$(CARGO_CACHE_DIR)/registry" "$(CURDIR)/$(CARGO_CACHE_DIR)/git"
	docker run --rm \
		-u "$(shell id -u):$(shell id -g)" \
		-e HOME=/build \
		-e CARGO_HOME=/build/.cargo \
		-v "$(CURDIR):/workspace" \
		-v "$(CURDIR)/$(CARGO_CACHE_DIR)/registry:/build/.cargo/registry" \
		-v "$(CURDIR)/$(CARGO_CACHE_DIR)/git:/build/.cargo/git" \
		-w "/workspace/$(PROTO_DIR)/$(PROTOTYPE)" \
		"$(IMAGO_IMAGE)" \
		bash build.sh

# Build all prototypes (uses shared devcontainer)
build-all:
	@echo "Building all prototypes..."
	@for p in $(PROTOTYPES); do \
		if [ -d "$(PROTO_DIR)/$$p" ] && [ -f "$(PROTO_DIR)/$$p/build.sh" ]; then \
			echo ""; \
			echo "=== Building $$p ==="; \
			$(MAKE) build-prototype PROTOTYPE=$$p || exit 1; \
		fi; \
	done
	@echo ""
	@echo "All prototypes built successfully."

# Build the shared guest-protocol crate
guest-protocol:
	@echo "Building guest-protocol crate..."
	cd crates/guest-protocol && cargo build --release

# Build the rust-lint container
build-lint-container:
	@echo "Building rust-lint container..."
	docker build -t $(LINT_IMAGE) $(DEVCONTAINER_DIR)/rust-lint

# Clean target directory for a specific prototype
# Uses shared devcontainer to handle root-owned files from builds
clean-prototype: check-prototype
	@echo "Cleaning target directory for: $(PROTOTYPE)"
	@if docker image inspect "$(IMAGO_IMAGE)" >/dev/null 2>&1; then \
		echo "Using container to clean (handles root-owned files)..."; \
		docker run --rm \
			-v "$(CURDIR):/workspace" \
			-w "/workspace/$(PROTO_DIR)/$(PROTOTYPE)" \
			"$(IMAGO_IMAGE)" \
			sh -c "rm -rf target *.bin"; \
		echo "Cleaned $(PROTO_DIR)/$(PROTOTYPE)"; \
	else \
		if [ -d "$(PROTO_DIR)/$(PROTOTYPE)/target" ]; then \
			rm -rf "$(PROTO_DIR)/$(PROTOTYPE)/target"; \
			echo "Removed $(PROTO_DIR)/$(PROTOTYPE)/target"; \
		else \
			echo "No target directory found for $(PROTOTYPE)"; \
		fi; \
		find "$(PROTO_DIR)/$(PROTOTYPE)" -maxdepth 1 -name "*.bin" -delete 2>/dev/null || true; \
	fi

# Clean all build directories (main imago + prototypes)
# Uses shared devcontainer to handle root-owned files
clean-all: clean-imago
	@echo "Cleaning all prototype target directories..."
	@if docker image inspect "$(IMAGO_IMAGE)" >/dev/null 2>&1; then \
		for p in $(PROTOTYPES); do \
			if [ -d "$(PROTO_DIR)/$$p" ]; then \
				echo "Cleaning $$p (via container)..."; \
				docker run --rm \
					-v "$(CURDIR):/workspace" \
					-w "/workspace/$(PROTO_DIR)/$$p" \
					"$(IMAGO_IMAGE)" \
					sh -c "rm -rf target *.bin" 2>/dev/null || true; \
			fi; \
		done; \
	else \
		for p in $(PROTOTYPES); do \
			if [ -d "$(PROTO_DIR)/$$p/target" ]; then \
				rm -rf "$(PROTO_DIR)/$$p/target" 2>/dev/null || \
					echo "Warning: Could not remove $(PROTO_DIR)/$$p/target (try: sudo rm -rf)"; \
			fi; \
			find "$(PROTO_DIR)/$$p" -maxdepth 1 -name "*.bin" -delete 2>/dev/null || true; \
		done; \
	fi
	@echo "Clean complete."

# Remove devcontainer image
clean-devcontainers:
	@echo "Removing devcontainer image..."
	@if docker image inspect "$(IMAGO_IMAGE)" >/dev/null 2>&1; then \
		docker rmi "$(IMAGO_IMAGE)" || true; \
		echo "Removed $(IMAGO_IMAGE)"; \
	else \
		echo "$(IMAGO_IMAGE) not found"; \
	fi

# Remove the rust-lint Docker image
clean-lint-container:
	@echo "Removing rust-lint container..."
	@if docker image inspect $(LINT_IMAGE) >/dev/null 2>&1; then \
		docker rmi $(LINT_IMAGE) || true; \
		echo "Removed $(LINT_IMAGE)"; \
	else \
		echo "$(LINT_IMAGE) not found"; \
	fi

# Remove cached cargo registry directory
clean-cargo-cache:
	@echo "Removing cargo cache directory..."
	rm -rf "$(CURDIR)/$(CARGO_CACHE_DIR)"
	@echo "Removed $(CARGO_CACHE_DIR)"

# Remove everything
distclean: clean-all clean-devcontainers clean-lint-container clean-cargo-cache
	@echo "Distclean complete."

# Run rustfmt and clippy checks
lint: build-lint-container
	@echo "Running lint checks..."
	$(SCRIPTS_DIR)/check-rust.sh check

# Run rustfmt and clippy with auto-fix
lint-fix: build-lint-container
	@echo "Running lint fixes..."
	$(SCRIPTS_DIR)/check-rust.sh fix

# Install pre-commit hooks
install-hooks:
	@echo "Installing pre-commit hooks..."
	@if command -v pre-commit >/dev/null 2>&1; then \
		pre-commit install; \
		echo "Pre-commit hooks installed."; \
	else \
		echo "Error: pre-commit not found. Install with: pip install pre-commit"; \
		exit 1; \
	fi

# Run a prototype (requires KVM access)
run-prototype: check-prototype
	@echo "Running prototype: $(PROTOTYPE)"
	@if [ ! -f "$(PROTO_DIR)/$(PROTOTYPE)/target/release/vmm" ]; then \
		echo "Error: VMM not built. Run 'make build-prototype PROTOTYPE=$(PROTOTYPE)' first."; \
		exit 1; \
	fi
	@if [ ! -f "$(PROTO_DIR)/$(PROTOTYPE)/guest.bin" ]; then \
		echo "Error: guest.bin not found. Run 'make build-prototype PROTOTYPE=$(PROTOTYPE)' first."; \
		exit 1; \
	fi
	@echo "Note: Running requires KVM access (sudo or kvm group membership)"
	@echo "Command: sudo $(PROTO_DIR)/$(PROTOTYPE)/target/release/vmm $(PROTO_DIR)/$(PROTOTYPE)/guest.bin"
	@echo ""
	@echo "For virtio-block prototypes, additional arguments may be needed."
	@echo "See $(PROTO_DIR)/$(PROTOTYPE)/README.md for usage details."

# =============================================================================
# Integration Test Targets
# =============================================================================

TESTS_DIR := tests
PYTHON := python3
VENV_DIR := $(TESTS_DIR)/.venv

# Create virtual environment for tests
test-venv:
	@echo "Creating Python virtual environment for tests..."
	@if [ ! -d "$(VENV_DIR)" ]; then \
		$(PYTHON) -m venv $(VENV_DIR); \
	fi
	@$(VENV_DIR)/bin/pip install -q -r $(TESTS_DIR)/requirements.txt
	@echo "Virtual environment ready at $(VENV_DIR)"

# Run safe integration tests only
test: imago test-venv
	@echo "Running safe integration tests..."
	cd $(TESTS_DIR) && ../$(VENV_DIR)/bin/stestr run test_info_safe

# Run CI-suitable tests (safe + caution)
test-ci: imago test-venv
	@echo "Running CI tests (safe images)..."
	cd $(TESTS_DIR) && ../$(VENV_DIR)/bin/stestr run "test_info_safe"

# Run all tests including malicious (explicit opt-in)
test-malicious: imago test-venv
	@echo "WARNING: Running tests including malicious images"
	@echo "This will process known malicious disk images."
	@echo ""
	cd $(TESTS_DIR) && ../$(VENV_DIR)/bin/stestr run

# Run tests and show output (useful for seeing diffs during development)
test-report: imago test-venv
	@echo "Running tests with verbose output..."
	cd $(TESTS_DIR) && ../$(VENV_DIR)/bin/stestr run --serial -- --verbose

# Clean test artifacts
clean-tests:
	@echo "Cleaning test artifacts..."
	rm -rf $(TESTS_DIR)/.venv
	rm -rf $(TESTS_DIR)/__pycache__
	rm -rf $(TESTS_DIR)/helpers/__pycache__
	rm -rf $(TESTS_DIR)/.stestr
	@echo "Test cleanup complete."
