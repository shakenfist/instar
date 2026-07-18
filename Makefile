# Instar Project Makefile
#
# Usage: make <target> [PROTOTYPE=<name>]
#
# Examples:
#   make instar                            # Build the main instar project
#   make build-prototype PROTOTYPE=info   # Build a specific prototype
#   make clean-all
#   make lint
#

.PHONY: help list-prototypes build-prototype build-all clean-prototype clean-all \
        clean-devcontainers lint lint-fix build-lint-container \
        install-hooks run-prototype guest-protocol \
        instar instar-devcontainer clean-instar run-instar check-binary-sizes \
        metadata audit deb rpm package \
        test-venv test test-rust test-integration test-ci test-malicious test-report clean-tests \
        fuzz-build fuzz-run snapshot-harnesses \
        test-container test-container-core test-container-convert-qcow2 test-container-convert-vhd \
        clean-cargo-cache release check-version

# Default target
help:
	@echo "Instar Project Makefile"
	@echo ""
	@echo "Usage: make <target> [PROTOTYPE=<name>]"
	@echo ""
	@echo "Targets:"
	@echo "  help                 Show this help message"
	@echo "  list-prototypes      List all available prototypes"
	@echo ""
	@echo "Main Project (src/):"
	@echo "  instar                Build the main instar project"
	@echo "  instar-devcontainer   Build devcontainer for main instar"
	@echo "  clean-instar          Clean the main instar build"
	@echo "  run-instar            Show how to run instar"
	@echo "  check-binary-sizes   Verify binaries fit within memory regions"
	@echo "  metadata             Validate workspace Cargo.toml manifests parse"
	@echo "  audit                Run cargo audit against the workspace"
	@echo "  deb                  Build a Debian (.deb) package (requires 'make instar' first)"
	@echo "  rpm                  Build an RPM (.rpm) package (requires 'make instar' first)"
	@echo "  package              Build both .deb and .rpm packages"
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
	@echo "Release:"
	@echo "  release VERSION=x.y.z  Bump versions, commit, and tag a release"
	@echo "  check-version          Verify Cargo.toml versions match a git tag"
	@echo ""
	@echo "Testing:"
	@echo "  test-venv            Create Python venv for tests"
	@echo "  test                 Run all tests (Rust unit + Python integration)"
	@echo "  test-rust            Run Rust unit tests only"
	@echo "  test-integration     Run Python integration tests only (on host)"
	@echo "  test-container       Run all tests inside container"
	@echo "  test-container-core  Run core tests (info, check, security) inside container"
	@echo "  test-container-convert-qcow2  Run QCOW2/VMDK/RAW convert tests inside container"
	@echo "  test-container-convert-vhd    Run VHD/VHDX convert tests inside container"
	@echo "  test-ci              Run CI-suitable tests (safe + caution)"
	@echo "  test-malicious       Run all tests including malicious images"
	@echo "  snapshot-harnesses   Run the seven snapshot shell harnesses (needs /dev/kvm)"
	@echo "  test-report          Show test differences without failing"
	@echo "  clean-tests          Clean test artifacts"
	@echo ""
	@echo "Examples:"
	@echo "  make instar"
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
LINT_IMAGE := instar-rust-lint
INSTAR_IMAGE := instar-build

# Paths
SRC_DIR := src
PROTO_DIR := prototypes
SCRIPTS_DIR := scripts
DEVCONTAINER_DIR := .devcontainer
CARGO_CACHE_DIR := .cargo-cache

# =============================================================================
# Main Instar Project Targets
# =============================================================================

# Build the main instar project (runs inside devcontainer)
instar: instar-devcontainer
	@echo "Building instar..."
	@mkdir -p "$(CURDIR)/$(CARGO_CACHE_DIR)/registry" "$(CURDIR)/$(CARGO_CACHE_DIR)/git"
	docker run --rm \
		-u "$(shell id -u):$(shell id -g)" \
		-e HOME=/build \
		-e CARGO_HOME=/build/.cargo \
		-v "$(CURDIR):/workspace" \
		-v "$(CURDIR)/$(CARGO_CACHE_DIR)/registry:/build/.cargo/registry" \
		-v "$(CURDIR)/$(CARGO_CACHE_DIR)/git:/build/.cargo/git" \
		-w "/workspace/$(SRC_DIR)" \
		"$(INSTAR_IMAGE)" \
		bash build.sh

# Build the instar devcontainer
instar-devcontainer:
	@if ! docker image inspect "$(INSTAR_IMAGE)" >/dev/null 2>&1; then \
		echo "Building instar devcontainer image..."; \
		docker build -t "$(INSTAR_IMAGE)" "$(SRC_DIR)/$(DEVCONTAINER_DIR)"; \
	fi

# Validate workspace Cargo.toml manifests parse cleanly. Fast manifest-only
# check (no compilation) suitable for quick local validation after editing
# Cargo.toml files.
metadata: instar-devcontainer
	@echo "Validating workspace manifests..."
	@mkdir -p "$(CURDIR)/$(CARGO_CACHE_DIR)/registry" "$(CURDIR)/$(CARGO_CACHE_DIR)/git"
	docker run --rm \
		-u "$(shell id -u):$(shell id -g)" \
		-e HOME=/build \
		-e CARGO_HOME=/build/.cargo \
		-v "$(CURDIR):/workspace" \
		-v "$(CURDIR)/$(CARGO_CACHE_DIR)/registry:/build/.cargo/registry" \
		-v "$(CURDIR)/$(CARGO_CACHE_DIR)/git:/build/.cargo/git" \
		-w "/workspace/$(SRC_DIR)" \
		"$(INSTAR_IMAGE)" \
		cargo metadata --format-version 1 --no-deps >/dev/null
	@echo "Workspace manifests OK."

# Run cargo audit against the workspace dependency tree. Reports
# any open RUSTSEC advisories, exits non-zero on any vulnerability.
# Used as part of the pre-release audit checklist.
audit: instar-devcontainer
	@echo "Running cargo audit..."
	@mkdir -p "$(CURDIR)/$(CARGO_CACHE_DIR)/registry" "$(CURDIR)/$(CARGO_CACHE_DIR)/git"
	docker run --rm \
		-u "$(shell id -u):$(shell id -g)" \
		-e HOME=/build \
		-e CARGO_HOME=/build/.cargo \
		-v "$(CURDIR):/workspace" \
		-v "$(CURDIR)/$(CARGO_CACHE_DIR)/registry:/build/.cargo/registry" \
		-v "$(CURDIR)/$(CARGO_CACHE_DIR)/git:/build/.cargo/git" \
		-w "/workspace/$(SRC_DIR)" \
		"$(INSTAR_IMAGE)" \
		cargo audit

# Build a Debian package from the artifacts produced by `make instar`.
# Runs cargo-deb inside the devcontainer with --no-build so no
# compilation happens here -- run `make instar` first. Output:
# src/target/debian/instar_*.deb
deb: instar-devcontainer
	@if [ ! -f "$(SRC_DIR)/target/release/instar" ] || \
	    [ ! -f "$(SRC_DIR)/target/release/core.bin" ]; then \
	    echo "Error: build artifacts missing. Run 'make instar' first."; \
	    exit 1; \
	fi
	@echo "Building .deb package..."
	@mkdir -p "$(CURDIR)/$(CARGO_CACHE_DIR)/registry" "$(CURDIR)/$(CARGO_CACHE_DIR)/git"
	docker run --rm \
		-u "$(shell id -u):$(shell id -g)" \
		-e HOME=/build \
		-e CARGO_HOME=/build/.cargo \
		-v "$(CURDIR):/workspace" \
		-v "$(CURDIR)/$(CARGO_CACHE_DIR)/registry:/build/.cargo/registry" \
		-v "$(CURDIR)/$(CARGO_CACHE_DIR)/git:/build/.cargo/git" \
		-w "/workspace/$(SRC_DIR)" \
		"$(INSTAR_IMAGE)" \
		cargo deb --no-build -p instar
	@echo ""
	@ls -la "$(SRC_DIR)/target/debian/"*.deb

# Build an RPM package from the artifacts produced by `make instar`.
# Runs cargo-generate-rpm inside the devcontainer; like cargo-deb it
# does not compile, only package. Output:
# src/target/generate-rpm/instar-*.rpm
rpm: instar-devcontainer
	@if [ ! -f "$(SRC_DIR)/target/release/instar" ] || \
	    [ ! -f "$(SRC_DIR)/target/release/core.bin" ]; then \
	    echo "Error: build artifacts missing. Run 'make instar' first."; \
	    exit 1; \
	fi
	@echo "Building .rpm package..."
	@mkdir -p "$(CURDIR)/$(CARGO_CACHE_DIR)/registry" "$(CURDIR)/$(CARGO_CACHE_DIR)/git"
	docker run --rm \
		-u "$(shell id -u):$(shell id -g)" \
		-e HOME=/build \
		-e CARGO_HOME=/build/.cargo \
		-v "$(CURDIR):/workspace" \
		-v "$(CURDIR)/$(CARGO_CACHE_DIR)/registry:/build/.cargo/registry" \
		-v "$(CURDIR)/$(CARGO_CACHE_DIR)/git:/build/.cargo/git" \
		-w "/workspace/$(SRC_DIR)" \
		"$(INSTAR_IMAGE)" \
		cargo generate-rpm -p vmm
	@echo ""
	@ls -la "$(SRC_DIR)/target/generate-rpm/"*.rpm

# Build both Linux package formats.
package: deb rpm

# Clean the main instar build
clean-instar:
	@echo "Cleaning instar build..."
	@if docker image inspect "$(INSTAR_IMAGE)" >/dev/null 2>&1; then \
		echo "Using container to clean (handles root-owned files)..."; \
		docker run --rm \
			-v "$(CURDIR):/workspace" \
			-w "/workspace/$(SRC_DIR)" \
			"$(INSTAR_IMAGE)" \
			sh -c "rm -rf target *.bin"; \
	else \
		rm -rf "$(SRC_DIR)/target" 2>/dev/null || true; \
		find "$(SRC_DIR)" -maxdepth 1 -name "*.bin" -delete 2>/dev/null || true; \
	fi
	@echo "Clean complete."

# Show how to run instar
run-instar:
	@echo "Running instar"
	@echo ""
	@if [ ! -f "$(SRC_DIR)/target/release/instar" ]; then \
		echo "Error: instar not built. Run 'make instar' first."; \
		exit 1; \
	fi
	@echo "Note: Running requires KVM access (sudo or kvm group membership)"
	@echo ""
	@echo "Usage:"
	@echo "  sudo $(SRC_DIR)/target/release/instar info <IMAGE>"
	@echo "  sudo $(SRC_DIR)/target/release/instar copy <INPUT> <OUTPUT>"
	@echo ""
	@echo "For help:"
	@echo "  $(SRC_DIR)/target/release/instar --help"

# Check that guest binaries fit within their memory regions
# This prevents memory overlap bugs that cause VM crashes
check-binary-sizes:
	@./scripts/check-binary-sizes.sh

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
build-prototype: check-prototype instar-devcontainer
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
		"$(INSTAR_IMAGE)" \
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
guest-protocol: instar-devcontainer
	@echo "Building guest-protocol crate..."
	@mkdir -p "$(CURDIR)/$(CARGO_CACHE_DIR)/registry" "$(CURDIR)/$(CARGO_CACHE_DIR)/git"
	docker run --rm \
		-u "$(shell id -u):$(shell id -g)" \
		-e HOME=/build \
		-e CARGO_HOME=/build/.cargo \
		-v "$(CURDIR):/workspace" \
		-v "$(CURDIR)/$(CARGO_CACHE_DIR)/registry:/build/.cargo/registry" \
		-v "$(CURDIR)/$(CARGO_CACHE_DIR)/git:/build/.cargo/git" \
		-w "/workspace/crates/guest-protocol" \
		"$(INSTAR_IMAGE)" \
		cargo build --release

# Build the rust-lint container
build-lint-container:
	@echo "Building rust-lint container..."
	docker build -t $(LINT_IMAGE) $(DEVCONTAINER_DIR)/rust-lint

# Clean target directory for a specific prototype
# Uses shared devcontainer to handle root-owned files from builds
clean-prototype: check-prototype
	@echo "Cleaning target directory for: $(PROTOTYPE)"
	@if docker image inspect "$(INSTAR_IMAGE)" >/dev/null 2>&1; then \
		echo "Using container to clean (handles root-owned files)..."; \
		docker run --rm \
			-v "$(CURDIR):/workspace" \
			-w "/workspace/$(PROTO_DIR)/$(PROTOTYPE)" \
			"$(INSTAR_IMAGE)" \
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

# Clean all build directories (main instar + prototypes)
# Uses shared devcontainer to handle root-owned files
clean-all: clean-instar
	@echo "Cleaning all prototype target directories..."
	@if docker image inspect "$(INSTAR_IMAGE)" >/dev/null 2>&1; then \
		for p in $(PROTOTYPES); do \
			if [ -d "$(PROTO_DIR)/$$p" ]; then \
				echo "Cleaning $$p (via container)..."; \
				docker run --rm \
					-v "$(CURDIR):/workspace" \
					-w "/workspace/$(PROTO_DIR)/$$p" \
					"$(INSTAR_IMAGE)" \
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
	@if docker image inspect "$(INSTAR_IMAGE)" >/dev/null 2>&1; then \
		docker rmi "$(INSTAR_IMAGE)" || true; \
		echo "Removed $(INSTAR_IMAGE)"; \
	else \
		echo "$(INSTAR_IMAGE) not found"; \
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

# Testdata location - can be overridden with INSTAR_TESTDATA_PATH env var
TESTDATA_PATH ?= $(CURDIR)/../instar-testdata

# Create virtual environment for tests
test-venv:
	@echo "Creating Python virtual environment for tests..."
	@if [ ! -d "$(VENV_DIR)" ]; then \
		$(PYTHON) -m venv $(VENV_DIR); \
	fi
	@$(VENV_DIR)/bin/pip install -q -r $(TESTS_DIR)/requirements.txt
	@echo "Virtual environment ready at $(VENV_DIR)"

# Run all tests (Rust unit tests + Python integration tests)
test: test-rust test-integration

# Run Rust unit tests (all workspace crates except no_main guest binaries)
test-rust: instar-devcontainer
	@echo "Running Rust unit tests..."
	docker run --rm \
		-u "$(shell id -u):$(shell id -g)" \
		-e HOME=/build \
		-e CARGO_HOME=/build/.cargo \
		-v "$(CURDIR):/workspace" \
		-v "$(CURDIR)/$(CARGO_CACHE_DIR)/registry:/build/.cargo/registry" \
		-v "$(CURDIR)/$(CARGO_CACHE_DIR)/git:/build/.cargo/git" \
		-w "/workspace/src" \
		"$(INSTAR_IMAGE)" \
		bash -c 'cargo test --release --workspace \
			--exclude core \
			--exclude info \
			--exclude copy \
			--exclude check-op \
			--exclude compare \
			--exclude convert \
			--exclude measure-op \
			--exclude create-op \
			--exclude rebase-op \
			--exclude resize-op \
			--exclude commit-op \
			--exclude map-op \
			--exclude snapshot-op \
			--exclude amend-op \
			--exclude bitmap-op \
			--exclude bench-op && \
		cargo test --release -p luks --features "decrypt,encrypt" && \
		cargo test --release -p qcow2 --features create && \
		cargo test --release -p qcow2 --features "create,vdi-input,parallels-input" && \
		cargo test --release -p create'

# Build all coverage-guided fuzz targets via cargo-fuzz inside the
# devcontainer (matches the .github/workflows/coverage-fuzz.yml build
# step). The container ships a pinned rust nightly + cargo-fuzz; the
# host doesn't need either.
#
# Pass FUZZ_TARGET=name to build just one target; default builds all.
FUZZ_TARGET ?=
fuzz-build: instar-devcontainer
	@echo "Building fuzz targets..."
	docker run --rm \
		-u "$(shell id -u):$(shell id -g)" \
		-e HOME=/build \
		-e CARGO_HOME=/build/.cargo \
		-v "$(CURDIR):/workspace" \
		-v "$(CURDIR)/$(CARGO_CACHE_DIR)/registry:/build/.cargo/registry" \
		-v "$(CURDIR)/$(CARGO_CACHE_DIR)/git:/build/.cargo/git" \
		-w "/workspace/src/fuzz" \
		"$(INSTAR_IMAGE)" \
		bash -c "cargo fuzz build $(FUZZ_TARGET)"

# Run a single fuzz target for a bounded wall-clock budget (seconds).
# Usage: make fuzz-run FUZZ_TARGET=fuzz_resize_planners FUZZ_DURATION=60
FUZZ_DURATION ?= 60
fuzz-run: instar-devcontainer
	@if [ -z "$(FUZZ_TARGET)" ]; then \
		echo "Error: FUZZ_TARGET=<name> is required"; \
		exit 1; \
	fi
	@echo "Running $(FUZZ_TARGET) for $(FUZZ_DURATION)s..."
	docker run --rm \
		-u "$(shell id -u):$(shell id -g)" \
		-e HOME=/build \
		-e CARGO_HOME=/build/.cargo \
		-v "$(CURDIR):/workspace" \
		-v "$(CURDIR)/$(CARGO_CACHE_DIR)/registry:/build/.cargo/registry" \
		-v "$(CURDIR)/$(CARGO_CACHE_DIR)/git:/build/.cargo/git" \
		-w "/workspace/src/fuzz" \
		"$(INSTAR_IMAGE)" \
		bash -c "cargo fuzz run $(FUZZ_TARGET) -- -max_total_time=$(FUZZ_DURATION)"

# Run the seven snapshot shell harnesses (tools/snapshot-*.sh):
# live byte-parity verification of `instar snapshot` against
# qemu-img — 241 assertions across the create/delete/apply
# matrices, the refusal batteries, and the CLI-parity checks.
# Runs inside the devcontainer (which ships the qemu-utils the
# harnesses compare against and matches the glibc the instar
# binary was built with), with /dev/kvm passed through. The
# scripts resolve $INSTAR relative to the repo root, so the
# container's /workspace mount finds the built binary. set -e
# stops at the first failing harness.
snapshot-harnesses: instar-devcontainer
	@if [ ! -f "$(SRC_DIR)/target/release/instar" ]; then \
		echo "Error: instar not built. Run 'make instar' first."; \
		exit 1; \
	fi
	docker run --rm \
		--device=/dev/kvm \
		-u "$(shell id -u):$(shell id -g)" \
		--group-add "$$(stat -c '%g' /dev/kvm)" \
		-e HOME=/build \
		-v "$(CURDIR):/workspace" \
		-w "/workspace" \
		"$(INSTAR_IMAGE)" \
		bash -c 'set -e; for h in tools/snapshot-*.sh; do \
			echo ""; echo "=== $$h ==="; bash "$$h"; done'

# Run Python integration tests only (on host)
# Runs all test files except malicious image tests (explicit opt-in via test-malicious)
test-integration: instar test-venv
	@echo "Running Python integration tests..."
	cd $(TESTS_DIR) && ../$(VENV_DIR)/bin/stestr run --exclude-regex test_info_malicious

# Run tests inside the devcontainer for consistent environment
# This ensures consistent glibc, paths, and other system dependencies
test-container: instar-devcontainer instar
	@echo "Running tests inside container..."
	@if [ ! -d "$(TESTDATA_PATH)" ]; then \
		echo "Error: Test data not found at $(TESTDATA_PATH)"; \
		echo "Set INSTAR_TESTDATA_PATH or ensure instar-testdata is a sibling directory."; \
		exit 1; \
	fi
	docker run --rm \
		--device=/dev/kvm \
		-u "$(shell id -u):$(shell id -g)" \
		--group-add "$$(stat -c '%g' /dev/kvm)" \
		-e HOME=/build \
		-e INSTAR_TESTDATA_PATH=/testdata \
		-v "$(CURDIR):/workspace" \
		-v "$(TESTDATA_PATH):/testdata:ro" \
		-w "/workspace" \
		"$(INSTAR_IMAGE)" \
		bash -c '\
			echo "Setting up test environment..."; \
			python3 -m venv /build/test-venv && \
			/build/test-venv/bin/pip install -q -r tests/requirements.txt && \
			echo "Running tests (excluding test_info_malicious)..."; \
			cd tests && \
			/build/test-venv/bin/stestr run \
				--exclude-regex "test_info_malicious" \
				--concurrency 4 \
		'

# Run core integration tests inside container (info, check, security, version, oslo-crossval)
# Excludes convert and compare tests which are split into separate targets
test-container-core: instar-devcontainer instar
	@echo "Running core integration tests inside container..."
	@if [ ! -d "$(TESTDATA_PATH)" ]; then \
		echo "Error: Test data not found at $(TESTDATA_PATH)"; \
		echo "Set INSTAR_TESTDATA_PATH or ensure instar-testdata is a sibling directory."; \
		exit 1; \
	fi
	docker run --rm \
		--device=/dev/kvm \
		-u "$(shell id -u):$(shell id -g)" \
		--group-add "$$(stat -c '%g' /dev/kvm)" \
		-e HOME=/build \
		-e INSTAR_TESTDATA_PATH=/testdata \
		-v "$(CURDIR):/workspace" \
		-v "$(TESTDATA_PATH):/testdata:ro" \
		-w "/workspace" \
		"$(INSTAR_IMAGE)" \
		bash -c '\
			echo "Setting up test environment..."; \
			python3 -m venv /build/test-venv && \
			/build/test-venv/bin/pip install -q -r tests/requirements.txt && \
			echo "Running core tests (excluding convert, compare, malicious)..."; \
			cd tests && \
			/build/test-venv/bin/stestr run \
				--exclude-regex "(test_convert\.|test_compare\.|test_info_malicious)" \
				--concurrency 4 \
		'

# Run QCOW2/VMDK/RAW convert + compare tests inside container
test-container-convert-qcow2: instar-devcontainer instar
	@echo "Running QCOW2/VMDK/RAW convert + compare tests inside container..."
	@if [ ! -d "$(TESTDATA_PATH)" ]; then \
		echo "Error: Test data not found at $(TESTDATA_PATH)"; \
		echo "Set INSTAR_TESTDATA_PATH or ensure instar-testdata is a sibling directory."; \
		exit 1; \
	fi
	docker run --rm \
		--device=/dev/kvm \
		-u "$(shell id -u):$(shell id -g)" \
		--group-add "$$(stat -c '%g' /dev/kvm)" \
		-e HOME=/build \
		-e INSTAR_TESTDATA_PATH=/testdata \
		-v "$(CURDIR):/workspace" \
		-v "$(TESTDATA_PATH):/testdata:ro" \
		-w "/workspace" \
		"$(INSTAR_IMAGE)" \
		bash -c '\
			echo "Setting up test environment..."; \
			python3 -m venv /build/test-venv && \
			/build/test-venv/bin/pip install -q -r tests/requirements.txt && \
			echo "Running QCOW2/VMDK/RAW convert + compare tests..."; \
			cd tests && \
			/build/test-venv/bin/stestr run \
				--exclude-regex "Vhd" \
				--concurrency 4 \
				"(test_convert\.|test_compare\.)" \
		'

# Run VHD/VHDX convert tests inside container
test-container-convert-vhd: instar-devcontainer instar
	@echo "Running VHD/VHDX convert tests inside container..."
	@if [ ! -d "$(TESTDATA_PATH)" ]; then \
		echo "Error: Test data not found at $(TESTDATA_PATH)"; \
		echo "Set INSTAR_TESTDATA_PATH or ensure instar-testdata is a sibling directory."; \
		exit 1; \
	fi
	docker run --rm \
		--device=/dev/kvm \
		-u "$(shell id -u):$(shell id -g)" \
		--group-add "$$(stat -c '%g' /dev/kvm)" \
		-e HOME=/build \
		-e INSTAR_TESTDATA_PATH=/testdata \
		-v "$(CURDIR):/workspace" \
		-v "$(TESTDATA_PATH):/testdata:ro" \
		-w "/workspace" \
		"$(INSTAR_IMAGE)" \
		bash -c '\
			echo "Setting up test environment..."; \
			python3 -m venv /build/test-venv && \
			/build/test-venv/bin/pip install -q -r tests/requirements.txt && \
			echo "Running VHD/VHDX convert tests..."; \
			cd tests && \
			/build/test-venv/bin/stestr run \
				--concurrency 4 \
				"test_convert\.TestConvert.*Vhd" \
		'

# Run CI-suitable tests (safe + caution)
# Runs all test files except malicious image tests
test-ci: instar test-venv
	@echo "Running CI tests (safe images)..."
	cd $(TESTS_DIR) && ../$(VENV_DIR)/bin/stestr run --exclude-regex test_info_malicious

# Run all tests including malicious (explicit opt-in)
test-malicious: instar test-venv
	@echo "WARNING: Running tests including malicious images"
	@echo "This will process known malicious disk images."
	@echo ""
	cd $(TESTS_DIR) && ../$(VENV_DIR)/bin/stestr run

# Run tests and show output (useful for seeing diffs during development)
test-report: instar test-venv
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

# =============================================================================
# Release Targets
# =============================================================================

# All Cargo.toml files that carry the workspace version
CARGO_TOML_FILES := \
	src/vmm/Cargo.toml \
	src/shared/Cargo.toml \
	src/core/Cargo.toml \
	src/crates/qcow2/Cargo.toml \
	src/crates/vmdk/Cargo.toml \
	src/crates/vhd/Cargo.toml \
	src/crates/vhdx/Cargo.toml \
	src/crates/luks/Cargo.toml \
	src/crates/raw/Cargo.toml \
	src/crates/measure/Cargo.toml \
	src/crates/create/Cargo.toml \
	src/crates/rebase/Cargo.toml \
	src/crates/resize/Cargo.toml \
	src/crates/commit/Cargo.toml \
	src/operations/info/Cargo.toml \
	src/operations/copy/Cargo.toml \
	src/operations/check/Cargo.toml \
	src/operations/compare/Cargo.toml \
	src/operations/convert/Cargo.toml \
	src/operations/measure/Cargo.toml \
	src/operations/create/Cargo.toml \
	src/operations/rebase/Cargo.toml \
	src/operations/resize/Cargo.toml \
	src/operations/commit/Cargo.toml \
	src/operations/snapshot/Cargo.toml \
	crates/guest-protocol/Cargo.toml

# Bump all Cargo.toml versions, commit, and create a signed tag.
#
# Usage: make release VERSION=0.2.0
#
# This does NOT push -- review the commit and tag before pushing.
release:
ifndef VERSION
	$(error VERSION is not set. Usage: make release VERSION=0.2.0)
endif
	@echo "Bumping version to $(VERSION) in all Cargo.toml files..."
	@for f in $(CARGO_TOML_FILES); do \
		if [ ! -f "$$f" ]; then \
			echo "Error: $$f not found"; \
			exit 1; \
		fi; \
		sed -i 's/^version = ".*"/version = "$(VERSION)"/' "$$f"; \
		echo "  updated $$f"; \
	done
	@echo ""
	@echo "Verifying all versions match..."
	@MISMATCH=0; \
	for f in $(CARGO_TOML_FILES); do \
		VER=$$(grep '^version = ' "$$f" | head -1 | \
			sed 's/version = "//;s/"//'); \
		if [ "$$VER" != "$(VERSION)" ]; then \
			echo "  MISMATCH: $$f has version $$VER"; \
			MISMATCH=1; \
		fi; \
	done; \
	if [ $$MISMATCH -ne 0 ]; then \
		echo "Error: version mismatch detected"; \
		exit 1; \
	fi
	@echo "All versions set to $(VERSION)."
	@echo ""
	@echo "Creating release commit and tag..."
	git add $(CARGO_TOML_FILES)
	git commit -m "Release v$(VERSION)."
	git tag "v$(VERSION)" -m "Release v$(VERSION)"
	@echo ""
	@echo "Done. Review the commit and tag, then push with:"
	@echo "  git push origin HEAD"
	@echo "  git push origin v$(VERSION)"

# Verify that the version in src/vmm/Cargo.toml matches a tag.
# Used by the release workflow as a safety check.
#
# Usage: make check-version TAG=v0.2.0
check-version:
ifndef TAG
	$(error TAG is not set. Usage: make check-version TAG=v0.2.0)
endif
	@EXPECTED=$$(echo "$(TAG)" | sed 's/^v//'); \
	ACTUAL=$$(grep '^version = ' src/vmm/Cargo.toml | head -1 | \
		sed 's/version = "//;s/"//'); \
	if [ "$$ACTUAL" != "$$EXPECTED" ]; then \
		echo "ERROR: Tag $(TAG) expects version $$EXPECTED"; \
		echo "       but src/vmm/Cargo.toml has $$ACTUAL"; \
		exit 1; \
	fi; \
	echo "Version check passed: $$ACTUAL matches $(TAG)"
