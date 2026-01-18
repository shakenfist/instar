# Imago Project Makefile
#
# Usage: make <target> [PROTOTYPE=<name>]
#
# Examples:
#   make build PROTOTYPE=virtio-block5
#   make clean-all
#   make lint
#

.PHONY: help list-prototypes build build-all clean clean-all \
        clean-devcontainers lint lint-fix build-lint-container \
        install-hooks run guest-protocol ensure-devcontainer

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
	@echo "Building:"
	@echo "  build                Build a specific prototype (requires PROTOTYPE=<name>)"
	@echo "  build-all            Build all prototypes"
	@echo "  guest-protocol       Build the shared guest-protocol crate"
	@echo "  build-devcontainer   Build devcontainer for a prototype (requires PROTOTYPE=<name>)"
	@echo "  build-lint-container Build the rust-lint Docker container"
	@echo ""
	@echo "Cleaning:"
	@echo "  clean                Clean target directory for a prototype (requires PROTOTYPE=<name>)"
	@echo "  clean-all            Clean all prototype target directories"
	@echo "  clean-devcontainers  Remove all prototype devcontainer images"
	@echo "  clean-lint-container Remove the rust-lint Docker image"
	@echo "  distclean            Remove everything (all targets + all containers)"
	@echo ""
	@echo "Linting:"
	@echo "  lint                 Run rustfmt and clippy checks on all prototypes"
	@echo "  lint-fix             Run rustfmt and clippy with auto-fix"
	@echo "  install-hooks        Install pre-commit hooks"
	@echo ""
	@echo "Running:"
	@echo "  run                  Run a prototype (requires PROTOTYPE=<name>)"
	@echo ""
	@echo "Examples:"
	@echo "  make build PROTOTYPE=virtio-block5"
	@echo "  make run PROTOTYPE=virtio-block5"
	@echo "  make clean PROTOTYPE=helloworld"
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
	pluggable2

# Docker image names
LINT_IMAGE := imago-rust-lint

# Paths
PROTO_DIR := prototypes
SCRIPTS_DIR := scripts
DEVCONTAINER_DIR := .devcontainer

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

# Build a specific prototype (runs inside devcontainer)
build: check-prototype ensure-devcontainer
	@echo "Building prototype: $(PROTOTYPE)"
	@if [ ! -f "$(PROTO_DIR)/$(PROTOTYPE)/build.sh" ]; then \
		echo "Error: build.sh not found for $(PROTOTYPE)"; \
		exit 1; \
	fi
	docker run --rm \
		-u "$(shell id -u):$(shell id -g)" \
		-e HOME=/home/vscode \
		-e CARGO_HOME=/home/vscode/.cargo \
		-e RUSTUP_HOME=/home/vscode/.rustup \
		-v "$(CURDIR):/workspace" \
		-w "/workspace/$(PROTO_DIR)/$(PROTOTYPE)" \
		"imago-$(PROTOTYPE)" \
		bash build.sh

# Ensure devcontainer exists (builds if needed)
ensure-devcontainer: check-prototype
	@if ! docker image inspect "imago-$(PROTOTYPE)" >/dev/null 2>&1; then \
		echo "Building devcontainer image for $(PROTOTYPE)..."; \
		docker build -t "imago-$(PROTOTYPE)" "$(PROTO_DIR)/$(PROTOTYPE)/$(DEVCONTAINER_DIR)"; \
	fi

# Build all prototypes (each runs inside its devcontainer)
build-all:
	@echo "Building all prototypes..."
	@for p in $(PROTOTYPES); do \
		if [ -d "$(PROTO_DIR)/$$p" ] && [ -f "$(PROTO_DIR)/$$p/build.sh" ]; then \
			echo ""; \
			echo "=== Building $$p ==="; \
			$(MAKE) build PROTOTYPE=$$p || exit 1; \
		fi; \
	done
	@echo ""
	@echo "All prototypes built successfully."

# Build the shared guest-protocol crate
guest-protocol:
	@echo "Building guest-protocol crate..."
	cd crates/guest-protocol && cargo build --release

# Build devcontainer for a specific prototype
build-devcontainer: check-prototype
	@echo "Building devcontainer for: $(PROTOTYPE)"
	@if [ -f "$(PROTO_DIR)/$(PROTOTYPE)/$(DEVCONTAINER_DIR)/Dockerfile" ]; then \
		docker build -t "imago-$(PROTOTYPE)" \
			"$(PROTO_DIR)/$(PROTOTYPE)/$(DEVCONTAINER_DIR)"; \
	else \
		echo "Error: Dockerfile not found for $(PROTOTYPE)"; \
		exit 1; \
	fi

# Build the rust-lint container
build-lint-container:
	@echo "Building rust-lint container..."
	docker build -t $(LINT_IMAGE) $(DEVCONTAINER_DIR)/rust-lint

# Clean target directory for a specific prototype
# Runs inside container if available (to handle root-owned files from builds)
clean: check-prototype
	@echo "Cleaning target directory for: $(PROTOTYPE)"
	@if docker image inspect "imago-$(PROTOTYPE)" >/dev/null 2>&1; then \
		echo "Using container to clean (handles root-owned files)..."; \
		docker run --rm \
			-v "$(CURDIR):/workspace" \
			-w "/workspace/$(PROTO_DIR)/$(PROTOTYPE)" \
			"imago-$(PROTOTYPE)" \
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

# Clean all prototype target directories
# Uses containers when available to handle root-owned files
clean-all:
	@echo "Cleaning all prototype target directories..."
	@for p in $(PROTOTYPES); do \
		if [ -d "$(PROTO_DIR)/$$p" ]; then \
			if docker image inspect "imago-$$p" >/dev/null 2>&1; then \
				echo "Cleaning $$p (via container)..."; \
				docker run --rm \
					-v "$(CURDIR):/workspace" \
					-w "/workspace/$(PROTO_DIR)/$$p" \
					"imago-$$p" \
					sh -c "rm -rf target *.bin" 2>/dev/null || true; \
			else \
				if [ -d "$(PROTO_DIR)/$$p/target" ]; then \
					rm -rf "$(PROTO_DIR)/$$p/target" 2>/dev/null || \
						echo "Warning: Could not remove $(PROTO_DIR)/$$p/target (try: sudo rm -rf)"; \
				fi; \
				find "$(PROTO_DIR)/$$p" -maxdepth 1 -name "*.bin" -delete 2>/dev/null || true; \
			fi; \
		fi; \
	done
	@echo "Clean complete."

# Remove all devcontainer images
clean-devcontainers:
	@echo "Removing devcontainer images..."
	@for p in $(PROTOTYPES); do \
		if docker image inspect "imago-$$p" >/dev/null 2>&1; then \
			docker rmi "imago-$$p" || true; \
			echo "Removed imago-$$p"; \
		fi; \
	done
	@echo "Devcontainer cleanup complete."

# Remove the rust-lint Docker image
clean-lint-container:
	@echo "Removing rust-lint container..."
	@if docker image inspect $(LINT_IMAGE) >/dev/null 2>&1; then \
		docker rmi $(LINT_IMAGE) || true; \
		echo "Removed $(LINT_IMAGE)"; \
	else \
		echo "$(LINT_IMAGE) not found"; \
	fi

# Remove everything
distclean: clean-all clean-devcontainers clean-lint-container
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
run: check-prototype
	@echo "Running prototype: $(PROTOTYPE)"
	@if [ ! -f "$(PROTO_DIR)/$(PROTOTYPE)/target/release/vmm" ]; then \
		echo "Error: VMM not built. Run 'make build PROTOTYPE=$(PROTOTYPE)' first."; \
		exit 1; \
	fi
	@if [ ! -f "$(PROTO_DIR)/$(PROTOTYPE)/guest.bin" ]; then \
		echo "Error: guest.bin not found. Run 'make build PROTOTYPE=$(PROTOTYPE)' first."; \
		exit 1; \
	fi
	@echo "Note: Running requires KVM access (sudo or kvm group membership)"
	@echo "Command: sudo $(PROTO_DIR)/$(PROTOTYPE)/target/release/vmm $(PROTO_DIR)/$(PROTOTYPE)/guest.bin"
	@echo ""
	@echo "For virtio-block prototypes, additional arguments may be needed."
	@echo "See $(PROTO_DIR)/$(PROTOTYPE)/README.md for usage details."
