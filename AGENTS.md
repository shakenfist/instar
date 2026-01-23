# Agents Guide for Imago

This document provides guidance for AI agents working on the imago codebase.

## Project Overview

Imago is a safe, sandboxed disk image format converter. It replaces unsafe
`qemu-img` calls with conversions performed inside a KVM sandbox.

## Repository Structure

```
imago/
├── .devcontainer/  # Development containers (rust-lint)
├── src/            # Main imago implementation
│   ├── vmm/        # Virtual machine monitor (host-side)
│   ├── core/       # Core guest initialization
│   ├── shared/     # Shared library code
│   ├── operations/ # Pluggable operations (info, copy)
│   └── build.sh    # Build script
├── crates/         # Shared Rust crates (guest-protocol)
├── prototypes/     # Experimental implementations (11 KVM prototypes)
├── scripts/        # Build and check scripts
├── docs/           # Design documents and research notes
├── testdata/       # Test images for security validation
├── Makefile        # Build and development automation
├── README.md       # Project overview
├── ARCHITECTURE.md # Technical design and security model
├── AGENTS.md       # This file
└── LICENSE         # Apache 2.0
```

## Current Status

The project has moved from prototype phase to initial implementation. The `info`
prototype has been promoted to the main implementation in `src/`. Prototypes
remain in `prototypes/` for reference.

## Key Concepts

### Security Model

The core principle: **never parse untrusted data with host privileges**.

- Host code only handles opaque byte streams
- All format parsing happens inside a KVM sandbox
- Exploits in format parsers are contained within the sandbox

### Supported Formats

Target formats: qcow2, raw, vmdk

## Working on This Project

### When Adding Prototypes

1. Create a subdirectory under `prototypes/` with a descriptive name
2. Include a README explaining the approach being tested
3. Document any dependencies or build requirements

### Code Style

- Follow the conventions of whatever language is being used
- Prioritize clarity over cleverness
- Comment security-relevant decisions

For Rust code specifically:
- Run `rustfmt` for formatting (pre-commit hook enforces this)
- Run `clippy` for linting (pre-commit hook enforces this)
- Use `./scripts/check-rust.sh fix` to auto-fix formatting issues

### Pre-commit Hooks

Pre-commit hooks are configured for Rust code quality. Before committing:

```bash
pre-commit run --all-files
```

The hooks use a dedicated Docker container (`.devcontainer/rust-lint/`) with
stable Rust to ensure consistent results across all development environments.

### Using the Makefile

The project includes a Makefile for common development tasks:

```bash
# Show all available commands
make help

# List available prototypes
make list-prototypes

# Build the main imago project
make imago

# Build a specific prototype
make build-prototype PROTOTYPE=virtio-block5

# Build all prototypes
make build-all

# Run lint checks
make lint

# Auto-fix formatting
make lint-fix

# Clean imago build
make clean-imago

# Clean a prototype's target directory
make clean-prototype PROTOTYPE=virtio-block5

# Clean everything (all targets + Docker images)
make distclean
```

### Building and Running Imago

The main imago implementation is in `src/`:

```bash
# Build imago
make imago

# Run imago (requires KVM)
sudo src/target/release/imago info <IMAGE>
sudo src/target/release/imago copy <INPUT> <OUTPUT>
```

### Testing Prototypes

Each prototype has its own devcontainer with the required toolchain. Use the
Makefile for building and testing:

```bash
# Build a specific prototype
make build-prototype PROTOTYPE=virtio-block5

# Build the devcontainer for a prototype
make build-prototype-devcontainer PROTOTYPE=virtio-block5

# View run instructions
make run-prototype PROTOTYPE=virtio-block5
```

For manual testing without the Makefile:

```bash
cd prototypes/<prototype-name>
./build.sh                           # Build the prototype
sudo ./target/release/vmm guest.bin  # Run (requires KVM)
```

### Testing Considerations

- Test with malformed/malicious input images
- Verify sandbox containment
- Check for resource exhaustion (memory, disk, CPU)
