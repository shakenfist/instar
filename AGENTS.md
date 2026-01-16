# Agents Guide for Imago

This document provides guidance for AI agents working on the imago codebase.

## Project Overview

Imago is a safe, sandboxed disk image format converter. It replaces unsafe
`qemu-img` calls with conversions performed inside a KVM sandbox.

## Repository Structure

```
imago/
├── prototypes/     # Experimental implementations in various languages
├── docs/           # Design documents and research notes
├── README.md       # Project overview
├── ARCHITECTURE.md # Technical design and security model
├── AGENTS.md       # This file
└── LICENSE         # Apache 2.0
```

## Current Status

The project is in early prototype phase. We are exploring different
implementation approaches before committing to a specific language or
architecture.

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

### Testing Prototypes

Each prototype has its own devcontainer with the required toolchain. Agents can
and should test prototypes by:

1. Building the devcontainer image for the prototype
2. Running the build script inside the container
3. Executing the prototype to verify it works

Example for testing a Rust KVM prototype:

```bash
cd prototypes/<prototype-name>

# Build the devcontainer image
docker build -t <prototype>-dev .devcontainer/

# Run the build inside the container (with KVM access)
docker run --rm -v "$(pwd):/workspace" -w /workspace \
    --device=/dev/kvm --group-add=$(getent group kvm | cut -d: -f3) \
    <prototype>-dev ./build.sh

# Run the prototype (requires sudo for KVM)
docker run --rm -it -v "$(pwd):/workspace" -w /workspace \
    --device=/dev/kvm --group-add=$(getent group kvm | cut -d: -f3) \
    <prototype>-dev sudo ./target/release/vmm <args>
```

### Testing Considerations

- Test with malformed/malicious input images
- Verify sandbox containment
- Check for resource exhaustion (memory, disk, CPU)
