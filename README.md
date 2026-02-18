# Imago

A safe, sandboxed disk image format converter.

## Overview

Imago replaces unsafe calls to `qemu-img` with a safer, sandboxed approach.
Image format conversions are performed within a KVM execution context,
providing strong isolation from the host system.

The name "imago" comes from Latin (meaning "image") and biology (the final
adult stage of insect metamorphosis) - reflecting both the image handling
and transformation aspects of the tool.

Confused about how imago does these things? Perhaps read the [technology primer](docs/technology-primer.md).

## Supported Formats

Initial target formats:
- **qcow2** - QEMU Copy-On-Write format
- **raw** - Raw disk images
- **vmdk** - VMware Virtual Machine Disk

## Project Status

**Initial implementation** - The `info` prototype has been promoted to the main
imago implementation in `src/`. Operations include `info`, `copy`, `check`,
`compare`, and `convert`. Prototypes remain available for reference.

## Building Imago

```bash
# Build the main imago project
make imago

# The binaries will be in src/target/release/
sudo src/target/release/imago info <IMAGE>
sudo src/target/release/imago copy <INPUT> <OUTPUT>
```

## Usage

### Image Information

```bash
# Display image format information (matches qemu-img info output)
imago info image.qcow2

# Discover and display the complete backing file chain
imago info --chain image.qcow2
```

The `--chain` flag iteratively runs the sandboxed info operation on each image
in the backing chain, validating paths against a security allowlist to prevent
directory traversal attacks.

### Image Comparison

```bash
# Compare two images for identical content (matches qemu-img compare output)
imago compare image1.raw image2.raw

# Strict mode: fail if images differ in size (even if content matches)
imago compare -s image1.raw image2.raw

# JSON output for programmatic consumption
imago compare --output json image1.raw image2.raw
```

Exit codes: 0 = identical, 1 = content differs.

The compare operation reads the virtual content of both images and reports the
first byte offset where content diverges. For QCOW2 images, this includes
L1/L2 cluster table lookup and compressed cluster decompression (zlib/deflate),
so comparisons work across formats (e.g., QCOW2 vs raw, compressed QCOW2 vs
uncompressed QCOW2). QCOW2 backing chains are automatically discovered and
flattened: unallocated clusters are resolved by walking the backing chain,
so overlay images compare correctly against their flattened equivalents.
When images differ in size, non-strict mode (default) treats extra zero-filled
regions as matching, while strict mode (`-s`) fails immediately on any size
difference.

Output is byte-for-byte identical with `qemu-img compare`.

### Image Integrity Check

```bash
# Validate image structural integrity (matches qemu-img check output)
imago check image.qcow2

# JSON output for programmatic consumption
imago check --output json image.qcow2

# Validate the entire backing chain
imago check --chain image.qcow2
```

For QCOW2 images, check validates:
- Header integrity (version, cluster_bits, virtual_size)
- Full L1/L2 table consistency (all sectors, not just first)
- Overlap detection (two L2 entries referencing same host cluster)
- Refcount validation (referenced clusters must have refcount > 0)
- Leak detection (clusters with refcount > 0 but no L2 reference)
- Dirty/corrupt incompatible feature flags

The `--chain` flag discovers the full backing chain (using the same chain
discovery infrastructure as `imago info --chain`), sets up each image as a
separate virtio-block device in the KVM guest, and validates:
- Format consistency: each backing image's format matches what chain
  discovery found
- Virtual size validity: backing images must have non-zero virtual size
- QCOW2 header validation: backing images that are QCOW2 get basic header
  checks (magic, version, cluster_bits, L1/refcount table bounds, corrupt
  feature flag)

Chain errors are reported separately as `chain-errors` in JSON output and
in human-readable output. Without `--chain`, `chain-errors` is always 0.

**Note:** The `chain-errors` field is always present in JSON output,
even when `--chain` is not used. This is a schema addition relative to
previous versions.

### Image Conversion

```bash
# Convert QCOW2 to raw (flattens backing chains)
imago convert input.qcow2 output.raw

# Convert with sparse output (skip writing zero-filled clusters)
imago convert -S input.qcow2 output.raw

# Progress reporting
imago convert -p 5 input.qcow2 output.raw
```

The convert operation reads the virtual content of a QCOW2 image (including
backing chain flattening) and writes it as a flat raw output. Compressed
clusters (zlib/deflate) are decompressed transparently.

**Limitations:** Cluster sizes above 64KB are not yet supported. Output
format is currently limited to raw.

### Version Compatibility

Different qemu-img versions produce slightly different output formats:
- **qemu-img 6.0-7.2** (Debian 12 bookworm): No "Child node '/file'" section
- **qemu-img 8.0+** (Debian 13 trixie): Includes "Child node '/file'" section

By default, imago detects the installed qemu-img version and emits matching output.
This ensures true drop-in replacement compatibility.

To explicitly specify which qemu-img version's output format to use:

```bash
# Emit output compatible with qemu-img 7.2 (no Child node section)
imago info --qemu-version 7.2 image.qcow2

# Emit output compatible with qemu-img 10.0 (includes Child node section)
imago info --qemu-version 10.0 image.qcow2
```

See [docs/output-formats.md](docs/output-formats.md) for detailed documentation on
output format profiles.

## Prototypes

Working prototypes exploring the KVM-based sandboxing approach:

| Prototype | Description |
|-----------|-------------|
| [helloworld](prototypes/helloworld/) | Minimal bare-metal KVM guest proof-of-concept |
| [helloworld2](prototypes/helloworld2/) | Uses vm-memory crate for safer memory management |
| [virtio-block](prototypes/virtio-block/) | Virtio-block device emulation with file copy |
| [virtio-block2](prototypes/virtio-block2/) | Adds guest-protocol (protobuf) integration |
| [virtio-block3](prototypes/virtio-block3/) | Adds configurable sector sizes |
| [virtio-block4](prototypes/virtio-block4/) | Adds performance statistics tracking |
| [virtio-block5](prototypes/virtio-block5/) | Adds ioeventfd optimization |
| [virtio-block6](prototypes/virtio-block6/) | Adds sparse/dynamic output file support, adopt recommended sector sizes and progress reporting intervals based on previous testing |
| [pluggable](prototypes/pluggable/) | Modular architecture separating core infrastructure from pluggable operations |
| [pluggable2](prototypes/pluggable2/) | Separate binary loading for operations (reduced attack surface) |
| [info](prototypes/info/) | Image format detection (qemu-img info equivalent) |

See [docs/index.md](docs/index.md) for full prototype documentation.

## Development

### Pre-commit Hooks

This project uses pre-commit hooks for Rust code quality:

```bash
# Install pre-commit (if not already installed)
pip install pre-commit

# Install the hooks
pre-commit install

# Run manually on all files
pre-commit run --all-files
```

The hooks run rustfmt (formatting) and clippy (linting) on all Rust code via
Docker, ensuring consistent tooling regardless of local Rust installation.

To auto-fix formatting issues:
```bash
./scripts/check-rust.sh fix
```

### Makefile

A Makefile is provided for common development tasks:

```bash
# Show all available targets
make help

# List available prototypes
make list-prototypes
```

**Main Imago Project:**
```bash
# Build imago
make imago

# Clean imago build
make clean-imago

# Show how to run imago
make run-imago
```

**Prototypes:**
```bash
# Build a specific prototype
make build-prototype PROTOTYPE=virtio-block5

# Build all prototypes
make build-all

# Build the shared guest-protocol crate
make guest-protocol

# Build devcontainer for a prototype
make build-prototype-devcontainer PROTOTYPE=virtio-block5

# Build the rust-lint Docker container
make build-lint-container
```

**Cleaning:**
```bash
# Clean a specific prototype's target directory
make clean-prototype PROTOTYPE=virtio-block5

# Clean all build directories (main + prototypes)
make clean-all

# Remove all devcontainer Docker images
make clean-devcontainers

# Remove the rust-lint Docker image
make clean-lint-container

# Remove everything (all targets + all containers)
make distclean
```

**Linting:**
```bash
# Run rustfmt and clippy checks
make lint

# Run with auto-fix
make lint-fix

# Install pre-commit hooks
make install-hooks
```

**Integration Testing:**
```bash
# Create Python venv for tests (testtools/stestr)
make test-venv

# Run safe integration tests
make test

# Run tests with verbose output (shows diffs)
make test-report

# Run all tests including malicious images (explicit opt-in)
make test-malicious

# Clean test artifacts
make clean-tests
```

The integration tests compare `imago info` output against `qemu-img info` to
verify drop-in replacement compatibility, validate `imago check` against
deliberately corrupt test images, cross-validate `imago compare` output
against `qemu-img compare`, and cross-validate `imago convert` output against
`qemu-img convert`. Test images are in the sibling `imago-testdata/`
repository.

**Running:**
```bash
# Show run instructions for a prototype
make run PROTOTYPE=virtio-block5
```

## Directory Structure

```
imago/
├── .devcontainer/  # Development containers
│   └── rust-lint/  # Stable Rust for linting
├── src/            # Main imago implementation
│   ├── vmm/        # Virtual machine monitor (host-side)
│   ├── core/       # Core guest initialization
│   ├── shared/     # Shared library code
│   ├── crates/     # Shared format parsing crates (no_std)
│   │   ├── qcow2/  # QCOW2 header, L1/L2, decompression, refcounts
│   │   ├── raw/    # MBR/GPT partition table detection
│   │   └── vmdk/   # VMDK4 header and descriptor parsing
│   ├── operations/ # Pluggable operations (info, copy, check, compare, convert)
│   └── build.sh    # Build script
├── crates/         # Shared Rust crates
│   └── guest-protocol/ # Protocol Buffers messaging for guests
├── prototypes/     # Experimental implementations (reference)
│   ├── helloworld/     # Minimal KVM VMM with bare-metal guest
│   ├── helloworld2/    # Same, using rust-vmm vm-memory crate
│   ├── virtio-block/   # Virtio-block device emulation
│   ├── virtio-block2/  # With guest-protocol integration
│   ├── virtio-block3/  # With configurable sector sizes
│   ├── virtio-block4/  # With performance statistics
│   ├── virtio-block5/  # With ioeventfd optimization
│   ├── virtio-block6/  # With sparse/dynamic output support
│   ├── pluggable/      # Modular operations architecture
│   ├── pluggable2/     # Separate binary loading for operations
│   └── info/           # Image format detection (qemu-img info)
├── scripts/        # Build and check scripts
├── tests/          # Integration tests (Python/testtools)
│   ├── base.py         # Base test class
│   ├── manifest.json   # Test image definitions
│   ├── helpers/        # Test utilities
│   └── test_*.py       # Test files
├── docs/           # Design documents and research
│   ├── index.md    # Documentation index
│   ├── usage.md    # Platform usage analysis (oVirt, Proxmox, OpenStack)
│   ├── security.md # CVE analysis for image handling
│   ├── qcow2/      # QCOW2 format documentation
│   ├── vmdk/       # VMDK format documentation
│   └── raw/        # Raw format documentation
├── testdata/       # Test images for security validation
│   ├── benign/     # Safe test images (qcow2, raw, vmdk, vhdx, vpc)
│   ├── malicious/  # CVE exploit images (DANGEROUS)
│   └── downloaded/ # External test images (CirrOS, QEMU iotests, etc.)
├── Makefile        # Build and development automation
└── README.md
```

## Security Model

The core security principle is that untrusted disk images should never be
parsed or manipulated by code running with host privileges. Instead:

1. A minimal KVM guest handles all image parsing and conversion
2. The host only deals with opaque byte streams
3. Any vulnerabilities in format parsing are contained within the sandbox

### Secure RAW Format Detection

Unlike qemu-img, imago validates RAW format detection by requiring a valid
partition table (MBR or GPT). This prevents arbitrary files from being accepted
as disk images, which is the root cause of backing file disclosure attacks
(CVE-2015-5163, CVE-2024-32498).

```bash
# Default (secure): rejects files without valid format or partition table
imago info /etc/passwd
# Error: Unknown format (no valid disk image header or partition table)

# Unsafe mode: matches qemu-img behavior (for compatibility testing only)
imago info --unsafe-quirks /etc/passwd
# file format: raw
```

See [docs/quirks.md](docs/quirks.md) for the classification of safe vs unsafe quirks.

## Test Data

The `testdata/` directory contains 44 disk images for security validation:

- **Benign images** - Basic valid images in various formats for functionality testing
- **Malicious images** - Crafted to exploit known CVEs (CVE-2015-5163, CVE-2024-32498,
  CVE-2022-47951, etc.) including backing file exploits, external data file exploits,
  and VMDK descriptor attacks
- **Edge cases** - Valid but unusual configurations (min/max cluster sizes, extended L2,
  various refcount widths, backing file chains)
- **AFL-discovered** - Malformed images from QEMU's fuzzing that trigger parser errors

See `testdata/README.md` for full documentation.

## Documentation

The `docs/` directory contains:

- Format specifications derived from QEMU source analysis (QCOW2, VMDK, raw)
- Platform usage analysis showing how oVirt, Proxmox, and OpenStack use qemu-img
- Security vulnerability analysis covering ~35 CVEs related to image handling

See `docs/index.md` for the full documentation index.

## GitHub Automation

This project uses Claude Code-powered GitHub automation for PR management.

### Bot Commands

Comment on a PR with these commands (requires write access):

| Command | Description |
|---------|-------------|
| `@shakenfist-bot please re-review` | Request a fresh automated code review |
| `@shakenfist-bot please attempt to fix` | Attempt to fix failing tests |
| `@shakenfist-bot please address comments` | Address automated review comments |

The "address comments" command extracts the structured JSON review from the PR
comment (embedded in a collapsed `<details>` section) and creates one commit per
actionable item (those marked with `action: fix` or `action: document`). If Claude
disagrees with a suggestion, it will explain its rationale instead of making changes.

### GitHub Issues

The automated reviewer creates GitHub issues for actionable items (fix/document).
These issues are linked in the review comment with "Closes #N" syntax, so they're
automatically closed when the PR merges.

### Workflows

- **Automated Review**: PRs automatically receive code review after CI passes,
  and GitHub issues are created for actionable items
- **Test Fixing**: On-demand test failure resolution via PR comment
- **Comment Addressing**: On-demand resolution of review feedback via PR comment

See `.github/workflows/` for implementation details.

## Claude Code Integration

This project includes Claude Code skills for common development tasks:

- `/imago-new-op <name>` - Scaffold a new operation binary
- `/imago-format [format]` - Disk image format reference (qcow2, vmdk, raw)
- `/imago-debug [issue]` - Troubleshooting guide for guest operations
- `/imago-calltable [function]` - Call table API documentation
- `/imago-add-test-image` - Add a new image to the integration test suite
- `/verbose-print` - Guidelines for adding diagnostic verbose_print() calls
- `/error-handling` - Ensure all error conditions return proper exit codes

Additional development skills:
- `.claude/skills/build-and-test.md` - Correct build/test patterns (always use
  Makefile targets like `make imago`, `make test-ci`)
- `.claude/skills/testing-discipline.md` - Test verification workflow (never
  accept failures as "pre-existing" without verification)
- `.claude/skills/pr-preparation.md` - PR readiness checklist (zero test
  failures, no VM crashes, all checks passing)
- `.claude/skills/documentation-updates.md` - Documentation requirements (every
  user-visible change requires docs updates)
- `.claude/skills/correct-fixes.md` - Fix root causes, not symptoms (security
  project: always do things the right way, not the easy way)
- `.claude/skills/error-handling.md` - Error propagation patterns (never use
  exit(), always return errors with context)

See `.claude/skills/` for details.

## License

Licensed under the Apache License, Version 2.0. See LICENSE file for details.
