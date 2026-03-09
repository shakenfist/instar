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
│   ├── crates/     # Shared format crates (qcow2, raw, vmdk, vhd, vhdx)
│   ├── shared/     # Shared library code (byte-order helpers, configs)
│   ├── operations/ # Pluggable operations (info, copy, check, compare, convert)
│   └── build.sh    # Build script
├── crates/         # Shared Rust crates (guest-protocol)
├── prototypes/     # Experimental implementations (11 KVM prototypes)
├── scripts/        # Build, check, and test image generation scripts
├── tests/          # Integration tests (Python/testtools)
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

Target formats: qcow2 (including external data files), raw, vmdk, vpc (VHD),
vhdx (VHDX), luks (info with optional decryption)

## Working on This Project

### When Adding Prototypes

1. Create a subdirectory under `prototypes/` with a descriptive name
2. Include a README explaining the approach being tested
3. Document any dependencies or build requirements

### Planning Documents

Implementation plans are kept as local-only files using the naming convention
`PLAN-*.md` (e.g., `PLAN-convert.md`). These files are excluded from version
control via `.gitignore` to allow developers to maintain detailed planning
notes without cluttering the repository.

When starting a major feature:
1. Create a `PLAN-<feature>.md` file in the repository root
2. Document the implementation phases and approach
3. The file stays local - it won't be committed

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

### Integration Testing

Integration tests compare `imago info` output against `qemu-img info` to verify
drop-in replacement compatibility, validate `imago check` against deliberately
corrupt test images, cross-validate `imago compare` output against
`qemu-img compare`, and cross-validate `imago convert` output against
`qemu-img convert`. Tests use Python testtools/stestr.

```bash
# Set up test environment
make test-venv

# Run safe integration tests
make test

# Run tests with verbose output (shows diffs on failure)
make test-report

# Run all tests including malicious images (use with caution)
make test-malicious

# Clean test artifacts
make clean-tests
```

**Test structure:**
- `tests/manifest.json` - Defines test images and their safety levels
- `tests/test_info_safe.py` - Tests against known-safe images
- `tests/test_info_malicious.py` - Tests against malicious images using expected overrides
- `tests/test_check_formats.py` - Tests for check operation (format detection, corruption, validation, incompatible feature bits, ZSTD compression, extended L2 entries, ZSTD + backing chains, extended L2 + compressed clusters, refcount widths 1-64 bit, compressed cluster leak detection, large cluster sizes 256K-2MB, VMDK GD/GT validation with overlap detection, QCOW2 snapshot detection)
- `tests/test_compare.py` - Tests for compare operation (raw-vs-raw, QCOW2-vs-raw, QCOW2-vs-QCOW2, compressed QCOW2, backing chains)
- `tests/test_convert.py` - Tests for convert operation (QCOW2-to-raw, raw-to-QCOW2, QCOW2 re-encoding, compressed output with `-c` flag, backing chains, round-trip validation, errors, large cluster sizes up to 2MB, manifest-driven cross-validation against qemu-img including compressed output, encrypted QCOW2 decryption, snapshot extraction)
- `tests/test_oslo_crossval.py` - Cross-validation against oslo.utils
  format_inspector (format detection, safety checks, virtual size).
  Skips if oslo.utils is not installed.
- `tests/expected_outputs/` - Expected output files for malicious images

**Adding new test images:**

Use the `/imago-add-test-image` skill for guided assistance, or manually:

1. Add the image to `imago-testdata/` repository
2. Add an entry to `tests/manifest.json` with appropriate safety level
3. Add a scenario to the appropriate test file (`test_info_safe.py` or `test_info_malicious.py`)
4. For malicious images, create an expected output file in `tests/expected_outputs/`

**LUKS test images:** Synthetic LUKS headers (luks-v1, luks-v2) are
generated by `scripts/create-luks-headers.py` for header parsing tests.
Real LUKS containers (luks-v1-raw-gpt, luks-v1-qcow2) are created by
`scripts/create-luks-testdata.sh` using cryptsetup, with known test
passphrases stored in the manifest. These use `skip_qemu_img: true`
since qemu-img cannot inspect inside LUKS without a secret object.

See `docs/testing.md` for detailed documentation.

**Safety levels:**
- `safe` - Run by default, known-good images
- `caution` - Edge cases that may expose bugs
- `malicious` - CVE exploit images, require explicit opt-in

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

## Claude Code Skills

Custom skills are available in `.claude/skills/` to help with common development
tasks:

### `/imago-new-op` - Scaffold New Operations

Creates a complete operation skeleton with all required files:

```
/imago-new-op <operation-name> [description]
```

Example:
```
/imago-new-op checksum "Calculate checksums of disk images"
```

This creates:
- `src/operations/<name>/src/main.rs` - Entry point with call table setup
- `src/operations/<name>/Cargo.toml` - Dependencies and build config
- `src/operations/<name>/linker.ld` - Linker script for 0x20000 load address
- `src/operations/<name>/.cargo/config.toml` - Cross-compilation settings

### `/imago-format` - Disk Image Format Reference

Quick reference for format structures, magic numbers, and parsing details:

```
/imago-format [format]
```

Where `[format]` is: `qcow2`, `vmdk`, `raw`, or omit for overview.

### `/imago-debug` - Troubleshooting Guide

Diagnose and fix common issues when developing guest operations:

```
/imago-debug [issue]
```

Where `[issue]` is: `build`, `boot`, `virtio`, `calltable`, `panic`, or omit for
general guidance.

### `/imago-calltable` - Call Table API Reference

Complete documentation for the call table API used by operations:

```
/imago-calltable [function]
```

Where `[function]` is: `io`, `progress`, `config`, or omit for full reference.

### `/imago-add-test-image` - Add Test Images

Guided process for adding new disk images to the integration test suite:

```
/imago-add-test-image
```

This skill walks through:
1. Gathering image metadata (path, format, safety level, description)
2. Updating `tests/manifest.json`
3. Adding test scenarios to the appropriate test file
4. For malicious images: creating expected output files safely

## GitHub Automation

The project includes Claude Code-powered GitHub automation for common PR tasks.

### Available Bot Commands

Comment on a PR with these commands (requires write access to the repository):

- `@shakenfist-bot please re-review` - Request a fresh automated code review
- `@shakenfist-bot please retest` - Re-run functional tests without pushing a new commit
- `@shakenfist-bot please attempt to fix` - Have Claude attempt to fix failing tests
- `@shakenfist-bot please address comments` - Have Claude address automated review
  feedback, creating one commit per valid issue

### How Automated Review Works

The automated reviewer outputs structured JSON that is:
1. Validated against a JSON schema (`tools/review-schema.json`)
2. GitHub issues are created for actionable items (action=fix or action=document)
3. Rendered to human-readable markdown and posted as a PR comment
4. The raw JSON is embedded in a collapsed `<details>` section at the end of
   the comment, allowing the address-comments automation to extract it

The review comment includes links to the created issues with "Closes #N" syntax,
so issues are automatically closed when the PR merges.

Each review item has an `action` field:
- `fix` - Must be fixed before merging (creates an issue)
- `document` - Documentation should be added (creates an issue)
- `consider` - Optional improvement (reviewer suggestion)
- `none` - Informational observation only

### How Automated Comment Addressing Works

When you trigger `@shakenfist-bot please address comments`:

1. The bot extracts the `review.json` from the PR review comment (from the
   embedded `<details>` section)
2. It extracts items where `action` is `fix` or `document`
3. For each actionable item, Claude Code:
   - Analyzes whether the item should be addressed
   - If valid: makes the fix, runs pre-commit, and stages changes
   - If disagreeing: provides a rationale explaining why
4. Each valid fix gets its own commit with attribution
5. All commits are pushed and a summary is posted to the PR

This allows reviewers to cherry-pick or drop individual fixes as needed.

### Workflow Files

- `.github/workflows/functional-tests.yml` - Main CI with automated review
- `.github/workflows/pr-re-review.yml` - Manual re-review trigger
- `.github/workflows/pr-retest.yml` - Manual retest trigger via bot command
- `.github/workflows/pr-fix-tests.yml` - Test failure fixing
- `.github/workflows/pr-address-comments.yml` - Review comment addressing
- `.github/workflows/test-drift-fix.yml` - Scheduled/on-demand test maintenance

### Scripts

- `tools/review-pr-with-claude.sh` - Performs automated PR reviews (outputs JSON)
- `tools/address-comments-with-claude.sh` - Addresses review comments (reads JSON)
- `tools/create-review-issues.py` - Creates GitHub issues for actionable items
- `tools/render-review.py` - Renders review JSON to markdown (includes issue links)
- `tools/review-schema.json` - JSON schema for review output validation
