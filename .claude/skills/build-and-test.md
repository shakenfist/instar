# Instar Build and Test Skill

## Overview

Instar uses Docker devcontainers for building and testing. **Never run build scripts or cargo commands directly** - always use Makefile targets.

## Building

To build instar and all operation binaries:

```bash
make instar
```

This runs the build inside a Docker container with all necessary Rust toolchains (including nightly for no_std binaries).

**Do NOT use:**
- `./build.sh` directly
- `cargo build` directly
- `source ~/.cargo/env && ...`

## Testing

### Run CI-safe tests (recommended for development):

```bash
make test-ci
```

### Run all tests including malicious images:

```bash
make test-malicious
```

### Run tests with verbose output:

```bash
make test-report
```

## Test Data

Test images are stored in a separate repository: `instar-testdata` (sibling directory to `instar`).

The manifest file `tests/manifest.json` defines test images with properties:
- `run_in_ci`: Whether to include in CI test runs
- `skip_qemu_img`: Don't compare against qemu-img output
- `unsafe_quirks_required`: Needs `--unsafe-quirks` flag to match qemu-img

## Running instar manually

After building with `make instar`, binaries are in `src/target/release/`:

```bash
src/target/release/instar info <image>
src/target/release/instar check <image>
src/target/release/instar copy <input> <output>
```

The user is in the `kvm` group, so `sudo` is not required.

## Pre-commit

Always run before committing:

```bash
pre-commit run --all-files
```

## Common Issues

1. **VM crash messages after output**: These appear on stderr and don't affect the actual operation result. The exit code indicates success/failure.

2. **Test failures**: See `testing-discipline.md` for proper handling. Never assume failures are pre-existing without verification.
