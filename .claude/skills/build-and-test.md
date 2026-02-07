# Imago Build and Test Skill

## Overview

Imago uses Docker devcontainers for building and testing. **Never run build scripts or cargo commands directly** - always use Makefile targets.

## Building

To build imago and all operation binaries:

```bash
make imago
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

Test images are stored in a separate repository: `imago-testdata` (sibling directory to `imago`).

The manifest file `tests/manifest.json` defines test images with properties:
- `run_in_ci`: Whether to include in CI test runs
- `skip_qemu_img`: Don't compare against qemu-img output
- `unsafe_quirks_required`: Needs `--unsafe-quirks` flag to match qemu-img

## Running imago manually

After building with `make imago`, binaries are in `src/target/release/`:

```bash
src/target/release/imago info <image>
src/target/release/imago check <image>
src/target/release/imago copy <input> <output>
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
