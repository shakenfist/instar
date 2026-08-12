# Agents Guide for Instar

This document provides guidance for AI agents working on the instar codebase.

## Project Overview

Instar is a safe, sandboxed disk image format converter. It replaces unsafe
`qemu-img` calls with conversions performed inside a KVM sandbox.

## Repository Structure

```
instar/
├── .devcontainer/  # Development containers (rust-lint)
├── src/            # Main instar implementation
│   ├── vmm/        # Virtual machine monitor (host-side)
│   ├── core/       # Core guest initialization
│   ├── crates/     # Shared format crates (qcow2, raw, vmdk, vhd, vhdx, luks, vdi, parallels, qcow1, dmg)
│   ├── shared/     # Shared library code (byte-order helpers, configs)
│   ├── operations/ # Pluggable operations (info, copy, check, compare, convert, dd, measure, create, resize, rebase, commit, map, snapshot, amend, bitmap, bench)
│   └── build.sh    # Build script
├── crates/         # Shared Rust crates (guest-protocol)
├── prototypes/     # Experimental implementations (11 KVM prototypes)
├── scripts/        # Build, check, and test image generation scripts
├── tests/          # Integration tests (Python/testtools)
├── docs/           # Design documents, research notes, and Lions-style commentary
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
- The VMM (host-side) code has been security audited — see
  `docs/security-audits.md` for full results and `PLAN-audit.md`
  for methodology

### Guest fault handling

The guest `core` installs a minimal IDT (`core/src/idt.rs`) as its first
boot step, covering the CPU exception vectors (0..=31). Any guest CPU
exception — for example an invalid opcode (`#UD`) from a codegen
miscompile, or a page fault from a stray pointer — is caught and reported
to the host as a clean `cpu-exception` error naming the vector and
faulting RIP, instead of escalating to a silent triple fault (which KVM
surfaces only as an opaque `VcpuExit::Shutdown`). This is the safety net
behind the guest ops' `#[inline(never)]` discipline: several runners carry
`#[inline(never)]` to dodge an intermittent `opt-level=z`+`lto` control-flow
miscompile (issue #375). Those attributes are still load-bearing, but a
recurrence now reports the vector and address instead of vanishing. Keep
them, and prefer the small-`_start` shape when adding operations.

### Supported Formats

Write formats (create / convert-output / dd-output): qcow2 (including
external data files), raw, vmdk, vpc (VHD), vhdx (VHDX).

luks: info + decrypting convert / compare / dd (v1/v2; no create/write).

Read-only input formats (convert / compare / dd / bench source; no
create/write): vdi, parallels (both magics), qcow (QCOW1, including
backing chains and compressed clusters), dmg (UDIF, zlib/raw/zero/ignore
chunk codecs).

Detection + info only (no read path): bochs, cloop.

qed: detected; every other op refused by policy (nil demand plus
oslo.utils' explicit ban), not by inability.

See [docs/format-coverage.md](docs/format-coverage.md)'s qemu-img
parity axis for the full op × format matrix.

### Operations

- `info`: report format, virtual size, and metadata for a disk image
- `copy`: raw byte-for-byte copy of a disk image
- `check`: validate image structure and integrity, and optionally repair
  qcow2 refcount/COPIED inconsistencies in place (`--repair[=leaks|all]`)
- `compare`: byte-identical virtual-content comparison between two images
- `convert`: convert a disk image from one format to another
- `measure`: predict file size required to convert an image to a target
  format. See [docs/measure.md](docs/measure.md) for the full reference.
- `create`: create a new empty disk image of a given format and size.
  Raw output is host-only (open + ftruncate + optional falloc / full
  zero-fill); every other format runs `crates/create` in the KVM
  sandbox and writes the metadata via virtio. Supports backing files
  (`-b BACKING [-F FMT]`) and the full qemu-img-style
  `-o KEY=VAL,...` option matrix (`-o` wins over individual flags
  on conflict). Preallocation modes: `off` (any format),
  `metadata` / `falloc` / `full` (qcow2; raw also accepts
  `falloc` / `full`). Non-qcow2 sparse formats (vmdk / vpc / vhdx)
  reject non-`off` preallocation with a "future work" pointer.
  See [docs/create.md](docs/create.md) for the full reference.
- `resize`: change the virtual size of an existing disk image in
  place. End-spec grammar matches qemu-img:
  `FILENAME [+-]SIZE[bkKMGTPE]` accepts absolute (`64M`), additive
  (`+1G`), and subtractive (`-512M`) forms. Raw resize is host-only
  (`open(O_RDWR) + ftruncate` plus optional preallocation
  post-pass); qcow2 / vmdk / vpc / vhdx run `crates/resize` in the
  KVM sandbox, which reads the existing header, plans the metadata
  mutation, and applies patches via virtio. qcow2 + raw support
  grow and shrink (`--shrink` required for shrink); vmdk / vpc /
  vhdx are grow-only. Preallocation `falloc` / `full` (raw + qcow2)
  preallocates only the newly-appended file region — a deliberate
  divergence from qemu's whole-data-region preallocation, queued
  under Future work. `qemu-img resize` cannot resize vmdk / vpc /
  vhdx on any shipped version (documented coverage gap; instar
  resize works for all three with coverage via the internal
  consistency suite). See [docs/resize.md](docs/resize.md) for the
  full reference.
- `map`: emit the allocation map of a disk image as a stream of
  contiguous extents covering `[0, virtual_size)`, mirroring
  `qemu-img map`. The guest binary walks the source's
  on-disk allocation metadata and streams one extent per coalesced
  run over the serial channel; the host renderer writes each extent
  to stdout as it arrives, so host memory stays O(1) regardless of
  fragmentation. Human and JSON output match `qemu-img map` byte-
  for-byte modulo a small list of documented divergences (raw
  sparseness not detected, VHD unallocated blocks reported as
  `present: false`, VHDX partial-present treated as data, qcow2
  compressed clusters reported as `compressed: false`, backing-
  chain `depth` always 0, `--image-opts` rejected). Window flags
  `--start-offset` / `--max-length` clip the emission range. See
  [docs/map.md](docs/map.md) for the full reference.
- `snapshot`: manage the internal snapshots of a qcow2 image
  (qcow2-only, like `qemu-img snapshot`). `-l` lists
  (byte-identical to qemu-img's modern layout; `--output=json`
  is an instar extension with QMP `SnapshotInfo` key names);
  `-c` / `-d` / `-a` create, delete, and apply snapshots
  entirely inside the KVM guest — refcount mutations, L1
  copies, COPIED-flag rewrites, and the header commit point are
  all guest-side writes with `fsync` barriers between groups.
  Delete matches by name only; apply matches ID-then-name in
  two full passes (qemu's matcher asymmetry). Mutating modes
  refuse `refcount_bits != 16`, compressed clusters,
  encryption, external data files, bitmaps, and dirty images;
  v1 caps the table at 16 snapshots. Post-op images are
  bit-for-bit identical to qemu-img's given identical inputs
  (modulo documented freed-cluster / file-tail notes —
  docs/quirks.md). Verified by seven shell harnesses
  (`make snapshot-harnesses`, 241 assertions, also run in CI),
  `tests/test_snapshot.py`, two coverage-guided fuzz targets,
  and the differential fuzzer's `op_snapshot` chain. See
  [docs/snapshot.md](docs/snapshot.md) for the full reference.
- `amend`: change a qcow2 image's compat version
  (`-o compat=0.10|1.1`, v2⇔v3) and/or the `lazy_refcounts`
  flag (`-o lazy_refcounts=on|off`) in place, rewriting only
  the header cluster — like `qemu-img amend`. qcow2-only;
  needs `/dev/kvm` (guest VMM). v1 gates: v3→v2 downgrade
  refused if a v3-only incompatible feature is set (compression
  type, extended L2, external data, dirty, corrupt) or
  `refcount_bits != 16`; `lazy_refcounts=on` requires v3;
  header-extension relocation across the version change is
  unsupported. Covered by Rust round-trip unit tests, Python
  integration tests with post-op `info`/`check`/`compare`
  cross-validation against `qemu-img amend`, cross-version
  `qemu-img info` baselines (6.0.0–10.2.0), and coverage +
  differential fuzzing. See [docs/amend.md](docs/amend.md)
  for the full reference.
- `dd`: windowed block copy — `instar dd [-f FMT] [-O OUTPUT_FMT]
  if=INPUT of=OUTPUT [bs=N] [count=N] [skip=N]` — qemu-img dd
  compatible (name=value operands, -O defaults to raw); reuses
  `convert.bin` via a windowed `ConvertConfig` with dense output.
- `bitmap`: manage a qcow2 image's persistent dirty bitmaps —
  `--add`/`--remove`/`--clear`/`--enable`/`--disable`/`--merge
  SOURCE` (repeatable, applied in command-line order), plus `-g`
  granularity and `--output {human,json}` — the sandboxed
  equivalent of `qemu-img bitmap`. qcow2 v3-only; runs in the KVM
  guest (needs `/dev/kvm`). The pure `no_std` planner lives in
  `src/crates/bitmap` (directory/table/action/merge logic, reusing
  the snapshot refcount mutators). Covered by `tests/test_bitmap.py`
  integration parity against `qemu-img bitmap`, cross-version
  baselines, and coverage + differential fuzzing. See
  [docs/bitmap.md](docs/bitmap.md).
- `bench`: issue a scripted sequence of read/write requests against a
  disk image and report how long they took — the sandboxed equivalent
  of `qemu-img bench`, except it measures instar's own end-to-end
  sandboxed I/O path (guest format layer → virtio-block → host I/O
  thread) rather than qemu's block layer over the page cache, so the
  two tools' numbers are comparable only to each other on an identical
  invocation, never in isolation. Reads all nine formats (raw, qcow2,
  vmdk, vhd, vhdx, vdi, parallels, qcow1, dmg); write tests (`-w`) are
  supported on raw and qcow2 only, including qcow2 overlays.
  The qcow2 `-w` path runs on the shared `crates/qcow2-write` planner
  and `crates/qcow2-write-exec` executor (third consumer after commit
  and rebase; PLAN-qcow2-write-infrastructure phase 6), and the
  refcount-growth planner now lives in that crate's `growth` module.
  Since phase 7, `bench -w` (like commit and rebase safe mode)
  copy-on-writes snapshot-bearing qcow2 images rather than refusing
  them — the shared crate's COW branch copies snapshot-shared clusters
  before modifying them, proven check-clean and read-back-parity
  against qemu.
  `--output {human,json}` mirrors qemu's human output byte-for-byte or
  emits a stable JSON schema for regression tracking.
  `CallTable::VERSION` bumped from 19 to 20 for the appended
  `send_bench_start`/`send_bench_result` callbacks. Covered by
  `tests/test_bench.py` (76 tests), the `fuzz_bench_schedule` coverage
  fuzzer, and the differential fuzzer's `op_bench` arm. See
  [docs/bench.md](docs/bench.md).

## Working on This Project

### When Adding Prototypes

1. Create a subdirectory under `prototypes/` with a descriptive name
2. Include a README explaining the approach being tested
3. Document any dependencies or build requirements

### Planning Documents

Tracked planning documents live in `docs/plans/` and follow the structure
in `PLAN-TEMPLATE.md` at the repo root. Each tracked plan is committed
alongside the work it describes, with phase plans named
`PLAN-<feature>-phase-NN-<descriptive>.md` next to the master plan.
`docs/plans/index.md` summarises every master plan; `docs/plans/order.yml`
controls the documentation navigation order.

Drafts dropped at the repo root (`PLAN-<feature>.md`) remain local-only
via the anchored `.gitignore` rule (`/PLAN-*.md`). Use repo-root drafts
for early scribbling that is not yet ready to commit; promote to
`docs/plans/` when the plan is shareable.

When starting a major feature:
1. Sketch a draft in the repo root (gitignored) if you want to iterate
   privately, or skip straight to step 2 once you know the shape.
2. Create `docs/plans/PLAN-<feature>.md` from `PLAN-TEMPLATE.md`,
   commit it on the same branch as the implementation work, and add a
   row to `docs/plans/index.md` plus an entry in
   `docs/plans/order.yml`.
3. For phased work, add `docs/plans/PLAN-<feature>-phase-NN-<descriptive>.md`
   files alongside the master plan and link them from the master's
   Execution table.

### Code Style

- Follow the conventions of whatever language is being used
- Prioritize clarity over cleverness
- Comment security-relevant decisions

For Rust code specifically:
- Run `rustfmt` for formatting (pre-commit hook enforces this)
- Run `clippy` for linting (pre-commit hook enforces this)
- Use `./scripts/check-rust.sh fix` to auto-fix formatting issues
- Never call `.unwrap()` in production code — the workspace enables
  clippy's `unwrap_used` lint (CI runs `-D warnings`, so a new unwrap
  fails lint). Use `?`/proper error propagation, or
  `.expect("why this cannot fail")` for provably-infallible cases
  (`.expect("lock poisoned")` for mutexes). Test code is exempt via
  `clippy.toml`'s `allow-unwrap-in-tests`; archived prototypes declare
  the lint but CI does not gate on it there.

### Pre-commit Hooks

Pre-commit hooks are configured for Rust code quality. Before committing:

```bash
pre-commit run --all-files
```

The hooks use a dedicated Docker container (`.devcontainer/rust-lint/`) with
stable Rust to ensure consistent results across all development environments.

### Toolchain pinning

The build devcontainer (`src/.devcontainer/Dockerfile`) pins its Rust
nightly via `ARG RUST_NIGHTLY=nightly-YYYY-MM-DD` — a broken floating
nightly otherwise breaks every from-scratch image build (a 2026-07-24
nightly ICE'd compiling tokio inside `cargo install cargo-audit` and
took out CI's "Build devcontainer" step). Renovate cannot bump rustup
toolchain pins; instead the weekly `rust-nightly-bump` workflow
(`tools/ci/bump-rust-nightly.sh`) test-builds the image, instar, and
the Rust test suite against the newest published nightly and opens a
bump PR only when everything passes. Do not un-pin the toolchain, and
do not bump the pin by hand without at least building the full image.
(The lint container is separate and uses a stable `rust:` tag Renovate
does manage.)

### CI test partition

Integration tests are split across several CI jobs by stestr regex
selectors (the `test-container-*` Makefile targets). The
`test-partition` CI job (`tools/ci/check-test-partition.sh`) fails if
any `test_*.py` test is run by **no** pull-request job. When you add a
new integration test module or a new integration job, the guard
validates that the new partition still covers everything; an orphan is
a hard CI failure. Deliberate exclusions live in an allowlist in
`tools/ci/check-test-partition.py` (currently just the malicious
suite). See [docs/testing.md](docs/testing.md).

### Using the Makefile

The project includes a Makefile for common development tasks:

```bash
# Show all available commands
make help

# List available prototypes
make list-prototypes

# Build the main instar project
make instar

# Build a specific prototype
make build-prototype PROTOTYPE=virtio-block5

# Build all prototypes
make build-all

# Run lint checks
make lint

# Auto-fix formatting
make lint-fix

# Clean instar build
make clean-instar

# Clean a prototype's target directory
make clean-prototype PROTOTYPE=virtio-block5

# Clean everything (all targets + Docker images)
make distclean
```

### Building and Running Instar

The main instar implementation is in `src/`:

```bash
# Build instar
make instar

# Run instar (requires KVM)
sudo src/target/release/instar info <IMAGE>
sudo src/target/release/instar copy <INPUT> <OUTPUT>
```

### Integration Testing

Integration tests compare `instar info` output against `qemu-img info` to verify
drop-in replacement compatibility, validate `instar check` against deliberately
corrupt test images, cross-validate `instar compare` output against
`qemu-img compare`, cross-validate `instar convert` output against
`qemu-img convert`, and cross-validate `instar measure` output against
`qemu-img measure` for raw and qcow2 targets. Tests use Python testtools/stestr.

```bash
# Set up test environment
make test-venv

# Run safe integration tests
make test

# Run tests with verbose output (shows diffs on failure)
make test-report

# Run all tests including malicious images (use with caution)
make test-malicious

# Run tests inside container (as CI does)
make test-container

# CI splits tests into three parallel jobs by format family:
make test-container-core              # info, check, security, oslo-crossval
make test-container-convert-qcow2    # QCOW2/VMDK/RAW convert + compare
make test-container-convert-vhd      # VHD/VHDX convert (slowest)

# Clean test artifacts
make clean-tests
```

**Test structure:**
- `tests/manifest.json` - Defines test images and their safety levels
- `tests/test_info_safe.py` - Tests against known-safe images
- `tests/test_info_malicious.py` - Tests against malicious images using expected overrides
- `tests/test_check_formats.py` - Tests for check operation
  (format detection, corruption, validation, incompatible
  feature bits, ZSTD compression, extended L2 entries, ZSTD
  + backing chains, extended L2 + compressed clusters,
  refcount widths 1-64 bit, compressed cluster leak
  detection, large cluster sizes 256K-2MB, VMDK GD/GT
  validation with overlap/compressed grain marker/RGD checks,
  VHD fragmentation/version/feature/fixed size validation,
  VHDX file identifier/region table cross-check/fragmentation,
  QCOW2 snapshot detection, TestExtendedL2Subclusters for
  partial subcluster allocation with Normal/Zero/Unallocated
  states)
- `tests/test_check_repair.py` - Tests for `check --repair`
  (leaks/all tiers repair the corrupt-fixture matrix to
  `qemu-img check`-clean with guest data preserved; the
  snapshot/compression/corrupt-bit refuse paths stay
  byte-identical; the overlapping case is a safe partial repair;
  plus `--repair`+`--chain` rejection, clean-image no-op,
  qcow2-only handling, and idempotence)
- `tests/test_compare.py` - Tests for compare operation
  (raw-vs-raw, QCOW2-vs-raw, QCOW2-vs-QCOW2, compressed
  QCOW2, backing chains, LUKS-in-QCOW2 decryption)
- `tests/test_convert.py` - Tests for convert operation
  (QCOW2-to-raw, raw-to-QCOW2, QCOW2 re-encoding,
  compressed output with `-c` flag, backing chains,
  round-trip validation, errors, large cluster sizes up to
  2MB, manifest-driven cross-validation against qemu-img
  including compressed output, encrypted QCOW2 decryption,
  LUKS-in-QCOW2 decryption, native LUKS v1/v2 decryption,
  LUKS v2 with Argon2id KDF and --max-guest-memory,
  LUKS-wrapping-QCOW2 conversion, snapshot extraction,
  extended L2 output with `--extended-l2`,
  LUKS-encrypted output with `--luks-encrypt-passphrase`)
- `tests/test_adversarial.py` - Adversarial image tests: compression bombs, circular
  backing chains, deep chains, integer overflow triggers, refcount order edges,
  oversized virtual sizes, VMDK grain size boundaries, VHDX conflicting dual
  headers, VHD/VHDX BAT beyond EOF, polyglot files (QCOW2+VMDK, QCOW2+ELF),
  truncated headers (QCOW2, VMDK, VHD), VMDK descriptor attacks (null bytes,
  multi-extent, huge size). Uses `run_adversarial()` helper with timeout/memory/
  signal enforcement.
- `tests/test_security.py` - Security feature detection tests (backing files,
  external data files, VMDK descriptors, raw format validation, backing chain
  security) and CVE reproduction tests (CVE-2024-32498 external data file,
  CVE-2015-5163 backing file traversal, CVE-2022-47951 VMDK descriptor,
  CVE-2015-5162 resource exhaustion, CVE-2014-0223 L1 integer overflow,
  CVE-2024-4467 json:{} format confusion). 19 CVE tests verify all 6 CVEs
  are mitigated.
- `tests/test_oslo_crossval.py` - Cross-validation against oslo.utils
  format_inspector (format detection, safety checks, virtual size).
  Skips if oslo.utils is not installed.
- `tests/test_snapshot.py` - Integration tests for the `instar snapshot`
  subcommand (phase 11): 12-image list matrix vs cross-version baselines,
  12 JSON golden comparisons with structural cross-check, mutation
  round-trips (create/delete/apply) with `qemu-img check` post-op
  assertions, error paths and qcow2-only enforcement, empty-table
  behaviour. JSON goldens in `tests/golden/snapshot-list/`.
- `tests/test_bench.py` - Integration tests for the `instar bench`
  subcommand (62 tests): read/write request scheduling, host-side
  validation matrix, the qcow2 write-envelope gates, `--output json`
  schema validation, human-output byte-parity with `qemu-img bench`,
  and the `KNOWN_BENCH_DIVERGENCES` registry.
- `tests/expected_outputs/` - Expected output files for malicious images

**Adding new test images:**

Use the `/instar-add-test-image` skill for guided assistance, or manually:

1. Add the image to `instar-testdata/` repository
2. Add an entry to `tests/manifest.json` with appropriate safety level
3. Add a scenario to the appropriate test file (`test_info_safe.py` or `test_info_malicious.py`)
4. For malicious images, create an expected output file in `tests/expected_outputs/`

**Adversarial test images:** Generated by scripts in `instar-testdata/scripts/`
(compression bombs, circular/deep chains, integer overflow headers, boundary
values for refcount order, virtual size, grain size, dual headers, BAT entries,
polyglot files, truncated headers, VMDK descriptor attacks, CVE reproducers).
Images live in `../instar-testdata/custom/audit/`. Scripts that generate
adversarial or CVE-reproducer images must always be placed in the private
`instar-testdata` repository, never in the public `instar/scripts/` directory.

**LUKS test images:** Synthetic LUKS headers (luks-v1, luks-v2) are
generated by `scripts/create-luks-headers.py` for header parsing tests.
Real LUKS containers (luks-v1-raw-gpt, luks-v1-qcow2) are created by
`scripts/create-luks-testdata.sh` using cryptsetup, with known test
passphrases stored in the manifest. The `luks-v1-aes-xts` test image is
built by `scripts/create-native-luks-testdata.py` (no root required) with
known encrypted content for conversion testing. The `luks-v2-aes-xts`
test image is built by `scripts/create-native-luks-v2-testdata.py` with
low-memory Argon2id parameters for LUKS v2 conversion testing. The
`luks-v1-qcow2-inner` test image is created by
`scripts/create-luks-qcow2-inner-testdata.sh` for testing LUKS containers
wrapping QCOW2 images. LUKS-in-QCOW2 test images are created by
`scripts/create-qcow2-luks-testdata.sh`. These use `skip_qemu_img: true`
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

### `/instar-new-op` - Scaffold New Operations

Creates a complete operation skeleton with all required files:

```
/instar-new-op <operation-name> [description]
```

Example:
```
/instar-new-op checksum "Calculate checksums of disk images"
```

This creates:
- `src/operations/<name>/src/main.rs` - Entry point with call table setup
- `src/operations/<name>/Cargo.toml` - Dependencies and build config
- `src/operations/<name>/linker.ld` - Linker script for 0x20000 load address
- `src/operations/<name>/.cargo/config.toml` - Cross-compilation settings

### `/instar-format` - Disk Image Format Reference

Quick reference for format structures, magic numbers, and parsing details:

```
/instar-format [format]
```

Where `[format]` is: `qcow2`, `vmdk`, `raw`, or omit for overview.

### `/instar-debug` - Troubleshooting Guide

Diagnose and fix common issues when developing guest operations:

```
/instar-debug [issue]
```

Where `[issue]` is: `build`, `boot`, `virtio`, `calltable`, `panic`, or omit for
general guidance.

### `/instar-calltable` - Call Table API Reference

Complete documentation for the call table API used by operations:

```
/instar-calltable [function]
```

Where `[function]` is: `io`, `progress`, `config`, or omit for full reference.

### `/instar-add-test-image` - Add Test Images

Guided process for adding new disk images to the integration test suite:

```
/instar-add-test-image
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

The review job lives in the shared workflow
`shakenfist/actions/.github/workflows/pr-auto-review.yml`, not in this
repository. `automated_reviewer` in `functional-tests.yml` is only the caller:
its `needs:` list names this project's test jobs, which is what gates the
review on CI passing. The runner, the timeout, the bot-commit check and the
fork restriction all live in the shared workflow.

Reviews run on same-repository pull requests only. The reviewer runs Claude
Code with `--dangerously-skip-permissions` while holding a token with
`pull-requests: write` and `issues: write`, and the PR diff is untrusted
input, so a fork PR is skipped rather than reviewed. Fork PRs get a skipped
job, not a failing one.

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

- `.github/workflows/functional-tests.yml` - Main CI, and the caller for the
  shared automated review workflow
  (`shakenfist/actions/.github/workflows/pr-auto-review.yml`)
- `.github/workflows/release.yml` - Release workflow (Sigstore-signed tags, GitHub Releases with pre-compiled binaries)
- `.github/workflows/pr-re-review.yml` - Manual re-review trigger
- `.github/workflows/pr-retest.yml` - Manual retest trigger via bot command
- `.github/workflows/pr-fix-tests.yml` - Test failure fixing
- `.github/workflows/pr-address-comments.yml` - Review comment addressing
- `.github/workflows/test-drift-fix.yml` - Scheduled/on-demand test maintenance
- `.github/workflows/differential-fuzz.yml` - On-demand differential fuzzing (instar vs qemu-img + libyal)
- `.github/workflows/coverage-fuzz.yml` - Coverage-guided fuzzing of parser crates (nightly + PR)
- `.github/workflows/fuzz-autofix.yml` - Automated fuzzer bug fix (daily Claude Code, 30-turn limit)

### Scripts

- `tools/review-pr-with-claude.sh` - Performs automated PR reviews (outputs JSON)
- `tools/address-comments-with-claude.sh` - Addresses review comments (reads JSON)
- `tools/create-review-issues.py` - Creates GitHub issues for actionable items
- `tools/render-review.py` - Renders review JSON to markdown (includes issue links)
- `tools/review-schema.json` - JSON schema for review output validation
- `scripts/differential-fuzz.py` - Differential fuzzing script (instar vs qemu-img + libyal)
- `scripts/extract-fuzz-corpus.py` - Seeds + restores the coverage-fuzz corpus from instar-testdata
- `tools/ci/fuzz-tier.sh` - Computes tiered nightly per-target fuzz durations
- `tools/ci/report-fuzz-crash.sh` - Files the `security-audit` issue for a coverage-fuzz crash (bounds the log excerpt, dedups against open issues; see "Crash reporting" in `docs/testing.md`)
- `tools/ci/pick-fuzz-artifact.sh` - Chooses which libFuzzer artifact to report as the reproducer
- `tools/ci/test-report-fuzz-crash.sh`, `tools/ci/test-pick-fuzz-artifact.sh` - Tests for those two; run them after any change (the `ci-tooling` CI job does)
