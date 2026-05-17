# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- **New `instar create` subcommand.** Creates a new empty disk
  image of a given format and size:
  `instar create [-f FMT] [OPTIONS] FILENAME [SIZE]`. Raw output
  is host-only (open + ftruncate + optional `--preallocation
  falloc`); qcow2 / vmdk / vpc (VHD) / vhdx run the new
  `create.bin` guest in the KVM sandbox and write the metadata
  via virtio. Supports backing files via
  `-b BACKING [-F FMT] [-u]` — the user-typed backing path is
  embedded verbatim into the new image so the reference stays
  portable, and the host resolves the path relative to the new
  image's directory when opening it. Per-format option flags
  (`--cluster-size`, `--refcount-bits`, `--extended-l2`,
  `--lazy-refcounts`, `--compat`, `--subformat`, `--grain-size`,
  `--block-size`), plus qemu-img-style
  `-o KEY=VAL,KEY=VAL,...` syntax that mirrors the same option
  matrix (`-o` wins on conflict). Recognises every key
  `qemu-img create -o` accepts for the supported formats —
  `size`, `backing_file`, `backing_fmt`, `cluster_size`,
  `compat`, `refcount_bits`, `extended_l2`, `lazy_refcounts`,
  `compression_type`, `subformat`, `grain_size`, and
  `block_size`. Unknown keys, encrypted-create (`encrypt.*`),
  external data files (`data_file*`), and deferred
  preallocation modes (`metadata` / `full`) return clear
  "deferred" errors with phase pointers. Output rendering:
  human one-liner (default), `--output=json`, or `-q` quiet.
  ([phase 1](docs/plans/PLAN-create-phase-01-emitters.md) ·
  [phase 2](docs/plans/PLAN-create-phase-02-guest-op.md) ·
  [phase 3](docs/plans/PLAN-create-phase-03-host-cli.md) ·
  [phase 4](docs/plans/PLAN-create-phase-04-target-options.md))

  Deferred to later phases:
  backing-file polish including vhdx-as-backing and multi-file
  vmdk subformats
  ([phase 5](docs/plans/PLAN-create.md)),
  preallocation modes beyond `off` and raw's `falloc`
  ([phase 6](docs/plans/PLAN-create.md)),
  comprehensive integration matrix and cross-version
  info-equivalence
  ([phase 8](docs/plans/PLAN-create.md)).

- **New `instar measure` subcommand.** Predicts the file size
  required to convert an image (or a hypothetical `--size N`
  image) to a target format. Output matches `qemu-img measure`
  byte-for-byte for raw and qcow2 targets across every qemu-img
  version 6.0.0 through 10.2.0; vmdk, vpc (VHD), and vhdx targets
  are instar-only since qemu-img cannot measure them. Accepts both
  individual clap flags and the qemu-img `-o key=value,...` syntax
  (`-o` wins on conflict). See
  [docs/measure.md](docs/measure.md) for the full reference.
  ([phase 3](docs/plans/PLAN-measure-phase-03-guest-op.md) ·
  [phase 4](docs/plans/PLAN-measure-phase-04-host-cli.md) ·
  [phase 5](docs/plans/PLAN-measure-phase-05-target-options.md))

- **Supporting library and crate-level pieces.** New
  `crates/measure/` (no_std, pure-function per-target size
  calculators), per-parser `scan_allocation` entry points on each
  format crate (raw / qcow2 / vmdk / vhd / vhdx),
  `MeasureConfig` / `MeasureResult` structs in `shared`, a new
  `MeasureResultMessage` protobuf field, and a new
  `send_measure_result` CallTable function pointer. CallTable
  version bumped from 13 to 14.
  ([phase 1](docs/plans/PLAN-measure-phase-01-calculators.md) ·
  [phase 2](docs/plans/PLAN-measure-phase-02-allocation-scanners.md) ·
  [phase 3](docs/plans/PLAN-measure-phase-03-guest-op.md))

- **Test and fuzz infrastructure.** Comprehensive integration
  tests for `instar measure` (`tests/test_measure.py`, 345 tests
  including cross-version baseline comparison for raw/qcow2
  targets, round-trip size-bound checks for vmdk/vpc/vhdx targets,
  and `-o` parsing). Cross-version baselines committed to
  `instar-testdata/expected-outputs/measure-*` for 80 qemu-img
  versions. Two new coverage-guided fuzz targets
  (`fuzz_measure_calc`, `fuzz_measure_scan`) in
  `src/fuzz/fuzz_targets/`. Differential fuzzer extended with an
  `op_measure` that compares instar against qemu-img for raw/qcow2
  and against `instar convert` output size for vmdk/vpc/vhdx.
  ([phase 6](docs/plans/PLAN-measure-phase-06-baselines.md) ·
  [phase 7](docs/plans/PLAN-measure-phase-07-integration-tests.md) ·
  [phase 8](docs/plans/PLAN-measure-phase-08-fuzz-coverage.md) ·
  [phase 9](docs/plans/PLAN-measure-phase-09-fuzz-differential.md))

- **Bug fixes surfaced during the measure work.**
  `parse_memory_size` accepts the T (terabyte) suffix alongside
  K/M/G (surfaced by phase 7b baselines). `instar measure -O qcow2`
  emits a leading `"bitmaps": 0` field in JSON output and the
  equivalent `bitmaps size: 0` trailing line in human output when
  the source is a qcow2 v3 image, matching qemu-img exactly
  (surfaced and refined by phase 7c source-image tests).

### Changed

- **CallTable ABI version bumped from 13 to 14** by the addition
  of `send_measure_result`. Stale operation binaries built against
  version 13 will fail-stop in `validate_call_table!` with a clear
  log message rather than silently miscompile.

- **`AllocationSummary` moved from `crates/measure` to
  `crates/shared`** so the per-format scanners can produce values
  of the type without depending on the measure crate (a back-compat
  re-export keeps phase 1 tests working).

## [0.2.0] - 2026-05-09

First public release.

### Changed

- **Project renamed** from `imago` to `instar` to avoid a
  crates.io name collision with an unrelated existing crate.
  The rename touches the binary name, crate names, environment
  variables, CI workflows, and documentation; there are no
  functional changes.
- **Guest binary resolver** now probes `INSTAR_BIN_DIR`, the
  executable directory, and `/usr/lib/instar/` in that order.
  Developer mode (binaries alongside the VMM in
  `src/target/release/`) keeps working as before; system
  installs from the new .deb/.rpm packages place the guest
  binaries under `/usr/lib/instar/` per FHS.

### Packaging

- **.deb and .rpm packages** are now produced for x86_64
  Linux as part of the release workflow. The VMM is installed
  at `/usr/bin/instar` and the six guest binaries
  (`core.bin`, `info.bin`, `copy.bin`, `check.bin`,
  `compare.bin`, `convert.bin`) at `/usr/lib/instar/`.
  Local builds: `make deb`, `make rpm`, or `make package`.
  The packages require **glibc 2.39 or newer** because the
  build container is based on Debian trixie. Compatible
  distributions include Debian 13, Ubuntu 24.04 LTS, Fedora
  40+, and Rocky/RHEL 10. Lowering the baseline to cover
  Rocky/RHEL 9, Debian 12, and Ubuntu 22.04 is tracked in
  docs/plans/PLAN-distro-matrix-ci.md.

### CI

- **Package smoke test** runs on every PR, building the .deb
  inside the devcontainer and installing it in a fresh
  debian:trixie container with `/dev/kvm` passthrough. The
  test verifies file layout under `/usr/bin` and
  `/usr/lib/instar/`, exercises the runtime resolver's
  fallback path, and runs a live `instar info` operation
  against KVM. Multi-distro and qemu-img differential
  coverage is planned for the merge queue (see
  docs/plans/PLAN-distro-matrix-ci.md).

### Fixed

- **check:** validate extended L2 subcluster bitmaps against QCOW2
  spec invalid-combination rules. Detects: alloc/zero bit overlap,
  alloc-without-host, host-without-ref, and compressed non-zero
  bitmap. Reports via new `subcluster-errors` JSON field and
  `debug_print` per variant.
- **convert:** write sparse subcluster bitmaps in QCOW2 extended-L2
  output (previously all subclusters were marked as allocated even
  when some contained only zeros).
- **qcow2 read:** narrow I/O for extended-L2 mixed subclusters when
  sector_size ≤ subcluster_size (skips disk reads for zero and
  unallocated subcluster ranges).

### Added (since v0.1)

- **New operations:** check, compare, convert (v0.1 had only
  info and copy)
- **Format crates** extracted into standalone `no_std` libraries:
  qcow2, vmdk, vhd, vhdx, luks, raw
- **Input formats:**
  - Raw (with MBR/GPT partition table validation)
  - QCOW2 v2/v3 (zlib and ZSTD compression, extended L2
    subclusters, AES-CBC and LUKS encryption, external data
    files, snapshots, backing chains)
  - VMDK (monolithicSparse, streamOptimized with DEFLATE
    compression, monolithicFlat and twoGbMaxExtentFlat
    multi-extent input, flat-in-backing-chain via
    parentFileNameHint)
  - VHD (fixed, dynamic, differencing with backing chains)
  - VHDX (dynamic, with CRC-32C validation)
  - LUKS v1/v2 containers (PBKDF2 and Argon2id KDF,
    AES-XTS decryption, inner format detection)
- **Output formats:** raw, QCOW2 v3 (with optional zlib
  compression, configurable cluster size), VMDK
  monolithicSparse (with optional DEFLATE compression,
  configurable grain size) and monolithicFlat (via
  `--subformat monolithicFlat`), VHD dynamic (configurable
  block size), VHDX dynamic (configurable block size)
- **Security model:** all image parsing runs inside a KVM
  sandbox; the host only handles opaque byte streams
- **Backing chain support:** chain discovery, flattening on
  convert, chain validation on check, security allowlist for
  backing file paths
- **qemu-img CLI compatibility:** output format matches
  qemu-img info, check, compare, and convert; auto-detects
  installed qemu-img version for output compatibility
- **Configuration:** layered config files (system, user,
  per-directory) with TOML format
- **Security audits:** static analysis, adversarial image
  testing (61 images, 12 attack categories), CVE reproduction
  (6 CVEs verified mitigated), VMM boundary audit
- **Fuzzing:** 13 coverage-guided fuzz targets, differential
  fuzzing against qemu-img, cross-validation against
  oslo.utils format_inspector
- **Release tooling:** Sigstore-signed tags, pre-compiled
  binary distribution via GitHub Releases

## [0.1] - 2026-01-28

Internal pre-release. Operations: info, copy. Format parsing
was inline (no standalone crates). No check, compare, or
convert operations. No public binary distribution.

[0.2.0]: https://github.com/shakenfist/instar/releases/tag/v0.2.0
[0.1]: https://github.com/shakenfist/instar/releases/tag/v0.1
