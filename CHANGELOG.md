# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- Added `crates/measure/`: a `no_std` size-calculator library with
  per-format estimators (raw, qcow2, vmdk, vhd, vhdx). Foundation for
  the upcoming `measure` operation.
  (PLAN-measure-phase-01-calculators.md)
- Added `scan_allocation()` to each format crate (raw, qcow2, vmdk,
  vhd, vhdx), producing `shared::AllocationSummary` for the measure
  subcommand. Pure slice-walking helpers
  (`count_allocated_in_l2_standard`, `count_allocated_in_l2_extended`,
  `count_allocated_in_bat`, `count_populated_gd_entries`,
  `count_allocated_in_gt`) are exposed for direct unit testing and
  future fuzzing.
  (PLAN-measure-phase-02-allocation-scanners.md)
- Added `operations/measure/` guest binary that produces a
  MeasureResultMessage over the serial channel given a source image
  (or `virtual_size_override`) and a target format. CLI surface ships
  in phase 4. (PLAN-measure-phase-03-guest-op.md)
- `instar measure` subcommand: predict the file size required to
  convert a source image (or hypothetical `--size N` image) to a
  target format. Output matches `qemu-img measure` byte-for-byte for
  raw and qcow2 targets; vmdk, vpc, vhdx are instar-only.
  (PLAN-measure-phase-04-host-cli.md)
- Added `MeasureConfig` and `MeasureResult` structs to `shared`, and
  `MeasureResultMessage` (field 10) to the GuestMessage protobuf oneof,
  plus the `measure_result_message` helper in `crates/guest-protocol`.
  (PLAN-measure-phase-03-guest-op.md)

### Changed

- Moved `AllocationSummary` from `crates/measure` to `crates/shared`
  (with a back-compat re-export from `measure`) so format crates can
  produce values of the type without depending on `measure`.
- Bumped `CallTable::VERSION` from 13 to 14, adding
  `send_measure_result` as the last function pointer. Operation
  binaries built against the older version will fail-stop in
  `validate_call_table!` rather than silently miscompile.

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
