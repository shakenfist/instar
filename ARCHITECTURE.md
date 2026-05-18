# Instar Architecture

## Design Goals

1. **Security first** - Untrusted image data never touches host-privileged code
2. **Format fidelity** - Accurate conversion between qcow2, raw, and vmdk
3. **Performance** - Minimize overhead from sandboxing
4. **Simplicity** - Clean API that's easy to integrate

## Security Model

### The Problem with qemu-img

`qemu-img` is a powerful tool but runs with full host privileges. When
processing untrusted disk images, any vulnerability in format parsing code
could lead to host compromise. Historical CVEs in qemu-img include buffer
overflows, integer overflows, and other memory safety issues.

### Instar's Approach

```
┌─────────────────────────────────────────────────────────────┐
│                        Host System                          │
│                                                             │
│  ┌─────────────┐     ┌─────────────────────────────────┐   │
│  │   Instar    │     │        KVM Sandbox              │   │
│  │   Client    │────▶│  ┌─────────────────────────┐    │   │
│  │             │     │  │   Conversion Engine     │    │   │
│  │ (handles    │◀────│  │   (parses formats,      │    │   │
│  │  I/O only)  │     │  │    performs conversion) │    │   │
│  └─────────────┘     │  └─────────────────────────┘    │   │
│                      └─────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
```

The host-side client:
- Opens source and destination files
- Streams raw bytes to/from the sandbox
- Never interprets image format structures

The sandboxed conversion engine:
- Runs inside a minimal KVM guest
- Parses source format, writes destination format
- Any exploit is contained within the sandbox

### RAW Format Validation

A key security enhancement over qemu-img is partition table validation for RAW
format detection. qemu-img treats any unrecognized file as a valid RAW disk
image, which is the root cause of backing file disclosure attacks (CVE-2015-5163,
CVE-2024-32498).

**Instar's default behavior (secure):** Files without recognized format headers
must have a valid partition table (MBR or GPT) to be accepted as RAW disk images.
Files without valid partition tables are rejected as "unknown format."

**With `--unsafe-quirks`:** Matches qemu-img behavior for compatibility testing.
This flag should never be used in production.

Detection logic:
- MBR: Valid 0x55AA signature at offset 510, plus valid boot indicators (0x00/0x80)
- GPT: Protective MBR with partition type 0xEE

See [quirks.md](docs/quirks.md) for details on safe vs unsafe quirks classification.

### Security Audits

All `unsafe` code in the codebase has been audited and classified. The VMM
(host-side) code has undergone a full boundary audit covering virtio-block
device emulation, serial protocol handling, MMIO dispatch, and KVM exit
handling — 8 bugs were found and fixed. Guest-side format parsing uses
unsafe for pointer arithmetic on binary data, with comprehensive bounds
checking on all image-derived offsets. Integer arithmetic on untrusted
input uses Rust's checked arithmetic (`checked_mul`, `checked_add`). See
[docs/security-audits.md](docs/security-audits.md) for full audit results.

## Communication Protocol

TBD - Options to explore:
- virtio-vsock for guest-host communication
- Shared memory regions with explicit synchronization
- Simple serial/console based protocol for prototyping

## Prototype Approaches

### Approach A: Minimal Linux Guest

Use a tiny Linux distribution (like Alpine or a custom initramfs) running
inside KVM. The guest runs a conversion daemon that communicates with the
host via virtio-vsock.

Pros:
- Can reuse existing libraries (e.g., qemu-img inside the guest)
- Familiar debugging environment
- Flexible

Cons:
- Larger attack surface (full Linux kernel)
- Higher memory/CPU overhead
- Boot time latency

### Approach B: Unikernel

Build a unikernel that only contains the conversion logic. No separate
kernel/userspace distinction.

Pros:
- Minimal attack surface
- Fast boot times
- Lower resource usage

Cons:
- More complex development
- Limited library ecosystem
- Harder to debug

### Approach C: Custom Bare-Metal (Active)

Write a minimal bare-metal program that runs directly under KVM with no OS.
Just enough code to handle virtio communication and format conversion.

**This is the approach being actively explored.**

Pros:
- Absolute minimum attack surface
- Fastest possible boot/execution
- Complete control

Cons:
- Significant development effort
- Must implement everything from scratch
- No existing tooling

**Progress:**
- [helloworld](prototypes/helloworld/) - Minimal KVM VMM with serial output
- [helloworld2](prototypes/helloworld2/) - Uses vm-memory crate for safer memory
- [virtio-block](prototypes/virtio-block/) - Virtio-block device emulation with file copy
- [virtio-block2](prototypes/virtio-block2/) - Adds guest-protocol (protobuf) integration
- [virtio-block3](prototypes/virtio-block3/) - Adds configurable sector sizes
- [virtio-block4](prototypes/virtio-block4/) - Adds performance statistics tracking
- [virtio-block5](prototypes/virtio-block5/) - Adds ioeventfd optimization
- [virtio-block6](prototypes/virtio-block6/) - Adds sparse/dynamic output file support
- [pluggable](prototypes/pluggable/) - Modular operations architecture
- [pluggable2](prototypes/pluggable2/) - Separate binary loading for operations
- [info](prototypes/info/) - Image format detection (qemu-img info equivalent)

**Current Implementation:**
The `info` prototype has been promoted to the main implementation in `src/`. This
provides a modular architecture with:
- **vmm/** - Host-side virtual machine monitor
- **core/** - Guest initialization (device init, call table)
- **crates/qcow2/** - Shared QCOW2 format crate: header parsing, L1/L2
  cluster lookup (including extended L2 with 16-byte entries
  and full subcluster bitmap parsing), subcluster bitmap validation
  (`validate_subcluster_bitmap()` enforcing QCOW2 spec
  invalid-combination rules), compressed cluster decompression (zlib
  via `decompress` feature, ZSTD via `decompress-zstd` feature using
  ruzstd), cluster compression (behind `compress` feature flag using
  raw deflate via miniz_oxide), refcount table reading (all widths:
  1/2/4/8/16/32/64-bit), compressed L2 entry parsing, backing file
  extraction, header extension parsing, incompatible feature bit
  validation. Supports cluster sizes from 512B to 2MB (cluster_bits
  9-21). Used by info, check, compare, convert, and measure
  operations. Also exposes `Qcow2State::scan_allocation` plus the
  pure helpers `count_allocated_in_l2_standard` /
  `count_allocated_in_l2_extended` to produce a
  `shared::AllocationSummary` consumed by the `measure` subcommand.
- **crates/raw/** - Shared RAW format crate: MBR/GPT partition table
  detection. Used by info operation. Also exposes a trivial
  `scan_allocation` (allocated_bytes == virtual_size) for the measure
  subcommand.
- **crates/vmdk/** - Shared VMDK format crate: VMDK4 binary header parsing
  (basic and full), descriptor I/O and text parsing, grain directory/table
  reading with sector-cached lookups, streamOptimized footer reading,
  grain marker handling, and write helpers for monolithicSparse and
  streamOptimized output. Used by info, check, convert, and compare
  operations. Also exposes `VmdkState::scan_allocation` plus
  `count_populated_gd_entries` / `count_allocated_in_gt` for the measure
  subcommand.
- **crates/vhd/** - Shared VHD/VPC format crate: footer parsing and
  validation (conectix cookie, CHS geometry, disk type), dynamic header
  parsing (cxsparse cookie, BAT offset, block size), BAT reading with
  sector-cached lookups, block-level data access via BlockLookup enum,
  VhdState for stateful block I/O, sub-sector-aligned read support
  (`read_offset_sectors` for VHD data spanning device sector boundaries),
  and write helpers (build_footer, build_dynamic_header,
  compute_vhd_geometry). Used by info, check, convert, and compare
  operations. Also exposes `VhdState::scan_allocation` plus the pure
  helper `count_allocated_in_bat` for the measure subcommand.
- **crates/vhdx/** - Shared VHDX format crate: CRC-32C (Castagnoli)
  checksum implementation, dual header parsing with sequence number
  selection, region table parsing with CRC validation, GUID-based
  metadata item lookup, 64-bit BAT reading with interleaved sector
  bitmap entry handling, VhdxState for stateful block I/O, and output
  builders (file identifier, headers, region table, metadata, BAT
  entries). Used by check, convert, and compare operations. Also
  exposes `VhdxState::scan_allocation` plus `count_allocated_in_bat`
  (which handles the chunk_ratio bitmap interleaving) for the measure
  subcommand.
- **crates/luks/** - Shared LUKS format crate: LUKS v1/v2 header
  constants, header parsing, PBKDF2 key derivation, Argon2id key
  derivation (behind `kdf-argon2` feature), AFsplitter key recovery,
  master key verification, and AES-XTS payload decryption (behind
  `decrypt` feature). Used by info and convert operations.
- **crates/measure/** - Shared size-calculator crate (`no_std`, no I/O):
  per-output-format estimators (raw / qcow2 / vmdk / vhd / vhdx) for the
  `required` and `fully-allocated` byte counts that `qemu-img measure`
  emits. The qcow2 estimator matches qemu-img's worst-case sizing
  semantics (L2 tables sized for the full virtual range; refcount layout
  sized once for the fully-allocated cluster count and reused for the
  sparse case). `AllocationSummary` has been moved to `crates/shared` so
  format crates can produce it without depending on `measure`; a
  back-compat re-export remains in this crate. Consumed by the
  `measure` operation in `src/operations/measure/`; intended for
  later reuse by `create` / `resize` once those subcommands ship.
- **operations/info/** - Format detection operation
- **operations/copy/** - File copy operation
- **operations/check/** - Image integrity validation operation (with
  optional `--chain` backing chain validation)
- **operations/compare/** - Image comparison operation (format-aware virtual
  content comparison between two images, supporting raw, QCOW2, VMDK,
  VHD, and VHDX inputs including compressed clusters, backing chain
  flattening, and LUKS-in-QCOW2 decryption via `--luks-passphrase`)
- **operations/convert/** - Image conversion operation (any input to raw,
  QCOW2 v3, VMDK, VHD, or VHDX output, with backing chain flattening
  and compressed cluster decompression). Scratch memory layout is computed
  at runtime via `ScratchLayout` based on output cluster size, enabling
  QCOW2 output with cluster sizes from 512B to 2MB. Three conceptual
  buffers (header, L2 table, refcount block) share a single multipurpose
  buffer since they are used in non-overlapping phases. QCOW2 writer
  uses linear cluster allocation with OFLAG_COPIED, 16-bit refcounts,
  and iterative convergence for refcount metadata sizing. Sparse output
  is the default (skip zero-filled clusters, matching `qemu-img convert`);
  use `--no-skip-zeros` for dense output. Optional compressed output
  (`-c` flag) packs clusters at sector granularity using raw deflate
  (via miniz_oxide), with fallback to uncompressed for incompressible
  data. VMDK writer emits monolithicSparse, streamOptimized, or
  monolithicFlat output (via `--subformat monolithicFlat`) with
  configurable grain size (4KB-64KB via `--grain-size`, default
  64KB) for sparse/streamOptimized. VHD writer emits dynamic VHD with configurable block size
  (512KB+ via `--block-size`, default 2MB), sector bitmaps, and BAT
  rewriting (blocks aligned to output sector size with carry-buffer
  assembly to handle bitmap+data spanning sector boundaries). VHDX
  writer emits dynamic VHDX with configurable block size (1MB-256MB
  via `--block-size`, default 32MB), 1MB-aligned structures, CRC-32C
  checksums, and BAT rewriting.
- **operations/measure/** - Image-size measurement operation. Predicts
  `required` (sparse, holes skipped) and `fully-allocated` (every
  cluster/grain/block written) byte counts for a target output format.
  Supported targets: raw, qcow2, vmdk, vpc (VHD), vhdx. For raw and
  qcow2 targets the host CLI's output (human and `--output=json`)
  matches `qemu-img measure` byte-for-byte; vmdk, vpc, and vhdx are
  instar-only because `qemu-img measure` does not support them. CLI
  flags mirror qemu-img (`--size SIZE | FILENAME`, `-O target-format`,
  `-f source-format`, `--output {human,json}`) plus per-target options
  as individual flags (`--cluster-size`, `--refcount-bits`,
  `--extended-l2`, `--compat`, `--preallocation`, `--subformat`,
  `--grain-size`, `--block-size`). Accepts both individual flags and
  `-o key=value,...` (qemu-img parity); `-o` values override individual
  flags when both are given.
  Single-source-device only; backing-chain composition and VMDK
  monolithicFlat sources are deferred. Integration tests in
  `tests/test_measure.py` cross-validate `instar measure` against
  the `qemu-img measure` baselines in
  `instar-testdata/expected-outputs/measure-*` for every safe-tier
  image and every curated `--size` case, plus round-trip the
  vmdk / vpc / vhdx outputs through `instar convert` to verify the
  predicted size bounds. Known scanner-divergence cases (raw
  SEEK_HOLE detection, qcow2/vhdx/vmdk overcounts on some real-world
  images, VHD CHS rounding) are skipped with documented reasons
  pending follow-up work.
- **operations/create/** - Empty-image creation operation. Reads a
  `CreateConfig` (target format, virtual size, per-format options,
  optional backing reference) from `OPERATION_CONFIG_ADDR`, optionally
  recovers the virtual size from a backing image's header on input
  device 0, calls the matching `crates/create::plan_*` to build a
  `MetadataPlan`, and writes every entry to the output device via
  `write_output_sector`. Backing-file lookup supports raw, qcow2,
  vmdk, vhd, and vhdx source headers (phase 5 added the vhdx path
  via `vhdx::VhdxState::init`'s metadata-region walk). When the
  target and backing are both vmdk, the guest also reads the
  parent's descriptor via `vmdk::read_and_parse_descriptor` and
  plumbs the real `parentCID` into the new image's descriptor
  (no longer the phase-1d deadbeef sentinel). The host CLI
  (`run_create` in `src/vmm/src/main.rs`, wired in phase 3) handles
  the raw target entirely host-side via open + ftruncate +
  optional posix_fallocate; for every other format it opens the
  output as a writable virtio device, optionally attaches the
  backing file as input device 0, populates `CreateConfig`, and
  launches `create.bin`. Result rendering supports human
  ("Created: ..."), JSON (`--output=json`), and quiet (`-q`)
  modes. Phase 4 wires the qemu-img-style
  `-o KEY=VAL,...` parser (`parse_create_o_options` +
  `apply_create_overrides` in `src/vmm/src/main.rs`) so the
  full per-format option matrix is reachable via either
  individual `--flag` forms or qemu-img-compatible `-o`
  syntax; `-o` wins on conflict. Phase 5 added two error codes —
  `ERROR_BACKING_FORMAT_UNSUPPORTED` (recognised format but
  size extraction not implemented) and
  `ERROR_BACKING_SIZE_TOO_LARGE` (pre-flight ceiling check
  surfaces a clearer "try a larger cluster size" hint instead
  of plan_*'s generic `InvalidVirtualSize`). Phase 6 added
  preallocation modes for raw and qcow2: for qcow2,
  `Preallocation::{Metadata,Falloc,Full}` (any non-Off mode)
  extends the `qcow2::create::Qcow2Layout` to cover L2 tables
  and a data region, populates L1 entries with L2 offsets
  (each with `OFLAG_COPIED`), and marks every used cluster
  (header + L1 + reftable + refblocks + L2 + data) refcount=1.
  The L2 tables are emitted by the guest *outside* the
  `MetadataPlan` (via a reusable single-cluster scratch slot)
  because they can total far more than
  `GUEST_CREATE_SCRATCH_LIMIT` (128 MiB at 1 TiB virtual with
  64 KiB clusters); the plan's `minimum_file_size` carries
  the total file size so the guest also writes a final
  trailing zero sector to extend the file. `Falloc` and
  `Full` lay out the same metadata as `Metadata`; the host's
  `apply_preallocation` helper (`src/vmm/src/main.rs`) layers
  `posix_fallocate` or a `fill_zeros` pass (tries
  `fallocate(FALLOC_FL_ZERO_RANGE)` first, falls back to a
  `pwrite` loop with a 64 KiB zero buffer) over the data
  region. Raw also gains the same `full` zero-fill path via
  `fill_zeros(fd, 0, virtual_size)`. Non-qcow2 sparse formats
  (vmdk / vpc / vhdx) reject non-`off` preallocation with a
  "future work" pointer — each format would need its own
  BAT-population pattern. The host enforces
  `--sector-size=512` because the `crates/create` MetadataPlan
  entries are 512-byte aligned but not always to larger sector
  sizes — relaxing this needs a planner-side change to emit
  coalesced sector-sized writes; tracked in PLAN-create.md's
  Future-work section. The binary builds at ~36 KiB / 384 KiB
  and is excluded from `cargo test --workspace` like the
  other `no_main` operation binaries. Integration tests in
  `tests/test_create.py` cross-validate the create writer on
  three surfaces: per-`(target, case)` comparison via
  `qemu-img info` against phase 7's recorded baselines
  (`instar-testdata/expected-outputs/create-info-json/<target>/`);
  runtime cross-validation creating the same image twice
  (instar + system qemu-img) and comparing via `instar info`;
  and full-matrix `instar check` round-trip for writer/reader
  self-consistency. The normalisation filter in
  `tests/helpers/info_json.py` strips the divergence whitelist
  (filename, actual-size, vmdk cid + parent-cid, vhdx log-size,
  the wrapping-file physical size, cache hints) before
  comparison; remaining writer divergences (qcow2
  refcount_bits hardcode, qcow2 compat hardcode, zstd
  accept-ignore, vhdx default block_size, vhd CHS-rounded
  virtual_size) are documented as per-case skips rather than
  whitelist extensions so each gap stays visible.
- **shared/** - Shared library code between components (call table, configs,
  format detection, memory layout constants, shared utilities,
  `bump_allocator!` macro for operations needing heap allocation,
  centralized byte-order helpers: `be_u16/32/64`, `le_u16/32/64`,
  `write_be_u16/32/64`, `write_le_u16/32/64`). Also defines
  `AllocationSummary`, the common result type produced by each format
  crate's `scan_allocation` function and consumed by the `measure`
  subcommand. `MeasureConfig` and `MeasureResult` structs carry
  options and results across OPERATION_CONFIG_ADDR and the
  `send_measure_result` CallTable callback (CallTable VERSION 14).
  Phase 2 of `PLAN-create.md` adds `CreateConfig` / `CreateResult` /
  `GUEST_CREATE_SCRATCH_LIMIT` here and a new `send_create_result`
  CallTable function pointer (appended at the end of the struct so
  existing operation binaries keep working unchanged).

**Chain validation in check (`--chain`):**
The check operation supports an optional `--chain` flag that uses the host-side
chain discovery infrastructure (same as `instar info --chain`) to discover the
full backing chain, then sets up each image as a separate virtio-block device
in the KVM guest. The guest validates each backing image for format consistency,
non-zero virtual size, and QCOW2 header integrity (magic, version,
cluster_bits, L1/refcount table bounds, corrupt feature flag). Backing file
paths are validated against the security allowlist before being opened. Chain
errors are reported separately from primary image errors.

The rust-vmm project provides crates that reduce implementation effort by 70%+:
- `kvm-ioctls` - Safe KVM API wrappers
- `kvm-bindings` - KVM bindings
- `vm-memory` - Guest memory abstraction
- `virtio-queue` - Virtqueue implementation
- `virtio-bindings` - Virtio protocol bindings

### Guest Memory Map

The guest runs in 32 MiB of physical memory (`GUEST_MEM_SIZE = 0x2000000`).
Constants are defined in `src/shared/src/lib.rs` with compile-time overlap
checks.

```
Address         Size    Region
──────────────  ──────  ─────────────────────────────────────────
0x0000_1000             GDT
0x0000_2000             Page tables
0x0001_0000     64 KiB  core.bin (guest entry point)
0x0002_0000    384 KiB  Operation binary (info/copy/check)
0x0008_0000      4 KiB  Call table
0x0008_1000      4 KiB  Operation config
0x0008_2000      1 KiB  Chain config
0x0010_0000      1 MiB  Virtqueue memory (16 devices × 64 KiB)
0x0020_0000     64 KiB  DMA pool
0x0030_0000   12.9 MiB  Scratch memory (temporary bitmaps/buffers)
0x00FF_0000     64 KiB  ── guard gap ──
0x0100_0000      4 MiB  Stack (grows down from STACK_TOP)
0x0140_0000   12.0 MiB  (unused)
0x0200_0000             End of guest memory
```

See [docs/chain-config.md](docs/chain-config.md) for the chain config
structure layout and VMM-to-guest data flow.

## Format Support

**Measurable target formats**: raw, qcow2 (qemu-img-parity),
vmdk, vpc (VHD), vhdx (instar-only — qemu-img does not
implement `measure` for these targets).

### qcow2

QEMU Copy-On-Write version 2/3. Supported features:
- Sparse allocation with cluster sizes 512B-2MB (cluster_bits 9-21)
- Compression (zlib, zstd) for clusters up to 2MB
- Backing file chains (automatic flattening)
- Refcount widths: 1, 2, 4, 8, 16, 32, 64 bits
- Extended L2 entries (16-byte with subcluster bitmaps;
  full subcluster support — the bitmap is parsed for
  per-subcluster data reading: Normal, Zero, and
  Unallocated states; the read path narrows I/O for mixed-
  subcluster clusters when sector_size ≤ subcluster_size).
  Output with `--extended-l2` writes 16-byte L2 entries with
  `incompatible_features` bit 4 and per-subcluster sparse
  bitmaps (`compute_subcluster_bitmap()`).
- Incompatible feature bit validation
- External data files (metadata/data separation, chain discovery with allowlist)
- Legacy AES-128-CBC encryption (crypt_method=1) decryption via `--qcow2-password`
- LUKS-in-QCOW2 encryption (crypt_method=2) decryption via `--luks-passphrase`
- LUKS-encrypted output (crypt_method=2) via `--luks-encrypt-passphrase`
  (AES-256-XTS with PBKDF2-SHA256 key derivation, LUKS v1 headers)
- Snapshot table parsing, detection, and extraction via `--snapshot`

### raw

Simple byte-for-byte disk representation. No metadata, just data.

### vmdk

VMware Virtual Machine Disk. Supported sub-formats for input/output:
- monolithicSparse (input, output, check)
- streamOptimized (input, output with `-c`, check)
- monolithicFlat (input and output): two-file descriptor + flat extent.
  The VMM detects the descriptor prefix on the host, parses the
  extent line via `vmdk::parse_descriptor_extents`, validates
  the flat path against the backing-file allowlist, and opens
  the flat extent as a second virtio-block device. Guest
  operations read content from that device through the same
  `ChainConfig.data_device_idx` redirect used for QCOW2
  external data files. Output via `--subformat monolithicFlat`.
- twoGbMaxExtentFlat (input): multi-extent flat descriptors with
  multiple flat extent files. Each extent is opened as a separate
  virtio-block device and reads are dispatched to the correct
  device based on the extent offset map.
- monolithicFlat with `parentFileNameHint=` (input): descriptors
  referencing a parent are followed as a backing chain, enabling
  flat images in overlay hierarchies.

Detected but not yet supported for I/O:
- twoGbMaxExtentSparse (multi-extent sparse, detected and rejected
  gracefully)

The check operation performs full structural validation: grain directory
and grain table walk, grain offset bounds checking, compressed grain
marker validation (LBA consistency and compressed size bounds),
redundant grain directory (RGD) cross-check, overlap detection via
1-bit-per-grain bitmap, streamOptimized footer validation, fragmentation
measurement, and multi-extent detection.

### vhd

Microsoft Virtual Hard Disk. Supported sub-formats:
- Fixed (type 2): raw data with 512-byte footer appended
- Dynamic (type 3): BAT-based block allocation with 2 MiB blocks (input,
  output, check)

The check operation performs full structural validation: footer cookie
and checksum, format version and feature flag validation, dynamic header
cookie/checksum/version, BAT offset and entry bounds checking, overlap
detection via 1-bit-per-block bitmap, fragmentation tracking, fixed VHD
size validation, and footer copy consistency (start vs end of file).

### vhdx

Microsoft VHDX Virtual Hard Disk v2 (Hyper-V). Supported:
- Dynamic VHDX: BAT-based block allocation with 32 MiB blocks (input,
  output, check)

VHDX uses CRC-32C (Castagnoli) checksums, GUID-identified metadata,
64-bit BAT entries with interleaved sector bitmap entries, and 1MB-aligned
structures. All on-disk fields are little-endian.

The check operation performs full structural validation: file identifier
signature check, dual header CRC-32C validation with active header
selection by sequence number, dirty log detection, region table 1 and 2
CRC-32C validation with cross-consistency check, GUID-based metadata
parsing, BAT entry validation (offset bounds, 1MB alignment, overlap
detection, state validation), and fragmentation tracking.

### luks

LUKS encrypted containers (v1 and v2). The info operation parses:
- Version, cipher name, cipher mode, hash algorithm
- UUID, payload offset, master key length, active key slots
- LUKS v2: JSON metadata area for cipher/hash extraction

With `--luks-passphrase`, LUKS v1 and v2 containers are decrypted inside
the KVM guest using pure-Rust RustCrypto crates (software AES, no
hardware acceleration needed in bare-metal). Key derivation uses PBKDF2
(v1) or Argon2id (v2, requires `--max-guest-memory` for the 1GB+ working
memory). The decrypted first block is passed through format detection to
report the inner format and virtual size.

The convert operation supports decrypting native LUKS containers
(`--luks-passphrase`) and LUKS-in-QCOW2 images (crypt_method=2). Both
use AES-XTS-plain64 for payload decryption. Native LUKS containers
wrapping QCOW2 images are transparently handled: the convert operation
detects the inner QCOW2 format and wraps the CallTable I/O function
pointers to offset and decrypt reads, allowing the qcow2 crate to
process the inner image without modification. LUKS v2 containers
using Argon2id KDF require `--max-guest-memory` to allocate the
working memory needed for key derivation.

## Test Image Generation

Synthetic test images that cannot be created by `qemu-img` are built
by scripts in `scripts/`:

- `create-vhd-testdata.sh` — Fixed VHD (disk_type=2) and differencing
  VHD (disk_type=4) via Python struct packing and qemu-img patching
- `create-vmdk-testdata.sh` — Binary VMDK4 with multi-extent descriptor
- `create-luks-testdata.sh` — LUKS v1 containers with inner formats
- `create-native-luks-testdata.py` — LUKS v1/v2 with known encrypted
  content (v1 raw, v2 Argon2id, v1 wrapping QCOW2)
- `create-qcow2-luks-testdata.sh` — QCOW2 with LUKS encryption (crypt_method=2)
- `create-check-testdata.sh` — QCOW2 images with specific corruptions
Adversarial and CVE-reproducer image generation scripts live in
`instar-testdata/scripts/` (the private testdata repository), not in
the public `instar/scripts/` directory. This includes scripts for
compression bombs, circular/deep chains, integer overflow headers,
boundary values, format confusion, and CVE reproducers.

Generated images live in `../instar-testdata/custom/format-coverage/`
and `../instar-testdata/custom/audit/` (adversarial images).
The test manifest (`tests/manifest.json`) references them with
`generated_by` and `skip_qemu_img: true`.

### Cross-version qemu-img baselines

`instar-testdata` ships a per-qemu-version baseline matrix
generated by `make baselines-info` / `make baselines-check` /
`make baselines-measure` (and aggregated via `make baselines`),
plus a `create-info-json` matrix produced by
`python scripts/generate-baselines.py --command create`.
Each command writes recorded stdout / stderr / exit-code triples
to `expected-outputs/<output-type>/[bucket/]<version>/<image-id>.{stdout,
stderr,meta.json}`, then `make profiles` deduplicates them into
profile buckets via `scripts/detect-profiles.py`. instar's
integration tests select the matching baseline for the locally
installed qemu-img version. Currently 80 versions are covered
(6.0.0 through 10.2.0). The measure baselines additionally use
a `_size/` pseudo-bucket for `--size`-mode invocations that have
no source image, and a `__<target>` suffix on source-image
filenames to record both `-O raw` and `-O qcow2` measurements
of the same image. The create baselines bucket by target format
(`create-info-json/<target>/<version>/<case-name>.{stdout,…}`)
and run a two-step pipeline (`qemu-img create` then `qemu-img
info --output=json`) — the recorded artefact is the info JSON
on the produced fixture, not create's own log line. Per-
invocation random fields (vmdk `cid` / `parent-cid`, vhdx
header-id) prevent dedup from collapsing duplicate-output
versions, so each version gets its own profile; phase 8's
comparison logic excludes those random fields from the
field-equivalence check.

## oslo.utils Cross-Validation

`tests/test_oslo_crossval.py` runs both instar and oslo.utils
`format_inspector` against every test image, comparing format
detection, safety verdicts, and virtual size. Known divergences
(GPT detection for raw images, QED banning, LUKS v2 rejection)
are documented in the test module. CI runs the crossval tests
against the PyPI release as part of the integration-test suite,
and a separate job runs them against oslo.utils git master to
catch upstream drift early.

## Differential Fuzzing

`scripts/differential-fuzz.py` implements Phase 3 of the security audit plan.
For each iteration it:

1. Generates a random disk image using qemu-img (varying format, virtual size,
   cluster size, compression, and data patterns).
2. Creates separate copies for instar and qemu-img.
3. Runs a random chain of 2-4 operations (info, check, convert, compressed
   convert, measure) against both tools.
4. Compares outputs: exit codes, JSON info output (after normalisation to
   remove known-divergent fields like disk size), and converted file content
   (via SHA-256 of raw-flattened output).

The `measure` operation uses two oracles depending on target. For
`raw` and `qcow2` targets, the fuzzer parses both `instar measure
--output=json` and `qemu-img measure --output=json` outputs and
compares the numeric `required`, `fully-allocated`, and `bitmaps`
fields. For `vmdk`, `vpc`, and `vhdx` targets (which qemu-img
measure does not support), it asserts a self-consistency bound:
`instar convert -O <target>` output file size must lie at or below
`fully_allocated + cushion`, with the cushion scaled to absorb
the convert writer's per-block sector alignment slack
(`max(1 MiB, fully_allocated / 16)`).

Known quirks (see `docs/quirks.md`) are excluded from comparison: non-QCOW2
formats for `check` (qemu-img only checks QCOW2), disk size fields, and
format-specific metadata.

### libyal Cross-Validation

When libyal tools are installed (`libvmdk-utils`, `libvhdi-utils`,
`libqcow-utils`), the fuzzer adds two additional layers of comparison:

1. **Info cross-check**: Parsed fields from libyal tools (virtual size,
   format version, cluster size, etc.) are compared against instar's JSON
   output for the same image.
2. **Parse-success consistency**: For each format, if the libyal tool
   successfully parses the image, instar check should report no errors
   (and vice versa). Disagreements are flagged as divergences.

This closes the gap where VMDK/VHD/VHDX had no differential reference for
check validation, and provides a third independent opinion for QCOW2 beyond
qemu-img. libyal tools are optional — the fuzzer degrades gracefully when
they are unavailable.

The CI workflow (`.github/workflows/differential-fuzz.yml`) runs on
`[self-hosted, debian-12, xl]` VM runners with KVM access. It accepts
configurable iteration count, seed, and timeout, uploads logs as artifacts,
and auto-files GitHub Issues with the `security-audit` label for any
divergences found.

### Coverage-Guided Fuzzing

Coverage-guided fuzzing (`src/fuzz/`) uses `cargo-fuzz` (libFuzzer) to
exercise the `no_std` parser crates directly without the VMM/KVM stack.
A mock `CallTable` (in `src/fuzz/src/lib.rs`) backed by thread-local
fuzzer input provides sector-based I/O, allowing libFuzzer to explore
deeply malformed inputs.

15 fuzz targets cover all parser crates: format detection, header
parsing (QCOW2, VMDK, VHD, VHDX, RAW, LUKS), L1/L2 cluster lookup,
refcount table traversal, zlib decompression, grain directory lookup,
BAT traversal, VHDX metadata parsing, plus the measure subcommand's
calculator math (`fuzz_measure_calc`) and the per-parser
`scan_allocation` entry points (`fuzz_measure_scan`).

The seed corpus is extracted from `instar-testdata` by
`scripts/extract-fuzz-corpus.py`, which filters images by format and
generates hand-crafted minimal valid inputs. The CI workflow
(`.github/workflows/coverage-fuzz.yml`) runs nightly at 04:00 UTC
(1 hour per target), with PR smoke tests and manual dispatch. Crashes
are minimized and filed as GitHub Issues immediately.

## Open Questions

1. How to handle backing files in qcow2? Flatten on conversion?
2. Should we support in-place format conversion or always copy?
3. What's the minimum viable protocol for host-guest communication?
4. How to handle progress reporting and cancellation?
5. Memory limits for the sandbox?
