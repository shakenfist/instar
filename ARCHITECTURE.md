# Imago Architecture

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

### Imago's Approach

```
┌─────────────────────────────────────────────────────────────┐
│                        Host System                          │
│                                                             │
│  ┌─────────────┐     ┌─────────────────────────────────┐   │
│  │   Imago     │     │        KVM Sandbox              │   │
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

**Imago's default behavior (secure):** Files without recognized format headers
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
(host-side) code uses unsafe primarily for KVM ioctls and libc FFI — all
invariants are enforced. Guest-side format parsing uses unsafe for pointer
arithmetic on binary data, with comprehensive bounds checking on all
image-derived offsets. Integer arithmetic on untrusted input uses Rust's
checked arithmetic (`checked_mul`, `checked_add`). See
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
  and full subcluster bitmap parsing), compressed
  cluster decompression (zlib via `decompress` feature, ZSTD via
  `decompress-zstd` feature using ruzstd), cluster compression (behind
  `compress` feature flag using raw deflate via miniz_oxide), refcount
  table reading (all widths: 1/2/4/8/16/32/64-bit), compressed L2 entry
  parsing, backing file extraction, header extension parsing,
  incompatible feature bit validation. Supports cluster sizes from 512B
  to 2MB (cluster_bits 9-21). Used by info, check, compare, and convert
  operations.
- **crates/raw/** - Shared RAW format crate: MBR/GPT partition table
  detection. Used by info operation.
- **crates/vmdk/** - Shared VMDK format crate: VMDK4 binary header parsing
  (basic and full), descriptor I/O and text parsing, grain directory/table
  reading with sector-cached lookups, streamOptimized footer reading,
  grain marker handling, and write helpers for monolithicSparse and
  streamOptimized output. Used by info, check, convert, and compare
  operations.
- **crates/vhd/** - Shared VHD/VPC format crate: footer parsing and
  validation (conectix cookie, CHS geometry, disk type), dynamic header
  parsing (cxsparse cookie, BAT offset, block size), BAT reading with
  sector-cached lookups, block-level data access via BlockLookup enum,
  VhdState for stateful block I/O, sub-sector-aligned read support
  (`read_offset_sectors` for VHD data spanning device sector boundaries),
  and write helpers (build_footer, build_dynamic_header,
  compute_vhd_geometry). Used by info, check, convert, and compare
  operations.
- **crates/vhdx/** - Shared VHDX format crate: CRC-32C (Castagnoli)
  checksum implementation, dual header parsing with sequence number
  selection, region table parsing with CRC validation, GUID-based
  metadata item lookup, 64-bit BAT reading with interleaved sector
  bitmap entry handling, VhdxState for stateful block I/O, and output
  builders (file identifier, headers, region table, metadata, BAT
  entries). Used by check, convert, and compare operations.
- **crates/luks/** - Shared LUKS format crate: LUKS v1/v2 header
  constants, header parsing, PBKDF2 key derivation, Argon2id key
  derivation (behind `kdf-argon2` feature), AFsplitter key recovery,
  master key verification, and AES-XTS payload decryption (behind
  `decrypt` feature). Used by info and convert operations.
- **operations/info/** - Format detection operation
- **operations/copy/** - File copy operation
- **operations/check/** - Image integrity validation operation (with
  optional `--chain` backing chain validation)
- **operations/compare/** - Image comparison operation (format-aware virtual
  content comparison between two images, supporting raw, QCOW2, VMDK,
  VHD, and VHDX inputs including compressed clusters and backing chain
  flattening)
- **operations/convert/** - Image conversion operation (any input to raw,
  QCOW2 v3, VMDK, VHD, or VHDX output, with backing chain flattening
  and compressed cluster decompression). QCOW2 writer uses linear
  cluster allocation with OFLAG_COPIED, 16-bit refcounts, and iterative
  convergence for refcount metadata sizing. Sparse output is the default
  (skip zero-filled clusters, matching `qemu-img convert`); use
  `--no-skip-zeros` for dense output. Optional compressed output
  (`-c` flag) packs clusters at sector granularity using raw deflate
  (via miniz_oxide), with fallback to uncompressed for incompressible
  data. VHD writer emits dynamic VHD with 2 MiB blocks, sector bitmaps,
  and BAT rewriting (blocks aligned to output sector size with carry-buffer
  assembly to handle bitmap+data spanning sector boundaries). VHDX writer
  emits dynamic VHDX with 32 MiB blocks,
  1MB-aligned structures, CRC-32C checksums, and BAT rewriting.
- **shared/** - Shared library code between components (call table, configs,
  format detection, memory layout constants, shared utilities,
  `bump_allocator!` macro for operations needing heap allocation,
  centralized byte-order helpers: `be_u16/32/64`, `le_u16/32/64`,
  `write_be_u16/32/64`, `write_le_u16/32/64`)

**Chain validation in check (`--chain`):**
The check operation supports an optional `--chain` flag that uses the host-side
chain discovery infrastructure (same as `imago info --chain`) to discover the
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

### qcow2

QEMU Copy-On-Write version 2/3. Supported features:
- Sparse allocation with cluster sizes 512B-2MB (cluster_bits 9-21)
- Compression (zlib, zstd) for clusters up to 2MB
- Backing file chains (automatic flattening)
- Refcount widths: 1, 2, 4, 8, 16, 32, 64 bits
- Extended L2 entries (16-byte with subcluster bitmaps;
  full subcluster support — the bitmap is parsed for
  per-subcluster data reading: Normal, Zero, and
  Unallocated states)
- Incompatible feature bit validation
- External data files (metadata/data separation, chain discovery with allowlist)
- Legacy AES-128-CBC encryption (crypt_method=1) decryption via `--qcow2-password`
- LUKS-in-QCOW2 encryption (crypt_method=2) decryption via `--luks-passphrase`
- Snapshot table parsing, detection, and extraction via `--snapshot`

### raw

Simple byte-for-byte disk representation. No metadata, just data.

### vmdk

VMware Virtual Machine Disk. Supported sub-formats for input/output:
- monolithicSparse (input, output, check)
- streamOptimized (input, output with `-c`, check)

Detected but not yet supported for I/O:
- monolithicFlat
- twoGbMaxExtentSparse / twoGbMaxExtentFlat (multi-extent, detected and
  rejected gracefully)

The check operation performs full structural validation: grain directory
and grain table walk, grain offset bounds checking, overlap detection
via 1-bit-per-grain bitmap, streamOptimized footer validation, and
multi-extent detection.

### vhd

Microsoft Virtual Hard Disk. Supported sub-formats:
- Fixed (type 2): raw data with 512-byte footer appended
- Dynamic (type 3): BAT-based block allocation with 2 MiB blocks (input,
  output, check)

The check operation performs full structural validation: footer cookie
and checksum, dynamic header cookie and checksum, BAT offset and entry
bounds checking, overlap detection via 1-bit-per-block bitmap, and
footer copy consistency (start vs end of file).

### vhdx

Microsoft VHDX Virtual Hard Disk v2 (Hyper-V). Supported:
- Dynamic VHDX: BAT-based block allocation with 32 MiB blocks (input,
  output, check)

VHDX uses CRC-32C (Castagnoli) checksums, GUID-identified metadata,
64-bit BAT entries with interleaved sector bitmap entries, and 1MB-aligned
structures. All on-disk fields are little-endian.

The check operation performs full structural validation: dual header
CRC-32C validation with active header selection by sequence number,
dirty log detection, region table CRC-32C validation, GUID-based
metadata parsing, BAT entry validation (offset bounds, 1MB alignment,
overlap detection, state validation).

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

Generated images live in `../imago-testdata/custom/format-coverage/`.
The test manifest (`tests/manifest.json`) references them with
`generated_by` and `skip_qemu_img: true`.

## oslo.utils Cross-Validation

`tests/test_oslo_crossval.py` runs both imago and oslo.utils
`format_inspector` against every test image, comparing format
detection, safety verdicts, and virtual size. Known divergences
(GPT detection for raw images, QED banning, LUKS v2 rejection)
are documented in the test module. CI runs the crossval tests
against the PyPI release as part of the integration-test suite,
and a separate job runs them against oslo.utils git master to
catch upstream drift early.

## Open Questions

1. How to handle backing files in qcow2? Flatten on conversion?
2. Should we support in-place format conversion or always copy?
3. What's the minimum viable protocol for host-guest communication?
4. How to handle progress reporting and cancellation?
5. Memory limits for the sandbox?
