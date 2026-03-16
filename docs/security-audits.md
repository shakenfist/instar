# Security Audits

This document records the results of security audits performed on
imago. For the threat model and CVE analysis, see [security.md](security.md).

## Reporting Vulnerabilities

If you discover a security vulnerability in imago, please report it
via [GitHub Security Advisories](https://github.com/shakenfist/imago/security/advisories/new).
Do not file public issues for security vulnerabilities.

## Phase 1: Static Analysis and Code Review

**Date:** 2026-03-14
**Scope:** All Rust source code in the imago workspace (15 crates)
**Techniques:** Manual unsafe code audit, integer arithmetic review,
automated linting (cargo clippy, cargo audit)

### Unsafe Code Audit

Every `unsafe` block and `unsafe fn` in the codebase was classified
as **sound** (invariants enforced), **fragile** (invariants hold but
depend on implicit assumptions), or **unsound** (invariants can be
violated by untrusted input).

#### VMM (host-side) — highest priority

The VMM runs on the host with full privileges. Bugs here bypass the
KVM sandbox entirely.

| Location | Category | Verdict | Notes |
|----------|----------|---------|-------|
| vmm/main.rs: ACTIVE_MMIO_BASE | Static mut read/write | Fragile | Should use OnceLock; safe in practice (single-threaded setup) |
| vmm/main.rs: set_user_memory_region | KVM API | Sound | Memory region lifetime managed correctly |
| vmm/io_thread.rs: epoll syscalls | libc FFI | Sound | All FDs validated, errors checked |
| vmm/ioevent.rs: KVM_IOEVENTFD ioctls | libc FFI | Sound | Structs fully initialized, errors checked |
| vmm/kvm_stats.rs: KVM_CHECK_EXTENSION | libc FFI | Sound | Capability check, no safety concern |
| vmm/virtio/block.rs: ByteValued impls | Trait impls | Sound | All 5 structs are repr(C) POD with no padding |

**VMM summary:** 0 unsound, 1 fragile (cosmetic — static mut could
use OnceLock), all others sound.

#### Guest core

| Location | Category | Verdict | Notes |
|----------|----------|---------|-------|
| core/main.rs: SingleThreadCell | Interior mutability | Sound | Single vCPU enforces invariant |
| core/main.rs: cstr_to_str | Pointer scan | Fragile | Bounded to 4096 bytes, UTF-8 validated; relies on operation providing valid readable memory |
| core/main.rs: call_operation | Transmute to fn ptr | Inherent | Design boundary — operation binary IS the untrusted code |
| core/main.rs: ct_read_input_sector | Buffer pointer | Fragile | Device index bounds-checked; buffer pointer trusted from operation |
| core/main.rs: ct_write_output_sector | Buffer pointer | Fragile | Buffer pointer trusted from operation |
| core/main.rs: ct_send_info_result_* | Struct pointer | Fragile | Null-checked but non-null validity trusted |
| core/main.rs: ct_get_chain_config | Config pointer | Sound | Magic validated before returning |
| core/main.rs: setup_call_table | CallTable write | Sound | Fixed address, guaranteed by memory layout |
| core/virtio.rs: MMIO access | Volatile read/write | Sound | Fixed addresses, bounds-checked ring indices |
| core/serial.rs: asm! blocks | x86 I/O | Sound | Compile-time port constants |
| shared/lib.rs: BumpAllocator | GlobalAlloc | Sound | Bounds-checked, no overflow possible on x86-64 |
| shared/bitmap.rs: Bitmap ops | Scratch memory | Sound | Bounds-checked, returns BeyondCapacity on overflow |

**Guest core summary:** 0 unsound. The "fragile" items are inherent
to the call table FFI boundary — operations must provide valid
pointers. This is acceptable because operations run inside the KVM
sandbox with no access to host memory.

#### Format crates

| Crate | Unsafe fns | Verdict | Notes |
|-------|-----------|---------|-------|
| qcow2 | 18 | All sound | Comprehensive bounds checking on all image-derived offsets; checked arithmetic for L1/L2/refcount lookups |
| vmdk | 5 | All sound | Grain marker validation, descriptor bounds checking |
| vhd | 2 | All sound | Block index bounds-checked, BAT uses checked arithmetic |
| vhdx | 4 | All sound | Multi-layer validation; BAT truncation **fixed** (see below) |
| raw | 0 | N/A | No unsafe code |
| luks | 0 | N/A | No unsafe code |

#### Operations

| Operation | Unsafe fns | Verdict | Notes |
|-----------|-----------|---------|-------|
| info | 6 | All sound | Header parsing delegates to format crates with validation |
| check | 8 | All sound | Extensive bounds checking; careful lifetime management in check_vhd |
| convert | 21 | All sound | Layout calculations bounds-checked against scratch memory; VHDX BAT overflow **fixed** |
| compare | 2 | Sound | Entry point + call table helper |
| copy | 2 | Sound | Entry point + call table helper |

### Bugs Found and Fixed

#### VHDX BAT calculation integer overflow

**Severity:** Medium
**Location:** `src/crates/vhdx/src/lib.rs`, lines 754-755 and
`calculate_bat_layout()` at line 1092
**Issue:** `total_bat_entries` and `chunk_ratio` were cast from u64
to u32 via `as u32` without overflow checking. A crafted VHDX image
with `virtual_disk_size` near u64::MAX and small `block_size` would
silently truncate these values, potentially causing undersized BAT
allocation or incorrect block lookups.
**Fix:** Replaced `as u32` with `u32::try_from().ok()?` in both
`init()` and `calculate_bat_layout()`. The function now returns
`None` for images whose BAT layout exceeds u32 capacity.
**Commit:** (this commit)

### Integer Arithmetic Review

All integer arithmetic on untrusted (image-derived) input was
reviewed. Key findings:

**Protected patterns (good):**
- QCOW2 L1/L2 lookups use chained `checked_mul`/`checked_add`
- VMDK grain lookups use `checked_mul(512)` chains
- VHD BAT lookups use `checked_add(block_idx.checked_mul(4))`
- QCOW2 cluster_bits validated to range 9..=21 before shift
- Decompression buffer sizes explicitly bounded

**Fixed:**
- VHDX `total_bat_entries as u32` truncation (see above)

**Accepted (platform-dependent):**
- Widespread `u64 as usize` casts for buffer indexing. These are
  safe on x86-64 (usize is 64-bit). The guest code targets bare-
  metal x86-64 exclusively, so no truncation occurs. Documented
  as a platform assumption.

**Accepted (bounded by construction):**
- VHD CHS geometry casts (`cylinders as u16`, `heads as u8`).
  The algorithm caps values to CHS limits (65535, 16, 255) before
  casting, following the VPC specification exactly.
- QCOW2 compressed cluster shift `62 - (cluster_bits - 8)`.
  Safe because `cluster_bits` is validated to 9..=21 at parse time.

### Truncating Cast Audit

All `as u32`, `as u16`, and `as u8` casts on values wider than the
target type were catalogued and classified.

#### Format crates (library code)

| Location | Cast | Classification | Notes |
|----------|------|----------------|-------|
| qcow2: cluster_bits parsing | `as u32` | Bounded | Validated to 9..=21 before cast |
| qcow2: L1/L2 index calculations | `as u32` | Guarded | Preceded by checked arithmetic |
| qcow2: refcount_bits | `as u32` | Bounded | Derived from refcount_order (0..=6) |
| vmdk: grain marker fields | `as u32` | Bounded | Grain size constant (128 sectors) |
| vmdk: descriptor parsing | `as u32` | Bounded | Descriptor limited to 20KB |
| vhd: CHS geometry | `as u16`, `as u8` | Bounded | Algorithm caps to CHS limits before cast |
| vhdx: BAT entries | `as u32` | **Fixed** | Was truncating; now uses `u32::try_from()` |

#### Guest core and shared

| Location | Cast | Classification | Notes |
|----------|------|----------------|-------|
| shared/bitmap.rs | `as usize` | Platform | u64 to usize, safe on x86-64 |
| core/main.rs: call table | `as usize` | Platform | u64 to usize, safe on x86-64 |
| core/virtio.rs: ring indices | `as u16` | Bounded | Queue size ≤ 256, index masked |

#### Operations (guest-side)

| Location | Cast | Classification | Notes |
|----------|------|----------------|-------|
| convert: `reftable_clusters as u32` (line 1624) | u64→u32 | Bounded | QCOW2 header field; reftable must fit in scratch memory (~12.5MB), so clusters ≤ ~200 |
| convert: `l1_size` (line 1682) | u64→u32 | Bounded | L1 table must fit in scratch memory; checked at line 1693 before use |
| convert: `entries_per_l2` (line 1680) | u64→u32 | Bounded | cluster_size/8; cluster_bits ≤ 21 so max = 262144 |
| convert: `num_gd_entries` (line 2495) | u64→u32 | Bounded | GD must fit in scratch memory; checked at line 2510 |
| convert: GTE sector offset (lines 2695, 2987) | u64→u32 | Spec | VMDK GTE is 32-bit sector offset per specification |
| convert: GDE sector offset (line 2726) | u64→u32 | Spec | VMDK GDE is 32-bit sector offset per specification |
| convert: progress percentage | u64→u32 | Bounded | Result of `(n * 100 / total)`, always ≤ 100 |
| info/check: format header fields | various | Bounded | Values validated by format crate parsers |

#### VMM (host-side)

| Location | Cast | Classification | Notes |
|----------|------|----------------|-------|
| main.rs: sector size | `as u32` | Bounded | Sector sizes are 512 or 4096 |
| main.rs: MMIO/config offsets | `as u32` | Bounded | Fixed layout constants |
| virtio/block.rs: queue operations | `as u16` | Bounded | Queue size ≤ 256 |

**Summary:** 0 unguarded truncating casts on untrusted input remain.
The VHDX BAT truncation (the only finding) has been fixed. All other
casts are either bounded by construction, guarded by preceding checks,
constrained by the VMDK/QCOW2 specification, or platform-safe
(u64→usize on x86-64). The operations marked "Bounded" are safe
because the corresponding data structures must fit within the guest's
12.5MB scratch memory — any value large enough to overflow u32 would
have already been rejected by the scratch memory bounds check.

### Static Analysis Tooling

| Tool | Status | Result |
|------|--------|--------|
| cargo clippy (nightly, -D warnings) | Pass | 0 warnings on VMM + all library crates |
| cargo audit | Pass | 0 vulnerabilities in 136 dependencies |
| rustfmt | Pass | All code formatted |
| check-binary-sizes.sh | Pass | All guest binaries within memory layout |
| shellcheck | Pass | All scripts clean |

### Standing Security Properties

These architectural properties are verified during every audit:

1. **KVM isolation:** All format parsing runs inside a KVM guest
   with a 32MB address space. A bug in format parsing cannot access
   host memory, files, or network.

2. **Rust memory safety:** The codebase is written in Rust with
   explicit `unsafe` blocks for hardware access and FFI. All unsafe
   blocks have been audited and classified.

3. **Bounded decompression:** Decompression buffers are statically
   bounded (COMPRESSED_BUF_SIZE for input, cluster_size for output).
   Compression bombs cannot cause unbounded memory allocation.

4. **Backing chain allowlist:** The VMM validates backing file paths
   against a user-configured allowlist before mapping them into the
   guest. Path traversal attacks are blocked at the host level.

5. **Feature bit enforcement:** Unknown QCOW2 incompatible feature
   bits cause immediate rejection. External data file and other
   dangerous features are blocked.

6. **Raw format hardening:** Files without valid format headers or
   partition tables are rejected by default. The `--unsafe-quirks`
   flag is required to accept them (matching qemu-img behaviour).

7. **Checked arithmetic:** All critical address calculations
   (L1/L2 lookups, BAT indexing, grain table offsets) use Rust's
   checked arithmetic (`checked_mul`, `checked_add`) to prevent
   integer overflow.

## Phase 4: CVE Reproduction

**Date:** 2026-03-16
**Scope:** 6 known qemu-img CVEs verified against imago
**Techniques:** Purpose-built reproducer images, automated tests

### CVEs Verified

| CVE | Class | CVSS | Result | Tests |
|-----|-------|------|--------|-------|
| CVE-2024-32498 | External data file path traversal | 6.5 | Mitigated | 4 |
| CVE-2015-5163 | Backing file path traversal | 3.5 | Mitigated | 5 |
| CVE-2022-47951 | VMDK descriptor path traversal | 5.7 | Mitigated | 2 |
| CVE-2015-5162 | Resource exhaustion (oversized vsize) | 7.5 | Mitigated | 2 |
| CVE-2014-0223 | Integer overflow in L1 table size | 7.5 | Mitigated | 3 |
| CVE-2024-4467 | json:{} block device specification | 7.8 | Mitigated | 3 |

**Total:** 19 tests, 7 reproducer images, 0 bypasses found.

### Reproducer Images

All reproducer images are in `imago-testdata/custom/audit/cve/`,
generated by `imago-testdata/scripts/create-cve-reproducer-testdata.py`.
See `imago-testdata/ADVERSARIAL.md` for validation instructions
including how to confirm qemu-img IS vulnerable to each CVE.

### Mitigation Details

**CVE-2024-32498 (external data file):** imago detects the QCOW2
`data-file` header extension and reports the path in info output.
The host-side path allowlist (`vmm/chain.rs`) rejects external
data files outside allowed directories when `--chain` or convert
is used. The file is never opened.

**CVE-2015-5163 (backing file traversal):** The host-side
`resolve_backing_path()` function canonicalises all paths (resolving
`../` and symlinks) before checking against the allowlist. Paths
with embedded null bytes are handled by Rust's `CStr`/`Path` types
which stop at the first null. Both relative traversal and null-byte
bypass variants are tested.

**CVE-2022-47951 (VMDK descriptor):** Text-only VMDK descriptors
(no binary magic) are rejected as "unknown format". Binary VMDKs
with embedded descriptors are parsed inside the KVM guest, which
has no access to host files. The extent path is parsed but cannot
be followed — the guest can only read data through the virtio-block
device provided by the VMM.

**CVE-2015-5162 (resource exhaustion):** All format parsing runs
in a 32MB KVM guest. No code path allocates memory proportional to
the declared virtual size. Decompression buffers are statically
bounded. Info and check operations complete in under 5 seconds on
a 1 PB virtual size image.

**CVE-2014-0223 (L1 integer overflow):** Imago does not support
QCOW1. All QCOW2 L1/L2 size calculations use `checked_mul()` and
`checked_add()` chains. An L1 size at the u32 overflow boundary
(536870913) is handled without crash — checked arithmetic returns
an error.

**CVE-2024-4467 (json:{} specification):** Imago does not support
the `json:{}` block device specification. All CLI arguments are
treated as literal file paths. A file whose content starts with
`json:` is rejected as "unknown format" (no valid format magic or
partition table). This attack class is architecturally impossible.

### Bugs Found

None. All 6 CVEs are fully mitigated by imago's existing
architecture. No new code changes were required.
