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

### Static Analysis Tooling

| Tool | Status | Result |
|------|--------|--------|
| cargo clippy (-D warnings) | Pass | 0 warnings on VMM + library crates |
| cargo audit | Pending | Not yet installed in lint container |
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
