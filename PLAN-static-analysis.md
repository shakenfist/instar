# Phase 1: Static Analysis and Code Review

## Prompt

Before executing any step of this plan, explore the imago codebase
thoroughly. Read relevant source files, understand existing patterns,
and ground your answers in what the code actually does today. Do not
speculate about the codebase when you could read it instead. Flag
any uncertainty explicitly rather than guessing.

## Situation

This plan implements Phase 1 of PLAN-audit.md: static analysis and
code review. The goal is to audit the imago codebase for structural
weaknesses before running any dynamic tests. This covers three
sub-phases:

- **1a.** Unsafe code audit
- **1b.** Integer arithmetic review
- **1c.** Static analysis tooling

## Scope

The imago workspace contains 15 member crates:

| Crate | Type | no_std | Purpose |
|-------|------|--------|---------|
| vmm | Host binary | No | KVM VMM, virtio, serial protocol |
| shared | Library | Yes | Types shared between core and ops |
| core | Guest binary | Yes | Device init, call table, dispatch |
| qcow2 | Library | Yes | QCOW2 format parsing/operations |
| vmdk | Library | Yes | VMDK format parsing/operations |
| vhd | Library | Yes | VHD/VPC format parsing/operations |
| vhdx | Library | Yes | VHDX v2 format parsing/operations |
| raw | Library | Yes | Raw format validation (MBR/GPT) |
| luks | Library | Yes | LUKS v1/v2 header and key mgmt |
| info | Guest binary | Yes | Format detection and metadata |
| copy | Guest binary | Yes | Block copy operation |
| check | Guest binary | Yes | Structural integrity checks |
| compare | Guest binary | Yes | Data comparison |
| convert | Guest binary | Yes | Format conversion |

Guest code runs inside a KVM sandbox (32MB address space) so bugs
there have limited blast radius. VMM code runs on the host with
full privileges, so bugs there bypass the sandbox entirely. The
audit should prioritise VMM code accordingly.

## Step 1a: Unsafe code audit

### Objective

Enumerate every `unsafe` block and `unsafe fn` in the codebase.
For each one, document what invariant it relies on, whether that
invariant is enforced or merely assumed, and whether a malicious
image could violate the invariant.

### Preliminary inventory

Research has identified approximately 237 unsafe references across
the codebase, grouped into the following categories. The numbers
below are approximate; the audit must produce exact counts.

**Guest core (`src/core/`):**

| File | Count | Category |
|------|-------|----------|
| core/src/virtio.rs | ~10 | MMIO volatile read/write |
| core/src/serial.rs | ~5 | x86 IN/OUT asm, utf8_unchecked |
| core/src/main.rs | ~24 | Static mut, FFI call table, HLT |

**Format crates (`src/crates/`):**

| File | Count | Category |
|------|-------|----------|
| crates/qcow2/src/lib.rs | ~18 | Cluster lookup, decompression, decryption |
| crates/vmdk/src/lib.rs | ~5 | Grain lookup, descriptor parsing |
| crates/vhd/src/lib.rs | ~2 | Block lookup |
| crates/vhdx/src/lib.rs | ~4 | Metadata parsing, block lookup |

**Operations (`src/operations/`):**

| File | Count | Category |
|------|-------|----------|
| operations/info/src/main.rs | ~8 | Header parsing (all formats) |
| operations/check/src/main.rs | ~8 | Format validation |
| operations/convert/src/main.rs | ~21 | Conversion, LUKS wrapping |
| operations/{compare,copy}/src/main.rs | ~2 | Entry points |
| All operations (_start + get_call_table) | ~10 | Boilerplate |

**VMM (`src/vmm/`) — HOST SIDE, HIGHEST PRIORITY:**

| File | Count | Category |
|------|-------|----------|
| vmm/src/main.rs | ~10 | Static mut, pointer ops on guest mem |
| vmm/src/io_thread.rs | ~5 | libc FFI (epoll) |
| vmm/src/ioevent.rs | ~4 | KVM ioctls |
| vmm/src/kvm_stats.rs | ~1 | KVM ioctl |
| vmm/src/virtio/block.rs | ~5 | ByteValued impls |

**Shared (`src/shared/`):**

| File | Count | Category |
|------|-------|----------|
| shared/src/lib.rs | ~3 | BumpAllocator (GlobalAlloc) |
| shared/src/bitmap.rs | ~3 | Scratch memory bit ops |

### Focus areas

For each unsafe block/fn, the audit should classify it as one of:

1. **Justified and sound** — the invariant is enforced by
   surrounding code and cannot be violated by untrusted input.
2. **Justified but fragile** — the invariant holds today but
   could be broken by future changes. Recommend adding a
   `// SAFETY:` comment documenting the invariant.
3. **Potentially unsound** — a malicious image or crafted input
   could violate the invariant. These are bugs to fix.

### Specific items to investigate

These were identified during preliminary research and warrant
close attention:

1. **CallTable magic validation** (`core/src/main.rs`): The
   call table is validated by checking magic `0x494D4147`. Can
   a malicious image influence the config area at 0x80000? The
   guest loads operation code at 0x20000 and the config area is
   at 0x80000 — verify that no operation binary can grow large
   enough to overwrite the config area. (Note: the pre-commit
   hook `check-binary-sizes.sh` already validates this, but
   confirm the threshold is correct.)

2. **`cstr_to_str` in core/main.rs** (line ~656): Constructs a
   `&'static str` from a raw pointer. Verify the NUL terminator
   scan is bounded and cannot read past the config area.

3. **`core::str::from_utf8_unchecked` in serial.rs** (line ~406):
   Used on UUID bytes. Verify the UUID is guaranteed to be ASCII
   hex digits.

4. **VMM guest memory pointer operations** (`vmm/src/main.rs`):
   Multiple locations dereference pointers into guest memory
   (lines ~2846, ~3231, ~3761, ~4330). These are the highest-
   risk unsafe blocks because they run on the host. Verify that
   all guest memory accesses are bounds-checked against the 32MB
   guest memory region.

5. **ByteValued impls** (`vmm/src/virtio/block.rs`): Five
   `unsafe impl ByteValued` declarations. ByteValued requires
   that the type has no padding, no pointers, and is valid for
   any bit pattern. Verify each struct meets these requirements.

6. **LUKS static mutable function pointers**
   (`operations/convert/src/main.rs`, lines ~83-94): Static
   mutable function pointers for LUKS wrapping. Verify these
   are only written once before use and cannot be influenced
   by image content.

7. **BumpAllocator** (`shared/src/lib.rs`): The global allocator
   uses a bump pointer in scratch memory. Verify that allocation
   requests from format parsing code cannot cause the bump
   pointer to exceed ALLOC_HEAP_BASE + heap size, and that
   there is no use-after-free (bump allocators cannot free).

8. **Bitmap scratch memory** (`shared/src/bitmap.rs`): The
   `init_in_scratch` function claims scratch memory for a
   bitmap. Verify that the bitmap size is bounded by available
   scratch memory and that overlapping bitmaps cannot be created.

### Deliverables for Step 1a

For each unsafe block/fn, produce a table row with:

| Location | Category | Invariant | Enforced? | Image influence? | Verdict |
|----------|----------|-----------|-----------|------------------|---------|

The table should be written to `docs/security-audits.md` (or a
sub-document linked from it) as the "Unsafe Code Audit" section.

Any "potentially unsound" findings should be filed as GitHub
Issues with the `security-audit` label.

## Step 1b: Integer arithmetic review

### Objective

Search for integer arithmetic in header parsing that could
overflow, and verify that overflow is either impossible (types
are wide enough) or explicitly checked.

### Preliminary findings

Research has identified the following patterns across the
codebase:

#### Already protected (checked arithmetic)

The codebase makes extensive use of checked arithmetic in
critical paths. Examples:

- **QCOW2 L1 table**: `l1_table_offset.checked_add(
  (l1_size as u64).saturating_mul(8))` (qcow2 line ~1203)
- **QCOW2 cluster lookup**: Chained `checked_mul` and
  `checked_add` for L1/L2 byte offsets (lines ~1248, ~1273)
- **VMDK grain table**: `checked_mul(512)` and chained
  `checked_add` (vmdk lines ~659, ~678)
- **VHD BAT**: `checked_add(block_idx.checked_mul(4))`
  (vhd line ~584)
- **VMDK descriptor hex parsing**: `value.checked_mul(16)?
  .checked_add(digit as u32)?` (vmdk line ~952)

These are good patterns that should be preserved and extended.

#### Potential issues identified

1. **VHDX BAT calculation overflow** (vhdx lines ~754-755,
   ~1097-1098): `total_bat_entries as u32` and `chunk_ratio
   as u32` are cast from u64 without overflow checking. A
   crafted VHDX image with a large virtual disk size and
   small block size could cause `total_bat_entries` to exceed
   `u32::MAX`, silently truncating the value. This could lead
   to undersized BAT allocation or incorrect block lookups.

   **Recommended fix**: Use `u32::try_from()` with error
   propagation, or keep the values as u64 throughout.

2. **QCOW2 compressed cluster shift** (qcow2 lines ~1458-
   1459): The expression `62 - (cluster_bits as u64 - 8)`
   computes a shift amount from untrusted header data. This
   is protected by the cluster_bits range check (9..=21) at
   parse time, so the shift is bounded to 33..=54 — safe for
   u64. However, the invariant is implicit and depends on
   the range check being applied before this code runs.

   **Recommended fix**: Add a `debug_assert!` or `// SAFETY:`
   comment documenting the dependency on the range check.

3. **Widespread `u64 as usize` casts in buffer operations**:
   Many locations cast file offsets (u64) to buffer indices
   (usize) via `as usize`. On the target platform (x86-64),
   usize is 64-bit so no truncation occurs. However, these
   casts are a maintenance hazard if the code is ever ported
   to 32-bit.

   **Recommended action**: No immediate fix needed for x86-64
   targets. Document the platform assumption. Consider using
   `usize::try_from()` in the highest-risk paths (buffer
   indexing after arithmetic).

4. **VHD CHS geometry calculation** (vhd line ~296):
   `(cylinders as u16, heads as u8, sectors_per_track as u8)`
   casts from u64 to u16/u8. The CHS values are computed from
   image size and should fit, but the casts are unchecked.

   **Recommended fix**: Add `.min(65535)` / `.min(255)` caps
   or use `u16::try_from()`.

5. **Sector-times-index multiplications**: Many locations
   compute `(i as usize) * sector_size` in loops. These are
   safe because `i` is bounded by the loop range, but the
   pattern is fragile. The audit should verify each loop bound.

### Specific files to audit

In priority order (most critical arithmetic first):

1. `src/crates/qcow2/src/lib.rs` — L1/L2 lookup, refcount
   lookup, compressed cluster size extraction, subcluster
   bitmap handling. ~2900 lines.
2. `src/crates/vhdx/src/lib.rs` — BAT calculation, metadata
   parsing, chunk ratio. ~1200 lines. Contains the most
   critical finding (BAT overflow).
3. `src/crates/vmdk/src/lib.rs` — Grain directory/table
   calculations, descriptor parsing. ~1200 lines.
4. `src/crates/vhd/src/lib.rs` — Footer parsing, BAT lookup,
   CHS geometry. ~900 lines.
5. `src/operations/convert/src/main.rs` — Output layout
   calculations (refcount tables, L1/L2 tables for QCOW2
   output, BAT for VHD/VHDX output). ~4100 lines.
6. `src/operations/check/src/main.rs` — Bitmap allocation
   sizing, refcount validation loops. ~2500 lines.
7. `src/vmm/src/main.rs` — Guest memory offset calculations.
   HOST SIDE. ~4800 lines.

### Deliverables for Step 1b

For each arithmetic operation that could overflow, produce a
table row with:

| Location | Operation | Input source | Width | Protected? | Risk |
|----------|-----------|--------------|-------|------------|------|

Findings rated "high risk" should be filed as GitHub Issues
with the `security-audit` label and fixed before proceeding
to Phase 2.

## Step 1c: Static analysis tooling

### Objective

Run automated static analysis tools and address any findings.

### Current tooling state

| Tool | Status | Configuration |
|------|--------|---------------|
| `cargo clippy` | Running | `-D warnings`, guest crates excluded |
| `cargo audit` | **Not configured** | No audit.toml |
| `cargo-deny` | **Not configured** | No deny.toml |
| `rustfmt` | Running | Default config |
| `check-binary-sizes.sh` | Running | Pre-commit hook |
| `actionlint` | Running | GitHub Actions linting |
| `shellcheck` | Running | Shell script linting |

### Tasks

#### 1c-i. Run `cargo clippy` with expanded lints

The current clippy configuration uses `-D warnings` but excludes
all guest crates (core and all five operations). This is because
guest crates are `no_std` and use nightly features that stable
clippy doesn't support.

**Action items:**

1. Verify that clippy runs cleanly on the VMM and library crates
   with current settings. Fix any warnings.
2. Investigate whether nightly clippy can lint the guest crates.
   If so, add a separate lint target that uses the nightly
   toolchain for guest code.
3. Consider enabling additional lint groups for security-relevant
   checks:
   - `clippy::cast_possible_truncation`
   - `clippy::cast_sign_loss`
   - `clippy::cast_possible_wrap`
   - `clippy::integer_arithmetic` (or `clippy::arithmetic_side_effects`)
   These may be too noisy to enable project-wide but should be
   evaluated on the VMM crate at minimum.

#### 1c-ii. Set up `cargo audit`

`cargo audit` checks dependencies against the RustSec advisory
database. Imago has no cargo-audit configuration.

**Action items:**

1. Install `cargo-audit` in the lint container.
2. Run `cargo audit` and address any advisories.
3. Add `cargo audit` to the pre-commit hooks or CI workflow.
4. Create `audit.toml` if any advisories need to be
   acknowledged as acceptable.

#### 1c-iii. Grep for truncating casts

Systematically search for `as u32`, `as u16`, `as u8`, and
`as usize` casts that could lose bits. The preliminary research
found the following hot spots:

| Pattern | Approx. count | Highest risk |
|---------|---------------|--------------|
| `as u32` | ~30 | VHDX BAT entries |
| `as u16` | ~5 | VHD CHS geometry |
| `as u8` | ~10 | Compression type, VMDK |
| `as usize` | ~80+ | Buffer indexing throughout |

For each cast, classify as:
- **Safe**: value is provably in range (e.g., `0u64 as u32`)
- **Guarded**: a bounds check or `min()` precedes the cast
- **Unguarded**: no check, value comes from untrusted input
- **Platform-dependent**: safe on x86-64 but not on 32-bit

Unguarded casts on untrusted input are bugs. File issues.

#### 1c-iv. Review `unsafe` documentation

Many unsafe blocks lack `// SAFETY:` comments explaining
why they are sound. While this is not a functional bug, it
makes auditing harder and increases the risk of future
regressions.

**Action items:**

1. Add `// SAFETY:` comments to all unsafe blocks that lack
   them, starting with VMM code (highest priority).
2. Consider enabling `clippy::undocumented_unsafe_blocks` on
   the VMM crate (this lint warns on unsafe blocks without
   a `// SAFETY:` comment).

### Deliverables for Step 1c

1. Clean `cargo clippy` run (already mostly done).
2. Clean `cargo audit` run with any acknowledged advisories
   documented.
3. List of all truncating casts with classifications.
4. `// SAFETY:` comments added to undocumented unsafe blocks
   (VMM crate first, then guest crates).

## Execution order

The three sub-phases can be partially parallelised:

1. **1c-ii** (`cargo audit`) can run immediately — it's a
   single command with no code changes needed.
2. **1c-i** (`cargo clippy` expansion) can run immediately.
3. **1a** (unsafe audit) is the main manual work. Start with
   VMM code (host-side, highest risk), then format crates,
   then operations, then core.
4. **1b** (integer arithmetic) can run in parallel with 1a,
   starting with the VHDX BAT overflow finding since it's
   the highest-risk issue identified so far.
5. **1c-iii** (truncating casts) naturally follows from 1b
   since the same code is being examined.
6. **1c-iv** (safety comments) should be done last, after
   1a has classified each unsafe block.

## Success criteria

Phase 1 is complete when:

- [ ] Every `unsafe` block/fn has been classified in the
  audit table (justified, fragile, or unsound).
- [ ] Every integer arithmetic operation on untrusted input
  has been verified as protected or filed as a bug.
- [ ] `cargo audit` runs clean (or advisories are documented).
- [ ] `cargo clippy` runs clean on all lintable crates.
- [ ] All truncating casts have been classified.
- [ ] VMM unsafe blocks have `// SAFETY:` comments.
- [ ] Any "potentially unsound" findings are filed as GitHub
  Issues with the `security-audit` label.
- [ ] `docs/security-audits.md` contains the Phase 1 results.

## Known findings to investigate first

These were identified during preliminary research and should
be investigated at the start of execution:

1. **VHDX `total_bat_entries as u32` truncation** — Likely
   a real bug. Fix before proceeding.
2. **VMM guest memory pointer dereferences** — Highest blast
   radius. Audit first.
3. **ByteValued impls** — Small number, quick to verify.
4. **LUKS static mutable function pointers** — Unusual
   pattern, verify soundness.

## Back brief

Before executing any step, back brief the operator on:
- Which step you are about to execute
- What files you will read
- What changes (if any) you expect to make
- How the work aligns with this plan
