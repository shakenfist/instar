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

## Multi-Device Operations

Some operations (rebase, commit) mutate one image while reading from
others. The VMM exposes up to 16 virtio-block devices to the guest,
each with its own MMIO base, sector size, and capacity. A `ChainConfig`
structure at a fixed guest-physical address tells the guest which
device index holds what — the overlay being modified, the old backing
chain, the new backing chain, and so on. See
[docs/chain-config.md](docs/chain-config.md) for the binary layout and
[docs/chain-discovery.md](docs/chain-discovery.md) for how the VMM
discovers backing chains in the first place.

Commit is the only v1 operation that opens an **input** device RW: the
overlay attaches at input slot 0 RW so the guest's overlay-clear pass
can write through the call-table primitive `write_input_sector(0, ...)`.
Every other operation opens input devices read-only, with the
output-device pointer attached separately. The host's
`open_chain_devices_rw(rw_slots: &[usize], ...)` helper takes an
explicit list of slots to open RW; rebase passes the empty list,
commit passes `&[0]`.

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
  validation. The chain reader honours the `QCOW_OFLAG_ZERO` (bit 0)
  flag on classic (non-extended) L2 entries: `cluster_lookup` returns
  a `ClusterLookup::Zero` verdict and the chain reader zero-fills for
  it, for both host == 0 and host != 0 (the phase-7 step-7z fix for
  issue #432; previously a zero-flagged chain cluster read as
  fall-through or stale host bytes — silent active-view corruption
  affecting rebase / convert / compare / bench). Supports cluster
  sizes from 512B to 2MB (cluster_bits 9-21). Used by info, check, compare, convert, and measure
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
  compute_vhd_geometry, plus footer_geometry / chs_rounded_geometry:
  build_footer writes qemu's upward-search CHS for qemu-roundable
  sizes — which can differ from the floor geometry of the same byte
  count, issue #413 — and the VHD-spec floor CHS for verbatim sizes
  qemu-img would never declare). Used by info, check, convert, and compare
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
- **crates/vdi/** - Shared VDI (VirtualBox Disk Image) format crate:
  header parsing and validation against qemu's twelve `vdi_open`
  rules (signature/version/geometry checks, odd `disk_size` rounded
  up to 512 rather than rejected, any `image_type` accepted,
  `block_extra` parsed but unused), allocation-order block-map
  reading with sector-cached lookups, and `VdiState` for stateful
  block I/O (`init`/`block_lookup`, mirroring `vhd::VhdState`).
  Read-only: no write/output support. Linked into the qcow2 crate's
  chain reader behind the `vdi-input` feature and used by convert,
  compare, bench, and rebase (PLAN-format-coverage phase 2).
- **crates/parallels/** - Shared Parallels Disk Image format crate:
  header parsing and validation against qemu's RO `parallels_open`
  rules (both magics, version check, `tracks`/`bat_entries` limits,
  `ext_off != 0` refused), per-magic BAT decoding (sector-valued
  entries under the legacy `WithoutFreeSpace` magic, cluster-valued
  entries under `WithouFreSpacExt`), the v1-only 32-bit `nb_sectors`
  mask, and `ParallelsState` for stateful block I/O
  (`init`/`block_lookup`, mirroring `vdi::VdiState`). Read-only: no
  write/output support. Linked into the qcow2 crate's chain reader
  behind the `parallels-input` feature and used by convert, compare,
  bench, and rebase (PLAN-format-coverage phase 3).
- **crates/qcow1/** - Shared QCOW1 ("qcow", qemu's original
  copy-on-write format, superseded by qcow2 but not formally
  deprecated by qemu) crate: header parsing and validation against qemu's exact
  RO `qcow_open` rules (magic + version == 1, `cluster_bits`/`l2_bits`
  ranges, size bounds including the empirically-pinned "Image too
  large" boundary, `crypt_method` <= 1 at parse, backing-file-name
  length), two-level L1/L2 block lookup (entries are absolute byte
  offsets; bit 63 marks a compressed cluster with a byte-granular
  `{host_offset, csize}` pair), and `Qcow1State` for stateful block
  I/O (`init`/`block_lookup`, mirroring `parallels::ParallelsState`;
  `init` additionally refuses `crypt_method != 0`, while `parse`
  stays lenient for info's benefit). Read-only: no write/output
  support. Linked into the qcow2 crate's chain reader behind the
  `qcow1-input` feature (which also pulls in the `decompress`
  feature for raw-DEFLATE compressed-cluster inflation) and used by
  convert, compare, bench, and rebase; the reader arm is the first
  non-QCOW2 format to support backing-chain fall-through, mirroring
  the QCOW2 arm's own unallocated-cluster recursion instead of the
  VDI/Parallels arms' zero-fill (PLAN-format-coverage phase 4).
- **crates/dmg/** - Shared DMG (Apple UDIF) format crate: koly-trailer
  parsing (reusing the phase-1 shared trailer helpers), chunk-table
  assembly from either the XML-plist path (string-scanned `<data>`
  blocks, decoded with a byte-for-byte port of glib's lenient base64)
  or the old resource-fork path, mish/BLKX chunk-entry parsing into a
  sorted, verified lookup table, and `DmgState` for stateful per-
  sector chunk lookup (`init`/`chunk_lookup`, returning span-typed
  Zero/Raw/Zlib results). Codec scope is zero/raw/ignore/zlib
  (zlib-WRAPPED inflate, unlike QCOW1's raw-deflate); ADC/bzip2/
  lzfse/zstd/unknown chunk types get a typed init refusal naming the
  code rather than qemu's drop-then-EIO shape, and a chunk table that
  parses to zero entries is refused cleanly at init (where qemu
  SIGSEGVs on every version tested). Enforces its own bounded-memory
  caps (`DMG_REGION_STAGE_CAP`, `DMG_MAX_CHUNKS`,
  `DMG_MAX_STAGED_SECTOR_COUNT`), distinct from qemu's own larger
  legal range, as typed refusals. Read-only: no write/output support;
  chunk *decompression* and byte copies live in the reader arm, not
  this crate. Linked into the qcow2 crate's chain reader behind the
  `dmg-input` feature (which also pulls in the `decompress` feature)
  and used by convert, compare, bench, and rebase; unlike every other
  format-coverage reader, DMG reads a missing/truncated span as an
  ERROR rather than zero-filling, matching qemu exactly
  (PLAN-format-coverage phase 5).
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
  `measure` operation in `src/operations/measure/` and by the
  size-estimation helpers shared with `create` and `resize`.
- **crates/qcow2-write/** - Shared qcow2 write-planner crate (`no_std`,
  no I/O, no guest addresses): the windowed step-program planner for
  "write N bytes at virtual offset X into an existing qcow2, allocating
  as needed" (PLAN-qcow2-write-infrastructure phase 3). `plan_write`
  classifies each touched cluster from staged metadata (owned in-place
  overwrite with zero metadata churn / fresh allocation with
  sub-cluster zero-fill, including a fresh L2 table when the L1 slot is
  empty / typed refusals for compressed, snapshot-shared,
  unknown-bit-pattern and backing-fill shapes) and emits typed `Step`s
  (`#[repr(C)]`, const-asserted at 48 bytes or less) into a
  caller-provided `StepBuf`; the executor runs each window literally
  and resumes on `BufFull`, which doubles as the staged-L2 window's
  load boundary (the planner emits `LoadCluster` and closes the window,
  because the slot's bytes exist only after execution). Steps are
  address-free — staged buffers are named by `RegionId` + offset and
  devices by `TargetDevice` (`Input0`/`Output`) — and each planning
  call borrows a `StagedRegions` view of the executor's staged L1 /
  L2-window / refcount-table / refblock buffers, of which only the
  refblocks are mutable: the planner mutates staged refcounts in place
  at plan time (bench's single-copy model) while L1/L2 mutations stay
  `PatchEntryU64` steps, and `plan_flush` emits the epoch's write-backs
  refcounts-last. Barriers are explicit steps with
  `BarrierClass::{Ordering, Durability}`; because the call table
  exposes only `fsync_input`, executors map `Durability` to fsync on RW
  input devices and degrade it to `Ordering` where no fsync primitive
  exists (matching commit/rebase's current no-fsync output-device
  reality). The crash-ordering contract — data written before the L2
  patch that reaches it, fresh-L2 init before the L1 patch, refcount
  write-backs only at flush and last, Durability barriers between flush
  groups — is emission-order data, pinned mechanically by an
  ordering-contract property suite (window-invariance across buffer
  capacities down to a 1-step buffer) and a SimDisk simulation harness
  that replays the step journal truncated at every Durability barrier.
  Envelope gates (qcow2 v2/v3, 16-bit refcounts, no
  unknown-incompatible bits, no extended-L2 / external data /
  encryption, not dirty/corrupt, no internal snapshots) run at state
  construction, so a gated image can never yield a write plan. Three
  ops consume it: commit (phase 4, 2026-07-13 — the qcow2
  backing-side write path), rebase safe mode including safe
  detach (phase 5, 2026-07-13 — the overlay-side copy path, with an
  op-side skip probe against original pre-run L2 state deciding
  which clusters reach the planner at all), and bench `-w` (phase 6,
  2026-07-13 — the qcow2 write-benchmark path). All are planned by
  this crate and executed through `crates/qcow2-write-exec`, proven
  byte-invisible by the `scripts/migration-proof.py` before/after
  harness (73/73, 69/69 and — for bench, whose oracle is
  compare + check rather than byte identity — 56/56 fixture combos,
  300-iteration differential fuzz clean each; rebase carries one
  sanctioned beyond-EOV raw divergence with proven virtual equality,
  and bench's allocating shapes are content-equivalent but not
  byte-identical by design). The crate also owns the pure
  refcount-growth planner in its `growth` module (`plan_refcount_growth`,
  `GrowthCaps`, `RefcountGrowthPlan`, `GrowthOverflow`), moved out of
  `crates/bench` in phase 6; growth execution moved to
  `crates/qcow2-write-exec` in phase 7 (see below). Phase 7
  (2026-07-13) added the crate's **copy-on-write branch**, lifting the
  three ops' interim snapshot-refusal gates (issues #420 / #421 / #423
  resolved). A COW-capable caller builds its `WriteState` via
  `new_state_cow` and relaxes the envelope with
  `check_envelope_with(hdr, allow_snapshots = true)`; the classifier
  then turns the `SnapshotShared` / `SnapshotSharedL2Table` verdicts
  from refusals into COW emission. Data-cluster COW copies the shared
  `D → D'`, repoints the L2, sets `rc(D')=1` and decrements `rc(D)`
  (the old cluster is never freed — the snapshot holds it); L2-table
  COW copies `T → T'`, repoints the L1, sets `rc(T')=1`, decrements
  `rc(T)`, and — critically — leaves the child data-cluster refcounts
  untouched (qemu eagerly bumps every reachable cluster to rc ≥ 2 at
  snapshot-creation time, so a child-increment would corrupt to rc 3;
  the children already classify shared and COW per-write). This needs
  a net-new refcount-**decrement** primitive (`dec_refcount`; v1 only
  ever incremented on allocation), whose underflow maps to
  `WriteError::RefcountInconsistent`. The zero-flag WRITE-target policy
  (decision 6): host == 0 allocates fresh, host != 0 rc 1 overwrites
  in place clearing the zero bit, host != 0 rc > 1 COWs — qemu never
  frees the old offset. No new `StepKind`. The COW output is proven
  qemu-parity, never byte-identical to qemu (C11). The crate's
  Vec-backed simulation harness (`TestImg` + the executor role +
  `run_write` / `run_flush` `BufFull`-resume loops + the COW fixtures +
  the `rc_of` / `max_rc` assertion helpers) lives in a feature-gated
  `#[cfg(any(test, feature = "sim"))] pub mod sim` (phase 8a): the crate's
  own unit tests import it, the `sim` feature is OFF in the production
  build (it needs `std`, and the guest ops are `no_std`
  `x86_64-unknown-none`, so the ops' `.bin` sizes are unchanged), and the
  `fuzz_qcow2_write` coverage target enables it to fuzz the planner
  (see Coverage-Guided Fuzzing below).
- **crates/qcow2-write growth-execution move (phase 7).** The
  imperative refcount-growth EXECUTION (previously in the bench op) is
  now the shared, region-agnostic `growth::grow_refcounts` in
  `crates/qcow2-write-exec`, so commit and rebase can grow the
  refcount structures during COW, not just bench. Behaviour is
  byte-identical to bench's prior execution (the #433 materialization
  fix and the single-fsync census are preserved).
- **crates/qcow2-write-exec/** - Shared guest-side step executor for
  `crates/qcow2-write` step programs (`no_std`,
  PLAN-qcow2-write-infrastructure phase 4): a literal interpreter of
  the `StepKind` doc contracts with zero planning logic —
  `execute(steps, regions, devices)` applies one planned window in
  emission order and aborts on the first failure with the step index
  and a typed cause (nothing panics; every region access is
  bounds-checked). The `DeviceIo` trait abstracts the per-device
  call-table entry points; `CallTableIo` maps `Input0` to
  `read/write_input_sector(0)` + `fsync_input(0)` and `Output` to
  `read/write_output_sector` with no fsync capability. Its byte-range
  layer (`read_bytes` / `write_bytes` / `fill_bytes`) sits over the
  strictly sector-addressed call table — whole aligned sectors
  transfer directly, sub-sector head/tail goes through
  read-modify-write on a caller-provided bounce sector — and is
  exposed as the shared replacement for the byte-range helpers the
  commit / rebase / bench / bitmap ops each hand-roll. `Regions`
  maps each planner `RegionId` to a caller-carved scratch slice
  (never `static`) plus the two executor service sectors (one shared
  RMW bounce — safe because all call-table I/O is synchronous and
  steps execute serially — and a fill-synthesis sector). Barrier
  policy: `Ordering` is a no-op (issue order is completion order),
  `Durability` fsyncs where the capability exists and degrades to
  `Ordering` elsewhere (matching commit/rebase's no-fsync
  output-device reality). Host-unit-tested against a mock `DeviceIo`
  with journals and failure injection, including end-to-end
  compositions driving `plan_write` / `plan_flush` through the
  executor over a model disk. Consumed by the commit op (phase 4),
  the rebase op's safe mode (phase 5), and the bench op's qcow2 `-w`
  path (phase 6, which also drives its refcount-growth I/O through
  the byte-range layer with the executor's fsync disabled so bench
  keeps its own single-fsync-per-cadence-point census). Phase 7 added
  the shared `growth::grow_refcounts` here (moved out of the bench op)
  so all three ops can grow the refcount structures during
  copy-on-write, and all three now build COW-capable write states that
  route the crate's `SnapshotShared` / `SnapshotSharedL2Table` COW
  steps through this executor.
- **operations/info/** - Format detection operation
- **operations/copy/** - File copy operation
- **operations/check/** - Image integrity validation operation (with
  optional `--chain` backing chain validation, and optional in-place
  qcow2 repair via `--repair[=leaks|all]`: the safe `leaks` tier
  reclaims unreferenced clusters, the lossy `all` tier rebuilds
  refcounts and reconciles COPIED flags under a crash-safe
  `corrupt`-bit write ordering — set bit → correct refcounts →
  reconcile COPIED → clear bit, each fsync-separated — reusing the
  `crates/check` planner crate and `crates/snapshot`'s refcount
  mutators; refuses on snapshotted/compressed/corrupt images)
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
  comparison; remaining writer divergences (qcow2 compat
  hardcode, zstd accept-ignore, vhdx default block_size, vhd
  CHS-rounded virtual_size) are documented as per-case skips
  rather than whitelist extensions so each gap stays visible.
- **operations/resize/** - In-place virtual-size mutation
  operation. Reads a `ResizeConfig` (target format, current and
  new virtual sizes, current file size, per-format hints from the
  existing header, preallocation mode, `--shrink` flag) from
  `OPERATION_CONFIG_ADDR`, reads sector 0 to confirm the format,
  walks the existing header / L1 / refcount / BAT / descriptor
  via the matching parser crate, calls the matching
  `crates/resize::plan_resize_*` to build a `ResizePlan` of up
  to 128 `ResizePatch` entries (`Write` / `Append` / `ZeroFill`),
  then applies each patch via `write_output_sector` plus the
  new phase-7 `read_output_sector` call-table primitive (the
  resize op is the first reader of the output device — future
  in-place operations like `rebase` / `commit` will reuse it).
  Per-format support: raw is host-only (`open(O_RDWR) +
  ftruncate` plus optional preallocation post-pass; no guest
  launch); qcow2 grows and shrinks (L1 + refcount-table
  extension via `qcow2::plan_grow`, L2 walk + cluster discard
  via `qcow2::plan_shrink`); vmdk monolithicSparse grows
  (sparse extent header rewrite + descriptor update + GD
  relocate via `vmdk::plan_grow`); vhd dynamic + fixed grow
  (BAT extension + footer + dynamic-header rewrite); vhdx
  dynamic grow (two-header sequence-number protocol +
  metadata `VirtualDiskSize` update + BAT extension). vmdk /
  vhd / vhdx shrink is rejected (`UnsupportedShrink`). The
  host CLI (`run_resize` / `run_resize_raw` / `run_resize_nonraw`
  in `src/vmm/src/main.rs`, wired in phase 8) parses the
  qemu-img-compatible `[+-]SIZE` end-spec grammar
  (`parse_resize_size`), opens the output `O_RDWR` (the same
  file is both input and output — the guest reads via
  `read_output_sector` and writes via `write_output_sector` to
  the device at slot 1; the stub-input-at-slot-0 pattern
  satisfies core's unconditional input-device probe, mirroring
  `run_create_nonraw`), launches `resize.bin`, and applies
  the phase-9 preallocation post-pass via the shared op-agnostic
  `apply_preallocation` helper (`falloc` ⇒ `posix_fallocate` on
  the newly-appended file region; `full` ⇒ `fill_zeros`
  on the same range). Deliberate divergence from qemu: instar
  preallocates only the appended region, not the entire data
  region of the new virtual size; full parity is queued under
  Future work. `--preallocation=falloc|full` combined with
  shrink is rejected for clarity; `--preallocation=metadata`
  on raw is rejected (raw has no metadata to populate); qcow2
  `metadata` preallocation is rejected by the planner
  (`PreallocationUnsupported`, deferred from phase 2c). Output
  rendering supports human (`Image resized.`, matches
  qemu byte-for-byte), `--output=json` (filename / format /
  action / old & new virtual sizes / new file size), and
  `-q` quiet. Integration tests in `tests/test_resize.py`
  cover six surfaces — schema-drift tripwire, cross-version
  baseline matrix (qcow2 + raw), live cross-validation, full-
  matrix round-trip check, internal consistency for
  vmdk/vpc/vhdx (the formats qemu rejects), and targeted
  error-path tests — totalling 114 tests (83 active +
  31 documented skips). Coverage and differential fuzz live in
  `src/fuzz/fuzz_targets/fuzz_resize_planners.rs` and
  `scripts/differential-fuzz.py`'s `op_resize`. The binary
  builds at ~73 KiB / 384 KiB.
- **operations/map/** - Allocation-map operation. Reads a
  `MapConfig` (sector_size, input_device_count, start_offset,
  max_length window) from `OPERATION_CONFIG_ADDR`, detects the
  source format on input device 0, refuses sources with chain
  composition (qcow2 backing-file references, vhd differencing
  disks; vhdx differencing is already rejected by
  `VhdxState::init`; vmdk multi-extent layouts fail the
  binary-header parse naturally), and dispatches to the matching
  per-format `<Format>State::map_extents` walker from phase 1 of
  PLAN-map. Streams one `MapExtentRecord` per coalesced extent
  through the call table's `send_map_extent` function pointer,
  followed by a `MapResult` summary through `send_map_result`.
  The emit closure clips each extent against the configured
  window (with file-offset adjustment for front-trimmed Data
  extents) and signals walker abort once the window is
  exhausted. Single-image v1; chain composition is a follow-up.
  Binary builds at ~28 KiB / 384 KiB (7%). Host CLI (phase 3
  of PLAN-map) wires `instar map [-f FMT] [--output={human,json}]
  [--start-offset=OFFSET] [--max-length=LEN] [--sector-size=N]
  FILENAME`: `run_map` in `src/vmm/src/main.rs` parses args
  (refusing `--image-opts`, VMDK monolithicFlat sources via
  `peek_is_vmdk_descriptor`, and `--start-offset >= file_size`
  on the host before launching the guest), writes `MapConfig`
  per-field at `OPERATION_CONFIG_ADDR`, attaches the source
  read-only as input device 0, and runs the vCPU loop. Phase 4
  of PLAN-map ships the streaming `MapRenderer<'a, W: Write>`
  that writes each extent to stdout (via a `BufWriter` over
  `stdout().lock()`) as the `MapExtentMessage` arrives in the
  vCPU loop; host memory stays O(1) regardless of how
  fragmented the source is. Human and JSON output match
  `qemu-img map` byte-for-byte modulo the divergences
  documented in `docs/quirks.md` (raw `SEEK_HOLE` not
  implemented, qcow2 compressed clusters reported as
  `compressed: false`, VHDX partially-present treated as data,
  no backing-chain depth in v1). BrokenPipe on stdout (user
  piped into `head`) short-circuits cleanly with exit 0.
  Integration tests in `tests/test_map.py` cross-validate
  `instar map` against the `qemu-img map` baselines in
  `instar-testdata/expected-outputs/map-*` for every safe-tier
  image, plus in-test fixtures for window-filter behaviour,
  host-side error paths (`--image-opts` refusal, chain image
  refusal, invalid sector size), and a divergence-regression
  suite that catches accidental fixes to known instar-vs-
  qemu-img gaps so `KNOWN_MAP_DIVERGENCES` doesn't go stale.
  Phase 6 baseline: 95 active tests + 91 documented skips.
- **operations/snapshot/** - Internal-snapshot operation
  (PLAN-snapshot, qcow2-only like `qemu-img snapshot`). Reads a
  `SnapshotConfig` (mode discriminator, argument bytes, flags,
  and for create the host-stamped `date_sec`/`date_nsec`) from
  `OPERATION_CONFIG_ADDR`, opens the image RW as input device 0,
  and dispatches on mode. MODE_LIST streams one
  `SnapshotEntryRecord` per table entry via the qcow2 crate's
  `for_each_snapshot_entry` (no in-memory cap; one entry
  resident at a time) followed by a `SnapshotResult` terminator;
  the host renderer produces byte-identical
  `qemu-img snapshot -l` output (modern ≥9.0 layout, local-time
  DATE column, byte-measured ID/TAG padding) or the
  `--output=json` QMP-keyed extension. The mutating modes
  (MODE_CREATE / MODE_DELETE / MODE_APPLY) compose the
  `src/crates/snapshot/` planner primitives — two-pass
  dry-run-then-apply refcount mutators, the COPIED-flag walker,
  the contiguous-cluster allocator, and the table
  serialisation/compaction helpers — into per-mode
  `fsync_input`-separated write groups with a single commit
  point each (create/delete: the 12-byte header write at offset
  60; apply: the raw L1 overwrite). Delete matches by name only;
  apply and `convert --snapshot` match ID-then-name in two full
  passes (qemu's asymmetry — docs/quirks.md). Uniform feature
  gates refuse `refcount_bits != 16`, compressed clusters,
  encryption, external data files, bitmaps, and dirty images;
  v1 caps the table at 16 snapshots and never grows the
  refcount structures. Post-op images are bit-for-bit identical
  to qemu-img's under `file.discard=ignore` (see
  docs/qcow2/qcow2-snapshots.md for the write orderings and
  docs/snapshot.md for the user reference). Binary builds at
  ~55 KiB / 384 KiB. Verification: seven shell harnesses
  (`tools/snapshot-*.sh`, 241 assertions, `make
  snapshot-harnesses`, run in CI by functional-tests);
  `tests/test_snapshot.py` (phase 11) adds 94 tests covering
  the five snapshot families: list-matrix (12 images, TZ=UTC,
  profile-resolved), JSON goldens with structural cross-check
  and QMP-key schema pin, mutation round-trips
  (create/delete/apply with post-op qemu-img check), error
  paths and qcow2-only enforcement, and empty-table behaviour
  (JSON goldens live in `tests/golden/snapshot-list/`); two
  coverage-guided fuzz targets (`fuzz_snapshot_parse`,
  `fuzz_snapshot_refcount`); and the differential fuzzer's
  `op_snapshot` chain (byte-identity after every element).
- **operations/amend/** - In-place qcow2 header amendment operation
  (PLAN-amend, qcow2-only). Reads an `AmendConfig` (target compat
  version and/or lazy_refcounts flag) from `OPERATION_CONFIG_ADDR`,
  opens the image RW as the output device, reads the existing header
  to determine the current version and feature state, runs the
  `crates/amend` planner to derive a `AmendPlan` (a handful of
  byte-range patches to the header cluster), and applies them via
  `write_output_sector` — only the header cluster is rewritten; no
  cluster or refcount data is touched. v1 gates: v3→v2 downgrade
  refused if the image carries a v3-only incompatible feature
  (dirty, corrupt, external data, compression type, extended L2) or
  uses `refcount_bits != 16`; `lazy_refcounts=on` requires v3;
  header-extension relocation across the version change is
  unsupported. Needs `/dev/kvm` (launches a guest VMM). See
  [docs/amend.md](docs/amend.md) for the full user reference.
- **operations/dd/** - Windowed block-copy operation (PLAN-dd,
  qemu-img dd compatible). Implemented host-side in `run_dd`
  (`src/vmm/src/main.rs`): parses `name=value` operands (`if=`,
  `of=`, `bs=`, `count=`, `skip=`) and the `-O` output-format flag
  (default **raw**, not the input format), computes the input byte
  window via `crates/dd::compute_dd_window` (count-then-skip
  semantics: `count` clamps down, `skip` subtracts from the front,
  skip-past-EOF ⇒ empty output with exit 0), then launches the
  existing `convert.bin` guest with a windowed `ConvertConfig`
  (input byte-window + dense output). The new `crates/dd` crate
  provides the pure window-math helper used by both the host CLI
  and tests. The structured writers (qcow2, vmdk, vhd, vhdx) were
  hardened during this phase via `qcow2::read_chain_virtual_range`
  to correctly fill output grains/blocks that span multiple input
  qcow2 clusters (fixing a pre-existing sub-cluster data-loss bug
  in `convert`). Output is byte- and size-identical to `qemu-img
  dd` for all five output formats (raw, qcow2, vmdk, vpc, vhdx).
  Known divergences: vhdx default block size (32 MiB vs qemu's 8
  MiB for small images), count=0 vmdk/vhdx edge cases. See
  [docs/dd.md](docs/dd.md) for the full user reference.
- **operations/bitmap/** - qcow2 persistent-dirty-bitmap management
  operation (PLAN-bitmap, qcow2 v3-only). The host side (`run_bitmap`
  in `src/vmm/src/main.rs`) validates the CLI surface (the repeatable
  CLI-order actions `--add`/`--remove`/`--clear`/`--enable`/
  `--disable`/`--merge`, the `-g` granularity, rejected qemu-only
  flags), pre-probes the image, and hands a `BitmapConfig` to the
  guest op, which mutates the image in place. The pure `no_std`
  `crates/bitmap` planner provides the bitmap directory/table/action/
  merge logic, reusing the snapshot refcount mutators to allocate and
  free bitmap-table clusters. The guest applies each action under the
  crash-safe **autoclear** dance (clearing the header's
  `bitmaps` autoclear bit while the extension is inconsistent and
  restoring it once the write settles) so a crash mid-update leaves
  the image safe rather than corrupt. Needs `/dev/kvm` (launches a
  guest VMM). The ABI appends one call-table callback
  (`send_bitmap_result`), bumping `CallTable::VERSION` from 18 to 19
  (same append-at-end discipline as amend's 17→18). Coverage:
  `tests/test_bitmap.py` integration parity against `qemu-img
  bitmap`, cross-version baselines, and fuzzing. See
  [docs/bitmap.md](docs/bitmap.md).
- **operations/bench/** - I/O benchmark operation (PLAN-bench), the
  sandboxed equivalent of `qemu-img bench`. Measures instar's own
  end-to-end sandboxed path (guest format layer → virtio-block →
  ioeventfd → host I/O thread → file I/O) rather than qemu's block
  layer over the page cache; running both tools against the same
  image and arguments is the reproducible sandbox-overhead
  measurement (see [docs/bench.md](docs/bench.md)). The host side
  validates the full option surface (echoed-but-unobeyed `-d`,
  buffer-size cap, cache/aio/image-opts postures) before launching
  the guest with a `BenchConfig`; the guest driver is synchronous
  and single-buffer in v1 (`effective-depth` always `1`), submitting
  each scheduled request in turn and timing the run between the
  `send_bench_start` marker (emitted once setup completes) and the
  terminal `send_bench_result`. Reads all five formats; write tests
  (`-w`) are supported on raw and qcow2 only (including qcow2
  overlays); a mid-run crash leaves at worst a repairable leak. Since
  the phase-6 migration (PLAN-qcow2-write-infrastructure), the qcow2
  `-w` allocate-on-write path runs on the shared `crates/qcow2-write`
  planner and `crates/qcow2-write-exec` executor — bench is the third
  consumer after commit and rebase — staging metadata and writing it
  back refcounts-last at each flush epoch. qcow2 write setup
  preemptively grows the image's refcount structures to the
  schedule's worst-case coverage before the timing bracket opens (new
  refblocks at the file end; refcount-table relocation with an
  fsync-ordered header flip — `PLAN-bench-refcount-growth`); the pure
  growth planner moved into `crates/qcow2-write`'s `growth` module in
  phase 6, though growth execution stays op-side. bench keeps its own
  fsync census (the executor's fsync is disabled; the op issues one
  `fsync_input(0)` per `--flush-interval` cadence point). The pure
  `no_std` `crates/bench` crate provides the request-schedule math
  (and `worst_case_touched`, which stays BenchParams-coupled) shared
  by the guest, host CLI and tests. `bench.bin` builds at ~173 KiB of
  the 768 KiB operation-region budget. The ABI appends two
  call-table callbacks (`send_bench_start`, `send_bench_result`),
  bumping `CallTable::VERSION` from 19 to 20. Coverage:
  `tests/test_bench.py` (76 tests), the `fuzz_bench_schedule`
  coverage fuzzer, and the differential fuzzer's `op_bench` arm. See
  [docs/bench.md](docs/bench.md).
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
  existing operation binaries keep working unchanged). Phase 7 of
  `PLAN-resize.md` adds `ResizeConfig` / `ResizeResult` plus two
  more CallTable function pointers: `read_output_sector` (lets a
  guest read from the same device it writes to — the first
  in-place-mutation primitive, reusable by `rebase` / `commit`
  / snapshot-delete) and `send_resize_result`. Same
  append-at-end discipline. Phase 1 of `PLAN-snapshot.md` adds
  `SnapshotConfig` (magic `b"SNAP"`, carrying the mode, the
  snapshot name/needle argument, and the create-mode
  `date_sec`/`date_nsec` wall-clock fields) / `SnapshotResult` /
  the `SnapshotEntryRecord` wire record, and three more CallTable
  entries — `send_snapshot_entry` (streams one listed snapshot
  per call), `send_snapshot_result`, and `fsync_input` (the
  guest-visible write barrier the mutating modes use between
  write groups) — bumping CallTable VERSION from 16 to 17, same
  append-at-end discipline. `PLAN-amend.md` and `PLAN-bitmap.md`
  each append one more entry (`send_amend_result`,
  `send_bitmap_result`), bumping VERSION 17→18→19; `PLAN-bench.md`
  appends two — `send_bench_start` (the timing-bracket start marker)
  and `send_bench_result` (the terminal result) — bumping VERSION
  from 19 to 20, same append-at-end discipline throughout.

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
checks. The core and operation regions, and the data pages that follow
them, were lifted on 2026-07-06 (commit `3a5e1e2`) to give both budgets
headroom after `core.bin` reached 94% of its previous 72 KiB limit
following the bench ABI additions; nothing at or above the virtqueue
region (`VQ_BASE_START`) moved.

```
Address         Size    Region
──────────────  ──────  ─────────────────────────────────────────
0x0000_1000             GDT
0x0000_2000             Page tables
0x0001_0000    128 KiB  core.bin (guest entry point)
0x0003_0000    768 KiB  Operation binary (whichever op is loaded)
0x000F_0000      4 KiB  Call table
0x000F_1000      4 KiB  Operation config
0x000F_2000      1 KiB  Chain config
0x000F_3000      4 KiB  VMM params
0x000F_4000     48 KiB  ── guard gap ──
0x0010_0000      1 MiB  Virtqueue memory (16 devices × 64 KiB)
0x0020_0000     64 KiB  DMA pool
0x0030_0000   12.9 MiB  Scratch memory (temporary bitmaps/buffers)
0x00FF_0000     64 KiB  ── guard gap ──
0x0100_0000      4 MiB  Stack (grows down from STACK_TOP)
0x0140_0000   12.0 MiB  (unused)
0x0200_0000             End of guest memory
```

`GUEST_CODE_BASE`/core loads at `0x10000` and may extend to
`OPERATION_LOAD_ADDR` (`0x30000`, 128 KiB max); the operation binary
loads at `0x30000` and may extend to `CALL_TABLE_ADDR` (`0xF0000`,
768 KiB max). `scripts/check-binary-sizes.sh` enforces both budgets
against each binary's `.bss`-inclusive ELF memory extent, not just the
flat `.bin` file size. The four data pages (call table, operation
config, chain config, VMM params) occupy `[0xF0000, 0xF4000)`,
followed by a 48 KiB guard gap up to `VQ_BASE_START` (`0x100000`).
Virtqueue memory and everything above it (DMA pool, scratch, the
64 KiB pre-stack guard gap, and the stack) is unchanged by the lift.

See [docs/chain-config.md](docs/chain-config.md) for the chain config
structure layout and VMM-to-guest data flow.

## Format Support

**Measurable target formats**: raw, qcow2 (qemu-img-parity),
vmdk, vpc (VHD), vhdx (instar-only — qemu-img does not
implement `measure` for these targets).

**Creatable target formats**: raw (host-only —
`open + ftruncate + posix_fallocate`), qcow2 (qemu-img
info-equivalent modulo `refcount_bits` / `compat` / `zstd`
hardcodes), vmdk monolithicSparse + streamOptimized, vpc
dynamic + fixed (modulo CHS `virtual_size` rounding), vhdx
dynamic (modulo default `block_size` when unspecified).
Backing-file references supported on qcow2, vmdk, vpc, vhdx
(matches qemu-img's permission set). See
[docs/create.md](docs/create.md) for the user reference and
[docs/quirks.md](docs/quirks.md) for the documented writer
divergences.

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

#### qcow2 write infrastructure

In-place mutation of an existing qcow2 (used by `commit`, `rebase`
safe mode and `bench -w`) runs on two shared `no_std` crates: the
**`crates/qcow2-write`** planner (pure, I/O-free, address-free —
turns a write into a typed step program; handles the envelope,
classification, allocate-on-write and copy-on-write) and the
**`crates/qcow2-write-exec`** executor (the literal step interpreter
plus the byte-range/device layer). Refcount growth is split the same
way across each crate's `growth` module. The maintainer reference for
this machinery — the step-program ABI, the write envelope, COW, growth
and the crash-ordering contract — is
[docs/qcow2/qcow2-write-planner.md](docs/qcow2/qcow2-write-planner.md).

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
`python scripts/generate-baselines.py --command create`, and a
`dd-info-json` matrix (produced by `--command dd`) recording the
`qemu-img info` JSON of the dd output for each `(format, window)`
case across all 80 qemu-img versions
(`instar-testdata/expected-outputs/dd-info-json/`).
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
   convert, measure, create, resize, rebase, commit, map) against both tools.
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

The `map` operation runs `instar map --output=json` and
`qemu-img map --output=json` against independent copies and
compares the resulting JSON arrays extent-by-extent on
`{start, length, present, zero, data}`. `{depth, compressed,
offset, filename}` are skipped (always 0 / always false /
compressed-cluster reporting drift / different paths). `raw` is
gated out entirely (SEEK_HOLE divergence). A per-format
`MAP_FIELD_SKIPS` catalogue skips the `present` field on `vpc`
sources, matching the documented VHD-unallocated-block
convention difference (`docs/quirks.md`). With ~25%/25%
probabilities, window args (`--start-offset` / `--max-length`)
are picked 64-KiB-aligned and passed to both binaries.

The `create` operation has its own dual oracle: it creates the same
image via `instar create` and the system `qemu-img create` into
separate tmp paths, then reads both back via `qemu-img info
--output=json` and compares the normalised JSON dicts (same
divergence-whitelist filter the phase 8b integration tests use,
inlined from `tests/helpers/info_json.py`). The random
`(target, options, size)` picker biases away from phase 8b's
documented writer-divergence list — vhd target excluded (CHS
rounding), qcow2 compat pinned to 1.1, compression_type=zstd
never set, vhdx block_size always explicit. Combinations the
curated test matrix doesn't exercise (random cluster sizes,
every qcow2 refcount_bits width, lazy_refcounts on/off, every
preallocation mode, every vmdk subformat) get coverage here
without spurious
findings from the known gaps.

The `commit`, `rebase` and `bench` arms additionally draw a
snapshot-fixture flag (40% probability) and, when `qemu-io` is present,
build a **snapshot-bearing** fixture (phase 8 of
PLAN-qcow2-write-infrastructure) exercising the copy-on-write paths
phase 7 opened: commit over a backing- or overlay-snapshot span, safe
rebase of a snapshot-bearing overlay, and `bench -w` over a
snapshot-shared span. For a snapshot fixture the oracle gains the
phase-7 read-back triple — active-view `qemu-img compare` identical +
`qemu-img check` clean (with a `refcount=1 reference=2` scan) +
per-carrier snapshot read-back `instar == qemu twin` (via
`tests/helpers/snapshot_readback.py`, which applies each snapshot on a
copy, converts to raw, and compares sha256) — the last of which the
active-view compare alone cannot see. Non-snapshot fixtures keep their
existing oracle unchanged. This folds in the retired standalone
`scripts/cow-soak.py` soak (phase 7e), which nothing in CI depended on;
the snapshot coverage now rides the existing `differential-fuzz.yml`
nightly with no new workflow.

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

32 fuzz targets cover all parser crates: format detection, header
parsing (QCOW2, VMDK, VHD, VHDX, RAW, LUKS), L1/L2 cluster lookup,
refcount table traversal, zlib decompression, grain directory lookup,
BAT traversal, VHDX metadata parsing, the measure subcommand's
calculator math (`fuzz_measure_calc`) and the per-parser
`scan_allocation` entry points (`fuzz_measure_scan`), the map
subcommand's per-parser `map_extents` entry points (`fuzz_map_iter`
— exercises `qcow2::Qcow2State::map_extents` and the vmdk / vhd /
vhdx equivalents with a recording closure, asserting the partition
invariant: emitted extents must cover `[0, virtual_size)` exactly
once with no gaps, overlaps, zero-length records, or `start+length`
overflow; this is the stricter assertion that scan-summary
invariants cannot see), plus the create subcommand's emitters
(`fuzz_create_emitters` — exercises `plan_qcow2`, `plan_vmdk`,
`plan_vhd`, `plan_vhdx` with structured fuzz input, asserting
plan-level bookkeeping invariants and a header re-parse round-trip
via the matching parser crate) and the resize subcommand's planners
(`fuzz_resize_planners` — exercises `plan_resize_raw` / `_qcow2` /
`_vmdk` / `_vhd` / `_vhdx`, asserting plan-level patch invariants:
bounded patch count, no offset+len overflow, every patch ends
within `total_file_size`, no overlapping Writes). The rebase and
commit planners have equivalent targets (`fuzz_rebase_planners`,
`fuzz_commit_planners`), the snapshot subcommand adds
`fuzz_snapshot_parse` (the streaming snapshot-table parser plus
the pure table readers) and `fuzz_snapshot_refcount` (the
refcount mutators, COPIED-flag walker, allocator, and table
round-trip under semantic invariants), and the check-repair
planners get `fuzz_check_repair` (the qcow2 leak-reclamation,
refcount-correction, count-accumulation, and COPIED-reconciliation
planners, asserting sub-byte-masked containment, tally correctness,
the overflow/bounds error classifications, and idempotence).
The dd subcommand adds `fuzz_dd_window` (the pure
input-window math — count-clamp / skip-subtract / empty-on-overrun
with saturating arithmetic), `fuzz_chs_rounded_size` (VHD/VHDX CHS
geometry rounding) and `fuzz_dd_read` (the byte-accurate windowed
qcow2 read primitives). The amend subcommand adds
`fuzz_amend_planners`, and the bitmap subcommand adds
`fuzz_bitmap_parse` (the qcow2 bitmap directory/table/extension
parsers) plus `fuzz_bitmap_planners` (the bitmap crate's
directory/action/merge functions over synthesised
directory+refblocks). The bench subcommand adds
`fuzz_bench_schedule` (the pure `crates/bench` schedule math: param
validation, offset advance, transfer splitting, and flush cadence,
over a deliberately unclamped fuzzed header). Finally, the
`crates/qcow2-write` planner gets two targets (phase 8 of
PLAN-qcow2-write-infrastructure). `fuzz_qcow2_write` decodes a fixture
archetype (clean / backing-present / shared-data / shared-L2 nested /
owned-L2 / zero-flag-target) at a cluster size {512, 4 KiB, 64 KiB,
2 MiB} and drives a bounded `plan_write` / `plan_flush` sequence through
the crate's feature-gated `sim` harness, asserting the copy-on-write
invariant oracle after every operation: **`max_rc < 3`** (the COW
corruption signature — a snapshot-shared child driven past its
creation refcount of 2), snapshot-shared clusters byte-preserved and
never freed (`rc >= 1`), no dangling / past-EOF L1/L2 pointer, and —
after a flush — `OFLAG_COPIED` set iff refcount is exactly 1. A
`WriteError` refusal is a valid outcome, not a crash.
`fuzz_qcow2_write_growth` feeds geometry to the `growth` module's
`plan_refcount_growth`, asserting no overflow, the self-coverage
invariant, and cap adherence. Both are registered in the fast tier
(`tools/ci/fuzz-tier.sh`); their shake-out found no planner bug.

The seed corpus is extracted from `instar-testdata` by
`scripts/extract-fuzz-corpus.py`, which filters images by format,
generates hand-crafted minimal valid inputs, and restores the corpus
accumulated by prior nightly runs (keyed by target name) so coverage
compounds. The CI workflow (`.github/workflows/coverage-fuzz.yml`) runs
nightly at 04:00 UTC with per-target durations tiered against a 450-min
budget (`tools/ci/fuzz-tier.sh` — deep parser targets get the larger
share), plus PR smoke tests and manual dispatch. Crashes are minimized
and filed as GitHub Issues immediately.

## Open Questions

1. How to handle backing files in qcow2? Flatten on conversion?
2. Should we support in-place format conversion or always copy?
3. What's the minimum viable protocol for host-guest communication?
4. How to handle progress reporting and cancellation?
5. Memory limits for the sandbox?
