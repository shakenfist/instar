# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- **The agent context is linted.** `skillsaw` now runs as a pre-commit
  hook and as the `Agent context` CI check over `AGENTS.md`, `CLAUDE.md`
  and `.claude/`, looking for malformed frontmatter, instructions
  smuggled into a file an agent is handed, embedded credentials and
  dangerous hook configuration. Running `pre-commit run --all-files`
  after this change fetches the new hook's environment once. The twelve
  Claude Code skills moved to `.claude/skills/<name>/SKILL.md` with
  frontmatter at the same time — as bare markdown files they had never
  been loadable, so none of them had ever been discovered.

- `map` and `snapshot` accept `--qemu-version`, forcing the qemu-img
  version whose output format is emulated instead of detecting the
  host's. This is how the per-version baselines are exercised without
  installing seven qemu builds.

### Changed

- **`map --output=json` and `snapshot -l` now match the output of the
  qemu-img version being emulated, not just the newest one.** `map`
  omits `present` below qemu 6.1 and `compressed` below 8.2 rather than
  emitting them unconditionally, and `snapshot -l` emits the pre-9.0
  column layout (`VM SIZE` / `VM CLOCK` titles, 2-digit hours) when the
  detected qemu-img is older than 9.0. Both boundaries were measured
  against static per-version qemu-img builds. If you parse instar's
  output on a host with qemu older than 10.x, it now differs — because
  it now agrees with your qemu-img.

- **The merge queue now tests the released packages on seven
  distributions.** A `package-matrix` job builds one `.deb` and one
  `.rpm` and runs the full integration suite against the *installed*
  package on Debian 12/13, Ubuntu 22.04/24.04, Fedora, and Rocky 9/10 —
  each against the `qemu-img` that distribution ships, which ranges from
  6.2 to 10.2. This catches two classes single-distro CI cannot:
  packaging regressions (the v0.3.0 incident, where ten of sixteen
  operation binaries were missing from the manifests) and output-format
  parity gaps against older `qemu-img`. It runs only in the merge queue,
  so pull-request latency is unchanged.

- **Lowered the release binary's glibc floor to run on far more
  distributions.** The `instar` binary is now built on Debian 11
  (bullseye, glibc 2.31) instead of a rolling recent Debian, so a
  single published artifact runs across Debian 11+, Ubuntu 22.04 LTS
  and 24.04 LTS, Fedora, and Rocky/RHEL 9 and 10 — previously the
  packages required glibc 2.39 and excluded Ubuntu 22.04 and
  Rocky/RHEL 9. glibc is forward-compatible, so building on the
  oldest supported glibc is what widens the range. The devcontainer
  is now split into a minimal `debian:bullseye` release build image
  (toolchain only, produces the binary and the `.deb`/`.rpm`) and the
  existing full Debian dev/test image (qemu-utils, the libyal
  parsers, and the fuzz/audit tooling), so lowering the floor does
  not drag the test tooling onto an older base.
  `tools/verify-glibc-floor.sh` installs the built packages on every
  target distribution and exercises them under KVM as the empirical
  acceptance check. The floor is now guarded rather than merely
  chosen: `renovate.json` excludes the release image's Dockerfile from
  automated base bumps, and `tools/ci/check-glibc-floor.sh` fails the
  build if the shipped binary ever requires a glibc above 2.31.

### Removed

- **The `@shakenfist-bot please address comments` automation is
  retired**, along with `pr-address-comments.yml` and its helper
  scripts. It triggered on `issue_comment`, so it held `contents:
  write` on the pull request branch for a feature nobody used, and it
  was the last caller of the local review renderer and schema — copies
  of what now lives in `shakenfist/actions` beside the reviewer itself.
  Review feedback is addressed by hand, or by asking for a re-review
  once it has been.

### Fixed

- **`rebase` no longer plans a write at an arbitrary offset for an
  overlay with a corrupt backing-path pointer.** The qcow2 rebase
  planner took the overlay header's `backing_file_offset` /
  `backing_file_size` at face value when rewriting the backing name
  in place, and `QcowHeader::parse` range-checks neither. A header
  claiming a slot past end-of-file, inside the fixed header, or one
  whose end overflows 64 bits produced a patch the guest would have
  applied outside the image (found by fuzzing, issue #485). Both
  modes now refuse such an overlay with `ERROR_HEADER_MISMATCH`, as
  does an overlay file too short to hold the header fields the
  rewrite touches (`ERROR_OVERLAY_CORRUPT`).

- **VHD images instar writes are no longer silently truncated when
  read by qemu-img older than 10.0.** instar stamped its VHD footers
  with the creator app `imgo`; for any creator it does not recognise,
  qemu before 10.0 computes the disk size from the footer's CHS
  geometry rather than trusting `current_size`, and instar's CHS
  product can address less than the size it declares. The tail of the
  disk was therefore invisible — silent data loss — on Debian 12,
  Ubuntu 22.04 and 24.04, and RHEL/Rocky 9, in `create`, `convert` and
  `resize` alike. Footers are now stamped `qem2`, which those versions
  do recognise, so they read `current_size` and see the whole disk.

  Existing VHDs are not corrupt and do not change size, but newly
  written ones differ byte-wise from previous releases (the four
  creator-app bytes and the footer checksum). Images written by other
  tools that use an unrecognised creator app remain subject to the
  same qemu behaviour; see docs/quirks.md.

## [0.3.0] - 2026-08-02

### Fixed

- **The .deb and .rpm packages now ship all fifteen operation
  binaries (commits `dd45714` and `7be1523`).** The
  `[package.metadata.deb]` and `[package.metadata.generate-rpm]`
  asset lists in `src/vmm/Cargo.toml` were last touched for v0.2.0
  and still shipped only the original six guest binaries (core,
  info, copy, check, compare, convert), so every post-v0.2
  subcommand of an installed package failed at runtime with a
  missing `/usr/lib/instar/<op>.bin`. Both manifests now carry
  `core.bin` plus one binary per operation (amend, bench, bitmap,
  commit, create, map, measure, rebase, resize and snapshot join
  the original five), and the package install smoke test
  (`tools/test-package-install.sh`) derives its expected roster
  from `src/operations/` — a future operation missing from the
  manifests fails the smoke test automatically — and exercises
  `create` and `map` from the installed package.

- **Guest CPU exceptions now fail loudly instead of
  triple-faulting (issue #375, PR #457).** The guest had no
  interrupt descriptor table, so any CPU fault — an invalid opcode
  from the dormant opt-level=z + lto miscompile the guest ops carry
  `#[inline(never)]` to dodge, a page fault from a stray pointer —
  escalated to a triple fault that KVM surfaced only as an opaque
  `VcpuExit::Shutdown` ("possible triple fault"): no vector, no
  faulting address. The guest core now installs a minimal IDT
  (`core/src/idt.rs`) covering the Intel exception vectors 0..=31
  as the first step of `_start`; each handler reports the vector
  and faulting RIP over the serial error channel and halts, and the
  host enriches the "guest did not return a result" error to name
  them (e.g. `amend: guest CPU exception: invalid opcode (#UD) at
  guest RIP 0x3002c`). A diagnostics improvement across every
  subcommand; the `#[inline(never)]` attributes stay as the primary
  defense against the miscompile itself.

- **Security hardening across the parse and device surfaces
  (issues #446–#449, PR #454).** Four defense-in-depth closures.
  The behaviour-visible one: LUKS2 Argon2 `kdf_time` and `kdf_cpus`
  are now clamped at parse time (zero, or above 512 / 16
  respectively, is refused), so a crafted LUKS2 header can no
  longer drive unbounded key-derivation CPU cost when the operator
  supplies a passphrase — such headers are refused, while real
  headers use tiny values and are unaffected (#449). Also:
  the virtio-block device rejects guest-written queue sizes that
  are zero, exceed the advertised maximum of 256, or are not a
  power of two, instead of relying solely on the downstream
  bounds checks (#447); the info, check and copy guest ops re-check
  `sector_size` in-guest, matching the backstop map and measure
  already carried (#448); and resize's host-side VHDX virtual-size
  probe now bounds its metadata read instead of sizing an
  allocation from an attacker-controlled u32 region length, closing
  a crafted-VHDX ~4 GiB host-allocation denial of service (#446).

- **`instar resize` now grows qemu-img-created qcow2 images
  (issue #373).** qemu-img truncates a fresh image at the exact end
  of its L1 table, so a valid image's file size is usually not a
  multiple of its cluster size; the grow planner refused that shape
  with "guest reported error 13" on virtually every qemu-created
  image at cluster sizes >= 4096 (and on cs=512 geometries whose L1
  byte length is not a multiple of 512), while qemu-img resize
  succeeded. Appended metadata regions now start at the next cluster
  boundary — where qemu's own allocator places them — and header-only
  grows leave the file size untouched. Covered by new planner unit
  tests and a qemu-created-image integration matrix
  (`TestResizeQemuCreatedImages`).

- **VHD footer CHS now matches qemu's upward-search geometry
  (issue #413).** `build_footer` recomputed the footer CHS by
  re-flooring `current_size` through `calculate_geometry`, but qemu
  writes the geometry its `calculate_rounded_image_size` search
  landed on — and the two differ whenever the search's final
  candidate sits above a head-count boundary while its product sits
  below one (a 104349-sector dd window declares 104363 sectors =
  877×7×17, but the floor of 104363 is 1023×6×17 = 104346, which
  cannot even address the declared size). Footers for qemu-roundable
  sizes (fixed points of `chs_rounded_size`, which is what the dd
  path stamps) now carry the search geometry via the new
  `footer_geometry` / `chs_rounded_geometry` helpers; verbatim-size
  footers (whole-image convert, create, resize) keep the VHD-spec
  floor CHS as before. Zero-size footers now write CHS `(0,0,0)` as
  qemu does for a count=0 dd, instead of `(0,4,17)`. Found by
  coverage fuzzing (`fuzz_chs_rounded_size` invariant 5, whose old
  floor-based form is rewritten against the search-geometry
  contract); differentially validated against `qemu-img create -f
  vpc` 10.0.8 footers across 337 sizes including the window edges,
  plus an end-to-end `instar dd` vs `qemu-img dd` footer comparison.

- **qcow2 chain reader ignored the classic-L2 zero flag (#432).** A v3
  `QCOW_OFLAG_ZERO` (bit 0) cluster reached through a backing chain read
  as the wrong bytes — host == 0 fell through to a lower backing and
  host != 0 read stale host bytes — silent active-view corruption with
  blast radius rebase / convert / compare / bench. `cluster_lookup` in
  `crates/qcow2` gained a `ClusterLookup::Zero` verdict and the chain
  reader now zero-fills for it (both host cases). Fixed fix-first as
  step 7z of PLAN-qcow2-write-infrastructure phase 7.

- **`instar bench -w` left the refcount table referencing
  unmaterialized blocks past EOF on overwrite-dominant growth
  schedules (issue #433).** An overwrite-dominant qcow2 `-w` schedule
  that also crossed the preemptive refcount-growth threshold
  provisioned refcount blocks and wrote their refcount-table pointers,
  but the run allocated nothing, so `flush_dirty_refblocks` (which
  writes back only dirty blocks) never materialized them — the
  refcount table ended up pointing at refcount blocks past
  end-of-file. Silent (exit 0) and `qemu-img check`-dirty on a
  check-clean input; repairable by `check -r`, but a later allocator
  could double-allocate. Growth now marks every newly provisioned
  refcount block dirty before its eager flush, materializing every
  block the refcount table references (restoring qemu's
  every-RT-referenced-block-is-allocated invariant); the write rides
  the existing growth fsync, so the flush census is unchanged.
  Regression test
  `test_overwrite_only_growth_check_clean_issue_433`. Found by the
  phase-6 probes and fixed before the phase-6 migration, which then
  carried the corrected growth through byte-identically. See
  [docs/plans/PLAN-qcow2-write-infrastructure.md](docs/plans/PLAN-qcow2-write-infrastructure.md).

- **`instar commit` no longer corrupts internal snapshots (issues
  #420 and #423, the latter an overlay-side defect found during the
  gate work).** commit's per-cluster loop blind-overwrote
  snapshot-shared backing clusters that qemu-img COWs and
  preserves — silent snapshot corruption, invisible to `qemu-img
  check` — and the post-commit overlay-clear pass decremented
  clusters an overlay snapshot still referenced (refcount=0 with a
  live reference; latent snapshot data loss). An interim gate first
  made commit refuse before any mutation when either side carried
  internal snapshots (errors 14 and 15); the phase-7 copy-on-write
  work (see the PLAN-qcow2-write-infrastructure phase 7 entry under
  *Added*) then resolved the defects properly — snapshot-shared
  clusters are copied before writing, backing snapshots are
  preserved bit-identically, and no refusal remains.

- **`instar rebase` safe mode no longer corrupts snapshot-bearing
  overlays (issue #421).** Safe-mode rebase (including safe-mode
  detach) mutated snapshot-shared L2 tables in place and
  under-counted refcounts on doubly-referenced clusters, enabling
  live data loss via a later `snapshot -d`. An interim gate first
  refused safe mode on snapshot-bearing overlays before any
  mutation (error 14; `-u` metadata-only rebase never touches
  snapshot-shared state and stayed allowed); the phase-7
  copy-on-write work (see *Added*) then lifted the refusal —
  snapshot-shared tables and clusters are copied before mutation,
  with snapshot read-back verified against a qemu-img twin.

- **`instar rebase` hung on deep-allocation safe rebases (issue
  #422, reported as a 512-byte-cluster livelock).** The root cause
  was a guest panic, not a livelock: the safe-mode L2 lookup slice
  was built once with the initial staged-L2 count, so staging a new
  L2 table and then visiting another cluster in its coverage indexed
  past the stale length — an out-of-bounds panic spinning forever in
  the guest's `loop {}` panic handler. Reproducible at the default
  64 KiB cluster size with sparse overlays, not cs=512-specific. A
  second latent defect fixed at the same time: the staged-L2 growth
  arena was carved before the refblock staging regions and could
  clobber them. The lookup slice is now re-derived after growth and
  the staging layout reordered (growable arena last). The original
  issue fixture now terminates in 0.58 s with the pre-existing
  refcount-exhaustion refusal (v1 never appends refblocks — a
  documented capacity limit retired later by the master plan's
  refcount-growth work), a previously-hanging 64 KiB sparse shape
  completes with qemu-identical content, and output byte-invariance
  on previously-working shapes was proven against a pre-fix build.

- **`instar dd`/`convert -O vpc` declared a different virtual size
  than `qemu-img` for windowed copies (issue #382).** The VHD size
  rounding (`vhd::chs_rounded_size`) approximated qemu's CHS rounding
  with one pass of ceiling divisions; qemu (`vpc.c
  calculate_rounded_image_size`) instead searches upward from the
  requested sector count for the first candidate whose floor-geometry
  product covers the request. For a 69632-sector dd window qemu
  declares 69700 sectors (CHS 820/5/17) while instar declared 69936 —
  with a footer CHS (822/5/17) that could not even address its own
  current_size. `compute_vhd_geometry` also carried a non-qemu
  "medium-large" 255-sectors-per-track branch at `65535*3*17` sectors
  (qemu switches at `65535*16*63`), diverging on every vpc output of
  roughly 1.6 GiB and larger. Both are now exact mirrors of qemu
  vpc.c, validated against `qemu-img` 10.0.8 across the branch
  boundaries and swept for the fixed-point property that lets
  `build_footer` recompute the identical CHS from current_size. The
  `fuzz_chs_rounded_size` target now asserts exact geometry
  reconstruction and idempotence instead of the old one-cylinder
  tolerance that had been documenting the bug.

- **Differential fuzzer: snapshot byte compare now ignores
  dead-cluster residue (issue #381).** Byte differences confined to
  clusters whose refcount is 0 in *both* images are residue, not
  divergence: under metadata-cache pressure (512-byte clusters) qemu
  flushes a half-refreshed freed L2 mid-walk even with
  `file.discard=ignore` — the eviction writes partially-updated
  COPIED flags to disk, then the remaining dirty flags are discarded
  with the cache entry when the L2 is freed — while instar never
  writes freed clusters at all. Both images are `check`-clean and
  `compare`-identical; only the dead bytes differ. See the updated
  "Freed-cluster bytes" quirk in docs/quirks.md.

- **Differential fuzzer: bench `-w` recipes temporarily steered
  away from small qcow2 clusters (issues #397–#401; steer-around
  since retired).** bench's original v1 write path allocated only
  from the refblocks populated at startup — never allocating new
  refblocks or growing the refcount table — and one 16-bit refblock
  covers just `cluster_size²/2` bytes of host file: 128 KiB at
  512-byte clusters, outrun by almost any allocating schedule. The
  picker's `qcow2-write-refblock-coverage` steer-around pinned `-w`
  qcow2 recipes to cluster sizes of at least 64 KiB while the
  limitation stood. The PLAN-bench-refcount-growth work (see
  *Added*) then taught bench to grow the refcount structures
  preemptively, and the steer-around and its
  `KNOWN_BENCH_DIVERGENCES` entry were retired — the full
  cluster-size matrix is back in `-w` differential coverage.

- **`instar info`'s human output for flat VMDK extents diverged from
  `qemu-img` (commit `dad884e`).** For monolithicFlat /
  twoGbMaxExtentFlat images, the human formatter emitted a single
  hardcoded placeholder extent block (descriptor path, empty format,
  a spurious "cluster size: 0"), omitted the `Child node
  '/extents.N'` blocks entirely, and reported `/file`'s length as the
  raw descriptor byte size instead of the protocol-node length
  rounded up to a 512-byte sector. The JSON path was already correct
  via `ResolvedVmdkDescriptor.flat_extents`; the human path now
  mirrors it (one entry per resolved flat extent, gated `/extents.N`
  child blocks, the same `div_ceil(512)` rounding the raw format
  already used). Found by the memory-map lift's full integration run
  (`test_info_safe` 526/536 → 536/536); non-flat vmdk output is
  unchanged.

- **`instar convert -O vmdk|vpc|vhdx` silently truncated data when
  the input qcow2 had clusters smaller than the output grain/block
  size (commit `779e7a7`).** The structured writers (vmdk, vhd,
  vhdx) filled only one input cluster per output grain/block,
  leaving the remainder of each grain zero-filled when the qcow2
  cluster size was smaller than the output grain or block size. The
  correct fix is `qcow2::read_chain_virtual_range`, which fills the
  full output grain by chaining as many input-cluster reads as
  needed. This is a pre-existing bug in the shipped `instar convert`
  command, found and fixed during `dd` implementation (phase 9).

- **Dense VHD output capacity under-estimate could stall the final
  write (commit `b80c5d7`).** The VHD writer computed output
  capacity from the pre-window virtual size rather than the
  post-window byte count when producing dense (dd-style) output,
  causing the capacity hint passed to the guest to be too small for
  the actual number of blocks written; the final write to the last
  block stalled waiting for capacity that was never signalled. Fixed
  by deriving the dense-output capacity from the actual window size.

- **Guest core `.bss` overflow corrupting operation code.** `core.bin`'s
  `.bss` (the `INPUT_DEVICES`/`OUTPUT_DEVICE` virtio statics) overflowed
  its 64 KiB budget into the operation region at `0x20000`; core's
  device init wrote a `VirtioBlock` struct to `0x20380`, clobbering ~72
  bytes of the loaded operation's code. Only `amend` had critical branch
  logic at that offset, so it surfaced as spurious `ERROR_HEADER_MISMATCH`
  for some qcow2 cluster sizes. Fixed by raising `OPERATION_LOAD_ADDR`
  `0x20000` → `0x22000` (giving core a 72 KiB region) and updating every
  `src/operations/*/linker.ld`; `scripts/check-binary-sizes.sh` now
  validates the `.bss`-inclusive ELF memory extent (not just the flat
  `.bin` file size, which excluded `.bss`) and warns as a binary nears
  its limit. Found by the phase-8 differential fuzzer.

- **`instar create` could emit an unrepresentable Fixed VHD plan for
  enormous virtual sizes (#353, #355, #357, #361, #362, #363, #367).**
  `plan_vhd` placed the footer at `byte_offset == virtual_size` with
  no upper bound, so a `virtual_size` near `u64::MAX` overflowed the
  file-size bookkeeping (the `fuzz_create_emitters` invariant panic).
  `plan_vhd` now rejects `virtual_size` above VHD's maximum
  (`0xFF000000` sectors = 2040 GiB, matching qemu `vpc.c`) before the
  subformat split.

- **`instar resize` panicked on a VHDX header with a near-maximum
  sequence number (#354, #360).** The grow planner incremented the
  parsed (attacker-controllable) `sequence_number` by 1 and 2 for the
  two header copies without bounds; a value within 2 of `u64::MAX`
  overflowed (the `fuzz_resize_planners` panic). The planner now
  rejects such a header up front with `Overflow`.

- **qcow2 sub-byte refcounts corrupted on `create` and `resize
  --shrink` (#365).** `crates/qcow2::create::build_header` hardcoded
  the header's `refcount_order` field to the 16-bit default instead
  of deriving it from `refcount_bits`, and `set_refcount_to_one`
  packed sub-byte (1/2/4-bit) refcount entries MSB-first while qemu
  (and instar's own `lookup_refcount`) are LSB-first. Both writers
  are shared by `create` and by the `resize --shrink` header rebuild,
  so `instar create -o refcount_bits=1` and `instar resize --shrink`
  on a `refcount_bits` 1/2/4 image produced files that exited 0 but
  failed `qemu-img check` (referenced clusters left at refcount 0).
  `build_header` now derives `refcount_order = log2(refcount_bits)`
  and sub-byte widths pack LSB-first; `create` and `resize --shrink`
  across `refcount_bits` 1/2/4/16 are `qemu-img check`-clean. The
  differential fuzzer's create and resize pickers gained a
  `refcount_bits` dimension to guard the path.

- **Sub-byte refcount accessors used the wrong bit order.** The
  `snapshot` crate's `read_refcount_in_block` /
  `set_refcount_in_block` (lifted from `resize::qcow2`, which now
  delegates to them) packed 1/2/4-bit refcount entries MSB-first
  within each byte; qemu's `get/set_refcount_ro0/ro1/ro2` are
  LSB-first. Round-trip tests pass under either order, which is
  how the divergence survived — found by the pre-push audit's
  cross-check against `qcow2::lookup_refcount` and pinned
  byte-exactly against the qemu source. Production impact was
  limited: the snapshot mutating modes refuse `refcount_bits !=
  16`. (The separate `instar resize --shrink` / `create`
  sub-byte corruption noted here originally is now also fixed —
  see the entry above.)

- **Snapshot list rows over-padded multibyte UTF-8 names.**
  qemu's `qemu-img snapshot -l` pads the ID and TAG columns with
  C `printf` minimum field widths, which count **bytes**; the
  renderer used Rust's `{:<7}` / `{:<16}`, which count chars and
  over-pad multibyte names (`snäp-名前` drew 9 pad spaces from
  instar, 4 from qemu). The columns now pad by byte length, so
  `-l` output is byte-identical for any name qemu can create.
  Found by PLAN-snapshot phase 13's differential fuzzer on its
  first smoke run — the phase 10/11 fixture names were all
  ASCII, where the two semantics agree (commit `5f6a1b9`).

- **Snapshot delete left stale COPIED flags in surviving L2s.**
  qemu's delete decrement walk also recomputes `OFLAG_COPIED` on
  every L2 entry it visits and flushes dirty L2s whose clusters
  were not freed, so an L2 shared between the deleted snapshot
  and a surviving one lands on disk with refreshed flags.
  instar's delete refreshed only the active chain, leaving
  stale COPIED-clear entries in the surviving snapshot's L2 —
  safe (a spurious COW after a later apply at worst; `qemu-img
  check` clean) but not byte-identical. Delete now refreshes
  the deleted chain's staged L2 set and writes back the
  surviving (refcount > 0) snap-set L2s in its final write
  group, matching qemu's cache-discard behaviour for freed L2s.
  Found by the phase 13 differential fuzzer's soak (commit
  `a5d0767`); a shared-L2 regression scenario joined
  `tools/snapshot-delete-matrix.sh`.

- **`convert --snapshot` picked the wrong snapshot on
  ID/name-collision images.** `qcow2::find_snapshot` matched
  id-or-name per entry and returned the first hit, where
  qemu's `find_snapshot_by_id_or_name` (the resolver behind
  `qemu-img convert -l` and `snapshot -a`) makes one full ID
  pass and only then a name pass. On an image with `id=1
  name="2"` and `id=2 name="x"`, `instar convert --snapshot 2`
  extracted the snapshot *named* "2" while qemu extracts ID 2.
  The matcher is now two full passes; the dead
  `find_snapshot_streaming` variant was removed. A collision
  regression test joins the convert suite; the bounded
  16-entry lookup residual is documented in `docs/quirks.md`
  (PLAN-snapshot phase 14, probe 1).

- **Zero `date_sec` rendered a blank snapshot DATE column.**
  qemu feeds a zero `date_sec` through `localtime` and renders
  the Unix epoch; instar early-returned an empty string,
  diverging on hand-crafted images (the value is unreachable
  via either tool's create). The early return is removed and
  the epoch renders like any other timestamp (PLAN-snapshot
  phase 14, probe 2; found by phase 13's date-normalization
  probes).

- **Fuzzing bug backlog (44 issues).** Five categories of fuzz
  findings from coverage-guided and differential fuzzing are
  closed by the `PLAN-fuzzing-bugs` work:
  - `create::plan_vmdk` no longer panics on adversarial
    `(virtual_size, grain_size)` tuples — capacity arithmetic
    now uses `checked_mul` and surfaces
    `CreateError::Overflow` (commit `0220ae9`).
  - `qcow2::scan_allocation` honours the invariant
    `allocated_bytes <= virtual_size` for on-disk L2 entries
    past `virtual_size`, which the spec allows but the
    measure path rejects. Last-cluster contributions are
    capped at `virtual_size - cluster_start`
    (commit `6de9687`).
  - The measure calculators (`measure_raw`, `measure_qcow2`,
    `measure_vmdk`, `measure_vhd`, `measure_vhdx`) route
    construction of their `MeasureOutput` through a new
    `try_new` helper that rejects sum-overflow on
    `required + fully_allocated` (commit `b4e312d`).
  - The dynamic-VHD, VHDX, and VMDK allocation scanners
    clamp `allocated_bytes` at `virtual_size`, fixing the
    `instar measure` failure on small dynamic-VPC images
    where a single 2 MiB block exceeds the 1 MiB virtual
    size (commit `bed14fc`).
  - `scripts/differential-fuzz.py` reclassifies external-
    tool subprocess timeouts as `inconclusive_external_timeout`
    rather than `exit_code_divergence`, so qemu-img hangs
    on adversarial qcow2 shrink inputs no longer file
    GitHub issues against instar (commit `71e3e33`).

### Added

- **Format-coverage phase 6: QED read-refusal recorded as policy
  (PLAN-format-coverage phase 6).** Resolves the master plan's Open
  question 1: QED stays a read-refused format, by deliberate
  decision rather than a parity gap. `instar info` already reads QED
  correctly (byte-parity with qemu-img); every other subcommand now
  carries a QED-named refusal pin — check (exit 63, naming the real
  format "qed" since check's own probe sees QED's offset-0 magic,
  unlike DMG), map, measure, bench (via the issue-#444 chain gate,
  with no `"bench:"` message prefix — a deviation from convert/
  compare/dd), resize, rebase, commit, amend, snapshot, and bitmap
  (convert/compare/dd and the oslo divergence were already pinned).
  The decision rests on nil real-world demand for reading QED plus
  oslo.utils' own explicit ban (a real `QEDInspector` that raises
  `SafetyCheckFailed: ... banned`) — a stronger ecosystem signal than
  the "oslo simply lacks an inspector" case that justified reading
  DMG/VDI/Parallels/QCOW1. This phase also **corrects a stale
  documentation claim**: QED is not formally deprecated by qemu (no
  `deprecated.rst` entry, no runtime warning, `qemu-img create -f
  qed` still works on 10.2.0) — qemu-img reads/writes/checks/maps/
  measures/benches QED normally; the refusal is instar's own scope
  choice. Two cosmetic wording inconsistencies are pinned as-is
  rather than normalised (the `"Qed"` Debug-spelling in resize/
  rebase; check's exit 63 vs. every other refusal's exit 1). The
  `qed-simple` baselines in instar-testdata were reconciled: the
  check/compare trees (permanently unconsumable under this policy)
  were retired and the generator's check/compare/measure/map
  whitelists lost `qed`, while the qemu-img-{human,json} trees were
  kept since they back `info`'s baseline coverage and are the raw
  source of truth profiles regenerate from. Revisit criteria (a real user
  request to read QED, or QED images surfacing in a served workload)
  and a qcow1-class reader sketch are recorded for a future phase if
  the decision is ever reversed. See
  [docs/format-coverage.md](docs/format-coverage.md) and
  [docs/quirks.md](docs/quirks.md) for the full decision record.

- **Format-coverage phase 5: DMG convert-from read path
  (PLAN-format-coverage phase 5).** `instar convert`, `compare`,
  `dd`, and `bench` now accept DMG (Apple UDIF) as input, via a new
  `src/crates/dmg/` no_std parser crate wired into the qcow2 crate's
  chain reader (`dmg-input` feature, enabled by convert/compare/
  bench/rebase). The reader parses the koly trailer, then the chunk
  table from either the XML-plist path (a byte-for-byte port of
  glib's lenient, invalid-character-skipping base64 decoder) or the
  old resource-fork path, into a sorted, verified mish/BLKX chunk
  lookup. Codec scope is zero/raw/ignore/zlib (zlib-wrapped inflate,
  unlike QCOW1's raw-deflate); ADC/bzip2/lzfse/zstd/unknown chunk
  types get a typed init refusal naming the code, since qemu's own
  codec support is compile-flag dependent across the version matrix
  (bzip2 decodes only on static 6.0.0 and host 10.0.11; lzfse and
  ADC decode nowhere) and no single build makes a valid parity
  target. **DMG inverts every prior phase's error posture**: a gap
  (an uncovered sector, a dropped/refused chunk, or the koly
  `SectorCount`-vs-mish-coverage tail), a truncated raw span, or
  truncated compressed data are all read ERRORS, matching qemu
  exactly — never zero-fill, the opposite of VDI/Parallels/QCOW1's
  zero-fill posture. **instar avoids a universal qemu crash**: any
  DMG whose chunk table parses to zero entries (bad mish magic,
  broken base64, or no `<data>` blocks) SIGSEGVs every tested
  qemu-img version (static 6.0.0, static 10.2.0, host 10.0.11) on
  read, while `info` is unaffected; instar refuses the empty table
  cleanly at reader init instead, shipped as the `dmg-empty-table`
  reproducer and recorded as a candidate upstream report — distinct
  from `dmg-no-chunk-table`'s ordinary clean-EINVAL shape (no chunk
  source at all). instar's own bounded-memory caps (1 MiB staged
  plist/resource-fork region, 32768-entry chunk table, 4096-sector
  per-chunk staging) are smaller than qemu's own legal range, a
  documented capacity divergence pinned by `dmg-overcap-chunk` (a
  qemu-legal 4 MiB chunk that qemu converts fine but instar refuses
  typed). Detection stays the phase-1 content-based koly-trailer
  scan, strictly stronger than qemu-img's `.dmg`-extension-only
  probe — now with a real behavioural consequence: an extensionless
  DMG converts as its raw container bytes under qemu but as the real
  decoded disk under instar, pinned as a deliberate divergence. DMG
  is supported at any backing-chain position, proven by a `qcow2 -F
  dmg` overlay-over-DMG chain converging byte-for-byte with qemu.
  `check` still refuses DMG (exit 63) but names the format "raw",
  not "dmg", since check's dispatch never runs the koly probe — a
  genuine rc parity with qemu-img's own dmg-check refusal, wording
  aside. `map`, `measure`, and `resize` are unaffected by this phase
  and keep their phase-1 raw pass-through (master-plan future work).
  Sixteen fixtures total (five safe including the phase-1
  `dmg-simple`: `dmg-mixed`, `dmg-multipart`, `dmg-rsrc-fork`, and
  the error-parity `dmg-gap`; eleven malformed/refused, extending the
  four phase-1 trailer fixtures with seven new reader-refusal
  fixtures for over-cap sizes, each unsupported codec, the capacity
  divergence, and the empty-table crash reproducer), cross-version
  qemu-img baselines where parity exists, oslo cross-validation,
  coverage-guided fuzzing of the table/chunk parsers
  (`fuzz_dmg_table`, `fuzz_dmg_chunk`), and `dmg` added to the
  differential fuzzer's format pool via a deterministic mini-builder
  (qemu-img cannot create DMGs) with `op_map`/`op_measure` gated to
  reflect the retained raw-pass-through divergence. See
  [docs/format-coverage.md](docs/format-coverage.md) and
  [docs/quirks.md](docs/quirks.md) for the full divergence records.

- **Format-coverage phase 4: QCOW1 convert-from read path
  (PLAN-format-coverage phase 4).** `instar convert`, `compare`,
  `dd`, and `bench` now accept QCOW1 ("qcow", qemu's original
  deprecated format) as input, including backing chains and
  compressed clusters, via a new `src/crates/qcow1/` no_std parser
  crate wired into the qcow2 crate's chain reader (`qcow1-input`
  feature, enabled by convert/compare/bench/rebase). This phase also
  **fixed two pre-existing defects**: (1) real QCOW1 images were
  misdetected as QCOW2 — `detect_format_from_header` checked only
  the shared `QFI\xfb` magic and never the version field, producing
  garbage `info` output (virtual size 0, a QCOW2-shaped `compat:
  0.10` block) and a misleading convert error; detection is now
  version-aware (`QFI\xfb` + version 1 => QCOW1, else the QCOW2
  route), with the reader arm landing strictly before the detection
  fix to avoid a latent silent-raw-read hazard; (2)
  `INFO_RESULT_FLAG_ENCRYPTED` was declared but never consumed by
  either info emitter — both now print `encrypted: yes` /
  `"encrypted": true`, gated off for the `"luks"` format string so
  the hand-maintained LUKS goldens stay byte-identical (encrypted
  QCOW2 images pick up the line for free as a side effect, with no
  baseline churn). The reader matches qemu's exact RO open path:
  `cluster_bits`/`l2_bits` range checks, size bounds including the
  empirically-pinned "Image too large" boundary, `crypt_method` <= 1
  at parse; a per-cluster walk (clusters down to 512 bytes);
  backing-chain fall-through on unallocated clusters — QCOW1 is the
  first non-QCOW2 format with backing support, and the reader arm
  mirrors the QCOW2 arm's own recursion mechanism rather than the
  VDI/Parallels arms' zero-fill; raw-DEFLATE compressed clusters (no
  zlib wrapper, unlike QCOW2's zlib-first two-try helper); past-EOF
  and truncated data-cluster reads zero-fill on every qemu version
  (no Parallels-style 8.1.x window); and odd header sizes truncate
  **down** to `total_sectors*512`, the opposite of VDI's round-up.
  instar now emits the format string `"qcow"` (matching qemu-img and
  oslo.utils), with `"qcow1"` kept as an accepted input alias.
  Malformed QCOW1 fixtures get a distinct `info` posture from
  VDI/Parallels: the new info arm validates the same fields the
  reader does and falls back to an empty (virtual size 0) default on
  failure, rather than best-effort nonzero fields. `check` still
  refuses QCOW1 (exit 63) — genuine parity, since qemu's own qcow
  driver has no check support either (wording differs only
  cosmetically). `map` and `measure` stay refusals — a deliberate,
  recorded divergence, since qemu-img actually supports both on
  qcow1 (master-plan future work; AES decryption of encrypted qcow1
  is future work too). Encrypted (AES, crypt_method=1) QCOW1 images:
  `info` works and reports the new encrypted line; data ops refuse
  cleanly, matching keyless qemu. Twelve new fixtures (seven safe:
  scattered-allocation data, a compressed twin, a backing overlay +
  base pair doubling as small-cluster coverage, an encrypted image,
  a past-EOF data cluster, and an odd-size header; five malformed:
  bad cluster_bits, bad l2_bits, oversized, invalid crypt_method, an
  overlong backing name), cross-version qemu-img baselines, oslo
  cross-validation (oslo detects qcow1 as `"qcow2"` by magic alone;
  virtual sizes agree except on the odd-size fixture), coverage-
  guided fuzzing of the header parser and two-level table walk
  (`fuzz_qcow1_header`, `fuzz_qcow1_table`), and `qcow` added to the
  differential fuzzer's format pool. A recorded qemu-img quirk:
  `convert -c -O qcow` writes a valid compressed image but exits 1
  with empty stderr on every version; the fixture generator and
  differential fuzzer verify by roundtrip instead of exit code. See
  [docs/format-coverage.md](docs/format-coverage.md) and
  [docs/quirks.md](docs/quirks.md) for the full divergence records.

- **Format-coverage phase 3: Parallels convert-from read path
  (PLAN-format-coverage phase 3).** `instar convert`, `compare`,
  `dd`, and `bench` now accept Parallels Disk Image as input — both
  the legacy `WithoutFreeSpace` (v1) and newer `WithouFreSpacExt`
  (v2/ext) magics — via a new `src/crates/parallels/` no_std parser
  crate wired into the qcow2 crate's chain reader (`parallels-input`
  feature, enabled by convert/compare/bench/rebase to avoid the
  raw-fallback hazard #444 closed). The reader matches qemu's RO open
  path exactly: `tracks`/`bat_entries` limits (the `tracks` cap is
  4186127, corrected during this phase from an off-by-681 planning
  estimate), per-magic BAT decoding (sector-valued entries under v1,
  cluster-valued entries under v2/ext), the v1-only 32-bit
  `nb_sectors` mask, `inuse`-dirty images always readable (instar
  only ever opens read-only), `data_off` ignored by reads, and
  past-EOF/truncated reads zero-filling rather than erroring — with
  one recorded version drift: qemu 8.1.0-8.1.5 refuse a past-EOF BAT
  entry at open (a regression window closed in 8.2.0), which instar's
  uniform zero-fill diverges from; the affected baselines are recorded
  faithfully via a new `profile-8-1-0` bucket, and
  `tests/test_info_safe.py` gained a general mechanism to skip
  scenario generation for any profile whose baseline meta records a
  non-zero qemu-img return code. A non-zero `ext_off` is refused at
  init — a deliberate divergence from qemu's read-only format-
  extension parsing (dirty bitmaps); no shipped or creatable fixture
  needs it today. Because qemu prints no `cluster_size` for Parallels,
  `instar info` now computes and stores it internally
  (`tracks << 9`) so the chain reader's chunking respects real cluster
  boundaries, while both emitters suppress the field for the
  `"parallels"` format string so `info` output stays byte-identical to
  qemu (verified by a full `test_info_safe` run, zero regressions).
  `parallels` leaves the phase-1 #444 refusal set entirely — it now
  has a real reader instead of a typed refusal. `check` is unaffected
  and still refuses Parallels (exit 63, "This image format
  (parallels) does not support checks"); qemu-img's own Parallels
  check is not mirrored because it asserts/crashes on newer qemu
  (10.2.0's `parallels_check_duplicate` assertion) for out-of-image
  BAT entries, making refusal the safer stance. `map`, `measure`, and
  `resize` are unchanged refusals. Nine new fixtures (five safe: a
  non-contiguous/swapped BAT, the v1-magic twin with sector-valued
  BAT entries, an `inuse`-dirty twin, a past-EOF BAT entry, and a
  4 KiB-cluster small-cluster case; four malformed: zero tracks, huge
  tracks, huge catalog, bad extension magic) plus the existing
  `parallels-v1`/`parallels-v2` joining the convert-parity matrix, all
  with cross-version qemu-img baselines, coverage-guided fuzzing of
  the header parser and BAT walk across both magics
  (`fuzz_parallels_header`, `fuzz_parallels_bat`), and `parallels`
  added to the differential fuzzer's format pool. See
  [docs/format-coverage.md](docs/format-coverage.md) and
  [docs/quirks.md](docs/quirks.md) for the full divergence records.

- **Format-coverage phase 2: VDI convert-from read path
  (PLAN-format-coverage phase 2).** `instar convert`, `compare`, and
  `dd` now accept VDI (VirtualBox Disk Image) as input — both dynamic
  and static images — via a new `src/crates/vdi/` no_std parser crate
  wired into the qcow2 crate's chain reader (`vdi-input` feature,
  enabled by convert/compare/bench/rebase to avoid the raw-fallback
  hazard #444 closed). The reader matches qemu's `vdi_open` exactly:
  all twelve open-time validation rules, allocation-order block-map
  lookup, discarded/unallocated entries reading as zeros,
  `block_extra` never participating in offset math, any `image_type`
  accepted (only type 2 is special, and needs no extra handling), and
  reads at or past the device capacity — including straddling reads —
  zero-filling rather than erroring, since qemu never validates VDI
  file length. An odd `disk_size` rounds up to 512 at open, matching
  qemu; `instar info`'s existing VDI parser now reports the rounded
  value too (previously reported the raw bytes), with a
  `KNOWN_VSIZE_DIVERGENCES` entry recording the resulting oslo.utils
  split (oslo reports the raw value). `vdi` leaves the phase-1 #444
  refusal set entirely — it now has a real reader instead of a typed
  refusal. `check` is unaffected and still refuses VDI (exit 63, "This
  image format (vdi) does not support checks"); `map`, `measure`, and
  `resize` are unchanged refusals. Nine new fixtures (four safe: data
  at multiple blocks with a discarded entry, static/identity block
  map, odd-size round-up, past-EOF zero-fill; five malformed:
  bad version, unaligned block-map offset, wrong block size, non-NULL
  parent UUID, too many blocks) plus the existing `vdi-simple` flipped
  to CI, all with cross-version qemu-img baselines, coverage-guided
  fuzzing of the header parser and block-map walk (`fuzz_vdi_header`,
  `fuzz_vdi_bat`), and `vdi` added to the differential fuzzer's format
  pool. See [docs/format-coverage.md](docs/format-coverage.md) and
  [docs/quirks.md](docs/quirks.md) for the full divergence records.

- **Format-coverage phase 1: Parallels, Bochs, cloop, and DMG
  detection + info parity (PLAN-format-coverage phase 1).** `instar
  info` now detects and correctly sizes four previously-unrecognised
  formats — Parallels (both `WithoutFreeSpace` and
  `WithouFreSpacExt` magics), Bochs (growing-mode), cloop (V2.0), and
  DMG (UDIF, detected by a new content-based koly-trailer scan rather
  than qemu-img's `.dmg`-filename probe) — matching `qemu-img info`
  byte-for-byte (human and JSON) across the 80-version baseline
  matrix. Also closes
  [#444](https://github.com/shakenfist/instar/issues/444): convert,
  compare, and dd previously read any detected-but-unsupported input
  format (qed, vdi, and now also the four new formats) silently as
  raw bytes zero-padded to the declared virtual size; a new central
  refusal gate in `discover_backing_chain` now rejects these with a
  typed `"<op>: input format '<fmt>' is detected but not supported
  for reading (detection and info only)"` error, covering mid-chain
  backing positions too. ISO is deliberately exempt (its raw
  interpretation is semantically correct and matches qemu-img, which
  has no ISO driver). Host info-emitter parity fixes: qemu-img's
  human-size formatter unit-selection for sub-MiB, KiB-round values,
  512-byte child-node file-length rounding for structured formats,
  and JSON `dirty-flag` suppression for the four detect-only drivers.
  New fixtures registered in `tests/manifest.json`: `parallels-v1`,
  `parallels-v2`, `bochs-growing`, `cloop-simple` (existing
  `instar-testdata` images, newly exercised), plus a generated
  `dmg-simple` UDIF image and four adversarial DMG fixtures
  (truncated koly, negative/huge SectorCount, missing chunk table),
  all with cross-version qemu-img baselines. See
  [docs/format-coverage.md](docs/format-coverage.md) and
  [docs/quirks.md](docs/quirks.md) for the full divergence records.

- **Fuzzing for the qcow2-write planner and its snapshot-bearing
  copy-on-write paths (PLAN-qcow2-write-infrastructure phase 8).**
  Two new coverage-guided libFuzzer targets exercise the
  `crates/qcow2-write` planner directly. `fuzz_qcow2_write` decodes a
  fixture archetype (clean / backing-present / shared-data /
  shared-L2 nested / owned-L2 / zero-flag-target) at a cluster size
  {512, 4 KiB, 64 KiB, 2 MiB} and drives a bounded
  `plan_write`/`plan_flush` sequence through the crate's Vec-backed
  simulation harness — lifted in this phase out of the crate's unit
  tests into a feature-gated `#[cfg(any(test, feature = "sim"))]
  pub mod sim` that is OFF in the production build, so the guest ops'
  `.bin` sizes are unchanged. After every operation it asserts the
  copy-on-write invariant oracle: `max_rc < 3` (the corruption
  signature), snapshot-shared clusters byte-preserved and never freed,
  no dangling/past-EOF L1/L2 pointer, and `OFLAG_COPIED` set iff
  refcount is exactly 1 after a flush (a `WriteError` refusal is a
  valid outcome, not a crash). `fuzz_qcow2_write_growth` feeds geometry
  to the `growth` module's `plan_refcount_growth`, asserting no
  overflow, the self-coverage invariant, and cap adherence. Both join
  the nightly `coverage-fuzz.yml` fast tier (30→32 targets); their
  bring-up shake-out found no planner bug. The differential fuzzer's
  `op_commit`/`op_rebase`/`op_bench` arms now also build
  snapshot-bearing fixtures (40% probability, when `qemu-io` is
  present) that exercise the phase-7 copy-on-write paths, with the
  oracle gaining the snapshot read-back triple — active-view
  `qemu-img compare` + `qemu-img check` clean + per-carrier snapshot
  read-back `instar == qemu twin` (`tests/helpers/snapshot_readback.py`)
  — and a 300-iteration local soak ran 0 divergences. The standalone
  `scripts/cow-soak.py` (phase 7e) is folded into the differential
  fuzzer and retired. See
  [docs/plans/PLAN-qcow2-write-infrastructure.md](docs/plans/PLAN-qcow2-write-infrastructure.md)
  and [docs/testing.md](docs/testing.md).

- **Copy-on-write for `commit`, `rebase` safe mode and `bench -w` on
  snapshot-bearing qcow2 images (PLAN-qcow2-write-infrastructure
  phase 7).** Writes into a qcow2 image that carries internal
  snapshots now **copy** the shared clusters instead of refusing (the
  phase-2 interim gates) or corrupting them — resolving issues #420
  (commit backing), #421 (rebase safe mode) and #423 (commit overlay).
  `crates/qcow2-write` gained a copy-on-write branch:
  `check_envelope_with(hdr, allow_snapshots)` / `new_state_cow` gate
  the capability, data-cluster COW copies a shared cluster before
  writing (repoint the L2, `rc(D')=1`, decrement `rc(D)`, never freeing
  the old cluster), and L2-table COW copies a shared table (repoint the
  L1, `rc(T')=1`, decrement `rc(T)`) while leaving child refcounts
  untouched (qemu bumps children to rc ≥ 2 at snapshot-creation time,
  so a child-increment would corrupt to rc 3). A net-new
  refcount-decrement primitive maps underflow to
  `RefcountInconsistent`. The snapshot-view semantic is per op —
  commit preserves backing snapshots bit-identically, rebase leaves the
  active view resolving through the new backing (qemu's contract), and
  bench preserves snapshots like commit. The correctness bar is
  qemu-parity (`qemu-img check` clean + active-view `qemu-img compare`
  + a snapshot read-back oracle), not image-byte identity. The zero-flag
  WRITE-target policy now matches qemu (host == 0 allocates fresh,
  host != 0 rc 1 overwrites in place clearing the zero bit, rc > 1
  COWs — the old offset is never freed). Verified check-clean and
  read-back-parity against pinned qemu-img 6.2.0 / 7.2.0 / 8.2.0 /
  9.2.0 / 10.2.0 (`tests/test_cow_cross_version.py`) and across 50
  randomized snapshot-bearing iterations with 0 divergences
  (`scripts/cow-soak.py`). Two follow-ups are recorded: commit does
  not byte-empty a snapshot-bearing overlay (the clear pass is skipped
  to avoid #423; active view and snapshots are correct), and rebase's
  COW refcount growth is coarsely sized. See
  [docs/plans/PLAN-qcow2-write-infrastructure.md](docs/plans/PLAN-qcow2-write-infrastructure.md).

- **Refcount growth for `commit` and `rebase` during copy-on-write
  (PLAN-qcow2-write-infrastructure phase 7).** The imperative
  refcount-growth execution moved out of the bench op into the shared,
  region-agnostic `growth::grow_refcounts` in `crates/qcow2-write-exec`,
  so commit and rebase can grow the refcount structures when a
  copy-on-write schedule crosses a refblock boundary rather than
  refusing `RefcountExhausted`. Bench's behaviour is byte-identical
  (the #433 materialization fix and the single-fsync census are
  preserved).

- **New `crates/qcow2-write` planner crate
  (PLAN-qcow2-write-infrastructure phase 3).** A pure `no_std`
  windowed step-program planner for "write N bytes at virtual offset
  X into an existing qcow2, allocating as needed": per-cluster
  classification (owned in-place overwrite / fresh allocation with
  sub-cluster zero-fill / typed refusals for compressed,
  snapshot-shared and unknown-bit-pattern shapes), L2 and
  data-cluster allocation, refcount maintenance in a single staged
  refblock copy, the unified v1 envelope gates, and the crash-safe
  write-ordering contract emitted as typed steps with explicit
  Ordering/Durability barriers. Internal infrastructure only — no
  operation consumes it yet, so there is no CLI-visible behaviour
  change: subsequent phases migrate commit, rebase safe mode and
  bench `-w` onto it and then add copy-on-write. Proven by 45 unit
  tests, an ordering-contract property suite (window-invariance from
  a 1-step buffer up, mechanical checks of the full ordering contract
  over emitted programs), and a simulation harness that executes
  emitted step programs against model disks and replays them
  truncated at every Durability barrier. See
  [docs/plans/PLAN-qcow2-write-infrastructure.md](docs/plans/PLAN-qcow2-write-infrastructure.md).

- **bench `-w` on qcow2 grows the refcount structures
  (PLAN-bench-refcount-growth phases 1-4).** Setup now computes the
  schedule's worst-case allocation bound and grows the refcount
  structures once, preemptively, before the timing bracket opens: new
  refblocks are placed at the end of the host file, and a refcount
  table that is out of slots is relocated there, enlarged, and
  committed with an fsync-ordered header flip. The old table is freed
  through the normal refcounts-last write-back cadence, so a crash in
  the window leaves at worst a repairable leak — the same benign
  artifact class as any mid-bench crash. The `bench: image too large
  for in-place bench write` refusal survives only for schedules that
  exceed the staging budget (more than 2048 refblock slots, more than
  2 MiB of staged refblock bytes, or a grown refcount table over
  64 KiB): roughly 256 MiB of host file at 512-byte clusters, and
  64 GiB or more at cluster sizes of 64 KiB and up. The differential
  fuzzer's `qcow2-write-refblock-coverage` steer-around and its
  `KNOWN_BENCH_DIVERGENCES` entry are retired (issues #397–#401),
  restoring the full cluster-size matrix to `-w` coverage. See
  [docs/plans/PLAN-bench-refcount-growth.md](docs/plans/PLAN-bench-refcount-growth.md).

- **CI test-partition guard.** A new lightweight `test-partition`
  job (and `tools/ci/check-test-partition.{sh,py}`) asserts that
  every Python integration test is claimed by at least one
  pull-request job. It enumerates the suite with `stestr list` and
  reads the real job selectors from the Makefile and workflow (no
  duplicated copy), failing if any test would run in zero jobs —
  guarding against a module silently dropping out of CI if the
  exclude-based `integration-core` job were ever refactored, or a
  `test_convert` class falling through the qcow2/vhd split. The
  guard's own logic is unit-tested with stdlib `unittest`. See
  [docs/testing.md](docs/testing.md).

- **`instar check --repair` for QCOW2 (PLAN-check-repair phases
  1-11).** Wires the long-reserved `CheckConfig::FLAG_REPAIR` ABI
  bit to real in-place qcow2 repair, mirroring `qemu-img check -r
  leaks`/`-r all`: `instar check --repair[=leaks|all] FILENAME`
  (qcow2 only; the read-only `instar check` is unchanged and
  byte-identical). The safe `leaks` tier (bare `--repair` or
  `--repair=leaks`) frees clusters the integrity walk proved
  unreferenced — a single monotonic refcount write, crash-safe and
  lossless. The lossy `--repair=all` tier rebuilds refcounts in
  both directions (raise under-counts, lower over-counts, free
  zero-counts) and reconciles the refcount↔COPIED invariant under a
  crash-safe `corrupt`-bit write ordering (set `INCOMPAT_CORRUPT` →
  correct refcounts → reconcile COPIED → clear bit, each
  fsync-separated; an interrupted run leaves the bit set so the
  image refuses read-write open until re-repaired). Repair runs in
  the KVM guest, reusing the new `crates/check` planner crate and
  `crates/snapshot`'s refcount mutators. It refuses rather than
  guessing: snapshotted images are repaired by neither tier (left
  untouched), and the lossy `all` tier declines its rebuild —
  reporting `repair-incomplete` — on compressed, external-data, or
  already-`corrupt` images and on refcount-table exhaustion, while
  the safe leak reclamation still runs; structural overlaps get a
  safe partial repair. A repair run
  reports the per-class counts of what it fixed (`repaired-leaks` /
  `repaired-refcounts` / `repaired-corruptions`, carried from the
  guest over the `CheckResultMessage` protobuf) in both the human
  and JSON output; a read-only `check` omits them, so its schema is
  unchanged. `--repair` cannot be combined with `--chain`. Covered
  by `tests/test_check_repair.py`,
  the `fuzz_check_repair` coverage fuzzer, and the differential
  fuzzer's `op_repair` arm (instar vs `qemu-img check -r`). The safe
  tier is intentionally narrower than `qemu-img -r leaks` (it never
  lowers a referenced cluster's refcount; use `--repair=all` to
  match) — see `docs/quirks.md`. Promoted from convert-followups
  phase 2.
- **New `instar snapshot` subcommand (PLAN-snapshot phases 1-14).**
  Manages the internal snapshots of a qcow2 image, mirroring
  `qemu-img snapshot`'s four modes:
  `instar snapshot [-l | -c NAME | -a SNAPSHOT | -d SNAPSHOT]
  [-f FMT] [-q] [-U] [--output={human,json}] FILENAME` (a bare
  `snapshot FILE` defaults to list, like qemu-img). qcow2-only,
  matching qemu's format restriction. List mode streams one
  entry record per snapshot from the guest (no in-memory cap;
  names up to the 255-byte on-disk maximum list in full — the
  phase 10 cross-version baselines caught and fixed a
  pre-release 63-byte parser truncation, commit `c2e1cc6`) and
  renders byte-identically to `qemu-img snapshot -l`'s modern
  (≥9.0) layout — local-time DATE column, 4-digit-hour
  VM_CLOCK, `--` for absent icount — or as a QMP-keyed JSON
  array (instar extension). The mutating modes run entirely in
  the KVM sandbox via `write_input_sector` with `fsync_input`
  barriers between write groups and a single commit point each:
  create copies the active L1, increments refcounts, clears
  COPIED flags, and reallocates the snapshot table; delete
  matches by name only (qemu 10.x's `bdrv_snapshot_find`),
  compacts the table, decrements, and refreshes COPIED flags;
  apply matches ID-then-name in two full passes
  (`find_snapshot_by_id_or_name`) and rewrites the active L1
  in place. Post-op images are bit-for-bit identical to
  qemu-img's given identical inputs under `file.discard=ignore`
  (instar never writes freed clusters). v1 gates: 16-snapshot
  cap, `refcount_bits=16` only, no refcount-structure growth,
  compressed / encrypted / external-data / bitmap / dirty
  images refused for mutation, apply-after-resize refused with
  a workaround message; names >255 bytes refused loudly where
  qemu silently truncates. Verified by seven shell harnesses
  (241 assertions, `make snapshot-harnesses`, wired into the
  functional-tests workflow), 94 integration tests in
  `tests/test_snapshot.py` with JSON goldens, cross-version
  `snapshot-list-human` baselines for 80 qemu-img versions
  (6.0.0-10.2.0), two coverage-guided fuzz targets
  (`fuzz_snapshot_parse`, `fuzz_snapshot_refcount`) in the
  nightly rotation, and the differential fuzzer's `op_snapshot`
  chain (byte-identity after every chain element). The
  `CallTable::VERSION` bumped from 16 to 17 for
  `send_snapshot_entry` / `send_snapshot_result` /
  `fsync_input`; the new `src/crates/snapshot/` planner crate
  carries the two-pass refcount mutators, COPIED-flag walker,
  allocator, and table serialisation helpers. Closes the
  convert-followups subcommand roster. See
  [docs/snapshot.md](docs/snapshot.md) for the full reference
  and `docs/quirks.md` for the documented divergences.

- **New `instar amend` subcommand (PLAN-amend phases 1-9).** Changes a
  qcow2 image's compatibility version (`compat=0.10`/`1.1`, i.e. qcow2
  v2⇔v3) and/or the `lazy_refcounts` flag in place by rewriting only the
  header cluster — the sandboxed equivalent of `qemu-img amend`.
  qcow2-only. v1 refuses a v3→v2 downgrade when the image carries a
  v3-only incompatible feature (compression type, extended L2, external
  data, dirty, corrupt) or uses `refcount_bits != 16`, and refuses
  `lazy_refcounts=on` against a v2 image. Covered by Rust round-trip unit
  tests, Python integration tests with post-op `info`/`check`/`compare`
  cross-validation against `qemu-img amend`, cross-version `qemu-img info`
  baselines (6.0.0–10.2.0), and coverage + differential fuzzing. See
  [docs/amend.md](docs/amend.md).

- **New `instar dd` subcommand (PLAN-dd phases 1-10).** Windowed block
  copy compatible with `qemu-img dd`:
  `instar dd [-f FMT] [-O OUTPUT_FMT] if=INPUT of=OUTPUT [bs=N]
  [count=N] [skip=N]`. Both `if=`/`of=` mandatory; all other
  arguments are `name=value` operands matching qemu-img's interface.
  `-O` defaults to **raw** (not the input format). Window semantics:
  `bs` defaults to 512, accepts 1024-based suffixes, range
  `1..=INT_MAX` (`bs=0` rejected); `count` clamps the copy down
  only (`min(virtual_size, count*bs)`) — `count=0` produces an
  empty output; `skip` subtracts `skip*bs` bytes from the front of
  the input, skip-past-EOF ⇒ empty output with exit 0. Output is
  always dense (no zero-skipping, unlike convert). The `-f`
  input-format hint is accepted for qemu-img compatibility but
  ignored — the input format is always auto-detected, and a one-line
  stderr warning is emitted when `-f` is supplied. All five output
  formats are supported (raw, qcow2, vmdk, vpc/VHD, vhdx) and are
  byte- and size-identical to `qemu-img dd` across qemu-img
  6.0.0–10.2.0 (baselines in
  `instar-testdata/expected-outputs/dd-info-json/`). Known
  divergences: vhdx default block size (instar emits 32 MiB, qemu
  8 MiB for small images — data and virtual size still match);
  `count=0 -O vmdk` (qemu-img itself exits 1; instar exits 0 with
  an unreadable vmdk); `count=0 -O vhdx` (instar's empty vhdx is
  rejected by `qemu-img info`). Implemented host-side in `run_dd`
  reusing `convert.bin` via a windowed `ConvertConfig`; the new
  `crates/dd` crate provides the pure window-math helper. Covered
  by integration tests (`tests/test_dd.py`), cross-version baselines
  (`tests/test_dd_baselines.py`), coverage fuzzing, and differential
  fuzzing against `qemu-img dd`. See [docs/dd.md](docs/dd.md).

- **New `instar bitmap` subcommand (PLAN-bitmap phases 1-10).**
  Creates, deletes, clears, enables, disables, and merges a qcow2
  image's **persistent dirty bitmaps** in place — the sandboxed
  equivalent of `qemu-img bitmap`. The six repeatable actions
  (`--add`/`--remove`/`--clear`/`--enable`/`--disable`/`--merge
  SOURCE`, plus `-g` granularity and `--output {human,json}`) are
  applied in command-line order and the tool is silent on success.
  qcow2 v3-only. Validated against `qemu-img bitmap` by integration
  tests (`tests/test_bitmap.py`), cross-version baselines, and
  coverage + differential fuzzing. The `CallTable::VERSION` bumps
  from 18 to 19 for the appended `send_bitmap_result` callback (same
  append-at-end discipline as prior subcommands). Note that `instar
  resize` now refuses images that carry persistent dirty bitmaps
  (see *Changed*). See [docs/bitmap.md](docs/bitmap.md).

- **New `instar bench` subcommand (PLAN-bench phases 1-8).** Issues a
  scripted sequence of read or write requests against a disk image and
  reports how long they took — the sandboxed equivalent of `qemu-img
  bench`, except it measures instar's own end-to-end sandboxed I/O path
  (guest format layer → virtio-block → host I/O thread) rather than
  qemu's block layer over the page cache, so the two numbers are
  comparable to each other on an identical invocation but never in
  isolation (see [docs/bench.md](docs/bench.md) for the full reframing
  and caveats). Reads all five formats (raw, qcow2, vmdk, vpc, vhdx);
  write tests (`-w`) are supported on raw and qcow2 only, including
  qcow2 overlays with a backing chain, via a write-through-metadata
  design (data and L2/L1 first, refcounts staged and written back last)
  that leaves at worst a repairable leak on a mid-run crash. `--output
  json` emits a stable schema with precomputed rates for downstream
  perf-regression tracking; the human-readable path is byte-parity with
  `qemu-img bench`, with 11 documented divergences tracked in
  `KNOWN_BENCH_DIVERGENCES`. `CallTable::VERSION` bumps from 19 to 20
  for the appended `send_bench_start`/`send_bench_result` callbacks
  (same append-at-end discipline as bitmap's 18→19). Covered by
  `tests/test_bench.py` (62 tests), the `fuzz_bench_schedule` coverage
  fuzzer, and the differential fuzzer's `op_bench` arm. See
  [docs/bench.md](docs/bench.md).

- **`instar map` differential fuzzer extension (PLAN-map phase 8).**
  Adds `op_map` to `scripts/differential-fuzz.py`'s random
  operation chain. For each randomly-generated image (raw
  gated out), runs `instar map --output=json` and
  `qemu-img map --output=json` against independent copies
  and compares the resulting JSON arrays extent-by-extent on
  `{start, length, present, zero, data}`. Window-arg coverage
  (`--start-offset` / `--max-length`, 25%/25% probabilities,
  64-KiB-aligned) diversifies the filter path. A per-format
  `MAP_FIELD_SKIPS` catalogue handles documented divergences
  — `vpc` skips the `present` field (instar reports VHD
  unallocated BAT entries as `present=false` faithful to
  `0xFFFFFFFF`; qemu-img reports them as `present=true,
  zero=true` matching the ZeroAllocated convention also used
  for raw sparse runs). 200-iteration local smoke (seed=1):
  zero divergences after the field skip; pre-fix run surfaced
  14 of the same vpc-present divergence, confirming `op_map`
  is exercised. CI auto-discovery via the existing
  `differential-fuzz.yml` workflow — no workflow edit.
  Documented the VHD-unallocated-block convention in
  `docs/quirks.md` alongside the analogous raw-sparseness and
  vhdx-partial-present entries.
- **`instar map` coverage-guided fuzz harness (PLAN-map phase 7).**
  Adds `src/fuzz/fuzz_targets/fuzz_map_iter.rs`: a libFuzzer
  target that dispatches on a format prefix byte
  (qcow2/vmdk/vhd/vhdx) and drives each parser's `map_extents`
  walker through the existing `instar_fuzz` mock CallTable.
  Records emitted extents into a 1 M-cap Vec and asserts the
  partition invariant — every byte of `[0, virtual_size)` must
  be covered by exactly one extent, with no overlaps, no gaps,
  no zero-length records, and no `start+length` overflow. That
  stricter assertion catches off-by-one cluster-boundary bugs
  that `fuzz_measure_scan`'s summary check (`allocated_bytes
  <= virtual_size`) cannot see. raw is omitted (pure of
  virtual_size, no on-disk input surface). 60-second smoke run
  reaches ~4M iterations with libFuzzer reporting ongoing
  coverage growth and zero crashes. CI integration via
  `.github/workflows/coverage-fuzz.yml`'s auto-discovery — no
  workflow edit required.
- **`instar map` integration tests (PLAN-map phase 6).**
  Adds `tests/test_map.py` with five test classes:
  `TestMapSmoke` (wiring), `TestMapBaselineSource`
  (per-image factory cross-validating against the phase 5
  baselines), `TestMapWindowFilter` (in-test fixtures
  exercising `--start-offset` / `--max-length`),
  `TestMapErrorPaths` (host-side guards), and
  `TestMapDivergenceRegression` (assertNotEqual against
  baselines for entries in `KNOWN_MAP_DIVERGENCES` so a
  silent fix surfaces loudly). 95 active tests + 91
  documented skips; the skips track real divergences
  documented in `docs/quirks.md`. Surfaced two bugs during
  development: (1) JSON output was missing a trailing
  newline (renderer fixed; phase 4's "no trailing newline"
  doc note corrected — it was a `cat -A` misread); (2)
  host-side `--start-offset > file_size` check compared
  against the on-disk file size rather than the virtual
  size, causing spurious rejections for sparse qcow2
  sources (check removed; qemu-img's silent past-EOF
  behaviour preserved).
- **`instar map` cross-version baselines (PLAN-map phase 5).**
  Generates `map-human` and `map-json` baselines for all 80
  qemu-img versions (6.0.0 through 10.2.x) across every
  safe-tier source image in the `instar-testdata` repo
  (~6,240 baseline cells total). detect-profiles.py
  deduplicates into 1 `map-human` profile (output stable
  across the full range) and 3 `map-json` profiles (two
  transitions at 6.0.x→6.1.x — likely the `compressed`
  field addition — and 8.1.x→8.2.x). Phase 6's integration
  tests will diff `instar map`'s output against the
  version-keyed profile for whichever qemu-img is installed.
  See `instar-testdata` commits `4e56008d8` (generator
  extension), `8e0498ca3` + `315859c3d` (profile dedup),
  and `0f972d5b1` (raw baselines).
- **New `instar map` subcommand (PLAN-map phases 1-4).** Reports
  which byte ranges of a disk image are data, zero, or
  unallocated, and where they live in the file — the sandboxed
  equivalent of `qemu-img map`: `instar map [-f FMT]
  [--output={human,json}] [--start-offset=OFFSET]
  [--max-length=LEN] [--sector-size=N] FILENAME`. Per-format
  extent walkers (`<Format>State::map_extents`) on every parser
  crate (`raw`, `qcow2`, `vmdk`, `vhd`, `vhdx`) emit coalesced
  `MapExtent` records, which the new `operations/map/map.bin`
  guest binary streams one at a time through the call table's new
  `send_map_extent` function pointer (a new streaming-emit shape —
  every other operation sends exactly one result message),
  followed by a `MapResult` summary; `CallTable::VERSION` bumps
  from 15 to 16 for the two new function pointers. The host
  renders each extent as it arrives via a streaming
  `MapRenderer<'a, W: Write>`, keeping host memory O(1) for
  pathologically fragmented sources; human and JSON output match
  `qemu-img map` byte-for-byte modulo the documented divergences
  in `docs/quirks.md` (raw `SEEK_HOLE` sparseness not detected,
  qcow2 compressed clusters emitted as `compressed: false`, VHDX
  partially-present blocks reported as fully data, VHD unallocated
  BAT entries as `present: false`, etc.). Window filtering
  (`--start-offset` / `--max-length`) matches qemu-img, including
  silently empty output for a window past the end of the image.
  Sources with chain composition are refused (single-image v1 —
  backing-chain walking is deferred, so the JSON `depth` field is
  always 0), as are `--image-opts` and descriptor-based VMDK
  layouts. BrokenPipe on stdout (user piped into `head` / `less`)
  short-circuits cleanly with exit 0. `map.bin` builds at ~30 KiB,
  well inside the 768 KiB operation region.
- **New `instar rebase` subcommand.** Changes the backing-file
  pointer recorded in a qcow2 or vmdk overlay and, in safe mode,
  copies divergent clusters from the old backing chain into the
  overlay so reads stay coherent:
  `instar rebase [-f FMT] [-u] -b BACKING [-F FMT] [-q]
  [--output FORMAT] FILENAME`. Both modes run the new
  `rebase.bin` guest in the KVM sandbox; the host opens the
  overlay as the output device (RW), the old backing chain as
  input slots [0..N), and (in safe mode) the new backing chain
  as input slots [N..M). Unsafe mode (`-u`) rewrites only the
  header's backing-file pointer; safe mode (default) also walks
  both chains and copies clusters whose content differs into the
  overlay before rewriting the pointer. Detach is encoded as
  `-b ""` (any mode). Per-format support: qcow2 v2/v3 with
  refcount_bits=16 in both modes; vmdk monolithicSparse unsafe-
  mode only (safe-mode vmdk is a planner gap). Format
  auto-detection from the overlay's magic bytes when `-f` is
  omitted. Output: `Image rebased.` / `Image detached.` literals
  (matches qemu byte-for-byte) or `--output=json` for a
  structured envelope (overlay, overlay_format, mode,
  clusters_copied, bytes_copied, new_backing or detached). `-q`
  suppresses both on success. Known divergences: long-path
  relocation is refused (qemu silently relocates), vmdk rebase
  is instar-only (qemu rejects all vmdk rebase), cross-cluster-
  size rebase is refused, external-data-file qcow2 overlays
  are refused. For qcow2, the post-rebase `qemu-img info
  --output=json` matches qemu-img rebase byte-for-byte across
  qemu-img 6.0.0 through 10.2.0 modulo the
  `KNOWN_REBASE_DIVERGENCES` whitelist. See
  [docs/rebase.md](docs/rebase.md) for the full reference.
  ([phase 1](docs/plans/PLAN-rebase-commit-phase-01-abi.md) ·
  [phase 2](docs/plans/PLAN-rebase-commit-phase-02-rebase-planners.md) ·
  [phase 3](docs/plans/PLAN-rebase-commit-phase-03-rebase-guest.md) ·
  [phase 4](docs/plans/PLAN-rebase-commit-phase-04-rebase-host.md) ·
  [phase 5](docs/plans/PLAN-rebase-commit-phase-05-rebase-tests.md) ·
  [phase 10](docs/plans/PLAN-rebase-commit-phase-10-fuzz.md) ·
  [phase 11](docs/plans/PLAN-rebase-commit-phase-11-diff-fuzz.md) ·
  [phase 12](docs/plans/PLAN-rebase-commit-phase-12-docs.md))

- **New `instar commit` subcommand.** Merges every allocated
  cluster from a qcow2 or vmdk overlay into its backing image,
  then zeroes the overlay's metadata so the overlay reads as
  empty against the (now-updated) backing:
  `instar commit [-f FMT] [-b BASE] [-q] [--output FORMAT]
  FILENAME`. Runs the new `commit.bin` guest in the KVM
  sandbox. The host opens the backing as the output device (RW)
  and the overlay as input slot 0 (RW, so the guest's
  overlay-clear pass can write through the new
  `write_input_sector(0, ...)` call-table primitive); the
  backing's own ancestor chain occupies input slots [1..N)
  read-only (v1 doesn't consult them but the slots are
  populated for forward compatibility). `-b` is optional —
  when omitted, the host resolves the overlay's recorded
  immediate parent; when supplied, the host refuses any base
  that doesn't match the recorded parent (intermediate-image
  commit is deferred). Atomicity contract: cluster data into
  the backing first, then backing metadata, then a batched
  overlay-clear pass; a crash between any two stages leaves
  both files internally consistent (the post-crash overlay +
  backing pair reads as the post-commit state). Per-format
  support: qcow2 v2/v3 with refcount_bits=16 in both implicit
  and explicit `-b`; vmdk monolithicSparse with explicit `-b`
  only (implicit `-b` is blocked by an info-side gap — see
  Known Divergences). Output: `Image committed.` literal
  (matches qemu byte-for-byte) or `--output=json` for a
  structured envelope (overlay, overlay_format, backing,
  backing_format, clusters_committed, bytes_committed,
  overlay_clusters_cleared). `-q` suppresses both on success.
  Known divergences: `-d` / `-p` / `-r` / `-t` are not
  implemented; intermediate-image commit refused;
  cluster-size mismatch between overlay and backing refused;
  cross-format commit refused; `cluster_size > 64 KiB`
  overflows the guest scratch budget and returns
  `ERROR_SCRATCH_TOO_SMALL`; vmdk implicit `-b` blocked by an
  info-side gap (the host info operation doesn't currently
  expose vmdk monolithicSparse's `parentFileNameHint` via
  `backing_file`, tracked separately under PLAN-info's vmdk
  follow-ups). For qcow2, the post-commit `qemu-img info
  --output=json` for both the overlay and the backing
  matches qemu-img commit byte-for-byte across qemu-img
  6.0.0 through 10.2.0 modulo the
  `KNOWN_COMMIT_DIVERGENCES` whitelist. See
  [docs/commit.md](docs/commit.md) for the full reference.
  ([phase 1](docs/plans/PLAN-rebase-commit-phase-01-abi.md) ·
  [phase 6](docs/plans/PLAN-rebase-commit-phase-06-commit-planners.md) ·
  [phase 7](docs/plans/PLAN-rebase-commit-phase-07-commit-guest.md) ·
  [phase 8](docs/plans/PLAN-rebase-commit-phase-08-commit-host.md) ·
  [phase 9](docs/plans/PLAN-rebase-commit-phase-09-commit-tests.md) ·
  [phase 10](docs/plans/PLAN-rebase-commit-phase-10-fuzz.md) ·
  [phase 11](docs/plans/PLAN-rebase-commit-phase-11-diff-fuzz.md) ·
  [phase 12](docs/plans/PLAN-rebase-commit-phase-12-docs.md))

- **Cross-version `qemu-img rebase` baselines** committed to
  `instar-testdata/expected-outputs/rebase-info-json/` for 80
  qemu-img versions (6.0.0 through 10.2.0). qcow2 only (qemu-img
  rebase rejects every other format on every shipped version);
  six cases per version covering unsafe-to-default-parent,
  unsafe-to-larger-parent, unsafe-detach, safe-to-default-parent,
  and safe-detach across 1M and 64M overlay sizes. The matrix
  is consumed by `tests/test_rebase.py:TestRebaseBaselineMatrix`
  (one test method per `(target, case)` pair, drift audit) and
  the corresponding round-trip class
  `TestRebaseRoundTrip`.

- **Cross-version `qemu-img commit` baselines** committed to
  `instar-testdata/expected-outputs/commit-overlay-info-json/`
  and `commit-backing-info-json/` for 80 qemu-img versions.
  Both buckets are populated because a commit's observable
  state lives on both sides — overlay's L2/refcount entries
  zeroed, backing's allocated clusters grown. Six qcow2 cases
  + two vmdk cases per version, with explicit `-b` for vmdk
  (the implicit-`-b` info-side gap blocks the implicit form
  for vmdk). Optional `qemu-io` seed at offset 0 exercises
  real data merges in seeded cases. Consumed by
  `tests/test_commit.py:TestCommitBaselineMatrix` and
  `TestCommitRoundTrip`.

- **Coverage-guided fuzzing for the rebase + commit planners.**
  Two new `cargo fuzz` targets at
  `src/fuzz/fuzz_targets/`:
  `fuzz_rebase_planners` exercises `plan_rebase_qcow2` and
  `plan_rebase_vmdk` across both `RebaseMode::Unsafe` and
  `RebaseMode::Safe`, asserting plan-level invariants
  (`patches.len() <= MAX_REBASE_PATCHES`, no integer overflow
  in `byte_offset + len`, every Write/Append's range within
  `total_file_size`, no overlapping `Write` patches) plus
  safe-mode context invariants (dirty-bitmap length relation,
  refblocks/grain-tables length relation,
  entries_per_refblock arithmetic). `fuzz_commit_planners`
  asserts the same shape for `plan_commit_qcow2` /
  `plan_commit_vmdk` contexts. Both targets land in the
  nightly + on-demand CI workflow via
  `.github/workflows/coverage-fuzz.yml`'s `TARGETS` array.
  Bringing up `fuzz_rebase_planners` surfaced one real
  planner bug (`plan_vmdk_unsafe` was constructing
  `RebasePlan::new(0)` instead of
  `RebasePlan::new(opts.overlay_file_size)`); fix shipped as
  the preceding commit before the harness landed.

- **Differential fuzzing arms for rebase + commit.** Two new
  operation hooks (`op_rebase`, `op_commit`) in
  `scripts/differential-fuzz.py`. Both build byte-identical
  fixtures via `qemu-img create`, run the respective
  subcommand on each side, then compare the resulting
  `qemu-img info --output=json` via the existing
  `_normalise_create_info` helper. Commit additionally
  compares the backing's info JSON (a commit's observable
  state lives on both sides) and runs each side in a
  per-pair subdirectory so explicit `-b base.<ext>`
  resolves against the chain entry's canonicalised
  basename. Picker constraints documented inline avoid
  the documented gaps (vmdk explicit-`-b` info-side
  blocker; qcow2 commit `cluster_size > 64 KiB` scratch
  budget; rebase long-path relocation). 100-iteration
  local runs with seeds 42 and 7777 report 0 divergences.

- **New `instar resize` subcommand.** Changes the virtual size of
  an existing disk image in place:
  `instar resize [-f FMT] [--shrink] [--preallocation MODE] [-q]
  [--output FORMAT] FILENAME [+-]SIZE[bkKMGTPE]`. Raw resize is
  host-only (open `O_RDWR` + ftruncate + optional preallocation
  post-pass); qcow2 / vmdk / vpc (VHD) / vhdx run the new
  `resize.bin` guest in the KVM sandbox, which reads the existing
  header, plans the metadata mutation, and applies patches via
  virtio-block. The `[+-]SIZE` end-spec grammar matches qemu-img
  exactly: bare `64M` is absolute, `+1G` is additive,
  `-512M` is subtractive (and requires `--shrink`).
  Per-format support: qcow2 grow + shrink (`--shrink` required for
  shrink), vmdk monolithicSparse grow only, vhd dynamic + fixed
  grow only, vhdx dynamic grow only, raw grow + shrink. Format
  auto-detection from the file's magic bytes when `-f` is omitted.
  Preallocation modes for grow (`--preallocation` or
  `-o preallocation=...`): `off` (any format, default),
  `falloc` / `full` (raw + qcow2 — host applies `posix_fallocate`
  or `fallocate(FALLOC_FL_ZERO_RANGE)` over the newly-added file
  region, with a `pwrite` zero-fill fallback for filesystems that
  reject `FALLOC_FL_ZERO_RANGE`). The host-side post-pass
  deliberately preallocates only the appended file region rather
  than the entire data region of the new virtual size; full
  data-region parity with qemu is queued under Future work. Shrink
  combined with `--preallocation=falloc|full` is rejected outright
  with a clear message (qemu silently accepts and discards the
  flag); `--preallocation=metadata` on raw is rejected (qemu
  accepts-but-no-ops). For vmdk / vpc / vhdx — formats `qemu-img
  resize` rejects with "Image format driver does not support
  resize" on every shipped version — instar resize works
  end-to-end, with coverage from the internal consistency suite
  (`TestResizeConsistency`) rather than a cross-tool diff.
  Output: `Image resized.` literal (matches qemu byte-for-byte)
  or `--output=json` for a structured envelope (filename, format,
  action ∈ {grow,shrink,noop}, old/new virtual size, new file
  size). `-q` suppresses both on success.
  See [docs/resize.md](docs/resize.md) for the full reference.
  ([phase 1](docs/plans/PLAN-resize-phase-01-skeleton.md) ·
  [phase 2](docs/plans/PLAN-resize-phase-02-qcow2-grow.md) ·
  [phase 3](docs/plans/PLAN-resize-phase-03-qcow2-shrink.md) ·
  [phase 4](docs/plans/PLAN-resize-phase-04-vhd.md) ·
  [phase 5](docs/plans/PLAN-resize-phase-05-vhdx.md) ·
  [phase 6](docs/plans/PLAN-resize-phase-06-vmdk.md) ·
  [phase 7](docs/plans/PLAN-resize-phase-07-guest-op.md) ·
  [phase 8](docs/plans/PLAN-resize-phase-08-host-cli.md) ·
  [phase 9](docs/plans/PLAN-resize-phase-09-preallocation.md) ·
  [phase 10](docs/plans/PLAN-resize-phase-10-baselines.md) ·
  [phase 11](docs/plans/PLAN-resize-phase-11-integration-tests.md) ·
  [phase 12](docs/plans/PLAN-resize-phase-12-fuzz.md) ·
  [phase 13](docs/plans/PLAN-resize-phase-13-docs.md))

- **Supporting library and crate-level pieces for resize.** New
  `crates/resize/` (no_std, pure-function per-format planners:
  `plan_resize_raw`, `plan_resize_qcow2`, `plan_resize_vmdk`,
  `plan_resize_vhd`, `plan_resize_vhdx`) with a structured
  `ResizePlan` carrying up to 128 `ResizePatch` entries
  (`Write` / `Append` / `ZeroFill`). New `ResizeConfig` /
  `ResizeResult` structs in `shared`, a new
  `ResizeResultMessage` protobuf field, two new CallTable
  function pointers (`read_output_sector` for in-place reads
  from the output device — reusable by future operations like
  rebase / commit; `send_resize_result` for the result envelope).
  ([phase 1](docs/plans/PLAN-resize-phase-01-skeleton.md) ·
  [phase 7](docs/plans/PLAN-resize-phase-07-guest-op.md))

- **Cross-version `qemu-img resize` baselines** committed to
  `instar-testdata/expected-outputs/resize-info-json/` for 80
  qemu-img versions (6.0.0 through 10.2.0). 41 cases per
  version (qcow2: 19, vmdk: 3, vhd: 6, vhdx: 5, raw: 8) capture
  `qemu-img create` → `qemu-img resize` → `qemu-img info` as the
  comparable artefact; the 16 vmdk/vhd/vhdx cases per version
  record qemu's "Image format driver does not support resize"
  rejection verbatim, documenting the cross-tool coverage gap
  and acting as a tripwire if qemu ever lifts the restriction.
  `instar-testdata`'s `scripts/generate-baselines.py` learns a
  new `resize` command + `resize-info-json` output type plus an
  on-demand `baselines-resize` Makefile target.
  ([phase 10](docs/plans/PLAN-resize-phase-10-baselines.md))

- **Integration test matrix for `instar resize`.** New
  `tests/test_resize.py` (~900 lines, 114 tests) covering six
  surfaces: (1) `TestResizeBaselineMatrix` — per-`(target, case)`
  diff of `instar create` → `instar resize` → `qemu-img info`
  against the phase-10 baseline (22 active for qcow2 + raw, 16
  skipped where qemu rejects, with `KNOWN_RESIZE_DIVERGENCES`
  documenting the rest); (2) schema-drift tripwire confirming
  the in-test case mirror matches the testdata generator's
  output; (3) `TestResizeCrossValidation` — 7 curated cases
  comparing instar end-to-end against the live qemu-img via
  `instar info` on both outputs; (4) `TestResizeRoundTripCheck`
  — `instar create → resize → check` across the full matrix
  catching reader/writer self-disagreement; (5)
  `TestResizeConsistency` — the 14 vmdk/vhd/vhdx cases qemu
  can't resize, verified via `instar info` virtual-size match
  + `instar check`; (6) `TestResizeErrorPaths` — 9 fixed tests
  pinning the host-CLI rejection contracts (shrink-without-flag,
  invalid size strings, metadata-on-raw, falloc-with-shrink,
  `--object` / `--image-opts`). The first matrix run surfaced
  two latent regressions (non-raw resize device routing,
  subtractive size CLI parsing) which were fixed in the same
  branch — exactly what an integration suite exists to catch.
  ([phase 11](docs/plans/PLAN-resize-phase-11-integration-tests.md))

- **Fuzz coverage for `instar resize`.** New
  `src/fuzz/fuzz_targets/fuzz_resize_planners.rs` coverage-guided
  libFuzzer target that exercises every public planner in
  `crates/resize/` with a structured 32-byte header decoded into
  per-format opts plus synthetic existing-state byte slices.
  Asserts plan-level invariants (patch count ≤ 128, no
  `offset + len` overflow, every patch ends within
  `total_file_size`, no overlapping Writes). Inputs are clamped
  to a realistic 40-bit (1 TiB) envelope with an 8 MiB file-size
  floor so the harness focuses on plausible host inputs rather
  than wide-open u64 ranges. The differential harness adds an
  `op_resize` operation that creates the same image twice
  (instar + system qemu-img), runs the matching resize on each,
  and compares via `qemu-img info` JSON. Picker restricted to
  qcow2 + raw and biased away from documented planner gaps
  (cluster_size=2 MiB scratch overflow, extended_l2 + non-Off
  preallocation, qcow2 metadata preallocation). Both harnesses
  picked up by the existing fuzz CI workflows; coverage-fuzz
  bumped from 16 to 17 default targets. New `make fuzz-build`
  / `fuzz-run` Makefile targets wrap the devcontainer
  invocations.
  ([phase 12](docs/plans/PLAN-resize-phase-12-fuzz.md))

- **Lifted the qcow2 grow image-size ceiling.** The original
  resize guest pre-pass staged every non-zero refcount block
  referenced by the existing image's refcount table — bounded
  by the 4 MiB EXISTING_STATE region, this imposed a
  per-cluster-size image-size ceiling (~128 GiB at the default
  64 KiB cluster). Followup-01 introduces a new public
  `compute_qcow2_grow_query` planner helper that identifies the
  *exact* refcount blocks each grow flavour (HeaderOnly /
  L1Grow / L1AndRefcountGrow) will demand via
  `ensure_block_staged`, bounded by `QCOW2_MAX_REQUIRED_BLOCKS
  = 16` regardless of image size. The guest pre-pass calls it
  before reading any refcount-block bytes and stages exactly
  the returned set. The qcow2 grow ceiling is now bounded only
  by what the filesystem can hold; tested through 1 TiB → 2 TiB
  in 163 ms. Shrink retains the older stage-all pre-pass and
  its per-cluster-size ceiling; lifting that is queued as a
  separate follow-up. New `tests/test_resize.py:TestResizeLarge
  Images` exercises 256 GiB / 500 GiB / 1 TiB / 2 TiB grows
  end-to-end through the VMM; new `qcow2_grow_large.rs`
  integration test exercises the planner directly with the
  targeted stage list. Fuzz size clamp for qcow2 in
  `fuzz_resize_planners` lifted from 40 to 48 bits (1 TiB to
  256 TiB); differential picker adds 256M and 1G qcow2 sizes.
  Drive-by fix: a vmdk planner-input overflow surfaced by the
  larger coverage smoke
  (`header_capacity_sectors * SECTOR` near u64::MAX) is now
  guarded by `checked_mul`.
  ([followup-01](docs/plans/PLAN-resize-followup-01-targeted-prepass.md))

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
  and external data files (`data_file*`) return clear "deferred"
  errors with phase pointers. Preallocation modes supported
  (phase 6): `off` (any format, default), `metadata` (qcow2
  only — guest populates L1/L2/refcount for the full virtual
  range and frames the data region), `falloc` (raw or qcow2 —
  host applies `posix_fallocate` over the data region on top
  of metadata mode), `full` (raw or qcow2 — host fills the
  data region with zeros via `fallocate(FALLOC_FL_ZERO_RANGE)`
  with a `pwrite` fallback). Non-qcow2 sparse formats
  (vmdk / vpc / vhdx) reject non-`off` preallocation with a
  "future work" pointer. Output rendering:
  human one-liner (default), `--output=json`, or `-q` quiet.
  Backing-file polish (phase 5): backing virtual_size is now
  recovered correctly for vhdx parents via
  `vhdx::VhdxState::init`'s metadata-region walk (previously
  returned BACKING_PARSE_FAILED with a phase-5 pointer);
  vmdk-from-vmdk chains now embed the real parent CID in the
  child's descriptor `parentCID=` line (previously a fixed
  `deadbeef` sentinel). Two new error codes —
  `ERROR_BACKING_FORMAT_UNSUPPORTED` and
  `ERROR_BACKING_SIZE_TOO_LARGE` — surface clearer messages
  for the corner cases; the latter fires a pre-flight ceiling
  check that suggests "try a larger cluster size" when a
  backing-derived virtual_size exceeds the target's
  addressable range.
  ([phase 1](docs/plans/PLAN-create-phase-01-emitters.md) ·
  [phase 2](docs/plans/PLAN-create-phase-02-guest-op.md) ·
  [phase 3](docs/plans/PLAN-create-phase-03-host-cli.md) ·
  [phase 4](docs/plans/PLAN-create-phase-04-target-options.md) ·
  [phase 5](docs/plans/PLAN-create-phase-05-backing-file.md) ·
  [phase 6](docs/plans/PLAN-create-phase-06-preallocation.md) ·
  [phase 7](docs/plans/PLAN-create-phase-07-baselines.md) ·
  [phase 8](docs/plans/PLAN-create-phase-08-integration-tests.md) ·
  [phase 9](docs/plans/PLAN-create-phase-09-fuzz-coverage.md) ·
  [phase 10](docs/plans/PLAN-create-phase-10-fuzz-differential.md))
  Preallocation for vmdk / vpc / vhdx (each format needs its
  own BAT-population pattern plus a host post-pass — analogous
  to qcow2 metadata mode), multi-file VMDK subformats
  (`monolithicFlat`, `twoGbMaxExtent*`), differencing VHD /
  VHDX as the *output* target, and `--sector-size > 512`
  remain deferred to future work (see PLAN-create.md's
  Future-work section).

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

- **Cross-version `qemu-img create` baselines** committed to
  `instar-testdata/expected-outputs/create-info-json/` for 80
  qemu-img versions (6.0.0 through 10.2.0). For each `(target,
  options, size)` case in a 36-entry per-version matrix the
  generator runs `qemu-img create` followed by `qemu-img info
  --output=json` and records the info JSON as the comparable
  artefact. Consumed by phase 8's integration tests, which
  compare instar's info JSON output against the version-matched
  qemu baseline modulo a documented divergence whitelist
  (filename, actual-size, vmdk cid + parent-cid, vhdx
  header-id). `instar-testdata`'s `scripts/generate-baselines.py`
  and `scripts/detect-profiles.py` learn a new `create` command
  + `create-info-json` output type.
  ([phase 7](docs/plans/PLAN-create-phase-07-baselines.md))

- **Differential fuzzer exercises `instar create`.**
  `scripts/differential-fuzz.py` adds `'create'` to its
  random operation list. Each picked iteration creates the
  same image via `instar create` and the system
  `qemu-img create` into separate tmp paths, reads both
  back via `qemu-img info --output=json`, and asserts
  normalised dict equality through the same divergence
  whitelist phase 8b's integration tests use (inlined into
  the fuzzer with a "keep in sync" comment). The random
  `(target, options, size)` picker is biased away from
  phase 8b's documented writer-divergence list so a finding
  surfaced by this surface is a real bug rather than a
  known limitation. Picked up by the existing
  differential-fuzz workflow without configuration changes.
  ([phase 10](docs/plans/PLAN-create-phase-10-fuzz-differential.md))

- **Coverage-guided fuzz target for `instar create` emitters**
  (`src/fuzz/fuzz_targets/fuzz_create_emitters.rs`). Decodes
  structured fuzz input into per-format option tuples and
  dispatches to every public planner in `crates/create/`
  (`plan_qcow2`, `plan_vmdk`, `plan_vhd`, `plan_vhdx`).
  Asserts plan-level bookkeeping invariants (write totals
  match, every write fits in `minimum_file_size`, no
  arithmetic overflow, write count within bound) plus a
  header re-parse round-trip via the matching parser crate
  (`qcow2::QcowHeader`, `vmdk::Vmdk4Header`,
  `vhd::VhdFooter`, `vhdx::VhdxHeader`). Picked up
  automatically by the nightly coverage-fuzz workflow
  (16 targets total now). Smoke run reaches ~700 coverage
  edges in 60 seconds with no crashes. Adding the
  dependency surfaced a latent gap in the fuzz crate's
  mock CallTable: the `send_create_result` field that phase
  2 of create added to `shared::CallTable` was missing
  because no prior fuzz target had pulled in the create
  crate transitively. Filled in alongside the new harness.
  ([phase 9](docs/plans/PLAN-create-phase-09-fuzz-coverage.md))

- **Integration test matrix for `instar create`.** Three new
  test surfaces in `tests/test_create.py` (added on top of the
  pre-existing phase 3–6 smoke / `-o` / backing / preallocation
  coverage): (1) `TestCreateBaselineMatrix` — per-`(target,
  case)` baseline comparison against phase 7's recorded
  `qemu-img info` JSON via `instar create` + system
  `qemu-img info`, normalised by a divergence-whitelist filter
  in `tests/helpers/info_json.py`; (2)
  `TestCreateCrossValidation` — 12 curated cases that build the
  same image twice (instar + system qemu-img) and compare both
  via `instar info`; (3) `TestCreateRoundTripCheck` —
  full-matrix `instar create` + `instar check` self-consistency
  pass. Known instar/qemu writer divergences (qcow2
  refcount_bits hardcode, qcow2 compat hardcode, zstd accept-
  ignore, vhdx default block_size, vhd CHS-rounded virtual_size)
  are documented in a `KNOWN_WRITER_DIVERGENCES` skip set with
  per-entry rationale; a separate `KNOWN_CHECK_FAILURES` set
  tracks writer/reader self-disagreements (currently only
  qcow2 refcount_bits=64). Phase 8 also reads the per-target
  raw baseline bucket directly rather than going through
  `get_expected_output()`, sidestepping a latent
  `detect-profiles.py` flat-copy collision bug in phase 7
  whereby case names like `1M-default` clobber each other in
  `profiles/profile-NN/` across the five target formats.
  ([phase 8](docs/plans/PLAN-create-phase-08-integration-tests.md))

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

- **`instar bench -w`'s qcow2 path migrated onto `crates/qcow2-write`,
  and its refcount-growth planner moved into that crate
  (PLAN-qcow2-write-infrastructure phase 6).** bench `-w` on qcow2 now
  plans its allocate-on-write schedule with the shared planner
  (`crates/qcow2-write`) and executes it through
  `crates/qcow2-write-exec`, the third consumer after commit (phase 4)
  and rebase (phase 5); the read path, raw `-w`, and the vmdk/vhd/vhdx
  read support are untouched. The pure refcount-growth planner
  (`plan_refcount_growth`, `GrowthCaps`, `RefcountGrowthPlan`,
  `GrowthOverflow`, with 12 unit tests) moved from `crates/bench` into
  a new `growth` module of `crates/qcow2-write`, so it is available to
  future write consumers; growth execution stays bench-side but now
  routes its I/O through the shared executor's byte-range layer.
  Unlike commit and rebase, this migration deliberately relaxes byte
  identity for allocating schedules: bench's oracle is `qemu-img
  compare` + `qemu-img check`, and the shared planner allocates the L2
  table before the data cluster (the reverse of pre-migration bench),
  so allocating outputs are content-equivalent and check-clean but not
  byte-identical; overwrite-only schedules stay byte-identical. The
  `scripts/migration-proof.py` harness (extended with `--op bench`)
  proved this over a 56-combo matrix — 2 controls and 17
  overwrite-only combos byte-identical, 34 allocating combos
  compare/check/info/`flushes-issued`/RT-geometry equivalent, 3
  refusals rc/stderr-identical — with 0 byte-identity failures, 0
  determinism failures and 0 matrix failures, and a 300-iteration
  bench differential-fuzz run reported 0 divergences. One new
  `BenchResult` code 9 (`ERROR_IMAGE_INCONSISTENT`, "bench: image
  metadata is inconsistent") carries the planner's classification
  refusals (unknown/reserved L1/L2 bit patterns, refcount
  inconsistencies, a v3 zero-flag on the target L2 entry) that had no
  existing bench rendering; existing codes are reused otherwise
  (allocation exhaustion keeps code 8, the contiguity gate keeps
  code 3). The fsync census is preserved exactly — the executor's
  flushes are disabled and bench issues its own single `fsync_input(0)`
  per `--flush-interval` cadence point, so `flushes-issued` is
  unchanged. See [docs/bench.md](docs/bench.md),
  [docs/quirks.md](docs/quirks.md) and the phase-6 findings in
  [docs/plans/PLAN-qcow2-write-infrastructure.md](docs/plans/PLAN-qcow2-write-infrastructure.md).

- **`instar rebase`'s safe-mode qcow2 path migrated onto
  `crates/qcow2-write` (PLAN-qcow2-write-infrastructure phase 5).**
  Safe-mode rebase (including safe detach) now plans its cluster
  copies with the shared planner (`crates/qcow2-write`) and executes
  them through `crates/qcow2-write-exec`, the second consumer after
  commit; the `-u` metadata-only path, unsafe detach and the vmdk
  path are untouched. The migration is byte-invisible: the
  `scripts/migration-proof.py` harness (extended with `--op rebase`)
  proved instar-before vs instar-after identity over a 69-combo
  fixture matrix — 0 identity failures, 0 determinism failures,
  byte-identical pre-refusal scaffolding on the 6 both-refuse
  shapes, and exactly 1 pre-declared divergence (beyond-EOV tail
  bytes of a copied cluster are now zeros where both old instar and
  qemu-img carry old-chain bytes; virtual content proven equal) —
  and a 300-iteration rebase differential-fuzz run reported 0
  divergences with baselines unchanged. Two silent-corruption shapes
  found by the phase's probes become typed refusals before harm:
  overlays with a sparse (holed) refcount table — stock-producible
  and check-clean, previously misallocated refcounts into the wrong
  refblocks — now refuse with new `RebaseResult` error 16
  (`ERROR_OVERLAY_INCONSISTENT`), and extended-L2 overlays —
  previously walked as 8-byte entries, silently corrupting virtual
  content — now refuse with new error 15
  (`ERROR_OVERLAY_UNSUPPORTED`), which also adds the spec-mandated
  refusal of zstd/unknown incompatible bits. Overlay staging
  capacity widens: the stage-everything L2 model and its growable
  arena are retired (the arena-clobber hazard class behind issue
  #422 is structurally gone), existing L2 tables are windowed with
  safe eviction, and refblocks stage at
  `min(2048, 3 MiB / cluster_size)`, so overlays that previously
  refused at staging time on populated-L2 count alone now rebase.
  `crates/rebase` slims by ~330 lines (the hand-rolled allocator and
  its state are deleted; the deferred header/backing-path patch
  machinery survives byte-identical). See
  [docs/rebase.md](docs/rebase.md), [docs/quirks.md](docs/quirks.md)
  and the phase-5 findings in
  [docs/plans/PLAN-qcow2-write-infrastructure.md](docs/plans/PLAN-qcow2-write-infrastructure.md).

- **`instar commit`'s qcow2 write path migrated onto
  `crates/qcow2-write` (PLAN-qcow2-write-infrastructure phase 4).**
  The commit op's inlined backing-side allocate-on-write composition
  is replaced by the shared planner (`crates/qcow2-write`) driven
  through the new `crates/qcow2-write-exec` guest step executor — a
  literal interpreter of the planner's step contracts (DeviceIo
  call-table mapping, a shared byte-range layer with sub-sector RMW
  replacing the per-op helpers, fill synthesis, and barrier policy
  with Durability degrading to Ordering on the fsync-less output
  device). The migration is byte-invisible: a new
  `scripts/migration-proof.py` harness proved instar-before vs
  instar-after byte identity over a 73-combo fixture matrix (0
  identity failures, 0 determinism failures, including byte-identical
  pre-refusal scaffolding on the refusal shapes), and a 300-iteration
  commit differential-fuzz run reported 0 divergences with baselines
  unchanged. Two silent-corruption shapes found by the phase's probes
  become typed refusals before harm: compressed backing clusters
  (previously overwritten in place, destroying every stream packed in
  the host cluster) now refuse with the existing unsupported-format
  error, and backings with a sparse (holed) refcount table —
  stock-producible via discard + `qemu-img resize --shrink`, and
  check-clean — now refuse with new `CommitResult` error 17
  (`ERROR_BACKING_INCONSISTENT`) instead of corrupting refcounts; new
  error 16 (`ERROR_BACKING_UNSUPPORTED`) adds the spec-mandated
  refusal of unknown/compression incompatible bits on the backing.
  Backing staging capacity widens (refblocks from a flat 32 to
  `min(2048, 3 MiB / cluster_size)`; the backing staged-L2 cap
  replaced by a windowed model), so strictly more images commit
  successfully; overlay-side caps are unchanged. Unaligned virtual
  sizes commit cleanly, including chained backings (the planner's new
  EOV-tail full-coverage rule). `crates/commit` slims by ~550 lines
  (the superseded allocator and dead plan machinery are deleted; all
  cross-image validation and the vmdk path are untouched). See
  [docs/commit.md](docs/commit.md), [docs/quirks.md](docs/quirks.md)
  and the phase-4 findings in
  [docs/plans/PLAN-qcow2-write-infrastructure.md](docs/plans/PLAN-qcow2-write-infrastructure.md).

- **Guest core and operation memory budgets doubled (2026-07-06,
  commit `3a5e1e2`).** Pre-emptive lift ahead of the bench work,
  prompted by `core.bin` reaching 94% of its 72 KiB budget: core's
  region grows from `[0x10000, 0x22000)` (72 KiB) to `[0x10000,
  0x30000)` (128 KiB), and the operation region from `[0x22000,
  0x80000)` (376 KiB) to `[0x30000, 0xF0000)` (768 KiB). The call
  table / operation config / chain config data pages move from
  `0x80000`-`0x84000` to `0xF0000`-`0xF4000`, gaining a new VMM-params
  page, followed by a new 48 KiB guard gap below the (unchanged)
  virtqueue region at `VQ_BASE_START` (`0x100000`). Nothing at or
  above `0x100000` moves. `VQ_BASE_START` also moved into `shared` as
  the single source of truth (previously duplicated in `vmm/main.rs`
  and `core/main.rs`), and four compile-time asserts now make the
  layout self-checking. See `src/shared/src/lib.rs`.

- **`instar resize` now refuses qcow2 images carrying persistent
  dirty bitmaps** rather than silently discarding them. Resizing
  rebuilds the header cluster, which would drop the qcow2 bitmaps
  extension and its bitmaps; instead the operation fails with:

  ```
  refusing to resize an image with persistent dirty bitmaps (would
  discard them); remove the bitmaps first with `instar bitmap
  --remove` or qemu-img
  ```

  preventing silent bitmap-data loss. Remove the bitmaps first (see
  the new `instar bitmap` subcommand under *Added*, or
  [docs/bitmap.md](docs/bitmap.md)).

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
