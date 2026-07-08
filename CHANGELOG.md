# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

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
- **`instar map` output polish (PLAN-map phase 4).** Replaces
  the phase 3 placeholder renderer with a streaming
  `MapRenderer<'a, W: Write>` that emits each extent to
  stdout as the guest sends it (via a `BufWriter` over
  `stdout().lock()`), bringing host memory back to O(1) for
  pathologically fragmented sources. Human and JSON output
  now match `qemu-img map` byte-for-byte, modulo eight
  documented divergences in `docs/quirks.md` (raw
  `SEEK_HOLE` not implemented, qcow2 compressed clusters
  emitted as `compressed: false`, VHDX partially-present
  reported as fully data, depth always 0 in v1, etc.).
  21 byte-exact unit tests pin the renderer against
  expected output sequences captured from `qemu-img 10.0.8`
  during plan research. BrokenPipe on stdout (user piped
  into `head` / `less`) short-circuits cleanly with exit 0.
- **`instar map` host CLI surface (PLAN-map phase 3).** The
  guest binary from phases 1-2 is now reachable end-to-end via
  `instar map [-f FMT] [--output={human,json}]
  [--start-offset=OFFSET] [--max-length=LEN] [--sector-size=N]
  FILENAME`. `run_map` validates args (refusing `--image-opts`,
  VMDK monolithicFlat sources, and `--start-offset >= file
  size` on the host), populates `MapConfig`, attaches the
  source read-only, runs the vCPU loop accumulating extent
  records, and routes the result through a placeholder
  human/JSON renderer (`format_map_human` / `format_map_json`)
  that produces *valid* output for both formats. The renderer
  is structural-only in phase 3; phase 4 of PLAN-map polishes
  to byte-for-byte qemu-img parity against the cross-version
  baseline matrix. 18 new unit tests pin the state-triple
  table, JSON field ordering, and error-message table so the
  phase 4 refactor preserves the contract.
- **`instar map` subcommand foundation (PLAN-map phases 1-2).**
  Per-format extent walkers (`<Format>State::map_extents`) on
  every parser crate (`raw`, `qcow2`, `vmdk`, `vhd`, `vhdx`)
  emit coalesced `MapExtent` records via a callback / coalescer
  pair in `shared`. The new `operations/map/map.bin` guest
  binary reads a `MapConfig`, detects the source format,
  refuses sources with chain composition (single-image v1),
  dispatches to the matching walker, and streams one
  `MapExtentRecord` per extent through the call table's new
  `send_map_extent` function pointer, followed by a `MapResult`
  summary through `send_map_result`. Window filtering
  (`start_offset` / `max_length`) is applied in the emit
  closure. Two new protobuf payloads (`MapExtentMessage` field
  15, `MapResultMessage` field 16) land in the `GuestMessage`
  oneof. The `CallTable::VERSION` bumps from 15 to 16 to add
  the two new streaming function pointers (the streaming-emit
  shape is new — every other operation sends exactly one
  result message). Backing-chain composition, walker-side
  window pruning, host CLI surface, output rendering,
  cross-version baselines, integration tests, and fuzz are
  follow-ups in PLAN-map phases 3-9. `map.bin` builds at
  ~28 KiB / 384 KiB.
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

### Fixed

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

### Changed

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
