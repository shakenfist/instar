# PLAN-bench phase 05: write tests

## Prompt

Before responding to questions or discussion points in this
document, explore the instar codebase thoroughly. Read relevant
source files, understand existing patterns (the commit guest op's
allocate-on-write composition, the snapshot crate's allocator and
refcount mutators, bitmap's RW-input staging idiom, the bench op
and host CLI as they stand after phase 4), and ground your
answers in what the code actually does today. The master plan's
**"Findings: allocating-write reuse for `-w` on qcow2 (OQ4, step
1d)"** section is the authoritative reuse map — read it in full;
every file:line reference below comes from it or from the
phase-3/4 surveys. Do not speculate when you could read instead;
flag uncertainty explicitly.

Phase plans live alongside the master plan
([PLAN-bench.md](PLAN-bench.md)) in `docs/plans/`. This is the
fifth of eight phases; phases 1-4 landed the schedule crate, the
ABI, the guest read op, and the host CLI (read benchmarks work
end-to-end on all five formats with header byte-parity).

I prefer one commit per logical change, and at minimum one commit
per phase. Each commit should be self-contained: it should build,
pass tests, and have a clear commit message explaining what
changed and why.

## Situation

This phase makes `-w` real for **raw and qcow2**:
`--pattern`/`--flush-interval`/`--no-drain` semantics, the
RW-input attach with `fsync_input` flush wiring (OQ5, resolved in
phase 2), allocating qcow2 writes per the OQ4 reuse verdict, and
refusals for vmdk/vhd/vhdx write tests. qemu's verified write
behaviour (master plan): ordinary format-layer writes filling the
buffer with the pattern byte — and because qemu's per-slot iovecs
are dead code (every in-flight request writes the same
`qiov[0]`), **qemu never writes request-distinguishable data
either**, so after identical `-w` runs the instar and qemu images
are byte-comparable. Phase 6 exploits that.

Grounding:

- **The reuse map (OQ4/1d, verified then):** the commit guest op
  (`src/operations/commit/src/main.rs:711-785`) is the working
  allocate-on-write template (allocate+zero L2 when the L1 slot
  is empty, allocate a data cluster when the L2 slot is empty,
  write data, set both `OFLAG_COPIED` flags), with metadata flush
  ordering at `:787-834`. The pure primitives live in
  `crates/snapshot` (`alloc_contiguous_clusters_in_refblocks` +
  `AllocCursor` `src/crates/snapshot/src/qcow2.rs:299-435`,
  refcount RMW accessors `:51/:152/:239`, COPIED rewriters
  `:450-532`) and `crates/commit` (L2/refcount disk-offset math
  `src/crates/commit/src/qcow2.rs:296-321`). bitmap
  (`src/operations/bitmap/src/main.rs`) is the RW-input-slot-0 +
  `fsync_input(0)` precedent. Commit's `write_output_byte_range`
  (`src/operations/commit/src/main.rs:175`) is the sub-sector RMW
  idiom (read covering sectors, patch, write back) — bench needs
  the *input-device* analog.
- **Net-new pieces the findings enumerated:** the per-offset
  driver; the overwrite-in-place fast path (allocated + COPIED ⇒
  data write only); staging the target's own refcount
  table/blocks (commit stages the backing's — directly analogous
  host pre-read plumbing); sub-cluster fill-then-patch for
  freshly allocated clusters; and the snapshot gate.
- **The write envelope** (union of the sister mutators, plus one):
  `refcount_bits == 16` only; no compression, no extended-L2, no
  external data file, no LUKS, not dirty/corrupt; **and `nb_snapshots
  > 0` refused** — commit blind-overwrites without a COPIED check
  because it assumes unique ownership; bench must not corrupt
  snapshot-shared clusters. Allocation never grows the refcount
  table (`RefcountExhausted` → clean refusal; one 16-bit refblock
  at 64 KiB clusters covers 2 GiB of address space, so this bites
  rarely and is a documented caveat).
- **Phase 3/4 state:** the guest op refuses `FLAG_WRITE` with
  `ERROR_BAD_CONFIG` (placeholder branch, commented); the host
  refuses `-w` in `validate_bench_args` (`bench: write tests (-w)
  are not yet supported`); the flush line renderer and
  `flushes-issued` JSON field are already wired;
  `flush_after_completion`/`total_flushes` sit unit-tested in
  `crates/bench`; the read path attaches the whole chain
  read-only. `fsync_input(u32)` (call-table slot, VERSION 17)
  fdatasyncs an RW input slot; the host stub returns false for
  RO slots.
- **The read dispatch stays available in write mode** —
  `read_chain_virtual_range`/`read_chain_virtual_cluster` over
  the same `ChainStates` — which is what makes backing-chain COW
  cheap (below).

## Mission

### 1. Semantics: what a bench write is

For each scheduled offset, write `bufsize` bytes of the pattern
byte at that virtual offset through the format layer, exactly as
a guest OS write would land:

- **raw**: patch `[offset, offset+bufsize)` in the flat file.
  With the 65536-byte transport sector, arbitrary offsets need
  sub-sector RMW: read the covering sectors, patch the window,
  write back (a `write_input_byte_range` helper mirroring
  commit's `write_output_byte_range`, targeting RW input slot 0).
- **qcow2**: per touched cluster (a request may straddle a
  cluster boundary — split at cluster granularity like the read
  path does):
  - *Overwrite fast path*: L2 entry allocated + `OFLAG_COPIED` ⇒
    patch the data cluster in place (sub-sector RMW against the
    host cluster offset). No metadata changes.
  - *Allocating path*: allocate a data cluster
    (`alloc_contiguous_clusters_in_refblocks` over the staged
    refblocks); **fill it with the cluster's current virtual
    content via the chain read** (`read_chain_virtual_cluster`
    at this device with the entry still unallocated — falls
    through to the backing chain, or yields zeros when there is
    none: one uniform rule that makes overlay COW correct *and*
    covers the zero-fill fresh-cluster case); patch the pattern
    window; write the full data cluster; update the L2 entry
    (host offset + COPIED); if the L1 slot had no L2 table,
    allocate + zero one first and update the L1 entry (+COPIED).
  - Writes through the backing chain never touch parent images:
    all allocation and data lands in the top image only; parents
    stay attached read-only.

### 2. Metadata write-back architecture (the crash-ordering decision)

**Decision: write-through L2/L1, staged refcounts, refcounts
last.**

- Data cluster writes go straight to the file (virtio RW input).
- L2 (and L1) updates are **written through** immediately after
  the data they point to — the update is a covering-sector RMW of
  the table cluster on disk. Ordering per update: data cluster
  first, then the L2 entry that makes it reachable, then (only
  when a new L2 was allocated) the L1 entry. No fsync between —
  matching qemu's promise level, which orders metadata through
  its cache without syncing mid-run.
- Refcount updates accumulate in **staged refblocks** (the
  bitmap/snapshot staging idiom, host-preloaded like commit
  pre-reads the backing's), written back at every flush point and
  once after the loop. Refcounts-last means a crash mid-bench
  leaves *leaked clusters* (allocated data reachable via L2 but
  under-refcounted → `qemu-img check` reports leaks, repairable),
  never a dangling L2 pointer — the same benign artifact class a
  qemu crash mid-bench produces.

Why not full staging of L2s: the request schedule can scatter
75000 requests across arbitrarily many L2 tables (large step over
a large image), so any staged-L2 budget is a refusal waiting to
happen; write-through has no cap and per-update ordering falls
out naturally. Why not write-through refcounts: they are the
high-frequency RMW target (every allocation), staging them is
bounded (`REFBLOCKS_LIMIT`-style, exactly how snapshot/bitmap
bound theirs), and deferring them is what makes the
crash-artifact benign. The 5b implementer must diff this order
against commit's proven `:787-834` sequence and justify any
deviation in the review.

**Flush points** (`flush_after_completion` says flush after
completion k): write back dirty staged refblocks, then
`fsync_input(0)`, count it in `flushes_issued`. `--no-drain` is
an accepted no-op (serial execution: the queue is always drained)
— still issue the flush. After the loop (interval 0 or not): a
final refblock write-back (no fsync unless the cadence issued
one at k == count) **before** `send_bench_result` — the result
closes the timing bracket, so end-of-run metadata write-back is
inside the measured window. This is a documented measurement
caveat: qemu amortises metadata through its cache during the
run; instar concentrates refcount write-back at flush points and
run end. The bracket placement contract itself is unchanged.

### 3. Gates and errors

Guest-side (qcow2 header is parsed there), checked before
`send_bench_start` — all pre-bracket, result-without-marker:

- The envelope: `refcount_bits != 16`, compression feature/any
  compressed cluster encountered (entry-level check during the
  run as well — hitting a compressed L2 entry in write mode is
  `ERROR_WRITE_UNSUPPORTED` mid-run), extended-L2, external data
  file, LUKS, dirty/corrupt incompatible bits, `nb_snapshots >
  0`. New `BenchResult` codes (appended, stable): 7
  `ERROR_WRITE_UNSUPPORTED` (`error_detail` = a small gate-id
  enum documented in shared), 8 `ERROR_ALLOC_EXHAUSTED`
  (`RefcountExhausted` — host renders "image too large for
  in-place bench write" per the findings).
- Host-side: `-w` with discovered format ∉ {raw, qcow2} →
  `bench: write tests are not yet supported for <fmt>`
  (divergence registry). The phase-4 `-w` refusal is removed;
  `validate_bench_args`'s cross-option rules (flush-requires-
  write, interval ≥ depth) now become reachable end-to-end.
- Host attach for `-w`: top image RW input slot 0, parents (if
  any) RO — a mixed-mode variant of the chain attach (commit
  already opens an RW input alongside other devices; mirror its
  open flags). Read tests keep the all-RO attach. `fsync_input`
  requires the RW slot, so the host stub's RO-slot `false` is
  the guard that the wiring is right.

### 4. What phase 5 does NOT do

No vmdk/vhd/vhdx writes (refused, Future work). No COW-granular
subclusters (extended-L2 is gated out). No refcount-table growth.
No new call-table slots, no VERSION bump (`fsync_input` and the
existing senders suffice — OQ5 as resolved in phase 2). No
guest-side "self-check" pass: post-write verification is
host-side in 5c/phase 6 (`qemu-img check` clean, pattern
read-back, qcow2 disk-size growth), where it is cross-validated
against qemu rather than against ourselves.

## Steps

| Step | Effort | Model | Isolation | Brief for sub-agent |
|------|--------|-------|-----------|---------------------|
| 5a | high | opus | none | Raw write path end-to-end: guest `write_input_byte_range` (sub-sector RMW on RW input slot 0, mirroring commit's output-side helper), the FLAG_WRITE branch for raw (per-offset pattern writes + `flush_after_completion` cadence + `fsync_input(0)` + `flushes_issued`), host `-w` enablement (drop the 4a refusal, RW-top attach, FLAG_WRITE + pattern into BenchConfig, vmdk/vhd/vhdx refusal message), flush-line rendering now reachable. Smoke: `-w --pattern 65 -c 100` on a raw image — pattern verifiable via cmp/xxd, `--flush-interval` count matches `total_flushes`, fsyncs actually reach the file (strace or /proc counters), byte-compare against a qemu `-w` run with identical args. Commit 1. |
| 5b | high | opus | worktree | qcow2 allocating writes per Mission §1-§3: the per-cluster driver (overwrite fast path; allocating path with chain-read COW fill), write-through L2/L1 ordering, staged refblocks + flush-point/end write-back, the full gate set + the two new error codes + host rendering. MUST diff the resulting write-back order against commit's `:787-834` and state the comparison explicitly in the report; MUST verify the COW fill against a qemu `-w` run on an overlay — the oracle is the **virtual view** (`qemu-img compare` full-image equality) plus `qemu-img check` clean on ours; physical byte-identity of the two overlays is NOT required (allocator placement may legitimately differ) but record whether it holds anyway. Worktree isolation: this is in-place-mutation code on the most corruption-prone path. Gates: build/size/lint/test-rust plus its own smoke (fresh qcow2 grows, check clean, pattern lands, overlay COW correct). Commit 2. |
| 5c | medium | sonnet | none | The recorded verification sweep + bookkeeping: matrix over {raw, fresh qcow2, populated qcow2, overlay} × {-w defaults, --pattern 65, --flush-interval 50 -d 1, --no-drain} — for each: instar vs qemu image byte-compare (or qemu-img compare where physical layouts legitimately differ — record which), `qemu-img check` clean, disk-size growth on fresh qcow2, flushes-issued == total_flushes, gate refusals (snapshot-bearing image, refcount_bits=1, compressed image, vmdk/vhd/vhdx), `--output json` fields. Append `## Captured write verification (step 5c)` to this plan; master plan row → Complete; index update; pre-commit. Stop-and-report on any content mismatch. Commit 3. |
