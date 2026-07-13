# qcow2 write infrastructure

## Prompt

Before responding to questions or discussion points in this
document, explore the instar codebase thoroughly. Read relevant
source files, understand existing patterns (VMM structure, guest
operation layout, shared crate conventions, call table ABI,
format parsing, test infrastructure), and ground your answers in
what the code actually does today. Do not speculate about the
codebase when you could read it instead. Where a question touches
on external concepts (QCOW2, KVM, virtio, qemu's block layer),
research as needed to give a confident answer. Flag any
uncertainty explicitly rather than guessing.

All planning documents should go into `docs/plans/`.

Consult `ARCHITECTURE.md` for the overall system structure (host
VMM, KVM guest, call table, device emulation). Consult
`AGENTS.md` for build commands, project conventions, code
organisation, and the security model summary. Consult
`docs/qcow2/` for format documentation (particularly
`qcow2-refcount.md`, `qcow2-l1l2-tables.md` and
`qcow2-snapshots.md`) and `docs/commentary/` for architectural
decisions and design rationale.

When we get to detailed planning, I prefer a separate plan file
per detailed phase. These separate files should be named for the
master plan, in the same directory as the master plan, and simply
have `-phase-NN-descriptive` appended before the `.md` file
extension. Tracking of these sub-phases should be done via the
table in the Execution section below.

I prefer one commit per logical change, and at minimum one commit
per phase. Do not batch unrelated changes into a single commit.
Each commit should be self-contained: it should build, pass
tests, and have a clear commit message explaining what changed
and why.

## Situation

With `bench` landed (PLAN-bench.md, 2026-07-06) instar implements
all 15 qemu-img subcommands — the parity roster is closed. The
next structural gap is one layer down: **there is no single
callable "write N bytes at virtual offset X into an existing
qcow2, allocating as needed" primitive.** The bench master plan's
OQ4 investigation (PLAN-bench.md, "Findings: allocating-write
reuse for `-w` on qcow2") established this explicitly; since then
bench has added a third independent composition of the same
sequence.

Today the allocate-on-write machinery exists as three separate
per-op inlined compositions plus shared pure fragments (file:line
refer to the tree at plan-writing time, commit 98b3140):

* **commit** — the original composition. Per-cluster commit loop
  at `src/operations/commit/src/main.rs:650-785`: allocate + zero
  an L2 table when the backing L1 slot is empty (L1 rewrite with
  `OFLAG_COPIED` at :746), allocate a data cluster when the L2
  slot is empty, write the data, set `OFLAG_COPIED` (:772), then
  flush dirty backing metadata in dependency order (:787-834) and
  defensively re-read the backing header (:903). Pure allocator
  `allocate_backing_cluster_qcow2` in
  `src/crates/commit/src/qcow2.rs:219-279`, returning
  `RefcountExhausted` when every staged refblock is full.
* **rebase (safe mode)** — its own parallel allocator
  `allocate_overlay_cluster_qcow2` in
  `src/crates/rebase/src/qcow2.rs:455`, driven from
  `src/operations/rebase/src/main.rs:823-903` (fresh L2
  allocation at :843, data cluster at :873, `OFLAG_COPIED`
  rewrites at :867 and :903).
* **bench `-w`** — per OQ4's verdict, a reuse-and-compose copy of
  commit's sequence inside the bench guest op, backed by
  `crates/snapshot`'s primitives, plus the one capability nobody
  else has: setup-time refcount growth
  (PLAN-bench-refcount-growth.md; `WRITE_MAX_REFBLOCKS = 2048` at
  `src/operations/bench/src/main.rs:118`, growth invocation at
  :724-744, pure planner `plan_refcount_growth` at
  `src/crates/bench/src/lib.rs:656` with `worst_case_touched` at
  :491).
* **Shared pure fragments** — `crates/snapshot` holds the
  best-factored primitives, reused by snapshot / bitmap / check
  --repair for *metadata-only* allocation:
  `read_refcount_in_block` (`src/crates/snapshot/src/qcow2.rs:51`),
  `set_refcount_in_block` (:152), `check_refcount_after_addend`
  (:239), `alloc_cluster_in_refblocks` (:299),
  `alloc_contiguous_clusters_in_refblocks` (:344, with the
  comment "Refcount-table growth is a separate concern"),
  `rewrite_l1_entry_copied_flag` (:450) and
  `rewrite_l2_entry_copied_flag` (:495, extended-L2 aware).
* **convert** — structurally different: a linear bump allocator
  writing a brand-new image in one pass (per OQ4's table). Out of
  scope for consolidation; it is already the right shape for its
  job.

Consequences of the fragmentation, established during planning:

* **Nobody implements copy-on-write.** A cluster that is
  snapshot-shared (refcount > 1, `OFLAG_COPIED` clear) must be
  copied before modification or the snapshot is corrupted. bench
  knows this and gates: it refuses images with internal snapshots
  (`nb_snapshots > 0` check at
  `src/operations/bench/src/main.rs:642`, ownership assumption
  documented at :1118). **commit has no such gate** — no
  `nb_snapshots` check anywhere in
  `src/operations/commit/src/main.rs` (verified by grep), and the
  per-cluster loop blind-overwrites backing clusters without a
  COPIED/refcount check. If qemu-img commit COWs snapshot-shared
  backing clusters (expected: qemu writes through its block
  layer, which COWs), instar commit into a snapshot-bearing
  backing file silently corrupts the snapshots. The differential
  fuzzer's snapshot-avoidance steering means this path is
  untested against qemu. rebase safe mode has the analogous
  question for snapshot-bearing overlays — and likewise carries
  no `nb_snapshots` gate (verified by grep over
  `src/operations/rebase/src/main.rs` and
  `src/crates/rebase/src/qcow2.rs`).
* **Refcount growth exists only in bench.** commit, snapshot,
  bitmap and check --repair all hit `RefcountExhausted` ceilings
  (`src/crates/commit/src/qcow2.rs:279`,
  `src/crates/snapshot/src/qcow2.rs:434`) because allocation only
  claims free entries inside already-populated refblocks.
  PLAN-bench-refcount-growth.md's future work already flags
  extending growth to the sister mutators.
* **The v1 envelope is repeated in every op**: `refcount_bits ==
  16` only (`src/crates/commit/src/qcow2.rs:137,223`;
  `src/crates/snapshot/src/qcow2.rs:353`;
  `src/operations/bitmap/src/main.rs:521`), extended-L2 refusal
  (`src/operations/commit/src/main.rs:487-494`), no compression,
  no encryption, dirty/corrupt refused — each op re-states and
  re-tests its own copy of the gates.
* **Deferred features are blocked on this layer**: `amend
  refcount_bits` (PLAN-amend.md deferral) needs refcount
  structure rewriting; `create` / `resize`
  `--preallocation=falloc|full` for qcow2 need bulk cluster
  allocation; bench `-w` for vmdk/vhd/vhdx (docs/bench.md future
  work) needs the per-format equivalent of exactly this
  infrastructure.

## Mission and problem statement

Build **`src/crates/qcow2-write/`** — a pure `no_std` planner
crate providing the missing callable primitive: write N bytes at
virtual offset X into an existing qcow2 image, classifying each
touched cluster (allocated-and-owned overwrite / unallocated
allocate / snapshot-shared copy-on-write), allocating L2 and data
clusters, maintaining refcounts, and emitting the metadata
mutations and their crash-safe ordering as data the guest op
executes. Then:

1. **Migrate the three existing compositions onto it** — commit,
   rebase safe mode, and bench `-w` — proving the migration with
   byte-identical outputs where the existing oracles demand byte
   parity (commit, rebase baselines and differential fuzzing
   unchanged) and compare+check parity for bench.
2. **Add copy-on-write** — the one genuinely net-new capability —
   so writes into snapshot-bearing images copy shared clusters
   instead of corrupting them or refusing. Adopt it per consumer
   as each consumer's oracle permits.
3. **Generalize bench's refcount growth** by moving the growth
   planner into the shared crate, adopted where each consumer's
   oracle permits (bench immediately; byte-parity consumers keep
   their `RefcountExhausted` refusal until their oracle question
   is settled).
4. **Settle the snapshot-bearing-image safety question
   empirically first**: establish what qemu-img commit / rebase
   actually do with internal snapshots present, and if instar
   corrupts today, land an interim refusal gate as a fast-tracked
   bug fix before the consolidation work begins.

Design sketch (to be settled in phase planning, not binding):

* **Crate boundary.** New sibling crate `src/crates/qcow2-write/`
  depending on `crates/qcow2` (header/table parsing) and
  `crates/snapshot` (allocator / refcount / COPIED primitives).
  No churn in existing crates in v1; re-homing the snapshot
  primitives into qcow2-write (inverting the dependency) is a
  possible later cleanup, not part of this plan.
* **Planner/executor split**, matching house convention: the
  crate is pure math over staged state (header geometry, L1,
  staged L2 set, staged refblocks + offsets + dirty bits,
  allocation cursor) and produces explicit steps; the guest op
  owns call-table I/O and drives the steps. The crash-ordering
  contract (data durable before the pointer that reaches it;
  refcounts flushed last; fsync barriers between groups —
  commit's proven order at
  `src/operations/commit/src/main.rs:787-834`) is encoded in the
  step ordering the planner emits, so every consumer inherits it
  instead of re-deriving it.
* **v1 envelope** is the union of the existing gates:
  `refcount_bits == 16`, no extended-L2, no compressed clusters,
  no encryption, no external data file, dirty/corrupt refused.
  One implementation of the gates, tested once.
* **Sub-cluster writes** RMW inside the cluster (zero-fill on
  fresh allocation, copy-fill on COW), as bench's write path does
  today.

## Open questions

1. **Resolved (phase 1): qemu COWs and preserves internal
   snapshots on every version tested; instar corrupts them —
   silently in the dominant mode. Live defect confirmed, phase 2
   is live.** See "Findings: phase 1 semantics pin" (Q1).
   Original question: **What does qemu-img commit do with a
   snapshot-bearing backing file?** Expected: COW via the block layer, snapshots
   preserved. Must be established empirically (live qemu
   experiments across the pinned qemu versions) before anything
   else, because if instar commit corrupts snapshots today that
   is a live data-corruption defect deserving an immediate
   interim gate (refuse `nb_snapshots > 0` backings, matching
   bench's posture) and a GitHub issue, independent of the
   consolidation timeline.
2. **Resolved (phase 1): qemu proceeds without refusal or
   warning — its contract covers the active view only, and the
   snapshot's virtual view silently reads through the new
   backing afterwards (a semantic instar must reproduce, not
   avoid). instar corrupts refcounts when the active L2 is
   snapshot-shared, with a demonstrated data-loss chain via a
   later `snapshot -d`; a separate 512-byte-cluster livelock was
   found incidentally.** See Findings (Q2). Original question:
   **Same question for rebase safe mode** writing into a
   snapshot-bearing overlay: are the L1/L2 tables it rewrites
   ever snapshot-shared, and what does qemu do?
3. **Resolved (phase 1): no. No byte-identity oracle exists for
   any v1 consumer's mutated image (exhaustive inventory), and
   qemu's own COW placement is nondeterministic run-to-run at
   512-byte clusters, so byte parity is unachievable in general.
   COW placement has full layout freedom; the constraint stack
   is compare + check + info-equivalence, plus the new snapshot
   read-back oracle phases 7-8 add.** See Findings (Q3).
   Original question: **Does our COW allocation order need byte
   parity with qemu?**
   Initial inventory during planning found the commit / rebase
   oracles are *looser than assumed*: the differential-fuzz
   comparisons are normalised `qemu-img info --output=json` on
   the resulting images (`scripts/differential-fuzz.py` op_commit
   :2837, op_rebase :2595), and the cross-version baselines are
   info-equivalence
   (`instar-testdata/expected-outputs/{commit-backing,commit-overlay,rebase}-info-json`);
   bench's is `qemu-img compare` + `qemu-img check`
   (PLAN-bench-refcount-growth.md). If phase 1's exhaustive
   inventory confirms no byte-identity surface exists for any v1
   consumer, COW placement has layout freedom everywhere and only
   check-cleanliness + content parity constrain it; any consumer
   that does turn out to be byte-parity-constrained gates
   snapshot-bearing images (refusal, not corruption) unless
   qemu's COW placement proves deterministic. Phase 1 probes both
   questions.
4. **Resolved (phase 1): windowed step-program** — bounded
   64 KiB step buffer (~11 worst-case steps × 32 B per cluster,
   ~186 clusters per refill), steps addressing staged buffers by
   region-id + offset, barriers as explicit step types, refblock
   flush as one composite step. Decisive argument: the
   crash-ordering contract becomes unit-testable data instead of
   living in three guest loops. See Findings (Q4). Original
   question: **API shape** — step-program versus an incremental
   query API the guest op polls per cluster.
5. **Resolved (phase 1): feasible.** bench fits with no region
   moved (its `WRITE_*` regions already are the struct;
   `BUF_DEST` is the bounce); commit fits at its 1 MiB cluster
   envelope (`DATA_BUF` is the bounce; its planner-scratch
   duplicate refblocks are reclaimable); rebase needs only its
   `EXISTING_STATE` arena interior re-carved from bump-cursor to
   fixed offsets. Standardise on bench's single-copy
   mutate-in-place refblock model. Staging must remain
   scratch-address-carved, never `static` (.bss hazard class).
   Binary sizes are a non-issue (3% / 4% / 21% of the 768 KiB
   cap). See Findings (Q4). Original question: **memory budget
   unification** across the three hand-laid scratch maps.
6. **Growth adoption beyond bench.** Preemptive over-provisioned
   growth cannot satisfy byte-parity oracles
   (PLAN-bench-refcount-growth.md OQ5) — but per OQ3 above,
   phase 1's inventory determines which consumers are actually
   byte-parity-constrained; commit and rebase may not be. Options: match qemu's
   lazy on-demand growth layout exactly (strict, but makes growth
   universal), or keep `RefcountExhausted` refusals in
   byte-parity consumers with the shared crate simply owning the
   refusal. Recommendation: the latter for this plan; qemu-lazy
   growth parity is future work.
7. **Which ops migrate in v1?** commit, rebase safe mode and
   bench `-w` (the three allocate-on-write compositions).
   snapshot / bitmap / check --repair keep driving the
   `crates/snapshot` primitives directly — their metadata-only
   allocation is already well-factored and their byte-parity
   posture is stricter. convert stays out entirely.

## Execution

| Phase | Plan | Status |
|-------|------|--------|
| 1. Semantics pin: qemu snapshot-bearing commit/rebase behaviour, COW order determinism, oracle inventory, memory budget survey | PLAN-qcow2-write-infrastructure-phase-01-semantics.md | Complete (2026-07-12; see Findings) |
| 2. Interim safety gates + defect handling — LIVE: commit snapshot corruption (#420), rebase snapshot corruption + data-loss chain (#421), rebase 512-byte-cluster livelock (#422; fix or gate per root-cause depth) | PLAN-qcow2-write-infrastructure-phase-02-gates.md | Complete (2026-07-12; commits ac8f60a / 2fb9af4 / c84743e; see Findings) |
| 3. `crates/qcow2-write` core: classification + allocate-on-write planner + ordering contract (no COW, no growth), unit tests + simulation harness | PLAN-qcow2-write-infrastructure-phase-03-crate.md | Complete (2026-07-12; commits 878ebf0 / bc322b2 / 19ba116 / d883b25; see Findings) |
| 4. Migrate commit onto the crate (byte-identical proof) | PLAN-qcow2-write-infrastructure-phase-04-commit.md | Complete (2026-07-13; commits c101c9f / a2fae94 / 6b0c856 / 7dff544 / 2237028; see Findings) |
| 5. Migrate rebase safe mode (byte-identical proof) | PLAN-qcow2-write-infrastructure-phase-05-rebase.md | Complete (2026-07-13; commits ad208bf / cfb86f9 / 5889573; see Findings) |
| 6. Migrate bench `-w`; move the refcount-growth planner into the shared crate | PLAN-qcow2-write-infrastructure-phase-06-bench.md | Not started |
| 7. Copy-on-write branch; lift bench's internal-snapshot gate; per-consumer COW policy per OQ3 | PLAN-qcow2-write-infrastructure-phase-07-cow.md | Not started |
| 8. Fuzz: coverage-guided target for the new crate; differential coverage for newly-permitted snapshot-bearing writes | PLAN-qcow2-write-infrastructure-phase-08-fuzz.md | Not started |
| 9. Docs: architecture notes, docs/qcow2/ implementation notes, per-op doc updates, CHANGELOG | PLAN-qcow2-write-infrastructure-phase-09-docs.md | Not started |

Phase 2 was conditional on phase 1 confirming a live defect;
phase 1 confirmed three (see the Findings defect register), so
phase 2 ran. Phase 6's plan file is the next to write.

One commit per phase minimum; each commit builds, lints and tests
clean on its own. Phases 4-6 are pure refactors from the outside:
each lands only when the migrated op's full existing test surface
(unit, integration, baselines, differential fuzz replay) passes
unchanged.

## Agent guidance

### Execution model

All implementation work is done by sub-agents, never in the
management session. The management session is reserved for
planning, review, and decision-making. Follow the standard
workflow from PLAN-TEMPLATE.md (plan → spawn sub-agent → review
actual files → fix or retry → commit), including the review
checklist (build, lint, binary sizes, test-rust, relevant
integration targets, pre-commit, semantic match to the brief).

### Planning effort

This master plan was written at high effort, grounded in the
bench OQ4 findings (PLAN-bench.md) plus a fresh survey of the
commit / rebase / bench guest ops and the commit / rebase /
snapshot pure crates. Phase plans 1, 3 and 7 must be planned at
high effort (empirical qemu semantics, crate API design and
crash-ordering contract, COW correctness). Phases 4-6 at high
effort for the first migration (commit, the template) and medium
for the following two once the pattern is proven. Phases 2, 8
and 9 at medium effort — they follow well-established gate /
fuzz-target / docs patterns.

Each phase plan should include the step-level table (step,
effort, model, isolation, sub-agent brief) per PLAN-TEMPLATE.md.

### Findings: phase 1 semantics pin (2026-07-12)

Executed per
[PLAN-qcow2-write-infrastructure-phase-01-semantics.md](PLAN-qcow2-write-infrastructure-phase-01-semantics.md)
as four investigation sub-agents (1a/1b/1c/1d) plus this
synthesis. Probe scripts and raw per-row JSON live in the
(ephemeral) session scratchpad; everything needed to reproduce
is recorded here. Environment: instar built from develop at
98b3140; pinned static qemu-img {6.2.0, 7.2.22, 8.2.10, 9.2.4,
10.2.0} from `instar-testdata/qemu-img-binaries/x86_64/`; system
qemu-img is now **10.0.11** (upgraded from the 10.0.8 the phase
plan recorded); qemu-io is always the system build (pinned dirs
ship qemu-img only — harmless, both sides of every comparison
get byte-identical fixtures).

#### Q1 — commit into a snapshot-bearing backing (step 1a)

Matrix: cluster_size {512, 65536} × post-snapshot-write {yes,
no} × committed extent {overlapping-shared, fresh-only} × 6 qemu
versions = 48 rows, plus a second-order probe (snapshot on the
overlay instead). Fixture recipe (cwd = fixture dir, relative
backing names, overlay created with `-o cluster_size=<cs>` to
match the base — without that, instar's cluster-size-mismatch
gate refuses first and masks the question):

```
qemu-img create -f qcow2 -o cluster_size=<cs> base.qcow2 64M
qemu-io -c 'write -P 0xaa 1M 2M' base.qcow2
qemu-img snapshot -c snap1 base.qcow2
[psw=yes] qemu-io -c 'write -P 0xbb 1M 512K' base.qcow2
qemu-img create -f qcow2 -o cluster_size=<cs> \
    -b base.qcow2 -F qcow2 overlay.qcow2
[shared] qemu-io -c 'write -P 0xcc 1536k 1M' overlay.qcow2
[fresh]  qemu-io -c 'write -P 0xcc 32M 1M'   overlay.qcow2
```

Core signal: snap1's virtual view, extracted before and after
commit via apply-on-a-copy + convert-to-raw + sha256.

**qemu verdict (all 48 rows, fully version-invariant 6.2.0 →
10.2.0): COWs and preserves.** Exit 0, base grows (e.g. 3145728
→ 4194304 at 64K: COW allocations for the shared region),
check-clean, snap1 bit-identical before/after.

**instar verdict: corrupts in every shape where its writes reach
snapshot-shared clusters or a snapshot-shared L2 table — 5 of 8
fixture shapes, two distinct modes.**

| Mode | Trigger | Effect | Detectability |
|------|---------|--------|---------------|
| A: silent data-cluster overwrite | committed extent overlaps snapshot-shared data clusters (the blind overwrite at `src/operations/commit/src/main.rs:772`) | base does NOT grow; pattern C bleeds bit-exactly into snap1 (corrupted hash matched an independent prediction) | **invisible**: `qemu-img check` clean (refcount-2 clusters referenced by both L1 trees stay formally consistent), active views match qemu's and the expected merge, info-equivalence passes — only snapshot read-back reveals it |
| B: shared-L2 mapping leak | the active L2 table itself is still snapshot-shared (no post-snapshot write ever COWed it) and commit allocates through it | new mappings leak into snap1 (snap1 gains pattern C at 32M, bit-exactly predicted); fresh clusters referenced by two L1 trees carry refcount 1 | check-visible: 16 × `ERROR cluster N refcount=1 reference=2`, rc=2 |

The one agreeing shape (64K, psw=yes, fresh-only) is exactly the
shape where nothing instar writes touches shared state. At
cs=512 instar refuses fresh-extent rows first
(`ERROR_REFCOUNT_EXHAUSTED`, the v1 no-refblock-append ceiling)
— logically clean but **not byte-idempotent**: scaffolding
clusters are written into the backing before the guest errors
(base grew 2172486 → 2228224 in the refused rows). Second-order
probe: snapshot on the *overlay* — both tools proceed, both
preserve it, no divergence.

#### Q2 — safe-mode rebase of a snapshot-bearing overlay (step 1b)

Matrix: cluster_size {512, 65536} × post-snapshot-write {yes,
no} × 6 versions = 24 rows. Fixture: base_old (0x11 at [0,4M)),
base_new (0x22 at [2,6M)), overlay on base_old with 0x33 at
[1,2M), `snapshot -c snap1`, optional post-snapshot 0x44 write,
then `rebase -b base_new -F qcow2` (safe mode) per side.

**qemu semantics (uniform across versions): proceeds, never
refuses, never warns.** The contract covers the **active view
only** (preserved by copying differing old-backing data and
properly COWing the snapshot-shared L2). Internal snapshots are
left untouched, so **the snapshot's virtual view silently
changes** — its unallocated ranges now resolve through the NEW
backing (bit-identical resulting snap1 hash on all six
versions). This is designed-in qemu behaviour, not a bug to
match against.

**instar behaviour — three regimes:**

1. **64K + snapshot-shared active L2 (psw=no): corrupts.**
   Writes new mappings into the shared L2 in place and sets
   refcount=1 on the 80 clusters it allocates while two L1 trees
   reference them (`refcount=1 reference=2` × 80, every
   version). Demonstrated data-loss payload: a routine
   `qemu-img snapshot -d snap1` afterwards decrements 1 → 0 and
   frees the clusters — 3 MiB of **active-view** data physically
   zeroed (verified at the host offsets) while `qemu-img map`
   still points at them. Also diverges semantically: snap1 stays
   at OLD content instead of qemu's read-through-new-backing.
2. **64K + already-COWed active L2 (psw=yes): byte-identical to
   qemu's output on all six versions** — a notable parity datum:
   where no shared metadata is in play, instar's safe-rebase COW
   placement matches qemu exactly.
3. **cs=512: livelock, snapshot-independent.** ~100% guest CPU,
   zero file progress, killed after 25+ minutes; reproduces on
   the identical fixture with **no snapshot at all**; the same
   fixture at 64K completes in 0.76 s. A separate pre-existing
   defect in rebase's 512-byte-cluster write path, discovered
   incidentally. The killed image was semantically untouched
   (still points at base_old, check-clean) — timing luck, not a
   guarantee.

#### Q3 — parity-oracle inventory + COW determinism (step 1c)

**No byte-identity surface exists for any v1 consumer's mutated
image — confirmed exhaustively.** commit: stdout smoke tests
(tests/test_commit.py:196-296), info-equivalence on overlay AND
backing in round-trip (:421, :441) and baseline-matrix (:758,
:763) tests, exit-codes + info in op_commit
(scripts/differential-fuzz.py:2946, :2961-3025). rebase:
info-equivalence on the rebased overlay
(tests/test_rebase.py:367, :689; differential-fuzz :2702,
:2719-2779). bench: sha256 only for **raw** `-w`
(tests/test_bench.py:837, differential-fuzz :2500-2508); qcow2
`-w` is compare + check (+ a no-growth file-size assert on the
populated fast path, :890-893). The baseline files contain raw
`qemu-img info` JSON but the consuming comparison
(`assert_info_equivalent`, tests/helpers/info_json.py:148)
strips `actual-size` and even the physical file length
(:20-49) — **effective strictness: info-equivalence
throughout.** docs/quirks.md's commit/rebase "byte-for-byte"
claims are about stdout strings and info JSON, not image bytes.

**No snapshot-bearing commit/rebase/bench fixture is generated
anywhere** in the test or fuzz surface (pickers at
differential-fuzz.py:2800-2834 / :2547-2592 / :2375-2426 create
no snapshots; op_snapshot's fixtures are not shared across ops;
bench's only snapshot fixture is its refusal test,
tests/test_bench.py:1041-1053). Consequently **no existing
oracle would have caught Q1 mode A** — and even on a
snapshot-bearing fixture, check/compare/info all pass on mode A;
only snapshot read-back discriminates. That read-back
(apply-on-copy + convert + sha256) is the oracle phases 7-8 must
add to the integration and differential-fuzz stacks.

**COW placement determinism probe:** `qemu-img commit` on the
Q1 fixture is run-to-run deterministic at 64K clusters (5/5
identical output hashes) and cross-version stable — post-commit
images across 6.2.0 → 10.2.0 differ in exactly 4 bytes, the
snapshot table's `date_nsec` creation timestamp, with identical
`map` output. But at 512-byte clusters it is **nondeterministic
under a single binary**: 8 runs, 8 distinct hashes (identical
virtual content, per-run physical placement — plausibly the
async block-job's in-flight interleaving; mechanism inferred,
fact verified). **Byte parity with qemu COW placement is
therefore unachievable in general, as well as unnecessary.**

**Migration-proof oracle for phases 4-6:** instar-before vs
instar-after — the same fixture corpus through the pre- and
post-migration binaries, sha256 equality of every mutated file
plus stdout. No committed corpus exists; phase 4 builds a
harness that (1) generates a deterministic matrix once per run
with a pinned qemu-img — cluster_size {512, 4096, 65536} × size
{1M, 64M} × seed {empty, 64K, multi-extent} × lazy_refcounts
{off, on} × {implicit, explicit `-b`}; (2) first asserts
instar's own run-to-run byte determinism (the premise of the
proof — expected from the single-threaded guest, never yet
asserted); (3) asserts before == after across the matrix.
Re-parameterises for phases 5 and 6.

#### Q4 — memory budget + API shape (step 1d)

Layout source of truth is `src/shared/src/lib.rs`
(`SCRATCH_MEM_BASE` 0x300000, `ALLOC_HEAP_BASE` 0xF70000 →
**12.4375 MiB of scratch per op**; op window [0x30000, 0xF0000)
= 768 KiB, `.bss`-inclusive extent enforced by
scripts/check-binary-sizes.sh). Binding constraint: **staging
must be scratch-address-carved slices, never `static`** (the
.bss/HEADER_MISMATCH hazard class); commit/rebase today have
~zero .bss precisely because they follow it. Binary headroom is
a non-issue: commit 26 KiB / rebase 33 KiB / bench 162 KiB of
768 KiB.

Scratch verdicts (OQ5): **bench** — shared staging struct fits
with no region moved; its `WRITE_*` regions already *are* the
struct's refblock portion and `BUF_DEST` (2 MiB) already serves
as the COW bounce. **commit** — fits at its existing 1 MiB
cluster envelope with no region moved (`DATA_BUF` is the
bounce); its 3 MiB `PLANNER_SCRATCH` mostly holds a **duplicate
copy of the staged refblocks** (crates/commit/src/qcow2.rs:
164-176) — reclaimable by standardising on bench's
mutate-in-place model, which is also what a 2 MiB-cluster
envelope would need. **rebase** — top-level regions need not
move but `EXISTING_STATE` (4 MiB bump-cursor arena,
src/operations/rebase/src/main.rs:459+) must be re-carved into
fixed offsets; fits at the 1 MiB envelope; `old_buf` is
semantically the COW bounce already; its 4 MiB
`PLANNER_SCRATCH` duplicate is likewise reclaimable. Cap
asymmetries to unify: `MAX_REFBLOCKS` 32 (commit) vs 2048
(rebase, bench); cluster caps 1 MiB / 1 MiB / 2 MiB.

API shape (OQ4): **windowed step-program.** Worst case ≈ 11
steps per cluster write (COW read, fill, data write, fresh-L2
write, L1 patch, L2 patch, 2 refcount RMWs, refblock
write-back, ≤ 2 barriers); at a packed 32 B/step a 64 KiB step
buffer holds ~186 worst-case clusters per refill and fits every
op's existing slack. Whole-op programs are infeasible (commit's
envelope reaches ~2M clusters). Steps address staged buffers by
region-id + offset (keeps the crate pure/address-free);
barriers are explicit step types; refblock flush stays a single
composite step (matches all three current implementations). The
decisive argument over an incremental query API: the
crash-ordering contract becomes **data** a unit test asserts
once, instead of living in three guest driving loops — which is
the fragmentation defect this plan exists to kill.
Op-specific absorptions for phase 3's design: commit is
two-image/two-device (backing via output device + overlay clear
pass via input slot 0, plus the defensive header re-read);
rebase's COW source is a *chain-virtual* read and it ends with
a deferred header/backing-path patch group that must land after
refcounts; bench splits setup from the timed bracket. **Barrier
asymmetry flagged:** the call table exposes only `fsync_input`
(src/shared/src/lib.rs:1017) — commit and rebase write via the
output device and issue zero fsyncs today, relying on ordering
alone; phase 3 must either add `fsync_output` (ABI change) or
define barrier steps as ordering-only where the executor has no
fsync.

#### Defect register (phase 2 goes live)

Three defects confirmed, all pre-existing on develop. Filed
2026-07-12 as
[#420](https://github.com/shakenfist/instar/issues/420),
[#421](https://github.com/shakenfist/instar/issues/421) and
[#422](https://github.com/shakenfist/instar/issues/422)
respectively:

1. **`instar commit` silently corrupts internal snapshots in
   the backing file (#420).** Blind in-place overwrite of
   snapshot-shared clusters (no COPIED/refcount check,
   `src/operations/commit/src/main.rs:772`; no `nb_snapshots`
   gate anywhere). qemu-img COWs and preserves on every version
   tested. Mode A is check-clean and invisible to every
   existing oracle; mode B additionally under-counts refcounts
   (16 × `refcount=1 reference=2`). Repro: Q1 recipe above.
   Interim fix (phase 2): refuse `nb_snapshots > 0` backings,
   matching bench's posture; real fix: phase 7 COW.
2. **`instar rebase` (safe mode) corrupts refcounts when
   overlay metadata is snapshot-shared — with a data-loss
   chain (#421).** In-place mutation of a snapshot-shared L2 +
   refcount=1 on doubly-referenced clusters (80 ×
   `refcount=1 reference=2`); a subsequent
   `qemu-img snapshot -d` frees live active-view clusters
   (3 MiB zeroed in the probe). qemu proceeds-and-COWs (its
   contract: active view only; snapshots read through the new
   backing afterwards — instar must match that semantic in
   phase 7, including the snapshot-view change). Repro: Q2
   recipe. Interim fix (phase 2): refuse `nb_snapshots > 0`
   overlays in safe mode (`-u` metadata-only rebase does not
   copy data and needs separate consideration in phase 2
   planning).
3. **`instar rebase` livelocks on 512-byte-cluster overlays,
   snapshots irrelevant (#422).** 100% guest CPU, zero progress, 25+
   minutes on a fixture qemu completes instantly; same fixture
   at 64K clusters completes in 0.76 s. Independent of the
   snapshot work; needs root-causing (phase 2 scope decision:
   fix if shallow, otherwise gate 512-byte safe-mode rebase and
   track). **Fixed in phase 2 (c84743e)**; the capacity refusal
   on the original fixture remains by design (see the phase-2
   findings).

Also recorded, not defect-classed: commit's
`ERROR_REFCOUNT_EXHAUSTED` refusal writes scaffolding clusters
before erroring (refusal is not byte-idempotent — worth folding
into the phase 3 ordering contract: no image mutation before
the envelope checks pass).

Phase-2 updates to the register: a **fourth defect** was found
by 2a's own parity test — commit's overlay-clear pass corrupts
refcounts when the *overlay* has internal snapshots (the
overlay-side sibling of #420; issue #423). Gated in ac8f60a
as `CommitResult` error 15 alongside the backing-side gate.
And **#422 is fixed in phase 2 (c84743e)** — root cause was a
guest panic, not a livelock (see the phase-2 findings below);
the pre-existing refcount-capacity refusal on the original
fixture remains by design.

### Findings: phase 2 interim gates (2026-07-12)

Executed per
[PLAN-qcow2-write-infrastructure-phase-02-gates.md](PLAN-qcow2-write-infrastructure-phase-02-gates.md)
as steps 2a (commit gate, ac8f60a), 2b (rebase gate, 2fb9af4),
2c (investigation, no code), 2d (fix, c84743e) and 2e (this
close-out). All refusal gates fire before any image mutation
and carry sha256-unchanged byte-idempotence tests
(`tests/test_commit.py:TestCommitSnapshotGate`,
`tests/test_rebase.py:TestRebaseSnapshotGate`).

**2a found a fourth defect.** Item 1's live-parity test on the
deliberately un-gated overlay-snapshot shape — including the
post-snapshot overlay write variant phase 1 did NOT probe —
diverged: commit's overlay-clear pass zeroes active L2 entries
and decrements shared clusters without accounting for the
snapshot's reference, leaving 8 × `refcount=0 reference=1`
(clusters freed while the overlay snapshot's L1 tree still
references them — latent snapshot data loss). qemu handles the
same shape check-clean. Phase 1's second-order probe missed it
because its shape happened to balance arithmetically; the
post-snapshot-write variant does not. Per the plan's
stop-and-report rule the verdict widened the gate: commit now
refuses when EITHER side has snapshots (backing = error 14,
#420; overlay = error 15, the overlay-side sibling of #420,
issue #423).

**2c root-caused #422: not a livelock and not cs=512-specific.**
The "livelock" was a guest panic (out-of-bounds slice index)
spinning in the rebase op's `loop {}` panic handler. Mechanism:
the safe-mode L2 lookup slice was built once with the initial
staged-L2 count; staging a NEW L2 table and then visiting
another cluster in its coverage indexed past the stale length.
Reproduced at the default 64 KiB cluster size with sparse
overlays. The investigation also found a latent second defect:
the staged-L2 growth arena was carved before the
rb_offsets/refblock staging regions and could clobber them (a
refblock flush would then write to garbage host offsets).

**2d fixed both** (c84743e): the lookup slice is re-derived via
`l2_arena()` after growth, and the staging layout reordered to
L1 → refcount table → rb_offsets → refblock data → growable L2
arena last. Outcomes: the exact #422 fixture now terminates in
0.58 s with the PRE-EXISTING refcount-exhaustion refusal (v1
never appends refblocks — that capacity limit remains,
documented, retired later by the growth work — mission item 3); a
previously-hanging 64 KiB sparse-overlay shape completes with
qemu-identical content; output byte-invariance on
previously-working shapes was proven against a pre-fix build.

**Deferrals recorded.** (1) Byte-idempotence of the
refcount-exhaustion refusal path: it writes semantically-inert
data clusters before refusing (unreferenced, metadata never
flushed, check-clean) — same caveat as commit's phase-1
finding; folded into phase 3's ordering contract (no image
mutation before the envelope checks pass). (2) Refblock growth
capacity for rebase/commit: mission item 3 / Future work, not
phase 2's scope.

### Findings: phase 3 crate implementation (2026-07-12)

Executed per
[PLAN-qcow2-write-infrastructure-phase-03-crate.md](PLAN-qcow2-write-infrastructure-phase-03-crate.md)
as steps 3a (crate skeleton, types and gates, 878ebf0), 3b
(plan_write / plan_flush, bc322b2), 3c (ordering-contract
property suite, 19ba116), 3d (SimDisk simulation harness,
d883b25) and 3e (this close-out). The settled decisions held;
what follows records the refinements and deviations the later
phases need to know.

**3a — two gates beyond decision 8's literal list.**
`Gate::UnknownIncompatible` (code 2) refuses the zstd
compression bit and any unknown incompatible bit, matching
bench's proven wgate posture — per-cluster zlib compression
carries no header bit, so compressed clusters are refused at
plan time by classification (`WriteError::CompressedCluster`)
rather than by the header gate. `Gate::InvalidStagingConfig`
(code 9) refuses out-of-range caller staging shapes through the
same channel. Gate codes 1-7 deliberately equal bench's wgate
constants so the phase-6 migration maps refusals one-to-one;
codes 8-9 are new to the crate.

**3b — API refinements the phase plan anticipated.**
`StagedRegions` is the concrete form of the API sketch's
`staged` parameter: each planning call borrows a per-call view
of the executor's staged L1 / L2-window / refcount-table /
refblock buffers, and only `refblocks` is mutable — the planner
mutates staged refcounts in place at plan time (decision 6),
while L1/L2 mutations remain `PatchEntryU64` steps so the
ordering suite checks them as data. `BufFull` doubles as the
decision-5 load boundary: `plan_write` returns it
unconditionally after emitting a `LoadCluster`, because the
slot's bytes exist only after the executor runs the load — this
is how a pure planner "reads disk". Hard contract for the
phase 4-6 executors: every emitted window MUST be executed
before the next planner call, or classification reads stale
staged bytes. `StepKind` gained `FillRange` (lowers
`DataSource::Fill` so bench-style patterned writes never bounce
through a staged buffer) and `ZeroRegion` (fresh-L2 slot init).
`WriteError` carries stable codes 1-14 for host rendering.

**3b — refusals sharper than today's ops.** `NeedsBackingFill`
(code 14): a partial allocating write on an image with a
backing file refuses in v1, because zero-filling the uncovered
remainder would mask backing read-through and the pure planner
cannot perform a chain read. commit and rebase write full
clusters, so their migrations are unaffected; bench's overlay
chain-fill stays a phase-6 caller responsibility until phase-7
COW absorbs the fill. Unknown/reserved L1/L2 bit patterns
refuse (`UnknownL1Entry` / `UnknownL2Entry`) — narrower than
today's ops, which blindly allocate over exotic entries;
affects only corrupt images.

**3b — snapshot-crate reuse (decision 10).** The primitives
actually used are `alloc_cluster_in_refblocks`,
`read_refcount_in_block` and `AllocCursor`;
`check_refcount_after_addend` and the COPIED-rewrite helpers
the decision listed have no v1 call site (nothing rewrites
COPIED flags until phase-7 COW).

**3c — what was proven, and what could not be.**
Window-invariance — the property the windowed design rests on —
is proven byte-identical (step sequences AND final content) at
buffer capacities {1, 2, 3, 4, 5, 7, 16} against a 1024-step
reference across a 192-run grid: cluster sizes 512/4K/64K × L2
slot counts {1, 2, 3, 256} × 2 seeded write sets × 2 flush
epochs. A negative-control test feeds six hand-built violating
programs through the invariant checkers and asserts each
panics, so the suite cannot pass vacuously. Recorded as not
mechanically expressible (asserted at the planner boundary
only): the executor-side Durability→Ordering degradation on
fsync-less devices, and an API-stated disk-size bound (the
staged-refblock host coverage is used as the ceiling).

**3d — simulation grid and one inherent limit.** A 22-test grid
(cluster sizes 512/4K/64K/2M × image sizes × write patterns,
plus a multi-epoch mixed scenario and the backed-image refusal)
executes emitted programs literally against Vec-backed
per-device disks and journals every disk mutation epoch-tagged
with the count of preceding barriers — which keeps truncation
semantics correct under decision 6, since staged refblocks
mutate at plan time but their bytes reach the journal only when
the flush writeback executes. The journal is replayed truncated
at every Durability barrier (176 truncation points across the
suite; all barriers exercised), each truncation point proven
structurally sound and byte-wise old-or-new for its epoch.
Recorded harness limit, inherent to decision 7(c) rather than a
gap: reachable-with-refcount-0 is the legitimate on-disk state
at truncation points between the pointer and refblock
writebacks, so full refcount walks run only on completed epochs
— phase-8 crash oracles must expect the same.

### Findings: phase 4 commit migration (2026-07-13)

Executed per
[PLAN-qcow2-write-infrastructure-phase-04-commit.md](PLAN-qcow2-write-infrastructure-phase-04-commit.md)
as steps 4p (empirical probes, no code; plan amendments in
c101c9f), 4a (`crates/qcow2-write-exec`, a2fae94), 4q (the one
sanctioned planner change, 6b0c856), 4b (the op migration,
7dff544), 4c (proof harness + recorded run, 2237028) and 4d
(this close-out). The divergence budget D1-D9 held as amended
after 4p; nothing outside it was found. What follows is what
phases 5-9 need.

**The migration is byte-invisible — the proof numbers.**
`scripts/migration-proof.py` (4c) is the reusable before/after
oracle, re-parameterised for phases 5-6 via `--op`: per combo
it builds sha256-verified twin fixture sets with the pinned
qemu-img, asserts instar's own run-to-run determinism first
(the premise — it held everywhere), then asserts before ==
after under strict bucketing with no tolerance windows.
Recorded run (before = the f953289 binary, after = 7dff544):
73/73 combos pass — 65 both-succeed (including the
unaligned-virtual-size combo, zero D9 fallbacks) and 8
both-refuse (exactly the cs=512 multi-extent wire-11
refcount-exhaustion shapes from 4p's inventory). The
both-refuse bucket demanded — and got — byte identity of the
mutated pre-refusal scaffolding too, which 4b preserved by
executing the already-emitted window before surfacing a
non-BufFull planner error; identity on refusal paths is part
of the proof surface, not an exclusion. Differential fuzz: 300
iterations `--ops commit`, 0 divergences; baseline matrix
passes against unmodified testdata; `make test-rust` green
(1704 tests). Phases 5-6 rerun the same harness with their own
matrices and must save a pre-migration binary before their 4b
equivalent starts (the phase-2 `instar-before-2d` precedent).

**Two live corruption defects found by 4p, both now typed
refusals.** (1) D2 confirmed: commit into a backing with
compressed clusters silently destroyed them — the old loop
masked the compressed L2 entry and overwrote the host offset
in place, killing every virtual cluster packed into that host
cluster (qemu packs multiple deflate streams per host
cluster); exit 0, check-clean, damage visible only on
read-back. qemu-img instead allocates a fresh uncompressed
cluster and preserves the other streams. The migrated op
refuses at classification with the overlay side's existing
`ERROR_UNSUPPORTED_FORMAT`. (2) D4 upgraded from latent to
LIVE: a holed refcount table is stock-producible (a discard
history + `qemu-img resize --shrink` frees all-zero refblocks
below populated ones) and passes `qemu-img check` clean;
commit's compact-then-index-as-dense staging then wrote
refcounts into the wrong refblocks (2654 check errors / 69
leaked clusters in the probe). The migrated op stages
refblocks dense-prefix and gates on RT contiguity: wire 17,
pre-mutation, byte-idempotent. Filed 2026-07-13 as
[#427](https://github.com/shakenfist/instar/issues/427)
(compressed backings) and
[#428](https://github.com/shakenfist/instar/issues/428)
(holed refcount tables).

**Executor facts phases 5-6 reuse.** `qcow2-write-exec` is a
literal interpreter of the `StepKind` doc contracts with zero
planning logic: `execute(steps, &mut Regions, &mut impl
DeviceIo) -> Result<ExecStats, ExecError>` (fail-stop with
step index + typed cause; nothing panics). `DeviceIo` is the
per-device abstraction; `CallTableIo` maps Input0 →
`read/write_input_sector(0)` + `fsync_input(0)` and Output →
`read/write_output_sector` with no fsync, so `Durability`
degrades to `Ordering` on Output (D8) and `Ordering` is a
no-op everywhere (synchronous call-table I/O). One judgment
call deviates from decision 2's letter: a SINGLE shared RMW
bounce sector serves both devices (not per-device) because
steps execute serially and the bounce is dead between calls —
rebase/bench carves need one RMW sector + one fill sector,
not two RMW sectors. The byte-range layer (`read_bytes` /
`write_bytes` / `fill_bytes`) is exposed publicly as the
shared replacement for the per-op byte-range helpers; note 4b
kept commit's raw-pointer staging helpers (they write into
scratch addresses with no live slice), so phase 5 should
decide per call site rather than assume a wholesale swap.

**The 4q EOV-tail rule.** `plan_write` judges coverage against
the effective cluster end `min(cluster_size, virtual_size -
cluster_virtual_base)`: a tail-cluster write from the cluster
base whose coverage reaches `virtual_size` classifies as full
coverage (bytes beyond EOV are not virtual content; the
beyond-EOV zero-fill is the correct pre-image regardless of
backing, matching qemu's observed tail bytes). The exemption
is one-shot — the write must reach EOV from the cluster base
in a single request; any genuinely partial write below EOV
(including a head gap on the tail cluster) still refuses
`NeedsBackingFill`, and that refusal carries decision-9
semantics (clean but not byte-idempotent mid-run). Off the
tail cluster the condition is exactly the old rule. Rebase
safe mode writes whole clusters like commit did, so phase 5
needs the same tail clamp in its driving loop.

**The wire-code mapping is the phase-5 template.** Appended
`CommitResult` codes: 16 `ERROR_BACKING_UNSUPPORTED`
(`Gate::UnknownIncompatible` — zstd / unknown incompatible
bits; spec-mandated, previously proceeded) and 17
`ERROR_BACKING_INCONSISTENT` (the classification refusals:
`SnapshotShared` / `SnapshotSharedL2Table` /
`RefcountInconsistent` / `RefcountCoverage` /
`UnknownL1Entry` / `UnknownL2Entry` /
`StagedRegionsMismatch` / `NeedsBackingFill` defensively /
the staging-time non-contiguous-RT gate). Everything else
reuses existing codes: `RefcountExhausted` keeps wire 11,
`CompressedCluster` maps to the existing
`ERROR_UNSUPPORTED_FORMAT`, envelope `Gate`s that duplicate
op gates keep those gates' codes (and are unreachable because
the op gates run first, in their existing order), and
planner-protocol errors (`BufFull` escaping the loop,
`OutOfBounds`, `ResumeMismatch`) map to the internal-bug
family. Phase 5 should build `RebaseResult`'s mapping the
same way: at most two new appended codes, everything else
reused.

**Capacity outcomes.** Backing refblock staging is
byte-driven: `min(2048, 3 MiB / cluster_size)` refblocks
(formerly a flat 32). 4 MiB was not available for the region
because the untouched vmdk runner still carves its backing
GD/GT copies from `PLANNER_SCRATCH` (retained at 2.25 MiB);
rebase reclaims its 4 MiB planner duplicate outright, so
phase 5 has more headroom to spend. The backing L2 window is
`min(256, 2 MiB / cluster_size)` slots. LRU eviction exists
in the crate but NEVER fires for commit, structurally: the
overlay's stage-everything cap is the identical formula
(`MAX_STAGED_L2 = 256`, 2 MiB staging), cluster sizes must
match, and every backing L2 the loop touches corresponds to a
staged overlay L2 — so distinct backing tables ≤ slots, slots
assign in first-touch order, and `plan_flush`'s slot-order
writeback reproduces the old staged-array flush order exactly
(the quiet half of D5's byte-identity). Phase 5 must re-check
that bound for rebase's access pattern; if its walk can touch
more tables than its overlay-side cap guarantees, eviction
becomes reachable and the flush order is no longer trivially
identical.

**D6: the matrix widening bucket is empty — phases 5-6 need
off-matrix probes.** Every refusal on the Q3 proof matrix is
wire-11 refcount exhaustion, which the migration deliberately
keeps (phase 6 lifts it), so the refuse-before/succeed-after
bucket had nothing to catch ON the matrix. The capacity
widening was proven by 4p's off-matrix exemplar instead
(cs=512, 16 MiB backing, 8 MiB seeded → 66 populated RT
entries > 32 → wire-10 refusal before; succeeds
deterministically after, check-clean, info-equivalent to a
qemu-img commit twin). Phases 5-6 must likewise construct
explicit off-matrix widening probes for whatever caps their
migrations lift — the Q3 matrix shape does not exercise the
widened region.

### Findings: phase 5 rebase migration (2026-07-13)

Executed per
[PLAN-qcow2-write-infrastructure-phase-05-rebase.md](PLAN-qcow2-write-infrastructure-phase-05-rebase.md)
as steps 5p (empirical probes, no code; plan amendments in
ad208bf), 5a (the op migration, cfb86f9), 5b (proof harness
extension + recorded run, 5889573) and 5c (this close-out).
The divergence budget R-D1..R-D10 held as amended after 5p;
nothing outside it was found. The `-u`, unsafe-detach and
vmdk paths are untouched; safe detach IS migrated. What
follows is what phases 6-9 need.

**The migration is byte-invisible except one pre-declared raw
divergence — the proof numbers.** Recorded run (before = the
saved bd833b1 dist, after = cfb86f9): 69/69 combos pass — 63
both-succeed byte-identical and 6 both-refuse (exactly 5p's
inventory: every cs=512 × divergent × safe combo, wire-10
refcount exhaustion, with byte-identical orphan-append
scaffolding). Determinism failures: 0. Byte-identity
failures: 0. D9 fallbacks: exactly the 1 pre-declared
oversized-old-backing row — the crate zero-fills beyond EOV
where instar-before AND qemu-img carry old-chain bytes into
the raw file; virtual content proven equal, backings
untouched. The plain unaligned-size twin combo is fully
byte-identical, isolating the divergence to the beyond-EOV
tail. Off-matrix: the P8 widening exemplar (wire-9 staging
refusal before → check-clean qemu-parity success after), the
34-table eviction shape before-vs-after BYTE-IDENTICAL —
R-D5 proven live: eviction changes intermediate I/O order
only, an evicted table is written once and never reloaded —
and the holed-RT wire-16 pre-mutation refusal. Differential
fuzz: 300 iterations `--ops rebase`, 0 divergences
(seed 5013); rebase suite including the baseline matrix: 28
ran, 0 failed. A JSON combo pins the `clusters_copied` /
`bytes_copied` counters via stdout identity.

**Two live corruption defects found by 5p, both now typed
refusals; a third found, out of scope.** (1) R-D4 confirmed
live: a holed refcount table on the OVERLAY — #428's overlay
sibling, stock-producible, check-clean — was silently
misallocated by rebase's compact-then-index-as-dense staging
(1092 check errors + 32 leaked clusters at exit 0 in the
probe; wire-10 refusal after 12.4 MB of mis-placed scribbles
on larger divergences). The #428 recipe self-masks on
qemu ≥ 10 (discard now produces zero-plain clusters); the
adapted recipe is pre-touch + partial write + discard
8M-32M + shrink to 82M, with the backing attached afterwards
via `rebase -u`. Refused since cfb86f9: wire 16
(`ERROR_OVERLAY_INCONSISTENT`), pre-mutation,
byte-idempotent. (2) R-D1 confirmed live: extended-L2
overlays were silently corrupted at exit 0 (the walk misread
16-byte entries as 8-byte). Refused since cfb86f9: wire 15
(`ERROR_OVERLAY_UNSUPPORTED`), which also adds the
spec-mandated zstd/unknown-incompatible-bit refusal — a
today-succeeds→refuses narrowing (the bit is inert without
compressed clusters), accepted and documented. Filed 2026-07-13 as
[#430](https://github.com/shakenfist/instar/issues/430) and
[#431](https://github.com/shakenfist/instar/issues/431).
(3) The qcow2 chain reader ignores the zero flag on classic
L2 entries: `cluster_lookup`'s classic arm
(src/crates/qcow2/src/lib.rs:2213-2238) ignores bit 0, so a
v3 zero-flag cluster in a chain member reads as fall-through
or stale bytes instead of zeros — silent active-view
corruption, blast radius rebase / convert / compare / bench.
Pre-existing `crates/qcow2` defect, explicitly NOT fixed by
phase 5 (filed 2026-07-13 as
[#432](https://github.com/shakenfist/instar/issues/432));
phases 6+ or a standalone fix must address it, and until
then differential matrices must avoid `write -z` seeds (5b's
does).

**The skip-probe original-state design is the pattern for
ops that must not involve the planner on mapped clusters.**
Rebase skips any cluster already mapped in the overlay
(plan_write there would classify Owned and wrongly overwrite
it with old-chain content). The migrated probe consults
ORIGINAL pre-run state: a read-only copy of the pre-run L1
(separate from the planner's patched `StagedRegions.l1`)
plus one cluster-sized probe buffer holding the current
original L2 table, reloaded on `l1_idx` change — the walk is
monotonic, so exactly one read per populated table, and
fresh tables never probe disk. Today's exact skip predicate
is preserved (any non-zero raw entry skips, so compressed /
zero-flag / garbage entries behave identically and the
crate's entry refusals stay unreachable for mapped
clusters). Bench's `-w` path always writes its scheduled
offsets — mapped clusters reach the planner deliberately as
Owned overwrites — so phase 6 likely does NOT need the
probe; it matters wherever a future consumer must leave
mapped content alone.

**Two judgment calls worth knowing.** The -u/unsafe-detach/
vmdk planner scratch keeps its original addresses as an
ALIAS carve over the safe-mode region ladder — the runners
are mutually exclusive per invocation, and compile-time
asserts pin both carves below the allocator heap. And the
refcount table stages as a bounded PREFIX
(`min(rt_size, 64 KiB)`, bench's model) rather than whole:
the planner reads only the entries covering the staged
refblocks (≤ 16 KiB at the 2048-refblock cap), and staging
the whole table would have narrowed in-envelope cs=1M
shapes whose refcount table exceeds 64 KiB.

**Capacity outcomes.** Stage-everything for existing L2s is
retired along with the growable L2 arena and its caps — the
#422 hazard class (arena growth clobbering refblock staging)
is gone by construction. Unlike commit, L2-window eviction
IS reachable for rebase (`min(256, 2 MiB / cluster_size)`
slots; overlays at cs ≥ 64K can touch more tables than
slots) and is accepted on the structural argument proven
live by the eviction shape above. Refblock staging is
byte-driven at `min(2048, 3 MiB / cluster_size)` (formerly
the joint 4 MiB bump arena shared with L2 staging); rebase
reclaimed its 4 MiB PLANNER_SCRATCH duplicate outright, as
the phase-4 findings predicted. The P8 shape (cs=512, 64 MiB
overlay, 512 populated L2 tables, identical chains) refused
wire 9 before and now rebases check-clean with qemu parity.

**What phase 6 (bench) inherits.** The wire-code template
has now been applied twice (commit 16/17, rebase 15/16): at
most two appended codes, `RefcountExhausted` keeps its
existing code, everything else reuses existing codes.
`scripts/migration-proof.py` has a migration-proof `--op`
registry ready for bench. Bench is already the closest
composition to the crate — it uses the snapshot-crate
allocator, dense-prefix refblock staging, and wgate codes
that equal the crate's gate codes 1-7 one-to-one (a phase-3
design decision) — so the mechanical migration surface is
smaller than rebase's. The phase-6 novelty is refcount
GROWTH: bench's preemptive grow-at-setup planner
(PLAN-bench-refcount-growth) must move into the shared
crate rather than remain a bench-side special case — that
absorption, not the write-path migration, is where phase 6's
design work lives.

**The vacuous NewBackingIncompatible gate (P9).** The rebase
op passes the overlay's own virtual size as
`new_backing_virtual_size`
(src/operations/rebase/src/main.rs:503 and :894), so the
planner's "new backing smaller than the overlay" check
compares the overlay's size to itself and can never fire.
5p probed the real shape (new backing smaller than the
overlay): behaviour matches qemu-img anyway, so nothing is
wrong today — but the gate is dead code as wired. Recorded
for a possible cleanup: either plumb the real new-backing
virtual size or delete the parameter; not changed by
phase 5.

## Administration and logistics

### Success criteria

* `make instar` builds and `make lint` is clean.
* Guest binaries pass `scripts/check-binary-sizes.sh`.
* All Rust unit tests pass (`make test-rust`), including the new
  `crates/qcow2-write` suite.
* All Python integration tests pass, including the commit /
  rebase / bench suites, with **zero changes to existing
  cross-version baselines** — the migrations are byte-invisible.
* Differential-fuzz soaks for commit, rebase and bench report 0
  divergences after migration.
* Copy-on-write: writes into snapshot-bearing qcow2 images leave
  `qemu-img check` clean, the active view `qemu-img compare`
  identical to qemu's result, and every pre-existing snapshot's
  content bit-identical when applied (verified via qemu-img
  snapshot -a on copies).
* The phase-1 findings (qemu's snapshot-bearing commit / rebase
  behaviour) are recorded in this plan, and any live defect found
  is gated and tracked before phases 3+ begin.
* `pre-commit run --all-files` passes.
* docs/, ARCHITECTURE.md, AGENTS.md, README.md and CHANGELOG.md
  are updated; the plans index reflects final status.

### Future work

* qemu-lazy refcount growth byte parity, unlocking growth for the
  byte-parity consumers (commit / rebase / snapshot / bitmap) and
  retiring their `RefcountExhausted` ceilings (extends
  PLAN-bench-refcount-growth.md future work).
* `amend refcount_bits` (deferred from PLAN-amend.md) on top of
  the refcount rewrite machinery.
* qcow2 `--preallocation=falloc|full` (and `metadata`) for create
  / resize on top of bulk allocation.
* Extended-L2 / subcluster allocation support (lifts the
  extended-L2 refusal shared by every mutator).
* `refcount_bits != 16` support in the shared envelope.
* Compressed-cluster and encrypted writes.
* vmdk / vhd / vhdx allocating-write infrastructure (the
  per-format siblings of this plan; unlocks bench `-w` beyond
  raw/qcow2 per docs/bench.md future work).
* Re-homing the `crates/snapshot` allocator / refcount / COPIED
  primitives into `crates/qcow2-write` once all consumers migrate
  (dependency inversion deferred from OQ4 here).

### Bugs fixed during this work

Phase 1 confirmed three pre-existing defects, phase 2 found a
fourth, phase 4's probes found two more, and phase 5's probes
found three more — two fixed by typed refusals, one out of
scope (details and repro recipes in the Findings sections;
#420-#422 filed 2026-07-12):

1. [#420](https://github.com/shakenfist/instar/issues/420)
   `instar commit` silently corrupts internal snapshots in the
   backing file (two modes; the dominant one invisible to every
   existing oracle). **Gate landed in phase 2 (ac8f60a,
   error 14) — the corruption is unreachable**; real fix
   phase 7 COW, issue stays open until then.
2. [#421](https://github.com/shakenfist/instar/issues/421)
   `instar rebase` (safe mode) corrupts refcounts on
   snapshot-shared overlay metadata, enabling live data loss via
   a later `snapshot -d`. **Gate landed in phase 2 (2fb9af4,
   error 14; `-u` stays allowed with a parity test) — the
   corruption is unreachable**; real fix phase 7 COW, issue
   stays open until then.
3. [#422](https://github.com/shakenfist/instar/issues/422)
   `instar rebase` livelocks on 512-byte-cluster overlays
   (snapshot-independent). **Fixed in phase 2 (c84743e)**: a
   guest panic from a stale staged-L2 lookup slice, plus a
   latent staging-layout clobber — not a livelock, not
   cs=512-specific. The remaining refcount-capacity refusal on
   the original fixture is a documented v1 limit, not this bug.
4. `instar commit`'s overlay-clear pass corrupts refcounts when
   the overlay has internal snapshots (the overlay-side sibling
   of #420; issue #423), found by phase 2a's parity test.
   **Gated in the same commit (ac8f60a, error 15)**; real fix
   phase 7 COW.
5. `instar commit` silently destroyed compressed clusters in
   the backing (found by phase 4p; check-clean, exit 0, every
   stream packed in the shared host cluster lost). **Refused
   since the phase-4 migration (7dff544,
   `ERROR_UNSUPPORTED_FORMAT`)**; filed 2026-07-13 as
   [#427](https://github.com/shakenfist/instar/issues/427).
   Real support (decompress-and-
   reallocate, qemu's behaviour) is possible phase 7+ work.
6. `instar commit` corrupted refcounts on backings with a
   sparse (holed) refcount table — stock-producible and
   check-clean (found by phase 4p, upgrading divergence D4 to
   a live defect). **Refused since the phase-4 migration
   (7dff544, error 17, pre-mutation)**; filed 2026-07-13 as
   [#428](https://github.com/shakenfist/instar/issues/428).
7. `instar rebase` (safe mode) corrupted refcounts on overlays
   with a sparse (holed) refcount table — the overlay-side
   rebase sibling of #428, stock-producible and check-clean
   (found by phase 5p; 1092 check errors + 32 leaked clusters
   at exit 0 in the probe; the #428 recipe self-masks on
   qemu ≥ 10 and needs the adapted recipe in the phase-5
   findings). **Refused since the phase-5 migration (cfb86f9,
   error 16, pre-mutation, byte-idempotent)**; filed
   2026-07-13 as
   [#430](https://github.com/shakenfist/instar/issues/430).
8. `instar rebase` (safe mode) silently corrupted extended-L2
   overlays — the walk misread 16-byte extended-L2 entries as
   8-byte classic entries, corrupting virtual content at
   exit 0 (found by phase 5p). **Refused since the phase-5
   migration (cfb86f9, error 15, pre-mutation)**; filed
   2026-07-13 as
   [#431](https://github.com/shakenfist/instar/issues/431).
9. The `crates/qcow2` chain reader ignores the zero flag on
   classic L2 entries (`cluster_lookup`'s classic arm ignores
   bit 0), so v3 zero-flag clusters in a chain member read as
   fall-through or stale bytes instead of zeros — silent
   active-view corruption with blast radius rebase / convert /
   compare / bench (found by phase 5p). **NOT fixed by
   phase 5** (pre-existing chain-read behaviour, explicitly
   out of the migration's scope); phases 6+ or a standalone
   fix must address it, and differential matrices must avoid
   `write -z` seeds until then. Filed 2026-07-13 as
   [#432](https://github.com/shakenfist/instar/issues/432).

Fix status is tracked here as phases land.

### Documentation index maintenance

`index.md` and `order.yml` in `docs/plans/` were updated when
this plan was created. Update the status column in `index.md` as
phases complete, and to *Complete* when all phases land.

### Back brief

Understanding: instar has three independent inlined compositions
of the qcow2 allocate-on-write sequence (commit, rebase safe
mode, bench `-w`) built from shared pure fragments, with the two
hard capabilities — copy-on-write for snapshot-shared clusters
and refcount growth — implemented nowhere and in exactly one
place respectively. This plan first settles the safety question
that fragmentation has left open (commit may corrupt
snapshot-bearing backings today; qemu's behaviour must be pinned
empirically and any live defect gated immediately), then builds
`crates/qcow2-write` as the single pure planner owning
classification, allocation, refcounts, the v1 envelope gates and
the crash-ordering contract, migrates the three compositions onto
it with byte-invisible refactor proofs, and finally adds COW —
adopted per consumer as its parity oracle permits, with bench
(compare+check oracle) lifting its internal-snapshot gate first.
The crate becomes the foundation for the deferred features that
all stall on this layer: amend refcount_bits, qcow2 preallocation
modes, and eventually per-format write infrastructure for the
other formats.
