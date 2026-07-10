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

1. **What does qemu-img commit do with a snapshot-bearing backing
   file?** Expected: COW via the block layer, snapshots
   preserved. Must be established empirically (live qemu
   experiments across the pinned qemu versions) before anything
   else, because if instar commit corrupts snapshots today that
   is a live data-corruption defect deserving an immediate
   interim gate (refuse `nb_snapshots > 0` backings, matching
   bench's posture) and a GitHub issue, independent of the
   consolidation timeline.
2. **Same question for rebase safe mode** writing into a
   snapshot-bearing overlay: are the L1/L2 tables it rewrites
   ever snapshot-shared, and what does qemu do?
3. **Does our COW allocation order need byte parity with qemu?**
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
4. **API shape.** An emitted step-program (bounded buffer of
   typed steps: read cluster, zero range, write range, patch
   table entry, barrier) versus an incremental query API the
   guest op polls per cluster. Step-program is more auditable and
   testable pure; the bounded-buffer size must fit existing
   scratch budgets. To settle at phase-plan time with the memory
   budget survey.
5. **Memory budget unification.** commit, rebase and bench each
   have hand-laid scratch maps (staged L2s, staged refblocks,
   bounce buffers) with static layout asserts. Does a shared
   staging struct fit all three existing maps without moving
   regions, and does the COW bounce buffer (one cluster, up to
   2 MiB) fit? Guest binaries must stay within
   `scripts/check-binary-sizes.sh` limits.
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
| 1. Semantics pin: qemu snapshot-bearing commit/rebase behaviour, COW order determinism, oracle inventory, memory budget survey | PLAN-qcow2-write-infrastructure-phase-01-semantics.md | Not started |
| 2. Interim safety gates for defects found in phase 1 (conditional; fast-tracked if instar corrupts today) | PLAN-qcow2-write-infrastructure-phase-02-gates.md | Not started |
| 3. `crates/qcow2-write` core: classification + allocate-on-write planner + ordering contract (no COW, no growth), unit tests | PLAN-qcow2-write-infrastructure-phase-03-crate.md | Not started |
| 4. Migrate commit onto the crate (byte-identical proof) | PLAN-qcow2-write-infrastructure-phase-04-commit.md | Not started |
| 5. Migrate rebase safe mode (byte-identical proof) | PLAN-qcow2-write-infrastructure-phase-05-rebase.md | Not started |
| 6. Migrate bench `-w`; move the refcount-growth planner into the shared crate | PLAN-qcow2-write-infrastructure-phase-06-bench.md | Not started |
| 7. Copy-on-write branch; lift bench's internal-snapshot gate; per-consumer COW policy per OQ3 | PLAN-qcow2-write-infrastructure-phase-07-cow.md | Not started |
| 8. Fuzz: coverage-guided target for the new crate; differential coverage for newly-permitted snapshot-bearing writes | PLAN-qcow2-write-infrastructure-phase-08-fuzz.md | Not started |
| 9. Docs: architecture notes, docs/qcow2/ implementation notes, per-op doc updates, CHANGELOG | PLAN-qcow2-write-infrastructure-phase-09-docs.md | Not started |

Phase 2 exists only if phase 1 confirms a live defect; if qemu
also refuses (or instar's behaviour already matches), it
collapses into a documentation note and the table is updated.

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

To be filled in during execution. Candidate already identified:
commit's blind overwrite of snapshot-shared backing clusters
(no `nb_snapshots` gate, no COPIED/refcount check before the
:772 overwrite) — confirmed or refuted by phase 1; if confirmed,
file a GitHub issue and fast-track the phase-2 gate. Scan the
GitHub tracker during phase 1 for open issues touching commit /
rebase / bench qcow2 writes and snapshot interactions.

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
