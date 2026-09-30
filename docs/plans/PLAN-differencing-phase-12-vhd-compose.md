# Differencing phase 12: guest VHD sector-bitmap read path

## Prompt

Plan phase 12 of `PLAN-differencing.md`, the first of the two guest
read-path phases: teach the guest to compose a differencing VHD child
against its parent at sector granularity, so that an allocated block
whose sector bitmap says a sector belongs to the parent reads the
parent's bytes rather than the child's zeros.

Phase 11 landed the host half (`c66f8b25`, #603) and deliberately
confined parent resolution to the one reporting call site. Nothing on
the host builds a composing VHD chain yet, and phase 14 is what changes
that, so this phase is a crate-level change verified by crate-level
tests. The phase plan is the deliverable; implementation is a separate
ask.

## Planning effort

**High.** This is a guest read path in `no_std` code where a wrong
answer is silently wrong data rather than a crash, and the central
design question -- how sector-granularity ownership is expressed
through a chunk-granularity chain walker -- is a genuine judgement
call. `PLAN-TEMPLATE.md`'s project note puts "subtle correctness
questions" at high effort, and issue #547 exists because the previous
answer to this question was "read the child and hope".

Review effort: **high**, for the same reason. The master plan does not
specify one for this phase.

## Scope

**In:**

* A sector-bitmap reader in `src/crates/vhd/src/lib.rs`: given an
  allocated block, report which of its 512-byte sectors the child owns.
* Extending the `ImageFormat::Vhd` arm of `read_chain_virtual_cluster`
  (`src/crates/qcow2/src/lib.rs:8486`) so that, for a differencing
  child, parent-owned sector runs descend to the next chain device
  instead of being served from the child.
* Lifting the phase 4 refusal at `init_chain_states`
  (`src/crates/qcow2/src/lib.rs:9528`) **conditionally**: only when a
  parent device actually follows the child in the chain.
* Rust unit tests in the qcow2 crate's existing mock-chain harness.
* A `CHANGELOG.md` entry, and the plan bookkeeping this phase owns.

**Out, and why:**

* **VHDX.** Phase 13. The two formats are separate phases by the master
  plan's own sequencing, and VHDX additionally needs
  `PAYLOAD_BLOCK_PARTIALLY_PRESENT` to stop being treated as fully
  present (`src/crates/vhdx/src/lib.rs:1408`, `:1438`, `:1487`) -- a
  different problem from reading a bitmap.
* **Host wiring so a composing operation attaches a VHD parent.** Phase
  14. See F8: no host path constructs a composing VHD chain today, by
  construction, because phase 11 gave nine of ten call sites a policy
  that refuses to resolve a VHD parent at all. This phase therefore
  cannot be exercised end to end, and does not try to be -- see
  decision 7.
* **Python integration tests and fuzzing.** Phase 15. They need
  fixtures instar did not write, and the libvhdi sector-bitmap defect
  recorded in the master plan (`PLAN-differencing.md:451-462`) shapes
  how those fixtures must be built. Nothing in this phase reads a
  real-world differencing chain, so the defect cannot reach it.
* **Documentation beyond `CHANGELOG.md`.** Phase 16. Nothing
  user-visible changes: with the host still refusing to resolve a VHD
  parent for every composing operation, this phase changes no command's
  output.
* **`map`'s per-extent `depth` field.** The master plan
  (`PLAN-differencing.md:543-546`) already defers that to phase 14's
  plan, and qcow2 has not solved it either.
* **The write side.** `commit` and `rebase` reject a VHD or VHDX source
  before any parent is considered, because neither operation supports
  those formats at all -- measured during phase 11's second review
  round and recorded in `docs/chain-discovery.md`.

## What the survey found

The master plan's phase 12 material is two bullets and two specifics
(`PLAN-differencing.md:500-505`, `:530-542`). Its *substance* is
correct. Its *scale* is not: the guest-side machinery this phase was
expected to build already exists, and what is missing is narrower and
better-precedented than the master plan implies. Corrections are made
at source in this commit, as noted per finding.

**F1. The guest chain walker already exists, and already has a VHD
arm.** `read_chain_virtual_cluster`
(`src/crates/qcow2/src/lib.rs:7930`) walks the chain device by device,
dispatching per format, and `ImageFormat::Vhd` is one of its arms
(`:8486`). The arm handles fixed VHDs by raw read, calls
`block_lookup`, and already returns `continue` -- descend to the next
device -- for `BlockLookup::Unallocated`. So "the guest read path" is
not new construction; it is one arm of an existing walker.

**F2. `ChainStates` already carries per-device VHD state.**
`vhd_states: [Option<VhdState>; MAX_CHAIN_DEVICES]`
(`src/crates/qcow2/src/lib.rs:9385`), behind the `vhd-input` feature,
initialised by `init_chain_states` (`:9507`). `MAX_CHAIN_DEVICES` is 16
(`src/shared/src/lib.rs:4725`). No new state plumbing is needed.

**F3. An unallocated BAT entry is already correct for a differencing
child.** In a differencing VHD an unallocated block means *the whole
block belongs to the parent*, and the arm's existing
`BlockLookup::Unallocated => continue` descends to the next device --
exactly right. Only the **allocated** case is wrong today: it serves
the entire block from the child, ignoring the per-sector bitmap. That
halves the change, and the master plan does not say it.

**F4. The master plan's line references for the bitmap have drifted.**
It cites `src/crates/vhd/src/lib.rs:1432-1441` and `:1534`. The
computation is now at `:1513-1516` (`bitmap_bytes`, rounded up to a
512-byte boundary), it is stored as `block_data_offset` at `:1522`, and
the skip is applied in `block_lookup` at `:1615-1616`. The *claim* --
that the size is computed only to skip past it and no bit is ever read
-- holds: the vhd crate contains no sector-bitmap reader of any kind.
Corrected at source.

**F5. There is a precedent in the same function, and it is the right
shape.** qcow2's extended-L2 subcluster path in
`read_chain_virtual_cluster` (`:7980-8135`) already solves the general
problem this phase faces: a per-cluster allocation bitmap, coalesced
into runs, where allocated runs are read from this device, zero runs
are memset, and unallocated runs **recurse into the backing chain for
that sub-range only** (`:8106-8130`, "UNALLOC: recurse into backing
chain"). The recursion passes `chain_start + dev_offset + 1`, the
sub-range's own virtual offset, and `buf.add(buf_off)`. Phase 12's VHD
arm is the same algorithm with a 512-byte granule instead of a
`cluster_size/32` one. Not in the master plan, and it is the single
most load-bearing fact in this survey.

**F6. `VhdState` already allocates a data-sector cache it never
uses.** `data_cached_sector` / `data_cache_buf`
(`src/crates/vhd/src/lib.rs:1344-1345`) are initialised at `:1528` and
`:1555` and then **read nowhere in the crate** -- grep returns only the
declaration, the two constructors and the doc comment. The comment
above them already reads "Sector cache for data reads (reused for
sector bitmap skip)". So the buffer this phase needs for bitmap reads
is already allocated, already sized at `MAX_SECTOR_SIZE`, and already
passed in per device. See decision 3.

**F7. The phase 4 refusal lives in the qcow2 crate, not the vhd
crate.** `VhdState::init` deliberately *accepts*
`DISK_TYPE_DIFFERENCING` (`src/crates/vhd/src/lib.rs:1427`); the
refusal is in `init_chain_states` at `:9528`, whose comment says so
explicitly and cites issue #547. It is therefore one `if` to relax, in
one place, with the VHDX twin immediately below it at `:9556` left
untouched for phase 13.

**F8. No host path constructs a composing VHD chain, so this phase has
no end-to-end test available.** Phase 11 threaded `ChainUse` through
`discover_backing_chain` so that only `run_info --chain` may resolve a
differencing VHD parent; the nine composing call sites break at the
gate and never produce a two-device chain config. Phase 14 is what
changes that. This is a scoping constraint, not a gap to fix here --
see decision 7.

**F9. The mock-chain test harness exists and has exactly the right two
exemplars.** The qcow2 crate's unit tests build synthetic multi-device
chains through a mock call table; `q1_arm_unallocated_descends_to_backing`
(`:6591`) and `q1_arm_mixed_chunk_allocated_and_backing` (`:6621`) are
the two shapes this phase must reproduce for VHD. There are no
`vhd_arm_*` tests at all today -- the VHD arm is currently covered only
indirectly.

**F10. Nothing else in the master plan's phase 12 material is wrong.**
The two "specifics phases 12 and 13 must confront" are both accurate,
the sequencing rationale holds, and the libvhdi caveat is correctly
aimed at phases 8 and 15 rather than here.

## Decisions

**1. Ownership is resolved per chunk, not per block, and the bitmap is
never materialised whole.** A VHD block is commonly 2 MB, giving 4096
sectors and a 512-byte bitmap; a `u64` cannot carry it, so qcow2's
`StandardSubclusters(host_offset, bitmap)` return shape does not
transfer. The lookup returns the bitmap's host byte offset alongside
the data offset, and the arm reads only the bitmap bytes covering the
chunk it is serving. A 64 KB chunk spans 128 sectors and therefore 16
bitmap bytes.

This is the decision a reviewer is most likely to argue with, because
the alternative -- return a whole-block ownership summary -- makes the
arm simpler. It is rejected because it forces either a 512-byte
per-device buffer that does not exist, or a full bitmap read on every
chunk, and because the run-coalescing loop the arm needs (decision 2)
wants the bytes rather than a summary anyway.

**2. The arm follows F5's run-coalescing structure, not a
sector-at-a-time loop.** Walk the chunk's sectors, coalesce maximal
runs of equal ownership, and issue one read per run: child-owned runs
from this device at the block's data offset, parent-owned runs by
recursing into `read_chain_virtual_cluster` at `chain_start +
dev_offset + 1` for that sub-range. A sector-at-a-time loop would be
correct and would issue up to 128 call-table reads per 64 KB chunk;
the coalescing loop issues one in the common case, where a block is
wholly the child's or wholly the parent's.

**3. The sector bitmap is read through the already-allocated, currently
unused data-sector cache** (F6): `data_cached_sector` /
`data_cache_buf`. This costs no new guest memory -- the buffers are
allocated per device today and read by nothing. It also keeps the BAT
cache un-thrashed, which matters because the BAT entry and the bitmap
sit in different regions of the file and a chunk read touches both.
Do **not** add a third per-device buffer; at `MAX_CHAIN_DEVICES` = 16
and `MAX_SECTOR_SIZE` = 64 KB that would be 1 MB of guest memory for
a cache that already exists.

**4. A set bit means the child owns the sector.** This is the VHD
specification's polarity and phase 1 pinned it; the implementer must
not re-derive it from a fixture, because a fixture whose blocks happen
to be wholly child-owned cannot tell the two polarities apart. State
the polarity in a comment at the point of use, and let 12d's
mixed-ownership test be what fails if it is inverted.

**5. The phase 4 refusal is lifted only when a parent device actually
follows the child.** `init_chain_states` keeps refusing a differencing
VHD that is the last device in the chain, because composing against a
parent that is not there is exactly the silently-wrong read issue #547
is about. Concretely: refuse when `dev_idx + 1 >= device_count`.

This preserves every existing test and every current user-visible
behaviour: with phase 14 unbuilt, no composing operation ever builds a
chain longer than one device for a VHD, so the refusal fires exactly as
it does today. The lift is dormant until phase 14 wakes it.

**6. A differencing child whose parent device is present but whose
parent is the wrong disk is not this phase's problem.** Size and
identity checking between child and parent happens on the host at
create time (`ERROR_PARENT_SIZE_MISMATCH`, phase 7) and at chain-walk
time (phase 11, with format checking tracked as issue #608). Adding a
second check in the guest read path would duplicate it in the place
least able to report it. If the implementer finds this uncomfortable,
the answer is issue #608, not code here.

**7. This phase is verified by Rust unit tests only, and says so.** F8
means there is no way to drive a composing VHD chain from a command
line until phase 14. Rather than build a temporary host path to test
against -- which would create precisely the contingent-refusal risk
phase 11 spent a whole phase eliminating -- 12d builds the chains
synthetically through the existing mock call table, as
`q1_arm_mixed_chunk_allocated_and_backing` does. The definition of done
states the coverage claim in those terms, so that a later reader does
not mistake "no integration test" for an oversight.

**8. `block_lookup`'s existing signature is preserved and a sibling is
added.** `BlockLookup` (`src/crates/vhd/src/lib.rs:1316`) is consumed
by `map` and by the non-chain read paths, which are correct as they
stand and are not differencing-aware. Adding a variant would make every
existing match site handle a case that cannot occur for them. Add a
separate lookup that returns the bitmap offset, and call it only from
the chain arm when `disk_type == DISK_TYPE_DIFFERENCING`.

## Step plan

Each step is one commit. 12b depends on 12a; 12c depends on 12b; 12d
depends on all three. 12e is independent.

| Step | Effort | Model | Isolation | Brief for sub-agent |
|------|--------|-------|-----------|---------------------|
| 12a | high | opus | none | Add a sector-bitmap reader to `src/crates/vhd/src/lib.rs`. Add a sibling of `block_lookup` (`:1574`) that, for an allocated block, returns both the data offset it returns today **and** the host byte offset of that block's sector bitmap -- which is `bat_entry * 512`, the bitmap being what `block_data_offset` (`:1522`) currently skips past. Do not change `BlockLookup` or `block_lookup` (decision 8). Add a second function that, given the bitmap's host offset and a range of sector indices within the block, reads the covering bitmap bytes through the existing `data_cached_sector` / `data_cache_buf` pair (`:1344-1345`, currently allocated and read by nothing -- see F6 and decision 3) and reports ownership per sector. A set bit means the child owns the sector (decision 4); say so in a comment where the bit is tested. Bitmap size is `(sectors_per_block.div_ceil(8) + 511) & !511` as computed at `:1513-1516`; reuse that rather than recomputing it. This is `no_std` and `no_main` guest code: no allocation, no panicking paths, `checked_*` arithmetic throughout, matching the surrounding style. Unit-test the pure parts in the vhd crate's own test module. |
| 12b | high | opus | none | Teach the `ImageFormat::Vhd` arm of `read_chain_virtual_cluster` (`src/crates/qcow2/src/lib.rs:8486`) to compose. Leave the fixed-VHD and `BlockLookup::Unallocated` paths exactly as they are -- `continue` is already correct for a differencing child's unallocated block (F3). In the `Allocated` case, when `state.disk_type == vhd::DISK_TYPE_DIFFERENCING`, use 12a's lookup to get the bitmap, walk the chunk's sectors, coalesce maximal runs of equal ownership, and serve each run: child-owned from this device at the data offset it already computes, parent-owned by recursing into `read_chain_virtual_cluster` with `chain_start + dev_offset + 1`, `chain_len - dev_offset - 1`, the run's own virtual offset and `buf.add(run_buf_off)`. **Model this on the extended-L2 subcluster path in the same function at `:8106-8130`** (decision 2, F5) -- same recursion arguments, same `remaining > 0` guard, same zero-fill when nothing remains. Non-differencing dynamic VHDs must take a textually unchanged path: this is the property 12d's first test pins. Preserve the existing sub-sector handling (`intra_sector != 0` → `read_offset_sectors`) for each run rather than assuming runs are sector-aligned in host space. |
| 12c | medium | opus | none | Relax the phase 4 refusal at `src/crates/qcow2/src/lib.rs:9528` per decision 5: refuse a differencing VHD only when no device follows it in the chain (`dev_idx + 1 >= device_count`). Leave the VHDX twin at `:9556` untouched -- that is phase 13. Rewrite the comment: it currently says "which nothing here can compose", which 12b makes false, and it must now state the surviving invariant (a differencing child with no parent device still reads as silently wrong data, which is what issue #547 is about) without citing a plan phase or step number, which this repo does not allow in landed code. Verify by inspection and say so in the commit message that no current caller can reach the lifted branch, because no host path builds a composing VHD chain (F8). |
| 12d | medium | sonnet | none | Rust unit tests for 12a-12c in the qcow2 crate's mock-chain harness. There are no `vhd_arm_*` tests today; `q1_arm_unallocated_descends_to_backing` (`:6591`) and `q1_arm_mixed_chunk_allocated_and_backing` (`:6621`) are the exemplars to copy, including how they build the synthetic devices. Cover, at minimum: a non-differencing dynamic VHD over a backing device reads identically before and after this phase (the regression guard -- write it first); an allocated block whose bitmap is all-zero reads wholly from the parent; all-ones reads wholly from the child; a mixed bitmap reads each sector from the right device, with the two devices carrying distinguishable bytes so an inverted polarity fails rather than passes (decision 4); an unallocated block still descends; and a differencing child with no following device still fails at `init_chain_states`. Build the chains synthetically -- do not add a fixture (decision 7). `make test-rust` must be clean; see `AGENTS.md` on the worktree target-ownership trap if cargo complains about `src/target`. |
| 12e | low | haiku | none | Housekeeping. Add a `CHANGELOG.md` entry stating that the guest can compose a differencing VHD against its parent and that no operation exposes it yet, so it is not a user-visible change. Amend this plan's *What the survey found* with anything 12a-12d discovered, and record any issue numbers filed. Do not add plan references to any source file or comment. |

## Risks and mitigations

| Risk | Mitigation |
|---|---|
| The bitmap bit polarity is inverted, and every test still passes because the fixtures are wholly child-owned | Decision 4 states the polarity, 12a's brief repeats it, and 12d's mixed-ownership test uses distinguishable bytes on the two devices specifically so an inversion fails. The management session checks that this test would fail if the bit test were negated -- reading the test is not the check; negating the bit and watching it fail is. |
| A non-differencing dynamic VHD's read path changes as collateral | 12b's brief requires the non-differencing path be textually unchanged, and 12d writes that regression test *first*. The whole Rust suite is expected zero-fail throughout. |
| The refusal lift makes a differencing VHD with an absent parent read as zeros -- issue #547 reopened by the phase meant to close it | Decision 5 ties the lift to a following device, 12c implements exactly that condition, and 12d tests the no-parent case still refuses. This is the one failure mode that would be silent in production, so it gets a test rather than an argument. |
| Scope creeps into phase 14 because composition is untestable end to end and that feels wrong | Decision 7 says so explicitly and the definition of done words its coverage claim to match. No step touches `src/vmm/` or `src/operations/`. |
| Guest memory grows and a large-cluster or many-device chain regresses | Decision 3 reuses buffers that already exist; the change adds no per-device allocation. 12a's brief names the constraint. The guest-op memory traps in `AGENTS.md` (`.bss` overflow, staging only the populated prefix) are worth re-reading before 12a starts. |
| Run coalescing has an off-by-one at a block or chunk boundary | 12d covers a chunk that starts mid-block and one that spans a block boundary, following `pls_arm_chunk_starting_at_cluster_boundary` (`:6232`) and `q1_arm_small_cluster_walk` (`:6747`) as the local precedent for those cases. |

## Definition of done

* `src/crates/vhd/src/lib.rs` contains a function that reads sector
  bitmap bytes, and `grep -c 'data_cache_buf' src/crates/vhd/src/lib.rs`
  returns more than the 8 occurrences it returns today -- that is, the
  allocated-but-unused cache identified in F6 is now used.
* A differencing VHD child over a parent device, with a block whose
  sector bitmap is mixed, reads each sector from the correct device.
  Demonstrated by a unit test that fails when the ownership bit test is
  negated; state in the commit message that the negation was run and
  what it printed.
* A non-differencing dynamic VHD over a backing device produces
  byte-identical output to `develop` at `c66f8b25`. This is the phase's
  regression invariant; state the two captured outputs in 12d's commit
  message.
* `init_chain_states` still refuses a differencing VHD that is the last
  device in its chain, and a unit test asserts it.
* `make test-rust` passes with zero failures, and the count is stated.
  The Python integration suite is unchanged and still passes -- it must
  be, since no command's output changes.
* No test in this phase depends on a testdata fixture. Coverage is
  crate-level by decision 7, and the definition of done says so rather
  than leaving the absence to be read as an oversight.
* No source file or comment added by this phase cites a plan phase,
  step or decision number, and the `init_chain_states` comment rewritten
  by 12c does not either.
* The master plan's phase 12 line references are corrected (F4) and its
  scale claim reconciled with F1, F3 and F5, in this plan's commit.
* `CHANGELOG.md` says the composition path exists and that no operation
  reaches it yet.

## Back brief

Before 12a starts, the implementing session states back:

1. Which function it will add to the vhd crate, what it returns, and
   why that shape rather than a whole-block bitmap (decision 1).
2. The exact condition it will write at
   `src/crates/qcow2/src/lib.rs:9528`, and why that condition cannot be
   reached by any current caller (decision 5, F8).
3. The bit polarity it will implement, and the test that would fail if
   it were inverted (decision 4).

**Gate before 12b.** 12b is the step that is cheap to propose and
expensive to redo: the run-coalescing loop's shape determines how the
VHDX arm is written in phase 13, and getting it wrong means writing it
twice. The implementing session proposes the loop's structure -- as
pseudocode or a diff of the arm alone -- and waits for agreement before
editing. Everything else in this phase proceeds without a gate.
