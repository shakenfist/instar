# Differencing phase 13: guest VHDX sector-bitmap read path

## Prompt

Plan phase 13 of `PLAN-differencing.md`, the second of the two guest
read-path phases: teach the guest to compose a differencing VHDX child
against its parent at logical-sector granularity, so that a
`PAYLOAD_BLOCK_PARTIALLY_PRESENT` block reads each sector from
whichever file owns it rather than failing the read.

Phase 12 landed the VHD half (`b4ae7fca`, #615). The two formats are
separate phases because they are not the same problem: VHD carries a
512-byte bitmap in front of every block, while VHDX keeps bitmaps in
their own 1 MiB blocks reached through interleaved BAT entries, counts
sectors in logical-sector units that may be 4096 bytes, and orders its
bitmap bits the other way round. Nothing on the host builds a composing
VHDX chain yet -- phase 14 is what changes that -- so this is a
crate-level change verified by crate-level tests. The phase plan is the
deliverable; implementation is a separate ask.

## Planning effort

**High.** Same reasoning as phase 12: a guest read path in `no_std`
code where a wrong answer is silently wrong data rather than a crash.
Two things make it no easier than phase 12 despite the precedent. The
bitmap is reached through a different structure, so the "find the
bitmap" half is new work rather than a port. And the three differences
from VHD -- bit order, sector unit, and a bitmap block that may be
legitimately absent -- are each individually invisible to a test that
happens to use the symmetric case, which is exactly the class of
mistake phase 12 spent two review rounds closing.

Review effort: **high**, for the same reason. The master plan does not
specify one for this phase.

## Scope

**In scope.**

* A sector-bitmap reader in `src/crates/vhdx/src/lib.rs`: resolve a
  payload block's interleaved sector-bitmap BAT entry, read bitmap
  bytes through the state's existing data cache, and coalesce runs of
  same-owner logical sectors.
* The `PAYLOAD_BLOCK_PARTIALLY_PRESENT` case of the VHDX arm of
  `read_chain_virtual_cluster` (`src/crates/qcow2/src/lib.rs:10269`):
  classify a chunk, serve a wholly-owned chunk with one read, and
  compose a mixed one.
* Separating `NotPresent` from `Zero` in that arm. They are currently
  one match arm, which is wrong for a differencing child -- see F3.
* Failing closed, on every path that could otherwise serve a
  parent-owned sector with no parent behind the child, exactly as the
  VHD arm does.
* Adding `vhdx-input` to the lint and unit-test feature matrix
  (issue #616), without which none of the above is compiled by either
  target.
* Crate-level tests, including a VHDX mock-chain harness.

**Out of scope.**

* Lifting `init_chain_states`' refusal of a differencing VHDX
  (`src/crates/qcow2/src/lib.rs:11298`). It stays unconditional, for
  the reason phase 12 established and issue #614 records: `device_count`
  bounds a flat array that may hold more than one chain, so "a device
  follows this one" does not mean "this child has a parent". Phase 14
  owns that, and needs #614 settled first.
* Any operation reaching the new path. No host change at all.
* `map`'s VHDX partial-present walk (`docs/map.md:238`). That is a
  different consumer of the same structure and a separate change; this
  phase must not silently make that limitation note false, and the
  definition of done says so.
* Integration tests and fuzzing (phases 15), documentation (phase 16).
* `PAYLOAD_BLOCK_UNDEFINED` / `UNMAPPED` semantics beyond what the
  current code already does. They are not differencing-specific.

## What the survey found

Surveyed on 2026-10-04 against `develop` at `758ffba8`, with phase 12
merged. Verified by running commands rather than by reading, where a
command existed.

**F1. The VHDX arm is compiled by neither `make lint` nor
`make test-rust` -- measured, not inferred.** Issue #616 says so;
this is the proof. With a deliberate type error injected into the VHDX
arm, `make lint` exits 0. Adding `vhdx-input` to the two feature lists
(`Makefile:536`, `scripts/check-rust.sh:134,140`) and re-running gives
`error[E0308]` naming the injected line. This is the same gap phase 12
found for VHD (its F12) and deliberately did not close for VHDX,
because this phase was going to rewrite that code.

**F2. Unlike the VHD arm, the VHDX arm already compiles clean.** With
`vhdx-input` added to both lists and no probe, `make lint` exits 0 with
no clippy findings, and `make test-rust` reports 2383 passed / 0 failed
-- identical to the baseline on `develop`. Phase 12's equivalent step
surfaced real clippy findings on first compile; this one will not. The
feature addition also buys **zero** new tests, because there is no
VHDX test in the qcow2 crate at all: `vhdx` appears ten times in that
11,000-line file and every occurrence is production code. So step 13a
is a one-line matrix change that makes later steps' code visible, not a
cleanup job, and it provides no coverage by itself.

**F3. The VHDX arm conflates "not present" with "explicitly zero", and
that is wrong for a differencing child.** At
`src/crates/qcow2/src/lib.rs:10275` the arm reads:

```rust
Some(VhdxBlockLookup::NotPresent) | Some(VhdxBlockLookup::Zero) => {
    continue;
}
```

and `VhdxBlockLookup::NotPresent`'s own doc comment says "(reads as
zero)". For a file with no parent the two are indeed the same answer,
which is why this has never been wrong. For a differencing child they
are opposites: `PAYLOAD_BLOCK_NOT_PRESENT` means the data lives in the
parent, and `PAYLOAD_BLOCK_ZERO` means this block is zeros and the
parent must *not* be consulted. Composing without separating them would
read the parent's data where the child says zero. The master plan does
not mention this; it is this survey's main find, and it is a
correctness item rather than a structural one.

**F4. `PARTIALLY_PRESENT` is already a deliberate, documented refusal,
and it is the phase's subject.** `block_lookup`
(`src/crates/vhdx/src/lib.rs:1984`) returns `None` for state 7, with a
comment saying it is a backstop for a caller that skipped the
`has_parent` check. The arm turns `None` into `return false`. So the
starting position is fail-closed rather than silently-wrong, which is a
better starting point than the VHD arm had.

**F5. `VhdxState` already carries everything the reader needs except
the bitmap itself.** `logical_sector_size` (512 or 4096, validated at
`src/crates/vhdx/src/lib.rs:1818`), `block_size`, `chunk_ratio`
(computed at `:1823` as `(2^23 * logical_sector_size) / block_size`),
`total_bat_entries`, `bat_offset`, and `has_parent` are all fields of
the struct at `:1641`. `block_lookup` already computes the interleave
correction, `sb_entries_before = block_index / chunk_ratio`, at
`:2001`. What is missing is reading the SB entry rather than skipping
past it.

**F6. The vhdx crate has an allocated, never-used data cache -- the
same free resource phase 12 found for VHD.** `data_cached_sector` and
`data_cache_buf` are fields of `VhdxState` (`:1669-1670`), are assigned
at init (`:1864-1865`), and are read nowhere: `grep -c data_cache_buf
src/crates/vhdx/src/lib.rs` returns 4, all declaration or assignment.
The VHD crate's count went from 8 (all unused) to 11 (used) over phase
12. Bitmap reads can use this cache, adding no guest memory, exactly as
phase 12's did.

**F7. The format differences from VHD are already pinned against real
oracles, and so is a fixture generator.** Phase 1 measured them
(`docs/plans/PLAN-differencing-phase-01-pin.md`):

* The VHDX sector bitmap is **least significant bit first**, "the
  opposite of VHD" (`:1463`). VHD is `bit (7 - i % 8)`; VHDX is
  `bit (i % 8)`.
* A bit counts one **logical sector**, which may be 4096 bytes, not a
  fixed 512 as in VHD.
* A sector-bitmap block is 1 MiB, hence `chunk_ratio` payload blocks
  per bitmap block.
* SB BAT entry states are `SB_BLOCK_NOT_PRESENT` (0) and
  `SB_BLOCK_PRESENT` (6) (`:430-431`).
* An SB entry "may only be `SB_BLOCK_NOT_PRESENT` if no associated
  payload block is `PAYLOAD_BLOCK_PARTIALLY_PRESENT`" (`:878-885`), so
  a `PARTIALLY_PRESENT` block whose bitmap block is absent is a
  malformed image.
* `vhdx_sector_bitmap_block()` and `patch_vhdx_child()` at `:1810` and
  `:1819` build such an image in Python; `instar-testdata` carries the
  resulting `vhdx-diff-child.vhdx` / `vhdx-diff-parent.vhdx` pair.

Set bit means the sector lives in this file, same polarity as VHD.

**F8. Neither `SB_BLOCK_NOT_PRESENT` nor `SB_BLOCK_PRESENT` exists as a
constant in the vhdx crate.** `grep -n 'SB_BLOCK' src/crates/vhdx/src/lib.rs`
returns nothing, while the six `PAYLOAD_BLOCK_*` constants are defined
at `:197-207`. The crate's BAT walkers skip SB entries by position
without ever looking at their state.

**F9. Phase 12's final shape differs from its mid-phase shape, and
phase 13 should copy the final one.** Review round 3 (`4a7a143f`)
removed the `read_cluster_sectors` / `read_offset_sectors` branch from
`read_vhd_child_runs`: every child run now goes through
`read_offset_sectors` with the caller's scratch, because the aligned
branch still took the 64 KiB-stack path whenever a run was not a whole
number of device sectors. A VHDX reader written by copying the
mid-phase VHD code would reintroduce that. The same round renamed the
regression guard to `vhd_arm_dynamic_reads_as_a_plain_dynamic_vhd`.

**Corrections made at source.** The master plan's phases 12-and-13
bullet cites pre-phase-12 line numbers throughout
(`read_chain_virtual_cluster` at `:7930`, the format dispatch at
`:8486`, `ChainStates` at `:9385`, the subcluster path at
`:8106-8130`, the refusals at `:9528` and `:9556`). Phase 12 added
about 2,800 lines to that file and every one of them is now wrong. The
planning commit corrects the two a phase 13 reader will follow -- the
VHDX refusal, now `:11298`, and the VHDX arm, now `:10269` -- and
marks the rest as pre-phase-12. No later step needs to redo this.

Nothing else the master plan says about phase 13 was found to be false.

## Decisions

1. **Mirror phase 12's three-part shape rather than inventing one.**
   A lookup that resolves where the bitmap lives, a run coalescer over
   the bitmap, and a classify-then-serve arm. Phase 12 arrived at this
   shape under two review rounds and it is now the house pattern for
   this exact problem; a second, different shape in the same function
   would be worse than a slightly imperfect fit. Concretely:
   `differencing_block_lookup` → `sector_bitmap_lookup`,
   `read_sector_bitmap_run` → `read_vhdx_sector_bitmap_run`,
   `classify_vhd_chunk_ownership` → `classify_vhdx_chunk_ownership`,
   `read_vhd_child_runs` → `read_vhdx_child_runs`.

2. **Do not generalise phase 12's VHD code into shared helpers.** The
   differences are not parameters: a different structure locates the
   bitmap, the bit order is reversed, the sector unit is variable, and
   the bitmap block can be legitimately absent. A shared helper would
   carry four conditionals and would make each format's reader harder
   to check against its own spec. The coalescer is the one piece that
   looks genuinely common -- `coalesce_ownership_run`
   (`src/crates/vhd/src/lib.rs:1401`) already takes a closure
   `FnMut(u32) -> Option<u8>` returning a bitmap byte -- and even there
   the bit order differs, so the VHDX reader passes its own
   bit-extraction. Revisit sharing in phase 15, with both readers
   written and both test suites available to prove the refactor
   invisible, not now.

3. **Separate `NotPresent` from `Zero` in the arm, for every VHDX, not
   only differencing ones (F3).** `Zero` zero-fills the chunk and stops;
   `NotPresent` descends to the next device. For a non-differencing
   VHDX this is behaviour-identical, because a chain never has a device
   behind a parentless image and both answers reach the zero-fill tail.
   The alternative -- gate the split on `has_parent` -- keeps a second
   code path alive to no purpose and leaves the wrong doc comment in
   place. The regression test must prove the identical-behaviour claim
   rather than assert it.

4. **Fail closed at the bottom of a chain on all three parent-owned
   paths**, as phase 12 does: `NotPresent` with no device behind a
   child whose `has_parent` is set, a wholly parent-owned
   `PARTIALLY_PRESENT` chunk, and the parent-owned runs of a mixed one.
   Use `devices_behind()` (`src/crates/qcow2/src/lib.rs:9419`), which
   phase 12 added for exactly this and which already fails closed on an
   impossible offset.

5. **A `PARTIALLY_PRESENT` block whose SB entry is `SB_BLOCK_NOT_PRESENT`
   fails the read.** F7 records that the spec forbids the combination.
   The alternative readings -- treat the absent bitmap as all-child or
   all-parent -- each invent an answer for a malformed image, and
   inventing answers for malformed images is what issue #547 was. The
   same applies to an SB entry in any state other than 0 or 6.

6. **Refuse a chunk that reaches past the end of the block its bitmap
   describes**, as the VHD arm does. This is the asymmetry phase 12's
   F13 recorded: the older non-differencing path does not cap at the
   block boundary and issue #613 tracks it. Phase 13 adds no new
   instance of that defect and does not fix the old one.

7. **Test at crate level with a mock chain; no testdata fixture.** Same
   as phase 12's decision 7 and for the same reason: no host path
   builds a composing VHDX chain until phase 14, so an integration test
   cannot reach this code. Phase 15 owns the fixture-based
   cross-validation. The mock harness should be a VHDX sibling of
   `run_vhd_chain_read`, not a generalisation of it -- see decision 2.

8. **The bitmap fixture builder takes an explicit logical sector
   size and an explicit bit list.** Phase 12's review found that
   single-shape fixtures hide whole classes of mistake: every early
   fixture had a one-byte bitmap, so no arm test crossed a bitmap byte,
   and every fixture had one block, so no test resolved a BAT entry for
   block 1. Build the general fixture first this time.

## Step plan

| Step | Effort | Model | Isolation | Brief for sub-agent |
|------|--------|-------|-----------|---------------------|
| 13a | low | sonnet | none | Add `vhdx-input` to the two feature lists that gate the qcow2 crate's optional input readers: the `cargo test --release -p qcow2` line in `Makefile`'s `test-rust` target (`:536`), and both `cargo clippy -p qcow2` invocations in `scripts/check-rust.sh` (`:134` and `:140`, the `fix` and check branches). The lists currently end `dmg-input,vhd-input`. Demonstrate the change reaches the code by injecting a deliberate type error into the VHDX arm of `read_chain_virtual_cluster` (`src/crates/qcow2/src/lib.rs:10269`), confirming `make lint` fails with `error[E0308]` naming that line, and removing the probe; state in the commit message that you did this and what it printed. F2 established that no clippy findings and no new tests follow, so do not expect either -- if clippy *does* report something, that is new since 2026-10-04 and worth saying so. Closes issue #616; use the `Fixes #616` keyword. |
| 13b | high | opus | none | Add the sector-bitmap reader to `src/crates/vhdx/src/lib.rs`. Three pieces. (1) `pub const SB_BLOCK_NOT_PRESENT: u64 = 0;` and `pub const SB_BLOCK_PRESENT: u64 = 6;` beside the `PAYLOAD_BLOCK_*` constants at `:197-207` (F8: neither exists today). (2) A `sector_bitmap_lookup` method on `VhdxState` (`:1641`) that, for a virtual offset, returns the host byte offset of the block's sector-bitmap block and the index of the first logical sector of the chunk within it, or `None`. The BAT index of the SB entry for payload block `b` is `(chunk_ratio + 1) * (b / chunk_ratio) + chunk_ratio`; `block_lookup` at `:2001` already computes the payload side of the same interleave and is the model to follow. Validate the SB entry's state: `SB_BLOCK_PRESENT` proceeds, anything else returns `None` (decision 5). Bit `n` of the bitmap block covers logical sector `n` *of the chunk group*, not of the block, so the sector index is relative to the group's first block. (3) A run coalescer. Read bitmap bytes through `data_cached_sector` / `data_cache_buf`, which are allocated and currently unused (F6) -- follow `read_u64_le_cached`'s cached-sector pattern. **The bit order is the opposite of VHD**: sector `i` is bit `i % 8` of byte `i / 8`, least significant first, measured in phase 1 (F7). A set bit means the sector lives in this file. A sector is `logical_sector_size` bytes, which is 512 **or 4096** -- not a constant. `coalesce_ownership_run` in the vhd crate (`src/crates/vhd/src/lib.rs:1401`) is the shape to copy, not to call (decision 2). Unit-test the coalescer as a pure function with both sector sizes, a bitmap spanning several bytes, and runs that start and end mid-byte. |
| 13c | high | opus | none | Teach the VHDX arm of `read_chain_virtual_cluster` (`src/crates/qcow2/src/lib.rs:10269`) to compose. Two separable changes; make them two commits if it reads better. First, split the `NotPresent | Zero` arm (F3, decision 3): `Zero` zero-fills `chunk_size` bytes and returns true, `NotPresent` continues to the next device, and for a child whose `has_parent` is set with no device behind it, `NotPresent` fails closed via `devices_behind()` (`:9419`, decision 4). Fix `VhdxBlockLookup::NotPresent`'s doc comment, which says "(reads as zero)". Second, add the `PARTIALLY_PRESENT` case: `block_lookup` (`src/crates/vhdx/src/lib.rs:1984`) returns `None` for state 7 today, so it needs a new `VhdxBlockLookup` variant carrying the block's file offset; classify the chunk with 13b's reader, serve an all-child chunk with the existing single read, fill an all-parent chunk by recursing into the chain, and for a mixed chunk fill from the parent and then overwrite the child's runs. Refuse a chunk reaching past the block boundary (decision 6). **Read every child run through `read_offset_sectors` with the caller's scratch, never `read_cluster_sectors`** -- phase 12's third review round removed exactly that branch because the aligned path still put a 64 KiB buffer on the guest stack whenever a run was not a whole number of device sectors (F9); `read_vhd_child_runs` on `develop` is the correct model, `ed4f2669`'s version is not. |
| 13d | high | opus | none | Crate-level tests in the qcow2 crate's test module. There is no VHDX harness there at all (F2), so build one: a VHDX sibling of `run_vhd_chain_read` and a fixture builder that takes the logical sector size, the per-block payload states, and an explicit list of child-owned sector indices (decision 8 -- build the general builder first; phase 12 paid two review rounds for not doing so). The mock device must refuse a read at any sector size but its own, as the VHD mock does, or a whole class of sector-size mistake is invisible. Cover, at minimum: an all-child and an all-parent `PARTIALLY_PRESENT` block; a mixed one; the same mixed case at `logical_sector_size` 4096; a run crossing a bitmap byte boundary; a block that is not the first in its chunk group, so the SB interleave arithmetic is exercised; `Zero` versus `NotPresent` giving different answers for a child with a parent behind it; each of the three fail-closed paths at the bottom of a chain; a `PARTIALLY_PRESENT` block with `SB_BLOCK_NOT_PRESENT`; and a chunk crossing a block boundary. Add a regression test proving decision 3's identical-behaviour claim for a non-differencing VHDX, comparing against `develop` at `758ffba8`. Prove each test by mutation rather than by reading it, keep the mutations in a runnable script, and state the count in the commit message -- phase 12 ended at fifteen and two of its survivors were real findings. The bit-order mutation (`i % 8` to `7 - i % 8`) and the sector-unit mutation (`logical_sector_size` to a literal 512) are the two that matter most. |
| 13e | medium | sonnet | none | Bookkeeping. `CHANGELOG.md`: a sibling of the phase 12 entry at `:12` saying the guest chain walker composes a differencing VHDX, and that no operation reaches it yet because `init_chain_states` still refuses every differencing VHDX. Record what the survey found at its source in `docs/plans/PLAN-differencing.md` if 13b-13d falsify anything this plan claims. Confirm `docs/map.md:238`'s VHDX partial-present limitation note is still true -- `map` is a different consumer and this phase does not change it -- and leave it alone if so. Do not touch `docs/` otherwise: phase 16 owns the documentation, and phase 14 owns the user-visible change. |

## Risks and mitigations

* **The bit order is written the VHD way.** This is the single most
  likely defect, it is invisible to any symmetric fixture (`0x00`,
  `0xFF`, or a palindromic byte), and it produces plausible data rather
  than an error. *Mitigation:* 13d's fixtures use asymmetric bytes, and
  the mutation set includes the bit-order flip specifically. The
  implementer checks the measured statement at
  `docs/plans/PLAN-differencing-phase-01-pin.md:1463` rather than
  reasoning from the VHD code beside them.
* **`logical_sector_size` 4096 is treated as 512.** Every bitmap
  arithmetic error of this kind still works at 512. *Mitigation:* 13d
  requires the mixed case at 4096, and a mutation replacing
  `logical_sector_size` with a literal 512 must fail a test. Phase 12
  hit precisely this: its first sector-size mutation survived because
  no test used any sector size but 512.
* **The SB interleave is computed for block 0 and never for any
  other.** `(chunk_ratio + 1) * (b / chunk_ratio) + chunk_ratio`
  degenerates to `chunk_ratio` when `b < chunk_ratio`, so a fixture
  with few blocks exercises nothing. *Mitigation:* 13d requires a
  block outside the first chunk group. Phase 12's equivalent gap --
  every fixture a single block -- was found by review, not by the
  phase.
* **The `NotPresent` / `Zero` split changes non-differencing reads.**
  It should not, and decision 3 rests on that. *Mitigation:* 13d's
  regression test compares against `develop` at `758ffba8`; the
  implementer states the two captured outputs in the commit message.
* **The arm is written against a reader that is never compiled.** 13a
  is first for this reason, and F1 proves it is load-bearing rather
  than tidy-mindedness: without it, 13b-13d can be committed broken and
  CI stays green.

## Definition of done

* `make lint` and `make test-rust` compile the VHDX arm. Falsifiable:
  injecting a type error at `src/crates/qcow2/src/lib.rs:10269` makes
  `make lint` fail, where on `758ffba8` it exits 0. Issue #616 is
  closed by the `Fixes` keyword in 13a's pull request body, not only in
  a commit message.
* `grep -c 'data_cache_buf' src/crates/vhdx/src/lib.rs` returns more
  than the 4 it returns today -- that is, F6's allocated-but-unused
  cache is used.
* `grep -c 'SB_BLOCK_PRESENT' src/crates/vhdx/src/lib.rs` is non-zero,
  and no literal `6` stands in for it at a use site.
* A differencing VHDX child over a parent device, with a
  `PARTIALLY_PRESENT` block whose sector bitmap is mixed, reads each
  logical sector from the correct device, at both 512 and 4096. A
  mutation reversing the bit order fails a test, and a mutation
  replacing `logical_sector_size` with 512 fails a different one.
  State in the commit message that both were run and what they printed.
* A `PARTIALLY_PRESENT` block whose SB entry is `SB_BLOCK_NOT_PRESENT`
  fails the read; so does an SB entry in any state but 0 or 6.
* `PAYLOAD_BLOCK_ZERO` and `PAYLOAD_BLOCK_NOT_PRESENT` produce
  different results for a differencing child with a device behind it,
  and identical results for a VHDX with nothing behind it. Both are
  asserted by tests, not argued in a comment.
* A non-differencing VHDX over a backing device produces byte-identical
  output to `develop` at `758ffba8`; the two captured outputs are in
  13d's commit message.
* `init_chain_states` still refuses every differencing VHDX
  unconditionally, and a test asserts the refusal fired for that reason
  -- by the status reaching `send_error`, not by the return value
  alone. Phase 12's `vhd_init_refuses_a_differencing_child_and_admits_a_dynamic_one`
  is the model, including its positive control.
* `make test-rust` passes with zero failures and the count is stated,
  against the 2383 this survey measured on `758ffba8`.
* No test in this phase depends on a testdata fixture.
* No source file or comment added by this phase cites a plan phase,
  step or decision number. Falsifiable:
  `git diff 758ffba8..HEAD -- 'src/*' | grep '^+' | grep -iE 'PLAN-[a-z0-9-]+\.md|decision [0-9]|phase 1[0-9]|13[a-e]'`
  is empty.
* `docs/map.md:238`'s VHDX partial-present limitation is either still
  true or updated; the pull request says which.
* `CHANGELOG.md` says the VHDX composition path exists and that no
  operation reaches it yet.

## Back brief

Before implementing, confirm back to me:

1. **The three VHDX-versus-VHD differences, in your own words**, and
   where in 13b each one is handled: bit order, sector unit, and the
   bitmap block's location and possible absence. Phase 12's review
   rounds were largely about input shapes nobody had thought of; the
   cheapest place to catch the equivalent here is before any code is
   written.
2. **Whether decision 2 still looks right once you have read both
   crates' bitmap code.** If the coalescer really is shareable with one
   closure and no conditionals, say so before writing a second copy --
   that is the one decision here a reviewer is most likely to argue
   with, and it is much cheaper to change now than after 13d's tests
   are written against two readers.
3. **The SB BAT index formula, checked against a worked example** with
   `chunk_ratio` 4096 and a block index above 4096. Get this wrong and
   every test using a small fixture still passes.

Gate: do not start 13d until 13b and 13c are both committed. Phase 12
wrote its harness against mid-phase code and the third review round
changed the production shape underneath it; the tests are cheaper to
write once the shape has settled.
