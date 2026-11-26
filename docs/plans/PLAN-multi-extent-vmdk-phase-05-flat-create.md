# Multi-extent VMDK phase 5: host-only flat create

## Status: Planned

Master plan: `PLAN-multi-extent-vmdk.md`.

## Planning effort

Medium, as the master plan's Planning effort paragraph names it.
Phase 4 pinned and shipped every byte of the descriptor this phase
writes, and the host already has a working single-extent precedent for
the whole shape of the job -- `run_create_vmdk_flat` opens files,
`ftruncate`s an extent, writes a descriptor, `fsync`s both and cleans
up on failure, all without the guest. This phase does that N times.

Two things kept it above mechanical, and both are decisions rather
than code. The operator's answer to open question 4 makes instar's
split create refuse something qemu accepts, which means the phase has
to draw a line between the path the user typed and the paths instar
derived, and defend it in the documentation. And the survey found the
existing cleanup path deletes a file it did not create, which this
phase would otherwise multiply by sixty-four.

## Decisions already taken by the operator

From the master plan, resolved 2026-11-16: sequential extent rotation
rather than simultaneous output devices (question 1), and the read-side
ceiling inside this plan as phase 3 (question 2).

Question 1 does not bind this phase. Rotation is a mechanism for
getting *format emission* out of the guest one extent at a time; a flat
extent has no format to emit, so this phase writes every byte on the
host and never rotates anything. That is the whole reason it can land
before phases 6 to 8.

Question 2 binds it hard, in a way the master plan's phase 5 section
does not anticipate. See decision 2.

Question 3 (`ddb.*` lines) was adopted by phase 4 and is already in the
emitter this phase calls; nothing here revisits it.

**Question 6 is resolved by adoption.** It asked whether flat create is
host-only. The survey confirms the seam exists and is exactly where the
master plan expected: `run_create` returns early into
`run_create_vmdk_flat` at `src/vmm/src/main.rs:21559`, before any VM is
launched, and the VMM already links the `vmdk` crate and calls
`vmdk::build_flat_descriptor` directly at `:17049`. Host-only is not a
choice this phase has to make; it is what the code does.

**Questions 4 and 5 were resolved by the operator on 2026-11-26**, as
this phase was planned, and both answers are recorded in the master
plan's open-questions section as part of the planning commit:

* **Question 4 -- extent paths and what is refused:** derive strictly
  from the output argument, refuse a derived extent that already
  exists, and keep overwriting the descriptor the user named. Decision
  1.
* **Question 5 -- maximum extent count:** refuse above
  `MAX_EXTENTS` (64 extents, 128 GiB) with a message naming the limit
  and the size that reached it, before any file is opened. Decision 2.

## Scope

In:

* `instar create -f vmdk -o subformat=twoGbMaxExtentFlat`: N sparse
  extent files of the lengths `split_layout` gives, plus the descriptor
  `build_split_descriptor` emits. Host-only.
* The extent **path set**: a generalisation of the existing
  `vmdk_flat_extent_path` that yields N paths and the decomposed stem
  the phase 4 emitter takes, carrying forward the name-safety refusal
  that function already enforces.
* Three refusals, all before any file is opened: a size needing more
  than `MAX_EXTENTS` extents, a size of zero, and a derived extent path
  that already exists.
* Failure cleanup that removes only what this run created. This is a
  fix to the existing single-extent path as well; see decision 5.
* `docs/create.md`, `docs/output-formats.md` and
  `docs/vmdk/vmdk-extents.md`.

Out, explicitly:

* **`twoGbMaxExtentSparse` create.** It needs format emission inside
  the guest and therefore phases 6 to 10. `create` must refuse it with
  a message that does not promise a date, and the refusal is a
  definition-of-done item.
* **`convert -O vmdk --subformat twoGbMaxExtent*`.** Phase 11. The
  convert subformat validator at `src/vmm/src/main.rs:16804` is not to
  be widened, and `git diff` proving it unchanged is a
  definition-of-done item.
* **`measure`.** Phase 12.
* **Any ABI change.** `CreateConfig.vmdk_subformat` stays at three
  values (`src/shared/src/lib.rs:2983`). A host-only path never
  populates a `CreateConfig`, so there is nothing to extend. `git
  diff --stat` listing no file under `src/operations/` is a
  definition-of-done item.
* **Raising `MAX_CHAIN_EXTENTS`.** Its own doc says lifting it means
  moving the guest config region. Not this phase, and the operator
  declined it as phase 5's answer to question 5.
* **Retrofitting `ddb.*` onto the existing subformats.** Already filed
  by phase 4 as #964.

## What the survey found

The master plan's phase 5 section is accurate about the shape of the
work and the seam it plugs into. Three of its surrounding claims are
stale, and one of the two questions it defers had already been
answered by code that landed after it was written.

**1. Open question 5's framing is foreclosed by phase 3.** The question
offers a choice between matching qemu's extent ceiling and imposing
one. Phase 1 had already measured that qemu has no ceiling (1000
extents at 2000 GiB, 16384 at 32 TiB, no refusal at 1 PiB), which the
question records. What it does not record, because phase 3 had not
landed, is that `shared::MAX_CHAIN_EXTENTS = 64`
(`src/shared/src/lib.rs:5258`) is a hard read-side cap: the guest's
extent table is a fixed array in a page of its own, and
`layout_descriptor_extents` refuses a descriptor declaring more than 64
extents rather than reading part of the image
(`src/vmm/src/main.rs:4934`). At qemu's 2 GiB extent size that is
128 GiB. Writing past it produces an image instar's own reader refuses,
which would also leave the differential fuzzer blind above the cap --
and reading its own output back was open question 2's stated reason for
doing the read side first.

Phase 4 reached the same conclusion from the other side and wrote it
into the emitter's own documentation at
`src/crates/vmdk/src/lib.rs:484-488`: "a caller that wants its own
output readable must bound `extent_count` at `MAX_EXTENTS`". So the
bound this phase enforces was already specified; it simply had nowhere
to be enforced until there was a caller.

**2. Open question 4's recommendation conflicts with instar's own
documented create contract.** The question recommends refusing if any
target already exists, and reports phase 1's measurement that qemu
instead truncates a pre-existing extent in place on all 80 builds. What
it does not weigh is that `instar create` already promises the same
thing for its own output: `CreateArgs::filename`'s help text at
`src/vmm/src/main.rs:9831` reads "Overwrites if it already exists
(matches qemu-img)", and `write_vmdk_flat` implements it with
`create(true).truncate(true)` at `:22695`. Refusing everything would
make the split subformat the one create path that does not honour that
promise. The operator's resolution splits the difference along the line
of what the user actually named, which decision 1 states.

**3. The extent-name safety predicate already exists.** Phase 4's
review round 2 declined an extent-name predicate and recorded it as a
note for this phase. The survey found the host already has one:
`vmdk_flat_extent_path` (`src/vmm/src/main.rs:17011`) refuses a derived
name that is not UTF-8 or that contains `"`, CR or LF, with a message
naming the operation, because a descriptor cannot quote such a name
unambiguously. Phase 4's emitter documentation points at it as "the
rule to follow" (`src/crates/vmdk/src/lib.rs:470`). This phase
generalises that function rather than writing a second predicate, and
the declined review item is thereby answered by reuse.

**4. A defect in the code this phase extends.** `write_vmdk_flat`
pushes each path onto `opened` immediately after opening it, and
`run_create_vmdk_flat` removes every path in `opened` if the write
fails (`src/vmm/src/main.rs:22663-22673`). The descriptor is opened
first, with `truncate(true)`. So a `create` that fails while opening
the extent -- a permissions error, a full filesystem -- truncates a
pre-existing file the user named *and then deletes it*, where qemu-img
would have left the truncated file in place. It is small, it is
shipping today for `monolithicFlat`, and this phase would otherwise
inherit it with sixty-four times the blast radius. Decision 5 fixes it
in the shared helper rather than filing it, and says why.

**5. Everything else the section claims holds.** `split_layout`,
`SplitLayout::sectors_of_extent`, `build_split_descriptor` and
`parse_descriptor_extents` are all `pub` in `src/crates/vmdk/src/lib.rs`
and the VMM already links that crate. The emitter formats `-s%03d` and
`-f%03d` names itself from a decomposed stem and picks the `FLAT`
keyword and its trailing ` 0` offset from `SplitLayout::kind`
(`:508-536`), so this phase supplies paths and lengths and emits no
descriptor text of its own. `scripts/create-vmdk-flat-testdata.sh`
already builds a `twoGbMaxExtentFlat` image and deletes its extents, as
phase 2 left it, which is the generator the tests extend.

**Corrected at source** in this planning commit, so a later reader does
not have to find these out again:

* Open questions 4 and 5 record the operator's resolutions, and why the
  recommendations as drafted no longer hold.
* Questions 3 and 6 had no resolution recorded although both were
  settled by adoption -- 3 by phase 4's shipped emitter, 6 by this
  phase. Both now say so, and the section's preamble no longer claims
  questions 3 to 6 are open.
* Success criterion 5 ("The size at which instar refuses a multi-extent
  image matches qemu-img's") is rewritten. It rests on the same
  `%03d`-implies-999 premise phase 1 disproved, and the operator has
  now chosen a limit qemu does not have.
* Success criterion 1's byte-identity claim is bounded to the sizes
  instar accepts.

## Decisions

1. **Refuse a derived extent that already exists; keep overwriting the
   named descriptor.** The user typed one path. `out.vmdk` is theirs to
   lose and create has always said so; `out-f001.vmdk` through
   `out-f064.vmdk` are instar's invention, and truncating sixty-four
   files nobody named is not a thing to do silently in a tool whose
   threat model assumes hostile input. The refusal names the first
   offending path and says nothing has been written. This is a
   documented divergence from qemu-img, which truncates all of them.

   *The cost, stated plainly:* a user who re-runs a failed create in
   the same directory now has to remove the extents themselves, where
   qemu-img would have overwritten them. That is the price of the
   guarantee, and `docs/create.md` says so in those terms rather than
   presenting the refusal as unambiguously better.

2. **Bound the extent count at `MAX_EXTENTS` (64), which is 128 GiB.**
   Refuse before any file is opened, with a message naming the limit,
   the extent count the size would need, and the size itself. 128 GiB
   exactly is 64 extents and is accepted; one byte more needs 65 and is
   refused. The bound is instar's, not qemu's, and the message and the
   documentation both say so -- it exists because the guest's extent
   table is a fixed array, and an image instar cannot read back is not
   output worth writing.

3. **Refuse a zero virtual size.** `split_layout(0)` yields zero
   extents, and `build_split_descriptor` then emits a descriptor with no
   extent lines at all, which `parse_descriptor_extents` refuses as
   `NoExtents`. Phase 4's emitter doc makes this the caller's bound.
   Refuse it with its own message rather than letting it reach the
   emitter.

4. **Generalise `vmdk_flat_extent_path`, do not duplicate it.** One
   function yields the decomposed stem the emitter wants and the N
   derived paths, and carries the existing UTF-8-and-no-quote refusal
   unchanged. `monolithicFlat` keeps using it with its `-flat` suffix.
   Writing a second path builder would leave two predicates to keep in
   step, which is how the `ddb.*` divergence in #964 happened.

5. **Fix the cleanup defect in place, in the shared helper.** Track
   whether this run created each file, and remove on failure only the
   ones it did. This changes shipped `monolithicFlat` behaviour: a
   failed create no longer deletes a pre-existing descriptor it
   truncated. That is a bug fix, not a format change, and it is in
   scope because this phase extends the exact function that has the
   defect and would multiply it by sixty-four. It gets its own commit
   and its own test so it is revertable independently of the phase.

   *The argument against, which the operator may prefer:* the skill
   that planned this phase says to record a surveyed bug as an issue
   rather than fix it. The counter is that leaving it would mean
   shipping the same defect twice over in the same release, in code
   written in the same week, and the correct-fixes guidance in this
   repository prefers fixing the cause where it lives. This is the
   first back-brief item.

6. **The extents are written before the descriptor, and every extent
   is `fsync`ed before the descriptor is.** A failure part-way must
   never leave a descriptor pointing at a set that does not match it,
   which is the master plan's success criterion 6. A descriptor that
   does not exist yet cannot lie.

7. **`twoGbMaxExtentSparse` is refused by `create` with a message that
   promises nothing.** It names the subformat as not supported for
   `create` and lists what is. No phase number, no plan file, no "yet"
   that implies a date -- this repository's convention is that landed
   code does not cite plan phases.

## Step plan

Sequential. Every step writes to the same worktree, and steps 5b
onward consume the previous step's interface, so none of these may run
in parallel.

| Step | Effort | Model | Isolation | Brief for sub-agent |
|---|---|---|---|---|
| 5a. The path set and the three refusals | high | opus | worktree | Generalise `vmdk_flat_extent_path` (`src/vmm/src/main.rs:17011`) into a function that takes the output path and a `SplitLayout` and returns the decomposed stem (`prefix`, `postfix`) that `vmdk::build_split_descriptor` takes plus the N derived extent paths, keeping its existing UTF-8 / no-`"`-CR-LF refusal verbatim and leaving `monolithicFlat`'s `-flat` call site working. Add the three refusals of decisions 1, 2 and 3, all of them before any file is opened: more than `vmdk::MAX_EXTENTS` extents, a zero size, and a derived extent that already exists. Match the wording shape of the read-side refusal at `:4934`. Read phase 4's emitter doc at `src/crates/vmdk/src/lib.rs:470-495` first -- it specifies these bounds as the caller's. Unit tests for each refusal and for the name derivation at 1, 2, 64 and 65 extents. Commit subject: "Derive a split VMDK's extent paths." |
| 5b. The writer | high | opus | worktree | Add the host-only writer beside `write_vmdk_flat` (`src/vmm/src/main.rs:22683`): for each extent, open and `ftruncate` to `layout.sectors_of_extent(i) * 512`; then write the descriptor from `vmdk::build_split_descriptor` using 5a's stem; `fsync` every extent before the descriptor, then the descriptor (decision 6). Follow the existing function's idioms exactly -- `mode(0o644)`, the measure-then-write two-call pattern at `:17049`, and the `Result` error strings prefixed `create:`. Do **not** change the convert path. Commit subject: "Write a split flat VMDK on the host." |
| 5c. Cleanup that removes only what it created | high | opus | worktree | Decision 5. Change the `opened` list in `run_create_vmdk_flat` / `write_vmdk_flat` (`:22659-22673`) to record whether this run created each file, and remove on failure only those. Both the single-extent and split paths use it. Add a test that a failure after a pre-existing descriptor was truncated leaves that file present. Keep this in its own commit, touching nothing else, so it can be reverted alone. Commit subject: "Delete only the files create itself made." |
| 5d. CLI wiring | medium | sonnet | worktree | Extend `is_vmdk_flat_create` (`src/vmm/src/main.rs`, two lines) and `create`'s subformat validation to accept `twoGbMaxExtentFlat` and route it to 5b. Refuse `twoGbMaxExtentSparse` per decision 7. Find every create-side subformat validation site -- there is more than one, and `:18312` and `:18644` map subformat strings to `vmdk_subformat` numbers for other subcommands, which must not change. Leave the convert validator at `:16804` untouched. Commit subject: "Accept twoGbMaxExtentFlat in create." |
| 5e. Tests against the real oracle | high | opus | worktree | Integration tests under `tests/`. The descriptor oracle is already committed: phase 1's pinned cases in `tests/golden/qemu-create-pins.json`, reachable through `tests/helpers/qemu_pins.py`, and the static per-version `qemu-img` builds in `instar-testdata`. The pinned flat cases are `vmdk-multi-flat-{1,2,4,5,21,2049}`, named in GiB. **Five of the six are comparable and the sixth is not:** 2049 GiB needs 1025 extents, so decision 2 refuses it. Do not iterate the case list blindly -- compare 1, 2, 4, 5 and 21, and use 2049 as the refusal test instead, which makes it a pinned witness that qemu writes a size instar declines. Assert instar's end-to-end `create` descriptor is byte-identical to qemu's for the five comparable sizes with `$CID` substituted, and that every extent file exists with the length the pin implies. Extend `scripts/create-vmdk-flat-testdata.sh`'s split-flat case rather than writing a new generator. Remember that `tests/` is copied to `/tmp` for the packaged run, so no test may resolve a path outside it -- `tools/ci/check-tests-relocatable.sh` enforces this and runs in CI. Classify the suite run with `tools/ci/check-stestr-run.sh`, never stestr's totals block. Commit subject: "Test split flat create against qemu's pins." |
| 5f. Mutation-check the three refusals | medium | sonnet | worktree | The master plan requires it for any test meant to prove a refusal. Break each of 5a's three refusals and decision 5's cleanup fix in turn, on a copy, and confirm a named test fails and names the right thing. Restore from the copy, never with `git checkout <dir>`. Run each mutant under `timeout` and count a timeout as killed. Leave the mutations in a runnable script and record its path and the kill count in the execution notes. Commit subject: "Mutation-check split create's refusals." |
| 5g. Documentation | medium | sonnet | worktree | `docs/create.md` has three places to change, all found already: the per-format table whose vmdk row lists the three subformats, the `-o` option list that repeats them, and the opening paragraph that says the monolithicFlat path does not require KVM -- which is now true of a second subformat. Add the new subformat, the 128 GiB limit with the reason it is instar's and not qemu's, and the pre-existing-extent refusal stated as the trade-off decision 1 describes, including its cost to the user. `docs/output-formats.md` already names the `twoGbMaxExtent*` subformats on the read side, where it describes the `/extents.N` children; say there that one of them can now be written. `docs/vmdk/vmdk-extents.md` (phase 4's page): the path derivation rule and the refusals, next to the naming rule already there. State the qemu divergences as divergences. Nothing under `docs/` outside `docs/plans/` may carry a `file.rs:123` line reference: the `docs-line-references` pre-commit hook rejects them and excludes only plan files, so name the function rather than the line. Commit subject: "Document split flat create." |

## Risks and mitigations

| Risk | Mitigation |
|---|---|
| The 128 GiB refusal looks arbitrary to a user who knows qemu writes 32 TiB images | The message names the limit and the mechanism, and `docs/create.md` explains that instar refuses what it could not read back. Checked in 5g by the management session reading the rendered text, not the diff. |
| Decision 5 changes shipped `monolithicFlat` failure behaviour | Its own commit, its own test, revertable alone. First back-brief item, so the operator can decline it before any code moves. |
| Sixty-four `ftruncate`d sparse files look like a 128 GiB write to a watching filesystem | They are holes, as `monolithicFlat` already does for one file. 5e asserts apparent length, not allocated length, and the test must not assert a disk-usage figure -- phase 2 measured that git-LFS stores such holes as bytes, which is why no split-flat fixture is committed. |
| A partial failure leaves extents behind with no descriptor | Decision 6's ordering makes that the only possible half-state, and it is the safe one: files with no descriptor are inert. 5c's cleanup removes them. |
| The refusal for a pre-existing extent fires on instar's own second run and reads as a bug | 5g documents the re-run story explicitly. |
| A sub-agent asserts a qemu-img behaviour nobody measured | The master plan forbids it. Every qemu claim in 5e cites a pinned case or a static build; the management session re-runs a sample. |

## Definition of done

Falsifiable; each is checkable by someone who did not do the work.

1. `instar create -f vmdk -o subformat=twoGbMaxExtentFlat out.vmdk 5G`
   writes `out.vmdk` plus `out-f001.vmdk`, `out-f002.vmdk` and
   `out-f003.vmdk`, and
   `out.vmdk`'s bytes equal phase 1's pinned 5 GiB
   `twoGbMaxExtentFlat` descriptor with `$STEM` and `$CID`
   substituted.
2. Each extent file's apparent length is
   `sectors_of_extent(i) * 512`: 2 GiB for every extent but the last.
   For 5 GiB that is 2 GiB, 2 GiB, 1 GiB.
3. `instar info out.vmdk` reads the image instar just wrote, and
   reports the virtual size it was asked for.
4. A size needing 65 extents (128 GiB + 1 byte) is refused, the
   message names the 64-extent limit and the size, and **no file
   exists afterwards** -- neither descriptor nor extent.
5. 128 GiB exactly is accepted and writes 64 extents.
6. The pinned `vmdk-multi-flat-2049` case -- a size qemu-img writes as
   1025 extents -- is refused by decision 2, and the test cites the
   pin so the divergence is recorded against a measurement rather
   than an assertion.
7. A zero size is refused with its own message, and no file is
   created.
8. A pre-existing `out-f002.vmdk` is refused by name, nothing is
   written, and the pre-existing file is unchanged byte for byte.
9. A pre-existing `out.vmdk` is still overwritten, matching the
   documented contract in `CreateArgs::filename`'s help text.
10. A derived extent name that is not UTF-8, or contains `"`, CR or
   LF, is refused by the same predicate `monolithicFlat` uses, and
   `monolithicFlat`'s own behaviour on such a name is unchanged.
11. A `create` that fails after truncating a pre-existing descriptor
    leaves that file present, for both `monolithicFlat` and the split
    subformat.
12. `create -f vmdk -o subformat=twoGbMaxExtentSparse` is refused with
    a message that lists the supported subformats and cites no plan
    phase, plan file or date.
13. `git diff` touches no line of the convert subformat validator at
    `src/vmm/src/main.rs:16804`, and `git diff --stat` lists no file
    under `src/operations/`.
14. `src/shared/src/lib.rs`'s `CreateConfig.vmdk_subformat` still
    documents three values.
15. Four mutants, one per refusal and one for the cleanup fix, each
    killed by a named test, none counted as killed by a skip or by a
    timeout that was really a hang. The script's path and the count
    are in the execution notes.
16. `docs/create.md` states the 128 GiB limit, that it is instar's and
    not qemu's, and the cost of the pre-existing-extent refusal to a
    user re-running a failed create.
17. `pre-commit run --all-files` passes with new files `git add`ed
    first, `make test-rust` reports 0 failures with the count checked,
    and the integration selection is classified by
    `tools/ci/check-stestr-run.sh` rather than by stestr's totals
    block or an exit code.
18. `scripts/check-binary-sizes.sh` passes. Core's `.bss` is
    untouched by a host-only change, and the before and after numbers
    in the execution notes show it.

## Back brief

Answer these before any step runs.

1. **Decision 5, the cleanup fix.** It is a behaviour change to
   shipping `monolithicFlat` code, made inside a phase about a new
   subformat. In scope as planned, or filed as an issue and left
   alone?
2. **Decision 1's divergence.** Confirm the refusal is worth diverging
   from qemu for, now that the cost to a user re-running a failed
   create is written down.
3. **The 128 GiB ceiling's message.** Should it name
   `MAX_CHAIN_EXTENTS`'s mechanism (the guest's extent table) or just
   the limit? Naming the mechanism explains an otherwise arbitrary
   number; it also tells a reader something about the guest's memory
   map.
4. **Whether this session may push and open the pull request** when
   the phase is done.

## Execution notes

Implementation began 2026-11-27 (AEDT), from commit `8e7ce7df` on
`multi-extent-vmdk-phase-05-flat-create`.

**Back brief, answered 2026-11-27 (AEDT).** All four as the plan
recommended.

1. Decision 5's cleanup fix stays in scope, in its own revertable
   commit with its own test, rather than being filed as an issue.
2. Decision 1's divergence from qemu-img is confirmed, now the cost to
   a user re-running a failed create is written down.
3. The extent-ceiling refusal **names the mechanism** -- that the
   guest's extent table is a fixed array, so instar could not read the
   image back -- and not only the limit. Step 5a's message does.
4. This session may push the branch and open the pull request when the
   phase is done.

Steps run in the order the table gives them, sequentially, because
every one of them writes to the same worktree and 5b onward consume
the previous step's interface.

The step table's `Isolation` column is read as the phase worktree
itself rather than a throwaway copy per sub-agent. A discarded
worktree would break that chain, and one cut from the shared clone
would be on `develop`, carrying neither this branch nor this plan.

**Step 5a, 2026-11-27.** The extent path set and the three refusals,
in `src/vmm/src/main.rs` alone (+442/-30).

The row asked for a function taking the output path and a
`SplitLayout`. That cannot also serve `monolithicFlat`, which has no
layout, so the sub-agent introduced a `VmdkExtentNaming` enum carrying
the layout in its `Split` variant. Kept: it is what decision 4 asks
for -- one derivation and one name-safety predicate -- rather than a
departure from it. `vmdk_flat_extent_path` survives as a two-line
adapter with its old signature, so convert's and create's
single-extent call sites are untouched.

The refusals live in `vmdk_split_create_plan`, applied zero size
first, then the extent count, then existence, so the ceiling refuses
before a size near `u64::MAX` could derive 2^33 names. The existence
test uses `symlink_metadata`, so a dangling symlink counts as the path
being taken: creating through one writes to a file the user never
named. That reading is beyond the row and is kept.

`vmdk_split_create_plan`, and `VmdkExtentPaths`'s two stem fields,
carry `#[allow(dead_code)]` until step 5b's writer calls them. **5b
removes both.**

Verified by the management session rather than from the report:
`build_split_descriptor`'s stem contract was re-read from
`src/crates/vmdk/src/lib.rs` (`prefix` is the base name without its
extension, `postfix` the extension including its dot) and matched
against the derivation; the convert subformat validator and
`CreateArgs::filename`'s help text were confirmed outside every diff
hunk; and `make test-rust` was re-run on the reviewed tree -- 3164
passed, 0 failed, 3 ignored over 83 test binaries -- with the four
refusal tests confirmed present in that run rather than inferred from
the total.
