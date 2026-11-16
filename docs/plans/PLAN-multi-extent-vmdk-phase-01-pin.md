# Multi-extent VMDK phase 1: pin qemu's output

## Status: Not started

Master plan: `PLAN-multi-extent-vmdk.md`.

## Planning effort

High. Everything later in the plan rests on these measurements, and
this repository has a history of sub-agents asserting plausible but
wrong qemu-img capabilities. Review effort: high for steps 1a and 1c,
which touch a pin that gates CI across 80 qemu builds.

## Decisions already taken by the operator

From the master plan, resolved 2026-11-16:

1. Sequential extent rotation, not simultaneous indexed output devices.
2. The read-side extent ceiling is fixed inside this plan, as phase 3.

Neither decision constrains this phase, which writes no instar code.
Open questions 3 to 6 remain open; this phase's measurements are what
settle 4 (extent path rules) and 5 (the maximum extent count), and it
must report on them rather than decide them.

## Scope

In scope:

* Extending the existing qemu-img pin infrastructure to cover
  `twoGbMaxExtentSparse` and `twoGbMaxExtentFlat` create, across all 80
  static builds in `instar-testdata/qemu-img-binaries/x86_64/`.
* A VMDK structural parser for tests and, later, the differential
  fuzzer, in the shape of `tests/helpers/vhdx_structure.py`.
* Making the pinned descriptor able to prove an extent *naming scheme*
  and *ordering*, which today it cannot (see the survey).
* Measuring, and recording in this plan: per-extent sector counts for
  sizes that are and are not multiples of 2 GiB, the `ddb.*` values and
  how geometry is derived, qemu's behaviour when a target extent file
  already exists, and the maximum extent count with the refusal past
  it.

Out of scope:

* Any change under `src/`. This phase writes no instar behaviour; its
  deliverable is an oracle. `git diff --name-only origin/develop...HEAD
  -- src/` must be empty at the end of it.
* Deciding the extent path rules or the maximum instar will support.
  Those are open questions 4 and 5, and the operator resolves them with
  this phase's measurements in hand.
* Reading `twoGbMaxExtent*` images, which is phase 3, and the structural
  *comparison arm* of the differential fuzzer, which is phase 16. This
  phase builds the parser those depend on and no more.
* Retrofitting `ddb.*` onto instar's existing VMDK output (open
  question 3).

## What the survey found

The master plan's phase 1 intent is **stale in one load-bearing way**:
it reads as though a cross-version sweep must be established, and
describes the per-version builds as the thing to use. All of that
already exists. `PLAN-bat-population-phase-01-pin.md` built it, and
this phase extends it rather than starting one. Corrected at source in
the master plan and in `docs/plans/index.md` as part of the planning
commit; a later step should not redo that.

What exists today, verified present:

| File | Lines | What it is |
|------|-------|-----------|
| `tests/helpers/qemu_pins.py` | 817 | `CASES`, `run_case`, `load_pin`, `expected`, the normalisers |
| `tools/sweep-qemu-create.py` | 183 | the sweep: `--write`/`--check`, `--versions`, `--cases`, `--scratch`, `--jobs` |
| `tests/golden/qemu-create-pins.json` | 1712 | the pin, shaped `{versions: [...], cases: {name: [{result, versions}, ...]}}` |
| `tests/test_qemu_create_pins.py` | 119 | the CI check |
| `tests/helpers/vhdx_structure.py` | 714 | the VHDX structural parser, the model for this phase's VMDK one |

`instar-testdata/qemu-img-binaries/x86_64/` holds 80 builds, 6.0.0
through 10.2.0, as the master plan said. There is a `KIND_VMDK_FLAT`
case kind already (`qemu_pins.py:51`, cases at `:197` and `:200`) which
captures a normalised descriptor and one extent length.

**The gap that matters.** `normalise_descriptor` (`qemu_pins.py:504-511`)
replaces every extent filename with a single placeholder. Run against
the 3-extent descriptor measured for the master plan:

```
CID=$CID
RW 4194304 SPARSE "$EXTENT"
RW 4194304 SPARSE "$EXTENT"
RW 2097152 SPARSE "$EXTENT"
```

The sector split survives, which is most of what matters, but the names
do not. A pin built on this normaliser cannot tell `-s001.vmdk` from
`-001.vmdk`, cannot catch extents emitted in the wrong order, and
cannot catch a descriptor pointing at the wrong file. Since proving the
naming scheme is a stated goal of this phase, the placeholder has to
carry an index. Decision 1 takes that up.

**The second gap.** `_run_vmdk_flat` (`:513-522`) measures exactly one
extent, through `_prealloc_measured_file({'measure': 'flat-extent'},
image)`. Multi-extent needs a list of per-extent lengths, and the
extent paths should come from parsing the descriptor rather than from
reconstructing qemu's naming, so that a wrong name shows up as a
missing file rather than being silently regenerated.

**There is no VMDK structural parser.** `tests/helpers/` holds
`vhdx_structure.py` but no VMDK equivalent. `qemu-img info` cannot tell
a correct extent split from a wrong one, which is the same reason
`PLAN-bat-population-phase-01-pin.md` built the VHDX comparator in its
phase 1 rather than later. Step 1b builds it here for the same reason.

**Measurements already in hand**, taken 2026-11-16 against the host
qemu-img 10.0.13 (Debian `1:10.0.13+ds-0+deb13u1`) and recorded in the
master plan's Situation: both subformats create successfully; naming is
`<stem>-s%03d.vmdk` and `<stem>-f%03d.vmdk`; a 5 GiB image splits
4194304 / 4194304 / 2097152 sectors; flat extents are the full 2 GiB in
length but sparse on disk; 40 GiB yields 20 extents; and qemu writes a
`ddb.*` block that instar emits for no subformat. The existing pin
confirms the `ddb.*` block is captured for `vmdk-flat-64M`, so the
machinery already records it. Nothing in the survey contradicted the
master plan's Situation.

## Decisions

1. **The extent placeholder becomes index-aware, and the existing pin
   is migrated textually rather than re-swept.** `normalise_descriptor`
   numbers placeholders from 1 in descriptor order (`$EXTENT1`,
   `$EXTENT2`, ...). Every existing pinned descriptor has exactly one
   extent line, so the migration is a deterministic replacement of
   `"$EXTENT"` with `"$EXTENT1"` in `tests/golden/qemu-create-pins.json`,
   and step 1a proves it by re-running `--check` over a three-version
   sample rather than re-running 80 builds for a rename.

   *This is the decision most likely to be argued with.* The
   alternative is a second normaliser used only by the new case kind,
   which touches no existing pin and carries no migration risk at all.
   It is rejected because two normalisers for one concept drift: the
   next person to fix a descriptor-normalisation bug fixes one of them.
   The migration is mechanical, the sampled `--check` catches it if it
   is not, and a wrong migration fails CI loudly rather than silently
   weakening an oracle. If review disagrees, the second normaliser is a
   clean fallback and nothing downstream changes.

2. **Pin cases stay small; the true extent ceiling is measured once and
   recorded in this plan, not in the pin.** The pin runs in CI, and the
   `%03d` naming implies a ceiling near 999 extents. Creating hundreds
   of files per case per version across 80 builds is not affordable,
   and the ceiling is a constant rather than something that needs
   per-version proof. Pinned cases are capped at 11 extents (21 GiB,
   which is also past the 15-extent read ceiling phase 3 removes, so
   phase 3 has a pinned case to prove itself against). The ceiling and
   the refusal past it are probed once on a four-version sample
   (6.0.0, 7.2.0, 8.2.0, 10.2.0) and written into *Sweep results*.

3. **Extent paths come from the descriptor, not from qemu's naming
   rule.** The new runner parses extent filenames out of the descriptor
   *before* normalising it, then stats each. A wrong or missing extent
   then surfaces as a `null` length rather than being papered over.

4. **The VMDK structural parser covers what the fuzzer will need, and
   stops there.** Descriptor fields (version, CID presence, parentCID,
   createType), per-extent kind, declared sector count, actual file
   length, and for sparse extents the VMDK4 header fields that define
   layout: magic, version, flags, capacity, grain size, descriptor
   offset and size, GD and RGD offsets, overhead. Grain *contents* are
   not parsed; phase 16 compares structure, and content parity is
   already covered by flattening both sides to raw.

5. **Flat cases are safe to pin at these sizes.** A 2 GiB flat extent
   is sparse on disk (measured: a 5 GiB flat image occupies 4 KiB), so
   an 11-extent flat case costs kilobytes, not 22 GiB. The runner still
   deletes each image after measuring, as `run_case` already does.

## Steps

One commit per step, each passing `pre-commit run --all-files` after
`git add` (the gate cannot see untracked files).

| Step | Effort | Model | Isolation | Brief for sub-agent |
|------|--------|-------|-----------|---------------------|
| 1a | medium | opus | none | **Index the extent placeholder.** In `tests/helpers/qemu_pins.py`, change `normalise_descriptor` (`:504-511`) so each `RW <sectors> <KIND> "<name>"` line's filename is replaced by `$EXTENT<n>`, numbered from 1 in descriptor order, keeping the `CID=` substitution as it is. `EXTENT_PLACEHOLDER` (`:60`) becomes a prefix; keep the name or rename it, but update every use. Migrate `tests/golden/qemu-create-pins.json` in the same commit by replacing `"$EXTENT"` with `"$EXTENT1"` wherever it appears in a descriptor field — every existing pinned descriptor has exactly one extent line, so this is deterministic; confirm that with `grep -c` before and after and state both counts in the commit message. Prove the migration: `python3 tools/sweep-qemu-create.py --check tests/golden/qemu-create-pins.json --versions 6.0.0,8.2.0,10.2.0 --cases vmdk-flat-64M --scratch <scratchpad>/pin1a` must exit 0. Add a unit test for the normaliser with a three-extent descriptor (use the one in the phase plan's survey section) asserting the three distinct placeholders and the preserved sector counts. Do not add the new case kind here. Commit subject: `Number the extent placeholders in VMDK pins.` |
| 1b | high | opus | worktree | **The VMDK structural parser.** Write `tests/helpers/vmdk_structure.py`: stdlib only, no import from `tests/base.py` (it must be importable the way `scripts/differential-fuzz.py:41-47` imports helpers), single quotes, 120 columns, trailing whitespace trimmed. Follow `tests/helpers/vhdx_structure.py` for API shape: `VmdkParseError(ValueError)`; `parse_vmdk(path) -> VmdkStructure` (frozen dataclass); `summarise(structure) -> dict`; `structural_diff(a, b) -> list[str]`. Parse the descriptor (plain text, or embedded in a VMDK4 sparse file at the offset/size the header records — `qemu_pins.py:380-401` already does that read and is the reference, do not edit it): `version`, `parentCID`, `createType`, and an ordered list of extents, each `(access, sectors, kind, filename)`. For each extent file resolved relative to the descriptor's directory, record the kind, declared sectors and actual length; and for a `SPARSE` extent parse the VMDK4 header after the `KDMV` magic per decision 4 — version, flags, capacity, grain size, descriptor offset and size, GD offset, RGD offset, overhead. Bounds-check every offset and length against the file before reading, and read with `seek`/`read`, never whole-file. `structural_diff` names the differing field and the extent index. Tests in a new `tests/test_vmdk_structure.py` (an `InstarTestBase` subclass using `_require_qemu_img`, `tests/base.py:473`, and `skip_unless_qemu_supports` for vmdk, `:456`): for host-qemu-written images, assert the parse of monolithicSparse 64M, monolithicFlat 64M, twoGbMaxExtentSparse 5G and twoGbMaxExtentFlat 5G; that the 5G cases have 3 extents with 4194304/4194304/2097152 declared sectors; that `structural_diff` is empty between two images made by the same command and names `createType` between sparse and flat; and that a truncated file, a bad `KDMV` magic, an extent line pointing at a missing file, and a descriptor with no extent lines each raise `VmdkParseError`. Run the module with stestr and confirm "Ran: N" matches the test count — do not trust the exit code, a >4 MiB attachment can kill a worker and still exit 0. Commit subject: `Add a structural VMDK parser for tests and the fuzzer.` |
| 1c | high | opus | none | **The multi-extent case kind and its cases.** In `tests/helpers/qemu_pins.py` add `KIND_VMDK_MULTI = 'vmdk-multi'` beside the existing kinds (`:51`), a `_run_vmdk_multi` runner registered in `RUNNERS` (`:526-531`), and the cases. The runner creates the image, and on rc 0 records: `rc`; normalised `stderr`; the normalised `descriptor` (now index-aware, from 1a); `extent_lengths`, a list of actual file lengths in descriptor order, with extent paths parsed out of the descriptor **before** normalisation per decision 3 and resolved relative to the image directory, `null` for any that does not exist; `extent_names`, the basenames with the image stem replaced by `$STEM`, so the naming scheme is pinned without pinning the scratch path; and for sparse, `summarise()` from `helpers.vmdk_structure` per extent. Cases, each both subformats unless noted: 2 GiB exactly (1 extent, the boundary), 2 GiB + 1 MiB (2 extents, tiny second), 5 GiB (3 extents, partial last — the measured 4194304/4194304/2097152 case), 4 GiB (2 extents, exact multiple), 21 GiB (11 extents, decision 2's cap, which is also past phase 3's 15-extent read ceiling), 1 MiB (1 extent, far below the split), and a refusal case creating into a directory where `<stem>-s002.vmdk` already exists (sparse only). Do not add a 999-extent case; decision 2 keeps the ceiling out of the pin. Smoke-test with `--versions 6.0.0,10.2.0 --write <scratchpad>/pin.json --cases <the new ones>` and confirm the 5 GiB sparse case reports the three sector counts above; **do not commit a pin in this step**. Commit subject: `Add multi-extent VMDK cases to the qemu sweep.` |
| 1d | medium | opus | none | **Run the full sweep and commit the pin.** Run `python3 tools/sweep-qemu-create.py --write tests/golden/qemu-create-pins.json --scratch <scratchpad>/sweep` over all 80 versions, host qemu-img excluded. This rewrites the whole pin, so confirm first that `--check` passes on the unmodified pin for a three-version sample, and afterwards that the only changed cases are the new ones plus 1a's placeholder migration — `git diff` the pin and say so in the commit message. Host load has made qemu commands fail spuriously in this repository before: before attributing any version boundary, re-run that case alone on the versions either side with `--check` and confirm it reproduces. Then probe decision 2's ceiling on 6.0.0, 7.2.0, 8.2.0 and 10.2.0 only: find the largest size that creates and the refusal past it, for both subformats, and record the exact stderr. Add a *Sweep results* section to this plan: the command, the date, wall time, the `instar-testdata` commit, a table of new cases with group count and any boundary, the ceiling probe, and what qemu did with a pre-existing extent. Any result contradicting the master plan's Situation is reported to the management session **before** anything depends on it. Commit subject: `Pin qemu-img multi-extent VMDK output.` |
| 1e | medium | sonnet | none | **CI check of the new cases.** Extend `tests/test_qemu_create_pins.py` (119 lines; follow its existing discovery of `self._testdata_root / 'qemu-img-binaries' / 'x86_64'` and its skip when absent) so the new cases are checked the way the existing ones are: every version directory present is listed in the pin; for 6.0.0, 6.2.0, 8.2.0 and 10.2.0 when present, each new case's `run_case` result equals `expected(case, version)`, one subTest per (version, case), reporting `structural_diff` output on failure; and the host `qemu-img` is compared against the group of the newest pinned version at or below its own, calling `skip_unless_qemu_supports` for vmdk first. If a new case turns out to have exactly one group across all 80 builds, assert that too, so a boundary appearing later is a failure until a phase handles it. Run `tools/ci/check-test-partition.sh` and confirm the module is still claimed, then run it with stestr and check "Ran: N" and 0 failures. Add `tests/stestr-timing.txt` lines only if the module exceeds 30 s, sorted by id, per `docs/testing.md`. Commit subject: `Check the multi-extent VMDK pins in CI.` |
| 1f | low | sonnet | none | **Close the phase.** Fold this phase's findings back into the master plan: if step 1d found a boundary or a result contradicting `PLAN-multi-extent-vmdk.md`'s Situation, correct the Situation at source and say so in the commit; if it found none, add one sentence saying the 80-build sweep confirmed it, naming the pin file. Record the ceiling probe's answer against open question 5 and the pre-existing-extent behaviour against open question 4, as measurements, **without resolving either question** — those are the operator's. Confirm `git diff --name-only origin/develop...HEAD -- src/` is empty, and that `git diff origin/develop...HEAD -- tests tools docs/ \| grep -nE 'PLAN-\|[Pp]hase [0-9]\|step 1[a-f]'` prints nothing: no plan, phase or step references in landed code or docs. Do not change the Execution table's status; the next phase's first commit closes this one out. Commit subject: `Record the multi-extent sweep in the plan.` |

## Risks and mitigations

| Risk | Mitigation |
|------|-----------|
| 1a's pin migration silently corrupts an existing oracle | The migration is a single deterministic substitution with before/after `grep -c` counts in the commit message, and a sampled `--check` across three versions must pass. If review prefers zero risk, decision 1's fallback is a second normaliser. The management session re-runs the `--check` itself rather than trusting the report. |
| The sweep's spurious failures get attributed as version boundaries | Known failure mode in this repository under host load. Step 1d re-runs any boundary case alone on the versions either side before recording it, and reports rather than writes when a result contradicts the master plan. |
| 80 versions × new cases is slow enough to tempt shortcuts | Decision 2 caps pinned cases at 11 extents and keeps the ceiling probe to a four-version sample. `--jobs` exists but concurrency is what causes the spurious failures above, so step 1d runs at the default of 1 and the wall time goes in *Sweep results*. |
| A green stestr run that ran almost nothing | Every step that runs tests checks "Ran: N" against the expected count rather than the exit code. A subunit attachment over 4 MiB kills a worker and the run still exits 0. |
| The parser in 1b is written against one qemu version's layout | 1b asserts against host-written images and 1d then exercises it across 80 builds through the sparse cases; a layout difference shows up as a pin group rather than as a silent misparse. |

## Definition of done

Falsifiable; each is checkable by someone who did not do the work.

1. `normalise_descriptor` gives a three-extent descriptor three
   distinct placeholders, and a unit test asserts it.
2. `tools/sweep-qemu-create.py --check tests/golden/qemu-create-pins.json`
   exits 0 for every version present in the testdata checkout.
3. `tests/golden/qemu-create-pins.json` lists exactly the 80 version
   directories under `instar-testdata/qemu-img-binaries/x86_64/`.
4. For a 5 GiB `twoGbMaxExtentSparse` image the pin records extents of
   4194304, 4194304 and 2097152 sectors, in that order, with three
   distinct `$EXTENT<n>` placeholders and three `$STEM`-relative names.
5. `parse_vmdk` raises `VmdkParseError`, not an unhandled exception,
   for each of: a truncated file, a bad `KDMV` magic, a descriptor
   whose extent file is missing, and a descriptor with no extent lines.
6. `tests/test_vmdk_structure.py` and `tests/test_qemu_create_pins.py`
   both run under stestr with "Ran: N" matching their test counts and
   0 failures.
7. This plan's *Sweep results* section names the maximum extent count
   qemu accepts, the verbatim stderr of the refusal past it, and what
   qemu does when a target extent already exists.
8. `git diff --name-only origin/develop...HEAD -- src/` is empty.
9. No plan, phase or step reference appears in anything landed outside
   `docs/plans/`.
10. The master plan's stale phase 1 intent is corrected at source, and
    `docs/plans/index.md` agrees with it.

## Back brief

Before step 1a, the implementing session restates: that this phase
writes no instar code; that the sweep, pin, grouping and CI check
already exist and are being *extended*; decision 1 and its fallback;
and decision 2's reason for keeping the extent ceiling out of the pin.

**Gate before step 1d.** The full sweep rewrites a 1712-line pin that
gates CI across 80 builds, and it is cheap to propose and expensive to
redo. The management session reviews 1c's smoke-test output and agrees
the case list before 1d runs. A case added after 1d means another full
sweep.
