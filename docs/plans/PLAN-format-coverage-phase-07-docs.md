# Format coverage phase 7: docs (qemu-img-parity axis)

Master plan: [PLAN-format-coverage.md](PLAN-format-coverage.md)

## Status: Ready for execution (planned 2026-07-20)

## Prompt

Before responding to questions or discussion points in this
document, explore the instar codebase thoroughly. Read relevant
source files, understand existing patterns (VMM structure, guest
operation layout, shared crate conventions, call table ABI,
format parsing, test infrastructure), and ground your answers in
what the code actually does today. Do not speculate about the
codebase when you could read it instead. Where a question touches
on external concepts (QCOW2, VMDK, VHD/VHDX, LUKS, KVM, virtio,
disk image formats), research as needed to give a confident
answer. Flag any uncertainty explicitly rather than guessing.

I prefer one commit per logical change, and at minimum one
commit per phase. Do not batch unrelated changes into a
single commit. Each commit should be self-contained: it
should build, pass tests, and have a clear commit message
explaining what changed and why.

## Situation

Phase 7 is the final phase of the format-coverage master
plan: the docs axis, plus the master-plan close-out. A
grounding survey (2026-07-20) of every doc the per-phase
docs steps touched found most of the documentation already
current — phases 1-6 each shipped their own docs step —
which narrows phase 7 to the genuinely unfinished work.

### Already current (do NOT duplicate)

* `docs/format-coverage.md`: the detection table, the
  conversion input/output tables (vdi/parallels/qcow/dmg
  rows present), the per-op resize/rebase/commit/dd tables,
  the Other Format Safety Checks table (incl. phase-6 QED
  row), the per-format test-image inventory, and Completed
  narrative items 18-22 covering phases 2-6.
* `docs/quirks.md`: six phase sections recording every
  parity/divergence fact this programme produced (phase 1
  at :2474, 2 at :2711, 3 at :2868, 4 at :3119, 5 at
  :3515, 6 at :4007 — line numbers as of the survey).
* `README.md` Supported Formats list (:16-28) — accurate,
  including the four read-only input rows.
* `ARCHITECTURE.md` — describes all four new crates
  (vdi/parallels/qcow1/dmg) and the chain-reader feature
  dispatch. No stale claims.
* `CHANGELOG.md` — all six phases have entries. The file's
  idiom adds no entries for docs-only changes, so phase 7
  adds none (recorded here as a decision).
* CLI strings — nothing stale: input format is auto-probed
  (no clap allowlist to update) and the output roster
  (raw/qcow2/vmdk/vpc/vhdx) is deliberately unchanged.

### Genuinely unfinished (the phase-7 scope)

1. **The qemu-img-parity axis is missing.** The master
   plan's mission item 5 and the success-criteria bullet
   "`docs/format-coverage.md` (or sibling) tracks coverage
   against qemu-img's real roster, not just oslo" are
   unmet: the document's purpose statement (:3-6) still
   declares an oslo-only charter, and parity information is
   scattered across seven per-op tables with **no
   consolidated op × format matrix** anywhere (the only
   op-per-row matrix in the repo is quirks.md's QED-only
   table at :4069).
2. **`AGENTS.md:56` is stale** — its Supported Formats
   list ("qcow2 ..., raw, vmdk, vpc, vhdx, luks") omits
   vdi, parallels, qcow (v1), and dmg entirely; it was
   never touched by the per-phase docs steps. The master
   plan's success criteria names AGENTS.md explicitly.
3. **vvfat is documented nowhere outside the master plan.**
   The success-criteria bullet "Bochs, cloop, vvfat (and
   QED ...) produce clean, tested, documented refusals" is
   satisfied for bochs/cloop (phase 1) and QED (phase 6),
   but vvfat appears in no user-facing doc. vvfat is a
   directory-backed qemu pseudo-format: it synthesizes a
   FAT filesystem over a host directory and has no on-disk
   single-file container, so there is no file for instar to
   detect or refuse (`qemu-img create -f vvfat` itself
   fails with "Format driver does not support creation" —
   already recorded in the master plan Situation). The
   docs owe a short recorded rationale, not code.
4. **Master-plan close-out**: Execution row 7, the
   success-criteria confirmation sweep, the programme
   retrospective, `docs/plans/index.md`, and this plan's
   findings.
5. Minor: `README.md:18`'s "Initial target formats:"
   heading wording predates the programme (the list under
   it is current); README omits any mention of the
   detection-only (bochs/cloop) and policy-refused (qed)
   formats.

### The sourcing rule (the load-bearing constraint)

Twice in this programme (phases 4 and 6) a sub-agent wrote
a plausible-but-wrong claim about qemu's capabilities, and
only empirical testing caught it (most recently: "qemu
cannot resize/rebase/commit QED" — it can, all rc 0).
Phase 7 produces a large parity matrix, which is maximally
exposed to this failure mode. Therefore:

**Every cell of the parity axis must either (a) cite a
recorded fact — a quirks.md section, an existing
format-coverage.md table row, or a phase plan's Findings —
or (b) be measured empirically before being written, by
running the actual op against an existing fixture with both
the built instar and qemu-img (host 10.0.11 and/or the
static per-version builds in instar-testdata). The step
report must list exactly which cells were measured fresh
and what the measurements were. No cell may be filled from
general knowledge of qemu.**

## Decisions

1. **Widen `docs/format-coverage.md`; do not create a
   sibling document.** The master plan allowed either. The
   per-op tables, the divergence records, the test-image
   inventory, and the oslo cross-validation section already
   live in format-coverage.md; a sibling would fork the
   audience and re-create the archaeology problem the axis
   exists to end.
2. **No CHANGELOG entry for phase 7.** The file's idiom
   records shipped behaviour per phase; docs-only changes
   have never had entries and phase 7 changes no behaviour.
3. **CLI strings unchanged.** Nothing is stale (see above);
   phase 7 is docs-only, no code or test changes.

## Design

Two steps complete the phase — and the master plan.

### 7a — the qemu-img-parity axis in format-coverage.md

* Widen the purpose statement (:3-6) to the dual charter:
  oslo.utils `format_inspector` parity (the original
  mission) AND coverage tracking against qemu-img's real
  format roster, pointing at the new axis section.
* Add a new top-level section, "qemu-img parity axis": a
  consolidated matrix with one row per format instar
  detects — raw, qcow2, vmdk, vhd/vpc, vhdx, luks, vdi,
  parallels, qcow (v1), dmg, qed, bochs, cloop, iso — and
  one column per subcommand surface, grouped to stay
  readable: read-side (info, check, convert-input, compare,
  dd, bench, map, measure), in-place (resize, rebase,
  commit, amend, snapshot, bitmap), output-side
  (convert-output/create/dd-output as a single column — the
  unchanged five-format roster). Use a compact legend, e.g.
  ✓ = supported with qemu parity; R‡ = instar refuses where
  qemu-img succeeds (recorded divergence); R= = instar
  refuses and qemu-img also refuses; — = not applicable.
  Every R‡ cell carries a footnote linking the quirks.md
  section (or format-coverage table) that records the
  divergence; wide tables must follow the file's existing
  conventions for readability.
* Apply the sourcing rule above to every cell. Cells with
  no recorded source (expected examples: the in-place ops ×
  vdi/parallels/qcow1/dmg/bochs/cloop; qemu's own behaviour
  on bochs/cloop fixtures) must be measured: run both
  binaries against the existing fixtures and record
  rc + message, then footnote the cell "measured 2026-07-20
  vs qemu-img <version>" in the step report (the doc
  footnote can cite the phase-7 plan findings).
* Add the vvfat subsection under the axis: why there is
  nothing to detect (directory-backed pseudo-format, no
  on-disk container), what qemu-img itself does, and that
  this satisfies the master plan's vvfat clause by
  documentation rather than code. Empirically re-verify the
  one checkable claim (`qemu-img create -f vvfat` failure
  mode) before quoting it.
* Cross-link: the axis section points at the six quirks.md
  phase sections as the underlying evidence records; the
  Documented Divergences section gains a one-line pointer
  to the axis.

### 7b — consistency fixes + master-plan close-out

* `AGENTS.md`: update the Supported Formats section to the
  real roster — write formats (raw/qcow2/vmdk/vpc/vhdx),
  luks (info + decrypting convert), the four read-only
  input formats (vdi, parallels, qcow v1, dmg), the
  detection-only formats (bochs, cloop), and the QED
  policy refusal — phrased per AGENTS.md's existing
  terse style, with a pointer to format-coverage.md's axis
  for the full matrix.
* `README.md`: fix the "Initial target formats:" heading
  wording (the programme is no longer initial); add a
  short line after the format list noting detection-only
  (bochs/cloop) and policy-refused (qed) formats with a
  link to docs/format-coverage.md. No other README changes
  (the list itself is current; the skills section already
  satisfies the standing requirement).
* Master plan (`PLAN-format-coverage.md`):
  * Execution row 7 → Complete (2026-07-20, commit hashes).
  * Success-criteria sweep: annotate each bullet with its
    satisfying evidence (the two previously-owing bullets —
    the parity-axis doc and the AGENTS.md update — now
    satisfied by 7a/7b; the vvfat clause satisfied by the
    documented rationale), in the same inline style phase 6
    used for the QED clause.
  * A short close-out retrospective at the end of the plan
    (the qcow2-write-infrastructure precedent): programme
    summary — four new no_std crates with fuzz targets,
    four formats graduated to read paths, one recorded
    policy refusal, detection parity closed against oslo's
    roster, `test_info_safe` growth 580 → 954, the
    integration suite zero-fail counts as recorded in the
    phase-5/6 findings, the seven bugs fixed along the way
    (issue #444, the qcow1 misdetection, the never-consumed
    encrypted flag, four instar-testdata defects) — all
    sourced from the phase plans' Findings sections, no
    re-running of suites.
  * Plan status header → Complete.
* `docs/plans/index.md`: phase-7 link check-marked; the
  format-coverage row's status → Complete (all 7 phases),
  with the one-paragraph outcome summary the index idiom
  uses for completed plans.
* This plan file: Status → Complete + findings from both
  steps (including the fresh-measurement list from 7a).
* Final consistency grep across README/ARCHITECTURE/
  AGENTS/docs for any claim the new axis contradicts.

## Out of scope

* Implementing anything in the master plan's Future work
  list (map/measure graduation, DMG codecs, in-place-op
  trailer probing, QED path (b), upstream qemu bug
  reports, etc.) — phase 7 records them, nothing more.
* Any code, test, fixture, or testdata change. Docs only.
* A CHANGELOG entry (Decision 2).
* Normalising refusal-message wording surfaced by the
  axis (same reasoning as phase 6).

## Step-level guidance

| Step | Effort | Model | Isolation | Brief for sub-agent |
|------|--------|-------|-----------|---------------------|
| 7a | medium | opus | none | In the instar worktree: author the qemu-img parity axis per the Design — widen the format-coverage.md purpose statement, add the consolidated matrix + legend + vvfat subsection + cross-links. HARD RULE: every cell cites a recorded fact (quirks.md section / existing table / phase Findings) or is measured empirically against BOTH the built instar and qemu-img using existing fixtures (fixtures for every format are in instar-testdata; static per-version qemu-img builds live there too; host qemu-img is 10.0.11). No cell from general knowledge. Re-verify `qemu-img create -f vvfat` before quoting its failure mode. Report: the full matrix as written, per-cell source citations, the exact list of freshly-measured cells with rc/message evidence, and any recorded fact the measurements contradicted (do not silently correct a quirks record — report the conflict). No code/test changes; docs only. |
| 7b | medium | sonnet | none | Docs close-out per the Design: AGENTS.md roster update; README heading + detection-only/policy-refused note; master plan row 7 Complete + success-criteria evidence sweep + close-out retrospective (sourced from phase-plan Findings; do not re-run suites) + Status Complete; index.md row Complete with outcome summary; this plan file Status Complete + findings incl. 7a's fresh-measurement list; final consistency grep. Report files changed, every success-criteria bullet with its evidence pointer, and any contradiction found. |

Sequencing: 7a then 7b (7b's close-out cites 7a's axis).

## Verification (management-session review checklist)

- [ ] Docs-only diff; no code, tests, or testdata touched.
- [ ] Every parity-axis cell has a citation or an explicit
      fresh measurement in the 7a report; spot-check cells
      against their cited quirks sections, and re-run at
      least two of the fresh measurements independently.
- [ ] Any measurement-vs-quirks conflict was surfaced, not
      silently patched.
- [ ] AGENTS.md roster matches reality; vvfat rationale
      present; charter statement widened.
- [ ] Master plan: row 7 Complete, every success-criteria
      bullet carries evidence, retrospective present,
      status Complete; index.md consistent.
- [ ] pre-commit clean; commit messages per conventions.

## Success criteria

Phase 7 — and the format-coverage master plan — are
complete when: format-coverage.md carries the dual charter
and the consolidated, fully-sourced op × format qemu-img
parity axis (including the vvfat rationale); AGENTS.md and
README are consistent with it; and the master plan is
closed out with every success-criteria bullet evidenced,
the retrospective recorded, and index.md updated.

## Back brief

Before executing, back brief the operator: confirm the
scope is docs-only (no code/tests/testdata), that the axis
lands inside format-coverage.md rather than a sibling doc,
that every matrix cell will be source-cited or freshly
measured under the sourcing rule, and that 7b closes out
the master plan (row 7, success-criteria sweep,
retrospective, index).
