# Format coverage phase 6: QED decision

Master plan: [PLAN-format-coverage.md](PLAN-format-coverage.md)

## Status: Ready for execution (planned 2026-07-19)

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

This phase resolves the master plan's Open question 1: does
QED get a read path (as VDI/Parallels/QCOW1/DMG did in
phases 2–5) or a principled, documented, fully-tested
refusal? Grounding was done 2026-07-19 by a combined
codebase survey + empirical pass (static qemu-img 6.0.0 /
8.2.0 / 10.2.0 + host 10.0.11; live git-master oslo.utils;
every instar op run against the qed fixture).

### Grounded facts

* **QED has an offset-0 header magic**
  (`format_detection.rs:170`), so — unlike DMG's
  info-op-only trailer probe — every probe path recognises
  it: the guest info op, the chain-discovery gate, AND the
  host prefix probes for the in-place ops. The empirical
  per-op audit found **zero dangerous cases**: all fifteen
  subcommands either work correctly (info, human and JSON,
  matching qemu byte-for-byte on the existing baselines) or
  refuse cleanly with a typed message and no file
  modification (verified by byte-hash after every mutating
  op). No raw pass-through, no crash, no silent-wrong
  output. The DMG-class audit hazard does not exist for
  QED.
* Refusal inventory: convert/compare/dd/bench refuse via
  the issue-#444 chain gate ("input format 'qed' is
  detected but not supported for reading (detection and
  info only)" — including the mid-chain backing position,
  pinned); check exits 63 ("This image format (qed) does
  not support checks"); map/measure emit their own guest
  refusals; resize/rebase/commit/amend/snapshot/bitmap
  refuse via their qcow2/vmdk whitelists. Cosmetic
  inconsistencies only: resize/rebase render the Debug
  spelling "Qed" where others say "qed", and exit codes
  vary (63 vs 1) — wording quirks, not safety issues.
* **Test-pin coverage is incomplete**: only convert
  (incl. mid-chain), compare, dd, and the oslo divergence
  are QED-named pins. check, map, measure, resize, rebase,
  commit, amend, snapshot, bitmap, and bench have no
  QED-named tests — their refusals ride on generic
  whitelist behaviour.
* **QED is NOT formally deprecated in QEMU.** No entry in
  any deprecated.rst/removed-features.rst, no runtime
  warning on any op or version, and `qemu-img create -f
  qed` still succeeds on 10.2.0. The master plan's
  "(deprecated)" annotation overstates qemu's stance; there
  is no removal timeline forcing a decision. qemu-img
  reads, writes, checks, maps, measures, and benches QED
  normally (all rc 0, convert md5 version-stable).
* **oslo.utils explicitly bans QED**: `detect_file_format`
  returns a real QEDInspector, whose safety check then
  raises `SafetyCheckFailed: ... banned` ("This file format
  is not allowed"). Detected-then-refused, by policy — the
  strongest ecosystem statement available that no OpenStack
  workload will hand a QED image to a converter expecting
  success. Already recorded in test_oslo_crossval.
* Testdata: one fixture (`qed-simple`, 10 MiB virtual,
  **entirely unallocated** — weak coverage), manifest
  `skip_qemu_img: true` / `run_in_ci: false` — yet the tree
  still carries a full, stale (2026-02-03), UNCONSUMED
  80-version qemu-img/check/compare baseline set for it,
  predating the flag. An inconsistency either decision
  should reconcile.
* Path (b) sketch (preserved for a future revisit): a QED
  reader is qcow1-class work — 68-byte LE header
  (cluster_size power-of-two in [4 KiB, 64 MiB], table_size
  1..16 clusters, `features & ~QED_FEATURE_MASK == 0` as
  the readability gate with QED_F_BACKING_FILE /
  QED_F_NEED_CHECK / QED_F_BACKING_FORMAT_NO_PROBE the only
  known bits), two-level L1/L2 cluster-offset tables, no
  compression, no encryption, in-header backing name with a
  no-probe flag. A `chain::ImageFormat::Qed` variant plus a
  reader arm would flip convert/compare/dd/bench, exactly
  like phase 4. `qemu-img create -f qed` still works, so
  deterministic fixtures are generatable, and the (stale)
  baseline corpus is regenerable. Estimated effort: at or
  below phase 4.

## Decision

**QED remains read-refused, as deliberate policy** — option
(a), confirming the master plan's lean, with a corrected
rationale:

1. Demand is nil. QED was a short-lived qcow2 alternative
   that never saw wide deployment; no user demand for
   reading QED archives has surfaced during five phases of
   format work.
2. The ecosystem agrees. oslo.utils detects QED and then
   bans it outright; instar refusing reads aligns with the
   stance of the tooling instar cross-validates against.
   (For DMG/VDI/etc. instar deliberately reads what oslo
   cannot — but there oslo merely lacks an inspector; for
   QED oslo has one and refuses by policy.)
3. The current refusal is already complete and safe (the
   audit's zero-dangerous-cases result); finishing the job
   costs only test pins and documentation.
4. The rationale is NOT "qemu deprecates it" — qemu does
   not, and this phase corrects that claim in our docs. The
   divergence is instar's own scope choice: qemu-img
   converts/checks/maps/measures QED; instar refuses, in
   the same recorded-divergence class as map/measure on the
   phase 2–5 formats.

**Revisit criteria** (recorded so the decision is cheap to
reverse): a real user request to read QED input, or QED
images surfacing in a workload instar serves. The path-(b)
sketch above is the starting point; the phase 2–5 template
applies directly.

## Design

Two small steps complete the phase:

### 6a — refusal-hardening pins + testdata reconciliation

* Add QED-named refusal pins for every op that lacks one:
  check (exit 63 + message), map, measure, bench, resize,
  rebase, commit, amend, snapshot, bitmap — each asserting
  the exact current message/exit code and that the image
  file is byte-unchanged after mutating ops (the audit
  table in this plan is the source of truth for expected
  values). Place each pin in its op's suite following that
  suite's existing refused-format patterns. The cosmetic
  inconsistencies (the "Qed" Debug spelling in
  resize/rebase; check's 63 vs the others' 1) are pinned
  AS-IS with comments — normalising them would touch other
  formats' messages for zero user value.
* Testdata: delete the stale, unconsumed 80-version
  qemu-img/check/compare baseline trees for `qed-simple`
  (they contradict its `skip_qemu_img: true` manifest state
  and predate it; regeneration is trivial via
  generate-baselines.py if path (b) is ever taken). Remove
  `'qed'` from generate-baselines.py's supported_formats
  whitelists so a future unrestricted run cannot silently
  recreate them (comment citing this plan). The fixture
  itself, its manifest entry, and the oslo recording stay.
* No product-code changes at all in this phase.

### 6b — docs (the decision record)

* quirks.md: a "Format-coverage phase 6" section — QED
  read-refusal as policy (rationale + revisit criteria);
  the qemu-not-deprecated correction; the per-op
  refusal/divergence table (qemu rc-0 ops instar refuses);
  the cosmetic-inconsistency note.
* format-coverage.md: QED row updated to "refused by
  policy (phase 6)" with the divergence note; narrative
  entry.
* Master plan: Execution row 6 → Complete; a dated
  RESOLVED addendum under Open question 1 (the historical
  question text stays); the success-criteria QED clause is
  satisfied by this decision; future-work gains the revisit
  criteria pointer. index.md: phase 6 check-marked.
* This plan file: Status → Complete + findings.
* CHANGELOG: a short policy-decision entry. README only if
  it makes format claims phase 6 changes (grep first).

## Out of scope

* Any QED reader/parser work (path (b) — preserved as a
  sketch only).
* Normalising refusal-message casing or exit codes across
  formats.
* New QED fixtures (the refusal surface parses only the
  68-byte header via info, already fuzz-covered through
  fuzz_format_detect and the info-op fuzzing).

## Step-level guidance

| Step | Effort | Model | Isolation | Brief for sub-agent |
|------|--------|-------|-----------|---------------------|
| 6a | medium | opus | none | Two parts. (1) In the instar worktree: add QED-named refusal pins per the Design bullet — one test per op lacking one (check/map/measure/bench/resize/rebase/commit/amend/snapshot/bitmap), each in its op's existing suite following that suite's refused-format precedent, asserting the EXACT messages/exit codes from this plan's Situation audit table (re-verify each empirically against the built instar before pinning — do not trust the table blindly), and byte-unchanged files after mutating ops. Run the touched suites (zero fail; isolated re-run before believing failures). (2) In instar-testdata (NO commits — management reviews): delete the qed-simple baseline trees under expected-outputs/*/ (qemu-img-human, qemu-img-json, check-human, check-json, compare-human — verify the exact set by find), remove 'qed' from generate-baselines.py supported_formats whitelists with a comment citing this plan, and confirm no instar test consumed the deleted files (grep + run test_info_safe end-to-end: count must be unchanged at 954). Report: pin list with verbatim pinned strings, suite counts, deleted-file inventory (count per tree), the whitelist diff, deviations. |
| 6b | medium | sonnet | none | Docs close-out per the Design: quirks.md phase-6 section; format-coverage.md row + narrative; master plan row 6 Complete + the dated RESOLVED addendum under Open question 1 + future-work revisit pointer; index.md; this plan file Status Complete + findings from 6a's report; CHANGELOG entry; consistency grep for stale QED claims (especially any "(deprecated)" language OUTSIDE the master plan's historical Situation table — correct those; leave the historical table text with the addendum handling the correction). Report files changed + stale claims found. |

Sequencing: 6a then 6b.

## Verification (management-session review checklist)

- [ ] No product code changed; only tests, testdata
      deletions, and docs.
- [ ] Every op has a QED-named pin; suites zero-fail;
      test_info_safe count unchanged (954).
- [ ] Deleted baselines were genuinely unconsumed; the
      whitelist guard prevents regeneration.
- [ ] The decision record is honest about qemu's actual
      stance (not deprecated) and the divergences.
- [ ] pre-commit clean; commit messages per conventions.

## Success criteria

Phase 6 is complete when the QED decision (refusal as
policy) is recorded with rationale and revisit criteria;
every instar op's QED refusal is pinned by a named test;
the testdata inconsistency is reconciled; and the master
plan's Open question 1 is resolved.

## Hand-off to phase 7

Phase 7 (docs) inherits: the completed per-format
divergence inventory (map/measure scope refusals for
vdi/parallels/qcow1/dmg; check/map/measure/bench policy
refusals for qed; dmg capacity caps and codec refusals) as
the backbone of the qemu-img-parity axis table, plus the
corrected qemu-deprecation framing for qcow1 (also not
warned at runtime) and qed.

## Back brief

Before executing, back brief the operator: confirm the
decision (refusal as policy, not a read path — with the
corrected not-deprecated rationale and recorded revisit
criteria), that 6a adds pins and deletes the stale
unconsumed qed baselines in testdata (management-reviewed
before commit), and that no product code changes.
