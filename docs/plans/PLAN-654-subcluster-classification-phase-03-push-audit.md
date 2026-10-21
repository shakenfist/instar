# PLAN-654 phase 3: the push audit

Parent plan: [PLAN-654-subcluster-classification.md](PLAN-654-subcluster-classification.md)

## Prompt

Plan phase 3 of `PLAN-654-subcluster-classification.md`, the mandatory
push audit. Phase 2 landed in `d42af1f5` (#810), which completes the
plan's substantive work. Phase 1 (`d08841e3`, #801) replaced the ad hoc
readings of host offset zero in the qcow2 chain reader, map, measure and
check with one classifier that mirrors qemu's seven subcluster types,
and refused what qemu calls an invalid entry. Phase 2 stopped the chain
reader treating an external data device as a backing layer, bumped the
chain config to version 4 for the flag that marks one, and refused the
two data-file entries qemu refuses.

This phase runs `PUSH-AUDIT.md` over both. The phase plan is the
deliverable; implementation is a separate ask.

## Planning effort

**Medium.** The audit instrument was repaired by the two push-audit
phases before this one, and the survey confirmed it resolves this
plan's scope correctly. So unlike differencing phase 18, no step here
repairs tooling. The judgement is in Decision 3, which overrides the
runbook's models for two dimensions, and in Decision 4, which gives the
test dimension a measurement to make rather than a diff to read.

Review effort: **medium**, concentrated on Scope and Decision 4.

## Scope

**In scope.** `PUSH-AUDIT.md` run over the union of the two merge
commits that put this plan's phases on `develop`, taken from the master
plan's `Merged` column:

```
d08841e3  Merge pull request #801  (phase 1, and the master plan itself)
d42af1f5  Merge pull request #810  (phase 2)
```

Nothing else is in scope. The master plan and the phase 1 plan were
committed inside #801 (`9bac3c45` is its first commit), and
`git log --first-parent origin/develop -- 'docs/plans/PLAN-654*'` names
only these two merges. This branch's own close-out and planning commits
are bookkeeping.

Triage of every finding, and the record of it in this plan, are in
scope.

**Out of scope.**

* **Fixing findings.** Per the `plan-push-audit-phase` shared block and
  `PUSH-AUDIT.md`'s push-audit section, findings land as their own pull
  request after this one merges. That pull request records this phase's
  merge commit and marks the plan `Complete`. If the audit finds
  nothing, this phase closes itself out instead (step 4).
* **The open issues this plan already handed over**: #794, #795, #804,
  #805, #806, #807 and #808. The audit may add to that list; it does
  not work it.
* **Items the two pull requests' automated reviews raised and the
  phases declined in writing.** They are recorded in each phase plan's
  execution notes. An agent re-raising one needs new evidence, not a
  second opinion.
* **The 23 merged branches still on origin**, this plan's two among
  them. `delete_branch_on_merge` is on, but branches that merge through
  the queue stay behind. That holds for the whole repository, not just
  this plan.

## What the survey found

### The scope is two merges, and the tool resolves it

Both `Merged` cells name merge commits: `git rev-list --parents -n1`
gives three words for each, and both are ancestors of `origin/develop`.
`tools/audit/scope-patch.sh --commits-file` over them resolves
**21 files** and writes **12,474 patch lines**. The two merges'
`--shortstat` are 19 files (+5,397/-1,108) and 14 files (+3,239/-294),
which overlap in 12.

| Area | Files | Churn (+/-) |
|---|---|---|
| `src/crates/qcow2/src/lib.rs` | 1 | +4,136/-890 |
| `src/vmm/src/main.rs` | 1 | +455/-10 |
| `src/shared/src/lib.rs` | 1 | +416/-17 |
| `src/operations/check`, `map`; `src/core/src/serial.rs` | 3 | +89/-65 |
| `tests/` (`helpers/qcow2_subclusters.py`, `test_qcow2_subclusters.py`, `test_check_formats.py`) | 3 | +1,256/-17 |
| `tools/mutate-differencing.sh` | 1 | +222/-34 |
| `docs/` (6 pages outside `plans/`), `CHANGELOG.md` | 7 | |
| `docs/plans/` (this plan's three files, `index.md`) | 4 | |

That is about a quarter of differencing phase 18's 54,821 lines. It
changes the partition argument (Decision 2) but not the conclusion.

### The instrument needs no repair

Differencing phase 18 gave both wave scripts `--range` and
`--commits-file` (`tools/audit/audit-scope.sh`), a printed file count,
and an exit 9 for an explicit scope that resolves to nothing.
Fuzz-autofix phase 2 fixed the inline-script check's line numbers and
truncation. `PUSH-AUDIT.md` now tells a push-audit phase to pass
`--commits-file` and to build the patch with `scope-patch.sh` rather
than by hand. The survey ran `scope-patch.sh` and got the 21 files
above. Nothing in this plan's scope is a workflow file, so the
remaining gap fuzz-autofix recorded, that no shellcheck runs on
workflow `run:` blocks, does not bite here.

### The integration suite reaches the new tests in CI

`make test-container-core` runs every module except `test_convert`,
`test_compare` and `test_info_malicious` (`Makefile:740-741`), so
`test_qcow2_subclusters` and `test_check_formats` run on every pull
request. `tools/mutate-differencing.sh --self-test` and
`--check-patterns` run in the `ci-tooling` job
(`.github/workflows/functional-tests.yml:200,211`). What CI does not
show is how many of those tests *skip*. Phase 2's definition-of-done
run skipped 549 of 1,805, and a fixture built at run time by `qemu-io`
can skip when the host's qemu lacks a feature. Decision 4 turns that
into a measurement.

### Phase 2 moved the harness phase 1's mutation cases run against

The plan added 23 cases and retired 2, so `EXPECTED_CASES` went from
105 to 126. Phase 1's `1fd5cedd` retargeted
`qcow2-wide-subcluster-alloc-at-host-zero-unfilled` and
`qcow2-wide-subcluster-lookup-loses-the-bitmap` at the new refusal,
under new names. Phase 2 moved the crate's `ScChain` test harness to
the device layout the VMM writes: the data device at index 1, the
backing image at 2. Phase 1's cases were shown to kill against the old
layout, and each phase verified only its own new cases. No run has
shown that phase 1's cases still kill on the merged tree. That is the
cross-phase effect the shared block's accumulated-diff rule exists to
catch, so step 2 runs all 23.

### Corrected at source in this branch's planning commit

Recorded here so a later step does not redo the work, and so step 3c
verifies it rather than finding it:

* **Seven open issues this plan filed were missing from the master
  plan's Future work:** #794 and #795 (step 1a), #804 and #805
  (phase 1 execution), and #806, #807 and #808 (step 2a). Each was
  recorded only in a phase plan. The runbook's plan check would have
  found every one. All seven are now Future work entries.
* **Two consider items from #810's review** were noted in the session
  but recorded nowhere. They now sit in Future work: the data-file
  refusal names no device (item 2, folded into the #806 entry because
  #806 is what makes it reachable), and the parent-hint flat VMDK has a
  crate test but no integration test (item 6).
* **The master plan had no `## Status:` line.** Every other master plan
  in `docs/plans/` carries one under its title, and the runbook's plan
  check reads it. The line was added, reading `In progress`.
* **The three Open questions still read as open.** Phase 1 answered all
  three. Each now carries a one-line answer and points at where phase 1
  recorded it.
* **"Bugs fixed during this work" was written in the future tense**
  ("is planned to close"). Both phases have landed, so it now says what
  they closed: #653, #654 and #800 in phase 1, and #792 and #803 in
  phase 2.

### Still to settle: one Future work entry with no issue

The entry "check's allocation count on data-file images" records
`instar check` reporting `3/4097` where `qemu-img check` reports
`3/16`. Unlike its neighbours, it names no issue. #804 is a different
defect: it is about the numerator (L2 tables counted as allocated),
while this entry is about the denominator. Step 4 measures it on
`develop` and either files it or records that it no longer holds.

## Decisions

1. **Audit the union of the two merges, built once by
   `scope-patch.sh`.** Wave 1 and the wave 2 mechanical script take
   `--commits-file`. The four judgment agents get the materialised
   `scope.patch`, restricted to their paths, plus the current state of
   those files, because a patch shows what changed and not what the
   tree now says. Step 2 checks the patch against the survey's
   21 files and 12,474 lines before any agent reads it.

2. **Partition the judgment agents by dimension, not by phase**, as
   differencing phase 18 did, and for the same reason: two per-phase
   agents would reproduce the per-phase audit the shared block forbids.
   At 12,474 lines each dimension can read its whole slice, so there is
   no further split. The runbook's style-conformance judgment agent is
   folded into 3a rather than run separately. Its five questions are
   about call-table, crate and operation boundaries, and 3a is already
   reading exactly that code.

3. **Override the runbook's models for 2a and 2b.** `PUSH-AUDIT.md`
   specifies sonnet at medium effort for code quality and tests, which
   suits one pull request's diff. 3a reads a qcow2 reader that two
   phases rebuilt in sequence, where the second added a variant to the
   first's `ClusterLookup` and a skip to the head of the first's device
   loop. The findings worth having are whether every match arm, render
   site and walker absorbed both, and that is opus work at high effort.
   3b goes to opus at high effort because its main job is to find tests
   that pass without testing anything. This plan began with #654, a
   defect that a reachability probe showed `fuzz_chain_compose` had
   compared zero holes for across 132,908 executions. 3c stays on
   sonnet at high effort. 3d keeps the runbook's opus at high effort.

   This is stated explicitly because a sub-agent handed the runbook
   will otherwise treat its model table as authoritative and this
   plan's as a suggestion.

   This is the decision most open to argument: two opus agents at high
   effort over a 12,000-line patch could be called overkill. The
   argument for it is that the patch is small *because* it is dense.
   Most of the 4,136 lines added to the qcow2 crate are tests of the
   subcluster boundaries, and a sonnet pass at medium effort is the
   setting least likely to notice that one of them can no longer fail.

4. **3b makes measurements, not just readings.** Two questions in its
   dimension cannot be answered from a diff:
   * **Which tests in the two in-scope modules skip, and why.** Phase
     2's run skipped 549 tests across nine modules and nobody broke
     them down. Step 2 runs `test_qcow2_subclusters` and
     `test_check_formats` and keeps the subunit stream. 3b reads it,
     not the summary. It names every skip in those two modules and
     checks the reason, which should be a missing qemu capability.
     Any skip that hides a fixture which never built is a finding.
     3b also reads #810's `test-container-core` log for the same
     modules, so the count is from CI and not only from Kasm.
   * **Whether the 23 mutation cases this plan added still kill on the
     merged tree.** Step 2 runs them. 3b checks that each killed case
     died for the reason its comment gives, not just that it died.

5. **3d's brief names the host side first.** The VMM part of the scope
   is small: 455 added lines in `src/vmm/src/main.rs`. It is also the
   only part outside the sandbox, and it parses what the guest sends:
   a refusal status and a virtual offset, and two new map extent
   states (`zero-at`, `hole-at`, sent by the guest's
   `src/core/src/serial.rs`). Whatever the guest says arrives as untrusted bytes,
   so an unknown status, a status for the wrong marker or an offset
   near `u64::MAX` must not panic the VMM or render misleading text.
   The guest-side questions follow: whether the extent walk is bounded
   for every walker that can reach a flat VMDK's run, and whether #806
   fails closed for every operation, not only the `convert` and
   `compare` that step 2a measured.

6. **Findings are triaged in the management session (step 4), not by
   the agent that found them**, and the fixes land as a follow-up pull
   request after this one merges. An agent that fixes what it finds
   produces a diff nobody planned. The audit pull request carries only
   the record.

## Step plan

| Step | Effort | Model | Isolation | Brief for sub-agent |
|------|--------|-------|-----------|---------------------|
| 2 | medium | sonnet | none | **Materialise the scope and run the mechanical checks; fix nothing.** Work in the phase worktree. (1) Write `d08841e3` and `d42af1f5` one per line to `audit-scope.txt` in your scratch directory and run `tools/audit/scope-patch.sh --commits-file audit-scope.txt > scope.patch`. Confirm stderr reports 21 files and the patch is 12,474 lines (±1%). Anything else means the list is wrong: stop and report. (2) Run `tools/audit/wave1.sh --commits-file audit-scope.txt`, then `tools/audit/wave2-mechanical.sh --commits-file audit-scope.txt`. Keep both outputs whole, with exit codes, and never pipe them through `tail`. Both must print the 21-file count first. (3) Wave 1 runs `make test-rust` after `make instar`, and the two share `src/target/release`. So run `rm -rf src/target/release` and `make instar` before any integration test. (4) Run `tests/test_qcow2_subclusters.py` and `tests/test_check_formats.py` with stestr, saving the subunit stream (`stestr last --subunit > in-scope.subunit`). Report "Ran: N" and the pass, skip, expected-fail and failure counts. A failure that touches no qcow2 data file is replayed with `--serial` before you report it, since host load fails heavy cases on Kasm. (5) Run `tools/mutate-differencing.sh --self-test` and `--check-patterns`. List the 23 case names this plan added (the names added by `git diff d08841e3^1 d42af1f5 -- tools/mutate-differencing.sh`) and run them by name. Report killed or survived for each, with the test that killed it. The harness mutates copies. Never restore `src/` with `git checkout`. (6) Note that `make test-rust` excludes the `no_main` guest binaries and that the `qcow2` crate's `create` tests are feature-gated. Say so rather than reporting the run as total coverage. Report in under 500 words, with paths to the full logs. No commit. |
| 3a | high | opus | none | **Wave 2a, code quality, plus the runbook's style-conformance judgment portion.** Input: step 2's mechanical report; `scope.patch` restricted to `src/` and `tools/`; and the current state of those files. Read both, because the patch says what changed and the tree says what it now means. The question is what the two phases did to each other. Phase 1 built `SubclusterType`, `subcluster_range` and the `RefusedL2Entry` path in `src/crates/qcow2/src/lib.rs`. Phase 2 added `ClusterLookup::DataFileRefused`, `DataFileEntryRefusal`, the `is_data_device()` skip at the head of `read_chain_virtual_cluster`'s device loop, and a bound on the VMDK extent walk. Every `match` on `ClusterLookup` and `RefusedL2Entry` is inside the qcow2 crate, including the walkers `map`, `measure` and `check` link against. Check that each one handles every variant the way qemu would, with no `_ =>` arm swallowing the new one, and that the operations calling those walkers (`map`, `measure`, `check`, `convert`, `compare`, `bench`, `rebase`) all reach a refusal rather than a generic failure. Check that the VMM's eight render sites for the two refusals agree. Look for logic duplicated between the invalid-entry and data-file refusal paths. The qcow2 crate grew by 4,136 lines: the `source-file-size` block asks whether that growth has a seam of its own, such as a test module, and the answer is a judgment, not a gate. Triage every TODO, `unwrap`, `expect` and `unsafe` the mechanical script flagged, skipping `#[cfg(test)]`. Apply the runbook's five style questions (call-table symmetry, `no_std` crates, operation layout, unit-change discipline, inline workflow scripts). Report findings with file:line and blocking or advisory, in under 800 words; fix nothing. |
| 3b | high | opus | none | **Wave 2b, tests.** Input: `scope.patch` restricted to `tests/`, `tools/mutate-differencing.sh` and the crate test modules; step 2's subunit stream and mutation results; and the core CI log for #810's head `fbfaa946` (find the `test-container-core` job with `~/bin/ci-status shakenfist/instar runs --branch 654-subcluster-classification-phase-02-data-device`, then `logs JOB_ID`). Read the whole log. Never use `tail`, because `INSTAR_REQUIRE_LIBVHDI` is a precedent for a green run that skipped its oracle. The main job is to find tests that cannot fail. (1) Name every skip in `test_qcow2_subclusters` and `test_check_formats`, locally and in CI, with its reason. A skip that hides a fixture which never built, or a `qemu-io` invocation that failed silently, is a finding. (2) For each of the 23 mutation cases, confirm the killing test is the one its comment names. A case killed by an unrelated compile error or panic proves nothing. (3) Phase 2 moved the `ScChain` harness to the VMM layout. Check that phase 1's crate tests still build the image shape they describe. (4) Check `EXPECTED_FAILURES` in `tests/test_qcow2_subclusters.py`: each entry should cite an open issue (#806), and none should be expected to fail for a reason the issue does not cover. (5) Find every public function or error path added in scope with no test reaching it from outside the process, per the `functional-test-coverage` block. Report grouped by file in under 800 words; fix nothing. |
| 3c | high | sonnet | none | **Wave 2c, documentation.** Input: the seven files `scope.patch` touches outside `docs/plans/` (`CHANGELOG.md`, `docs/chain-config.md`, `docs/guest-architecture.md`, `docs/qcow2/qcow2-format.md`, `docs/qcow2/qcow2-l1l2-tables.md`, `docs/quirks.md` and `docs/testing.md`), plus `ARCHITECTURE.md` and `docs/format-coverage.md` read in full. The facts that must not disagree between pages: the chain config is version 4; bit 31 of a device's flags is `FLAG_DATA_DEVICE` and the host sets it; a data device sits in the slot right after its owner, or after a flat VMDK's run of extents; an invalid L2 entry and the two data-file entries are refused with qemu's wording; and an extended-L2 unallocated subcluster reads through to the backing file. For each, find every page that states it and check each against the code (`src/shared/src/lib.rs`, `src/vmm/src/main.rs`), not against another page. Check that `docs/testing.md`'s case count matches `EXPECTED_CASES`. Then run the runbook's four plan checks one at a time over `PLAN-654-subcluster-classification.md` and `docs/plans/index.md`. This branch's planning commit already corrected Future work, the `## Status:` line and the Open questions (see this plan's survey), so check those corrections rather than redoing them: grep the master plan for each of #794, #795, #804, #805, #806, #807 and #808. Report in under 600 words; fix nothing. |
| 3d | high | opus | none | **Wave 2d, security, host side first.** (1) What the VMM parses from the guest. The two refusals travel as a `send_error` whose operation string is a marker (`InvalidL2EntryRefusal` and `DataFileEntryRefusal`, `src/shared/src/lib.rs:3203` onwards). The VMM captures them at `src/vmm/src/main.rs:1020-1023` and renders them through `l2_entry_refused()` and `l2_entry_refusal_error()` (`:841-885`). The guest's `src/core/src/serial.rs` also sends two new map extent states, `zero-at` and `hole-at`, which the VMM's `map_state_triple` (`:16724`) parses. The status, virtual offset and state strings all arrive from the guest and are untrusted. Establish by reading and by running what an unknown status, a status sent under the other marker, a truncated message and an offset near `u64::MAX` do. None may panic the VMM or render text that misdescribes the image. (2) `write_chain_device_entries` marks data devices and masks bit 31 out of info-reported flags. Confirm a crafted image cannot make the host mark a device it did not open as a data file, and that external data file paths still pass the same allowlist as backing files. (3) Guest side: `ChainConfig::data_devices_are_owned` is a self-consistency check on a config the host writes. Confirm every reader of a data device goes through it, and that the VMDK extent-walk bound holds for every walker that can reach a flat VMDK's run (convert, compare, map, measure, check, rebase), not only the one phase 2 bounded. (4) #806 says a backing image's own data file is not discovered and reads fail closed. Phase 2 measured `convert` and `compare` only. Establish for every operation that reads such an image whether it fails closed or quietly reads the wrong device or zeros. A quiet wrong answer is at least high. Cite or measure every claim about qemu (qemu v10.0.0 source; static builds in `instar-testdata`). Report each finding with severity, file:line, vulnerability class and a recommended fix, in under 800 words. File any critical or high finding as a `security-audit` issue; fix nothing. |
| 4 | high | — | none | **Management session.** Read all four reports together. Assign every finding blocking, advisory-fix-now, or filed-as-issue, and record each with its evidence under an *Audit findings* heading in this plan. Check a finding against the deciding phase's plan before calling it a defect: a disagreement with a recorded decision is filed, not fixed. Re-measure at least one claim from each report. Measure the Future work entry with no issue (see the survey) and file it or record that it no longer holds. Then close out. If the audit raised findings, the plan stays `In progress` and the fixes land as a follow-up pull request after this one merges; that pull request records this phase's merge commit and sets `Complete`. If it raised none, set this phase's `Status`, the master plan's `## Status:` line and its `docs/plans/index.md` row to `Complete` here, and leave the `Merged` cell empty. Commit subject: "Record the PLAN-654 push audit." |

Steps 3a to 3d read only and can run in parallel once step 2 has
reported. Step 2 writes build output to the shared worktree, so it runs
alone and first.

## Risks and mitigations

| Risk | Mitigation |
|---|---|
| Step 2 transcribes a SHA wrongly and the audit reads a subset | Step 2 stops unless `scope-patch.sh` reports 21 files and about 12,474 lines. Both numbers were measured during the survey, and a mis-transcription moves them. |
| Host load fails heavy integration cases and a flake is read as a finding | Step 2 replays any failure that touches no qcow2 data file with `--serial` before reporting it. That pattern was measured on Kasm in both earlier phases. |
| The mutation run takes long enough to tempt a subset | All 23 cases run. Phase 2's harness move is the reason the audit runs them, and the cases most at risk are phase 1's, which a subset would be tempted to drop. |
| An agent treats the runbook's model table as authoritative and under-reads | Decision 3 states the override and its reason. Each step row carries its own model and effort, and that is what the implementer follows. |
| A finding re-litigates a choice a phase decided in writing | Step 4 checks each finding against the deciding phase plan. Both phases' execution notes record what review raised and what was declined. |
| An agent asserts a plausible but wrong qemu capability, as this repository's history says they do | 3d's brief requires cite-or-measure, and step 4 re-measures at least one claim per report before accepting it. |

## Definition of done

Falsifiable, in the order a reviewer can check them:

* `scope.patch` was built by `tools/audit/scope-patch.sh` from a file
  naming exactly `d08841e3` and `d42af1f5`, reports 21 files, and is
  within 1% of 12,474 lines.
* `tools/audit/wave1.sh --commits-file` exits 0 over that scope, or each
  non-zero exit is recorded in this plan with its disposition. Both
  scripts printed the 21-file count.
* The two in-scope integration modules ran on a freshly built binary.
  This plan records their "Ran: N" and the count of each outcome, and
  names every skip with its reason.
* All 23 mutation cases this plan added were run on the merged tree.
  This plan records each one as killed, with the killing test, or as
  survived with a disposition.
* All four wave 2 reports exist, and each names the files it read. Each
  of their findings appears under *Audit findings* with a disposition:
  blocking, advisory, or an issue number.
* Every finding disposed of as an issue has a real issue number that
  `gh issue view` shows open.
* `grep -c` on the master plan finds each of #794, #795, #804, #805,
  #806, #807 and #808 inside its Future work section.
* The Future work entry on check's allocation count names an issue, or
  has been removed with the measurement that retired it recorded here.
* If the audit raised no findings: this phase's `Status`, the master
  plan's `## Status:` line and its `docs/plans/index.md` row all read
  `Complete`, and this row's `Merged` cell is empty. If it raised
  findings: all three still read `In progress`, and this plan names the
  follow-up pull request's scope.
* `docs/plans/order.yml` is untouched.
* `pre-commit run --all-files` passes.

## Back brief

Confirm before step 2:

* That models and efforts follow this plan's step table rather than the
  runbook's (Decision 3).

Gate before steps 3a to 3d are spawned: report step 2's output (scope
size, wave 1 exit code, integration counts, mutation results) and wait.
Four high-effort agents are the expensive part of this phase, and if
step 2 shows a mutation case surviving or a fixture skipping, the
briefs should change before they run.

## Execution notes

* 2026-10-22 (AEDT), back brief. Michael confirmed the step table's
  models over the runbook's (Decision 3). He relaxed the gate before
  3a to 3d: carry on without waiting if step 2 is clean, and stop only
  if a mutation case survives, a fixture skips without a capability
  reason, wave 1 fails or the scope size is off. He also gave
  permission to push and open the pull request once the definition
  of done passes.
* Step 2, on HEAD `29bd35e2`, was clean, so 3a to 3d ran without a
  pause.
  * **Scope:** `scope-patch.sh` reported 21 files and 12,474 lines,
    the survey's figures exactly, and both wave scripts printed the
    21-file count.
  * **Wave 1:** `wave1.sh --commits-file` exited 0. `make test-rust`
    passed 2680 with 0 failed and 3 ignored.
  * **Integration:** on a freshly built binary, the two in-scope
    modules ran 314 tests: 306 passed, 2 skipped, 6 expected
    failures, 0 unexpected successes, 0 failed.
    * Both skips are `TestZstdBackingChain` cases, skipped because
      qemu-img 10.0.13 does not support ZSTD.
    * Two of the expected failures are `data_file_mid_chain` (#806).
      The other four are the compressed-cluster map divergence
      documented in `docs/quirks.md`.
  * **Mutation:** `--self-test` and `--check-patterns` (126 land)
    pass, and all 23 cases fail their named test as required.
* Step 2 corrected this plan in two places, both now fixed at source:
  * The plan added 23 mutation cases, not 21. The net count of 21
    hid two phase 1 cases retargeted under new names.
  * `src/core/src/serial.rs` carries no refusal marker. Its two lines
    are map extent states, sent by the guest. Decision 5 had also
    counted the file as host-side code, but `src/core` is the guest's
    runtime. Decision 5 and 3d's brief now point at the marker in
    `src/shared` and the VMM's capture and parse sites.
