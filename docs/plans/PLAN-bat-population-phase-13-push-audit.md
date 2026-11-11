# Phase 13: the push audit

Phase 13 of [PLAN-bat-population.md](PLAN-bat-population.md), the last
row of its Execution table. Read the `plan-push-audit-phase` shared
block in the master plan before anything else: it defines what this
phase is for and why its scope cannot be derived after the fact. Then
read `PUSH-AUDIT.md`, which is the runbook this phase executes.

This phase audits the accumulated work of phases 1 to 12 and **changes
no code**. Its steps are readers. The management session writes the
record, which is the commit.

Planning effort: medium. The judgement in a push audit is in scoping it
and in triaging what comes back, not in inventing a method -- the
runbook and the scope tooling both exist, and a previous push-audit
phase in this repository has already been through the traps. What this
plan mostly has to get right is the commit list, and that it is honest
about the parts it cannot cover.

Review effort: high, concentrated in one place. An audit that reports
nothing is indistinguishable from an audit that ran over nothing, and
this phase has a live instance of exactly that failure (see the survey).
The review that matters is of the resolved scope, not of the findings.

## Scope

In: the union of the first-parent diffs of the twelve merge commits that
put phases 1 to 12 on `develop`, which resolves to **78 files**; and the
three Python scripts phase 10 landed in `instar-testdata`.

Out: fixing what the audit finds. Findings land as their own pull
request after this one merges, per the shared block and the
`implement-phase` skill. Also out: the 17,271 generated files in
`instar-testdata` (decision 3).

The commit list, which is the whole of this phase's scope and the one
thing a reader should check first:

```
fef62417  phase 1   #809
5c5bba75  phase 2   #819   (instar half; see decision 4)
a8d2f4ca  phase 3   #824
d140aa04  phase 4   #835
52518787  phase 5   #848
aef757d2  phase 6   #853
03269d7f  phase 7   #858
e49b6275  phase 8   #874
3b74ba8d  phase 9   #877
e0b0fe13  phase 10  #881   (instar half; see decision 2)
41f74d40  phase 11  #884
2da0c22e  phase 12  #889
```

Plus, in `instar-testdata`, the recovered range `99c8663c34..f73d43670a`
(decision 2), of which only `scripts/detect-profiles.py`,
`scripts/generate-baselines.py`, `scripts/validate-profiles.py`,
`README.md` and `Makefile` are in scope.

## What the survey found

The master plan's phase 13 row is one line -- "Push audit:
`PUSH-AUDIT.md` over every phase above" -- so there was little to be
stale. The survey's work was establishing that the scope is
constructible, and it found one thing wrong and one thing missing.

### Every recorded merge commit is real, and the record is complete for `instar`

All twelve are two-parent merge commits, all are ancestors of
`origin/develop`, and all name a `bat-population` pull request. The
shared block warns that phases which landed before a plan started
recording them have to be reconstructed from `gh pr list` and
`git rev-list`; none of that is needed here. This is a real result and
the reason this phase can be planned at medium effort.

### The default audit scope is not empty here -- it is wrong, which is worse

`PUSH-AUDIT.md` says a push-audit phase must pass `--commits-file`,
because `develop...HEAD` covers only what the audit branch adds and an
empty range reads as a clean audit. On this machine it is worse than
empty. The local `develop` branch is stale at `e0b0fe13`, four merges
behind `origin/develop`, so the implicit scope resolves to **47 files**
-- drawn from the renovate bumps, a nightly-toolchain bump and the
assurance pull request that landed between phases, and containing almost
none of phases 1 to 11.

An empty scope invites suspicion. A plausible-looking 47-file scope of
unrelated work does not. Measured:

```
audit scope: 47 files (develop...HEAD)                 <- wrong
audit scope: 78 files (--commits-file phase-merges.txt) <- correct
```

### Phase 10's `Merged` cell is missing its `instar-testdata` half

The shared block requires a phase that landed in another repository to
record `<repo> <sha> (#pr)`. Phase 2 did: its cell reads
`instar-testdata d2f9467719 (direct to main); instar 5c5bba75 (#819)`.
Phase 10 did not -- its cell names only `e0b0fe13` (#881), although four
of its steps (10a to 10d) landed work in `instar-testdata`: the aimable
baseline generator, this plan's create cases, the derived-profile
validator and the per-image fixture baselines.

The range is recoverable, which is the good case the shared block hopes
for rather than the "no range is recoverable" case. Six contiguous
commits on 2026-11-07 in that repository, `99c8663c34..f73d43670a`,
sitting cleanly after the 2026-11-06 nightly fuzz-corpus commits and
before the next day's. They match steps 10a to 10d one for one. This
phase records that range in phase 10's `Merged` cell as a correction at
source.

### `instar-testdata` has no `PUSH-AUDIT.md`, so there is no audit to cite

The shared block says a phase landing in another repository is audited
against that repository's default branch as part of the pull request
that lands it, and that this plan's push-audit phase cites that audit
rather than re-running it. Neither half of that is available here.
`instar-testdata` has no `PUSH-AUDIT.md` -- its `audit/` directory holds
`run-qemu-img-audit.py`, a qemu-img capability audit, which is a
different thing entirely -- and that repository takes direct commits to
`main` rather than merge requests, so there was never a pull request to
audit within. The shared block's instruction for a repository with no
runbook is to say so and say what was done instead, which this phase
does, and decision 3 sets what is done instead.

### The instrument already works, and its limits are known

The scope mechanism this phase depends on was built by a previous
push-audit phase in this repository, `PLAN-differencing-phase-18-push-audit.md`,
whose own step 1 was to give the wave scripts an explicit scope.
`tools/audit/audit-scope.sh`, `wave1.sh` and `wave2-mechanical.sh` all
exist, with tests beside them. `audit-scope.sh` is sourced rather than
executed -- running it directly prints nothing and exits quietly, which
cost this survey a wrong answer before the file's own header corrected
it, and which the step briefs therefore state outright.

That phase also recorded what its audit could not reach, and this phase
inherits the same limits: `wave1.sh` has no integration-test step, so the
only Python executed is whatever the test-review step runs itself; and
the mutation harnesses are not run, because a full run needs docker,
testdata and `/dev/kvm` together.

### Scope shape

The 78 files, by area, so the judgement steps can be briefed concretely:

| Area | Files |
|---|---|
| `docs/` | 30 |
| `tests/` | 17 |
| `src/crates/` | 8 |
| `src/operations/` | 5 |
| `src/fuzz/` | 5 |
| `tools/` | 4 |
| `scripts/` | 2 |
| `src/vmm/`, `src/shared/` | 1 each |
| `ARCHITECTURE.md`, `AGENTS.md`, `CHANGELOG.md` | 1 each |
| `.github/`, `.gitignore` | 1 each |

### Corrected at source

Phase 12's row is set to `Complete` with `2da0c22e` (#889), and phase
10's `Merged` cell gains its `instar-testdata` range, in this phase's
first commit.

## Decisions

1. **The audit runs with `--commits-file`, never the default scope, and
   the resolved file count is reported before any check runs.** This is
   `PUSH-AUDIT.md`'s own instruction, and the survey found the default
   resolves to 47 files of unrelated work on this machine rather than to
   nothing. Every step that reads files states the count it saw, so a
   step that silently audited the wrong set is visible in its own
   report.

2. **Phase 10's `instar-testdata` range is recorded in the master plan
   as `99c8663c34..f73d43670a`, and the recovery is described as a
   recovery.** The shared block requires reconstructed ranges to be
   labelled as reconstructed; this one is clean enough to state as fact,
   but how it was derived -- six contiguous commits between two nightly
   fuzz-corpus runs, matching steps 10a to 10d -- goes in the plan so
   the next reader can falsify it rather than trust it.

3. **The audit reads `instar-testdata`'s three scripts and runs its
   validator; it does not read the 17,271 generated files.** That range
   changes 17,276 files, of which 17,271 are generated `expected-outputs`
   data and five are code or documentation. Reading generated data is not
   an audit, and 17,000 files would swamp the phase and the agent's
   context both.

   This is the decision most likely to be argued with, and the argument
   against it is good: the derived profile directories in that
   repository have been silently wrong twice while the raw baselines were
   fine and the suite stayed green, so "the data is generated" is
   precisely not a reason to trust it. The answer is that phase 10 added
   `scripts/validate-profiles.py` for exactly that reason, and the
   useful audit is of the validator and of whether it actually runs --
   not of its inputs one file at a time. So the step reads the three
   scripts as code and *runs* the validator, and reports its exit status
   and what it covers. If the validator turns out not to cover the
   generated set, that is a finding, and a better one than any number of
   hand-read baselines.

4. **Phase 2's `instar-testdata` half is cited, not re-audited.** Its
   cell already records `d2f9467719`, and that work is five fixtures
   plus a generator, superseded in place by phase 10's changes to the
   same scripts, which decision 3 does cover. The phase says so rather
   than implying coverage it does not have.

5. **Findings are recorded and fixed in this phase.** This reverses
   what this plan originally decided, on Mikal's instruction at the back
   brief. The shared block and the `implement-phase` skill both say a
   push audit records its findings and a follow-up pull request resolves
   them, and the reason is that an audit-plus-fixes diff stops being
   reviewable as an audit. That cost was put to him and he chose to
   accept it, so the fixes land here and there is no follow-up pull
   request to wait for.

   Two consequences follow and are handled rather than left implicit.
   This phase therefore *does* change code, so the definition-of-done
   item asserting it changed none is replaced by one bounding what it
   may change. And this phase's own pull request is what marks the plan
   `Complete`; its `Merged` cell stays empty, because a phase cannot
   know its own merge commit while it is being written, and whoever
   next touches the plan fills it in. Two of the three push-audit
   phases already in this repository carry a filled cell and one is
   empty; the filled ones were filled afterwards, which is the same
   thing.

   The audit steps themselves are still readers. Nothing in 2a to 2e
   may change a file: findings come back as reports, the management
   session triages them, and the fixes are made afterwards as their own
   commits so that the audit and its remedies stay separable in the
   history even though they share a pull request.

6. **The four judgement steps run in parallel.** They are read-only, so
   they cannot collide in the worktree, and none consumes another's
   output. This is the one place a push-audit phase is cheaper than an
   implementation phase.

## Step plan

Step 1 runs first and alone: the later steps consume its resolved scope
and its mechanical report. Steps 2a to 2e then run together. Step 3 is
the management session.

| Step | Effort | Model | Isolation | Brief for sub-agent |
|------|--------|-------|-----------|---------------------|
| 1 | medium | sonnet | none | Materialise the audit scope and run the mechanical waves. Write the twelve merge commits from this plan's Scope section, one per line, to `audit-commits.txt` in the session scratch directory (NOT in the worktree). Then run `tools/audit/wave1.sh --commits-file <that file>` and, if wave 1 passes, `tools/audit/wave2-mechanical.sh --commits-file <that file>`. Note that `tools/audit/audit-scope.sh` is *sourced* by those scripts, not executed -- do not try to run it directly, it prints nothing and exits quietly. Report the resolved file count each script prints; it must be 78, and if it is not, stop and say so rather than continuing, because a different count means the scope is wrong. For the test totals, read the `Ran:` and `Failed:` lines rather than trusting the exit code, which is unreliable in this repository. Save both scripts' full output to the scratch directory and give the paths. Change no file in the worktree. |
| 2a | high | opus | none | Wave 2a, code quality, per `PUSH-AUDIT.md`'s 2a section, over the Rust in the audit scope: 8 files under `src/crates/`, 5 under `src/operations/`, 5 under `src/fuzz/`, and one each in `src/vmm/` and `src/shared/`. Resolve the scope with `--commits-file` as step 1 did and state the count you saw. The thing to look for across twelve phases is what the phases did to each other rather than what each did alone: a helper duplicated once two phases had both landed, a constant defined twice, an invariant one phase established and a later one quietly weakened. The VHDX layout work was deliberately consolidated into one shared function during the plan, so check it really is one. Report findings with file and symbol, severity, and the evidence; report "nothing" explicitly if that is the answer. Change no file. |
| 2b | high | opus | none | Wave 2b, tests, per `PUSH-AUDIT.md`'s 2b section, over the 17 files under `tests/` in the audit scope, the crate test modules inside the scope diff, and `src/fuzz/`. Resolve the scope with `--commits-file` and state the count. Five fuzz targets and a differential-fuzzer arm were added across the plan; confirm each is registered everywhere it must be (the `.rs` file, `src/fuzz/Cargo.toml`, `coverage-fuzz.yml`'s `TARGETS`) and that `tools/ci/check-fuzz-targets.sh` passes. The specific risk this plan carries is a guard that cannot fail: phases 10 to 12 added classification tests and structural comparisons whose oracles are themselves in the diff. Pick the three you trust least and say for each whether a regression would actually fail it. You may run tests; you may not change any file. Note `wave1.sh` has no integration-test step, so anything you do not run here is unrun. |
| 2c | high | sonnet | none | Wave 2c, documentation, per `PUSH-AUDIT.md`'s 2c section, over the 30 `docs/` files in the audit scope plus `ARCHITECTURE.md`, `AGENTS.md` and `CHANGELOG.md`. Resolve the scope with `--commits-file` and state the count. Phase 12 swept the cross-cutting pages six commits ago, so the question is not whether they were updated but whether twelve phases left any fact stated two different ways -- the VHDX default block size, which subformats each command writes, and the preallocation behaviour are the three that moved most and are where to look first. Also check no file under `docs/` outside `docs/plans/` cites a source line number or a plan phase, step or decision number; both are pre-commit-enforced, so a hit is a real escape. Change no file. |
| 2d | high | opus | none | Wave 2d, security, per `PUSH-AUDIT.md`'s 2d section, over the parsing and writing paths this plan touched: the VHDX BAT and metadata paths in `src/crates/vhdx/`, the fixed-layout emitters in `src/crates/create/`, and the host-side option and size handling in `src/vmm/`. Resolve the scope with `--commits-file` and state the count. This plan writes attacker-influenced geometry into on-disk structures and reads it back, so the shapes that matter are: an arithmetic overflow in a BAT offset or entry count, a length used before it is bounds-checked, a cast narrowing a u64 to u32, and a guest-side buffer sized from image-supplied values. The crates are `no_std` and must be panic-free, so an unchecked arithmetic operation is a defect even where the value cannot currently reach it. Report with file, function and the input that would reach it. Change no file. |
| 2e | medium | sonnet | none | Audit the `instar-testdata` half. Work in the clone at `../instar-testdata` (branch `main`); do NOT create a worktree there and do NOT commit anything. Scope: the five non-generated files in `99c8663c34..f73d43670a` -- `scripts/detect-profiles.py`, `scripts/generate-baselines.py`, `scripts/validate-profiles.py`, `README.md` and `Makefile`. Read the three scripts as code (Python conventions: single quotes, 120 columns). Then RUN `scripts/validate-profiles.py` and report its exit status, what it printed, and -- the question that matters -- which of the 17,271 generated files under `expected-outputs/` it actually validates, and which it does not look at. Do not read the generated files individually; there are 17,000 of them and that is not an audit. Note this repository has no `PUSH-AUDIT.md`, so there is no runbook to follow and no prior audit to cite; say what you checked and what you could not. |
| 3 | high | — | none | Management session. Triage every finding from 1 and 2a-2e into blocking, fix-in-follow-up, or filed-as-issue, record the disposition of each in this plan under "Audit findings", write the "Coverage this audit did not have" section, and commit the record. |

## Risks and mitigations

| Risk | Mitigation |
|---|---|
| A step resolves the default scope and audits 47 files of renovate bumps, reporting a clean result | Every reading step is briefed to print the resolved count and to stop if it is not 78. Step 1 stops the phase rather than continuing. The management session checks the count in each of the six reports before triaging a single finding. |
| An agent runs `audit-scope.sh` directly, gets nothing, and proceeds against an empty set | Every brief states that the file is sourced, not executed, and that running it prints nothing. This is in the briefs because it happened during the survey. |
| The 17,271 generated testdata files swamp step 2e | The brief bounds it to five files and forbids reading the generated set, and redirects the effort to the validator's coverage, which is the useful question. |
| The audit reports nothing and that is taken as a pass | The phase records a negative result as a negative result, in one sentence per step, and the "Coverage this audit did not have" section is a required part of the record rather than an optional caveat. |
| A judgement agent fixes what it finds | Every brief says to change no file. The steps are readers; step 3 writes. A step that returns a diff has its diff discarded and its finding triaged. |
| Findings grow into a thirteenth implementation phase | Decision 5: findings are recorded here and fixed in a follow-up pull request, which is what marks the plan complete. |

## Definition of done

* `audit-commits.txt` holds exactly the twelve shas in this plan's Scope
  section, and for each, `git rev-list --parents -n1` shows two parents
  and `git merge-base --is-ancestor <sha> origin/develop` succeeds.
* Both mechanical scripts printed `audit scope: 78 files
  (--commits-file ...)`, and the count appears in step 1's report.
* Wave 1's result is recorded with its test totals read from the `Ran:`
  and `Failed:` lines, not from an exit code.
* Each of 2a, 2b, 2c, 2d and 2e produced a report that states the
  resolved file count it saw, and either findings or an explicit
  statement that it found nothing.
* Every finding is recorded under "Audit findings" with a disposition of
  blocking, fix-in-follow-up, or filed-as-issue, and every one filed as
  an issue has an issue number.
* The master plan's phase 10 row names the `instar-testdata` range, and
  its phase 12 row reads `Complete` with `2da0c22e`.
* The plan states in writing that `instar-testdata` has no
  `PUSH-AUDIT.md` and what was done instead.
* A "Coverage this audit did not have" section exists and names at least
  the integration suite and the mutation harnesses.
* Every file this phase changed outside `docs/plans/` is traceable to a
  recorded finding: for each path in `git diff --name-only
  origin/develop`, either it is a plan file, or the "Audit findings"
  section names the finding it fixes. A fix with no finding behind it is
  scope creep and is reverted.
* Phase 13's row leaves its `Merged` cell empty, for the follow-up
  pull request to fill once this phase has merged.

## Back brief

Answer before any step runs:

1. **Is decision 3 right to leave the 17,271 generated files unread?**
   The counter-argument is real: those derived directories have been
   silently wrong twice before. The plan's answer is to audit the
   validator rather than its inputs.
2. **Should step 2e run `validate-profiles.py` at all?** It is a local
   read-only script in another repository's clone, but it is still
   running something rather than reading it, and that clone is one the
   fuzz automation commits to daily.
3. **Is a follow-up pull request the right home for the findings**, or
   should trivially safe ones be fixed in this phase's own pull request?
4. **May this session push and open the pull request** when the record
   is written?

## Out of scope

* Nothing the audit finds is out of scope to fix, by the back brief's
  instruction -- but a fix still needs a finding behind it. Something
  noticed in passing that no audit step reported is filed, not fixed.
* The 17,271 generated `expected-outputs` files in `instar-testdata`
  (decision 3).
* Re-auditing phase 2's `instar-testdata` fixtures (decision 4).
* Writing a `PUSH-AUDIT.md` for `instar-testdata`. The gap is recorded
  here and is worth an issue, but authoring another repository's audit
  runbook is not this phase's job.
* The master plan's Future work list. The audit may add to it; it does
  not work through it.
