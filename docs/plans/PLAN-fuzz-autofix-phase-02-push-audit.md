# Phase 2 — push audit of the autofix loop

Parent plan: [PLAN-fuzz-autofix.md](PLAN-fuzz-autofix.md)

The last phase of the plan: run `PUSH-AUDIT.md` over everything this
plan built, fix or decline what it finds in writing, and close the
plan.

## Goal

Audit the accumulated work of the whole plan — the workflow, the
stager, the result helper, their tests and their documentation — as
one body of code, rather than one phase at a time. Land the findings
as this phase's pull request, record each one as fixed or declined in
the master plan, and set the plan `Complete`.

## Planning effort

High, and the reason is scoping rather than difficulty. Every phase
of this plan has already merged, so `git diff develop...HEAD` is
empty and there is no range to audit; the scope had to be
reconstructed commit by commit from the merge history, and two of the
merges belong to other plans' pull requests. Getting that wrong makes
the audit either vacuous or unreadably wide.

## Review effort

The master plan does not specify one. Read this at medium: the
judgement worth checking is the scope table, Decision 4 and
Decision 7, not the individual step briefs.

## Scope

**In scope**

* `PUSH-AUDIT.md` wave 1 and wave 2 over the reconstructed scope
  below: `.github/workflows/fuzz-autofix.yml`, the phase-1 changes to
  `.github/workflows/test-drift-fix.yml`, the `ci-tooling` job in
  `.github/workflows/functional-tests.yml`, `tools/autofix-prompt-base.txt`,
  `tools/fuzz-issue-schema.json`, `tools/ci/stage-autofix-changes.sh`,
  `tools/ci/claude-result.sh`, `tools/ci/autofix-artifact-patterns.sh`,
  their two test scripts, and the deleted comment-addresser files.
* The documentation this plan wrote or should have written:
  `docs/testing.md`'s *Automated bug fixes*, `docs/development.md`'s
  script index, `docs/security-audits.md`, `docs/commentary/reading-order.md`
  step 14, and `AGENTS.md`.
* Fixing the blocking findings on this branch, and writing the
  declined ones into the master plan with the reason.
* Correcting the master plan's stale Execution-table cell and
  recording the reconstructed scope there (see *What the survey
  found*).

**Out of scope**

* **PR #533 and the rebase-planner bug behind #483/#485/#492.** #533
  is what the loop *produced*, not the loop. It merged as `aaee69b`
  and was reviewed on its own merits as an ordinary change, which is
  exactly what phase 1 said would happen. Auditing it here would
  audit the fuzzer's finding rather than this plan's machinery.
* **The rest of PR #226 and PR #484.** The workflow was born inside
  #226 (the security-audit plan's pull request) and touched again in
  #484 (fuzz crash reporting). Those pull requests carry their own
  plans and their own audits; only their commits that touch this
  plan's paths are in scope, path-filtered.
* **Issues #529 (reproducer never executed) and #534 (turn budget
  exhausted before the commit summary).** Both are open, both are
  already in the master plan's Future work, and both are behaviour
  changes rather than audit findings. If the audit re-derives either,
  the finding is "already tracked as #NNN" and nothing more.
* **Rust source, guest operations, format crates.** This plan changed
  none of them. Wave 1 still builds and tests them (Decision 4), but
  no finding about them is this plan's to fix.

## What the survey found

The master plan's phase 2 section is short and its factual claims
mostly hold. Two do not, and the scope it assumes does not exist in
the form it describes.

### The Merged column is one pull request short

`PLAN-fuzz-autofix.md:139` records phase 1 as `` `b6b67a8` (#520),
`931b5a9` (#530) `` and the prose below it says "the close-out pull
request that records the result adds its own merge commit to that
cell when it lands". It has landed: `7b4e860` (#535), on 2026-08-31.
Corrected at source as part of this planning commit.

### There is no "union of merge ranges" to audit

The master plan says phase 2 "runs `PUSH-AUDIT.md` over this plan's
accumulated diff against `develop` — every phase's work together",
and `PLAN-TEMPLATE.md`'s `plan-push-audit-phase` block says the range
has to have been recorded as each phase landed. For this plan it was
not, because most of the work predates the Execution table entirely —
the master plan says so itself at `:130`. So the scope was
reconstructed, per that block's instruction, from
`git log --ancestry-path --merges <sha>..develop` for every commit
that has touched the plan's paths. The result:

| What | Landed as | PR | In scope |
|------|-----------|----|----------|
| The workflow itself — `2fcf75e`, `382c5bf`, `14a2680`, `b91511a`, `7205b2a`, `1775257` | `af1bdb1` | #226 | These six commits only, path-filtered. #226 is `PLAN-audit.md`'s pull request and its diff is enormous. |
| Prompt and schema follow-ups — `a705cad` | `22e8fa7` | #484 | That one commit, path-filtered. #484 is the fuzz-crash-reporting pull request. |
| The staging fix and its tests — eleven commits | `3d5a612` | #509 | The whole merge. |
| Addresser staging — three commits, ending `fe917dc` | `7b1afe4` | #511 | The whole merge. Its file has since been deleted; the diff still shows what the stager was asked to do in `--tracked-only` mode. |
| Phase 1, part 1 — the result helper and the three call sites, nine commits | `b6b67a8` | #520 | The whole merge. |
| Phase 1, part 2 — testdata checkout, two commits | `931b5a9` | #530 | The whole merge. |
| Phase 1 close-out | `7b4e860` | #535 | The whole merge. |
| Retirement of the comment addresser (`14e9cba`) | `2353c98` | #524 | Path-filtered: the deletion of `tools/address-comments-with-claude.sh` and its three helpers. #524 is the consistency-audit pull request. |

Two rows of this table were re-derived independently by the
management session before step 3 started, which the risk table
requires. `af1bdb1` (#226) yields exactly the six commits named and
no others, confirming that row. `3d5a612` (#509) carries **eleven**
commits, not the nine first written here, and `b6b67a8` (#520)
carries **nine**, not five; the counts above are corrected. Neither
error changed the scope, because both rows take the whole merge and
the patch is built with `git diff <merge>^1 <merge>`, but step 4's
brief walks the commits one by one and an understated count would
have let it stop early.

Deliberately excluded, having touched the same files for unrelated
reasons: `3926404` (imago→instar rename), `2e52304` (#482, the
two-image CI split), `9327c64`/`fcd5ad7`/`51f928b`/`f98930f`
(renovate action bumps), `91356c6` (testdata LFS prep), `6cf325e`
(merge queue cancellation), `4ea702d` (skills loadable).

The command that reproduces the scope is in Decision 1. It was run
during planning and yields **7,887 lines** of patch, beginning with
the creation of `.github/workflows/fuzz-autofix.yml` in `2fcf75e`;
the current state of the eight surviving files is 3,086 lines. Both
are small enough to hand to a judgement agent whole, which is why
Decision 1 hands over both.

### Both audit scripts read a range that is empty here

`tools/audit/wave1.sh:88` and `:119`, and every check in
`tools/audit/wave2-mechanical.sh`, compute from `git diff
develop...HEAD`. On this branch that is empty until the plan file is
committed, and even then it contains only this document. Left alone
the scripts would report a clean audit of nothing. Decision 2 says
what to do about it.

### wave2-mechanical.sh has almost nothing to say about this diff

It greps `*.rs` for TODOs, `#[allow(dead_code)]`, `#[test]` counts,
`unsafe {}` blocks and `.unwrap()`. This plan added no Rust at all —
the entire scope is YAML, bash, a prompt text file and a JSON schema.
Its one relevant check is the adversarial-file placement grep. The
shell-and-YAML equivalent does not exist and is written into step 2's
brief rather than added to the script, because it is this diff's
shape and not a general one.

### wave1's inline-script check bites, and is itself broken

`tools/audit/wave1.sh:99`-`:113` warns on `run: |` blocks over five
lines in `.github/workflows/*.yml`, which is CLAUDE.md's "no large
scripts in CI workflow steps" rule. `fuzz-autofix.yml` is 1,125 lines
and this plan's central artefact, so unlike the Rust half of wave 1
this check fires on something real. It is the one place where the
audit's mechanical wave has a genuine question to ask about this
diff.

Running it during planning found two defects in the check itself,
which matter because they would have silently degraded this phase's
own audit:

* **The reported line numbers are wrong.** The awk prints `NR`, the
  record number accumulated across every file in the glob, where it
  means `FNR`, the line number within the current file. Only the
  first file alphabetically gets correct numbers. The advisory
  currently reports `.github/workflows/fuzz-autofix.yml:2147` for a
  file that is 1,125 lines long; `sed -n '2147p'` on it prints
  nothing. Every number the check has ever printed for any workflow
  but `coverage-fuzz.yml` has been past that file's end.
* **`head -20` truncates past the in-scope files.** There are 32 hits
  across the ten workflow files. Sorted by filename, the cap falls
  inside `fuzz-autofix.yml`: two of its four hits are shown, and
  `test-drift-fix.yml`, this plan's other workflow, contributes six
  hits of which **none** are printed. Wave 1 as it stands cannot show
  this phase its own findings.

With `FNR` substituted and the cap removed, the true hits in the two
in-scope workflows are:

| File | Line | Block |
|------|------|-------|
| `fuzz-autofix.yml` | 79 | 13 lines |
| `fuzz-autofix.yml` | 213 | 11 lines |
| `fuzz-autofix.yml` | 876 | 9 lines |
| `fuzz-autofix.yml` | 1076 | 25 lines |
| `test-drift-fix.yml` | 82 | 20 lines |
| `test-drift-fix.yml` | 124 | 15 lines |
| `test-drift-fix.yml` | 204 | 9 lines |
| `test-drift-fix.yml` | 242 | 7 lines |
| `test-drift-fix.yml` | 512 | 9 lines |
| `test-drift-fix.yml` | 759 | 16 lines |

Decision 7 says what this phase does about the check. The ten hits
above are the input to step 3's judgement, not findings in
themselves — the rule has legitimate exceptions and a `run:` block
that only assembles a heredoc is not a script.

### PUSH-AUDIT's security brief does not describe this code

Wave 2d is written for the VMM and the format parsers: virtio
descriptors, decompression bounds, `MAX_CHAIN_DEVICES`, unsafe
blocks. None of it applies. What this plan actually built is a
self-hosted runner job that runs `claude --dangerously-skip-permissions`
with a repository write token, on a prompt assembled from a GitHub
issue body — and that surface has already produced one fix in this
plan's own history (`1775257`, *Close prompt injection loophole with
structured JSON*). Decision 5 replaces the 2d brief for this phase.

### Claims that checked out

* `git diff develop...HEAD` is empty for phase 1's merged branch —
  verified before the worktree was removed.
* The comment addresser really is gone:
  `tools/address-comments-with-claude.sh`,
  `tools/ci/reset-autofix-worktree.sh`,
  `tools/ci/test-reset-autofix-worktree.sh` and
  `tools/ci/test-address-comments-staging.sh` are all absent, and
  nothing in the tree references any of them. The `autofix` in
  `reset-autofix-worktree.sh`'s name was misleading — it served the
  addresser, not `fuzz-autofix.yml`.
* Phase 1's done-criteria spot-check: `grep -rn 'Co-Authored-By:
  Claude Opus' .github/ tools/` is empty;
  `tools/ci/test-claude-result.sh` exists and
  `functional-tests.yml` runs it at `:142`; `output-format text`
  appears zero times in either workflow and `stream-json` appears six
  and three times.
* The "30-turn limit" in `docs/development.md:778`,
  `docs/testing.md:1301`, `docs/security-audits.md:504` and
  `docs/commentary/reading-order.md:476` is **not** stale, despite
  the master plan's Future work saying runs happened "at 30 turns,
  then 40". `fuzz-autofix.yml:60` is
  `MAX_TURNS: ${{ inputs.max_turns || '30' }}` — 30 is the schedule's
  default and 40 was a dispatch input. Four documents agreeing with
  the code is worth recording so step 5 does not re-open it.

Corrections made at source in this planning commit: the Merged cell
for phase 1, the phase 2 section's account of its own scope, and the
`docs/plans/index.md` row. Later steps should not redo them.

## Decisions

1. **The audit reads a reconstructed patch and the current state,
   not a range.** Step 2 builds both into the scratchpad and every
   judgement step is briefed against the files rather than against
   `git diff develop...HEAD`:

   ```bash
   PATHS=".github/workflows/fuzz-autofix.yml \
       .github/workflows/test-drift-fix.yml \
       .github/workflows/functional-tests.yml \
       tools/autofix-prompt-base.txt tools/fuzz-issue-schema.json \
       tools/ci/stage-autofix-changes.sh \
       tools/ci/test-stage-autofix-changes.sh \
       tools/ci/claude-result.sh tools/ci/test-claude-result.sh \
       tools/ci/autofix-artifact-patterns.sh \
       tools/address-comments-with-claude.sh \
       tools/ci/reset-autofix-worktree.sh \
       tools/ci/test-reset-autofix-worktree.sh \
       tools/ci/test-address-comments-staging.sh"
   : > scope.patch
   for c in 2fcf75e 382c5bf 14a2680 b91511a 7205b2a 1775257 \
            a705cad 14e9cba; do
       git show --format="commit %h %s%n" "$c" -- $PATHS >> scope.patch
   done
   for m in 3d5a612 7b1afe4 b6b67a8 931b5a9 7b4e860; do
       git log -1 --format="commit %h %s%n" "$m" >> scope.patch
       git diff "${m}^1" "$m" -- $PATHS >> scope.patch
   done
   ```

   The patch answers "what did the phases do to each other"; the
   current files answer "what is there now". An audit given only the
   patch would re-litigate defects that a later commit already fixed,
   which is the failure mode this plan's own history is full of —
   four review rounds on #509 each fixed the previous round's fix.

2. **The audit scripts run anyway, and their empty results are
   recorded as empty.** `wave2-mechanical.sh` will report nothing
   because its range is empty and its greps are Rust-shaped. That is
   worth one line in the findings rather than a workaround: the
   alternative — editing the scripts to take a range, or hand-running
   their greps over the scope — is repo tooling changed for one
   audit, and `PLAN-TEMPLATE.md` is explicit that an audit which says
   what it could not scope is a result. The substantive mechanical
   pass for a shell-and-YAML diff is step 2's brief instead.

3. **Findings land on this branch, not a separate one.** The
   push-audit shared block says findings land as their own pull
   request against the default branch. This phase's pull request is
   that pull request: the plan file, the fixes and the written
   declines ship together, which is how every other phase in this
   repository has landed.

4. **Wave 1 runs in full, including the Rust legs that cannot say
   anything.** `make instar`, `make test-rust`, `make fuzz-build`,
   `check-binary-sizes` and `check-rust.sh` will all pass trivially
   because this plan changed no Rust. Running them costs machine time
   and no judgement, and the alternative — deciding which legs of a
   runbook to skip because the diff "looks like" YAML — is exactly
   how an audit becomes a formality. The parts that actually inspect
   this diff are `pre-commit` (actionlint over both workflows,
   shellcheck over the four scripts, yamllint) and wave 1b's
   inline-script heuristic. **This is the decision most likely to be
   argued with**, and the counter-argument is fair: it is perhaps
   forty minutes of a shared machine for zero information. It is
   taken anyway because the plan is auditing a piece of CI whose
   defining failure was a gate that silently passed over an empty
   input, and skipping the legs that would report nothing would
   reproduce that shape in the audit itself.

5. **Wave 2d is re-briefed for CI supply chain, not for the VMM.**
   The threat model for this scope is: an issue body that a fuzzer
   wrote (or that any GitHub user can write) becomes the prompt for
   an agent running `--dangerously-skip-permissions` on a self-hosted
   runner holding a token that can push branches and open pull
   requests. `PUSH-AUDIT.md`'s 2d brief is unchanged in the
   repository — this is a per-phase substitution recorded here, not
   an edit to the runbook, because one phase's threat model is not
   evidence the runbook is wrong. If the same substitution is needed
   for a second CI-shaped plan, that is when the runbook should
   change.

6. **The complexity-gate gap at `fuzz-autofix.yml:928` is not
   reopened here.** Phase 1 declared it out of scope and documented
   it in a comment where a reader meets it. Run 33297854229 has since
   reached that code, so the precondition phase 1 named is now met —
   but acting on it is a behaviour change, and this phase audits.
   Step 7 records it as a finding and files or updates an issue; it
   does not fix it.

7. **The two bugs in wave 1's inline-script check are fixed here,
   as a prerequisite rather than a finding.** `NR` becomes `FNR` and
   the `head -20` cap is dropped in favour of a count-and-print. This
   is `tools/audit/wave1.sh`, which belongs to `PUSH-AUDIT.md`'s
   tooling and not to this plan, so fixing it is strictly outside the
   scope this phase set itself — the argument for doing it anyway is
   that the phase cannot honestly run its own wave 1 with a check
   that reports line numbers past the end of the file and hides the
   findings for half the files in scope. Every plan that has run this
   runbook has been reading fictitious line numbers, so the fix is
   also the widest-reaching thing this phase can do for two lines of
   awk. It ships in step 1's commit, separately from the audit
   findings, and is recorded in this file's *Result* section as a
   finding against the runbook rather than against this plan — not in
   Future work, since it is fixed rather than deferred.

   The check is instar-only: `kerbside/tools/audit/wave1.sh` and
   `ryll/tools/audit/wave1.sh` have a long-line check and a `head -20`
   but no inline-script check at all, so there is nothing to
   propagate and no sibling repository to open a pull request
   against.

## Step plan

| Step | Effort | Model | Isolation | Brief for sub-agent |
|------|--------|-------|-----------|---------------------|
| 1 | low | sonnet | none | Run `tools/audit/wave1.sh` from the worktree root and capture its full output to the scratchpad as `wave1.txt`. It exits non-zero on failure with a structured code (1 pre-commit, 2 rustfmt/clippy, 3 `make instar`, 4 binary sizes, 5 `make test-rust`, 7 `make fuzz-build`); report the code and the failing leg if it fails. Expect it to pass — this plan changed no Rust. **Before running it, fix the two bugs in its inline-script check** (per Decision 7, and see *What the survey found* for the measurements): in the awk at `tools/audit/wave1.sh:104`-`:109`, `NR` must be `FNR` — as written it prints the record number accumulated across the whole `.github/workflows/*.yml` glob, so it reports `fuzz-autofix.yml:2147` for a 1,125-line file — and the `head -20` on the result must go, because with 32 hits sorted by filename the cap hides two of `fuzz-autofix.yml`'s four hits and all six of `test-drift-fix.yml`'s. Print a total count and then every hit. Verify the fix by confirming the check now reports `fuzz-autofix.yml` at lines 79, 213, 876 and 1076 and `test-drift-fix.yml` at 82, 124, 204, 242, 512 and 759; those are this phase's expected numbers and a mismatch means the fix is wrong, not that the plan is stale. Then run the script. Two parts of the output matter and must be quoted verbatim in the report rather than summarised: the `pre-commit` leg (actionlint over `.github/workflows/fuzz-autofix.yml` and `test-drift-fix.yml`, shellcheck over `tools/ci/stage-autofix-changes.sh`, `test-stage-autofix-changes.sh`, `claude-result.sh`, `test-claude-result.sh`), and the `wave 1b` inline-script advisory in full. Do not fix any *finding*; the wave1.sh repair is the only edit this step makes. Commit subject: `Fix the inline-script check line numbers.` |
| 2 | medium | sonnet | none | Build the audit artefacts and run the shell/YAML mechanical pass wave2-mechanical.sh cannot. First, run the scope command in Decision 1 from the worktree root, writing `scope.patch` to the scratchpad; sanity-check it against the measurement taken during planning — 7,887 lines, first hunk the creation of `.github/workflows/fuzz-autofix.yml` in `2fcf75e` at patch line 4. A materially different length means the scope table in *What the survey found* has drifted; stop and report rather than auditing a different body of code. Then run `tools/audit/wave2-mechanical.sh` and capture its output — it will be almost entirely empty, which is the expected result and must be reported as such, not as a pass. Then do by hand, over the eight surviving in-scope files, what that script does for Rust: (a) `TODO`/`FIXME`/`HACK`/`XXX`; (b) every `\|\| true`, `2>/dev/null` and `set +e` — for each, say whether it is deliberately swallowing a failure the caller then checks another way, or silently discarding one; (c) every unquoted `$VAR` expansion shellcheck did not already flag, especially inside `run:` blocks where a value comes from a GitHub context expression; (d) every `${{ }}` expression interpolated directly into a `run:` block, with the source of the value (`github.event`, `inputs`, `steps.*.outputs`, `env`); (e) any file added under `src/`, `tests/` or `scripts/` by the scope patch that should live in `shakenfist/instar-testdata` instead. Report as a list, each item with file and line. Judgement on (b)-(d) belongs to steps 3 and 6; this step gathers. Commit subject: `Record the wave 2 mechanical results.` |
| 3 | medium | sonnet | none | Wave 2a, code quality, over the reconstructed scope. Read `scope.patch` for the history and the eight current files for the state; step 2's list is your input for the mechanical findings. The specific question this scope raises: `tools/ci/stage-autofix-changes.sh` (301 lines) and `tools/ci/claude-result.sh` (474 lines) were written seven months apart by different sub-agents for the same workflow, and `tools/ci/autofix-artifact-patterns.sh` is sourced by one of them. Look for logic duplicated between them, and for logic duplicated between either script and the inline `run:` blocks in `fuzz-autofix.yml` — the workflow is 1,125 lines and the plan's stated reason for extracting scripts at all was that "the bugs in this area all hid in inline YAML", so inline logic that should have moved out is a finding against that stated intent. Triage each TODO/`\|\| true` step 2 found as blocking or advisory with a reason. Apply the `comment-proportion` shared block in `PUSH-AUDIT.md` to `stage-autofix-changes.sh`'s header comment specifically: it deliberately records the four-round review history of PR #509, which is the kind of length that block says can be justified — say whether it is. Skip the `python-version-discipline` block; there is no Python in scope. Report file, line, blocking or advisory. Commit subject: `Record the code quality audit findings.` |
| 4 | medium | sonnet | none | Wave 2b, test review, over `tools/ci/test-stage-autofix-changes.sh` (468 lines) and `tools/ci/test-claude-result.sh` (588 lines), both run by the `ci-tooling` job at `.github/workflows/functional-tests.yml:139` and `:142`. These two suites are the whole test surface of this plan. The standard from the `functional-test-coverage` shared block applies directly: for each behaviour the scripts implement, is there a test that would have failed before the commit that added it? Work backwards from `scope.patch` — each of the eleven commits in `3d5a612` and each of the nine in `b6b67a8` fixed a specific defect (counts measured, not estimated -- `git log --oneline <merge>^1..<merge> --no-merges`), and the commit subjects name them (`Do not re-widen staging after the gates have run.`, `Report new files git hides, and fix a false rationale.`, `Do not refuse an attempt for its own test output.`, `Judge a finished run by its result string alone.`). For each, find the test that pins it, or report its absence. Also check: does anything test the *interaction* the workflow depends on — that `stage-autofix-changes.sh --snapshot` before an attempt and the stager after it agree about which files are new? And is `tools/ci/autofix-artifact-patterns.sh` exercised at all, or only sourced? Note that neither suite can test the workflow YAML itself, which is the plan's own stated reason for extracting them; say what remains untestable and whether that is the right boundary. Report grouped by file. Commit subject: `Record the test coverage audit findings.` |
| 5 | medium | sonnet | none | Wave 2c, documentation. Check the four documents that describe this machinery against what the code now does: `docs/testing.md`'s *Automated bug fixes* section (around `:1299`-`:1345`), `docs/development.md`'s script index (`:778`, `:807`-`:810`), `docs/security-audits.md:503`-`:504`, and `docs/commentary/reading-order.md`'s step 14 (`:464`-`:478`). Apply the `readme-discipline`, `llm-doc-discipline` and `plan-phase-references` shared blocks from `PUSH-AUDIT.md`. Specific things to check rather than rediscover: the 30-turn figure in all four places is **correct** (`fuzz-autofix.yml:60` defaults `MAX_TURNS` to 30; a dispatch input raised it to 40 for one run) — do not report it; `AGENTS.md:133`-`:139` describes `PUSH-AUDIT.md` and plan-phase references and is in scope; `CHANGELOG.md` contains **no** entry for any of #509, #520, #530 or #535 — measured during planning, so do not spend the step rediscovering it; the judgement asked for is whether CI tooling that no user invokes belongs in a user-facing changelog at all, answered once, either way, with a reason. The claim most likely to be stale is the master plan's own *Diagnosis: the gate reads the index, the safety net stages too late* section, which describes the pre-`3d5a612` workflow in the present tense and cites line numbers 285, 348, 505, 561 and 637 that no longer mean anything — `Check complexity (attempt 1)` is now at `:384` and `Verify fix (attempt 1)` at `:473`. Decide whether that section reads as history or as a description of current behaviour, and if the latter, say what minimal edit fixes it. Report as a bullet list; "no documentation gaps found" is a valid answer. Commit subject: `Record the documentation audit findings.` |
| 6 | high | opus | none | Wave 2d, security — **re-briefed per Decision 5; ignore `PUSH-AUDIT.md`'s 2d brief, which is written for the VMM and the format parsers and does not apply to any file in scope.** The system under review: `.github/workflows/fuzz-autofix.yml` runs daily on a self-hosted runner, selects an open `security-audit` issue, assembles a prompt from `tools/autofix-prompt-base.txt` plus that issue's body, and invokes `claude -p --dangerously-skip-permissions` with a token that can push branches and open pull requests. Issue bodies are written by `tools/ci/report-fuzz-crash.sh` from fuzzer output, but the label is applied to human-filed issues too and any GitHub user can edit an issue body. Read the workflow end to end, then `tools/ci/stage-autofix-changes.sh`, `tools/ci/claude-result.sh`, `tools/ci/autofix-artifact-patterns.sh` and `tools/fuzz-issue-schema.json`. Assess: (1) **Prompt injection.** `1775257` (*Close prompt injection loophole with structured JSON*) closed one hole using `tools/fuzz-issue-schema.json`; is the schema actually enforced on the path that reaches the prompt today, and is there any other path from issue text into the prompt or into a shell command? (2) **Token scope and exfiltration.** Which secrets are in the job environment while Claude runs, and could the model be induced to read or transmit one? Note the workflow's own constraint that its token cannot push `.github/workflows/`, which the stager enforces by unstaging rather than by excluding — verify that actually holds. (3) **The stager as a security boundary.** It refuses untracked files, gitignored files absent from the pre-run baseline, and anything under `.github/workflows/`. Can a crafted prompt get a file past all three? Consider symlinks, a tracked file that is itself a `.gitignore`, submodule paths, and a file that is deleted and recreated. (4) **Baseline integrity.** `pre-run-ignored.txt` and `pre-retry-ignored.txt` are snapshots on the runner's filesystem; the workflow `rm -f`s stale state because the runner is persistent between jobs. Is that complete, and can a previous run's state influence this one? (5) **The self-hosted runner itself:** does the job run untrusted-issue-derived content before or after any privileged step, and is the concurrency group enough to prevent two runs sharing the workspace? Report each finding with severity (critical / high / medium / low / informational), file, line, vulnerability class and recommended fix. File any critical or high as a `security-audit` GitHub issue per `PLAN-audit.md`'s conventions before reporting. Commit subject: `Record the security audit findings.` |
| 7 | high | opus | none | Triage every finding from steps 1-6. For each: fix on this branch, or decline in writing with the reason. Fixes are limited to the audit's own findings — this is not the place to implement #529 or #534, and Decision 6 keeps the complexity-gate gap at `fuzz-autofix.yml:928` as a recorded finding rather than a fix (file an issue for it, or add an occurrence comment if one exists). Write every declined finding into `PLAN-fuzz-autofix.md`'s Future work section with its reason, because the master plan is the only document anyone reads again. Re-run `tools/audit/wave1.sh` after any fix. If the audit found nothing, say so in one sentence in the master plan — that is a real result. Commit subject: `Fix the push audit findings.` (or `Record the push audit findings.` if nothing needed fixing). |
| 8 | low | sonnet | none | Close out. Add a *Result* section to this file recording what each wave found and what was fixed or declined. Set this phase's row in `PLAN-fuzz-autofix.md`'s Execution table to `Complete` and fill its `Merged` cell after the pull request lands (leave the cell for the management session if it has not). Set the master plan's Status heading at `:3` and the `docs/plans/index.md` row to `Complete` — the status cell holds exactly the word `Complete` and nothing else, per the `plan-status-vocabulary` block. Update the index row's description to say what the plan delivered rather than what remains. Do not touch `docs/plans/order.yml`. Commit subject: `Close out the fuzz autofix plan.` |

## Risks and mitigations

| Risk | Mitigation |
|------|------------|
| The reconstructed scope is wrong — a commit belonging to this plan is missing, or one belonging to another plan is included — and the audit reads the wrong code. | The reconstruction is written out commit by commit in *What the survey found* with its merge and its pull request, so it is checkable rather than asserted. Step 2's first act is to sanity-check `scope.patch` against a known landmark. The management session re-derives one row independently before step 3 starts. |
| The audit degenerates into a formality because the mechanical wave has nothing to say about a YAML-and-bash diff. | Decision 2 and step 2. The Rust-shaped checks report empty and that is recorded as empty; the substantive mechanical pass is written for this diff's actual shape. The judgement steps read the files, not a script's summary of them. |
| Wave 2d is the step that matters and it is the step most likely to produce speculative findings, because the threat model involves an LLM and speculation is cheap there. | The step-6 brief asks five specific questions against named files rather than "look for security problems", and requires a severity and a line number per finding. The management session checks each critical or high against the code before an issue is filed — the same rule the qemu-capability lesson produced: cite or measure, do not assert. |
| A finding is real, expensive, and out of scope, and gets fixed anyway because it is in front of us. | Step 7's brief names the three things that are explicitly not fixed here (#529, #534, the complexity gate) and requires declines in writing in the master plan. The plan's job is to record, file and say why. |
| Wave 1 passes trivially and is read as the audit having passed. | Step 1's brief requires the `pre-commit` and inline-script legs quoted verbatim, and Decision 4 states in the plan itself that the Rust legs are inert here. |

## Definition of done

Falsifiable, in order:

1. `tools/audit/wave1.sh`'s inline-script check reports
   `.github/workflows/fuzz-autofix.yml` at lines 79, 213, 876 and
   1076 and `.github/workflows/test-drift-fix.yml` at lines 82, 124,
   204, 242, 512 and 759 — every one of which exists in its file,
   checkable with `sed -n '<line>p'` — and prints all 32 of its hits
   rather than the first 20.
2. `tools/audit/wave1.sh` exits 0 on this branch, and its output is
   recorded in this file's *Result* section including the full
   inline-script advisory.
3. This file's *Result* section names, for each of waves 2a, 2b, 2c
   and 2d, either at least one finding or the sentence that the wave
   found nothing.
4. Every finding in the *Result* section is marked fixed (with the
   commit that fixed it) or declined (with a reason), and every
   declined one also appears in `PLAN-fuzz-autofix.md`'s Future work
   section.
5. Every critical or high finding from step 6 has a GitHub issue
   number recorded next to it.
6. `git log --oneline develop..HEAD` on this branch touches no file
   outside `docs/plans/`, the eight in-scope files, the documentation
   named in step 5's brief, and `tools/audit/wave1.sh`.
7. `grep -c 'b6b67a8\|931b5a9\|7b4e860' docs/plans/PLAN-fuzz-autofix.md`
   is at least 3 — phase 1's `Merged` cell names all three of its
   pull requests.
8. The status cell for this plan reads exactly `Complete` in both
   `PLAN-fuzz-autofix.md`'s Execution table and the
   `docs/plans/index.md` row, and no fact about the plan's state is
   stated differently in the two.
9. `pre-commit run --all-files` passes.

## Back brief

Before executing any step of this plan, back brief the operator on
your understanding of it and how the work you intend to do aligns.

One gate within the phase:

* **After step 6, before step 7.** Step 7 decides what gets fixed and
  what gets declined in writing in the master plan, and a decline is
  the last time anyone looks at a finding. Present the full finding
  list with the proposed disposition for each, and get agreement
  before any of it is edited. This is cheap to agree and expensive to
  redo: reversing a decline means reopening a closed plan.
