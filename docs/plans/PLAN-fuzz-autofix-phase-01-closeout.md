# Phase 1 — close out the autofix loop: derived trailers and an end-to-end proof

Parent plan: [PLAN-fuzz-autofix.md](PLAN-fuzz-autofix.md)

This is the first phase *file* for this plan. Everything before it —
the workflow itself, and the staging fix in PR #509 — was tracked
inline in the master plan under "Remaining work". The master plan now
carries an Execution table, and this file is its only row.

## Goal

Retire the master plan's two remaining work items:

1. The hardcoded `Co-Authored-By: Claude Opus 4.6 (1M context)`
   trailer in the Create PR step, which no longer names the model that
   runs — and the two other Claude automations with the same defect
   and a *different* stale name.
2. The plan's own outstanding success criterion: one run that reaches
   a pull request, proving the loop end to end.

## Planning effort

High. The trailer change is not the one-line edit it looks like: it
requires changing how three separate automations capture Claude's
output, and the capture is load-bearing for their failure reporting.
The end-to-end proof has an ordering constraint that has already
bitten this plan twice.

## Scope

**In scope**

* A tested `tools/ci/` helper that turns a `claude -p --output-format
  json` result into (a) the plain result text and (b) an accurate
  `Co-Authored-By` trailer.
* Switching all three Claude automations to JSON output and the
  helper: `.github/workflows/fuzz-autofix.yml`,
  `.github/workflows/test-drift-fix.yml`, and
  `tools/address-comments-with-claude.sh`.
* Documentation for the helper in `docs/development.md`'s script
  index, and for the derived trailer in `docs/testing.md`.
* Dispatching `fuzz-autofix.yml` against issue #485 once the above is
  on `develop`, and triaging whatever it produces.
* Correcting the false and stale claims the survey found in the master
  plan, and refreshing the `docs/plans/index.md` row.

**Out of scope**

* The rebase-planner bug behind #483, #485 and #492 (writes emitted
  past `total_file_size`). If the autofix run proposes a fix for it,
  that PR is reviewed on its own merits as a separate change; this
  phase is not committed to landing it.
* `coverage-fuzz.yml` hitting its 480-minute job timeout — see
  *Out-of-scope findings* below.
* The complexity-gate gap already documented in a comment at
  `.github/workflows/fuzz-autofix.yml:813`: a tracked file the verify
  build modifies between the gate and the commit is committed without
  being counted against the 3-file limit. It is recorded where a
  reader will meet it; changing it needs a run that has actually
  reached that code, which this phase's step 7 will be the first to
  produce.
* `Signed-off-by: Michael Still` hardcoded in
  `tools/address-comments-with-claude.sh:818`. That one is correct —
  the human owning the automation is the sign-off — and is not stale.

## What the survey found

Checked against the tree at `7b1afe4`.

### The staging fix is in place and correctly positioned

The master plan's Resolution section holds up. `stage-autofix-changes.sh`
runs at `.github/workflows/fuzz-autofix.yml:302` and `:613`, immediately
after each `Run Claude Code` step (`:244`, `:586`) and upstream of every
gate that reads the index — `Check complexity` (`:322`, `:633`) and
`Verify fix` (`:411`, `:715`). The old downstream `git add -u` is now a
`--tracked-only` call at `:836`. Tests run in the `ci-tooling` job at
`.github/workflows/functional-tests.yml:139`. No correction needed.

### The loop has never been exercised, because nothing is eligible

Six scheduled runs have completed since the staging fix merged, two of
them (2026-08-21 `d0aa5499`, 2026-08-22 `7b1afe45`) with the fix on
`develop`. All six succeeded with every step after `Find eligible
issue` skipped. There are three open `security-audit` issues and none
is eligible:

| Issue | Body | Labels | Verdict |
|-------|------|--------|---------|
| #485 | valid fuzzer JSON | `autofix-failed` | blocked by label |
| #492 | valid fuzzer JSON | `autofix-failed` | blocked by label |
| #483 | hand-written prose | none blocking | correctly rejected by `is_valid_fuzzer_json` (`:100`) |

So the fix is on `develop` and has still never run. Nothing is broken;
there is simply no input. The `workflow_dispatch` path at `:110` checks
only `is_valid_fuzzer_json` and **not** the blocking labels, so a manual
dispatch on #485 exercises the full path without editing any labels.

All three are the same underlying bug, which #483 diagnoses in detail.

### The master plan's trailer claim is false

The master plan says the trailer must stay hardcoded because "the
workflow cannot introspect which model the `claude` CLI resolves to".
Measured on the host at CLI 2.1.238, it can:

```json
"modelUsage": {
  "claude-opus-5": {
    "outputTokens": 4,
    "contextWindow": 1000000,
    "canonicalModel": "claude-opus-5"
  }
}
```

`claude -p --output-format json` reports the resolved model and its
context window. This claim is corrected in the master plan as part of
the planning commit.

### The stale trailer is in three places, disagreeing three ways

| Site | Trailer today |
|------|---------------|
| `.github/workflows/fuzz-autofix.yml:850`, `:861` | `Claude Opus 4.6 (1M context)` |
| `.github/workflows/test-drift-fix.yml:522`, `:535`, `:543` | `Claude Opus 4.5` |
| `tools/address-comments-with-claude.sh:820` | `Claude Opus 4.5` |

All three invoke `claude -p ... --output-format text` with stderr
folded into stdout, so all three need the same capture change. Recent
human commits on this repo use the form `Claude Opus 5 (15M context,
high effort) <noreply@anthropic.com>`.

### The address-comments item is done

The master plan's third remaining-work bullet describes PR #511 as
pending ("it lands after this one"). It merged as `7b1afe4`, and
`tools/address-comments-with-claude.sh:637` now calls the stager in
`--tracked-only` mode. Corrected in the master plan.

### Out-of-scope findings

* **`coverage-fuzz.yml` is timing out.** The runs of 2026-08-18,
  -19, -20 and -21 all report `cancelled` after exactly 480 minutes,
  which is `timeout-minutes: 480` firing. The workflow computes an
  internal 450-minute budget at `:152` precisely to stay inside that,
  and the budget is not holding. Crash reporting is inline in the fuzz
  loop (`:354`), so issues would still be filed for crashes found
  before the cut — this does not explain the empty eligible-issue
  list — but the campaign is being truncated nightly. Belongs to
  [PLAN-coverage-fuzzing.md](PLAN-coverage-fuzzing.md); step 1 files
  an issue.

### Corrections already made

The false claims above are corrected at their source in this same
commit, so a later step does not redo the work: the master plan's
Remaining work section now records that the CLI *can* report its model
and that PR #511 merged, and `docs/plans/index.md` carries the phase
link and a description of why the loop has still never run. Nothing
else in the master plan was found to be wrong.

## Decisions

1. **Derive the trailer at run time from `--output-format json`,
   rather than picking a generic string.** The master plan reached for
   a generic trailer only because it believed introspection was
   impossible. It is not, and a derived trailer is the only option
   that cannot go stale a fourth time.

2. **Emit the canonical model id verbatim — `Claude claude-opus-5
   (1M context)` — not a prettified `Claude Opus 5`.** *This is the
   decision a reviewer is most likely to argue with*, because it does
   not match the form human commits on this repo use. Prettifying
   means either a lookup table (`claude-opus-5` → `Opus 5`), which is
   the same staleness this phase exists to remove, or a mechanical
   de-slugging that mangles the cases it has to handle
   (`claude-haiku-4-5-20251001`). The id is unambiguous, machine-
   checkable against the model roster, and honest about what actually
   ran. Human-authored commits are unaffected; only the three
   automations use this path.

3. **Context window is rendered, not raw.** `1000000` → `1M`,
   `200000` → `200K`, anything not a clean multiple → the raw digit
   string. This matches the `(1M context)` / `(200K context)` forms
   already in the history.

4. **One helper with two modes, in `tools/ci/`, with its own test
   script wired into `ci-tooling`.** This follows the precedent the
   master plan itself set for `stage-autofix-changes.sh` and
   `pick-fuzz-artifact.sh`: logic that only runs inside a live
   unattended run cannot be tested there, and every bug in this area
   so far has hidden in inline YAML. Three inline copies would
   re-create exactly the drift the survey found.

5. **Never lose the diagnostics.** Today `2>&1 | tee` means a
   catastrophic Claude failure still leaves readable output in
   `claude-output-N.txt`, which `Report failure` quotes into the issue
   comment. JSON on stdout cannot carry that, so stderr is captured to
   its own file and the helper's `--text` mode falls back to
   concatenating the raw stdout and stderr whenever the JSON does not
   parse or carries no result. A trailer for an unparseable result
   falls back to `Co-Authored-By: Claude <noreply@anthropic.com>`.

6. **Prove the loop by dispatching on #485, and review the resulting
   PR on its merits.** Manual dispatch bypasses the label gate without
   mutating labels, so the proof is repeatable on demand and does not
   depend on waiting for a cron. If Claude's fix for the rebase
   planner is wrong, the PR is closed and the proof still stands: what
   is being tested here is the machinery, not the model.

7. **The end-to-end proof happens after this PR merges, not within
   it.** `fuzz-autofix.yml` checks out `develop` (`:65`), and
   `test-drift-fix.yml` and the address-comments loop take their
   trusted tools from the default branch for the same reason. This is
   the ordering constraint that made #509 land before #511; ignoring
   it here would test the old code and report a false pass.

## Step plan

Steps 1–6 are one pull request. Step 7 runs only once that PR is on
`develop` (Decision 7). Step 8 is a small follow-up commit.

| Step | Effort | Model | Isolation | Brief for sub-agent |
|------|--------|-------|-----------|---------------------|
| 1 | low | sonnet | none | Measure the JSON contract before anything depends on it, and file the out-of-scope issue. Run `claude -p` with `--output-format json` under three outcomes and record the exact shape of each in a scratch note: (a) plain success; (b) `--max-turns 1` against a prompt needing several tool calls, i.e. turn exhaustion; (c) a hard failure such as an unreadable prompt file. For each, record whether the process exits non-zero, whether stdout is valid JSON, whether `.result` exists and what it holds, `.subtype`, `.is_error`, and whether `.modelUsage` is present. This needs `--dangerously-skip-permissions` for (b), so run it in the scratchpad directory, not in a source tree. Separately, file a GitHub issue against `coverage-fuzz.yml` recording that the scheduled runs of 2026-08-18 through -21 were cancelled at exactly the 480-minute `timeout-minutes`, that the workflow's own 450-minute budget at `.github/workflows/coverage-fuzz.yml:152` is meant to prevent this, and that the campaign is being truncated nightly; reference `PLAN-coverage-fuzzing.md`. Commit subject: `Record the claude JSON output contract.` (the note goes in the phase plan under a new *CLI contract* heading; the issue is not a commit). |
| 2 | high | opus | none | Write `tools/ci/claude-result.sh` and `tools/ci/test-claude-result.sh`. Two modes, flag-style like `tools/ci/stage-autofix-changes.sh`: `--text <result.json> --raw-fallback <file>` prints the plain result text (`.result`) or, if the JSON does not parse or has no usable result, the contents of the fallback file verbatim; `--trailer <result.json>` prints exactly two lines, `Assisted-By: Claude Code` and `Co-Authored-By: Claude <model> (<window> context) <noreply@anthropic.com>`. Model is the `.modelUsage` key with the greatest `.outputTokens` — there can be more than one when a session used a subagent or fell back — emitted verbatim per Decision 2. Window rendering per Decision 3. If `.modelUsage` is absent or empty, emit `Co-Authored-By: Claude <noreply@anthropic.com>`. Ground the parse behaviour in step 1's recorded contract, not in assumption. Give the script a header comment in the style of `stage-autofix-changes.sh`: say why it exists (three automations, three different stale model names, and the master plan's own false claim that introspection was impossible), and say what it refuses to do (guess a display name from the id). Tests must be a self-contained bash script using fixture JSON built inline, no network and no `claude` invocation, exiting non-zero on the first failure; cover success, multi-model `modelUsage`, missing `modelUsage`, malformed JSON, an empty file, and each of the three window renderings. Wire it into `.github/workflows/functional-tests.yml` in the `ci-tooling` step list next to `Test the autofix stager` (around line 139). `pre-commit` runs shellcheck over `tools/`. Commit subject: `Derive the Claude trailer instead of hardcoding it.` |
| 3 | high | opus | none | Switch `.github/workflows/fuzz-autofix.yml` to JSON capture. Both `Run Claude Code` steps (`:244`, `:586`) currently do `claude ... --output-format text 2>&1 \| tee ${GITHUB_WORKSPACE}/claude-output-N.txt \|\| true`. Replace with `--output-format json`, stdout to `claude-result-N.json`, stderr to `claude-stderr-N.txt`, then `tools/ci/claude-result.sh --text claude-result-N.json --raw-fallback claude-stderr-N.txt > claude-output-N.txt` and `cat` both so the run log still shows them. Everything downstream keeps reading `claude-output-N.txt` — in particular `Extract commit summary` (`:789`) greps it for the `COMMIT_SUMMARY_START`/`END` markers, and `Report failure` quotes it — so that filename must not change. Do not disturb the `rm -f` of stale stager state or the `--snapshot` call that precede the invocation; do add the two new files to that `rm -f` list, for the same self-hosted-runner reason the comment there gives. Then replace the two hardcoded trailer blocks (`:849`-`:850` and `:860`-`:861`) with the helper's `--trailer` output for the winning attempt (`steps.result.outputs.attempt`). Add both new files to the `Upload logs` list at `:963`. `pre-commit` runs actionlint over workflows. Commit subject: `Name the model that actually wrote the fix.` |
| 4 | medium | sonnet | none | Same change to `.github/workflows/test-drift-fix.yml`, which has the identical shape at `:423`-`:427` (capture) and three trailer sites at `:522`, `:535` and `:543`. It writes a single `claude-output.txt` with no attempt suffix, so the JSON is `claude-result.json` and stderr is `claude-stderr.txt`. Two of the three trailer sites are inside `git commit -m` heredoc-style strings with leading indentation baked in; read them carefully rather than pattern-replacing, and prefer restructuring those to `-F` a message file like the summary_found branch already does, so the trailer can be appended by the helper. Follow whatever step 3 settled on for `fuzz-autofix.yml`, and read that diff first. Commit subject: `Name the model in the test-drift fixes too.` |
| 5 | high | opus | none | Same change to `tools/address-comments-with-claude.sh`. Its invocation is at `:603`-`:609` and differs from the workflows: it uses `> "${claude_output_file}" 2>&1` inside an `if !` so the exit status drives `item_error "Claude execution failed"`, and it runs once per review item with an `-${i}` suffix. Preserve the exit-status check exactly — a Claude that fails must still be an item-level error — and add per-item `claude-result-${i}.json` and `claude-stderr-${i}.txt`. The trailer is at `:819`-`:820`, inside a `printf` block that also emits `Signed-off-by: Michael Still`; keep the sign-off, replace only the two Claude lines. The helper lives in `${tools_dir}`, which is the trusted copy checked out from the base branch — resolve it the same way the script already resolves `${stager}` (see the comment at `:630`), not relative to the work tree. Commit subject: `Name the model in the review-comment fixes.` |
| 6 | medium | sonnet | none | Documentation. In `docs/development.md`, add `tools/ci/claude-result.sh` and `tools/ci/test-claude-result.sh` to the script index (the block at `:824`-`:828`, following the phrasing of the `stage-autofix-changes.sh` entry). In `docs/testing.md`, in the automated-bug-fixes section around `:1274`-`:1296`, add a short paragraph saying the commit trailer names the model the CLI actually resolved to, derived from the run's JSON output, and that a run whose output could not be parsed falls back to an unqualified `Co-Authored-By: Claude`. Do not add anything to `AGENTS.md` or `ARCHITECTURE.md`: no convention and no component boundary changes here. Commit subject: `Document the derived commit trailer.` |
| 7 | high | — | — | **Management session, after the PR above merges.** Dispatch `gh workflow run fuzz-autofix.yml -f issue_number=485` and watch it. Confirm each of: `Find eligible issue` reports found=true; `Run Claude Code (attempt 1)` writes a parseable `claude-result-1.json`; the stager stages tracked edits and the complexity gate sees a non-empty index; the run reaches `Commit, push, and create PR`; the pushed commit's `Co-Authored-By` names the model, not `Opus 4.6`. Then triage: if a PR opened, review it as a normal change against #483's diagnosis and either land it or close it with a reason. If the run fails, the failure mode is the finding — classify it, and say whether it is the staging bug returning (it should not be), the model failing on a genuinely hard bug (expected and acceptable), or a new defect in the JSON capture (a regression from steps 3–5). Commit subject: none; the outcome is recorded in step 8. |
| 8 | medium | sonnet | none | Close out. Record the step 7 outcome in this phase plan under a *Result* heading and in the master plan, set the master plan's Execution row and the `docs/plans/index.md` row to `Complete` if the run reached a PR — and to a stated status with a reason if it did not. Update the master plan's Success criteria section to mark the end-to-end criterion met, and move anything still outstanding into its Future work section rather than leaving the plan In progress for it. Commit subject: `Close out the fuzz autofix plan.` |

## Risks and mitigations

| Risk | Mitigation |
|------|------------|
| JSON capture loses the diagnostics that `2>&1 \| tee` gave, so a failed run reports nothing useful into the issue comment. | Decision 5's `--raw-fallback`, and step 2's tests cover the malformed-JSON and empty-file cases explicitly. The management session checks step 3's diff for the fallback wiring before the PR goes up — this is the failure that would only be noticed months later, on a run nobody was watching. |
| `--output-format json` behaves differently on turn exhaustion than on success, and the workflow's most common outcome is turn exhaustion. | Step 1 measures it before step 2 is written, rather than step 2 assuming it. Gated in the back brief. |
| Steps 3–5 are three near-identical edits done by three sub-agents, and drift between them re-creates the defect. | The shared helper is the structural mitigation; on top of it, steps 4 and 5 are briefed to read step 3's diff first, and the management session diffs the three call sites against each other before proposing the commit. |
| The step 7 run produces a bad fix for a real correctness bug and it gets landed on the strength of "the automation worked". | Decision 6 separates the two judgements. The PR is reviewed against #483's written diagnosis, by a human, as an ordinary change. |
| The end-to-end proof is run against un-merged code and reports a false pass. | Decision 7. Step 7 is explicitly gated on the PR being on `develop`, and its first check is that the pushed trailer is not `Opus 4.6` — which is only possible if the merged code ran. |

## Definition of done

Falsifiable, in order:

1. `grep -rn 'Co-Authored-By: Claude Opus' .github/ tools/` returns
   nothing.
2. `tools/ci/test-claude-result.sh` exits 0, and
   `grep -c 'test-claude-result.sh' .github/workflows/functional-tests.yml`
   is at least 1.
3. `grep -c 'output-format text' .github/workflows/fuzz-autofix.yml
   .github/workflows/test-drift-fix.yml
   tools/address-comments-with-claude.sh` is 0 for all three.
4. `tools/ci/claude-result.sh --trailer` on a fixture whose
   `modelUsage` key is `claude-opus-5` with `contextWindow` 1000000
   prints exactly
   `Co-Authored-By: Claude claude-opus-5 (1M context) <noreply@anthropic.com>`
   as its second line; on an empty file it prints
   `Co-Authored-By: Claude <noreply@anthropic.com>`.
5. `pre-commit run --all-files` passes, including actionlint over the
   two workflows and shellcheck over the two new scripts.
6. A `fuzz-autofix.yml` run exists whose `Commit, push, and create PR`
   step completed, and whose pushed commit's `Co-Authored-By` line
   names a model from the current roster.
7. No fact about the trailer is stated differently in
   `docs/development.md`, `docs/testing.md`, and
   `PLAN-fuzz-autofix.md`.
8. The master plan contains no claim that the workflow cannot
   introspect its model, and no description of PR #511 as pending.

## Back brief

Before executing any step of this plan, back brief the operator on
your understanding of it and how the work you intend to do aligns.

Two gates within the phase:

* **After step 1, before step 2.** The measured JSON contract decides
  what `--text` mode has to tolerate. Report the three shapes and the
  proposed fallback rule, and get agreement before writing the helper
  — this is cheap to agree and expensive to rework once three call
  sites depend on it.
* **After step 6, before step 7.** Step 7 is an unattended run against
  a live issue that can open a pull request. Confirm the operator
  wants it dispatched, and when.
