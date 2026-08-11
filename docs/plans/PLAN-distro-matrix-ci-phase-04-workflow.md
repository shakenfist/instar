# Phase 4: Workflow integration (merge_group package-matrix job)

Master plan: [PLAN-distro-matrix-ci.md](PLAN-distro-matrix-ci.md).
Planning effort: **medium**. Isolation: none. Depends on phases 1, 2,
2b, 3 — all complete as of 2026-08-11.

Rewritten 2026-08-11 from the original sketch. The sketch was written
before phases 2b and 3 executed and before anyone had read the sibling
repo's merge-queue implementation; it contained one instruction that
would have broken PR CI (see "Corrections" below).

## Objective

Add a `package-matrix` job to
`.github/workflows/functional-tests.yml`, gated to `merge_group`
events, that fans out over the seven matrix distros and runs
`tools/test-package-functional.sh` for each against a single shared
pair of build artifacts. Add the aggregate `can_merge` gate the queue
will require. PR events keep today's jobs; the matrix runs only in the
merge queue and on `workflow_dispatch`.

## Grounding facts (verified 2026-08-11)

Read before changing anything; these were checked against the tree and
the sibling repo, not recalled.

- **`functional-tests.yml` has no `merge_group` trigger today.** It
  fires on `pull_request` (with a `paths:` filter over `src/**`,
  `crates/**`, `tests/**`, `scripts/**`, `tools/**`, `Makefile`, and
  the workflow itself) and `workflow_dispatch`. 807 lines, 9 jobs.
- **Job graph.** `test-partition` (gated `pull_request`, `s` runner) ·
  `build-and-test` (`s`, ungated) · `package-smoke`, `integration-core`,
  `integration-convert-qcow2`, `integration-convert-vhd`,
  `snapshot-harnesses`, `oslo-crossval-master` (all `needs:
  build-and-test`, all `[self-hosted, debian-12, xl]`) ·
  `automated_reviewer`.
- **Only `test-partition` carries an event gate.** Every other job runs
  on whatever the workflow triggers on. Adding `merge_group:` to the
  trigger list therefore re-runs the entire PR suite inside the queue
  unless each job is gated. This is the single largest decision in the
  phase (D2).
- **`package-smoke` (line 260) is the artifact-producing precedent**:
  `make instar && make deb`, then `tools/test-package-install.sh` on
  `debian:trixie`. It builds the `.deb` in-job and does not upload it.
- **Testdata prep is a solved step.** `tools/ci/prepare-testdata.sh`
  clones with `secrets.GITLAB_TESTDATA_TOKEN`, materialises LFS,
  canary-verifies, and writes `TESTDATA_PATH=<path>` to `$GITHUB_ENV`.
  `integration-core` (line 311) is the pattern to copy verbatim,
  including the resparsify step that follows it.
- **The runner's interface** (`tools/test-package-functional.sh`):
  `[--smoke] [--select REGEX] [--concurrency N] <package> <distro-image>`,
  reads `TESTDATA_PATH` from the environment, needs docker and
  `/dev/kvm`, prints a `--- Versions under test ---` block containing
  `qemu-img --version`, and ends with `PASS:`/`FAIL: <pkg> functional
  suite on <distro>`. It already fails loudly on a truncated run (the
  subunit-4MB worker death, a worker reporting `N/A` elapsed, and a
  full run executing fewer than 2500 tests).
- **Package output paths.** `make deb` → `src/target/debian/instar_*.deb`;
  `make rpm` → `src/target/generate-rpm/instar-*.rpm`; `make package`
  does both. Both are compile-free repackaging of what `make instar`
  produced.
- **Sibling pattern of record** — `shakenfist/shakenfist`'s
  `functional-tests.yml`:
  - trigger is a bare `merge_group:` alongside `pull_request:` with a
    `branches:` (not `paths:`) filter;
  - matrix jobs gate on
    `(github.event_name == 'merge_group' || github.event_name == 'workflow_dispatch')`,
    which is what makes a dispatch dry run possible;
  - the required check is an aggregate job, **`can_merge`**, with
    `if: always() && github.event_name == 'merge_group'`, `needs:` the
    matrix jobs, and a jq expression over `toJSON(needs)` asserting
    every dependency is `success` or `skipped`. `can_enqueue` is its
    PR-side twin;
  - docs-only changes are handled by a `check_paths` job using
    `dorny/paths-filter@v4` with `predicate-quantifier: 'every'`, whose
    `code_changed` output gates the heavy jobs — **not** by a trigger
    `paths:` filter.

## Corrections to the original sketch

- **Step 4e was wrong and would have broken PR CI.** It said to add the
  matrix to "the aggregate gate (the `needs:` list that the
  branch-protection required check depends on — see the `package-smoke`
  entry at `functional-tests.yml:783`)". Line 783 is inside
  `automated_reviewer`, which is the PR auto-review job, not a gate. Its
  `needs:` list exists to hold the reviewer back until CI passes. Adding
  a merge_group-only job to it would make the reviewer **skip on every
  PR**, because a job whose dependency is skipped is itself skipped by
  default. This repo has no aggregate gate at all today; phase 4 must
  create one (`can_merge`, per the sibling), and `automated_reviewer`
  must not be touched beyond an explicit `pull_request` gate.
- **`merge_group` does not honour the trigger's `paths:` filter.** The
  filter on `pull_request` is not inherited, so the workflow always runs
  in the queue. That is the safe direction — a required check that never
  runs would hang the queue forever — but it means a docs-only PR pays
  for the full matrix unless a `check_paths`-style job is added (D4).
- **The matrix table's qemu estimates are stale.** Phase 3 measured
  Rocky 9 shipping **qemu 10.1.0**, not the 8.2 the master plan
  estimated. Phase 2c/2b measured all seven. Take versions from those
  measurements, and let the job report the live version (4c) rather than
  asserting a table.

## Decisions

### D1. Trigger and gating shape

Add a bare `merge_group:` to the trigger list. Gate the new matrix and
its build job on
`(github.event_name == 'merge_group' || github.event_name == 'workflow_dispatch')`,
matching the sibling exactly. The dispatch arm is what makes the phase
acceptance runnable without enqueuing anything.

### D2. What the queue runs — recommendation: matrix + a fast build gate only

Because only `test-partition` is gated today, the naive change makes
the queue run seven `xl` integration jobs *plus* seven matrix
containers. Recommendation:

- Keep **`build-and-test`** ungated so it also runs in the queue — it
  is the cheap `s`-runner fast-fail, and the package build depends on a
  working build anyway.
- Gate `package-smoke`, `integration-core`,
  `integration-convert-qcow2`, `integration-convert-vhd`,
  `snapshot-harnesses`, `oslo-crossval-master`, and
  `automated_reviewer` to `github.event_name != 'merge_group'`.

The justification is coverage, not cost alone: each matrix entry runs
the **full** suite (D3 of the master plan) against the packaged binary,
so the queue's coverage is a superset of the PR integration jobs on
seven distros rather than one. Re-running the PR jobs in the queue buys
a second copy of a strictly weaker signal. Record this reasoning in the
workflow as a comment — the next reader will otherwise "fix" the gates.

### D3. Build once, consume seven times

Add a `package-build` job (`needs: build-and-test`, merge_group-gated)
that runs `make instar && make package` and uploads
`src/target/debian/instar_*.deb` and
`src/target/generate-rpm/instar-*.rpm` as one artifact. Each matrix
entry downloads it and picks the file its `pkg_kind` names.

This is only valid because phase 1 lowered the build floor to bullseye
(`GLIBC_2.30`), making one artifact set installable on all seven
distros — it is the concrete payoff of decision D1 in the master plan,
and phase 1's completion is what unlocks it. Assert it rather than
assume it: if a matrix entry ever fails at *install* time, that is a
floor regression, not a test failure.

### D4. Docs-only changes in the queue

Recommendation: **defer**. Adopting the sibling's `check_paths` job is
the right long-term shape, but it is a change to how *every* job in
this workflow is gated and it is not needed for the matrix to work.
Ship the matrix first; revisit if docs-only merges prove painful. Note
it explicitly in the phase-5 handover so the operator knows a docs-only
PR currently pays full matrix latency.

### D5. Fan-out control

`fail-fast: false` always — one distro's failure must not mask the
other six. Add `max-parallel` as a tunable, defaulting to a value the
operator confirms against the real `xl` pool size (see R1); the
KVM-contention risk (R2) argues for a number below seven regardless of
pool size.

## Steps

| Step | Effort | Model | Isolation | Brief for sub-agent |
|------|--------|-------|-----------|---------------------|
| 4a | medium | sonnet | none | **Triggers and gates (D1, D2).** Add bare `merge_group:` to `on:`. Add `if: github.event_name != 'merge_group'` to `package-smoke`, `integration-core`, `integration-convert-qcow2`, `integration-convert-vhd`, `snapshot-harnesses`, `oslo-crossval-master`, `automated_reviewer`; leave `build-and-test` ungated and `test-partition` as it is. Comment the *why* (D2's coverage argument) at the top of the job list. Verify with `actionlint` and by reading each job's resulting effective condition — do not add the matrix yet. |
| 4b | medium | sonnet | none | **`package-build` job (D3).** `needs: build-and-test`, gated `merge_group \|\| workflow_dispatch`, `[self-hosted, debian-12, xl]`. Copy `package-smoke`'s docker install + `docker image rm -f instar-build instar-release` preamble. Run `make instar && make package`. `actions/upload-artifact@v4` with a single named artifact containing both `src/target/debian/instar_*.deb` and `src/target/generate-rpm/instar-*.rpm`; `if-no-files-found: error` so a missing `.rpm` fails here rather than in seven confusing places. |
| 4c | high | opus | none | **`package-matrix` job.** `needs: package-build`, same gate, `[self-hosted, debian-12, xl]`, `strategy: {fail-fast: false, max-parallel: <D5>}`, `matrix.distro` as a list of objects `{name, image, pkg_kind}` over the seven entries in the master-plan table (`debian:12`, `debian:13`, `ubuntu:22.04`, `ubuntu:24.04`, `fedora:latest`, `rockylinux:9`, `rockylinux/rockylinux:10`). `name: "${{ matrix.distro.name }}"`. Steps: checkout into `instar/` (mirror `integration-core`'s two-checkout layout), `prepare-testdata.sh` with `TESTDATA_TOKEN`, the resparsify loop, docker install, `download-artifact`, then `tools/test-package-functional.sh <resolved package> <image>`. Resolve the package path by `pkg_kind` in a **script, not inline YAML** (per the no-large-scripts-in-workflow-steps rule) — extend `tools/ci/` with a small resolver or add a `--pkg-kind` mode to the runner; decide and document which. `timeout-minutes` per R3. |
| 4d | medium | sonnet | none | **Result surfacing.** Tee the runner output; on completion append a row to `$GITHUB_STEP_SUMMARY` with distro name, image, the live qemu-img version parsed from the runner's `--- Versions under test ---` block, the `Ran:/Passed/Skipped/Failed` totals, and PASS/FAIL. Use `if: always()` so failures report too. Put the parsing in a `tools/ci/` script, not inline YAML. The qemu version in the summary is what makes a red row attributable to a version boundary rather than a packaging bug (phase 2/2b lineage). |
| 4e | medium | sonnet | none | **Flake quarantine (master-plan policy).** Support an optional `allow_failure: true` key on a matrix entry, consumed as `continue-on-error: ${{ matrix.distro.allow_failure \|\| false }}`. Default **no entry** to it. Document in the workflow comment and `docs/testing.md`: an entry that fails twice consecutively for a reason established as environmental gets the flag with a linked issue, and the flag is removed when the issue closes. Note the sharp edge — a `continue-on-error` job reports `success` to the `needs` context, so a quarantined entry genuinely stops gating. |
| 4f | medium | sonnet | none | **`can_merge` aggregate gate (corrects sketch 4e).** New job: `needs: [package-build, package-matrix]`, `if: always() && github.event_name == 'merge_group'`, small runner, `permissions: {actions: read}`, and the sibling's jq body — `ALL_SUCCESS=$(echo "$NEEDS_JSON" \| jq '. \| to_entries \| map([.value.result == "success", .value.result == "skipped"] \| any) \| all')` then `[ $ALL_SUCCESS == true ]`. Do **not** touch `automated_reviewer`'s `needs:`. This job's name is what phase 5 makes the queue's required check. |
| 4g | low | sonnet | none | **Docs.** `docs/testing.md`: the PR-vs-merge-queue job split, the seven entries, the quarantine policy, and how to reproduce one entry locally (`tools/test-package-functional.sh` with `--select`). `AGENTS.md`/`ARCHITECTURE.md`: a pointer only, no duplication. CHANGELOG `[Unreleased]`. Update the master plan's phase-4 row and its stale qemu-version estimates against the phase-2c/2b measurements. |

## Acceptance

- A `workflow_dispatch` dry run fans out over all seven distros, each
  installing the shared artifact and running the full suite.
- Build-once/consume-many confirmed: one `.deb` and one `.rpm` feed all
  seven entries, and no entry rebuilds instar (D3, the phase-1 payoff).
- The job summary names each distro, its live qemu-img version, its
  test totals, and its result.
- `pull_request` runs are unchanged: same jobs, no matrix, no added
  latency. Verify by reading a real PR run, not by reasoning.
- `can_merge` exists, aggregates the matrix, and reports only on
  `merge_group`. `automated_reviewer` still runs on PRs.
- Measured per-entry and total wall-clock recorded in this file, so
  phase 5 can size the queue (R1, R3).
- `actionlint` and `shellcheck` clean via `pre-commit run --all-files`.

## Risks

- **R1 — runner pool size is unknown.** Seven concurrent `xl` entries,
  each pulling a distro image and running a full KVM suite. I could not
  enumerate the pool (`gh api orgs/shakenfist/actions/runners` needs
  `admin:org`), so `max-parallel` must be set from a number Michael
  confirms, not guessed. Getting this wrong starves the rest of the
  fleet rather than failing loudly.
- **R2 — KVM contention manufactures failures.** Phase 2c saw nine
  failures that were host-load artifacts reading as data corruption,
  and phase 2b had to re-run serially. Seven containers at
  `--concurrency 4` is 28 concurrent KVM workloads. Dial `max-parallel`
  and `--concurrency` together, and classify any first-run divergence by
  isolated `--select` replay before calling it a regression (memory:
  diffuzz_spurious_divergence_contention).
- **R3 — timeouts are unmeasured.** The suite is ~3250 tests; the dev
  host does ~15 min across 16 workers, and phase 3 flagged that
  `--concurrency 4` in one container is materially longer without
  recording the number. Set generous `timeout-minutes` (90 as a
  starting point), measure on the first dispatch run, then tighten. A
  timeout that fires mid-suite in the queue looks like a flaky distro.
- **R4 — `GITLAB_TESTDATA_TOKEN` in `merge_group`.** Flagged by the
  master plan and again by phase 3. Verify the secret is exposed to the
  `merge_group` event class before relying on it; a queue run that
  cannot fetch testdata fails opaquely, and the LFS-pointer failure mode
  looks like a mass instar regression (memory:
  testdata_lfs_pointer_drift). The dispatch dry run in 4c's acceptance
  exercises the same path and is the cheap way to find out.
- **R5 — a skipped dependency skips its dependents.** The mechanism
  behind the sketch's broken 4e. Any `needs:` edge crossing the
  PR/merge_group boundary must use `if: always() && <event test>`, as
  `can_merge` does. Re-check every `needs:` after 4a's gating changes.
- **R6 — `continue-on-error` reports success.** A quarantined entry
  (4e) does not merely tolerate failure; it becomes invisible to
  `can_merge`. That is the intent, but it means a forgotten flag
  silently drops a distro from the gate. Tie each flag to an open issue.

## Out of scope

- Enabling the merge queue itself and the verification merge — phase 5.
- Adopting `check_paths`/`dorny/paths-filter` for docs-only skipping
  (D4) — deferred, noted for phase 5.
- Any change to instar behaviour or to the runner script's semantics.
  If a matrix entry finds a real parity gap, it is a new phase, not a
  fix folded in here (this is how phase 2b came to exist).
- Publishing the built packages anywhere — they are CI artifacts only.
