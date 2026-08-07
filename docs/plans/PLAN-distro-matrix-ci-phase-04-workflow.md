# Phase 4: Workflow integration (merge_group package-matrix job)

Master plan: [PLAN-distro-matrix-ci.md](PLAN-distro-matrix-ci.md).
Planning effort: **medium**. Isolation: none. Depends on phases 2, 3.

## Objective

Add a `package-matrix` job to
`.github/workflows/functional-tests.yml`, gated to `merge_group`
events, that fans out over the seven matrix distros and runs
`tools/test-package-functional.sh` for each. PR events keep today's
jobs (build, unit, integration, `package-smoke`); the matrix runs only
in the merge queue.

## Background (verified facts)

- `functional-tests.yml` triggers on `pull_request` and
  `workflow_dispatch` today (no `merge_group` yet). Jobs run on
  `[self-hosted, debian-12, xl]` with `/dev/kvm`.
- `package-smoke` (`functional-tests.yml:256`) is the single-distro
  precedent: `make instar && make deb`, then the smoke script on
  `debian:trixie`.
- Sibling pattern to lift: `shakenfist/shakenfist`'s
  `functional-tests.yml` splits `functional_matrix_pr` from
  `functional_matrix_merge`; `shakenfist/kerbside-patches` has a
  Rocky/Fedora cross-distro matrix. Read both for the merge_group gate
  shape and runner labelling.
- `GITLAB_TESTDATA_TOKEN` must be present for `merge_group` (risk noted
  in master plan).

## Steps

| Step | Effort | Model | Isolation | Brief for sub-agent |
|------|--------|-------|-----------|---------------------|
| 4a | medium | sonnet | none | Add `merge_group:` to the workflow triggers. Gate all *new* work on `if: github.event_name == 'merge_group'` and confirm the existing jobs still run on `pull_request` only (don't double-run them in the queue unless intended — decide and document). |
| 4b | high | opus | none | Add the `package-matrix` job: `needs: build-and-test`; `strategy.matrix` over the seven distros (image + package-format + a stable name); each entry checks out, prepares testdata (prepare-testdata.sh), builds the right package once or consumes a shared build artifact (decide: build-once .deb+.rpm in `build-and-test` and `actions/upload-artifact` → matrix `download-artifact`, since phase 1 makes ONE artifact set glibc-valid for all entries — this is the payoff of D1). Then call `tools/test-package-functional.sh <pkg> <image>`. `fail-fast: false`. |
| 4c | medium | sonnet | none | Per-entry result surfacing: emit a per-distro result (distro, qemu-img version, pass/fail) and a job summary (`$GITHUB_STEP_SUMMARY`) so a red matrix names the distro immediately. Include the qemu-img version in the summary (ties back to phase 2 divergence attribution). |
| 4d | medium | sonnet | none | Flake guard: document and implement the "twice-consecutive-fail → temporary `continue-on-error`" policy from the master plan as a per-entry annotation mechanism (a matrix `include` flag), so one flaky distro can be quarantined without editing the queue. Do NOT default any entry to continue-on-error. |
| 4e | low | sonnet | none | Add the matrix job to the aggregate gate (the `needs:` list that the branch-protection required check depends on — see the `package-smoke` entry at `functional-tests.yml:783`). Update `docs/testing.md` / `AGENTS.md` CI overview with the PR-vs-merge-queue job split. |

## Acceptance

- On a `workflow_dispatch` dry run (or a throwaway merge_group), the
  matrix fans out over seven distros, each installs the shared
  artifact and runs the full suite.
- Build-once/consume-many confirmed: one .deb and one .rpm feed all
  seven entries (D1 payoff).
- Job summary names each distro + its qemu-img version + result.
- `pull_request` runs are unchanged (no matrix, no regression in PR
  latency).
- Actionlint/workflow lint clean (pre-commit runs it).

## Notes / risks

- Building the artifacts once and sharing them is only valid because
  phase 1 lowered the floor; assert phase 1 landed before enabling
  build-once. If phase 1 fell back to per-distro builds, this job
  becomes (build,test) pairs instead — reflect the actual phase-1
  outcome here.
- Verify `GITLAB_TESTDATA_TOKEN` (and any registry creds) are exposed
  to `merge_group` before relying on testdata in the matrix.
