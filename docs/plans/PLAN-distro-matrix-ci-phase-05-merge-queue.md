# Phase 5: Enable the GitHub merge queue + live verification

Master plan: [PLAN-distro-matrix-ci.md](PLAN-distro-matrix-ci.md).
Planning effort: **low**. Operator-driven (not delegated). Depends on
phase 4.

## Objective

Turn on GitHub's "Require merge queue" branch protection on `develop`
(and `main`) so the `package-matrix` job actually gates merges, and
verify a real PR merges through the queue and is gated by the matrix.

## Why operator-driven

This flips a repo-wide branch-protection setting that changes how every
merge works, and it is visible to all contributors. Per the master
plan's decision D2 the merge queue IS in scope, but the switch itself
and the verification merge are Michael's to perform, not a sub-agent's.

## Steps

| Step | Effort | Model | Isolation | Brief |
|------|--------|-------|-----------|-------|
| 5a | low | (operator) | none | In Settings → Branches → branch protection for `develop`: enable "Require merge queue". Set the queue's required checks to include the `package-matrix` aggregate. Mirror the settings shakenfist/shakenfist uses (confirm build concurrency and min/max group size). Repeat for `main` if release merges target it. |
| 5b | low | (operator) | none | Confirm `GITLAB_TESTDATA_TOKEN` and any registry credentials are available to `merge_group` runs (the master-plan risk item). A queue run that can't fetch testdata fails opaquely. |
| 5c | low | (operator) | none | Verification merge: take a trivial no-op PR through the queue end-to-end. Confirm the matrix runs in the `merge_group` context, gates the merge, and the seven distros report. Confirm a `pull_request` push does NOT run the matrix (PR latency unchanged). |
| 5d | low | sonnet | none | Docs close-out: mark the master plan Complete in `docs/plans/index.md` (+ `order.yml` if adding rows), add the CHANGELOG entry for merge-queue matrix CI, and record the enabled-settings snapshot (queue config, required checks) in `docs/development.md` so the configuration is reproducible if the repo is re-created. |

## Acceptance

- Merge queue enabled on `develop` (and `main` if applicable), with the
  matrix as a required check.
- A real PR observed merging through the queue, gated by the matrix.
- `pull_request` events do not run the matrix.
- Master plan marked Complete; index/order/CHANGELOG updated.

## Notes / risks

- Merge-queue flakiness cascade (master plan): before enabling, be
  confident the matrix is stable — a flaky entry blocks ALL merges.
  Consider running the matrix in a non-gating "report-only" mode for a
  week (via `workflow_dispatch` / a temporary non-required check)
  before making it required, to measure flake rate on real load.
- The export-repo-config workflow (`export-repo-config.yml`) may need to
  learn the new branch-protection/queue settings so the exported repo
  config stays authoritative — check whether it captures merge-queue
  configuration and extend it if not.
