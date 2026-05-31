# PLAN-rebase-commit phase 05: rebase integration tests + baselines

## Prompt

Before responding to questions or discussion points in this
document, explore the codebase thoroughly. Read
`tests/base.py` (InstarTestBase + the per-op runners),
`tests/test_create.py` and `tests/test_resize.py` (smoke +
baseline matrix patterns), `tests/helpers/info_json.py` and
`tests/helpers/comparators.py` (normalisation and diffing),
the baseline generator at
`instar-testdata/scripts/generate-baselines.py` (CREATE_CASES,
RESIZE_CASES, dispatcher, profile dedup), and the existing
`expected-outputs/` directory layouts. Ground your answers in
what the code actually does today.

Phase plans live alongside the master plan in `docs/plans/`,
named `PLAN-rebase-commit-phase-NN-<descriptive>.md`. The
master plan is [PLAN-rebase-commit.md](PLAN-rebase-commit.md).
This phase is the fifth of twelve.

I prefer one commit per logical step.

## Situation

Phase 4 (partial) shipped the rebase host CLI's pre-checks,
chain discovery, and rendering helpers. The KVM lifecycle
that actually launches the rebase guest binary (step 4d) is
deferred. This means today:

- **Error paths are testable end-to-end.** The host CLI
  catches missing overlays, missing new backings, oversized
  paths, overdeep chains, and the unsupported-format /
  unsupported-subformat surface, and reports them via clear
  `stderr` messages before any guest launches.
- **Success paths are not yet testable end-to-end.** Until
  step 4d lands, `instar rebase` errors out at the guest-
  launch boundary with "guest lifecycle not yet wired".
  Success-path tests can be written today but must skip
  with a clear "depends on phase 4 step 4d" message.

Cross-version baselines (`qemu-img rebase` outputs across
the ~80 versions in `instar-testdata/qemu-img-binaries/`)
are independent of instar's guest launcher — `qemu-img` does
the work — so the baselines themselves can be generated and
stored today. The matrix tests that compare instar's output
to those baselines depend on 4d, just like the in-process
success tests.

Phase 5 therefore delivers a complete test surface: the
helpers and test classes are in place, the error-path tests
run, the success-path tests skip with clear messages, and
the baselines are generated and stored. When 4d ships the
success-path tests start passing without any phase 5
changes — the test suite simply ungates.

The relevant existing infrastructure this phase builds on:

- **InstarTestBase**
  (`tests/base.py` lines 36–84). Loads the manifest,
  detects the host's qemu-img version, exposes
  `get_image()`, `get_expected_output()`,
  `get_qemu_version_for_profile()`, and the per-op
  runners (`run_instar_info`, `run_instar_check`,
  `run_instar_convert`, etc.).
- **Test-class pattern**
  (`tests/test_create.py`, `tests/test_resize.py`).
  Smoke class (per-format quick happy paths) + matrix
  class (factory-generated per-(target, case) tests) +
  error-paths class.
- **JSON normalisation**
  (`tests/helpers/info_json.py`). `normalise_info_json`
  + `assert_info_equivalent` whitelist legitimate
  divergences (`actual-size`, cache hints, vmdk
  `cid`/`parent-cid`) and diff with a friendly error.
- **Baseline generator**
  (`instar-testdata/scripts/generate-baselines.py`).
  CREATE_CASES + RESIZE_CASES + a dispatcher that
  iterates `qemu-img-binaries/<arch>/<version>/`,
  produces raw per-version outputs under
  `expected-outputs/<cmd>-<type>/<target>/<version>/`,
  and a sibling `detect-profiles.py` that builds
  `version-map.json` to deduplicate identical outputs
  into profile names like `profile-8-2-10`.
- **Existing rebase test infrastructure**
  (`src/crates/rebase/src/qcow2.rs`,
  `src/crates/rebase/src/vmdk.rs`). The phase 2 planner
  crates have in-crate `#[cfg(test)]` tests; phase 5's
  Python integration tests exercise the host/guest
  combination, complementary to the Rust unit tests.

## Mission and problem statement

After phase 5 lands:

1. `tests/base.py` exposes new helpers:
   - `run_instar_rebase(overlay, *args, timeout=60)` —
     invokes `instar rebase` with the given positional +
     flag arguments, returns `(stdout, stderr,
     returncode)`.
   - `run_qemu_img_rebase(overlay, backing, *args,
     timeout=60)` — invokes the system `qemu-img rebase`,
     same return shape.

2. `tests/test_rebase.py` exists and exposes three test
   classes:
   - `TestRebaseErrorPaths` — exercises the host CLI's
     pre-check failure paths. Every test in this class
     runs today against phase 4 step 4c.
   - `TestRebaseSuccessPaths` — qcow2 `-u`, vmdk `-u`,
     qcow2 detach. Each test calls `self.skipTest("phase
     4 step 4d deferred — guest lifecycle not yet wired")`
     for now; the skip messages disappear when 4d ships.
   - `TestRebaseBaselineMatrix` — factory-generated
     per-(target, case) tests that load baselines from
     `expected-outputs/rebase-info-json/`. Same skip
     pattern as success paths.

3. `instar-testdata/scripts/generate-baselines.py` knows
   how to generate rebase baselines:
   - `REBASE_CASES` dict declares cases per target
     format. Each entry: `(case_name, overlay_size,
     backing_size_or_none, options)`.
   - The dispatcher routes `--command rebase` through a
     new `generate_rebase_baseline(qemu, target, case)`
     helper. The helper builds the overlay + backing
     using the same qemu-img version (so the test
     image's exact byte layout matches what that
     qemu-img would produce), runs `qemu-img rebase`,
     then `qemu-img info --output=json` on the result,
     and saves the JSON output as the baseline.
   - The output directory tree mirrors the existing
     conventions: raw per-version under
     `expected-outputs/rebase-info-json/<target>/<version>/<case>.stdout.txt`,
     with `detect-profiles.py` building a
     `version-map.json` and a `profiles/` tree for
     deduplication.

4. The baseline generator is run once against the
   pre-existing qemu-img-binaries tree, the resulting
   files committed to the `instar-testdata` repo, and the
   `instar-testdata` Cargo lockstep updated (if there is
   one — see open question 4).

5. Smoke tests for `TestRebaseErrorPaths` cover at least:
   - Overlay file doesn't exist.
   - New backing doesn't exist (safe mode without `-u`).
   - New backing doesn't exist (`-u` mode: should NOT
     fail, but the guest will then error out — for now
     this is the "guest deferred" message).
   - Oversized backing path (> 1024 bytes).
   - Missing `-b` flag (rejected by clap).
   - Overlay is raw or VHDX (unsupported format —
     pre-check + guest error path).
   - Detach (`-b ""`) against a vmdk overlay (works
     mechanically today through pre-checks, but the
     guest lifecycle is deferred).

6. `pre-commit run --all-files`, `make instar`,
   `make test-rust`, and `make test-integration
   tests/test_rebase.py` all pass. Tests run with
   `pytest` in the Python venv pattern that
   `tests/test_resize.py` uses.

7. The `tests/manifest.json` is unchanged — phase 5 does
   not add new fixture images; the matrix tests build
   their overlays + backings on-the-fly via `instar
   create` (same pattern as `TestCreateBaselineMatrix`).
   This avoids growing the testdata repo for tests that
   are equally well served by deterministic on-the-fly
   creation.

## Open questions

### 1. Should the baselines be generated and committed now, or wait for 4d?

Working choice: **generate and commit now**. The baselines
are `qemu-img`'s outputs, independent of instar's status.
Generating them now means:

- The `instar-testdata` repo gets the new
  `expected-outputs/rebase-info-json/` tree once.
- When 4d ships, the `TestRebaseBaselineMatrix` tests
  ungate automatically and exercise the full matrix
  against the already-committed baselines.
- Future fixes that touch the rebase planner are caught
  by the baseline matrix at landing time, not waiting
  for a separate baseline-generation pass.

Alternative: defer baseline generation until 4d ships.
Rejected because it couples two unrelated workstreams.

### 2. What's the `REBASE_CASES` matrix shape?

Working draft (each tuple `(case_name, overlay_size,
backing_size, opts)`; `backing_size = None` means detach):

```python
REBASE_CASES = {
    'qcow2': [
        ('1M-to-default-parent', '1M', '1M', []),
        ('1M-to-larger-parent', '1M', '64M', []),
        ('1M-detach', '1M', None, []),
        ('64M-to-default-parent', '64M', '64M', []),
        # cluster_size sweep on overlay
        ('1M-cs-4k-to-parent', '1M', '1M', ['overlay_cluster_size=4k']),
        # backing-format hint (qcow2 -> qcow2 today; cross-format deferred)
        ('1M-to-parent-with-F', '1M', '1M', ['backing_format=qcow2']),
    ],
    'vmdk': [
        ('1M-to-default-parent', '1M', '1M', []),
        ('1M-detach', '1M', None, []),
    ],
}
```

Notes:
- All cases use `-u` since safe-mode qcow2 is deferred
  (phase 3 step 3e) and safe-mode vmdk is deferred
  (phase 2 step 2e). When those land, additional cases
  drop the `-u` and the baseline generator picks them up
  automatically (cases just have different option sets).
- Cluster-size sweep on overlay limited to 4 KiB — the
  phase 2 planner only supports `refcount_bits == 16`,
  which constrains the smallest cluster size. 64k
  default is exercised by `1M-to-default-parent`.
- Cross-format rebase (qcow2 overlay onto vmdk backing,
  or vice versa) is out of scope for v1. The planner's
  `NewBackingIncompatible` check rejects format mixing
  for safety; a future plan can relax this.

### 3. Where does the rebase baseline-generator helper live?

Working choice: **add it to the existing generator script
at `instar-testdata/scripts/generate-baselines.py`** as a
peer of `generate_create_baseline` /
`generate_resize_baseline`. The dispatcher just gains a new
`elif command == "rebase":` arm. Keeping the helpers in one
file matches the pattern create and resize already
established.

### 4. Cross-repo coordination with `instar-testdata`

The baselines live in `instar-testdata`, a separate git
repo. Phase 5 makes coordinated changes:

- `instar` (this repo): test code that *reads* the
  baselines.
- `instar-testdata`: the generator script and the
  baseline files themselves.

Working choice: **two coordinated commits, one per repo.**
The instar-side commit lands first with the test code that
skips when baselines are missing; the instar-testdata-side
commit lands second with the new `REBASE_CASES` and the
generated baseline tree. Until the testdata commit lands,
`TestRebaseBaselineMatrix` skips with "no baseline for
<target>/<case>". This matches how create and resize
baselines were added historically.

Step 5g closes out by surfacing the testdata-side
diff for review (the operator commits it in the
`instar-testdata` worktree).

### 5. How should `TestRebaseSuccessPaths` skip cleanly?

Working choice: use `self.skipTest(...)` with a message
naming the dependency:

```python
def test_qcow2_unsafe_rebase_round_trip(self):
    """qcow2 -u rebase round-trips backing reference."""
    self.skipTest("rebase guest lifecycle deferred (phase 4 step 4d)")
```

When 4d ships, removing the `skipTest` line is the only
required change. Pytest reports the test as skipped, not
failing, so CI stays green meanwhile.

### 6. JSON normalisation for rebase output

The post-rebase `qemu-img info --output=json` output is
the existing info JSON shape (no rebase-specific
envelope). `tests/helpers/info_json.py` already
normalises that shape; phase 5 reuses it directly. No new
helper needed.

What may differ between instar's rebased overlay and
qemu-img's: `actual-size` (filesystem-dependent — already
in `UNIVERSAL_DIVERGENCE`), VMDK `cid` / `parent-cid`
(already in `TARGET_DIVERGENCE`). The existing whitelist
should cover everything.

Open subquestion: does the `backing-filename` field in
qcow2 info JSON include the path verbatim as the user
typed it? If yes, the test must use the same string for
both instar and qemu-img invocations.

### 7. Manifest hash drift

Phase 5 doesn't add fixture images, so manifest hash
drift isn't a phase 5 concern. The matrix tests build
images on-the-fly under `tempfile.TemporaryDirectory()`,
so they don't depend on testdata image hashes.

## Execution

| Step | Effort | Model | Isolation | Brief for sub-agent |
|------|--------|-------|-----------|---------------------|
| 5a | medium | sonnet | none | Add `run_instar_rebase(overlay, *args, timeout=60)` and `run_qemu_img_rebase(overlay, backing, *args, timeout=60)` helpers to `tests/base.py`. Mirror the signature shape of `run_instar_check` / `run_qemu_img_check` (return `(stdout, stderr, returncode)`). The instar helper accepts arbitrary additional flags via `*args` (the test class passes `-u`, `-q`, `--output`, `-b <path>`, etc.). The qemu-img helper takes `backing` as a required positional plus optional flag args. Both helpers catch `subprocess.TimeoutExpired` and return `(stdout_so_far, stderr_so_far, -1)`. |
| 5b | medium | sonnet | none | Create `tests/test_rebase.py` with `TestRebaseErrorPaths`. Smoke tests that run today: overlay missing; new backing missing (safe mode); oversized backing path; missing `-b` flag; overlay is raw / VHDX (unsupported format); detach (`-b ""`) against an overlay that doesn't exist; quiet mode swallowing the success line (smoke). Each test asserts the exit code and the substring in stderr — no JSON parsing needed at this layer. |
| 5c | medium | sonnet | none | Add `TestRebaseSuccessPaths` to `tests/test_rebase.py`. Stubs for qcow2 `-u` rebase, vmdk `-u` rebase, qcow2 detach. Each test calls `self.skipTest("rebase guest lifecycle deferred (phase 4 step 4d)")` so the suite still runs cleanly. Comments name the expected post-skip assertion shape: build overlay + backing via `instar create`, run `instar rebase`, run `qemu-img info` on the result, assert the new backing reference appears in the info JSON. |
| 5d | high | opus | none | Extend `instar-testdata/scripts/generate-baselines.py` to support `--command rebase`. Add `REBASE_CASES` dict (working draft in open question 2; confirm with operator before generating). Add `generate_rebase_baseline(qemu, target, case)` helper alongside the existing `generate_create_baseline` / `generate_resize_baseline` (search the file for those function names). The helper: invokes the supplied `qemu-img` to create overlay + backing, runs `qemu-img rebase -f <target> -b <backing> -u <overlay>`, runs `qemu-img info --output=json <overlay>` on the result, stores stdout/stderr/meta.json into `expected-outputs/rebase-info-json/<target>/<version>/<case>.<ext>`. Use opus: the generator pattern is dense (manifest discovery, sparse-image normalisation, profile dedup hooks). |
| 5e | high | opus | none | Add `TestRebaseBaselineMatrix` to `tests/test_rebase.py`. Mirror `TestCreateBaselineMatrix` in `tests/test_create.py:817–1012`: `_baseline_root` / `_baseline_version_dir` / `_baseline_stdout` / `_baseline_meta` helpers; `test_rebase_cases_match_baselines` schema-drift check; factory `_make_rebase_baseline_test(target, case)` registered into the class via `setattr` at module load. Each generated test currently calls `self.skipTest(...)` for the 4d deferral; the skip-removal will be a one-line follow-up. Use opus: the matrix factory + the baseline-loading + the normalisation glue is the heaviest test code in the phase. |
| 5f | medium | sonnet | none | Round-trip helper test. Add one test to `TestRebaseSuccessPaths` (also currently skipped) that: builds overlay + backing in a tempdir; runs `instar rebase -u` and `qemu-img rebase -u` against fresh copies of the same overlay; runs `qemu-img info --output=json` on each; calls `assert_info_equivalent` from `tests/helpers/info_json.py`. This is the canonical "instar matches qemu-img" assertion shape; once 4d ships and the skip is removed, the test asserts the contract directly. |
| 5g | low | sonnet | none | Run `pre-commit run --all-files`. Resolve any rustfmt / clippy findings (unlikely — phase 5 is Python-only). Run `make test-integration tests/test_rebase.py` (error-path tests should pass; everything else should skip). Update the phase-5 execution table row in `docs/plans/PLAN-rebase-commit.md` to mark each shipping commit. Surface the `instar-testdata` worktree diff for operator review (instar-testdata is a separate repo; the baseline files live there). |

## Agent guidance

### Execution model

Same as phases 1–4: implementation runs in the management
session unless explicitly delegated. Use opus for 5d and 5e
because the cross-repo generator + matrix factory cross
qemu-img knowledge, filesystem layout, and Python test
discovery simultaneously.

### Planning effort

Master plan flagged phase 5 as **medium effort**. Within
the phase, 5d and 5e are high; the rest are medium-low.

### Step ordering

Strict dependency: 5a → 5b → 5c → 5d → 5e → 5f → 5g.
5a provides the helpers everyone else uses. 5b and 5c are
independent of 5d (they don't read baselines). 5e
depends on 5d having defined the case shape. 5f reuses
the existing info_json helpers but builds on 5a's
runners.

### Management session review checklist

After each step:

- [ ] The files that were supposed to change actually
      changed.
- [ ] No unrelated files modified.
- [ ] `pre-commit run --all-files` clean.
- [ ] `make test-integration tests/test_rebase.py` runs
      to completion; error-path tests pass, success-path
      tests skip with clear messages, matrix tests skip
      with "no baseline" or "phase 4 step 4d deferred".
- [ ] No new fixture images added to
      `tests/manifest.json` (matrix tests build on the
      fly).
- [ ] The `instar-testdata` worktree diff (step 5d) is a
      separate commit in a separate repo; the operator
      reviews and commits it separately.
- [ ] The baseline file structure under
      `instar-testdata/expected-outputs/rebase-info-json/`
      matches the existing `create-info-json/` and
      `resize-info-json/` layouts byte-for-byte.

## Administration and logistics

### Success criteria

Phase 5 is complete when:

* `tests/test_rebase.py` exists with the three test
  classes documented above.
* `tests/base.py` exposes `run_instar_rebase` and
  `run_qemu_img_rebase`.
* Error-path tests pass.
* Success-path and matrix tests skip with clear messages.
* `instar-testdata/scripts/generate-baselines.py`
  supports `--command rebase` and produces baselines
  matching the on-disk shape for create and resize.
* `instar-testdata/expected-outputs/rebase-info-json/`
  is populated (in the testdata repo) for every
  installed qemu-img version.
* `make test-integration tests/test_rebase.py` completes
  cleanly.
* The execution-table row for phase 5 in
  `PLAN-rebase-commit.md` is marked complete with
  shipping commit hashes (instar-side) and a pointer to
  the testdata-side commit.

### Future work created by this phase

- When phase 3 step 3e (qcow2 safe-mode runner) lands,
  add `REBASE_CASES` entries that drop `-u` and
  regenerate baselines.
- When phase 2 step 2e (vmdk safe-mode planner) +
  phase 3 vmdk safe-mode runner land, same for vmdk
  cases.
- Cross-format rebase (qcow2 ↔ vmdk) when the planner
  relaxes the format-match check.
- Differential fuzz integration: `scripts/differential-fuzz.py`
  could gain a `rebase` operation in its `OPERATIONS`
  list once the success-path tests pass cleanly. Track
  separately.
- Once phase 4 step 4d ships and the success-path
  skips are removed, audit the baselines for any
  qemu-img-version-specific divergences and add to the
  normalisation whitelist in `tests/helpers/info_json.py`
  if needed.

### Bugs fixed during this work

To be filled in as work progresses.

### Documentation index maintenance

Not added to `docs/plans/order.yml` — phase plans live
alongside the master plan but only the master plan is
indexed.

### Back brief

Before executing any step of this plan, please back brief
the operator as to your understanding of the plan and how
the work you intend to do aligns with that plan.
