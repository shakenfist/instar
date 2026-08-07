# Phase 2: qemu-img version→profile coverage + live version-detection

Master plan: [PLAN-distro-matrix-ci.md](PLAN-distro-matrix-ci.md).
Planning effort: **high**. Isolation: none (main tree).

## Objective

Ensure that when the suite runs against a distro's *live* qemu-img,
every version-sensitive assertion resolves to a captured profile and
instar's own version-detection selects the matching profile. This is
the corrected form of the original draft's "comparator policy" design
block: the per-version profile system already exists, so the work is
**coverage and selection**, not building a tolerant comparator.

## Background (verified facts)

- Baselines are stored per-profile:
  `expected-outputs/<cmd>-<type>/profiles/<profile>/<image>.stdout.txt`,
  with `expected-outputs/<cmd>-<type>/version-map.json` mapping
  qemu-img versions → profile names.
- Harness: `tests/base.py:112` `get_output_profiles`,
  `tests/base.py:138` `get_expected_output`, `tests/base.py:89`
  `_detect_qemu_version` (parses `qemu-img --version`). Profile tests
  iterate all profiles with `--qemu-version`; live tests use the
  detected version.
- instar's own qemu-version-adaptive output logic lives in
  `src/vmm/src/version.rs` and is consumed in `src/vmm/src/main.rs`
  emitters; `tests/test_oslo_crossval.py` cross-validates.
- The matrix distros' qemu-img versions (approx): 6.2, 7.2, 8.2, 9.x,
  10.x. Some of these may not have a captured profile in
  instar-testdata.

## The core question

For each matrix distro's qemu-img version, one of:
1. **A profile exists and matches** → nothing to do beyond asserting
   selection works live.
2. **A profile exists for a nearby version** and the version-map's
   bucketing already covers this version → verify the map entry.
3. **No profile covers this version** → decide: capture a new baseline
   profile (preferred where a static qemu-img build exists — see the
   testdata baseline-generator memory note), or record the version as
   "portable-assertions-only" (run only the version-independent
   assertions on that distro, log the skip loudly).

## Steps

| Step | Effort | Model | Isolation | Brief for sub-agent |
|------|--------|-------|-----------|---------------------|
| 2a | high | opus | none | Audit: enumerate every matrix distro's shipped qemu-img version (from the distro package archives / the phase-1 verify containers), and cross-reference each against `version-map.json` for all commands. Produce a coverage table: (distro, qemu-img version, has-profile?, profile-name-or-gap). This table drives the rest. |
| 2b | high | opus | none | For gaps where a static qemu-img build exists, generate the missing baseline profiles using the instar-testdata baseline generator (`generate-baselines.py` + per-version static qemu-img builds; always `--no-commit` — see the testdata_baseline_generator memory note). Land these in instar-testdata via its own PR (Maintainer-role token; see testdata_push_token memory note). For gaps with no available static build, mark the version portable-only in the harness. |
| 2c | high | opus | none | Verify live version-detection: for each matrix distro, confirm `_detect_qemu_version` parses that distro's `qemu-img --version` string correctly and `src/vmm/src/version.rs` selects the matching profile. Add a focused test that runs in-container per distro (or a fixture table of real `--version` strings across the matrix). Watch for distro-patched version strings (e.g. `qemu-img version 8.2.2 (Debian 1:8.2.2+ds-...)`). |
| 2d | medium | sonnet | none | Add a `portable`/`version-specific` classification helper in `tests/base.py` (e.g. `assert_qemu_compatible(...)`) ONLY where the existing profile machinery does not already cover a live-run assertion. Do not reinvent what `get_expected_output` already does. Prefer extending the version-map bucketing over adding a parallel comparator. |
| 2e | low | sonnet | none | Docs: `docs/testing.md` — how the profile system extends across the distro matrix; how a new qemu-img version gets a profile; the portable-only fallback. Note the per-distro version-string quirks found in 2c. |

## Acceptance

- Coverage table shows every matrix distro's qemu-img version either
  has a profile or is explicitly portable-only.
- Live version-detection verified per distro (correct profile selected,
  distro-patched version strings parsed).
- Any new baselines landed in instar-testdata (separate PR), and instar
  points at the updated testdata.
- `make test` still passes on the dev image.

## Notes / risks

- Do NOT capture baselines from a distro's live qemu-img on a CI runner
  (non-reproducible); use the static-build baseline generator.
- Distro qemu-img builds sometimes carry backported patches that change
  output vs upstream at the same version number — if a live distro
  diverges from the captured upstream-version profile, that is a
  finding to record (a real "distro X patches qemu-img" quirk), not
  necessarily an instar bug. Classify before treating as a regression
  (memory: diffuzz spurious-divergence discipline).
