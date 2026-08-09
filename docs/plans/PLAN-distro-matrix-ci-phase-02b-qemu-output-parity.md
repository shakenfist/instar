# Phase 2b: qemu output-parity widen (map/snapshot on older qemu)

Master plan: [PLAN-distro-matrix-ci.md](PLAN-distro-matrix-ci.md).
Planning effort: **high** (touches instar's core output emitters and the
version model). Isolation: none for the code; instar-testdata baseline
work lands via its own `--no-commit`-audited PR. **Phase 4 (the
merge-queue matrix) depends on this** — without it the matrix is red on
every distro shipping qemu < 8.2.

## Why this phase exists

Phase 2 concluded, from the `info` baselines alone, that instar's
two-boolean output model (`include_child_node` ≥8.0, `include_dirty_flag`
≥6.1) needed no widening. The phase-3 in-container runner then ran the
**full** suite against real older-qemu distros for the first time and
disproved that for two other commands: instar hard-codes the newest
qemu output for `map` and `snapshot`, so it diverges on any pre-8.2 /
pre-9.0 qemu. This is the widen-vs-document decision phase 2d reserved
for management; Michael chose **inventory, then widen** (2026-08-09).

## The inventory (phase-3 full runs, 2026-08-09)

Full suite via `tools/test-package-functional.sh` against the two
pre-8.2 matrix distros. Both reduced to the **same three** divergence
classes (bitmap noise eliminated once the runner installed the
`qemu-storage-daemon` oracle):

| Distro (qemu) | Ran | Failed | map-json `compressed` | snapshot `-l` header | qcow1→vpc |
|---------------|-----|--------|-----------------------|----------------------|-----------|
| debian:12 (7.2.22) | 3253 | 28→21* | 19 | 1 | 1 |
| ubuntu:22.04 (6.2.0) | 3253 | 21 | 19 | 1 | 1 |

\* debian:12's original 28 included 7 `test_bitmap` FileNotFoundError
(missing oracle), fixed in the runner (commit 01bef5a); the residue is
21, identical to ubuntu:22.04. The older 6.2.0 qemu surfaced **no new
gaps** beyond 7.2.22 — the set is bounded. Distros shipping qemu ≥ 8.2
(Ubuntu 24.04 8.2.2; Debian 13 / Fedora / Rocky 9/10 at 10.x) do not
hit the map/snapshot gaps and already pass (rockylinux:9 full run:
0 failures).

Both emitters are **host-side** (`map` is formatted by the host from
`MapExtentMessage` structs the guest returns; `run_snapshot_list` is
host-side), so both gates thread through `version::get_profile()` with
**no guest-ABI change** — the same shape as the existing
`include_child_node` gate.

## Steps

| Step | Effort | Model | Isolation | Brief |
|------|--------|-------|-----------|-------|
| 2b-A | high | opus | none | **map-json `compressed` gate (READY — clean boundary).** The field was added at **qemu 8.2.0**, verified directly: 0/38 `map-json/profiles/profile-6-1-0` baselines carry `"compressed"`, 38/38 of `profile-10-0-0` do. instar emits it unconditionally at `src/vmm/src/main.rs:15141,15149`. Add `include_map_compressed` to `version::OutputProfile` (`for_version`: `v.major > 8 || (v.major == 8 && v.minor >= 2)`), thread the profile into the host map emitter (the `MapJsonWriter`/`emit_extent` struct — give it a `&OutputProfile` like the info emitters at `main.rs:1310`), and emit the `compressed` key only when set. Update the Rust unit test `json_compressed_false_emitted_for_every_state` (`main.rs:18867`) to be profile-aware (assert present at ≥8.2, absent below). Re-run the two pre-8.2 distros via the runner and confirm the 19 map failures clear. |
| 2b-B | high | opus | worktree | **snapshot `-l` header gate (BLOCKED on a boundary + a testdata bug).** Real qemu 7.2.22 emits the *old* header (`VM SIZE`/`VM CLOCK` spaces, `00:00:00.000` 2-digit, narrower ID column); instar and qemu 10.x emit the *new* form (`VM_SIZE`/`VM_CLOCK` underscores, `0000:00:00.000` 4-digit) — instar's emitter at `main.rs:16178`. **The testdata cannot pin the boundary:** `snapshot-list-human/profile-6-0-0` (which 7.2.x maps to) stores the *new* underscored form (0 of its 11 baselines contain `VM SIZE`), i.e. it does **not** match what real qemu <9.0 emits — a likely baseline-generation bug. So: (1) determine the true spaces→underscores boundary empirically (qemu git tags / per-version static builds — do NOT trust the version-map here; measure), (2) fix the `snapshot-list-human` baselines in instar-testdata (separate `--no-commit`-audited PR, Maintainer-role token — memory: testdata_baseline_generator, testdata_push_token), (3) add the version gate to `OutputProfile` and emit the old header below the boundary, (4) update the snapshot-format Rust tests (`main.rs:~18959, ~19042`). Validate via the runner. |
| 2b-C | medium | opus | none | **Classify qcow1→vpc (one exotic case).** `test_convert_qcow1_to_vpc` fails identically on 6.2.0 and 7.2.22 (`ref=2097152 flat=2088960`): instar's vpc output, flattened, drops the last 8192 bytes vs qemu's qcow1→raw — a VHD CHS-geometry difference. It passes on qemu 10.x, so instar version-adapts vpc geometry and the <8.x emulation diverges. Get the ground truth with a **real qemu 7.2 `qemu-img convert -O vpc`** oracle: if real old qemu also truncates, instar is faithfully emulating it and the test's zero-tail assertion is too strict for old qemu → record a narrow known divergence (extend the `KNOWN_*_DIVERGENCES` mechanism, per-image, with a reason — no blanket tolerance). If real old qemu preserves the data, instar has a vpc-geometry bug → fix the geometry calc. Decide widen-vs-document from the measurement, not assumption. |
| 2b-D | low | sonnet | none | **bitmap oracle on the RPM family.** The deb family now installs `qemu-storage-daemon` via `qemu-system-common` (commit 01bef5a). Confirm the provider on Fedora/Rocky (or, if it is genuinely unavailable, make `_bitmap_dirty_extents` in `tests/base.py`/`test_bitmap.py` `skipTest` when `shutil.which('qemu-storage-daemon')` is None — the correct behaviour for any absent oracle) so the bitmap differential tests either run or skip cleanly on `.rpm` distros rather than erroring. |
| 2b-E | medium | opus | none | **Full-matrix validation + docs.** Re-run `tools/test-package-functional.sh` (full, not `--smoke`) across all seven distros; confirm green on debian:12, ubuntu:22.04, ubuntu:24.04, debian:13, fedora, rockylinux:9, rockylinux/rockylinux:10 (modulo any documented 2b-C divergence). Update `docs/testing.md` (the version-profile section) and `docs/format-coverage.md` (parity axis) with the map/snapshot version boundaries; refresh the memory note that recorded the info-only "no widen" conclusion. |

## Acceptance

- map-json `compressed` emitted iff detected qemu ≥ 8.2; the 19 map
  failures clear on both pre-8.2 distros; ≥8.2 distros unchanged (2b-A).
- snapshot `-l` header matches real qemu on both sides of the (measured)
  boundary; the `snapshot-list-human` testdata baselines corrected;
  `test_create_list_agreement` passes on debian:12 (2b-B).
- qcow1→vpc classified against a real old-qemu oracle and either fixed
  or recorded as a documented, per-image known divergence (2b-C).
- bitmap oracle runs or skips cleanly on the RPM family (2b-D).
- Full functional suite green (modulo documented divergences) on all
  seven matrix distros via the phase-3 runner (2b-E).
- `make test` green on the dev image; `pre-commit` clean.

## Risks / notes

- **Measure, don't assume, per command.** The map boundary was directly
  verifiable in the baselines; the snapshot one was NOT (the testdata is
  inconsistent with real old qemu). Treat every remaining command as
  suspect until measured against a real old-qemu oracle — this is the
  same discipline as the diffuzz spurious-divergence and
  qemu-capability-sourcing rules.
- **Distro backports.** A distro can carry an output change at a version
  number upstream did not; the boundaries above are upstream-derived and
  must be validated against the actual distro qemu the matrix runs (the
  runner does exactly that).
- **Scope creep.** Only `map`, `snapshot`, and the one `convert` case
  are in evidence. Do not widen speculatively; add a gate only where a
  runner failure proves a real divergence.
- **testdata coupling.** 2b-B's baseline fix and the instar code change
  must land together (re-point instar at the updated testdata), or the
  suite flips red on the transition.
