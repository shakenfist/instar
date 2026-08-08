# Plan: Multi-distro install + qemu-img differential CI

## Status: Phases 1–2 code complete; phases 3–5 drafted

Rewritten 2026-08-08 from the original 2026-05-08 draft. The v0.3.0
release has shipped and the `package-smoke` job in
`.github/workflows/functional-tests.yml` has been stable, so the
original "do not start until v0.2 ships and smoke is stable" hold is
lifted. This rewrite corrects several stale facts in the original
draft (see "Corrections to the original draft" below), records the
three gating decisions taken with Michael on 2026-08-08, and folds in
issue #474.

## Prompt

Michael asked, after the v0.3.0 release, to work through the warm-up
issues (#471, #472, #473, #464, #461) and then start planning the
distro matrix CI work. This plan is that planning output. It resolves
the original draft's open design decisions (glibc floor, merge-queue
scope, in-container vs host execution) against decisions Michael made,
and folds in issue #474 (post-release .deb/.rpm install validation).

Before executing any phase, explore the codebase and ground the work
in what exists today — the harness (`tests/base.py`), the packaging
manifests (`src/vmm/Cargo.toml`), the devcontainer
(`src/.devcontainer/Dockerfile`), the smoke script
(`tools/test-package-install.sh`), the existing per-version profile
baseline system in instar-testdata, and the sibling-repo merge-queue
workflows referenced below. Flag uncertainty rather than guessing.

## Goal

Run instar's full functional test suite against the installed .deb /
.rpm packages on a representative matrix of Linux distributions in the
GitHub merge queue. Each matrix entry installs the package, points the
harness at `/usr/bin/instar`, and runs every `tests/test_*.py` against
the qemu-img version that ships with that distribution.

Two purposes:

1. **Catch packaging regressions** that don't surface in the in-tree
   build layout: asset-path errors, runtime-dependency mistakes,
   mode-bit drift, resolver fallback bugs. The v0.3.0 packaging
   incident (ten of sixteen operation binaries silently missing from
   the manifests) is exactly this class; the PR-level `package-smoke`
   job now catches the obvious case on one distro, and the merge-queue
   matrix generalises it across distros and both package formats.
2. **Catch qemu-img output-profile regressions.** instar adapts its
   qemu-img-compatible output to the detected qemu-img version. Today
   that adaptation is exercised only against whatever qemu-img is on
   the build runner. The matrix exercises it against the several real
   qemu-img versions users actually run, catching profile-selection
   drift against the reality of a specific distro.

## Corrections to the original draft

The 2026-05-08 draft was written before v0.3.0 and several
infrastructure changes. Facts corrected here:

- **Build base.** The draft says the build container is pinned to
  `debian:trixie`. It is actually
  `mcr.microsoft.com/devcontainers/base:debian` (a *floating* Debian
  tag, currently trixie → glibc 2.41), set in
  `src/.devcontainer/Dockerfile:2`. Phase 1 pins this deliberately.
- **The glibc coverage arithmetic in the draft is wrong.** The draft
  claims a `bookworm` (glibc 2.36) base "covers Ubuntu 22.04+". Ubuntu
  22.04 LTS ships glibc **2.35**, which is *below* 2.36, so a
  bookworm-built binary will **not** run there. glibc is
  forward-compatible only: a binary runs on hosts whose glibc is
  **≥** the build glibc. You must build on the *oldest* glibc you
  intend to support.
- **The qemu-drift comparator (the draft's "largest design block") is
  already largely built.** instar-testdata carries a per-version
  *profile* system: `expected-outputs/<cmd>-<type>/version-map.json`
  maps qemu-img versions to profile names, and per-profile baselines
  live under `expected-outputs/<cmd>-<type>/profiles/<profile>/`. The
  harness (`tests/base.py:112` `get_output_profiles`,
  `tests/base.py:138` `get_expected_output`) iterates profiles
  explicitly with `--qemu-version`. So the matrix work is *not*
  "invent a tolerant comparator"; it is "ensure every matrix distro's
  qemu-img version maps to a captured profile, and that instar's live
  version-detection selects the right one." See phase 2.
- **The build/test tooling split.** `src/.devcontainer/Dockerfile`
  bundles two unrelated concerns: the **build toolchain** (Rust
  nightly, `protobuf-compiler`, `cargo-binutils`) that determines the
  output binary's glibc floor, and **test/dev tooling** (`qemu-utils`,
  `libqcow-utils`/`libvhdi-utils`/`libvmdk-utils` libyal reference
  parsers for differential fuzzing, `cargo-fuzz`, `cargo-audit`, `gh`)
  that is *not* a build dependency of the released binary. Only the
  first group constrains the glibc floor. This is what makes the
  glibc-floor decision cheap (see phase 1): the libyal/fuzz deps that
  would make a Rocky 9 build painful are test-only and stay on the
  Debian dev image.
- **`package-smoke` already exists** (`functional-tests.yml:256`),
  runs on `[self-hosted, debian-12, xl]`, builds the .deb via `make
  instar && make deb`, and runs `tools/test-package-install.sh` on
  `debian:trixie`. The matrix job is its merge-queue-scoped
  generalisation.

## Decisions (2026-08-08)

### D1. glibc floor: cover all seven target distros (≤ 2.34)

Chosen: the widest coverage — all seven distros in the matrix below,
including Ubuntu 22.04 LTS (glibc 2.35) and Rocky/RHEL 9 (glibc 2.34).
That requires a build-glibc floor of **≤ 2.34**.

**Build base: `debian:bullseye` (Debian 11, glibc 2.31) — agreed
2026-08-08.** The floor is a property of the *build* image only.
bullseye's 2.31 sits below the matrix floor (Rocky 9's 2.34) with ~3
minor-versions of margin, so a bullseye-built binary runs on every
target distro. It keeps the whole build toolchain apt-based and
identical in shape to today's Dockerfile (rustup nightly,
`protobuf-compiler`, `cargo-binutils`) — no port to a non-Debian
package manager — and the libyal / `cargo-fuzz` / `cargo-audit`
tooling that is awkward outside Debian does **not** move, because it
is test-only and stays on the existing Debian dev image. bullseye is
Debian oldstable (still supported), not an EOL base; the next-older
Debian (buster, glibc 2.28) is archived and deliberately not chosen.

This is the concrete form of the broader principle Michael affirmed:
**build Debian-only; validate on the real distros.** The build never
leaves Debian; the non-Debian coverage comes entirely from installing
and running the produced package *inside* the real target-distro
containers (phases 3–4), not from building there.

`rockylinux:9` (glibc 2.34) is retained only as a **contingency** — to
be used solely if phase 1's empirical verification finds a concrete
distro on which the bullseye-built binary fails (none is expected).
Adopting it would mean porting the toolchain install to dnf, so it is
not the plan of record.

Phase 1 still **verifies the binary actually runs on every distro in
the matrix** (`tools/verify-glibc-floor.sh`) — that empirical check,
not the nominal glibc number, is the acceptance gate for the floor.

**Architecture: split the devcontainer.** Introduce a minimal
low-glibc *build* image (toolchain only) that produces the binary and
the packages, separate from the existing fat Debian *dev/test* image
(which keeps qemu-utils, libyal, fuzzers). `make instar` / `make deb`
/ `make rpm` use the build image; `make test` / fuzz targets keep the
dev image. This keeps the glibc floor a one-line property of a small
image and avoids dragging test tooling onto an old base.

### D2. Merge queue: enable it end-to-end

Chosen: this programme goes all the way through enabling the GitHub
"Require merge queue" branch-protection setting on `develop` (and
`main`) and verifying a real PR merges through the queue and gates on
the matrix (phase 5). Not just building the job and leaving the switch
for later.

### D3. Execution model: run the suite inside the distro container

Chosen: each matrix entry installs the package inside the distro
container, installs Python + pytest + qemu-utils there, sets
`INSTAR_BINARY_PATH=/usr/bin/instar` and `INSTAR_TESTDATA_PATH`, and
runs the suite in-container. This reuses the `test-package-install.sh`
docker-run skeleton and avoids a host/container qemu-img version split.
The testdata is bind-mounted read-only, as the existing jobs do.

## Issue #474 (post-release install validation)

#474 carries the v0.3.0 release's manual real-VM validation of the
**published** .deb/.rpm artifacts (release-plan steps 16-17, deferred
per the v0.2.0 precedent). It is close but not identical to this plan:
#474 is a one-time manual check of the *already-shipped v0.3.0
binaries* (which are glibc-2.41 trixie builds), whereas this plan
automates validation of *future* builds at a lower glibc floor.

Resolution: phase 1 opens by doing #474's manual check (install the
published `instar_0.3.0-1_amd64.deb` and `.rpm` on real KVM-capable
Debian/Ubuntu and Fedora/Rocky VMs, run `instar info` plus `create` +
`map`), which both closes #474 and establishes the human-verified
baseline the automation must reproduce. Once the matrix job is green
(phase 4), the belt-and-braces role of #474 is permanently automated.

## Distro matrix

| Distro        | Package | qemu-img (approx) | glibc | Notes |
| ------------- | ------- | ----------------- | ----- | ----- |
| Debian 12     | .deb    | 7.2               | 2.36  | LTS "bookworm" |
| Debian 13     | .deb    | 9.x               | 2.41  | "trixie", prior build base |
| Ubuntu 22.04  | .deb    | 6.2               | 2.35  | LTS, oldest qemu-img target |
| Ubuntu 24.04  | .deb    | 8.2               | 2.39  | LTS |
| Fedora latest | .rpm    | 9.x/10.x          | 2.39+ | Bleeding-edge qemu-img |
| Rocky/RHEL 9  | .rpm    | 8.2               | 2.34  | Wide enterprise install |
| Rocky/RHEL 10 | .rpm    | 9.x               | 2.39  | Newer enterprise |

Seven entries; each runs the full functional suite. Add openSUSE Leap,
Arch, or Alpine only on specific demand (Alpine is musl, not glibc —
out of scope). The lowest glibc in the matrix is Rocky 9's 2.34, which
D1's build floor must clear.

## Execution

Per-phase detail lives in the phase files below. One commit per
logical change; at minimum one commit per phase.

| Phase | Plan | Status |
|-------|------|--------|
| 1. Build/dev container split + lower glibc floor (closes #474 manually) | PLAN-distro-matrix-ci-phase-01-glibc-build.md | Code complete (steps 1b-1g landed; build base is debian:bullseye, binary floor GLIBC_2.30 verified on Rocky 9 + Debian 12; dev base digest-pinned; workflows reconciled). Remaining: operator step 1a — run tools/validate-published-release.sh on real .deb and .rpm VMs to close #474. |
| 2. qemu-img version→profile coverage + live version-detection | PLAN-distro-matrix-ci-phase-02-qemu-profiles.md | Code complete. Matrix qemu versions enumerated (tools/probe-qemu-versions.sh); full-version profile/baseline selection replaces the 7.2.19-boundary prefix bug (only Debian 12 mis-selected, and benignly — differing fields are normalised); parsers pinned both sides; docs/testing.md updated. No version.rs widen needed. Live in-container per-distro runs deferred to phase 3. |
| 3. In-container matrix runner script | PLAN-distro-matrix-ci-phase-03-runner.md | Not started |
| 4. Workflow integration (merge_group package-matrix job) | PLAN-distro-matrix-ci-phase-04-workflow.md | Not started |
| 5. Enable the GitHub merge queue + live verification | PLAN-distro-matrix-ci-phase-05-merge-queue.md | Not started |

Phases 1 and 2 are independently valuable and ship on their own merits
(phase 1 widens release compatibility; phase 2 hardens version
detection) before any merge-queue machinery exists. Phase 3 depends on
1. Phase 4 depends on 2 and 3. Phase 5 depends on 4.

## Agent guidance

### Execution model

All implementation is done by sub-agents; the management session
plans, reviews the actual files (not the sub-agent's summary), and
commits. Use `isolation: "worktree"` for phase 1 (the container/build
change is risky and easy to get wrong). Phases 2-4 can work in the main
tree. Phase 5 is operator-driven (GitHub settings) and not delegated.

### Planning effort

- Phase 1: **high** — the build/dev split touches the Makefile's docker
  orchestration, the release workflow, and the glibc floor; getting it
  wrong breaks every build. Empirical verification (does the binary run
  on all seven?) is required, not nominal glibc arithmetic.
- Phase 2: **high** — requires understanding the existing profile
  system and the live version-detection path, and deciding what to do
  when a distro's qemu-img version has no captured profile.
- Phase 3: **medium** — generalises an existing script along a
  well-defined path.
- Phase 4: **medium** — follows the sibling-repo merge_group pattern.
- Phase 5: **low** — a GitHub setting plus a verification merge.

### Dependencies and risks

- **`GITLAB_TESTDATA_TOKEN` must reach `merge_group` events.** Verify
  the self-hosted runners expose it for this new job class as they do
  for `pull_request` (see `tools/ci/prepare-testdata.sh` and the
  testdata-token memory note re: Maintainer-role access level).
- **Self-hosted runner pool sizing.** Seven concurrent KVM matrix
  entries, each pulling a distro image and running ~30 min of tests.
  Measure on first runs; sibling repos handle comparable merge-queue
  fan-out.
- **Merge-queue flakiness cascade.** The queue does not rerun
  individual entries; one flaky distro blocks all merges. Any matrix
  entry that fails twice consecutively gets a temporary
  `continue-on-error: true` while investigated, rather than holding the
  queue. (See the diffuzz spurious-divergence-under-contention memory
  note — KVM-under-load flakiness is a known class here.)
- **libyal in-container.** The in-container suite (D3) needs qemu-utils
  for the qemu-img oracle but does **not** need the libyal differential
  parsers (those belong to the fuzz suites, which are not part of the
  matrix). Keep the in-container install minimal.

## Out of scope

- Publishing packages to apt/dnf repositories (PPA, Copr, mirrors).
- Code-signing the packages.
- macOS/Windows packaging — instar requires `/dev/kvm`.
- ARM (aarch64) packaging — deferred per PLAN-release.md until test
  hardware exists.
- Alpine / musl targets — the glibc floor work does not address musl;
  a static-musl build is a separate investigation.
