# Phase 1: Build/dev container split + lower glibc floor

Master plan: [PLAN-distro-matrix-ci.md](PLAN-distro-matrix-ci.md).
Planning effort: **high**. Isolation: **worktree** (breaks every build
if wrong).

## Objective

Lower the release binary's glibc floor to ≤ 2.34 so a single artifact
runs on all seven matrix distros (down to Rocky 9 / Ubuntu 22.04),
without dragging the test/fuzz tooling onto an old base. Split the
current all-in-one devcontainer into a minimal low-glibc **build**
image and the existing fat Debian **dev/test** image.

Also closes issue #474 (manual validation of the published v0.3.0
artifacts) as the human baseline the automation will reproduce.

## Background (verified facts)

- Current base: `mcr.microsoft.com/devcontainers/base:debian`
  (floating, currently glibc 2.41) — `src/.devcontainer/Dockerfile:2`.
- The Dockerfile installs both build toolchain (`protobuf-compiler`,
  rustup nightly pinned `nightly-2026-07-22`, `cargo-binutils`) and
  test/dev tooling (`qemu-utils`, `libqcow-utils`, `libvhdi-utils`,
  `libvmdk-utils`, `cargo-fuzz`, `cargo-audit`, `gh`). Only the first
  group sets the binary's glibc floor.
- `make instar` runs the build inside `$(INSTAR_IMAGE)` built from
  `src/.devcontainer/` (`Makefile:121-144`). `make deb` / `make rpm`
  run `cargo deb` / `cargo generate-rpm` `--no-build` in the same image
  (`Makefile:182+`). `make audit`, fuzz targets, and `make test` also
  use it.
- glibc is forward-compatible only: build on the oldest glibc to
  support. Rocky 9 = 2.34 is the matrix floor.
- The nightly is pinned and force-bumped by
  `.github/workflows/rust-nightly-bump.yml`; that workflow test-builds
  the devcontainer image. If phase 1 adds a second image, the bump
  workflow must build both (see step 1f).

## Approach

Recommended build base: **`debian:bullseye`** (glibc 2.31, apt-based,
minimal toolchain port). Fallback: `rockylinux:9` (glibc 2.34) only if
a bullseye-built binary fails on a specific distro. The **acceptance
test is empirical**: the built binary must run `instar info` + one
post-v0.2 subcommand on every matrix distro, not merely report a low
glibc number.

## Steps

| Step | Effort | Model | Isolation | Brief for sub-agent |
|------|--------|-------|-----------|---------------------|
| 1a | low | sonnet | none | **Close #474 first (manual, operator-run).** Provide Michael a copy-paste script: on a clean KVM-capable Debian/Ubuntu VM `apt install ./instar_0.3.0-1_amd64.deb` then run `instar info`, `instar create`, `instar map` on a sample qcow2; on Fedora/Rocky 10 the same with the published `.rpm`. Record outputs. This is operator-driven — the sub-agent produces the script and the expected-output checklist, Michael runs it. Post results to #474 and close it. This establishes the human baseline. |
| 1b | high | opus | worktree | Create `src/.devcontainer/build/Dockerfile` — the minimal build image `FROM debian:bullseye`, installing ONLY: `protobuf-compiler`, `curl`/`ca-certificates`, rustup with the same pinned `${RUST_NIGHTLY}` + `rust-src`/`llvm-tools-preview` components, and `cargo-binutils` (for `rust-objcopy`), `cargo-deb`, `cargo-generate-rpm`. NO qemu-utils, libyal, cargo-fuzz, cargo-audit, gh. Match the existing `/build` world-writable CARGO_HOME/RUSTUP_HOME umask pattern exactly (see the worktree-target-ownership and rust-devcontainer-permissions memory notes — any docker run writing into the bind-mounted tree must run as host uid with a writable CARGO_HOME). Keep the existing `src/.devcontainer/Dockerfile` as the dev/test image unchanged. |
| 1c | high | opus | worktree | Rewire the Makefile: `make instar`, `make deb`, `make rpm` use the new build image (`$(INSTAR_BUILD_IMAGE)` from `src/.devcontainer/build/`); `make test`, `make audit`, and the fuzz targets keep `$(INSTAR_IMAGE)` (dev image). Add a `build-devcontainer` target parallel to `instar-devcontainer`. Verify `make instar && make deb && make rpm` produce artifacts and `check-binary-sizes` still passes. |
| 1d | high | opus | worktree | **Empirical glibc verification.** Write `tools/verify-glibc-floor.sh` that, given a built .deb and .rpm, installs each in a throwaway container for every matrix distro image (debian:12, debian:13, ubuntu:22.04, ubuntu:24.04, fedora:latest, rockylinux:9, rockylinux:10) and runs `instar info` + `instar create` + `instar map` on a fixture, asserting clean exit. This is the real acceptance test for the floor. If any distro fails on a bullseye-built binary, STOP and report — do not silently switch to rockylinux:9 without management review. |
| 1e | medium | sonnet | worktree | Pin the *dev/test* image base too while here: change `src/.devcontainer/Dockerfile` FROM to a pinned Debian tag (not floating `:debian`) so dev-image rebuilds are reproducible, matching the nightly-pin rationale already in the file. Coordinate the exact tag with Michael. |
| 1f | medium | sonnet | none | Update `.github/workflows/rust-nightly-bump.yml` to test-build BOTH images against a candidate nightly (the build image and the dev image) so a nightly that breaks either blocks the bump. Update `package-smoke` in `functional-tests.yml` if the build-image change alters `make instar`/`make deb` invocation. |
| 1g | low | sonnet | none | Docs: CHANGELOG entry (lower glibc floor → wider distro support; the container split); `docs/development.md` and `AGENTS.md`/`ARCHITECTURE.md` for the two-image model and which make targets use which; note the new minimum-glibc in README install section if it states one. |

## Acceptance

- `make instar && make deb && make rpm` produce working artifacts from
  the new build image.
- `tools/verify-glibc-floor.sh` passes on all seven matrix distros.
- `package-smoke` still green.
- #474 closed with recorded real-VM results.
- Full `make test` still passes on the dev image (the split did not
  disturb the test path).
- `pre-commit run --all-files` clean.

## Notes / risks

- If bullseye's rustup nightly ergonomics bite (unlikely — rustup is
  distro-agnostic), the pin already protects us; the fuzz/audit tools
  that are genuinely awkward on old bases are NOT in the build image.
- Watch CARGO_HOME/target ownership: the build image runs as host uid
  writing into the bind-mounted source tree (memory:
  instar_worktree_target_ownership, rust_devcontainer_permissions).
- Do not remove the dev image or move fuzz tooling — differential
  fuzzing still needs libyal on Debian.
