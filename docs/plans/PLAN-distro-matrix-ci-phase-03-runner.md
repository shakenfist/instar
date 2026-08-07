# Phase 3: In-container matrix runner script

Master plan: [PLAN-distro-matrix-ci.md](PLAN-distro-matrix-ci.md).
Planning effort: **medium**. Isolation: none. Depends on phase 1.

## Objective

Produce `tools/test-package-functional.sh`: given a package
(.deb or .rpm) and a distro image, install the package in that distro
container, install the test prerequisites, and run the full Python
integration suite in-container against `/usr/bin/instar` and the
distro's qemu-img. This is the per-matrix-entry inner runner (D3:
in-container execution).

## Background (verified facts)

- `tools/test-package-install.sh` already accepts a package path and a
  distro image and does the docker-run skeleton + install + smoke
  checks. Generalise from it; do not start from scratch.
- Harness reads `INSTAR_BINARY_PATH` (`tests/base.py:261`) and
  `INSTAR_TESTDATA_PATH` (`tests/base.py:64`). Set both.
- Existing jobs bind-mount testdata read-only and prepare it via
  `tools/ci/prepare-testdata.sh` (LFS-materialised, canary-guarded —
  memory: testdata_lfs_pointer_drift).
- Per global CLAUDE.md: no large inline scripts in workflow steps —
  the logic lives in this `tools/` script, called from the workflow.

## Steps

| Step | Effort | Model | Isolation | Brief for sub-agent |
|------|--------|-------|-----------|---------------------|
| 3a | medium | sonnet | none | Write `tools/test-package-functional.sh <package> <distro-image>`. Reuse `test-package-install.sh`'s docker-run skeleton (incl. `/dev/kvm` passthrough as the functional jobs do). Inside the container: detect apt vs dnf; install the package (`apt install ./pkg.deb` / `dnf install ./pkg.rpm`); install `python3`, `pip`/`venv`, `pytest`, and `qemu-utils` (distro-appropriate package names — this is the fiddly part, table it per distro family); set `INSTAR_BINARY_PATH=/usr/bin/instar` and `INSTAR_TESTDATA_PATH=/testdata` (bind-mounted RO); run `pytest tests/`. Surface the container exit code and a per-distro result summary to the host. |
| 3b | medium | sonnet | none | Handle the Python-deps install robustly across families: Debian/Ubuntu (`python3-pytest` or venv+pip under PEP 668 — use a venv, per the operating-environment note that Debian enforces PEP 668), Fedora/Rocky (`python3-pytest` / `pip`). Pin nothing the repo doesn't already pin; reuse `tests/requirements*.txt` if present. |
| 3c | medium | sonnet | none | Add a fast self-test mode (`--smoke`) that runs only a subset, so the script is usable both as the matrix runner (full) and as a local one-distro check (smoke) — mirrors how `package-smoke` is used today. Keep the full run the default. |
| 3d | low | sonnet | none | `shellcheck` clean (repo runs shellcheck in pre-commit and CI); wire into `tools/run-shellcheck.sh` coverage if that script enumerates explicitly. Docs: a short `docs/testing.md` subsection on running the functional suite against an installed package locally. |

## Acceptance

- `tools/test-package-functional.sh src/target/debian/instar_*.deb debian:12`
  installs and runs the full suite green locally.
- Same for an `.rpm` on `rockylinux:9` (proves the dnf path and the
  phase-1 glibc floor together).
- `--smoke` mode works and is fast.
- `shellcheck` clean; `pre-commit run --all-files` clean.

## Notes / risks

- KVM access inside the container is required (the guest ops run under
  KVM). Mirror the `--device /dev/kvm` / privileged flags the existing
  functional jobs use; verify group perms.
- Testdata must be LFS-materialised before the container sees it
  (prepare-testdata.sh); a container that sees LFS pointers gives the
  "file format: unknown" mass failure (memory: testdata_lfs_pointer_drift).
