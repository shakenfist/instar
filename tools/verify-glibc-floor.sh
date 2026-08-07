#!/bin/bash
# Verify the glibc floor of a built instar release empirically: install
# the .deb / .rpm on every distribution in the matrix CI and exercise
# the binary against /dev/kvm. This is the real acceptance gate for the
# build base (docs/plans/PLAN-distro-matrix-ci-phase-01-glibc-build.md
# step 1d) -- a nominal "build glibc <= target glibc" is necessary but
# not sufficient, so we prove the binary actually runs on each distro
# rather than trusting the version arithmetic.
#
# Usage: tools/verify-glibc-floor.sh <deb> <rpm>
#
# Example:
#   tools/verify-glibc-floor.sh \
#       src/target/debian/instar_*.deb \
#       src/target/generate-rpm/instar-*.rpm
#
# Requires:
#   - docker on the host
#   - /dev/kvm accessible to docker (passed through to each container)
#   - qemu-utils on the host (test-package-install.sh creates a fixture)
#
# Each distro is installed and run via tools/test-package-install.sh
# (the single source of truth for the install + info/create/map smoke),
# so this script is only the matrix driver: it maps each package format
# to the distros that consume it, runs them all (it does NOT stop at the
# first failure -- a full picture of which distros pass is the point),
# prints a summary, and exits non-zero if any distro failed.
#
# The distro lists can be overridden for a narrower local run, e.g.:
#   DEB_DISTROS="debian:12" RPM_DISTROS="rockylinux:9" \
#       tools/verify-glibc-floor.sh <deb> <rpm>

set -uo pipefail

if [ $# -ne 2 ]; then
    echo "Usage: $0 <deb> <rpm>" >&2
    exit 2
fi

DEB_PKG="$1"
RPM_PKG="$2"

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
SMOKE="$SCRIPT_DIR/test-package-install.sh"

if [ ! -x "$SMOKE" ]; then
    echo "Error: $SMOKE not found or not executable" >&2
    exit 1
fi
for pkg in "$DEB_PKG" "$RPM_PKG"; do
    if [ ! -f "$pkg" ]; then
        echo "Error: package not found: $pkg" >&2
        exit 1
    fi
done

# The matrix. glibc floors are noted for orientation; the run, not the
# number, is what decides. bullseye's build floor (GLIBC_2.30 in
# practice) must clear the lowest here (Rocky 9, 2.34).
#   .deb: Debian 12 (2.36), Debian 13 (2.41), Ubuntu 22.04 (2.35),
#         Ubuntu 24.04 (2.39)
#   .rpm: Fedora latest (2.39+), Rocky 9 (2.34), Rocky 10 (2.39)
DEB_DISTROS="${DEB_DISTROS:-debian:12 debian:13 ubuntu:22.04 ubuntu:24.04}"
RPM_DISTROS="${RPM_DISTROS:-fedora:latest rockylinux:9 rockylinux:10}"

PASSED=""
FAILED=""

run_one() {
    local pkg="$1"
    local distro="$2"
    echo ""
    echo "############################################################"
    echo "# $distro"
    echo "############################################################"
    if "$SMOKE" "$pkg" "$distro"; then
        PASSED="$PASSED $distro"
    else
        FAILED="$FAILED $distro"
    fi
}

for distro in $DEB_DISTROS; do
    run_one "$DEB_PKG" "$distro"
done
for distro in $RPM_DISTROS; do
    run_one "$RPM_PKG" "$distro"
done

echo ""
echo "============================================================"
echo "glibc-floor verification summary"
echo "============================================================"
for distro in $PASSED; do
    echo "  PASS  $distro"
done
for distro in $FAILED; do
    echo "  FAIL  $distro"
done

if [ -n "$FAILED" ]; then
    echo ""
    echo "FAIL: the built binary did not run on:$FAILED"
    echo "Do NOT switch to the rockylinux:9 build contingency without" >&2
    echo "management review -- investigate the specific failure first." >&2
    exit 1
fi

echo ""
echo "PASS: the built binary runs on every matrix distro."
