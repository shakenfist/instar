#!/bin/bash
# Capture the exact `qemu-img --version` string every matrix-CI distro
# ships in its stock package. This is the empirical input to
# docs/plans/PLAN-distro-matrix-ci-phase-02-qemu-profiles.md step 2a:
# instar's output profile is chosen from the detected qemu-img
# major.minor.patch, so we must know each distro's real version string
# (including distro suffixes and the epoch form) rather than assume it.
#
# Usage: tools/probe-qemu-versions.sh
#
# Requires:
#   - docker on the host (pulls the distro base images if not cached)
#
# For each distro it installs the qemu-img-providing package with the
# native package manager and prints one line:
#   <distro-image><TAB><raw qemu-img --version first line>
# so the output is a paste-ready table for the phase-2 bucketing.
#
# The distro lists mirror tools/verify-glibc-floor.sh and can be
# overridden for a narrower run, e.g.:
#   DEB_DISTROS="debian:12" RPM_DISTROS="rockylinux:9" \
#       tools/probe-qemu-versions.sh

set -uo pipefail

# apt ships qemu-img inside qemu-utils; dnf ships it as qemu-img.
# Rocky 10 is not published in the Docker Official `rockylinux` library
# (which stops at 9); use the maintained `rockylinux/rockylinux` org repo.
DEB_DISTROS="${DEB_DISTROS:-debian:12 debian:13 ubuntu:22.04 ubuntu:24.04}"
RPM_DISTROS="${RPM_DISTROS:-fedora:latest rockylinux:9 rockylinux/rockylinux:10}"

RESULTS=""
FAILED=""

probe_one() {
    local distro="$1"
    local install_cmd="$2"
    echo "### probing $distro ..." >&2
    local out
    if out=$(docker run --rm "$distro" bash -c "
            set -e
            $install_cmd >/dev/null 2>&1
            qemu-img --version | head -1
        " 2>/dev/null); then
        RESULTS="${RESULTS}${distro}"$'\t'"${out}"$'\n'
    else
        FAILED="$FAILED $distro"
        RESULTS="${RESULTS}${distro}"$'\t'"<probe failed>"$'\n'
    fi
}

for distro in $DEB_DISTROS; do
    probe_one "$distro" "apt-get update -qq && apt-get install -y -qq qemu-utils"
done
for distro in $RPM_DISTROS; do
    # EL renamed/split the qemu-img package across releases (qemu-img on
    # EL9, provided by qemu-kvm-tools on some EL10 spins). Install by the
    # binary it provides so the probe is package-name agnostic.
    probe_one "$distro" "dnf install -y -q qemu-img || dnf install -y -q /usr/bin/qemu-img"
done

echo ""
echo "============================================================"
echo "matrix distro qemu-img versions"
echo "============================================================"
printf '%s' "$RESULTS"

if [ -n "$FAILED" ]; then
    echo ""
    echo "WARNING: probe failed on:$FAILED" >&2
    exit 1
fi
