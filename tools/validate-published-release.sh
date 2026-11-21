#!/bin/bash
# Validate a PUBLISHED instar release artifact on a real KVM-capable
# host. This is the manual, on-a-real-VM counterpart to the
# container-based tools/verify-glibc-floor.sh: run it on a clean
# Debian/Ubuntu VM (for the .deb) and a clean Fedora/Rocky VM (for the
# .rpm), each with /dev/kvm, to confirm the artifact GitHub Releases
# actually shipped installs and runs end to end.
#
# It downloads the release asset, installs it with the distro's native
# package manager, and exercises the resolver -> KVM path plus a
# post-v0.2 subcommand with its own guest binary.
#
# Usage:
#   tools/validate-published-release.sh <deb|rpm> [version]
#
# Examples (run ON the target VM):
#   ./validate-published-release.sh deb 0.3.0
#   ./validate-published-release.sh rpm 0.3.0
#
# Run from a clone if you can. On rpm systems the script installs
# through tools/ci/dnf.sh, which retries a distro mirror that is part
# way through rotating its metadata. A copy of this file on its own
# still works, but calls dnf directly and says so, and then a mirror
# mid-rotation reads as a failed install: rerun before you blame the
# artifact.
#
# Requires on the VM: /dev/kvm accessible to your user (kvm group),
# curl, sudo, and qemu-utils (for the fixture; installed if missing on
# apt/dnf systems).
#
# Expected result on every VM: each step prints output and the script
# ends with "PASS". Concretely you should see:
#   - the package installs with no unmet-dependency errors,
#   - /usr/bin/instar and /usr/lib/instar/*.bin present,
#   - `instar --help` prints usage,
#   - `instar info` reports "file format: qcow2" for the fixture,
#   - `instar create` prints "Created: ...",
#   - `instar map` prints an offset/length table header.
#
# Record the outputs against #474 and close it once both a .deb and an
# .rpm VM pass.

set -euo pipefail

PKG_TYPE="${1:-}"
REL_VERSION="${2:-0.3.0}"

case "$PKG_TYPE" in
    deb|rpm) ;;
    *)
        echo "Usage: $0 <deb|rpm> [version]" >&2
        exit 2
        ;;
esac

BASE_URL="https://github.com/shakenfist/instar/releases/download/v${REL_VERSION}"
# Resolved, symlinks and all, so that the clone check further down
# compares names rather than stat'ing anything at a path it has not yet
# decided to trust.
SCRIPT_DIR=$(dirname "$(realpath "$0")")
REPO_ROOT=$(realpath "${SCRIPT_DIR}/..")

if [ ! -e /dev/kvm ]; then
    echo "Error: /dev/kvm not present -- instar needs KVM to run." >&2
    exit 1
fi

WORKDIR=$(mktemp -d)
trap 'rm -rf "$WORKDIR"' EXIT
cd "$WORKDIR"

echo "=== Validating published instar ${REL_VERSION} (${PKG_TYPE}) on $(. /etc/os-release 2>/dev/null; echo "${PRETTY_NAME:-this host}") ==="

echo ""
echo "--- Downloading and installing the package ---"
if [ "$PKG_TYPE" = "deb" ]; then
    ASSET="instar_${REL_VERSION}-1_amd64.deb"
    curl -fsSL -o "$ASSET" "${BASE_URL}/${ASSET}"
    sudo apt-get update -qq
    # qemu-utils provides qemu-img for the fixture; instar has no build
    # dependency on it.
    sudo apt-get install -y -q qemu-utils
    sudo apt-get install -y -q "./${ASSET}"
else
    ASSET="instar-${REL_VERSION}-1.x86_64.rpm"
    curl -fsSL -o "$ASSET" "${BASE_URL}/${ASSET}"
    # Through the dnf wrapper: a mirror serving metadata that names
    # repodata it has already rotated away would otherwise read as a
    # broken release artifact, which is the one thing this script is
    # meant to be able to tell you. The wrapper is only there when
    # this runs from a clone (see the header), so without it this
    # falls back to plain dnf rather than failing the rpm path.
    #
    # "From a clone" is checked as this file's own resolved directory
    # being the enclosing tree's tools/, not as something existing at
    # tools/ci/dnf.sh: a lone copy run from /tmp/foo/ resolves REPO_ROOT
    # to /tmp, and /tmp/tools/ci/dnf.sh is a path any other local user
    # can create -- which this would then run with sudo already primed.
    # Both sides are strings derived from realpath, so nothing a local
    # user plants can make them agree: comparing inodes instead (-ef)
    # follows a symlink planted at /tmp/tools/validate-published-release.sh
    # back to this file, and passes.
    DNF_WRAPPER="${REPO_ROOT}/tools/ci/dnf.sh"
    if [ "${SCRIPT_DIR}" = "${REPO_ROOT}/tools" ] && [ -f "$DNF_WRAPPER" ]; then
        dnf_install() { DNF='sudo dnf' bash "$DNF_WRAPPER" install -y "$@"; }
    else
        echo "note: $0 is not a clone's own copy with $DNF_WRAPPER" \
            "beside it, so calling dnf directly." >&2
        echo "      A mirror mid-rotation will fail the install below;" \
            "rerun before blaming the artifact." >&2
        dnf_install() { sudo dnf install -y "$@"; }  # direct dnf: no wrapper beside a lone copy
    fi
    dnf_install qemu-img
    dnf_install "./${ASSET}"
fi

echo ""
echo "--- Verifying file layout ---"
test -x /usr/bin/instar && echo "OK: /usr/bin/instar"
ls /usr/lib/instar/*.bin >/dev/null && echo "OK: /usr/lib/instar/*.bin present"

echo ""
echo "--- instar --help ---"
instar --help >/dev/null && echo "OK: --help"

echo ""
echo "--- instar info (resolver -> KVM path) ---"
qemu-img create -q -f qcow2 fixture.qcow2 1M
instar info fixture.qcow2

echo ""
echo "--- instar create (post-v0.2 guest binary, KVM write path) ---"
instar create -f qcow2 created.qcow2 1M

echo ""
echo "--- instar map (second post-v0.2 guest binary) ---"
instar map created.qcow2

echo ""
echo "PASS: published ${PKG_TYPE} ${REL_VERSION} installs and runs on this host."
echo "Record this output against issue #474."
