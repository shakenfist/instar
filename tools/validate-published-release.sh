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
    sudo dnf install -y qemu-img
    sudo dnf install -y "./${ASSET}"
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
