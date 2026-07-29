#!/bin/bash
# Smoke-test an instar Linux package by installing it in a fresh
# container and exercising the binary against /dev/kvm.
#
# Usage: tools/test-package-install.sh <package> <distro-image>
#
# Examples:
#   tools/test-package-install.sh src/target/debian/instar_*.deb debian:trixie
#   tools/test-package-install.sh src/target/generate-rpm/instar-*.rpm rockylinux:9
#
# Requires:
#   - docker on the host
#   - /dev/kvm accessible to docker (passed through to the container)
#   - qemu-utils on the host (for fixture creation)
#
# What this verifies:
#   - The package installs cleanly with the distro's native installer.
#   - The expected file layout lands on disk: /usr/bin/instar plus
#     core.bin and one .bin per src/operations/ entry under
#     /usr/lib/instar/. The roster is derived from src/operations/ so
#     a newly added operation whose binary is missing from the
#     packaging manifests fails this test automatically.
#   - instar starts up and responds to --help.
#   - instar can perform an info operation against KVM, which exercises
#     the guest binary resolver finding files at /usr/lib/instar/.
#   - instar can create a qcow2 and map it, exercising per-operation
#     guest binaries (create.bin, map.bin) beyond the original v0.2
#     roster, including a KVM write path.
#
# The test is intentionally minimal: format-correctness coverage lives
# in the existing functional test suite. This script exists to catch
# packaging regressions (asset paths, runtime dependencies, mode bits,
# resolver fallback logic).

set -euo pipefail

if [ $# -ne 2 ]; then
    echo "Usage: $0 <package> <distro-image>" >&2
    exit 2
fi

PKG_PATH="$1"
DISTRO_IMAGE="$2"

if [ ! -f "$PKG_PATH" ]; then
    echo "Error: package not found: $PKG_PATH" >&2
    exit 1
fi

PKG_PATH=$(realpath "$PKG_PATH")
PKG_DIR=$(dirname "$PKG_PATH")
PKG_FILE=$(basename "$PKG_PATH")

case "$PKG_FILE" in
    *.deb)
        # apt-get install <abs-path> requires the leading ./ or absolute
        # path to disambiguate from a package name lookup.
        INSTALL_CMD="apt-get update -qq && apt-get install -y -q /pkg/${PKG_FILE}"
        ;;
    *.rpm)
        # dnf install accepts an absolute path directly. -y to skip
        # confirmation, --setopt=install_weak_deps=False to avoid
        # pulling unnecessary recommends.
        INSTALL_CMD="dnf install -y --setopt=install_weak_deps=False /pkg/${PKG_FILE}"
        ;;
    *)
        echo "Error: unsupported package extension: $PKG_FILE" >&2
        exit 1
        ;;
esac

# Derive the expected guest-binary roster from src/operations/ so the
# check tracks the source tree: core.bin plus <op>.bin per operation.
REPO_ROOT=$(realpath "$(dirname "$0")/..")
if [ ! -d "$REPO_ROOT/src/operations" ]; then
    echo "Error: cannot derive operation roster: $REPO_ROOT/src/operations not found" >&2
    exit 1
fi
EXPECTED_BINS="core.bin"
for op in "$REPO_ROOT"/src/operations/*/; do
    EXPECTED_BINS="$EXPECTED_BINS $(basename "$op").bin"
done

# Generate a tiny qcow2 fixture on the host. 1 MiB is the smallest
# qemu-img will produce; instar info parses the header and reports
# the format, so this is sufficient for a smoke test.
WORKDIR=$(mktemp -d)
trap 'rm -rf "$WORKDIR"' EXIT
qemu-img create -q -f qcow2 "$WORKDIR/fixture.qcow2" 1M

echo "=== Smoke-testing $PKG_FILE on $DISTRO_IMAGE ==="

docker run --rm \
    --device /dev/kvm \
    -v "$PKG_DIR:/pkg:ro" \
    -v "$WORKDIR:/work:ro" \
    "$DISTRO_IMAGE" \
    bash -c "
        set -euo pipefail

        echo '--- Installing package ---'
        $INSTALL_CMD

        echo ''
        echo '--- Verifying file layout ---'
        MISSING=0
        for b in $EXPECTED_BINS; do
            f=\"/usr/lib/instar/\$b\"
            if [ ! -e \"\$f\" ]; then
                echo \"FAIL: missing \$f\"
                MISSING=1
            else
                echo \"OK: \$f\"
            fi
        done
        if [ ! -e /usr/bin/instar ]; then
            echo 'FAIL: missing /usr/bin/instar'
            MISSING=1
        else
            echo 'OK: /usr/bin/instar'
        fi
        if [ \"\$MISSING\" -ne 0 ]; then
            echo 'FAIL: packaged file layout is incomplete'
            exit 1
        fi
        test -x /usr/bin/instar

        echo ''
        echo '--- instar --help ---'
        instar --help >/dev/null

        echo ''
        echo '--- instar info /work/fixture.qcow2 ---'
        # Exercises the full resolver -> KVM path. The binary is at
        # /usr/bin/instar so current_exe().parent() is /usr/bin/, which
        # has no core.bin; the resolver must fall back to
        # /usr/lib/instar/ for this command to work.
        instar info /work/fixture.qcow2

        echo ''
        echo '--- instar create -f qcow2 /tmp/created.qcow2 1M ---'
        # A post-v0.2 subcommand with its own guest binary
        # (create.bin), exercising a KVM write path from the
        # installed package.
        instar create -f qcow2 /tmp/created.qcow2 1M

        echo ''
        echo '--- instar map /tmp/created.qcow2 ---'
        # A second post-v0.2 guest binary (map.bin), reading back the
        # image created above.
        instar map /tmp/created.qcow2
    "

echo ''
echo "PASS: $PKG_FILE installs and runs on $DISTRO_IMAGE"
