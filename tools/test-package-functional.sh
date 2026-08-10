#!/bin/bash
# Run instar's full Python integration suite against an installed
# package, inside a distribution container, using that distro's own
# qemu-img as the differential oracle.
#
# Usage:
#   tools/test-package-functional.sh [options] <package> <distro-image>
#
# Options:
#   --smoke            Run only a fast KVM-exercising subset (version
#                      detection, safe info, create, map) instead of the
#                      full suite. For quick local one-distro checks.
#   --select REGEX     Run only tests matching REGEX (a stestr selection
#                      regex). Use it to replay a specific failure on one
#                      distro without paying for the whole suite --
#                      classifying a failure as a real divergence needs an
#                      uncontended re-run, and this is how you get one.
#                      Mutually exclusive with --smoke.
#   --concurrency N    stestr worker count (default 4). Lower it when
#                      several matrix containers share one KVM host.
#   -h, --help         Show this help.
#
# Examples:
#   tools/test-package-functional.sh \
#       src/target/debian/instar_*.deb debian:12
#   tools/test-package-functional.sh --smoke \
#       src/target/generate-rpm/instar-*.rpm rockylinux:9
#   tools/test-package-functional.sh --select 'test_convert\.' \
#       src/target/debian/instar_*.deb debian:13
#
# Environment:
#   TESTDATA_PATH   instar-testdata working tree to mount read-only at
#                   /testdata (default: <repo>/../instar-testdata). It
#                   MUST already be git-LFS materialised -- in CI run
#                   tools/ci/prepare-testdata.sh first. A container that
#                   mounts LFS pointer files gives a mass "file format:
#                   unknown" failure that looks like an instar regression
#                   but is a testdata problem; this script canary-checks
#                   for that and refuses to run.
#
# Requires:
#   - docker on the host
#   - /dev/kvm accessible to docker (passed through to the container)
#
# How it works (the tests-from-tree / binary-from-package split):
#   The suite is driven by stestr (tests/.stestr.conf), not pytest. The
#   whole tests/ tree is copied into the container and run there; the
#   binary under test is the INSTALLED package at /usr/bin/instar, via
#   the harness's INSTAR_BINARY_PATH override (tests/base.py). So this
#   exercises the packaged binary and its packaged guest binaries under
#   /usr/lib/instar/ against the real tests. The container runs as root
#   (package + prerequisite install need it) and the repo is mounted
#   read-only, so no root-owned .stestr/ artefacts leak into the host
#   worktree.
#
# This is the per-matrix-entry functional runner. It is separate from
# tools/test-package-install.sh, which stays the fast packaging smoke
# check (file layout, --help, info/create/map).

set -euo pipefail

SMOKE=0
SELECT=''
CONCURRENCY=4

usage() {
    sed -n '2,58p' "$0" | sed 's/^# \{0,1\}//'
}

POSITIONAL=()
while [ $# -gt 0 ]; do
    case "$1" in
        --smoke)
            SMOKE=1
            shift
            ;;
        --select)
            SELECT="${2:-}"
            if [ -z "$SELECT" ]; then
                echo "Error: --select needs a regex" >&2
                exit 2
            fi
            shift 2
            ;;
        --concurrency)
            CONCURRENCY="${2:-}"
            if ! [[ "$CONCURRENCY" =~ ^[1-9][0-9]*$ ]]; then
                echo "Error: --concurrency needs a positive integer" >&2
                exit 2
            fi
            shift 2
            ;;
        -h | --help)
            usage
            exit 0
            ;;
        --)
            shift
            while [ $# -gt 0 ]; do
                POSITIONAL+=("$1")
                shift
            done
            ;;
        -*)
            echo "Error: unknown option: $1" >&2
            exit 2
            ;;
        *)
            POSITIONAL+=("$1")
            shift
            ;;
    esac
done

if [ "${#POSITIONAL[@]}" -ne 2 ]; then
    echo "Usage: $0 [--smoke] [--concurrency N] <package> <distro-image>" >&2
    exit 2
fi

PKG_PATH="${POSITIONAL[0]}"
DISTRO_IMAGE="${POSITIONAL[1]}"

if [ ! -f "$PKG_PATH" ]; then
    echo "Error: package not found: $PKG_PATH" >&2
    exit 1
fi

PKG_PATH=$(realpath "$PKG_PATH")
PKG_DIR=$(dirname "$PKG_PATH")
PKG_FILE=$(basename "$PKG_PATH")

case "$PKG_FILE" in
    *.deb) PKG_KIND=deb ;;
    *.rpm) PKG_KIND=rpm ;;
    *)
        echo "Error: unsupported package extension: $PKG_FILE" >&2
        exit 1
        ;;
esac

REPO_ROOT=$(realpath "$(dirname "$0")/..")
if [ ! -d "$REPO_ROOT/tests" ]; then
    echo "Error: tests/ tree not found under $REPO_ROOT" >&2
    exit 1
fi

TESTDATA_PATH="${TESTDATA_PATH:-$REPO_ROOT/../instar-testdata}"
if [ ! -d "$TESTDATA_PATH" ]; then
    echo "Error: testdata not found at $TESTDATA_PATH" >&2
    echo "Set TESTDATA_PATH or ensure instar-testdata is a sibling directory." >&2
    echo "In CI, run tools/ci/prepare-testdata.sh first." >&2
    exit 1
fi
TESTDATA_PATH=$(realpath "$TESTDATA_PATH")

# Canary: refuse to run against un-materialised git-LFS pointer files.
# A pointer begins with the literal "version https://git-lfs...". This
# turns a silent LFS miss into a clear infrastructure error here rather
# than 200+ "file format: unknown" failures inside the container.
canary_ok=0
for rel in "custom/security/qcow2-backing-textfile.qcow2" "custom/raw/zeros-1mb.raw"; do
    path="$TESTDATA_PATH/$rel"
    [ -f "$path" ] || continue
    canary_ok=1
    if head -c 64 "$path" | grep -q 'git-lfs.github.com/spec'; then
        echo "Error: testdata LFS not materialised: $rel is still a git-LFS" >&2
        echo "pointer file. This is an infrastructure problem (run" >&2
        echo "tools/ci/prepare-testdata.sh), NOT an instar regression." >&2
        exit 1
    fi
done
if [ "$canary_ok" -eq 0 ]; then
    echo "Error: no testdata canary fixture found under $TESTDATA_PATH;" >&2
    echo "the checkout looks incomplete." >&2
    exit 1
fi

# Test selection. The malicious-image tests are never run in the matrix;
# test_bench is a large (80+) benchmark set with no differential-oracle
# value here, so it is excluded from the default full run too.
EXCLUDE_RE='(test_info_malicious|test_bench)'
SELECT_RE=''
if [ "$SMOKE" -eq 1 ] && [ -n "$SELECT" ]; then
    echo "Error: --smoke and --select are mutually exclusive" >&2
    exit 2
fi
if [ "$SMOKE" -eq 1 ]; then
    # Anchor each module name with a trailing '\.' so the selector cannot
    # leak into unrelated modules by substring (e.g. bare "test_create"
    # would also match test_snapshot's test_create_list_agreement).
    SELECT_RE='(test_version_detection\.|test_info_safe\.|test_create\.|test_map\.)'
elif [ -n "$SELECT" ]; then
    SELECT_RE="$SELECT"
fi

echo "=== Functional-testing $PKG_FILE on $DISTRO_IMAGE ==="
if [ "$SMOKE" -eq 1 ]; then
    echo "    mode: smoke subset, concurrency $CONCURRENCY"
elif [ -n "$SELECT" ]; then
    echo "    mode: selection '$SELECT', concurrency $CONCURRENCY"
else
    echo "    mode: full suite, concurrency $CONCURRENCY"
fi
echo "    testdata: $TESTDATA_PATH (read-only)"

# The in-container script. Values that contain regex metacharacters are
# passed via the environment (-e) to avoid a second layer of quoting.
# Intentionally single-quoted: these variables are expanded inside the
# container from the -e environment, not by the host shell.
# shellcheck disable=SC2016
INNER='
set -euo pipefail

echo "--- Installing package and test prerequisites ---"
if [ "$PKG_KIND" = deb ]; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq
    apt-get install -y -q "/pkg/$PKG_FILE"
    # Every .deb matrix distro ships python3 >= 3.10 by default.
    # qemu-storage-daemon is the oracle for the bitmap differential
    # tests; Debian 12 (bookworm) ships it in qemu-system-common, while
    # Debian 13 (trixie) moved it into qemu-utils. Installing both covers
    # every .deb distro (the extra package is harmless where redundant).
    apt-get install -y -q python3 python3-venv python3-pip \
        qemu-utils qemu-system-common
else
    dnf install -y --setopt=install_weak_deps=False "/pkg/$PKG_FILE"
    # The test deps (testtools >= 2.9.1) require Python >= 3.10, but some
    # EL streams (Rocky/RHEL 9) default python3 to 3.9. Install a newer
    # interpreter explicitly; the interpreter is selected below.
    dnf install -y python3.12 python3.12-pip || dnf install -y python3.11 python3.11-pip || true
    dnf install -y python3 python3-pip || true
    # The package that *provides* qemu-img differs across EL streams.
    dnf install -y qemu-img || dnf install -y /usr/bin/qemu-img
    # qemu-storage-daemon is the oracle for the bitmap differential
    # tests. Fedora ships it as its own package; some EL streams do not
    # package it at all, so this is best-effort -- the tests skip
    # cleanly when it is missing rather than erroring.
    dnf install -y qemu-storage-daemon || \
        dnf install -y /usr/bin/qemu-storage-daemon || \
        echo "note: qemu-storage-daemon unavailable; bitmap oracle tests will skip"
fi

# Pick a Python >= 3.10 for the test venv (testtools requirement).
PYBIN=""
for cand in python3.13 python3.12 python3.11 python3.10 python3; do
    command -v "$cand" >/dev/null 2>&1 || continue
    if "$cand" -c "import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)"; then
        PYBIN="$cand"
        break
    fi
done
if [ -z "$PYBIN" ]; then
    echo "Error: no Python >= 3.10 available for the test venv" >&2
    exit 1
fi

echo ""
echo "--- Versions under test ---"
echo "instar:   $(command -v instar) (package $PKG_FILE)"
echo "python:   $("$PYBIN" --version) ($PYBIN)"
qemu-img --version | head -n1

echo ""
echo "--- Preparing test tree ---"
# Copy the read-only mounted tests/ tree to a writable location so
# stestr can create its .stestr/ results dir without touching the host
# worktree.
cp -a /workspace/tests /tmp/instar-tests
cd /tmp/instar-tests
"$PYBIN" -m venv /tmp/test-venv
/tmp/test-venv/bin/pip install -q --upgrade pip
/tmp/test-venv/bin/pip install -q -r requirements.txt

echo ""
echo "--- Running suite ---"
STESTR_ARGS=(run --concurrency "$CONCURRENCY")
if [ -n "$EXCLUDE_RE" ]; then
    STESTR_ARGS+=(--exclude-regex "$EXCLUDE_RE")
fi
if [ -n "$SELECT_RE" ]; then
    STESTR_ARGS+=("$SELECT_RE")
fi
set +e
/tmp/test-venv/bin/stestr "${STESTR_ARGS[@]}" 2>&1 | tee /tmp/stestr-output.txt
STESTR_RC=${PIPESTATUS[0]}
set -e

# Truncation guard. A stestr worker that dies mid-stream (the subunit v2
# packet-size limit is one real way: a test attaching more than ~4MB of
# captured output raises "ValueError: Length too long") silently drops
# every remaining test in that worker. stestr then reports a totals block
# for the tests it did see and exits 0 if none of them failed -- a
# partial run that looks green. Never let that pass as a result.
if grep -q "Length too long" /tmp/stestr-output.txt; then
    echo "" >&2
    echo "Error: a stestr worker died on the subunit packet-size limit" >&2
    echo "(a test attached >4MB of captured output). The run is PARTIAL:" >&2
    echo "the tests remaining in that worker never executed." >&2
    exit 1
fi
if grep -qE "^ - Worker [0-9]+ \([0-9]+ tests\) => N/A" /tmp/stestr-output.txt; then
    echo "" >&2
    echo "Error: stestr reported a worker with no elapsed time (N/A)," >&2
    echo "which means that worker crashed rather than finishing. The run" >&2
    echo "is PARTIAL and its result is not trustworthy." >&2
    exit 1
fi
if [ -z "$SELECT_RE" ]; then
    # Full-suite floor. The suite is ~3250 tests; anything dramatically
    # short means the run was cut off before stestr noticed.
    RAN=$(sed -n "s/^Ran: \([0-9]*\) tests.*/\1/p" /tmp/stestr-output.txt | tail -n1)
    if [ -n "$RAN" ] && [ "$RAN" -lt 2500 ]; then
        echo "" >&2
        echo "Error: full run executed only $RAN tests (expected ~3250)." >&2
        echo "The run was truncated; treat it as a failure, not a pass." >&2
        exit 1
    fi
fi
exit "$STESTR_RC"
'

set +e
docker run --rm \
    --device /dev/kvm \
    -v "$REPO_ROOT:/workspace:ro" \
    -v "$TESTDATA_PATH:/testdata:ro" \
    -v "$PKG_DIR:/pkg:ro" \
    -e INSTAR_TESTDATA_PATH=/testdata \
    -e INSTAR_BINARY_PATH=/usr/bin/instar \
    -e PKG_KIND="$PKG_KIND" \
    -e PKG_FILE="$PKG_FILE" \
    -e EXCLUDE_RE="$EXCLUDE_RE" \
    -e SELECT_RE="$SELECT_RE" \
    -e CONCURRENCY="$CONCURRENCY" \
    "$DISTRO_IMAGE" \
    bash -c "$INNER"
RC=$?
set -e

echo ""
if [ "$RC" -eq 0 ]; then
    echo "PASS: $PKG_FILE functional suite on $DISTRO_IMAGE"
else
    echo "FAIL: $PKG_FILE functional suite on $DISTRO_IMAGE (exit $RC)"
fi
exit "$RC"
