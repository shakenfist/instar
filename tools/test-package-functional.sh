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
#   STESTR_TIMING_OUT
#                   when set, a host path to write this run's derived
#                   per-test durations to, in the format
#                   tools/ci/generate-stestr-timing.py produces. Setting
#                   it declares the run a MEASUREMENT: the committed
#                   timing file is not seeded into the repository first,
#                   so the durations come only from this run. Seeding and
#                   measuring at once would be self-referential -- every
#                   test that did not execute would keep the duration it
#                   was seeded with, so a deleted test's figure would
#                   live on forever and a test that silently stopped
#                   running would never lose its old one. The cost is a
#                   worse-packed run, which is why only the nightly
#                   measurement leg sets this and never a gating one.
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
#   Before "stestr run", tools/ci/seed-stestr-timing.sh loads
#   tests/stestr-timing.txt (a committed, machine-derived list of
#   per-test durations) into the fresh .stestr repository, so
#   the scheduler bin-packs workers by measured duration instead of
#   distributing every test round-robin. Without it, one matrix leg put
#   1424s of VirtualPC conversion tests on a single worker out of 5967s
#   total execute time, so that worker ran 2197s wall while the
#   lightest ran 913s. See tools/ci/seed-stestr-timing.sh for why.
#
# This is the per-matrix-entry functional runner. It is separate from
# tools/test-package-install.sh, which stays the fast packaging smoke
# check (file layout, --help, info/create/map).

set -euo pipefail

SMOKE=0
SELECT=''
CONCURRENCY=4

usage() {
    # Self-delimiting: print the header comment block from line 2 up to
    # the first line that is not a comment. A hard-coded end line goes
    # quietly wrong -- truncating or over-running --help -- the next
    # time anyone edits this (deliberately extensive) header.
    awk 'NR > 1 { if (!/^#/) exit; sub(/^# ?/, ""); print }' "$0"
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

# Refuse to run against an incomplete or un-materialised testdata
# checkout. The same check runs in tools/ci/prepare-testdata.sh; it
# lives in one script so the two cannot disagree about which fixtures
# matter, and it fails on an absent fixture as well as on a git-LFS
# pointer, because the tests that read these skip rather than fail when
# the file is missing.
"$REPO_ROOT/tools/ci/check-testdata-fixtures.sh" "$TESTDATA_PATH"

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
if [ -n "${TIMING_OUT:-}" ]; then
    echo "--- NOT seeding stestr timing data: this run measures it ---"
    # A measurement must not inherit the numbers it is measuring. stestr
    # keeps one duration per test id in its repository and only the tests
    # that execute update theirs, so a seeded repository hands back the
    # seeded figure for every test that did not run -- including tests
    # that no longer exist. Starting empty costs this run a worse
    # partition and gives the derived file only what was measured here.
    echo "(the partition will be blind, which is the price of measuring)"
else
    echo "--- Seeding stestr timing data ---"
    # See tools/ci/seed-stestr-timing.sh for why: a repository created
    # fresh in every container has no durations to bin-pack from, which
    # is what puts several minutes of VHD conversion tests on one worker
    # while the others idle. The timing file travels with the tests/ tree
    # (copied above), and a missing one is not an error -- the scheduler
    # just partitions blind, as it always has.
    /workspace/tools/ci/seed-stestr-timing.sh /tmp/test-venv/bin/stestr stestr-timing.txt
fi

echo ""
echo "--- Counting the selection ---"
# A lower bound on how many tests this run must execute, discovered
# rather than written down, for the length floor further down.
#
# It is a lower bound and not the real total, which matters if you are
# tempted to tighten the comparison. "stestr list" enumerates only
# statically discoverable ids; tests that build their cases at load time
# appear as one id here and as many at run time. Measured on this tree:
# listing the suite minus test_info_malicious gives 2378 ids, and running
# that same selection reports 3675, with no parenthesised scenario id in
# the listing at all. So "ran fewer than listed" always means something
# went wrong, while "ran at least as many as listed" does not prove the
# run was complete. Deriving even that bound beats the figure this
# replaced, which was a hand-written ~3250 that drifts every time a test
# is added.
LIST_ARGS=(list)
if [ -n "$EXCLUDE_RE" ]; then
    LIST_ARGS+=(--exclude-regex "$EXCLUDE_RE")
fi
if [ -n "$SELECT_RE" ]; then
    LIST_ARGS+=("$SELECT_RE")
fi
set +e
/tmp/test-venv/bin/stestr "${LIST_ARGS[@]}" > /tmp/stestr-list.txt 2>/tmp/stestr-list-err.txt
LIST_RC=$?
set -e
if [ "$LIST_RC" -ne 0 ]; then
    echo "" >&2
    echo "Error: could not list the tests for this selection; stestr list" >&2
    echo "exited $LIST_RC. Without a count there is nothing to check the" >&2
    echo "run length against, so this is a failure rather than a run with" >&2
    echo "one guard switched off." >&2
    sed -n "1,20p" /tmp/stestr-list-err.txt >&2
    exit 1
fi
EXPECTED=$(grep -c . /tmp/stestr-list.txt)
if [ "$EXPECTED" -eq 0 ]; then
    echo "" >&2
    echo "Error: the selection matched no tests at all. A selector that" >&2
    echo "matches nothing exits zero with everything passing, which is" >&2
    echo "indistinguishable from a green run." >&2
    exit 1
fi
echo "selection contains $EXPECTED tests"

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
# Length floor, against the count discovered above rather than a
# constant, so it covers every selection instead of only an unselected
# full run. The previous form was keyed on SELECT_RE being empty, which
# meant any selected run -- including the merge-queue gate once that
# started passing a selector -- skipped this check entirely, and a
# truncated gate run reads as green.
RAN=$(sed -n "s/^Ran: \([0-9]*\) tests.*/\1/p" /tmp/stestr-output.txt | tail -n1)
if [ -z "$RAN" ]; then
    echo "" >&2
    echo "Error: stestr printed no \"Ran: N tests\" total, so the run" >&2
    echo "length cannot be checked. Treat it as a failure." >&2
    exit 1
fi
if [ "$RAN" -lt "$EXPECTED" ]; then
    echo "" >&2
    echo "Error: run executed $RAN tests, fewer than the $EXPECTED ids" >&2
    echo "discovery found for this selection. Since load-time cases make" >&2
    echo "a real run longer than the listing, not shorter, the run was" >&2
    echo "truncated; treat it as a failure, not a pass." >&2
    exit 1
fi

# Skip floor, the complement of the length floor above. A skipped test
# reports a result, so it counts towards "Ran", which means a selection
# in which every test skipped satisfies the floor exactly as a
# selection in which every test executed. That is not hypothetical
# here: every test in the nightly selection calls skipTest when its VHD
# fixture is missing, so one absent file would give a green leg that
# tested nothing. The length floor cannot see it, because the count is
# right.
#
# The rule is "nothing executed at all" and not "fewer than some
# fraction executed", and the reason is that there is no legitimate
# skip rate to compare against. Skips are a property of the distro, not
# of the change: the EL streams that cannot install qemu-storage-daemon
# skip the whole bitmap oracle set, every distro skips whichever
# fixtures its qemu cannot produce, and the full suite legitimately
# skips hundreds. Any fraction tight enough to catch a real loss on
# Debian would fail Rocky on a good night. Zero executed tests needs no
# tuning, is never legitimate, and is the shape every realistic cause
# of a silently-empty run takes.
#
# One deliberate consequence: a hand-run --select whose every case
# skips on this distro now fails rather than passing. That run did not
# test anything either, and saying so is the point.
SKIPPED=$(sed -n "s/^ *- Skipped: \([0-9]*\).*/\1/p" /tmp/stestr-output.txt | tail -n1)
SKIPPED=${SKIPPED:-0}
EXECUTED=$((RAN - SKIPPED))
if [ "$EXECUTED" -le 0 ]; then
    echo "" >&2
    echo "Error: all $RAN tests in this selection skipped; nothing was" >&2
    echo "actually executed. A skip counts towards the \"Ran\" total" >&2
    echo "that stestr prints, so this run passes the length floor above" >&2
    echo "while testing nothing at all. The usual cause is missing test" >&2
    echo "fixtures, so check the testdata preparation rather than the" >&2
    echo "tests." >&2
    exit 1
fi
echo "$EXECUTED of $RAN tests executed, $SKIPPED skipped"

# Derive the timing data, if this run was asked to measure. Deliberately
# after the truncation guards and before the verdict: a truncated run
# holds durations for only the tests its surviving workers reached, and
# publishing those would quietly teach the scheduler that half the suite
# takes no time at all. A run that completed and merely FAILED tests is
# still a valid measurement, so this does not depend on STESTR_RC.
if [ -n "${TIMING_OUT:-}" ]; then
    echo ""
    echo "--- Deriving stestr timing data ---"
    if "$PYBIN" /workspace/tools/ci/generate-stestr-timing.py .stestr "$TIMING_OUT"; then
        # The container runs as root; hand the file back to the user who
        # invoked docker so the job can diff and commit it.
        chown "$TIMING_UID:$TIMING_GID" "$TIMING_OUT" || true
    else
        # A measurement that cannot be derived must not change the
        # verdict of the suite: the leg still tested this distro.
        echo "warning: could not derive timing data from this run" >&2
    fi
fi
exit "$STESTR_RC"
'

# Measurement mode. The repository is mounted read-only on purpose -- so
# a container running as root cannot leave root-owned stestr artefacts in
# the host worktree -- which means a run asked to publish its measured
# durations needs a second, writable mount for that one file. Only the
# derived text crosses the boundary, not stestr's repository directory:
# the derivation runs in the container, where the repository and the
# interpreter that reads it already are.
TIMING_ARGS=()
if [ -n "${STESTR_TIMING_OUT:-}" ]; then
    TIMING_DIR=$(dirname "$STESTR_TIMING_OUT")
    mkdir -p "$TIMING_DIR"
    TIMING_DIR=$(realpath "$TIMING_DIR")
    TIMING_ARGS=(
        -v "$TIMING_DIR:/timing-out"
        -e TIMING_OUT="/timing-out/$(basename "$STESTR_TIMING_OUT")"
        -e TIMING_UID="$(id -u)"
        -e TIMING_GID="$(id -g)"
    )
    echo "    measuring: per-test durations will be written to $STESTR_TIMING_OUT"
fi

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
    "${TIMING_ARGS[@]+"${TIMING_ARGS[@]}"}" \
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
