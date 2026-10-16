#!/usr/bin/env bash
#
# Verify a prepared instar-testdata checkout contains the fixtures the
# suite cannot do without, and that git-LFS materialised them.
#
# Two different failures hide behind a green run without this check.
#
# An un-materialised LFS object leaves a 131-byte pointer file where an
# image should be. That surfaces downstream as 200+ "file format:
# unknown" failures which read like an instar regression rather than an
# infrastructure problem, so it is worth naming here.
#
# A missing fixture is quieter and worse. Every consumer of the paths
# below resolves its fixture through a helper that calls skipTest when
# the path does not exist -- get_adversarial_image in tests/base.py,
# differencing_image and composed_golden in tests/test_differencing.py,
# and the explicit `if not image.path.exists()` in tests/test_security.py
# and in the VHD conversion tests in tests/test_convert.py.
# An absent or renamed fixture therefore deletes its proof from the suite
# and leaves CI green -- greener, in fact: stestr counts a skip towards
# its `Ran:` total, so even a run that is checked for having executed
# enough tests is satisfied by a wholly skipped selection. Presence is
# required here for exactly that reason: a checkout that is missing one
# of these must fail loudly at preparation time, not silently reduce the
# suite.
#
# usage: check-testdata-fixtures.sh TESTDATA_PATH [--annotate]
#        check-testdata-fixtures.sh --list
#
#   --annotate prefixes failures with ::error:: for GitHub Actions.
#   --list     prints the required fixtures, one per line, and exits.
#              tools/ci/test-check-testdata-fixtures.sh drives every
#              case off this rather than parsing the array out of this
#              file, so reformatting the array cannot quietly shrink
#              what the test covers.
#
# Exits 0 when every fixture is present and real, 1 otherwise.

set -uo pipefail

# The fixtures whose absence would silently shrink the suite. Each must
# have a matching entry in tests/manifest.json; tools/ci/test-check-
# testdata-fixtures.sh asserts that, so a typo here fails in the test
# rather than by breaking every CI job against a correct checkout. That
# test reads this list through --list, so the layout here is free to
# change.
REQUIRED_FIXTURES=(
    "custom/security/qcow2-backing-textfile.qcow2"
    "custom/raw/zeros-1mb.raw"
    "custom/audit/vhd-diff-locator-dotdot.vhd"
    # The two images behind the six heavy VHD conversion tests that no
    # longer gate a merge. Every one of them begins `if not
    # image.path.exists(): self.skipTest(...)`, and stestr counts a skip
    # in its `Ran:` total, so a checkout without these images gives a
    # green nightly that tested nothing -- and the nightly is now the
    # only place those six run across all seven distros.
    "downloaded/qemu-iotests/hyperv2012r2-dynamic.vhd"
    "downloaded/qemu-iotests/virtualpc-dynamic.vhd"
)

ANNOTATE=0
TESTDATA_PATH=""

while [ $# -gt 0 ]; do
    case "$1" in
        --list)
            printf '%s\n' "${REQUIRED_FIXTURES[@]}"
            exit 0
            ;;
        --annotate)
            ANNOTATE=1
            shift
            ;;
        -*)
            echo "unknown option: $1" >&2
            exit 1
            ;;
        *)
            if [ -n "${TESTDATA_PATH}" ]; then
                echo "unexpected extra argument: $1" >&2
                exit 1
            fi
            TESTDATA_PATH="$1"
            shift
            ;;
    esac
done

if [ -z "${TESTDATA_PATH}" ]; then
    echo "usage: $0 TESTDATA_PATH [--annotate] | $0 --list" >&2
    exit 1
fi

# err MESSAGE... -- one failure, as a single line, annotated when asked.
err() {
    if [ "${ANNOTATE}" -eq 1 ]; then
        echo "::error::$*" >&2
    else
        echo "error: $*" >&2
    fi
}

if [ ! -d "${TESTDATA_PATH}" ]; then
    err "testdata path does not exist or is not a directory: ${TESTDATA_PATH}"
    exit 1
fi

missing=()
pointers=()

for rel in "${REQUIRED_FIXTURES[@]}"; do
    path="${TESTDATA_PATH}/${rel}"
    if [ ! -f "${path}" ]; then
        missing+=("${rel}")
        continue
    fi
    # A git-LFS pointer begins with the literal "version
    # https://git-lfs.github.com/spec/v1" line, so 64 bytes is enough
    # to recognise one without reading an image.
    if head -c 64 "${path}" | grep -q 'git-lfs.github.com/spec'; then
        pointers+=("${rel}")
    fi
done

if [ "${#pointers[@]}" -ne 0 ]; then
    err "testdata LFS not materialised: ${pointers[*]} -- still git-LFS" \
        "pointer file(s). This is an infrastructure problem (git-lfs" \
        "pull did not fetch objects), NOT a test or instar regression. Fix" \
        "LFS auth/availability on the runner and re-run; do not modify" \
        "instar code to match this output."
fi

if [ "${#missing[@]}" -ne 0 ]; then
    err "testdata checkout is missing required fixture(s): ${missing[*]}." \
        "Every test that uses these skips rather than fails when the file" \
        "is absent, so continuing would run a quietly smaller suite. Check" \
        "the clone completed, and that the fixture was not renamed in" \
        "instar-testdata without updating REQUIRED_FIXTURES in $0 and" \
        "tests/manifest.json."
fi

if [ "${#pointers[@]}" -ne 0 ] || [ "${#missing[@]}" -ne 0 ]; then
    exit 1
fi

echo "testdata fixtures verified: ${#REQUIRED_FIXTURES[@]} present and materialised"
