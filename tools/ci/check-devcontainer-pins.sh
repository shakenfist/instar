#!/bin/bash
# Assert the two devcontainer Dockerfiles agree on every pin they share:
# the Rust nightly, and the versions of the cargo tools both install.
#
# The dev/test image and the release build image must use the same
# toolchain: the release image compiles the shipped binary and the
# guest cross-builds, while the dev image compiles what the tests run
# against. A drift means one was hand-edited, and the symptom is subtle
# -- guest binaries built by a different nightly than the packages,
# with no error anywhere.
#
# bump-rust-nightly.sh already refuses to run on drift, but it only runs
# weekly, so a hand-edit could sit undetected for up to a week. This
# script is the same check, cheap enough to run from pre-commit and from
# build-and-test on every pull request. bump-rust-nightly.sh calls it
# rather than duplicating the comparison.
#
# The cargo tool pins matter for the same reason. Renovate bumps a crate
# across both files in a single PR, so drift means someone edited one
# file by hand -- and the release image would then package with a
# different cargo-deb / cargo-generate-rpm than the one the dev image's
# tests exercised.
#
# Usage: tools/ci/check-devcontainer-pins.sh
# Exits 0 when the pins agree, 1 otherwise.

set -euo pipefail

REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
cd "$REPO_ROOT"

DOCKERFILE="src/.devcontainer/Dockerfile"
BUILD_DOCKERFILE="src/.devcontainer/build/Dockerfile"

read_pin() {
    sed -nE 's/^ARG RUST_NIGHTLY=(nightly-[0-9]{4}-[0-9]{2}-[0-9]{2})$/\1/p' "$1"
}

fail=0
for f in "$DOCKERFILE" "$BUILD_DOCKERFILE"; do
    if [ ! -f "$f" ]; then
        echo "ERROR: $f not found" >&2
        fail=1
    fi
done
[ "$fail" -eq 0 ] || exit 1

DEV_PIN="$(read_pin "$DOCKERFILE")"
BUILD_PIN="$(read_pin "$BUILD_DOCKERFILE")"

for pair in "$DOCKERFILE:$DEV_PIN" "$BUILD_DOCKERFILE:$BUILD_PIN"; do
    f="${pair%%:*}"
    p="${pair#*:}"
    if [ -z "$p" ]; then
        echo "ERROR: no 'ARG RUST_NIGHTLY=nightly-YYYY-MM-DD' pin found in $f" >&2
        exit 1
    fi
done

if [ "$DEV_PIN" != "$BUILD_PIN" ]; then
    echo "ERROR: Rust nightly pin drift between the devcontainer images:" >&2
    echo "  $DOCKERFILE       = $DEV_PIN" >&2
    echo "  $BUILD_DOCKERFILE = $BUILD_PIN" >&2
    echo "" >&2
    echo "Both must pin the same nightly. Do not fix this by hand-editing" >&2
    echo "one file -- run tools/ci/bump-rust-nightly.sh, which bumps and" >&2
    echo "validates both together." >&2
    exit 1
fi

echo "Rust nightly pins agree: $DEV_PIN"

# The cargo tools both images install. The dev image installs cargo-fuzz
# and cargo-audit as well; those are deliberately absent here because the
# release image does not have them to compare against.
SHARED_TOOLS=(CARGO_BINUTILS_VERSION CARGO_DEB_VERSION CARGO_GENERATE_RPM_VERSION)

read_tool_pin() {
    # $1 = Dockerfile, $2 = ARG name
    sed -nE "s/^ARG $2=([^[:space:]]+)\$/\\1/p" "$1"
}

drift=0
for arg in "${SHARED_TOOLS[@]}"; do
    dev="$(read_tool_pin "$DOCKERFILE" "$arg")"
    build="$(read_tool_pin "$BUILD_DOCKERFILE" "$arg")"

    for pair in "$DOCKERFILE:$dev" "$BUILD_DOCKERFILE:$build"; do
        if [ -z "${pair#*:}" ]; then
            echo "ERROR: no 'ARG $arg=<version>' pin found in ${pair%%:*}" >&2
            drift=1
        fi
    done

    if [ -n "$dev" ] && [ -n "$build" ] && [ "$dev" != "$build" ]; then
        echo "ERROR: $arg drift between the devcontainer images:" >&2
        echo "  $DOCKERFILE       = $dev" >&2
        echo "  $BUILD_DOCKERFILE = $build" >&2
        drift=1
    fi
done

if [ "$drift" -ne 0 ]; then
    echo "" >&2
    echo "Both images must install the same version of every shared cargo" >&2
    echo "tool. Renovate bumps a crate across both files in one PR, so do" >&2
    echo "not fix this by hand-editing a single file." >&2
    exit 1
fi

echo "Shared cargo tool pins agree: ${SHARED_TOOLS[*]}"
