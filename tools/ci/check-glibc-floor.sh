#!/bin/bash
# Assert the built instar binary's glibc floor is low enough to honour
# the support promise the project publishes.
#
# glibc is forward-compatible only: a binary runs where the host glibc
# is >= the highest GLIBC_x.y symbol version it references. docs/
# installation.md and README.md promise glibc 2.31 or newer and Debian
# 11+, so 2.31 is the ceiling — not the matrix CI's oldest distro
# (Rocky 9, glibc 2.34), which is looser than the published promise and
# would let a base moving to, say, glibc 2.33 pass while breaking
# Debian 11. Debian 11 is not in the matrix, so nothing else would
# catch that. bullseye's own glibc is 2.31, so a correctly built binary
# structurally cannot exceed the ceiling; today it tops out at 2.30.
#
# This is the cheap nominal check, and it exists because the expensive
# empirical one (tools/verify-glibc-floor.sh, which installs the real
# packages on every distro) needs containers, packages and /dev/kvm, so
# it only runs in the merge queue matrix or by hand. That gap is not
# theoretical: renovate bumped the release build image from
# debian:bullseye to debian:trixie in PR #488, the binary's floor rose
# from GLIBC_2.30 to GLIBC_2.39, pull request CI was entirely happy, and
# the first sign of trouble was three distros failing in the merge queue
# after the change had already landed on develop. Running this straight
# after `make instar` turns that into a pull request failure.
#
# Usage: tools/ci/check-glibc-floor.sh [binary]
#
# Defaults to src/target/release/instar. Override the ceiling with
# MAX_GLIBC, e.g. MAX_GLIBC=2.34 to check only that the matrix CI's
# distributions would run the binary.

set -euo pipefail

BINARY="${1:-src/target/release/instar}"
MAX_GLIBC="${MAX_GLIBC:-2.31}"

if [ ! -f "$BINARY" ]; then
    echo "error: $BINARY does not exist; build it with 'make instar' first" >&2
    exit 1
fi

# objdump when binutils is present, otherwise grep the binary directly.
# The GLIBC_x.y version strings live in .dynstr as literal text, so the
# fallback finds the same set without needing a toolchain on the runner
# -- verified equivalent on a bullseye-built binary.
if command -v objdump >/dev/null 2>&1; then
    versions=$(objdump -T "$BINARY" | grep -o 'GLIBC_[0-9]\+\.[0-9]\+' || true)
else
    versions=$(grep -ao 'GLIBC_[0-9]\+\.[0-9]\+' "$BINARY" || true)
fi

if [ -z "$versions" ]; then
    echo "error: no GLIBC_ symbol versions found in $BINARY" >&2
    echo "       a dynamically linked glibc binary always references some;" >&2
    echo "       this probably means the wrong file was checked" >&2
    exit 1
fi

floor=$(echo "$versions" | sed 's/^GLIBC_//' | sort -uV | tail -1)

# sort -V puts the ceiling last when the floor is acceptable, including
# when the two are equal.
highest=$(printf '%s\n%s\n' "$floor" "$MAX_GLIBC" | sort -V | tail -1)
if [ "$highest" != "$MAX_GLIBC" ]; then
    echo "error: $BINARY requires GLIBC_$floor, above the $MAX_GLIBC ceiling" >&2
    echo >&2
    echo "The binary will not start on every platform the project says it" >&2
    echo "supports (glibc 2.31+, Debian 11+; see docs/installation.md)." >&2
    echo "This almost always means the release build image's base moved:" >&2
    echo "check FROM in src/.devcontainer/build/Dockerfile is still" >&2
    echo "debian:bullseye. Symbol versions referenced:" >&2
    echo "$versions" | sed 's/^GLIBC_//' | sort -uV | sed 's/^/  GLIBC_/' >&2
    exit 1
fi

echo "glibc floor OK: $BINARY requires at most GLIBC_$floor (ceiling $MAX_GLIBC)"
