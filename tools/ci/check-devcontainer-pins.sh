#!/bin/bash
# Assert the devcontainer Dockerfiles pin their toolchain correctly.
#
# Three separate properties, all of which fail silently in production:
#
#   1. The two images agree on every pin they share -- the Rust nightly,
#      and the versions of the cargo tools both install.
#   2. Every `cargo install` runs with --locked, and takes its version
#      from an ARG rather than a hardcoded literal.
#   3. Every pin stays matchable by the customManagers entry in
#      renovate.json, so it keeps being bumped.
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
# Exits 0 when every property above holds, 1 otherwise.
#
# tools/ci/test-check-devcontainer-pins.sh exercises each failure path
# by mutating a copy of the real tree.

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

# The pins are only half the protection, and not the half that fixed the
# outage this check was extended for: --locked is what builds each tool
# against the dependency set its author released it with, so a broken
# transitive dependency published upstream cannot reach the image. A pin
# without --locked still re-resolves the whole tree. CHANGELOG.md,
# docs/development.md, AGENTS.md and both Dockerfiles all state --locked
# as a rule; without a check, deleting it from one line -- or adding a
# new `cargo install` without it -- passes pre-commit and CI in silence
# and restores exactly the failure mode.
#
# The `# renovate:` comments are the other silent-failure surface. They
# are what puts each pin under Renovate's 3-day minimumReleaseAge, and a
# comment that stops matching does not error anywhere: the pin simply
# freezes forever, which is worse than the floating installs it
# replaced. So the format the customManagers regex in renovate.json
# needs is asserted here rather than trusted.
#
# Rather than check those two things directly, the checks below make the
# whole chain derivable from the crate name:
#
#     cargo-deb  ->  CARGO_DEB_VERSION  ->  # renovate: depName=cargo-deb
#
# Every crate on an install line must arrive as `<crate>@${<ARG>}`, that
# ARG must be declared with the name the crate implies, and the renovate
# comment above it must name the same crate. Checking a spelling of the
# rule would leave the gaps between them: `cargo install --locked
# cargo-audit` with no version at all carries a --locked, references no
# ARG and hardcodes nothing, so it satisfies each rule separately while
# floating exactly as it did before this was pinned.

# Docker continues a RUN across backslash-terminated lines, so the
# --locked and the crate specs of one install can sit on three different
# lines. Emit one logical line per instruction, prefixed with the line
# number it starts at, so a check can look at a whole invocation. Whole
# line comments are dropped (the blocks above these installs discuss
# `cargo install` in prose); Docker has no other kind.
logical_lines() {
    awk '
        cont == 0 && /^[[:space:]]*#/ { next }
        {
            if (cont == 0) { start = NR; buf = $0 } else { buf = buf " " $0 }
            cont = /\\[[:space:]]*$/ ? 1 : 0
            if (cont == 0) { gsub(/\\/, " ", buf); print start ":" buf }
        }
    ' "$1"
}

# cargo-generate-rpm -> CARGO_GENERATE_RPM_VERSION, and back again.
crate_to_arg() { printf '%s_VERSION\n' "$1" | tr 'a-z-' 'A-Z_'; }
arg_to_crate() { printf '%s\n' "${1%_VERSION}" | tr 'A-Z_' 'a-z-'; }

problems=0

for f in "$DOCKERFILE" "$BUILD_DOCKERFILE"; do
    while IFS= read -r logical; do
        lineno="${logical%%:*}"
        content="${logical#*:}"
        case "$content" in
            *"cargo install"*) ;;
            *) continue ;;
        esac

        # A RUN chains commands, and the images already use
        # `umask 0000 && cargo install ...`. Split on the shell
        # separators so each install is checked on its own: taking
        # everything after the first `cargo install` as its arguments
        # would misread a second one on the same line as a crate named
        # "cargo", and would let one --locked cover both.
        while IFS= read -r segment; do
            case "$segment" in
                *"cargo install"*) ;;
                *) continue ;;
            esac

            case "$segment" in
                *--locked*) ;;
                *)
                    echo "ERROR: $f:$lineno: 'cargo install' without --locked:" >&2
                    echo " ${segment}" >&2
                    problems=1
                    ;;
            esac

            # Word splitting is the point here: the crate specs are the
            # non-flag arguments after `cargo install`.
            # shellcheck disable=SC2086
            for spec in ${segment#*cargo install}; do
                case "$spec" in
                    -*) continue ;;
                esac

                if ! printf '%s' "$spec" \
                        | grep -qE '^[a-z0-9-]+@"?\$\{[A-Z0-9_]+\}"?$'; then
                    echo "ERROR: $f:$lineno: crate must be installed as" >&2
                    echo "       <crate>@\"\${<CRATE>_VERSION}\", not:" >&2
                    echo "  $spec" >&2
                    problems=1
                    continue
                fi

                crate="${spec%%@*}"
                var="${spec#*@}"
                var="${var#\"}"
                var="${var%\"}"
                var="${var#\$\{}"
                var="${var%\}}"

                if [ "$var" != "$(crate_to_arg "$crate")" ]; then
                    echo "ERROR: $f:$lineno: $crate is installed from \${$var};" >&2
                    echo "       name the ARG $(crate_to_arg "$crate") after the crate" >&2
                    problems=1
                elif ! grep -qE "^ARG $var=" "$f"; then
                    echo "ERROR: $f:$lineno: \${$var} is not declared as an ARG" >&2
                    problems=1
                fi
            done
        done < <(printf '%s\n' "$content" | sed -e 's/&&/\n/g' -e 's/||/\n/g' -e 's/;/\n/g')
    done < <(logical_lines "$f")

    while IFS= read -r hit; do
        [ -n "$hit" ] || continue
        lineno="${hit%%:*}"
        content="${hit#*:}"
        name="${content%%=*}"
        name="${name#ARG }"

        # The customManagers regex captures `[^\s"]+`, so a quoted value
        # -- which Docker accepts, and which matches the quoting style of
        # the install lines right below -- silently fails to match.
        if ! printf '%s' "$content" | grep -qE "^ARG $name=[^[:space:]\"]+[[:space:]]*\$"; then
            echo "ERROR: $f:$lineno: pin value must be unquoted, or Renovate" >&2
            echo "       will not match it:" >&2
            echo "  $content" >&2
            problems=1
        fi

        # The ARG has to actually reach an install line.
        if ! grep -qF "\${$name}" "$f"; then
            echo "ERROR: $f:$lineno: ARG $name is never referenced as \${$name}" >&2
            problems=1
        fi

        # And the renovate comment has to sit directly above it, naming
        # the crate the ARG is named after.
        expected="# renovate: datasource=crate depName=$(arg_to_crate "$name")"
        previous=""
        [ "$lineno" -gt 1 ] && previous="$(sed -n "$((lineno - 1))p" "$f")"
        if [ "$previous" != "$expected" ]; then
            echo "ERROR: $f:$lineno: ARG $name must be directly preceded by" >&2
            echo "       $expected" >&2
            echo "  found: ${previous:-<start of file>}" >&2
            problems=1
        fi
    done < <(grep -nE '^ARG CARGO_[A-Z0-9_]*_VERSION=' "$f" || true)
done

if [ "$problems" -ne 0 ]; then
    echo "" >&2
    echo "Every cargo tool install in the devcontainer images must run with" >&2
    echo "--locked and take its version from an ARG that Renovate can see." >&2
    echo "See docs/development.md, 'Cargo tool pinning'." >&2
    exit 1
fi

echo "Every cargo install is --locked and every pin is Renovate-visible"
