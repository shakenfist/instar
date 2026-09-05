#!/bin/bash
# Assert the devcontainer Dockerfiles pin their toolchain correctly.
#
# Four separate properties, all of which fail silently in production:
#
#   1. The two images agree on every pin they share -- the Rust nightly,
#      and the versions of the cargo tools both install.
#   2. Every `cargo install` runs with --locked, and takes its version
#      from an ARG rather than a hardcoded literal.
#   3. Every pin stays matchable by the customManagers entry in
#      renovate.json, so it keeps being bumped.
#   4. That customManagers entry, as it is actually written in
#      renovate.json today, really does match them.
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
# Nothing here is keyed off a hardcoded list of tools or a crate-name
# prefix. The set of shared tools is the intersection of what the two
# files actually install, and the set of pins is whatever the install
# lines reference, so a tool added later is covered the day it is added.
#
# Usage: tools/ci/check-devcontainer-pins.sh
# Exits 0 when every property above holds, 1 otherwise. Every problem
# found is reported before exiting -- a contributor who has broken two
# things should see both, not rediscover the second after fixing the
# first.
#
# tools/ci/test-check-devcontainer-pins.sh exercises each failure path
# by mutating a copy of the real tree.

set -euo pipefail

REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
cd "$REPO_ROOT"

DOCKERFILE="src/.devcontainer/Dockerfile"
BUILD_DOCKERFILE="src/.devcontainer/build/Dockerfile"
RENOVATE_JSON="renovate.json"

problems=0

note_problem() { problems=1; }

for f in "$DOCKERFILE" "$BUILD_DOCKERFILE" "$RENOVATE_JSON"; do
    if [ ! -f "$f" ]; then
        echo "ERROR: $f not found" >&2
        problems=1
    fi
done
# The only early exit: every check below reads these files, so
# continuing would just produce noise about an absent file.
[ "$problems" -eq 0 ] || exit 1

# ---------------------------------------------------------------------
# Property 1a: the Rust nightly pin.

read_pin() {
    sed -nE 's/^ARG RUST_NIGHTLY=(nightly-[0-9]{4}-[0-9]{2}-[0-9]{2})$/\1/p' "$1"
}

DEV_PIN="$(read_pin "$DOCKERFILE")"
BUILD_PIN="$(read_pin "$BUILD_DOCKERFILE")"

nightly_missing=0
for pair in "$DOCKERFILE:$DEV_PIN" "$BUILD_DOCKERFILE:$BUILD_PIN"; do
    if [ -z "${pair#*:}" ]; then
        echo "ERROR: no 'ARG RUST_NIGHTLY=nightly-YYYY-MM-DD' pin found in ${pair%%:*}" >&2
        nightly_missing=1
        note_problem
    fi
done

# Only compare when both were found: an absent pin reads as the empty
# string and would otherwise report a second, misleading "drift".
if [ "$nightly_missing" -eq 0 ]; then
    if [ "$DEV_PIN" != "$BUILD_PIN" ]; then
        echo "ERROR: Rust nightly pin drift between the devcontainer images:" >&2
        echo "  $DOCKERFILE       = $DEV_PIN" >&2
        echo "  $BUILD_DOCKERFILE = $BUILD_PIN" >&2
        echo "" >&2
        echo "Both must pin the same nightly. Do not fix this by hand-editing" >&2
        echo "one file -- run tools/ci/bump-rust-nightly.sh, which bumps and" >&2
        echo "validates both together." >&2
        note_problem
    else
        echo "Rust nightly pins agree: $DEV_PIN"
    fi
fi

# ---------------------------------------------------------------------
# Property 2: what the install lines say.
#
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
# replaced.
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
#
# Because the install lines are what everything downstream is derived
# from, this section runs first: the shared-tool comparison and the
# Renovate-visibility checks both consume the crate -> ARG pairs it
# collects, and neither is limited to a fixed list or to crates whose
# name happens to start with "cargo-".

# Docker continues a RUN across backslash-terminated lines, so the
# --locked and the crate specs of one install can sit on three different
# lines. Emit one logical line per instruction, prefixed with the line
# number it starts at, so a check can look at a whole invocation.
#
# Comments are dropped wherever they appear -- the blocks above these
# installs discuss `cargo install` in prose, and Docker also strips a
# comment sitting inside a continuation without ending it. `next` fires
# before `cont` is reassigned, so the continuation state carries across
# such a comment exactly as Docker treats it.
logical_lines() {
    awk '
        /^[[:space:]]*#/ { next }
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

read_tool_pin() {
    # $1 = Dockerfile, $2 = ARG name
    sed -nE "s/^ARG $2=([^[:space:]]+)\$/\\1/p" "$1"
}

# Populated by the loop below: for each file, the crates it installs and
# the ARG each one takes its version from. Only well-formed installs are
# recorded, so a malformed one is reported once here rather than again
# as a phantom drift or a missing renovate comment.
declare -A INSTALLED_ARG=()   # "<file>|<crate>" -> ARG name
declare -A INSTALLED_CRATES=()  # "<file>" -> space separated crate list

collect_installs() {
    local f="$1"
    local logical lineno content segment spec crate var

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
                    note_problem
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
                    note_problem
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
                    note_problem
                    continue
                fi
                if ! grep -qE "^ARG $var=" "$f"; then
                    echo "ERROR: $f:$lineno: \${$var} is not declared as an ARG" >&2
                    note_problem
                    continue
                fi

                if [ -z "${INSTALLED_ARG["$f|$crate"]:-}" ]; then
                    INSTALLED_ARG["$f|$crate"]="$var"
                    INSTALLED_CRATES["$f"]="${INSTALLED_CRATES["$f"]:-} $crate"
                fi
            done
        done < <(printf '%s\n' "$content" | sed -e 's/&&/\n/g' -e 's/||/\n/g' -e 's/;/\n/g')
    done < <(logical_lines "$f")
}

for f in "$DOCKERFILE" "$BUILD_DOCKERFILE"; do
    collect_installs "$f"
done

# ---------------------------------------------------------------------
# Property 1b: the cargo tools both images install.
#
# The shared set is the intersection of what the two files install, not
# a list maintained here. A hardcoded list silently exempts the next
# tool added to both images from the very drift check it needs, which is
# the same class of hole this guard exists to close; the dev-only tools
# (cargo-fuzz, cargo-audit) fall out of the intersection on their own.

shared_crates=()
for crate in ${INSTALLED_CRATES["$DOCKERFILE"]:-}; do
    if [ -n "${INSTALLED_ARG["$BUILD_DOCKERFILE|$crate"]:-}" ]; then
        shared_crates+=("$crate")
    fi
done

drift=0
for crate in "${shared_crates[@]:-}"; do
    [ -n "$crate" ] || continue
    arg="${INSTALLED_ARG["$DOCKERFILE|$crate"]}"
    dev="$(read_tool_pin "$DOCKERFILE" "$arg")"
    build="$(read_tool_pin "$BUILD_DOCKERFILE" "$arg")"

    if [ "$dev" != "$build" ]; then
        echo "ERROR: $arg drift between the devcontainer images:" >&2
        echo "  $DOCKERFILE       = ${dev:-<unset>}" >&2
        echo "  $BUILD_DOCKERFILE = ${build:-<unset>}" >&2
        drift=1
        note_problem
    fi
done

if [ "$drift" -ne 0 ]; then
    echo "" >&2
    echo "Both images must install the same version of every shared cargo" >&2
    echo "tool. Renovate bumps a crate across both files in one PR, so do" >&2
    echo "not fix this by hand-editing a single file." >&2
elif [ ${#shared_crates[@]} -gt 0 ]; then
    echo "Shared cargo tool pins agree: ${shared_crates[*]}"
fi

# ---------------------------------------------------------------------
# Property 3: the pins stay visible to Renovate.
#
# Driven by the crates found on the install lines above rather than by
# an ARG-name pattern, so a crate whose name does not begin with
# "cargo-" gets the same coverage. The reverse direction -- an ARG that
# no install line references -- is checked afterwards.

renovate_pin_file="$(mktemp)"
trap 'rm -f "$renovate_pin_file"' EXIT

for f in "$DOCKERFILE" "$BUILD_DOCKERFILE"; do
    for crate in ${INSTALLED_CRATES["$f"]:-}; do
        name="${INSTALLED_ARG["$f|$crate"]}"
        decl="$(grep -nE "^ARG $name=" "$f" | head -n 1)"
        lineno="${decl%%:*}"
        content="${decl#*:}"

        # The customManagers regex captures `[^\s"]+`, so a quoted value
        # -- which Docker accepts, and which matches the quoting style of
        # the install lines right below -- silently fails to match.
        if ! printf '%s' "$content" | grep -qE "^ARG $name=[^[:space:]\"]+[[:space:]]*\$"; then
            echo "ERROR: $f:$lineno: pin value must be unquoted, or Renovate" >&2
            echo "       will not match it:" >&2
            echo "  $content" >&2
            note_problem
            continue
        fi

        # And the renovate comment has to sit directly above it, naming
        # the crate the ARG is named after.
        expected="# renovate: datasource=crate depName=$crate"
        previous=""
        [ "$lineno" -gt 1 ] && previous="$(sed -n "$((lineno - 1))p" "$f")"
        if [ "$previous" != "$expected" ]; then
            echo "ERROR: $f:$lineno: ARG $name must be directly preceded by" >&2
            echo "       $expected" >&2
            echo "  found: ${previous:-<start of file>}" >&2
            note_problem
            continue
        fi

        printf '%s\t%s\t%s\n' "$f" "$crate" \
            "$(read_tool_pin "$f" "$name")" >> "$renovate_pin_file"
    done

    # A pin no install line uses is dead weight that Renovate will keep
    # raising PRs for. Scoped to the crate naming convention, because an
    # ARG that is not a crate pin has no business being judged against
    # it.
    while IFS= read -r hit; do
        [ -n "$hit" ] || continue
        lineno="${hit%%:*}"
        content="${hit#*:}"
        name="${content%%=*}"
        name="${name#ARG }"
        if [ -z "${INSTALLED_ARG["$f|$(arg_to_crate "$name")"]:-}" ] \
                && ! grep -qF "\${$name}" "$f"; then
            echo "ERROR: $f:$lineno: ARG $name is never referenced as \${$name}" >&2
            note_problem
        fi
    done < <(grep -nE '^ARG CARGO_[A-Z0-9_]*_VERSION=' "$f" || true)
done

# ---------------------------------------------------------------------
# Property 4: renovate.json really matches those pins.
#
# Everything above asserts the *format* the customManagers entry needs,
# from this script's memory of it. That leaves the entry itself
# unguarded: a typo in matchStrings, or a managerFilePatterns path that
# stops naming these files, freezes all of the pins forever while this
# script still prints that they are Renovate-visible. So read the regex
# that is actually in renovate.json and run it over the two Dockerfiles,
# and require it to find exactly the pins found above -- same crates,
# same versions, no more and no fewer.

if ! command -v python3 > /dev/null 2>&1; then
    echo "ERROR: python3 is required to cross-check renovate.json" >&2
    problems=1
elif ! python3 tools/ci/check-renovate-manager.py \
        "$RENOVATE_JSON" "$renovate_pin_file" \
        "$DOCKERFILE" "$BUILD_DOCKERFILE"; then
    problems=1
fi

if [ "$problems" -ne 0 ]; then
    echo "" >&2
    echo "Every cargo tool install in the devcontainer images must run with" >&2
    echo "--locked and take its version from an ARG that Renovate can see." >&2
    echo "See docs/development.md, 'Cargo tool pinning'." >&2
    exit 1
fi

echo "Every cargo install is --locked and every pin is Renovate-visible"
