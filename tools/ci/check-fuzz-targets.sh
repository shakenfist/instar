#!/usr/bin/env bash
#
# Guard the fuzz target registration lists.
#
# Registering a new libFuzzer target means touching several places by
# hand: the .rs file itself, a [[bin]] stanza in src/fuzz/Cargo.toml, and
# the TARGETS=(...) array in .github/workflows/coverage-fuzz.yml that
# every nightly and post-merge fuzz run reads whenever no explicit
# target list is given. A target missing from that array is never
# fuzzed in CI at all, silently, while everything else -- including its
# row in docs/testing.md -- keeps claiming it is. Nothing before this
# script compared those lists to the tree.
#
# This asserts the three lists name exactly the same set of targets:
#   1. the .rs basenames under src/fuzz/fuzz_targets/
#   2. the `name = "..."` value of every [[bin]] stanza in
#      src/fuzz/Cargo.toml -- not `grep -c '^name = '`, which also
#      counts the crate's own [package] name
#   3. the TARGETS=(...) array in .github/workflows/coverage-fuzz.yml
#
# tools/ci/fuzz-tier.sh's FAST_TIER is checked separately, as a subset
# rather than for equality: an unlisted target legitimately defaults to
# the deep tier, so only a FAST_TIER entry naming a target that exists
# nowhere above is an error.
#
# Usage: tools/ci/check-fuzz-targets.sh
# Exits 0 with a one-line summary when every list agrees, 1 otherwise --
# every mismatch is reported before exiting, not just the first one
# found.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${REPO_ROOT}"

FUZZ_TARGETS_DIR="src/fuzz/fuzz_targets"
CARGO_TOML="src/fuzz/Cargo.toml"
WORKFLOW=".github/workflows/coverage-fuzz.yml"
FUZZ_TIER="tools/ci/fuzz-tier.sh"

FAILURES=0

fs_targets() {
    local f base
    for f in "${FUZZ_TARGETS_DIR}"/*.rs; do
        [ -e "${f}" ] || continue
        base="$(basename "${f}" .rs)"
        printf '%s\n' "${base}"
    done
}

# Only a name inside a [[bin]] table counts -- the [package] table above
# it also has a `name = "..."` line, for the crate itself.
cargo_bin_targets() {
    awk '
        /^\[\[bin\]\]/ { in_bin = 1; next }
        /^\[/          { in_bin = 0 }
        in_bin && /^name = / {
            line = $0
            sub(/^name = "/, "", line)
            sub(/".*$/, "", line)
            print line
        }
    ' "${CARGO_TOML}"
}

workflow_targets() {
    awk '
        /^[[:space:]]*TARGETS=\($/ { in_arr = 1; next }
        in_arr && /^[[:space:]]*\)[[:space:]]*$/ { in_arr = 0; next }
        in_arr {
            line = $0
            gsub(/^[[:space:]]+|[[:space:]]+$/, "", line)
            if (line != "" && line !~ /^#/) print line
        }
    ' "${WORKFLOW}"
}

fast_tier_targets() {
    awk '
        /^FAST_TIER=\($/ { in_arr = 1; next }
        in_arr && /^\)[[:space:]]*$/ { in_arr = 0; next }
        in_arr {
            line = $0
            gsub(/^[[:space:]]+|[[:space:]]+$/, "", line)
            if (line != "" && line !~ /^#/) print line
        }
    ' "${FUZZ_TIER}"
}

mapfile -t FS_LIST < <(fs_targets | sort -u)
mapfile -t CARGO_LIST < <(cargo_bin_targets | sort -u)
mapfile -t WORKFLOW_LIST < <(workflow_targets | sort -u)
mapfile -t FAST_LIST < <(fast_tier_targets | sort -u)

# A parsing regression here (a reformat of one of the three files, say)
# must not silently pass as "0 targets agree with 0 targets" -- each
# list is expected to be non-empty on any real tree.
if [ "${#FS_LIST[@]}" -eq 0 ]; then
    echo "ERROR: found no .rs files under ${FUZZ_TARGETS_DIR}/" >&2
    FAILURES=$((FAILURES + 1))
fi
if [ "${#CARGO_LIST[@]}" -eq 0 ]; then
    echo "ERROR: found no [[bin]] name entries in ${CARGO_TOML}" >&2
    FAILURES=$((FAILURES + 1))
fi
if [ "${#WORKFLOW_LIST[@]}" -eq 0 ]; then
    echo "ERROR: found no TARGETS=(...) entries in ${WORKFLOW}" >&2
    FAILURES=$((FAILURES + 1))
fi
if [ "${#FAST_LIST[@]}" -eq 0 ]; then
    echo "ERROR: found no FAST_TIER entries in ${FUZZ_TIER}" >&2
    FAILURES=$((FAILURES + 1))
fi

declare -A IN_FS=() IN_CARGO=() IN_WF=()
for t in "${FS_LIST[@]}"; do IN_FS["${t}"]=1; done
for t in "${CARGO_LIST[@]}"; do IN_CARGO["${t}"]=1; done
for t in "${WORKFLOW_LIST[@]}"; do IN_WF["${t}"]=1; done

mapfile -t UNION < <(
    printf '%s\n' "${FS_LIST[@]}" "${CARGO_LIST[@]}" "${WORKFLOW_LIST[@]}" | sort -u
)

for t in "${UNION[@]}"; do
    missing=()
    [ -n "${IN_FS[${t}]:-}" ] || missing+=("${FUZZ_TARGETS_DIR}/${t}.rs")
    [ -n "${IN_CARGO[${t}]:-}" ] || missing+=("${CARGO_TOML} [[bin]]")
    [ -n "${IN_WF[${t}]:-}" ] || missing+=("${WORKFLOW} TARGETS array")
    if [ "${#missing[@]}" -gt 0 ]; then
        echo "ERROR: fuzz target '${t}' is missing from: ${missing[*]}" >&2
        FAILURES=$((FAILURES + 1))
    fi
done

# Subset, not equality: an unlisted target defaults to the deep tier, so
# only a name that exists nowhere is a mistake worth failing on.
for t in "${FAST_LIST[@]}"; do
    if [ -z "${IN_FS[${t}]:-}" ]; then
        echo "ERROR: FAST_TIER in ${FUZZ_TIER} names '${t}'," \
            "which is not a fuzz target under ${FUZZ_TARGETS_DIR}/" >&2
        FAILURES=$((FAILURES + 1))
    fi
done

if [ "${FAILURES}" -ne 0 ]; then
    echo "check-fuzz-targets: ${FAILURES} problem(s) found" >&2
    exit 1
fi

summary="check-fuzz-targets: ${#FS_LIST[@]} fuzz targets agree across"
summary="${summary} fuzz_targets/, Cargo.toml, and coverage-fuzz.yml;"
summary="${summary} FAST_TIER (${#FAST_LIST[@]} targets) is a subset."
echo "${summary}"
