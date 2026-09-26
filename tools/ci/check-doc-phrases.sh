#!/usr/bin/env bash
#
# Guard against a specific text corruption in the documentation.
#
# A bad automated replace once spliced the word "work" into the middle
# of a plan filename mentioned in prose, turning a sentence naming, say,
# PLAN-map into one naming PLAN-m and workap either side of the space.
# The result reads like a minor typo, not a clear breakage -- a reader
# skimming the page does not stumble, they just come away slightly
# confused, so nothing forces a human to notice and report it. Phase 9
# of PLAN-differencing.md found and fixed seven instances of this in
# docs/testing.md alone; a further 17 had already spread across five
# other pages by the time phase 10 went looking, and would have kept
# spreading silently without something that greps for the pattern on
# every change. This is that something. (Concrete before/after examples
# are not reproduced here: doing so would itself match the pattern this
# script exists to catch. See docs/plans/PLAN-differencing-phase-10-
# docs.md's decision 4 for real ones.)
#
# Scope is every tracked file except two directories, because the
# corruption lands in any prose that names a plan file -- CHANGELOG.md
# and ARCHITECTURE.md cite plan names as freely as docs/ does, and
# scoping to docs/ would leave them unguarded. The two exclusions:
#   - tools/ci/, because this repo's own tooling legitimately contains
#     the literal pattern -- this script's tests build fixtures
#     carrying the corrupted phrase on purpose, to prove the guard
#     catches it, and this header would otherwise match itself.
#   - docs/plans/, because those pages are the historical record of the
#     corruption: they quote corrupted phrases verbatim as examples
#     when describing the bug and its repair, and rewriting a quoted
#     example would erase the record rather than fix a defect.
# Anywhere else, a match is real corruption -- no legitimate plan
# reference has a single letter between the hyphen and the following
# space.
#
# Usage: tools/ci/check-doc-phrases.sh
# Exits 0 with a one-line summary when the tree is clean, 1 otherwise --
# every hit is reported, with file and line number, before exiting, not
# just the first one found.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${REPO_ROOT}"

PATTERN='PLAN-[a-z] work[a-z]'

FAILURES=0

# git grep exits 1 when nothing matches, which is not itself an error
# here, so do not let `set -e` treat it as one.
HITS=""
if HITS="$(git grep -nE "${PATTERN}" -- ':!docs/plans/**' ':!tools/ci/**')"; then
    while IFS= read -r hit; do
        [ -n "${hit}" ] || continue
        echo "ERROR: mangled plan-filename phrase: ${hit}" >&2
        FAILURES=$((FAILURES + 1))
    done <<< "${HITS}"
fi

if [ "${FAILURES}" -ne 0 ]; then
    echo "check-doc-phrases: ${FAILURES} problem(s) found" >&2
    exit 1
fi

echo "check-doc-phrases: no mangled plan-filename phrases in tracked files."
