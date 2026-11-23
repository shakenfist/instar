#!/usr/bin/env bash
#
# Fail when a test uses tempfile.NamedTemporaryFile.
#
# A failed `convert`, `dd` or `copy` removes an output file it left
# empty (#849). A NamedTemporaryFile handed to instar as that output is
# then already gone when its `with` block ends, and Python 3.10 and 3.11
# raise FileNotFoundError from the cleanup where 3.12 and later ignore
# it. The PR gate runs the suite on Debian 13's Python 3.13, so it
# passes there; the merge queue's Debian 12 and Ubuntu 22.04 legs fail,
# and 25 such tests ejected every PR queued after #945 (#959). Tests use
# tests/helpers/scratch.py's ScratchFile, a drop-in that tolerates the
# removal on every Python; docs/testing.md states the convention.
#
# The match is the name, not a call shape: an import of it, a call to
# it, or a mention of it in a comment or a docstring. Distinguishing a
# temporary file instar writes from one it only reads would take a
# parser, and a test that only reads one today can be changed to write
# it tomorrow by an edit that never revisits the `with`. ScratchFile
# costs nothing where the file is only read, so the rule is everywhere.
#
# Usage: tools/ci/check-no-named-temporary-file.sh
# Exits 0 with a one-line summary when the tree is clean, 1 naming every
# hit by file and line otherwise, and 2 when git grep itself fails.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${REPO_ROOT}"

PATTERN='NamedTemporaryFile'

# Files that may name it. Each entry needs its reason; widen this rather
# than narrowing the pattern.
#   tests/helpers/scratch.py: ScratchFile is built on it, with the
#     cleanup the rest of tests/ cannot rely on.
EXEMPT=(
    'tests/helpers/scratch.py'
)

PATHSPEC=(':(glob)tests/**/*.py')
for f in "${EXEMPT[@]}"; do
    PATHSPEC+=(":(exclude)${f}")
done

# git grep exits 1 when nothing matches, which is the clean case, but
# above 1 is an error: outside a checkout it exits 128, and treating
# that as "no matches" would make this guard pass having read nothing.
set +e
HITS="$(git grep -nIE "${PATTERN}" -- "${PATHSPEC[@]}")"
GREP_STATUS=$?
set -e
if [ "${GREP_STATUS}" -gt 1 ]; then
    echo "ERROR: git grep failed (exit ${GREP_STATUS}); not a git checkout?" >&2
    exit 2
fi

if [ "${GREP_STATUS}" -eq 0 ]; then
    while IFS= read -r hit; do
        echo "ERROR: NamedTemporaryFile in a test: ${hit}" >&2
    done <<< "${HITS}"
    echo "check-no-named-temporary-file: $(grep -c . <<< "${HITS}") problem(s) found." >&2
    echo "Use helpers.scratch.ScratchFile; see docs/testing.md." >&2
    exit 1
fi

echo 'check-no-named-temporary-file: no test uses NamedTemporaryFile.'
