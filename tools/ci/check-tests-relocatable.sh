#!/usr/bin/env bash
#
# Fail when a file under tests/ builds a path into the repository outside
# tests/.
#
# The suite's tree is relocatable: tools/test-package-functional.sh copies
# tests/ alone to /tmp/instar-tests and runs it there against an installed
# package, with no repository around it. A test that reaches out of tests/
# resolves its path against /tmp and raises FileNotFoundError -- and it does
# so only in the merge queue, because the pull request gate runs the suite
# from the repository where the path exists. That is the most expensive place
# to find it: two tests reading src/crates/vmdk/src/lib.rs passed every check
# on #968 and then failed all seven package-matrix legs (#959 is the same
# shape for a different cause).
#
# Source-level checks belong in tools/ci instead, where the whole tree is
# present and they run on every pull request; see
# tools/ci/check-vmdk-split-pins.py, which is the one moved out of tests/.
#
# The match is the pathlib join form -- `/ 'name'` -- against the
# repository's own top-level directories, read from git rather than written
# down here so a new one is covered the day it appears. A test that assembled
# such a path by string concatenation or os.path.join would slip through; the
# package matrix stays the backstop for that, and this guard is what stops
# the shape that has actually happened.
#
# instar-testdata is not matched: it is a sibling of the repository, not a
# part of it, and the harness passes INSTAR_TESTDATA_PATH into the container.
#
# Usage: tools/ci/check-tests-relocatable.sh
# Exits 0 with a one-line summary when the tree is clean, 1 naming every hit
# by file and line otherwise, and 2 when git itself fails.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${REPO_ROOT}"

# The repository's top-level directories, minus tests/ itself, which a test
# may of course address.
if ! TOP_DIRS="$(git ls-tree -d --name-only HEAD)"; then
    echo 'ERROR: git ls-tree failed; not a git checkout?' >&2
    exit 2
fi
ALTERNATION=''
for dir in ${TOP_DIRS}; do
    [ "${dir}" = 'tests' ] && continue
    if [ -z "${ALTERNATION}" ]; then
        ALTERNATION="${dir}"
    else
        ALTERNATION="${ALTERNATION}|${dir}"
    fi
done
if [ -z "${ALTERNATION}" ]; then
    echo 'ERROR: no top-level directories found besides tests/' >&2
    exit 2
fi

# Files that may reach out, each with its reason. Widen this rather than
# narrowing the pattern.
#   tests/base.py: get_instar_binary falls back to the build tree at
#     src/target/release/instar, and only when INSTAR_BINARY_PATH is unset.
#     The packaged harness sets it to /usr/bin/instar, so the fallback is
#     never reached there, and it skipTest()s when the binary is absent.
EXEMPT=(
    'tests/base.py'
)

PATHSPEC=(':(glob)tests/**/*.py')
for f in "${EXEMPT[@]}"; do
    PATHSPEC+=(":(exclude)${f}")
done

PATTERN="/ *['\"](${ALTERNATION})['\"]"

# git grep exits 1 when nothing matches, which is the clean case, but above
# 1 is an error: outside a checkout it exits 128, and treating that as "no
# matches" would make this guard pass having read nothing.
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
        echo "ERROR: a test builds a path outside tests/: ${hit}" >&2
    done <<< "${HITS}"
    echo "check-tests-relocatable: $(grep -c . <<< "${HITS}") problem(s) found." >&2
    echo 'The suite runs from a copy of tests/ alone; put a source-level check' >&2
    echo 'in tools/ci instead. See tools/ci/check-vmdk-split-pins.py.' >&2
    exit 1
fi

echo "check-tests-relocatable: no test under tests/ builds a path into ${ALTERNATION//|/, }."
