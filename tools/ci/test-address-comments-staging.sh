#!/usr/bin/env bash
#
# Tests for the staging, reset and reporting wiring in
# tools/address-comments-with-claude.sh.
#
# That loop only runs inside a privileged issue_comment workflow a
# maintainer triggers by hand, against a live pull request, so nothing
# observes it unless a test does -- which is how #510 sat there for
# months turning real fixes into "No changes needed" rows. The loop
# needs `claude` and `gh`, but only to call them: stub both and the
# whole item loop runs against a scratch repo in under a second.
#
# Each case pins one outcome a maintainer reads off the summary table,
# and the commits behind it. The states worth pinning are the ones
# where what Claude did and what the index shows disagree: a new file
# it left untracked, an edit CI has to throw away, and an item that was
# abandoned after touching the tree.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
ADDRESS="${REPO_ROOT}/tools/address-comments-with-claude.sh"

WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"' EXIT
export GIT_CEILING_DIRECTORIES="${WORK}"

FAILURES=0

start() { echo "--- $1"; }
ok() { echo "    ok: $1"; }
fail() { echo "    FAIL: $1" >&2; FAILURES=$((FAILURES + 1)); }

check() {
    # check DESCRIPTION ACTUAL EXPECTED
    if [ "$2" = "$3" ]; then
        ok "$1"
    else
        fail "$1: expected '$3', got '$2'"
    fi
}

contains() {
    # contains DESCRIPTION HAYSTACK NEEDLE
    case "$2" in
        *"$3"*) ok "$1" ;;
        *) fail "$1: '$3' not in '$2'" ;;
    esac
}

lacks() {
    case "$2" in
        *"$3"*) fail "$1: '$3' unexpectedly in '$2'" ;;
        *) ok "$1" ;;
    esac
}

BIN="${WORK}/bin"
mkdir -p "${BIN}"

# The loop checks for gh before it does anything, and never reaches a
# call to it once --pr and --review-json are both supplied.
printf '#!/bin/sh\nexit 1\n' > "${BIN}/gh"
chmod +x "${BIN}/gh"
export PATH="${BIN}:${PATH}"

# Stands in for Claude Code, dispatching on the item title in the
# prompt. Each branch leaves the working tree in one of the states the
# loop has to tell apart, and -- the point of the whole exercise --
# stages none of it, which is what the real thing does.
cat > "${BIN}/claude" <<'STUB'
#!/usr/bin/env bash
prompt=""
while [ $# -gt 0 ]; do
    case "$1" in
        -p) prompt="$2"; shift 2 ;;
        *) shift ;;
    esac
done
cd "${WORK_DIR}"
summary() { echo 'CHANGE_SUMMARY_START'; echo "$1"; echo 'CHANGE_SUMMARY_END'; }
case "${prompt}" in
    *ITEM-tracked*)
        echo 'fn main() { fixed(); }' > src/main.rs
        summary 'Fix main' ;;
    *ITEM-newfile*)
        echo 'fn main() { helped(); }' > src/main.rs
        echo 'pub fn help() {}' > src/helper.rs
        summary 'Add helper' ;;
    *ITEM-newonly*)
        echo '# notes' > docs/new.md
        summary 'Add doc' ;;
    *ITEM-workflow*)
        echo 'name: edited' > .github/workflows/ci.yml
        summary 'Fix workflow' ;;
    *ITEM-nothing*)
        summary 'Did nothing' ;;
    *ITEM-artifact*)
        echo 'junk' > src/main.rs.orig
        summary 'Left an artifact' ;;
    *ITEM-disagree*)
        echo 'fn main() { half_done(); }' > src/main.rs
        echo 'stray' > src/stray.rs
        echo 'DISAGREEMENT_START'; echo 'Not a real problem'; echo 'DISAGREEMENT_END' ;;
    *ITEM-after*)
        echo 'fn main() { later(); }' > src/main.rs
        summary 'Later fix' ;;
esac
STUB
chmod +x "${BIN}/claude"

ITEMS='ITEM-tracked ITEM-newfile ITEM-newonly ITEM-workflow ITEM-nothing
       ITEM-artifact ITEM-disagree ITEM-after'

REVIEW="${WORK}/review.json"
{
    echo '{"summary": "stub review", "items": ['
    N=0
    SEP=''
    for T in ${ITEMS}; do
        N=$((N + 1))
        printf '%s{"id": %d, "title": "%s", "action": "fix",' "${SEP}" "${N}" "${T}"
        printf ' "category": "bug", "severity": "medium",'
        printf ' "description": "%s", "location": "l", "suggestion": "s"}\n' "${T}"
        SEP=','
    done
    echo ']}'
} > "${REVIEW}"

# A scratch repo with the shapes the loop cares about: a tracked source
# file, a workflow file, and ignored build output that has to survive.
setup() {
    D="${WORK}/repo"
    rm -rf "${D}"
    mkdir -p "${D}/src" "${D}/docs" "${D}/.github/workflows" "${D}/target"
    git -C "${D}" init -q
    git -C "${D}" config user.email bot@example.com
    git -C "${D}" config user.name bot
    echo 'fn main() {}' > "${D}/src/main.rs"
    echo '# docs' > "${D}/docs/index.md"
    echo 'name: ci' > "${D}/.github/workflows/ci.yml"
    printf 'target/\n' > "${D}/.gitignore"
    echo 'expensive' > "${D}/target/instar"
    git -C "${D}" add -A
    git -C "${D}" commit -qm base
    BASE_SHA="$(git -C "${D}" rev-parse HEAD)"
}

# Commits the run added, so the base commit that created the fixture
# does not count as one of them.
added_commits() { git -C "${D}" log --oneline "${BASE_SHA}..HEAD" -- "$@"; }

# Run the loop with TOOLS_DIR pointing wherever the case needs, which
# is how CI supplies the base-branch copy of tools/.
run() {
    set +e
    OUT="$(TOOLS_DIR="$1" WORK_DIR="${D}" CLAUDE_BIN="${BIN}/claude" \
        "${ADDRESS}" --pr 511 --review-json "${REVIEW}" 2>&1)"
    RC=$?
    set -e
}

# The Notes cell of one item's summary row.
row() { echo "${OUT}" | grep -F "| $1 |" | tail -1; }

# The files in the commit whose subject is $1.
commit_files() {
    git -C "${D}" log --format='%H %s' \
        | grep -F " $1." | head -1 | cut -d' ' -f1 \
        | xargs -r git -C "${D}" show --name-only --format= \
        | LC_ALL=C sort | tr '\n' ' ' | sed 's/ $//'
}

start "the item loop stages, commits and reports each outcome"
setup
run "${REPO_ROOT}/tools"
check "exit 0" "${RC}" "0"

# The plain case: a tracked edit reaches the commit.
contains "tracked edit is fixed" "$(row ITEM-tracked)" "✅ Fixed"
check "tracked edit committed" "$(commit_files 'Fix main')" "src/main.rs"

# The defect the --tracked-only mode opens up. `git add -u` cannot see
# a file Claude created, so before this the commit went out saying
# "Fixed" with the new file missing from it entirely.
contains "new file is fixed" "$(row ITEM-newfile)" "✅ Fixed"
check "new file committed" "$(commit_files 'Add helper')" "src/helper.rs src/main.rs"
contains "new file named in the row" "$(row ITEM-newfile)" "src/helper.rs"

# Same defect where the new file is the whole fix: the index would be
# empty, so the item was reported as changing nothing.
contains "new file alone is fixed" "$(row ITEM-newonly)" "✅ Fixed"
check "new file alone committed" "$(commit_files 'Add doc')" "docs/new.md"

# A commit touching .github/workflows/ cannot be pushed with this
# workflow's token, so CI drops the edit -- but "modified no file" is
# then a lie, and it sends a maintainer looking for the wrong problem.
contains "workflow-only edit is not pushable" "$(row ITEM-workflow)" "⚠️ Not pushable"
contains "workflow file named" "$(row ITEM-workflow)" ".github/workflows/ci.yml"
lacks "not reported as changing nothing" "$(row ITEM-workflow)" "modified no file"
check "workflow edit not committed" \
    "$(added_commits .github/workflows/ | wc -l)" "0"

# An item that really changed nothing still has to say so.
contains "empty item is skipped" "$(row ITEM-nothing)" "modified no file"

# pre-commit hooks leave these routinely, so they are not a fix.
contains "editor leftover is not a fix" "$(row ITEM-artifact)" "modified no file"
check "leftover not committed" "$(commit_files 'Left an artifact')" ""

# The leak the reset exists to stop: an abandoned item's edits must not
# be picked up and committed under the next item's id and rationale.
contains "disagreement is skipped" "$(row ITEM-disagree)" "Not a real problem"
check "next item commits only its own file" \
    "$(commit_files 'Later fix')" "src/main.rs"
check "abandoned new file never committed" \
    "$(added_commits src/stray.rs | wc -l)" "0"

check "tree left clean" "$(git -C "${D}" status --porcelain)" ""
check "ignored build output survives" "$(cat "${D}/target/instar")" "expensive"

# Both helpers are resolved from TOOLS_DIR, which in CI is a sparse
# checkout of the base branch. A missing one must stop the run: falling
# back to whatever Claude staged is #510, and skipping the reset
# commits one item's work under another's id.
start "a TOOLS_DIR missing a helper refuses to start"
setup
for HELPER in stage-autofix-changes.sh reset-autofix-worktree.sh; do
    PARTIAL="${WORK}/tools-no-${HELPER}"
    rm -rf "${PARTIAL}"
    cp -r "${REPO_ROOT}/tools" "${PARTIAL}"
    rm -f "${PARTIAL}/ci/${HELPER}"
    run "${PARTIAL}"
    check "refuses without ${HELPER}" "${RC}" "1"
    contains "names the missing helper" "${OUT}" "${HELPER}"
    check "made no commit" "$(added_commits | wc -l)" "0"
done

# In --tracked-only mode the stager fails only on a broken invocation,
# under which nothing is staged at all -- so carrying on would report
# every item as changing nothing, which is the #510 misreport reached
# by another route.
start "a failing stager is an item-level error, not a warning"
setup
BROKEN="${WORK}/tools-broken-stager"
rm -rf "${BROKEN}"
cp -r "${REPO_ROOT}/tools" "${BROKEN}"
printf '#!/bin/sh\necho broken >&2\nexit 2\n' > "${BROKEN}/ci/stage-autofix-changes.sh"
chmod +x "${BROKEN}/ci/stage-autofix-changes.sh"
run "${BROKEN}"
check "exit 0" "${RC}" "0"
contains "reports an error" "$(row ITEM-tracked)" "❌ Error"
lacks "does not claim nothing changed" "$(row ITEM-tracked)" "modified no file"
check "made no commit" "$(added_commits | wc -l)" "0"
check "tree left clean" "$(git -C "${D}" status --porcelain)" ""

if [ "${FAILURES}" -ne 0 ]; then
    echo "${FAILURES} failure(s)" >&2
    exit 1
fi

echo "all address-comments staging tests passed"
