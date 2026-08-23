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
#
# stdout is the `--output-format stream-json --verbose` stream the loop
# now captures, not prose: assistant lines carrying the text, and a
# result line repeating the final one in `.result` -- which is what the
# reducer reports -- alongside the .modelUsage the commit trailer is
# derived from. A stub that still printed prose would leave the reduced
# output empty and turn every case below into "No summary marker
# found".
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
# One assistant line and nothing else: narration the run went on past.
narrate() {
    jq -nc --arg t "$1" \
        '{type: "assistant",
          message: {content: [{type: "text", text: $t}]}}'
}
# The last assistant line and the result line that ends the run. The
# real CLI puts the final assistant message in `.result`, and the
# reducer prefers it over the concatenated narration -- so a stub that
# left `.result` out would not exercise the path the loop actually
# takes.
say() {
    narrate "$1"
    jq -nc --arg t "$1" \
        '{type: "result", subtype: "success", is_error: false,
          num_turns: 1, result: $t,
          modelUsage: {"claude-opus-5": {outputTokens: 4,
                                         contextWindow: 1000000,
                                         canonicalModel: "claude-opus-5"}}}'
}
summary() { say "CHANGE_SUMMARY_START
$1
CHANGE_SUMMARY_END"; }
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
    *ITEM-both*)
        echo 'fn main() { both(); }' > src/main.rs
        echo 'name: alsoedited' > .github/workflows/ci.yml
        summary 'Fix both' ;;
    *ITEM-ignored*)
        echo 'crash' > docs/fixture.bin
        summary 'Add fixture' ;;
    *ITEM-nothing*)
        summary 'Did nothing' ;;
    *ITEM-artifact*)
        echo 'junk' > src/main.rs.orig
        summary 'Left an artifact' ;;
    *ITEM-disagree*)
        echo 'fn main() { half_done(); }' > src/main.rs
        echo 'stray' > src/stray.rs
        say 'DISAGREEMENT_START
Not a real problem
DISAGREEMENT_END' ;;
    *ITEM-after*)
        echo 'fn main() { later(); }' > src/main.rs
        summary 'Later fix' ;;
    # A disagreement raised mid-run and then abandoned: it argues the
    # item away, changes its mind, and fixes it. Only the final message
    # -- the one carrying the change summary -- describes the outcome.
    *ITEM-reconsidered*)
        narrate 'DISAGREEMENT_START
On reflection I do not think this is a real problem
DISAGREEMENT_END'
        echo 'fn main() { reconsidered(); }' > src/main.rs
        summary 'Fix after reconsidering' ;;
esac
STUB
chmod +x "${BIN}/claude"

ITEMS='ITEM-tracked ITEM-newfile ITEM-newonly ITEM-workflow ITEM-ignored
       ITEM-both ITEM-nothing ITEM-artifact ITEM-disagree ITEM-after
       ITEM-reconsidered'

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
    printf 'target/\n**/*.bin\n' > "${D}/.gitignore"
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
    local tools="$1"
    shift
    set +e
    OUT="$(TOOLS_DIR="${tools}" WORK_DIR="${D}" CLAUDE_BIN="${BIN}/claude" \
        "${ADDRESS}" --pr 511 --review-json "${REVIEW}" "$@" 2>&1)"
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

# The trailer names whatever the stream said ran, rather than a model
# name typed in once and left to go stale -- which is what it had done.
TRACKED_MSG="$(git -C "${D}" log --format='%H %s' | grep -F ' Fix main.' \
    | head -1 | cut -d' ' -f1 \
    | xargs -r git -C "${D}" log -1 --format=%B)"
contains "trailer names the model the stream reported" "${TRACKED_MSG}" \
    "Co-Authored-By: Claude claude-opus-5 (1M context) <noreply@anthropic.com>"
contains "trailer keeps the sign-off" "${TRACKED_MSG}" \
    "Signed-off-by: Michael Still"
lacks "trailer names no hardcoded model" "${TRACKED_MSG}" "Opus 4"

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

# The success path leaves the workflow edit the stager refused in the
# tree. Without a reset after the commit it is still there when the
# next item is judged, so an item that touched nothing is told it made
# a workflow edit needing hand application.
contains "mixed item is fixed" "$(row ITEM-both)" "✅ Fixed"
contains "mixed item notes the dropped workflow edit" "$(row ITEM-both)" "Discarded"
check "workflow edit not committed with it" \
    "$(commit_files 'Fix both')" "src/main.rs"

# An item that really changed nothing still has to say so.
contains "empty item is skipped" "$(row ITEM-nothing)" "modified no file"
lacks "empty item inherits no workflow residue" "$(row ITEM-nothing)" "Not pushable"
lacks "empty item inherits no discard note" "$(row ITEM-nothing)" "Discarded"

# git hides ignored paths from the untracked listing, and `**/*.bin` is
# in this repo's .gitignore -- which is what a fuzz regression fixture
# is called. Reported as changing nothing, it is #510 by a third route.
lacks "ignored new file is not reported as no change" \
    "$(row ITEM-ignored)" "modified no file"
contains "ignored new file is named" "$(row ITEM-ignored)" "docs/fixture.bin"

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

# The other side of the same grep, and a data-loss path rather than a
# reporting one. The DISAGREEMENT check is control flow: match it and
# the item is recorded as Skipped and reset_worktree throws the working
# tree away. A run that raised a disagreement mid-stream and then went
# on to fix the item -- or that merely quoted the marker while
# reasoning -- must not trip it, which is why the reducer reports the
# final result text rather than every assistant message concatenated.
contains "a reconsidered disagreement is still fixed" \
    "$(row ITEM-reconsidered)" "✅ Fixed"
lacks "not recorded as skipped" "$(row ITEM-reconsidered)" "Skipped"
lacks "the abandoned rationale is not published" \
    "$(row ITEM-reconsidered)" "On reflection"
check "the fix is committed, not discarded" \
    "$(commit_files 'Fix after reconsidering')" "src/main.rs"

check "tree left clean" "$(git -C "${D}" status --porcelain)" ""
check "ignored build output survives" "$(cat "${D}/target/instar")" "expensive"

# The helpers are resolved from TOOLS_DIR, which in CI is a sparse
# checkout of the base branch. A missing one must stop the run: falling
# back to whatever Claude staged is #510, skipping the reset commits
# one item's work under another's id, and without the result reader
# `set -e` kills the run partway through the first item and takes the
# summary table with it.
start "a TOOLS_DIR missing a helper refuses to start"
setup
for HELPER in stage-autofix-changes.sh reset-autofix-worktree.sh \
        autofix-artifact-patterns.sh claude-result.sh; do
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

# The reader is written never to fail, and is guarded anyway: this
# loop is `set -e` with no continue-on-error above it, so one non-zero
# exit would abandon the run mid-item and take the summary table with
# it -- which is exactly what the startup helper check exists to
# prevent, arriving through the call site instead.
start "a failing result reader degrades instead of aborting the run"
setup
BADREADER="${WORK}/tools-broken-reader"
rm -rf "${BADREADER}"
cp -r "${REPO_ROOT}/tools" "${BADREADER}"
printf '#!/bin/sh\nexit 3\n' > "${BADREADER}/ci/claude-result.sh"
chmod +x "${BADREADER}/ci/claude-result.sh"
READER_OUT="${WORK}/out-bad-reader"
rm -rf "${READER_OUT}"
run "${BADREADER}" --output-dir "${READER_OUT}"
check "exit 0" "${RC}" "0"
contains "says the reader failed" "${OUT}" "Result reader failed"
contains "the summary table still reaches the end" "$(row ITEM-reconsidered)" \
    "ITEM-reconsidered"
contains "the output file names the failure" \
    "$(cat "${READER_OUT}/claude-output-1.txt")" "The result reader exited 3"
contains "the output file points at the raw stream" \
    "$(cat "${READER_OUT}/claude-output-1.txt")" "claude-stream-1.jsonl"

# Staging swept every untracked path in the repo, so anything sitting
# in the tree when an item finished was attributed to that item and
# committed. --ci because the run refuses a dirty tree otherwise, which
# is the other half of the same problem.
start "a file the run did not create is never committed"
setup
echo 'mine' > "${D}/scratch.txt"
run "${REPO_ROOT}/tools" --ci
check "exit 0" "${RC}" "0"
check "scratch file not committed" "$(added_commits scratch.txt | wc -l)" "0"
contains "the item that did create one still works" \
    "$(row ITEM-newfile)" "src/helper.rs"

# The capture writes stdout to a JSONL stream and stderr to its own
# file, and neither is piped -- a pipe would hand the `if` below
# `tee`'s exit status instead of `claude`'s, and a run that died would
# be reported as one that simply said nothing. The reduction runs
# before the status is acted on, so the stderr of a run that failed is
# still what a maintainer reads in the artifacts.
start "a claude that exits non-zero is an item-level error"
setup
FAILING="${WORK}/claude-failing"
printf '#!/bin/sh\necho "boom: model unavailable" >&2\nexit 1\n' > "${FAILING}"
chmod +x "${FAILING}"
FAILING_OUT="${WORK}/out-failing"
rm -rf "${FAILING_OUT}"
set +e
OUT="$(TOOLS_DIR="${REPO_ROOT}/tools" WORK_DIR="${D}" CLAUDE_BIN="${FAILING}" \
    "${ADDRESS}" --pr 511 --review-json "${REVIEW}" \
    --output-dir "${FAILING_OUT}" 2>&1)"
RC=$?
set -e
check "exit 0" "${RC}" "0"
contains "reports an error" "$(row ITEM-tracked)" "❌ Error"
contains "names the failure" "$(row ITEM-tracked)" "Claude execution failed"
check "made no commit" "$(added_commits | wc -l)" "0"
contains "stderr reaches the reported output" \
    "$(cat "${FAILING_OUT}/claude-output-1.txt")" "boom: model unavailable"

# The reset runs `git clean -fd` over the whole work tree, so an output
# directory inside it is deleted partway through the run: the next
# item's jq cannot find its file and set -e takes the summary with it.
start "an output directory inside the work tree is refused"
setup
run "${REPO_ROOT}/tools" --output-dir "${D}/address-output"
check "refuses" "${RC}" "1"
contains "says why" "${OUT}" "inside the work tree"
check "made no commit" "$(added_commits | wc -l)" "0"

# Against a fresh CI checkout the reset is right. Against a
# maintainer's checkout it would discard work the script was never
# offered, the first time an item is skipped.
start "a dirty work tree is refused outside CI mode"
setup
echo 'work in progress' > "${D}/src/main.rs"
run "${REPO_ROOT}/tools"
check "refuses" "${RC}" "1"
contains "says why" "${OUT}" "uncommitted changes"
check "local edit survives" "$(cat "${D}/src/main.rs")" "work in progress"
run "${REPO_ROOT}/tools" --ci
check "--ci proceeds anyway" "${RC}" "0"

if [ "${FAILURES}" -ne 0 ]; then
    echo "${FAILURES} failure(s)" >&2
    exit 1
fi

echo "all address-comments staging tests passed"
