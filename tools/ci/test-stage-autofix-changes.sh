#!/usr/bin/env bash
#
# Tests for tools/ci/stage-autofix-changes.sh.
#
# The staging this covers used to be a bare `git add -u` in inline
# workflow YAML that only ever ran during a live daily autofix run, and
# it was in the wrong step for months without anything noticing. These
# cases pin the states the working tree can be in when Claude Code hands
# back control: nothing changed, a tracked file edited or deleted, and
# each of the things the script refuses rather than guesses at.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
STAGE="${REPO_ROOT}/tools/ci/stage-autofix-changes.sh"

WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"' EXIT

# `git rev-parse --is-inside-work-tree` walks up through parents, so if
# TMPDIR is inside a checkout (some CI and container setups put it
# there) the "not a work tree" case would find that checkout and the
# scratch repos would be nested. Stop the walk at the scratch root.
export GIT_CEILING_DIRECTORIES="${WORK}"

REFUSED=3

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

# A scratch repo with one commit and the ignore rules that matter.
setup() {
    D="${WORK}/repo"
    rm -rf "${D}"
    mkdir -p "${D}"
    git -C "${D}" init -q
    git -C "${D}" config user.email bot@example.com
    git -C "${D}" config user.name bot
    mkdir -p "${D}/src/crates/qcow2" "${D}/tests" "${D}/docs"
    echo 'fn main() {}' > "${D}/src/main.rs"
    echo 'fn parse() {}' > "${D}/src/crates/qcow2/lib.rs"
    printf '**/target/\n**/*.bin\n*.swp\n' > "${D}/.gitignore"
    git -C "${D}" add -A
    git -C "${D}" commit -qm 'base'
    BASE="${WORK}/baseline.txt"
    rm -f "${BASE}"
}

# Run and capture both output and status without tripping `set -e`.
run() {
    set +e
    OUT="$("${STAGE}" "$@" 2>&1)"
    RC=$?
    set -e
}

stage() { run --baseline "${BASE}" "${D}"; }
snapshot() { run --snapshot "${BASE}" "${D}"; }
staged() { git -C "${D}" diff --cached --name-only | LC_ALL=C sort | tr '\n' ' ' | sed 's/ $//'; }

start "a clean tree stages nothing and says so"
setup
snapshot
stage
check "exit 0" "${RC}" "0"
check "nothing staged" "$(staged)" ""
contains "reports the empty case" "${OUT}" "Nothing staged"

start "a tracked modification is staged"
setup
snapshot
echo 'fn main() { fixed(); }' > "${D}/src/main.rs"
stage
check "exit 0" "${RC}" "0"
check "modified file staged" "$(staged)" "src/main.rs"

start "a tracked deletion is staged"
setup
snapshot
rm "${D}/src/crates/qcow2/lib.rs"
stage
check "exit 0" "${RC}" "0"
check "deletion staged" "$(staged)" "src/crates/qcow2/lib.rs"

start "a file already staged by Claude stays staged"
setup
snapshot
echo 'fn main() { fixed(); }' > "${D}/src/main.rs"
git -C "${D}" add src/main.rs
stage
check "exit 0" "${RC}" "0"
check "still staged, once" "$(staged)" "src/main.rs"

# The whole point of the design: a created file is refused by name
# rather than classified. Staging it wrong ships a branch that does not
# compile behind a PR claiming the build passed.
start "a newly created file is refused, not staged"
setup
snapshot
echo 'fn t() {}' > "${D}/tests/regression_qcow2.rs"
echo 'fn main() { fixed(); }' > "${D}/src/main.rs"
stage
check "exit ${REFUSED}" "${RC}" "${REFUSED}"
contains "names the file" "${OUT}" "tests/regression_qcow2.rs"
contains "says why" "${OUT}" "would not reach the pull request"
check "the tracked edit is still staged for the report" "$(staged)" "src/main.rs"

start "a file created anywhere is refused, not just under a source root"
setup
snapshot
echo 'scratch' > "${D}/notes.txt"
stage
check "exit ${REFUSED}" "${RC}" "${REFUSED}"
contains "names it" "${OUT}" "notes.txt"

# pre-commit is in the prompt and its hooks leave these behind, so
# refusing on them would refuse routine runs.
start "editor and merge artifacts do not cause a refusal"
setup
snapshot
echo x > "${D}/src/main.rs~"
echo x > "${D}/src/main.rs.orig"
echo x > "${D}/src/main.rs.rej"
echo x > "${D}/src/main.rs.bak"
echo x > "${D}/src/.#main.rs"
stage
check "exit 0" "${RC}" "0"
contains "reported as artifacts" "${OUT}" "editor or merge artifact(s)"
lacks "not refused" "${OUT}" "REFUSED"

# git hides ignored paths from the untracked listing entirely, and
# `**/*.bin` is exactly what a fuzz-crash fixture gets called.
start "a new gitignored file is refused"
setup
snapshot
printf 'x' > "${D}/tests/crash.bin"
stage
check "exit ${REFUSED}" "${RC}" "${REFUSED}"
contains "names it" "${OUT}" "tests/crash.bin"
contains "says .gitignore hides it" "${OUT}" ".gitignore hides"

# src/fuzz/.gitignore ignores `corpus/` and `artifacts/` as whole
# directories, which is where a fuzz-crash input would land.
start "a new file inside a wholly-ignored directory is refused"
setup
mkdir -p "${D}/src/fuzz"
printf 'corpus/\n' > "${D}/src/fuzz/.gitignore"
git -C "${D}" add src/fuzz/.gitignore
git -C "${D}" commit -qm fuzzignore
snapshot
mkdir -p "${D}/src/fuzz/corpus/fuzz_qcow2_header"
echo crashbytes > "${D}/src/fuzz/corpus/fuzz_qcow2_header/crash-abc"
stage
check "exit ${REFUSED}" "${RC}" "${REFUSED}"
contains "names the collapsed directory" "${OUT}" "src/fuzz/corpus/"

# Build output that predates the attempt is not the attempt's doing.
# Without this the stager would refuse every run, since the prompt
# tells Claude to run `make instar`.
start "ignored build output present before the attempt is not refused"
setup
mkdir -p "${D}/src/target/debug"
echo x > "${D}/src/target/debug/instar"
echo x > "${D}/src/core.bin"
snapshot
echo 'fn main() { fixed(); }' > "${D}/src/main.rs"
stage
check "exit 0" "${RC}" "0"
check "the fix is staged" "$(staged)" "src/main.rs"
lacks "not refused" "${OUT}" "REFUSED"

start "ignored output created during the attempt is still refused"
setup
snapshot
mkdir -p "${D}/src/target/debug"
echo x > "${D}/src/target/debug/instar"
stage
check "exit ${REFUSED}" "${RC}" "${REFUSED}"
contains "names the collapsed tree" "${OUT}" "src/target/"

start "a gitignored editor artifact is not a refusal"
setup
snapshot
echo x > "${D}/src/main.rs.swp"
stage
check "exit 0" "${RC}" "0"
contains "reported as an artifact" "${OUT}" "editor or merge artifact(s)"

start "without a baseline no ignored comparison is made"
setup
printf 'x' > "${D}/tests/crash.bin"
run "${D}"
check "exit 0" "${RC}" "0"
lacks "nothing about the ignored file" "${OUT}" "crash.bin"

# `git push` with the GITHUB_TOKEN actions/checkout persists is refused
# for any commit touching .github/workflows/, and that failure lands
# two hours downstream at the push.
start "a workflow edit is unstaged and refused"
setup
mkdir -p "${D}/.github/workflows"
echo 'name: x' > "${D}/.github/workflows/ci.yml"
git -C "${D}" add .github/workflows/ci.yml
git -C "${D}" commit -qm workflow
snapshot
echo 'name: edited' > "${D}/.github/workflows/ci.yml"
echo 'fn main() { fixed(); }' > "${D}/src/main.rs"
stage
check "exit ${REFUSED}" "${RC}" "${REFUSED}"
check "only the source file staged" "$(staged)" "src/main.rs"
contains "names the workflow" "${OUT}" ".github/workflows/ci.yml"

# An exclude pathspec declines to add a path; it does not remove what
# is already in the index, and Claude does sometimes stage.
start "a workflow edit Claude staged itself is actively unstaged"
setup
mkdir -p "${D}/.github/workflows"
echo 'name: x' > "${D}/.github/workflows/ci.yml"
git -C "${D}" add .github/workflows/ci.yml
git -C "${D}" commit -qm workflow
snapshot
echo 'name: edited' > "${D}/.github/workflows/ci.yml"
git -C "${D}" add .github/workflows/ci.yml
stage
check "exit ${REFUSED}" "${RC}" "${REFUSED}"
check "unstaged" "$(staged)" ""
contains "names it" "${OUT}" ".github/workflows/ci.yml"

start "a new workflow file Claude staged itself is unstaged"
setup
mkdir -p "${D}/.github/workflows"
snapshot
echo 'name: new' > "${D}/.github/workflows/new.yml"
git -C "${D}" add .github/workflows/new.yml
stage
check "exit ${REFUSED}" "${RC}" "${REFUSED}"
check "unstaged" "$(staged)" ""
contains "names it" "${OUT}" ".github/workflows/new.yml"

start "--tracked-only stages tracked edits and checks nothing"
setup
snapshot
echo 'fn main() { fixed(); }' > "${D}/src/main.rs"
echo 'fn t() {}' > "${D}/tests/regression.rs"
printf 'x' > "${D}/tests/crash.bin"
run --tracked-only "${D}"
check "exit 0" "${RC}" "0"
check "only the tracked modification" "$(staged)" "src/main.rs"
lacks "no refusal" "${OUT}" "REFUSED"

start "--tracked-only still keeps workflow edits out of the index"
setup
mkdir -p "${D}/.github/workflows"
echo 'name: x' > "${D}/.github/workflows/ci.yml"
git -C "${D}" add .github/workflows/ci.yml
git -C "${D}" commit -qm workflow
echo 'name: edited' > "${D}/.github/workflows/ci.yml"
git -C "${D}" add .github/workflows/ci.yml
echo 'fn main() { fixed(); }' > "${D}/src/main.rs"
run --tracked-only "${D}"
check "exit 0" "${RC}" "0"
check "workflow edit unstaged" "$(staged)" "src/main.rs"
contains "reported" "${OUT}" ".github/workflows/ci.yml"

start "--snapshot records the baseline and stages nothing"
setup
echo 'fn main() { fixed(); }' > "${D}/src/main.rs"
printf 'x' > "${D}/src/core.bin"
snapshot
check "exit 0" "${RC}" "0"
check "nothing staged" "$(staged)" ""
contains "reports the count" "${OUT}" "as the pre-attempt baseline"
check "baseline holds the ignored file" \
    "$(grep -c 'src/core.bin' "${BASE}")" "1"

start "a path with a space is refused by name"
setup
snapshot
echo x > "${D}/docs/image notes.md"
stage
check "exit ${REFUSED}" "${RC}" "${REFUSED}"
contains "names it" "${OUT}" "docs/image notes.md"

start "the zero-argument form both workflows use behaves the same"
setup
snapshot
echo 'fn main() { fixed(); }' > "${D}/src/main.rs"
set +e
OUT="$(cd "${D}" && "${STAGE}" --baseline "${BASE}" 2>&1)"
RC=$?
set -e
check "exit 0" "${RC}" "0"
check "default REPO_DIR is the cwd" "$(staged)" "src/main.rs"

start "a REPO_DIR below the top level works from the top level"
setup
snapshot
echo 'fn main() { fixed(); }' > "${D}/src/main.rs"
run --baseline "${BASE}" "${D}/src"
check "exit 0" "${RC}" "0"
check "repo-relative path staged" "$(staged)" "src/main.rs"

start "argument errors are rejected"
setup
run "${D}" extra
check "too many arguments" "${RC}" "2"
run --tracked-only "${D}" extra
check "too many arguments after a flag" "${RC}" "2"
run --snapshot
check "--snapshot with no file" "${RC}" "2"
run --baseline
check "--baseline with no file" "${RC}" "2"
# Exit 2 alone does not pin this: an unhandled flag falls through to
# REPO_DIR and fails the -d test with the same status. One argument,
# not two, or the argument-count check prints usage anyway.
run --nonsense
check "unrecognised flag" "${RC}" "2"
contains "reports usage" "${OUT}" "usage:"
run --help
check "help exits 0" "${RC}" "0"
run "${WORK}/not-a-repo"
check "missing directory" "${RC}" "2"
mkdir -p "${WORK}/plain-dir"
run "${WORK}/plain-dir"
check "not a work tree" "${RC}" "2"

if [ "${FAILURES}" -ne 0 ]; then
    echo "${FAILURES} failure(s)" >&2
    exit 1
fi

echo "all stage-autofix-changes tests passed"
