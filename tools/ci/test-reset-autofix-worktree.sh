#!/usr/bin/env bash
#
# Tests for tools/ci/reset-autofix-worktree.sh.
#
# The reset only runs when an item of an address-comments run is
# abandoned, inside a privileged issue_comment workflow a maintainer
# triggers by hand -- so nothing observes it unless these cases do. The
# bug it was written for (#510) hid for months in exactly that kind of
# unobserved path, and its predecessor was a bare `git checkout -- .`
# that looked like a reset and left the index untouched.
#
# Each case pins one thing the working tree can be holding when an item
# gives up, plus the one thing that has to survive.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
RESET="${REPO_ROOT}/tools/ci/reset-autofix-worktree.sh"

WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"' EXIT

# `git rev-parse --is-inside-work-tree` walks up through parents, so a
# TMPDIR inside a checkout would make the "not a work tree" case find
# that checkout instead. Stop the walk at the scratch root.
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

# A scratch repo with one commit, an ignore rule, and ignored build
# output already present -- the state a working runner is in, where
# src/target/ holds a Rust build nobody wants recreated.
setup() {
    D="${WORK}/repo"
    rm -rf "${D}"
    mkdir -p "${D}/src" "${D}/docs"
    git -C "${D}" init -q
    git -C "${D}" config user.email bot@example.com
    git -C "${D}" config user.name bot
    echo 'fn main() {}' > "${D}/src/main.rs"
    echo '# docs' > "${D}/docs/index.md"
    printf 'target/\n' > "${D}/.gitignore"
    git -C "${D}" add -A
    git -C "${D}" commit -qm 'base'
    mkdir -p "${D}/target"
    echo 'expensive' > "${D}/target/instar"
}

run() {
    set +e
    OUT="$("${RESET}" "$@" 2>&1)"
    RC=$?
    set -e
}

# Everything git can still see as a difference from HEAD, staged or
# not, plus anything untracked. Empty means the reset was complete.
dirt() {
    {
        git -C "${D}" diff HEAD --name-only
        git -C "${D}" ls-files --others --exclude-standard
    } | LC_ALL=C sort -u | tr '\n' ' ' | sed 's/ $//'
}

build_output() { cat "${D}/target/instar" 2>/dev/null || echo MISSING; }

start "a staged modification is discarded"
setup
echo 'fn main() { changed(); }' > "${D}/src/main.rs"
git -C "${D}" add src/main.rs
run "${D}"
check "exit 0" "${RC}" "0"
check "nothing left" "$(dirt)" ""
check "file restored" "$(cat "${D}/src/main.rs")" "fn main() {}"

start "an unstaged modification is discarded"
setup
echo 'fn main() { changed(); }' > "${D}/src/main.rs"
run "${D}"
check "exit 0" "${RC}" "0"
check "nothing left" "$(dirt)" ""
check "file restored" "$(cat "${D}/src/main.rs")" "fn main() {}"

# The case the old `git checkout -- .` reset could not handle, and the
# one that made the leak reachable once CI started staging for Claude.
start "a staged new file is removed"
setup
echo 'new' > "${D}/src/added.rs"
git -C "${D}" add src/added.rs
run "${D}"
check "exit 0" "${RC}" "0"
check "nothing left" "$(dirt)" ""
check "file gone" "$([ -e "${D}/src/added.rs" ] && echo present || echo gone)" "gone"

start "an untracked new file is removed"
setup
echo 'new' > "${D}/src/added.rs"
mkdir -p "${D}/src/newdir"
echo 'new' > "${D}/src/newdir/also.rs"
run "${D}"
check "exit 0" "${RC}" "0"
check "nothing left" "$(dirt)" ""
check "file gone" "$([ -e "${D}/src/added.rs" ] && echo present || echo gone)" "gone"
check "new directory gone" \
    "$([ -e "${D}/src/newdir" ] && echo present || echo gone)" "gone"

start "a staged deletion is restored"
setup
git -C "${D}" rm -q docs/index.md
run "${D}"
check "exit 0" "${RC}" "0"
check "nothing left" "$(dirt)" ""
check "file back" "$(cat "${D}/docs/index.md")" "# docs"

# `git clean` deliberately has no -x. Recreating src/target/ is a full
# Rust build, and nothing stages an ignored path, so it is not what
# leaks between items.
start "ignored build output survives"
setup
echo 'fn main() { changed(); }' > "${D}/src/main.rs"
echo 'stale' > "${D}/target/leftover"
run "${D}"
check "exit 0" "${RC}" "0"
check "nothing left" "$(dirt)" ""
check "build output kept" "$(build_output)" "expensive"
check "ignored leftover kept" \
    "$([ -e "${D}/target/leftover" ] && echo present || echo gone)" "present"

start "everything at once"
setup
echo 'fn main() { changed(); }' > "${D}/src/main.rs"
git -C "${D}" add src/main.rs
echo '# edited' > "${D}/docs/index.md"
echo 'new' > "${D}/src/added.rs"
git -C "${D}" add src/added.rs
echo 'new' > "${D}/untracked.txt"
run "${D}"
check "exit 0" "${RC}" "0"
check "nothing left" "$(dirt)" ""
check "build output kept" "$(build_output)" "expensive"

# The caller supports a WORK_DIR pointing anywhere, while the stager
# anchors itself at the top level and the index check is repo-wide. If
# this reset stayed scoped to the cwd, an edit outside the given
# subdirectory would be staged, seen as a change, and left behind for
# the next item to commit.
start "a subdirectory argument still cleans the whole repo"
setup
echo 'fn main() { changed(); }' > "${D}/src/main.rs"
git -C "${D}" add src/main.rs
echo 'new' > "${D}/untracked.txt"
run "${D}/docs"
check "exit 0" "${RC}" "0"
check "nothing left" "$(dirt)" ""
check "outside file restored" "$(cat "${D}/src/main.rs")" "fn main() {}"

start "argument handling"
setup
run --nonsense
check "unrecognised flag" "${RC}" "2"
contains "reports usage" "${OUT}" "usage:"
run "${D}" extra
check "too many arguments" "${RC}" "2"
run --help
check "help exits 0" "${RC}" "0"
contains "help reports usage" "${OUT}" "usage:"
run "${WORK}/not-a-repo"
check "missing directory" "${RC}" "2"
mkdir -p "${WORK}/plain-dir"
run "${WORK}/plain-dir"
check "not a work tree" "${RC}" "2"

if [ "${FAILURES}" -ne 0 ]; then
    echo "${FAILURES} failure(s)" >&2
    exit 1
fi

echo "all reset-autofix-worktree tests passed"
