#!/usr/bin/env bash
#
# Tests for tools/audit/diff-added-lines.awk.
#
# What is being guarded: the line numbers wave 2's unsafe, unwrap and
# dead-code checks report. They used to come from `grep -n` over the
# concatenated diff stream, which is a position in a temporary
# artefact rather than a location in any file. A reader cannot tell a
# plausible wrong number from a right one by looking, which is exactly
# the case for testing it rather than reading it.
#
# The decisive case is the last one: a real commit from this
# repository's history, where every reported line is checked against
# the file on disk. The synthetic cases cover the shapes a hand-built
# fixture can hold and real history may not -- a hunk with no count on
# its +new field, removed lines (which must not advance the counter),
# a second file in the same diff, and a "\ No newline at end of file"
# marker.

set -uo pipefail

# No repository root is needed: every case here builds its own fixture
# or feeds the program a literal diff on stdin.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
AWK_PROG="${SCRIPT_DIR}/diff-added-lines.awk"

WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"' EXIT

FAILURES=0

start() { echo "--- $1"; }
ok() { echo "    ok: $1"; }
fail() { echo "    FAIL: $1" >&2; FAILURES=$((FAILURES + 1)); }

run() { awk -f "${AWK_PROG}"; }

expect_output() {
    local name="$1" expected="$2" actual="$3"
    if [ "${actual}" = "${expected}" ]; then
        ok "${name}"
    else
        fail "${name}"
        echo "      expected:" >&2
        # shellcheck disable=SC2001  # sed anchors per line; bash patterns cannot
        sed 's/^/        /' <<< "${expected:-<nothing>}" >&2
        echo "      actual:" >&2
        # shellcheck disable=SC2001
        sed 's/^/        /' <<< "${actual:-<nothing>}" >&2
    fi
}

start "a simple hunk numbers added lines from the hunk header"
actual="$(run <<'EOF'
diff --git a/a.rs b/a.rs
index 1111111..2222222 100644
--- a/a.rs
+++ b/a.rs
@@ -10,3 +10,5 @@ fn existing() {
 context one
+added at 11
+added at 12
 context two
EOF
)"
expect_output "two added lines at 11 and 12" \
"a.rs:11: added at 11
a.rs:12: added at 12" "${actual}"

start "removed lines do not advance the new-file counter"
actual="$(run <<'EOF'
diff --git a/b.rs b/b.rs
--- a/b.rs
+++ b/b.rs
@@ -20,4 +20,3 @@
 context at 20
-removed
-removed too
+added at 21
EOF
)"
expect_output "the added line is 21, not 23" "b.rs:21: added at 21" "${actual}"

start "a hunk header with no count on +new is read as a single line"
actual="$(run <<'EOF'
diff --git a/c.rs b/c.rs
--- a/c.rs
+++ b/c.rs
@@ -0,0 +1 @@
+only line
EOF
)"
expect_output "single-line hunk numbers from 1" "c.rs:1: only line" "${actual}"

start "a second file in the same diff resets the path and the counter"
actual="$(run <<'EOF'
diff --git a/d.rs b/d.rs
--- a/d.rs
+++ b/d.rs
@@ -1,1 +1,2 @@
 keep
+in d at 2
diff --git a/e.rs b/e.rs
--- a/e.rs
+++ b/e.rs
@@ -100,1 +100,2 @@
 keep
+in e at 101
EOF
)"
expect_output "each file is numbered in its own right" \
"d.rs:2: in d at 2
e.rs:101: in e at 101" "${actual}"

start "the +++ header is never mistaken for an added line"
actual="$(run <<'EOF'
diff --git a/f.rs b/f.rs
--- a/f.rs
+++ b/f.rs
@@ -1,0 +1,1 @@
+real content
EOF
)"
expect_output "only the content line is emitted" "f.rs:1: real content" "${actual}"

start "a no-newline marker and index lines are ignored"
actual="$(run <<'EOF'
diff --git a/g.rs b/g.rs
index abc..def 100644
--- a/g.rs
+++ b/g.rs
@@ -1,1 +1,1 @@
-old
+new
\ No newline at end of file
EOF
)"
expect_output "the marker is not content" "g.rs:1: new" "${actual}"

start "a deleted file's added-line side is /dev/null and emits nothing"
actual="$(run <<'EOF'
diff --git a/h.rs b/h.rs
deleted file mode 100644
--- a/h.rs
+++ /dev/null
@@ -1,2 +0,0 @@
-gone one
-gone two
EOF
)"
expect_output "a pure deletion emits no added lines" "" "${actual}"

# The decisive case: a generated commit, with every reported line
# checked against the file it names. It is built here rather than
# taken from this repository's history because the CI job that runs
# this test checks out at fetch-depth 1, where a history-dependent
# case takes its SKIP branch -- and a SKIP that always fires is a pass
# standing in for a check that never ran, which is the defect the
# whole phase is about. A generated commit also lets the fixture carry
# the shapes real history here does not: a path with a space in it,
# and a line whose content starts with "++ ".
start "every line reported for a generated commit matches the file on disk"
FIX="${WORK}/fixture"
mkdir -p "${FIX}"
SPACED='f2 with space.rs'
(
    cd "${FIX}" || exit 1
    git init -q -b main .
    git config user.email 'test@example.com'
    git config user.name 'Diff Added Lines Test'
    git config commit.gpgsign false
    # A base with enough lines that the second commit produces several
    # hunks in one file, which is what makes the per-hunk line
    # bookkeeping worth testing.
    { for i in $(seq 1 60); do echo "base line ${i}"; done; } > wide.rs
    printf 'unchanged\n' > keep.rs
    git add -A
    git commit -q -m base

    # Three separated edits in one file -> three hunks.
    sed -i '5a inserted after five' wide.rs
    sed -i '31a inserted after thirty one' wide.rs
    printf 'appended at the end\n' >> wide.rs
    # A new file whose name contains a space: git emits "+++ b/f2 with
    # space.rs" followed by a TAB, and awk field splitting used to cut
    # it at the first space.
    printf 'spaced one\nspaced two\n' > "${SPACED}"
    # A line whose content starts with "++ ", so the diff body carries
    # "+++ y" -- which a blind /^\+\+\+ / match reads as a file
    # header, dropping the line and misattributing the rest.
    printf '++ y\nafter the plus plus\n' > plusplus.md
    # A deletion, which must not advance the new-file counter.
    printf 'unchanged\n' > keep.rs
    sed -i '1d' keep.rs
    printf 'replacement\n' >> keep.rs
    git add -A
    git commit -q -m 'several hunks, a spaced path and a ++ line'
) || { fail "could not build the fixture repository"; echo "1 failure(s)" >&2; exit 1; }

checked=0
mismatched=0
seen_spaced=0
seen_plusplus=0
while IFS= read -r line; do
    [ -z "${line}" ] && continue
    # Split on the LAST two colons rather than the first: the path can
    # contain a colon, and splitting on the first would misparse it.
    content="${line#*: }"
    prefix="${line%": ${content}"}"
    num="${prefix##*:}"
    file="${prefix%":${num}"}"
    case "${file}" in
        "${SPACED}") seen_spaced=1 ;;
        plusplus.md) seen_plusplus=1 ;;
    esac
    [ -f "${FIX}/${file}" ] || { fail "reported a path that does not exist: ${file}"; continue; }
    on_disk="$(sed -n "${num}p" "${FIX}/${file}")"
    checked=$((checked + 1))
    if [ "${on_disk}" != "${content}" ]; then
        mismatched=$((mismatched + 1))
        [ "${mismatched}" -le 3 ] && {
            echo "      ${file}:${num}" >&2
            echo "        reported: ${content}" >&2
            echo "        on disk:  ${on_disk}" >&2
        }
    fi
done < <(git -C "${FIX}" diff HEAD~1 HEAD | run)

if [ "${checked}" -eq 0 ]; then
    fail "nothing was checked, so this case proved nothing"
elif [ "${mismatched}" -ne 0 ]; then
    fail "${mismatched} of ${checked} reported lines do not match the file"
else
    ok "${checked} reported line(s) all match the file on disk"
fi

# The fixture only proves what it contains, so confirm the two shapes
# it was built for actually reached the output.
if [ "${seen_spaced}" -eq 1 ]; then
    ok "the spaced path was reported in full, not cut at the space"
else
    fail "no hit was attributed to '${SPACED}'; the fixture or the parse is wrong"
fi
if [ "${seen_plusplus}" -eq 1 ]; then
    ok "the file with a '++ ' line was not mistaken for a header"
else
    fail "no hit was attributed to plusplus.md; a '+++ ' body line was read as a header"
fi

echo
if [ "${FAILURES}" -ne 0 ]; then
    echo "${FAILURES} failure(s)" >&2
    exit 1
fi
echo "all diff-added-lines tests passed"
