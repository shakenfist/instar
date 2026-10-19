#!/usr/bin/env bash
# wave2-mechanical.sh -- pre-push audit, scriptable parts of wave 2.
#
# Runs the mechanical subset of wave 2 checks. The judgment-needing
# parts (missed abstractions, doc accuracy, security analysis) still
# need agents (waves 2a-judgment, 2b, 2c, 2d).
#
# Reports findings as plain text; never exits non-zero on a finding,
# only if the script itself failed or the scope was misused (exit 9).
# A broken invocation is not a finding. Read the output and decide
# what to fix.
#
# Usage: tools/audit/wave2-mechanical.sh [--range REV..REV | --commits-file PATH]
# Run from the worktree root.
#
# Every check below is scoped to a set of files that audit-scope.sh
# resolves. That file is the authority on what --range and
# --commits-file mean, on the default, and on when an empty scope is
# an error; it is not restated here, because three copies of one
# policy drift. The resolved file count is printed before any check
# runs, and every check below is skipped when the scope is unresolved
# or legitimately empty.

set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$REPO_ROOT" || exit 1

# shellcheck source=tools/audit/audit-scope.sh
source "$SCRIPT_DIR/audit-scope.sh"
audit_scope_init "$@"
audit_scope_report

bold() { printf '\033[1m%s\033[0m\n' "$*"; }

# diff_added_lines -- read a unified diff on stdin and print each ADDED
# line as "<path>:<line>: <content>". The awk program is a separate
# file so tools/audit/test-diff-added-lines.sh can exercise it against
# fixtures; it documents why a stream offset was the wrong thing to
# report and what the line number means for a multi-commit union.
diff_added_lines() {
    awk -f "$SCRIPT_DIR/diff-added-lines.awk"
}

# show_capped CAP CONTENT -- print CONTENT (one hit per line) capped
# at CAP lines, preceded by a line naming the true total; or "(none)"
# when CONTENT is empty.
#
# It printed nothing at all for empty content when it was introduced,
# which left two of the four sections below showing only their hint
# line while the other two said "(none)" explicitly. In an audit whose
# whole purpose is telling "nothing found" apart from "nothing
# examined", every section has to state its result.
#
# This fixes a sibling of a defect the push-audit runbook already hit at
# a smaller scale, where `head -20` cut 32 hits and hid six of them: a
# bare `head -N` silently hides everything past the cap, which at this
# audit's 55,000-line union is far more likely to bite than it did
# there. It does not change which lines are shown or the cap, only
# whether a reader can tell the list was cut.
show_capped() {
    local cap="$1" content="$2" total
    total="$(printf '%s\n' "$content" | grep -c .)"
    if [[ "$total" -eq 0 ]]; then
        echo "(none)"
        return 0
    fi
    if [[ "$total" -gt "$cap" ]]; then
        echo "showing first ${cap} of ${total}:"
    else
        echo "${total} hit(s):"
    fi
    printf '%s\n' "$content" | head -n "$cap"
}

# Deliberately whole-file, not added-lines: a TODO already sitting in
# a file this work touched is worth a reader's attention, and the
# diff-scoped checks below cover what was added. What was wrong was
# the heading, which implied every hit was new -- over a 103-file
# union most of them predate the plan.
bold "=== wave 2a: TODO / FIXME / HACK anywhere in touched files (not only added lines) ==="
if [[ "$AUDIT_SCOPE_SKIP_SCOPED" -eq 0 ]]; then
    # NUL-delimited and filtered to files still on disk: the old
    # pipeline split on whitespace (so a path with a space became two
    # unreadable paths) and sent deleted paths to grep, then discarded
    # grep's complaint -- and every other error it could raise -- with
    # 2>/dev/null.
    # shellcheck disable=SC2119  # no pathspec: whole-scope, by design
    HITS=$(audit_scope_names_existing_null \
        | xargs -r -0 grep -nH -E '\b(TODO|FIXME|HACK|XXX)\b' \
        | grep -v 'docs/plans/' \
        || true)
    if [[ -n "$HITS" ]]; then
        echo "$HITS"
    else
        echo "(none)"
    fi
fi
echo

bold "=== wave 2a: new #[allow(dead_code)] in changed files ==="
if [[ "$AUDIT_SCOPE_SKIP_SCOPED" -eq 0 ]]; then
    DEAD_CODE=$(audit_scope_diff '*.rs' \
        | diff_added_lines \
        | grep -E 'allow\(dead_code\)' \
        || true)
    show_capped 20 "$DEAD_CODE"
    if [[ -n "$DEAD_CODE" ]]; then
        echo "(if any of the above were added in this branch, consider whether the dead code can be deleted instead)"
    fi
fi
echo

bold "=== wave 2b: new test count in changed files ==="
if [[ "$AUDIT_SCOPE_SKIP_SCOPED" -eq 0 ]]; then
    NEW_TESTS=$(audit_scope_diff '*.rs' \
        | grep -cE '^\+\s*#\[test\]' \
        || true)
    echo "new #[test] functions: $NEW_TESTS"
    NEW_RS=$(audit_scope_names_all '*.rs' | wc -l)
    echo "rust files changed: $NEW_RS"
fi
echo

bold "=== wave 2c: doc files touched in changed set ==="
if [[ "$AUDIT_SCOPE_SKIP_SCOPED" -eq 0 ]]; then
    DOCS=$(audit_scope_names_all \
        | grep -E '^(README\.md|ARCHITECTURE\.md|AGENTS\.md|CHANGELOG\.md|docs/)' \
        || true)
    if [[ -n "$DOCS" ]]; then
        echo "$DOCS"
    else
        echo "WARNING: no documentation files touched. Did the changes merit doc updates?"
    fi
fi
echo

bold "=== wave 2c: phase references outside plans directories ==="
# PUSH-AUDIT.md's plan-phase-references block says the audit greps
# README.md and docs/ for a phase number, and that a line which is
# genuinely not about an implementation plan is exempted with a
# trailing marker. Without this the block described a check nobody
# ran, and a contributor reading it would reasonably assume otherwise.
PHASE_REFS=$(grep -rEni 'phase [0-9]' README.md docs/ --include='*.md' \
    | grep -v '^docs/plans/' \
    | grep -v 'audit-ok: phase-reference' \
    || true)
if [[ -n "$PHASE_REFS" ]]; then
    echo "$PHASE_REFS"
    echo "(documentation outside docs/plans/ describes what the software does, not which phase built it: describe the behaviour, link the master plan, or append '<!-- audit-ok: phase-reference -->' if the reference is not about an implementation plan)"
else
    echo "(none)"
fi
echo

bold "=== wave 2d: VMM unsafe blocks added (host-side, higher risk) ==="
if [[ "$AUDIT_SCOPE_SKIP_SCOPED" -eq 0 ]]; then
    VMM_UNSAFE=$(audit_scope_diff 'src/vmm/**/*.rs' \
        | diff_added_lines \
        | grep -E '\bunsafe\b' \
        || true)
    show_capped 10 "$VMM_UNSAFE"
    if [[ -n "$VMM_UNSAFE" ]]; then
        echo "(VMM unsafe blocks bypass the KVM sandbox; each must have a // SAFETY: comment)"
    fi
fi
echo

bold "=== wave 2d: guest-side unsafe blocks added (sandboxed, lower risk) ==="
if [[ "$AUDIT_SCOPE_SKIP_SCOPED" -eq 0 ]]; then
    # src/fuzz is named explicitly: it sits outside the main cargo
    # workspace (which is why make fuzz-build is its own wave 1 step),
    # so it is easy to leave out of a path list and nothing else here
    # would report an unsafe block added under it.
    GUEST_UNSAFE=$(audit_scope_diff \
            'src/core/**/*.rs' \
            'src/operations/**/*.rs' \
            'src/crates/**/*.rs' \
            'src/fuzz/**/*.rs' \
            'src/shared/**/*.rs' \
        | diff_added_lines \
        | grep -E '\bunsafe\b' \
        || true)
    show_capped 10 "$GUEST_UNSAFE"
fi
echo

bold "=== wave 2d: new .unwrap() / .expect() in changed code ==="
if [[ "$AUDIT_SCOPE_SKIP_SCOPED" -eq 0 ]]; then
    UNWRAP=$(audit_scope_diff '*.rs' \
        | diff_added_lines \
        | grep -E '\.(unwrap|expect)\s*\(' \
        || true)
    show_capped 20 "$UNWRAP"
    if [[ -n "$UNWRAP" ]]; then
        echo "(review each: are they panic-safe given the inputs? unwrap in VMM I/O paths is a denial-of-service risk)"
    fi
fi
echo

bold "=== wave 2d: adversarial / CVE fixtures added under src/tests/scripts ==="
if [[ "$AUDIT_SCOPE_SKIP_SCOPED" -eq 0 ]]; then
    # shellcheck disable=SC2119  # no pathspec: whole-scope, by design
    BADPLACE=$(audit_scope_names_added \
        | grep -E '^(src|tests|scripts)/.*(adversarial|malicious|cve|exploit)' \
        || true)
    if [[ -n "$BADPLACE" ]]; then
        echo "$BADPLACE"
        echo "(these belong in shakenfist/instar-testdata, not the main repo)"
    else
        echo "(none)"
    fi
fi
echo

bold "=== wave 2 mechanical complete ==="
echo "now spawn agents for the judgment-needing parts:"
echo "  2a-judgment: code quality / missed abstractions"
echo "  2b-judgment: test coverage review"
echo "  2c-judgment: doc accuracy vs code intent"
echo "  2d-judgment: security review (VMM input validation, sector bounds, decompression caps, concurrency)"
exit 0
