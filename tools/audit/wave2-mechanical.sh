#!/usr/bin/env bash
# wave2-mechanical.sh -- pre-push audit, scriptable parts of wave 2.
#
# Runs the mechanical subset of wave 2 checks. The judgment-needing
# parts (missed abstractions, doc accuracy, security analysis) still
# need agents (waves 2a-judgment, 2b, 2c, 2d).
#
# Reports findings as plain text; never exits non-zero unless the
# script itself failed. Read the output and decide what to fix.
#
# Usage: tools/audit/wave2-mechanical.sh
# Run from the worktree root.

set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$REPO_ROOT" || exit 1

bold() { printf '\033[1m%s\033[0m\n' "$*"; }

bold "=== wave 2a: TODO / FIXME / HACK in changed files ==="
if git rev-parse --verify develop >/dev/null 2>&1; then
    HITS=$(git diff develop...HEAD --name-only \
        | xargs -r grep -nH -E '\b(TODO|FIXME|HACK|XXX)\b' 2>/dev/null \
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
if git rev-parse --verify develop >/dev/null 2>&1; then
    git diff develop...HEAD -- '*.rs' \
        | grep -E '^\+.*allow\(dead_code\)' \
        | head -20
    echo "(if any of the above were added in this branch, consider whether the dead code can be deleted instead)"
fi
echo

bold "=== wave 2b: new test count in changed files ==="
if git rev-parse --verify develop >/dev/null 2>&1; then
    NEW_TESTS=$(git diff develop...HEAD -- '*.rs' \
        | grep -cE '^\+\s*#\[test\]' \
        || true)
    echo "new #[test] functions: $NEW_TESTS"
    NEW_RS=$(git diff develop...HEAD --name-only -- '*.rs' | wc -l)
    echo "rust files changed: $NEW_RS"
fi
echo

bold "=== wave 2c: doc files touched in changed set ==="
if git rev-parse --verify develop >/dev/null 2>&1; then
    DOCS=$(git diff develop...HEAD --name-only \
        | grep -E '^(README\.md|ARCHITECTURE\.md|AGENTS\.md|CHANGELOG\.md|docs/)' \
        || true)
    if [[ -n "$DOCS" ]]; then
        echo "$DOCS"
    else
        echo "WARNING: no documentation files touched. Did the changes merit doc updates?"
    fi
fi
echo

bold "=== wave 2d: VMM unsafe blocks added (host-side, higher risk) ==="
if git rev-parse --verify develop >/dev/null 2>&1; then
    VMM_UNSAFE=$(git diff develop...HEAD -- 'src/vmm/**/*.rs' \
        | grep -nE '^\+.*\bunsafe\b' \
        || true)
    if [[ -n "$VMM_UNSAFE" ]]; then
        echo "$VMM_UNSAFE" | head -10
        echo "(VMM unsafe blocks bypass the KVM sandbox; each must have a // SAFETY: comment)"
    else
        echo "(none)"
    fi
fi
echo

bold "=== wave 2d: guest-side unsafe blocks added (sandboxed, lower risk) ==="
if git rev-parse --verify develop >/dev/null 2>&1; then
    GUEST_UNSAFE=$(git diff develop...HEAD -- \
            'src/core/**/*.rs' \
            'src/operations/**/*.rs' \
            'src/crates/**/*.rs' \
            'src/shared/**/*.rs' \
        | grep -nE '^\+.*\bunsafe\b' \
        || true)
    if [[ -n "$GUEST_UNSAFE" ]]; then
        echo "$GUEST_UNSAFE" | head -10
    else
        echo "(none)"
    fi
fi
echo

bold "=== wave 2d: new .unwrap() / .expect() in changed code ==="
if git rev-parse --verify develop >/dev/null 2>&1; then
    git diff develop...HEAD -- '*.rs' \
        | grep -nE '^\+.*\.(unwrap|expect)\s*\(' \
        | head -20 \
        || echo "(none)"
    echo "(review each: are they panic-safe given the inputs? unwrap in VMM I/O paths is a denial-of-service risk)"
fi
echo

bold "=== wave 2d: adversarial / CVE fixtures added under src/tests/scripts ==="
if git rev-parse --verify develop >/dev/null 2>&1; then
    BADPLACE=$(git diff develop...HEAD --name-only --diff-filter=A \
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
