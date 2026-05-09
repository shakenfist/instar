#!/usr/bin/env bash
# wave1.sh -- pre-push audit, mechanical wave.
#
# Runs the build, lint, and test verification described in
# PUSH-TEMPLATE.md wave 1. Single approval, single script,
# structured exit code.
#
# Style conformance is intentionally kept narrow here -- only the
# fully-mechanical checks live in this script. Anything needing
# judgment (call-table boundary discipline, missed abstractions,
# documentation alignment, security analysis) stays as a wave 2
# sub-agent.
#
# Usage: tools/audit/wave1.sh
# Run from the worktree root.

set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$REPO_ROOT" || exit 6

red() { printf '\033[31m%s\033[0m\n' "$*"; }
green() { printf '\033[32m%s\033[0m\n' "$*"; }
bold() { printf '\033[1m%s\033[0m\n' "$*"; }

bold "=== wave 1a: pre-commit ==="
if ! pre-commit run --all-files; then
    red "FAIL: pre-commit"
    exit 1
fi
green "PASS: pre-commit"
echo

bold "=== wave 1a: rustfmt + clippy via the rust-lint container ==="
if ! ./scripts/check-rust.sh check; then
    red "FAIL: rustfmt/clippy"
    exit 2
fi
green "PASS: rustfmt + clippy"
echo

bold "=== wave 1a: make instar (full devcontainer build) ==="
if ! make instar; then
    red "FAIL: make instar"
    exit 3
fi
green "PASS: make instar"
echo

bold "=== wave 1a: make check-binary-sizes (384KB cap) ==="
if ! make check-binary-sizes; then
    red "FAIL: guest binary size cap exceeded"
    exit 4
fi
green "PASS: make check-binary-sizes"
echo

bold "=== wave 1a: make test-rust (workspace unit tests) ==="
if ! make test-rust; then
    red "FAIL: make test-rust"
    exit 5
fi
green "PASS: make test-rust"
echo

bold "=== wave 1b: mechanical style checks ==="

# 1. Long-line check: warn on Rust source lines over 120 chars in
#    changed files relative to develop. Non-fatal -- purely
#    informational. Skip if develop is not a known ref (e.g. shallow
#    clone in CI).
if git rev-parse --verify develop >/dev/null 2>&1; then
    # -z / -0: NUL-delimited so filenames with spaces or special
    # characters survive the xargs split.
    LONG_LINES=$(git diff develop...HEAD -z --name-only -- '*.rs' \
        | xargs -r -0 awk 'length > 120 {print FILENAME":"NR": "length" chars"}' \
        2>/dev/null || true)
    if [[ -n "$LONG_LINES" ]]; then
        echo "ADVISORY: lines over 120 chars in changed Rust files:"
        echo "$LONG_LINES" | head -20
    fi
fi

# 2. Inline-script check: warn on multi-line `run: |` blocks in
#    GitHub Actions workflow files (CLAUDE.md says scripts >5 lines
#    should live in tools/). Heuristic: count consecutive non-blank
#    lines under any `run: |` and flag blocks of >5 lines.
INLINE=$(awk '
    /run: \|/ { in_run=1; count=0; start=NR; file=FILENAME; next }
    in_run && /^[[:space:]]*$/ { in_run=0; if (count > 5) print file":"start": run-block of "count" lines"; next }
    in_run && /^[a-zA-Z-]+:/ { in_run=0; if (count > 5) print file":"start": run-block of "count" lines"; next }
    in_run { count++ }
    END { if (in_run && count > 5) print file":"start": run-block of "count" lines" }
' .github/workflows/*.yml 2>/dev/null || true)
if [[ -n "$INLINE" ]]; then
    echo "ADVISORY: long inline scripts in CI workflows (move to tools/):"
    echo "$INLINE" | head -20
fi

# 3. Adversarial / CVE fixture check: any new test asset committed
#    under src/, tests/, or scripts/ that looks like a malicious
#    image probably belongs in shakenfist/instar-testdata, not here.
if git rev-parse --verify develop >/dev/null 2>&1; then
    BADPLACE=$(git diff develop...HEAD --name-only --diff-filter=A \
        | grep -E '^(src|tests|scripts)/.*(adversarial|malicious|cve|exploit)' \
        || true)
    if [[ -n "$BADPLACE" ]]; then
        echo "ADVISORY: adversarial/CVE assets added under src/tests/scripts:"
        echo "$BADPLACE"
        echo "(consider moving to shakenfist/instar-testdata)"
    fi
fi

green "PASS: wave 1b mechanical"
echo

bold "=== wave 1 complete ==="
green "all mechanical checks passed; proceed to wave 2 (judgment agents)"
exit 0
