#!/usr/bin/env bash
# wave1.sh -- pre-push audit, mechanical wave.
#
# Runs the build, lint, and test verification described in
# PUSH-AUDIT.md wave 1. Single approval, single script,
# structured exit code.
#
# Style conformance is intentionally kept narrow here -- only the
# fully-mechanical checks live in this script. Anything needing
# judgment (call-table boundary discipline, missed abstractions,
# documentation alignment, security analysis) stays as a wave 2
# sub-agent.
#
# Usage: tools/audit/wave1.sh [--range REV..REV | --commits-file PATH]
# Run from the worktree root.
#
# The mechanical style checks in wave 1b (long lines in changed Rust
# files, adversarial fixtures added in the wrong repo) are scoped to a
# set of files that audit-scope.sh resolves. That file is the authority
# on what --range and --commits-file mean, on the default, and on when
# an empty scope is an error; it is not restated here, because three
# copies of one policy drift.
#
# What is specific to this script: a misused or empty explicit scope
# exits 9 before any check runs, so a wrong invocation costs nothing.
# An unresolved or legitimately empty default skips wave 1b's two
# scoped checks with a warning and leaves every other wave 1 check --
# pre-commit, the build, the test suite -- running.

set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$REPO_ROOT" || exit 6

# shellcheck source=tools/audit/audit-scope.sh
source "$SCRIPT_DIR/audit-scope.sh"
audit_scope_init "$@"
audit_scope_report

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

# make fuzz-build compiles every libFuzzer target (cargo fuzz build
# --bins). The fuzz crate (src/fuzz) is OUTSIDE the main cargo
# workspace, so `make instar` / `make test-rust` / check-rust.sh do
# NOT build it -- a fuzz target can silently drift out of sync with a
# workspace struct change (e.g. a new *Opts/*Config field) and only
# fail in the coverage-fuzz CI job. Building all targets here catches
# that class of drift before push.
bold "=== wave 1a: make fuzz-build (all libFuzzer targets) ==="
if ! make fuzz-build; then
    red "FAIL: make fuzz-build (fuzz crate drifted from a workspace change?)"
    exit 7
fi
green "PASS: make fuzz-build"
echo

# Mermaid fails at render time rather than at commit time, so a broken
# diagram commits cleanly and passes every other check here. The script
# renders in the upstream mermaid-cli container; do not pipe it, or the
# pipeline reports the filter's status and every failure turns green.
#
# The message says "see above" rather than naming a cause, because a
# broken diagram is only one of the ways this exits non-zero: a fence
# mmdc cannot read is refused by name, and so is a path outside the
# repository or one the container cannot carry, while a docker daemon
# that is not running surfaces as the run's own status. Each of those
# already prints what it was; asserting "a diagram does not render"
# over the top sends a developer looking for a broken diagram that
# does not exist.
bold "=== wave 1a: tools/mermaid-lint.sh (render every diagram) ==="
if ! ./tools/mermaid-lint.sh; then
    red "FAIL: mermaid-lint (see the output above)"
    exit 8
fi
green "PASS: mermaid-lint"
echo

bold "=== wave 1b: mechanical style checks ==="

# 1. Long-line check: warn on Rust source lines over 120 chars in
#    changed files relative to the resolved audit scope (default:
#    develop...HEAD). Non-fatal -- purely informational. Skipped when
#    AUDIT_SCOPE_SKIP_SCOPED is set: the default scope's `develop` is
#    not a known ref (e.g. shallow clone in CI), or the default scope
#    resolved to zero files (nothing merits a warning here, since
#    audit_scope_report already printed one).
if [[ "$AUDIT_SCOPE_SKIP_SCOPED" -eq 0 ]]; then
    # -z / -0: NUL-delimited so filenames with spaces or special
    # characters survive the xargs split.
    #
    # FNR, not NR: awk is handed every file at once, and NR counts
    # across the whole input, so every file after the first reported a
    # cumulative line number. That was wrong from the start and is
    # wrong more often now, since a --commits-file scope passes dozens
    # of files in one invocation; the same NR/FNR defect was already
    # fixed once in inline-script-check.awk. xargs may also split a
    # long list into several awk runs, which resets NR but never FNR.
    #
    # names_existing_null, not names_null: a scope can name a file that
    # was deleted, and awk's error for it used to be discarded by a
    # 2>/dev/null that discarded every other error with it.
    LONG_LINES=$(audit_scope_names_existing_null '*.rs' \
        | xargs -r -0 awk 'length > 120 {print FILENAME":"FNR": "length" chars"}' \
        || true)
    if [[ -n "$LONG_LINES" ]]; then
        echo "ADVISORY: lines over 120 chars in changed Rust files:"
        echo "$LONG_LINES" | head -20
    fi
fi

# 2. Inline-script check: warn on multi-line `run: |` blocks in
#    GitHub Actions workflow files (CLAUDE.md says scripts >5 lines
#    should live in tools/). The counting rule, the three bugs it has
#    already had, and the one limitation it keeps are documented in
#    the awk program itself, which is separate so that
#    test-inline-script-check.sh can exercise it against fixtures
#    without running the rest of wave 1.
INLINE=$(awk -f "$SCRIPT_DIR/inline-script-check.awk" \
    .github/workflows/*.yml 2>/dev/null || true)
if [[ -n "$INLINE" ]]; then
    INLINE_COUNT=$(echo "$INLINE" | wc -l | tr -d ' ')
    echo "ADVISORY: long inline scripts in CI workflows (move to tools/): $INLINE_COUNT hits"
    echo "$INLINE"
fi

# 3. Adversarial / CVE fixture check: any new test asset committed
#    under src/, tests/, or scripts/ that looks like a malicious
#    image probably belongs in shakenfist/instar-testdata, not here.
#    "Added" is the union across the resolved scope: a file added in
#    one commit of a --commits-file counts as added even if a later
#    commit in the same union modified it.
if [[ "$AUDIT_SCOPE_SKIP_SCOPED" -eq 0 ]]; then
    # shellcheck disable=SC2119  # no pathspec: whole-scope, by design
    BADPLACE=$(audit_scope_names_added \
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
