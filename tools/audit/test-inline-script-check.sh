#!/usr/bin/env bash
#
# Tests for tools/audit/inline-script-check.awk.
#
# The check has silently mis-counted three times, each time in a way
# that left it still producing plausible output: line numbers that ran
# continuously across files, bodies truncated at their first blank
# line, and blocks that ran through the comments between steps. An
# advisory check that over- or under-reports is worse than no check,
# because its output still looks like a finding. Each case below pins
# one of those bugs.
#
# Fixtures are minimal YAML written to a temp directory rather than
# real workflow files, so the expected counts do not move when a
# workflow is edited. The previous verification was "must find 16
# blocks in fuzz-autofix.yml", and fuzz-autofix.yml has since been
# deleted.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROGRAM="${SCRIPT_DIR}/inline-script-check.awk"

WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"' EXIT

FAILURES=0

start() { echo "--- $1"; }
ok() { echo "    ok: $1"; }
fail() { echo "    FAIL: $1" >&2; FAILURES=$((FAILURES + 1)); }

# Compare the check's whole output against an expected listing, so a
# spurious extra hit fails as loudly as a missing one.
expect() {
    local name="$1" expected="$2"
    shift 2
    local actual
    actual="$(cd "${WORK}" && awk -f "${PROGRAM}" "$@" || true)"
    if [ "${actual}" = "${expected}" ]; then
        ok "${name}"
    else
        fail "${name}"
        echo "      expected: ${expected:-<nothing>}" >&2
        echo "      actual:   ${actual:-<nothing>}" >&2
    fi
}

start "a body of six lines is reported, five is not"
cat > "${WORK}/threshold.yml" <<'EOF'
jobs:
  a:
    steps:
      - name: Five
        run: |
          one
          two
          three
          four
          five

      - name: Six
        run: |
          one
          two
          three
          four
          five
          six
EOF
expect "only the six-line block" \
    "threshold.yml:13: run-block of 6 lines" threshold.yml

start "an interior blank line does not end the body"
cat > "${WORK}/blank.yml" <<'EOF'
jobs:
  a:
    steps:
      - name: Blank
        run: |
          cd src

          one
          two
          three
          four
          five
EOF
expect "block spans the blank line" \
    "blank.yml:5: run-block of 6 lines" blank.yml

start "dedented comments between steps end the body"
cat > "${WORK}/comments.yml" <<'EOF'
jobs:
  a:
    steps:
      - name: Short
        run: |
          one
          two

      # A comment block explaining the next step, at step indent and
      # long enough that counting it would push the four-line body
      # above the threshold. This is the bug the second rewrite of
      # the terminator introduced: a comment is dedented but is not a
      # YAML key, so the block never closed here.
      - name: Next
        run: echo hi
EOF
expect "no hit at all" "" comments.yml

start "a sibling key at the run: indent ends the body"
cat > "${WORK}/sibling.yml" <<'EOF'
jobs:
  a:
    steps:
      - name: Sibling
        run: |
          one
          two
          three
          four
          five
          six
        env:
          SEVEN: seven
          EIGHT: eight
          NINE: nine
EOF
expect "six lines, not the env block too" \
    "sibling.yml:5: run-block of 6 lines" sibling.yml

start "line numbers are per file, not cumulative"
cat > "${WORK}/first.yml" <<'EOF'
jobs:
  a:
    steps:
      - name: First
        run: |
          one
          two
          three
          four
          five
          six
EOF
cp "${WORK}/first.yml" "${WORK}/second.yml"
expect "both blocks report line 5" \
    "first.yml:5: run-block of 6 lines
second.yml:5: run-block of 6 lines" first.yml second.yml

start "a block that runs to end of file is reported"
cat > "${WORK}/eof.yml" <<'EOF'
jobs:
  a:
    steps:
      - name: Last
        run: |
          one
          two
          three
          four
          five
          six
EOF
expect "reported from END" \
    "eof.yml:5: run-block of 6 lines" eof.yml

start "a run: block is not confused by one in an earlier file"
cat > "${WORK}/open.yml" <<'EOF'
jobs:
  a:
    steps:
      - name: Runs to EOF
        run: |
          one
          two
EOF
expect "short trailing block does not absorb the next file" \
    "first.yml:5: run-block of 6 lines" open.yml first.yml

echo
if [ "${FAILURES}" -ne 0 ]; then
    echo "${FAILURES} failure(s)" >&2
    exit 1
fi
echo "all inline-script-check tests passed"
