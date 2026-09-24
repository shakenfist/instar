#!/usr/bin/env bash
#
# Tests for tools/replace-once.py.
#
# The mutation harness's honesty rests entirely on this script refusing
# ambiguous substitutions: if it silently replaced nothing, every case
# would run an unmutated tree and the test would pass for the ordinary
# reason. That is the failure two hand-rolled sed harnesses shipped
# before it existed, so the contract is worth asserting rather than
# assuming -- and full harness runs, which are the only thing that
# exercises it today, need docker and testdata and do not run in CI.
#
# Contract (see the script's docstring): literal matching, exactly one
# occurrence, nothing written unless the count is one, exit 2 for a
# refusal and 3 for an I/O or encoding problem.
#
# Pure Python and bash: no docker, no venv, no testdata.
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SCRIPT="${REPO_ROOT}/tools/replace-once.py"
WORK="$(mktemp -d)"
trap 'rm -rf -- "${WORK}"' EXIT

FAILURES=0

check() {
    # check DESCRIPTION EXPECTED_STATUS EXPECTED_CONTENT INITIAL SEARCH REPLACE
    local description="$1" want_status="$2" want_content="$3"
    local initial="$4" search="$5" replace="$6"
    local file="${WORK}/subject.txt" got_status got_content

    printf '%s' "${initial}" >"${file}"
    python3 "${SCRIPT}" "${file}" "${search}" "${replace}" >/dev/null 2>&1
    got_status=$?
    # The X sentinel keeps a trailing newline: $() strips them, and a
    # mutation that lost one would otherwise compare equal.
    got_content="$(cat "${file}"; printf X)"
    want_content="${want_content}X"

    if [ "${got_status}" -ne "${want_status}" ]; then
        printf 'FAIL %s: exit %s, wanted %s\n' \
            "${description}" "${got_status}" "${want_status}" >&2
        FAILURES=$((FAILURES + 1))
    fi
    if [ "${got_content}" != "${want_content}" ]; then
        printf 'FAIL %s: file is %q, wanted %q\n' \
            "${description}" "${got_content}" "${want_content}" >&2
        FAILURES=$((FAILURES + 1))
    fi
}

# The one case that is supposed to work.
check 'exactly one occurrence is replaced' 0 'a NEW c' 'a OLD c' 'OLD' 'NEW'

# Refusals. Each asserts the file is untouched as well as the status,
# because a refusal that wrote first would be worse than no check.
check 'no occurrence is refused'    2 'a b c'         'a b c'         'MISSING' 'NEW'
check 'two occurrences are refused' 2 'x OLD y OLD z' 'x OLD y OLD z' 'OLD'     'NEW'
check 'a no-op mutation is refused' 2 'a OLD c'       'a OLD c'       'OLD'     'OLD'
check 'an empty search is refused'  2 'a b c'         'a b c'         ''        'NEW'

# Literal, not regular expression: the dots must not match anything.
check 'the search is literal, not a regex' \
    2 'a b c' 'a b c' 'a.b.c' 'NEW'
check 'regex metacharacters are matched literally' \
    0 'NEW tail' '.*+ tail' '.*+' 'NEW'

# Multi-line searches are how the harness pins indented Rust.
check 'a multi-line search is replaced' \
    0 $'one\nNEW\nthree\n' $'one\ntwo\nthree\n' $'two\n' $'NEW\n'

# I/O is exit 3, distinct from a refusal.
python3 "${SCRIPT}" "${WORK}/does-not-exist" 'a' 'b' >/dev/null 2>&1
if [ $? -ne 3 ]; then
    echo 'FAIL an unreadable path: wanted exit 3' >&2
    FAILURES=$((FAILURES + 1))
fi

# Wrong arity is a usage error, not a silent success.
python3 "${SCRIPT}" only-one-argument >/dev/null 2>&1
if [ $? -ne 2 ]; then
    echo 'FAIL wrong argument count: wanted exit 2' >&2
    FAILURES=$((FAILURES + 1))
fi

if [ "${FAILURES}" -ne 0 ]; then
    echo "replace-once: ${FAILURES} assertion(s) failed" >&2
    exit 1
fi
echo 'replace-once: contract holds'
