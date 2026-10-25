#!/usr/bin/env bash
#
# Tests for tools/ci/fuzz-tier.sh.
#
# The nightly coverage fuzz run sizes its fuzzing from what is left of
# the job's timeout, and a plan that asks for more than that is killed
# part way through, taking the corpus push after it with it (#519). So
# the two properties asserted here are that `budget` leaves the reserve
# it is asked to, and that a `plan` never sums to more than its budget,
# however small that budget is.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TIER="${REPO_ROOT}/tools/ci/fuzz-tier.sh"

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

# Two fast-tier targets and two deep ones.
TARGETS=(fuzz_dd_window fuzz_chs_rounded_size fuzz_qcow2_header fuzz_vhdx_header)

total() {
    # The sum of the durations in a plan.
    awk '{ s += $2 } END { print s + 0 }'
}

lowest() {
    # The smallest duration in a plan.
    awk 'NR == 1 || $2 < m { m = $2 } END { print m + 0 }'
}

start "budget: the time left before the deadline, less the reserve"
check "deadline in an hour, ten minutes reserved" \
    "$(FUZZ_TIER_NOW=1000 "${TIER}" budget 4600 600 99999)" "3000"

start "budget: never more than the cap"
check "an early start is capped" \
    "$(FUZZ_TIER_NOW=1000 "${TIER}" budget 100000 600 27000)" "27000"

start "budget: never negative"
check "a deadline already inside the reserve" \
    "$(FUZZ_TIER_NOW=1000 "${TIER}" budget 1200 600 27000)" "0"

start "plan: a roomy budget favours the deep targets"
PLAN="$("${TIER}" plan 2000 300 "${TARGETS[@]}")"
check "fast targets get the fast slice" \
    "$(grep '^fuzz_dd_window ' <<< "${PLAN}" | cut -d' ' -f2)" "300"
check "deep targets split the rest" \
    "$(grep '^fuzz_qcow2_header ' <<< "${PLAN}" | cut -d' ' -f2)" "700"
check "the plan sums to the budget" "$(total <<< "${PLAN}")" "2000"

start "plan: a budget too small for the fast slice is shared equally"
PLAN="$("${TIER}" plan 800 300 "${TARGETS[@]}" 2> "${TMPDIR:-/tmp}/fuzz-tier-warn.$$")"
WARN="$(cat "${TMPDIR:-/tmp}/fuzz-tier-warn.$$")"
rm -f "${TMPDIR:-/tmp}/fuzz-tier-warn.$$"
check "every target gets the same share" "$(cut -d' ' -f2 <<< "${PLAN}" | sort -u)" "200"
check "the plan fits the budget" "$(total <<< "${PLAN}")" "800"
if grep -q '::warning::' <<< "${WARN}"; then
    ok "and says so"
else
    fail "no warning for a budget that could not give every target its slice"
fi

start "plan: no target is ever given zero seconds"
# libFuzzer reads -max_total_time=0 as no limit at all.
PLAN="$("${TIER}" plan 0 300 "${TARGETS[@]}" 2> /dev/null)"
check "a zero budget gives each target one second" "$(lowest <<< "${PLAN}")" "1"

start "plan: never more than the budget, across budgets"
for B in 1 4 299 300 599 600 1199 1200 1201 5000 27000; do
    T="$("${TIER}" plan "${B}" 300 "${TARGETS[@]}" 2> /dev/null | total)"
    # A budget below one second per target is the single permitted
    # overrun: one second each, by the rule above.
    LIMIT="${B}"
    [ "${LIMIT}" -lt "${#TARGETS[@]}" ] && LIMIT="${#TARGETS[@]}"
    if [ "${T}" -le "${LIMIT}" ]; then
        ok "budget ${B}: plan sums to ${T}"
    else
        fail "budget ${B}: plan sums to ${T}, over the budget"
    fi
done

if [ "${FAILURES}" -ne 0 ]; then
    echo "${FAILURES} failure(s)" >&2
    exit 1
fi
echo "All fuzz-tier checks passed."
