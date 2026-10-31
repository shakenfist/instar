#!/usr/bin/env bash
#
# Tests for tools/ci/publish-stestr-timing.sh.
#
# The publisher runs unattended once a night, and the two ways it can be
# wrong are both invisible: it opens a pull request every morning for
# noise until someone disables the nightly, or it opens none ever and the
# committed scheduling hint rots while CI stays green. So the verdict for
# each class of measurement is asserted here rather than reasoned about.
#
# The verdict cases all run with --dry-run, so no git branch is created,
# nothing is pushed, and no GitHub API call is made. The measurements are
# built from the repository's own committed tests/stestr-timing.txt,
# which also means a malformed committed file fails this test rather than
# a nightly.
#
# The write path -- the copy over the committed file, the branch push and
# the pull-request deduplication -- is then exercised for real, because
# --dry-run returns before reaching any of it: commenting out the copy
# left every case above green. It runs against a throwaway git
# repository with a `file://` remote, so the push goes to a directory
# under this test's own temp tree, with `gh` stubbed by a script on PATH.
# Nothing in it touches this repository or the GitHub API, and the last
# section asserts that.
#
# One case drives it with a hostile measurement rather than a merely
# malformed one. The ids in that file come from the job that ran the
# whole suite over 7.5 GiB of deliberately malformed images, and from
# here they travel into a Markdown report, into the body of a pull
# request opened unattended, and into the committed file -- so an id
# carrying a backtick, a code fence, an `@name` or a forged table row is
# a real input shape, and it must stop the refresh rather than be
# escaped downstream.
#
# Needs bash, coreutils, git and python3. No docker, no venv, no
# testdata.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PUBLISHER="${REPO_ROOT}/tools/ci/publish-stestr-timing.sh"
COMMITTED="${REPO_ROOT}/tests/stestr-timing.txt"

WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"' EXIT

FAILURES=0

start() {
    echo "--- $1"
}

ok() {
    echo "    ok: $1"
}

fail() {
    echo "    FAIL: $1" >&2
    FAILURES=$((FAILURES + 1))
}

run_publisher() {
    # run_publisher OUTFILE ARGS... -- returns the exit status, writes
    # combined output to OUTFILE.
    local out="$1"
    shift
    local status=0
    "${PUBLISHER}" "$@" > "${out}" 2>&1 || status=$?
    return "${status}"
}

if [ ! -f "${COMMITTED}" ]; then
    echo "FAIL: ${COMMITTED} is missing; the publisher has nothing to compare against" >&2
    exit 1
fi

# The heaviest test in the committed file, found rather than named, so
# this keeps working when the suite's shape changes. One awk pass rather
# than `sort | head`: under `set -o pipefail` the head closing the pipe
# makes sort exit on SIGPIPE and takes the whole script with it.
HEAVIEST="$(awk -F '\t' '$2 > max { max = $2; id = $1 } END { print id }' "${COMMITTED}")"
if [ -z "${HEAVIEST}" ]; then
    echo "FAIL: could not find the heaviest test in ${COMMITTED}" >&2
    exit 1
fi
echo "heaviest committed test: ${HEAVIEST}"
echo ""

# --- An unchanged measurement stays quiet ------------------------------
start "a measurement identical to the committed file publishes nothing"
cp "${COMMITTED}" "${WORK}/identical.txt"
OUT="${WORK}/identical.log"
STATUS=0
run_publisher "${OUT}" "${WORK}/identical.txt" --dry-run || STATUS=$?
if [ "${STATUS}" -ne 0 ]; then
    fail "an unchanged measurement exited ${STATUS}; it is the normal case and must succeed"
else
    ok "exited zero"
fi
if grep -q "have not moved enough" "${OUT}"; then
    ok "reported the change as immaterial"
else
    fail "did not report the change as immaterial"
fi
if grep -q "would publish" "${OUT}"; then
    fail "offered to publish an unchanged measurement"
else
    ok "published nothing"
fi

# --- A heavy test halving is published ---------------------------------
start "a heavy test halving opens a pull request"
awk -F '\t' -v id="${HEAVIEST}" 'BEGIN { OFS = "\t" }
    $1 == id { $2 = sprintf("%.2f", $2 / 2); print; next }
    { print }' "${COMMITTED}" > "${WORK}/halved.txt"
if cmp -s "${COMMITTED}" "${WORK}/halved.txt"; then
    fail "fixture did not change the heaviest test's duration"
fi
OUT="${WORK}/halved.log"
STATUS=0
run_publisher "${OUT}" "${WORK}/halved.txt" --dry-run || STATUS=$?
if [ "${STATUS}" -ne 0 ]; then
    fail "a material measurement exited ${STATUS}"
else
    ok "exited zero"
fi
if grep -q "would publish" "${OUT}"; then
    ok "offered to publish"
else
    fail "did not offer to publish a material change"
fi
if grep -q "${HEAVIEST}" "${OUT}"; then
    ok "the body names the test that moved"
else
    fail "the body does not name the test that moved"
fi
if grep -q "Why this is material" "${OUT}"; then
    ok "the body states which rule fired"
else
    fail "the body does not state which rule fired"
fi

# --- A uniformly slower run stays quiet --------------------------------
# The property the comparison is built on, asserted end to end through
# the publisher as well as in the comparison's own unit tests: stestr's
# bin packing is scale-free, so a contended runner must not open a pull
# request even though every number in the file changed.
start "a uniformly 25% slower measurement publishes nothing"
awk -F '\t' 'BEGIN { OFS = "\t" } { $2 = sprintf("%.2f", $2 * 1.25); print }' \
    "${COMMITTED}" > "${WORK}/slower.txt"
OUT="${WORK}/slower.log"
STATUS=0
run_publisher "${OUT}" "${WORK}/slower.txt" --dry-run || STATUS=$?
if [ "${STATUS}" -ne 0 ]; then
    fail "a uniformly slower measurement exited ${STATUS}"
else
    ok "exited zero"
fi
if grep -q "would publish" "${OUT}"; then
    fail "offered to publish a uniform slowdown, which changes no scheduling decision"
else
    ok "published nothing"
fi

# --- --force overrides the quiet default -------------------------------
start "--force publishes an immaterial measurement"
OUT="${WORK}/forced.log"
STATUS=0
run_publisher "${OUT}" "${WORK}/slower.txt" --dry-run --force || STATUS=$?
if [ "${STATUS}" -ne 0 ]; then
    fail "--force exited ${STATUS}"
else
    ok "exited zero"
fi
if grep -q "would publish" "${OUT}"; then
    ok "offered to publish"
else
    fail "--force did not publish"
fi
if grep -q "force" "${OUT}"; then
    ok "the body says the refresh was forced"
else
    fail "the body does not say the refresh was forced"
fi

# --- A material move has to persist ------------------------------------
# The case the first three refreshes turned out to be: a measurement that
# differs materially from the committed file but ALSO from the previous
# night's measurement is one bad night, not a change, and must wait. The
# previous measurement here is the committed file itself, which is
# exactly the shape #862 had -- #857 had committed the night before's
# measurement -- so the two comparisons the publisher runs give the same
# answer and the refresh must not publish.
start "a material move the previous measurement does not confirm waits"
cp "${COMMITTED}" "${WORK}/previous-disagrees.txt"
echo "run 1 on 2026-10-30T02:00:00Z (https://example.invalid/runs/1)" \
    > "${WORK}/previous-disagrees.txt.source"
OUT="${WORK}/persist-wait.log"
STATUS=0
run_publisher "${OUT}" "${WORK}/halved.txt" --previous "${WORK}/previous-disagrees.txt" --dry-run \
    || STATUS=$?
if [ "${STATUS}" -ne 0 ]; then
    fail "waiting exited ${STATUS}; it is a normal night and must succeed"
else
    ok "exited zero"
fi
if grep -q "would publish" "${OUT}"; then
    fail "published a move the previous measurement does not confirm"
else
    ok "published nothing"
fi
if grep -q "Waiting for a measurement that agrees" "${OUT}"; then
    ok "said it is waiting, and why"
else
    fail "did not say it is waiting"
fi
if grep -q "previous measurement (run 1 on 2026-10-30" "${OUT}"; then
    ok "named the previous measurement by its source"
else
    fail "did not name where the previous measurement came from"
fi
# Every comparison goes to the log -- committed against tonight,
# previous against tonight, committed against previous -- so a night
# that waits is diagnosable from the log alone.
if [ "$(grep -c 'weight moved between tests' "${OUT}")" -eq 3 ]; then
    ok "logged all three comparisons"
else
    fail "did not log every comparison against the previous measurement"
fi
if grep -q "the previous measurement differs materially from this one" "${OUT}"; then
    ok "said the two nights disagree"
else
    fail "did not say which persistence condition failed"
fi

start "a material move the previous measurement confirms publishes"
# The previous night saw the same halving, with a little jitter on top so
# this proves the comparison ran rather than a byte-for-byte match.
awk -F '\t' -v id="${HEAVIEST}" 'BEGIN { OFS = "\t" }
    $1 == id { $2 = sprintf("%.2f", $2 * 1.02); print; next }
    { print }' "${WORK}/halved.txt" > "${WORK}/previous-agrees.txt"
if cmp -s "${WORK}/halved.txt" "${WORK}/previous-agrees.txt"; then
    fail "fixture did not jitter the previous measurement"
fi
echo "run 2 on 2026-10-30T02:00:00Z (https://example.invalid/runs/2)" \
    > "${WORK}/previous-agrees.txt.source"
OUT="${WORK}/persist-agree.log"
STATUS=0
run_publisher "${OUT}" "${WORK}/halved.txt" --previous "${WORK}/previous-agrees.txt" --dry-run \
    || STATUS=$?
if [ "${STATUS}" -ne 0 ]; then
    fail "a persistent move exited ${STATUS}"
else
    ok "exited zero"
fi
if grep -q "would publish" "${OUT}"; then
    ok "offered to publish"
else
    fail "did not publish a move two measurements agree on"
fi
if grep -q "The move has persisted" "${OUT}" && grep -q "from run 2 on 2026-10-30" "${OUT}"; then
    ok "the body says the move persisted and names the previous measurement"
else
    fail "the body does not say the move persisted"
fi
# The body, not the log: three reports in it -- committed against
# tonight, then both comparisons against the previous measurement.
if grep -q "Against the previous measurement" "${OUT}" \
    && grep -q "The previous measurement (run 2 on 2026-10-30.*) against the committed file" "${OUT}" \
    && [ "$(sed -n '/^--- body ---$/,/^--- end body ---$/p' "${OUT}" | grep -c 'weight moved between tests')" -eq 3 ]; then
    ok "the body carries both comparisons against the previous measurement"
else
    fail "the body does not carry both comparisons against the previous measurement"
fi

start "a previous night that had not itself moved does not confirm tonight's move"
# Thresholds are not transitive. A previous night that moved the
# heaviest test's share by a little over half the single-test threshold,
# and a tonight that moved it by a little over the whole of it, agree
# with each other while only tonight disagrees with the committed file.
# That is one night's move, and calling it "persisted" would be false.
# The fixtures are built to a target share move and their three
# relationships are checked with the comparator itself before the
# publisher is asked, so this proves the case rather than assuming it.
share_shift() {
    # share_shift FILE POINTS -- FILE with the heaviest test's duration
    # set so its share of the suite's weight rises by POINTS.
    awk -F '\t' -v id="${HEAVIEST}" -v pp="$2" 'BEGIN { OFS = "\t" }
        NR == FNR { total += $2; if ($1 == id) d = $2; next }
        $1 == id {
            share = 100 * d / total + pp
            $2 = sprintf("%.2f", share * (total - d) / (100 - share))
        }
        { print }' "$1" "$1"
}
share_shift "${COMMITTED}" 1.2 > "${WORK}/previous-unmoved.txt"
share_shift "${COMMITTED}" 2.4 > "${WORK}/just-over.txt"
compare_rc() {
    local rc=0
    python3 "${REPO_ROOT}/tools/ci/compare-stestr-timing.py" "$1" "$2" > /dev/null 2>&1 || rc=$?
    echo "${rc}"
}
if [ "$(compare_rc "${COMMITTED}" "${WORK}/just-over.txt")" = 0 ] \
    && [ "$(compare_rc "${WORK}/previous-unmoved.txt" "${WORK}/just-over.txt")" = 10 ] \
    && [ "$(compare_rc "${COMMITTED}" "${WORK}/previous-unmoved.txt")" = 10 ]; then
    ok "fixture: tonight is material against committed, immaterial against the previous night,"
    ok "    and the previous night is immaterial against committed"
else
    fail "fixture does not have the non-transitive shape this case needs"
fi
echo "run 3 on 2026-10-30T02:00:00Z (https://example.invalid/runs/3)" \
    > "${WORK}/previous-unmoved.txt.source"
OUT="${WORK}/persist-unmoved.log"
STATUS=0
run_publisher "${OUT}" "${WORK}/just-over.txt" --previous "${WORK}/previous-unmoved.txt" --dry-run \
    || STATUS=$?
if [ "${STATUS}" -eq 0 ] && ! grep -q "would publish" "${OUT}"; then
    ok "published nothing"
else
    fail "published a move only one night showed (exit ${STATUS})"
fi
if grep -q "had not itself moved materially" "${OUT}" && grep -q "Waiting for a" "${OUT}"; then
    ok "said the previous night had not moved, and that it is waiting"
else
    fail "did not say the previous night had not itself moved"
fi

start "a previous night that moved the other way does not confirm tonight's move"
# The oscillation #857 and #862 actually were: both nights material
# against the committed file, in opposite directions, so they disagree
# with each other. The case above cannot catch a publisher that skips
# the previous-against-tonight comparison, because there the previous
# night had not moved at all; this one can.
share_shift "${COMMITTED}" 4.8 > "${WORK}/previous-swung.txt"
if [ "$(compare_rc "${COMMITTED}" "${WORK}/previous-swung.txt")" = 0 ] \
    && [ "$(compare_rc "${WORK}/previous-swung.txt" "${WORK}/halved.txt")" = 0 ]; then
    ok "fixture: the previous night moved materially, and differs materially from tonight"
else
    fail "fixture does not have the swung shape this case needs"
fi
OUT="${WORK}/persist-swung.log"
STATUS=0
run_publisher "${OUT}" "${WORK}/halved.txt" --previous "${WORK}/previous-swung.txt" --dry-run \
    || STATUS=$?
if [ "${STATUS}" -eq 0 ] && ! grep -q "would publish" "${OUT}"; then
    ok "published nothing"
else
    fail "published a move two swinging nights disagree on (exit ${STATUS})"
fi
if grep -q "the previous measurement differs materially from this one" "${OUT}"; then
    ok "said the two nights disagree"
else
    fail "did not say the two swinging nights disagree"
fi

OUT="${WORK}/persist-unmoved-forced.log"
STATUS=0
run_publisher "${OUT}" "${WORK}/just-over.txt" --previous "${WORK}/previous-unmoved.txt" --dry-run --force \
    || STATUS=$?
if [ "${STATUS}" -eq 0 ] && grep -q "would publish" "${OUT}" \
    && grep -q "does not confirm this one\*\* -- the previous measurement had not itself moved" "${OUT}"; then
    ok "--force publishes it, and the body says why it is unconfirmed"
else
    fail "--force did not publish it with the reason in the body (exit ${STATUS})"
fi

start "a previous measurement without a sidecar is named by its path"
rm -f "${WORK}/previous-agrees.txt.source"
OUT="${WORK}/persist-nosource.log"
STATUS=0
run_publisher "${OUT}" "${WORK}/halved.txt" --previous "${WORK}/previous-agrees.txt" --dry-run \
    || STATUS=$?
if [ "${STATUS}" -eq 0 ] && grep -q "from ${WORK}/previous-agrees.txt," "${OUT}"; then
    ok "fell back to the path"
else
    fail "did not fall back to the path (exit ${STATUS})"
fi

start "with no previous measurement a material move publishes on one night's evidence"
# The fallback direction, asserted on purpose: the first night, or a
# night where every earlier artifact expired or the listing failed, must
# publish as it always did -- visibly -- rather than wait for a
# confirmation that can never arrive.
OUT="${WORK}/persist-unchecked.log"
STATUS=0
run_publisher "${OUT}" "${WORK}/halved.txt" --dry-run || STATUS=$?
if [ "${STATUS}" -eq 0 ] && grep -q "would publish" "${OUT}"; then
    ok "offered to publish"
else
    fail "did not publish without a previous measurement (exit ${STATUS})"
fi
if grep -q "No previous measurement was available" "${OUT}"; then
    ok "the body says the move is unconfirmed"
else
    fail "the body does not say no previous measurement was available"
fi

start "--force publishes a move the previous measurement does not confirm"
OUT="${WORK}/persist-forced.log"
STATUS=0
run_publisher "${OUT}" "${WORK}/halved.txt" --previous "${WORK}/previous-disagrees.txt" --dry-run --force \
    || STATUS=$?
if [ "${STATUS}" -eq 0 ] && grep -q "would publish" "${OUT}"; then
    ok "offered to publish"
else
    fail "--force did not publish (exit ${STATUS})"
fi
if grep -q "does not confirm this one\*\* -- the previous measurement differs materially" "${OUT}"; then
    ok "the body says the previous measurement does not confirm it, and why"
else
    fail "the body hides that the previous measurement disagrees"
fi

start "an immaterial move is not checked for persistence at all"
OUT="${WORK}/persist-immaterial.log"
STATUS=0
run_publisher "${OUT}" "${WORK}/slower.txt" --previous "${WORK}/previous-agrees.txt" --dry-run \
    || STATUS=$?
if [ "${STATUS}" -eq 0 ] && ! grep -q "would publish" "${OUT}"; then
    ok "published nothing"
else
    fail "an immaterial move with a previous measurement misbehaved (exit ${STATUS})"
fi
if grep -q "previous measurement" "${OUT}"; then
    fail "compared an immaterial move against the previous measurement"
else
    ok "did not mention the previous measurement"
fi

start "a previous measurement that is missing or malformed is an error"
OUT="${WORK}/persist-missing.log"
STATUS=0
run_publisher "${OUT}" "${WORK}/halved.txt" --previous "${WORK}/not-there.txt" --dry-run || STATUS=$?
if [ "${STATUS}" -eq 0 ]; then
    fail "a missing previous measurement was quietly skipped"
else
    ok "missing previous measurement exited ${STATUS}"
fi
printf 'test_info.TestInfo.test_a 1.00\n' > "${WORK}/previous-malformed.txt"
OUT="${WORK}/persist-malformed.log"
STATUS=0
run_publisher "${OUT}" "${WORK}/halved.txt" --previous "${WORK}/previous-malformed.txt" --dry-run \
    || STATUS=$?
if [ "${STATUS}" -eq 0 ]; then
    fail "a malformed previous measurement reported success"
else
    ok "malformed previous measurement exited ${STATUS}"
fi
if "${PUBLISHER}" "${WORK}/halved.txt" --previous > /dev/null 2>&1; then
    fail "--previous without a file was accepted"
else
    ok "--previous without a file rejected"
fi

# --- Bad input fails loudly --------------------------------------------
start "a malformed measurement is an error, not a quiet no-op"
printf 'test_info.TestInfo.test_a 1.00\n' > "${WORK}/malformed.txt"
OUT="${WORK}/malformed.log"
STATUS=0
run_publisher "${OUT}" "${WORK}/malformed.txt" --dry-run || STATUS=$?
if [ "${STATUS}" -eq 0 ]; then
    fail "a malformed measurement reported success"
else
    ok "exited ${STATUS}"
fi

# The measured ids come from the job that ran the suite over 7.5 GiB of
# deliberately malformed images, and they end up in a Markdown report, in
# the body of a pull request opened unattended, and in the committed
# file. So a hostile id must stop the refresh here, at the one place that
# writes it -- not be escaped further down, and not be dropped the way
# the seeding path drops a bad line before a run.
start "a hostile test id stops the refresh and reaches neither the body nor the file"
# The backticks and the $( ) below are the hostile payload, so the single
# quotes keeping them literal are the whole point.
# shellcheck disable=SC2016
{
    cat "${COMMITTED}"
    printf 'test_convert.TestEvil.test_a`whoami`\t900.00\n'
    printf 'test_convert.TestEvil.test_fence```\t500.00\n'
    printf 'test_convert.TestEvil.test_mention @shakenfist please merge\t400.00\n'
    printf 'test_convert.TestEvil.test_row | 0.00s | 0.00s | +99.00 pp |\t300.00\n'
} > "${WORK}/hostile.txt"
OUT="${WORK}/hostile.log"
STATUS=0
run_publisher "${OUT}" "${WORK}/hostile.txt" --dry-run || STATUS=$?
if [ "${STATUS}" -eq 0 ]; then
    fail "a hostile test id reported success"
else
    ok "exited ${STATUS}"
fi
if grep -q 'is not a test id' "${OUT}"; then
    ok "said which line it refused"
else
    fail "did not say why it refused the measurement"
fi
if grep -q 'would publish' "${OUT}"; then
    fail "offered to publish a measurement carrying a hostile id"
else
    ok "offered to publish nothing"
fi
# Refused at the read, so the report that becomes the pull request body
# is never built at all -- neither its movers table nor the body the dry
# run would print. The one place the rejected bytes appear is the
# diagnostic naming the line, which goes to the job log and is quoted
# with repr.
if grep -q -- '--- body ---' "${OUT}" || grep -q '| Test | Committed |' "${OUT}"; then
    fail "a pull request body was built from a measurement carrying a hostile id"
else
    ok "no body and no movers table were built"
fi

start "an empty measurement is an error"
: > "${WORK}/empty.txt"
OUT="${WORK}/empty.log"
STATUS=0
run_publisher "${OUT}" "${WORK}/empty.txt" --dry-run || STATUS=$?
if [ "${STATUS}" -eq 0 ]; then
    fail "an empty measurement reported success"
else
    ok "exited ${STATUS}"
fi

start "a missing measurement file is an error"
OUT="${WORK}/missing.log"
STATUS=0
run_publisher "${OUT}" "${WORK}/not-there.txt" --dry-run || STATUS=$?
if [ "${STATUS}" -eq 0 ]; then
    fail "a missing measurement reported success"
else
    ok "exited ${STATUS}"
fi

start "bad arguments are rejected"
if "${PUBLISHER}" > /dev/null 2>&1; then
    fail "no arguments were accepted"
else
    ok "no arguments rejected"
fi
if "${PUBLISHER}" a b --dry-run > /dev/null 2>&1; then
    fail "two measurement files were accepted"
else
    ok "two positional arguments rejected"
fi
if "${PUBLISHER}" "${WORK}/identical.txt" --nonsense > /dev/null 2>&1; then
    fail "an unknown flag was accepted"
else
    ok "unknown flag rejected"
fi

# --- The write path ----------------------------------------------------
# Everything above stops at --dry-run, which returns before the publisher
# writes anything, so the three things it does when it decides to publish
# were untested: the copy of the measurement over the committed file, the
# branch commit and push, and the `gh pr list` check that updates an open
# pull request in place instead of opening a second one. A scratch
# repository with a `file://` remote makes a real push harmless, and a
# `gh` stub on PATH makes the dedup branch drivable both ways.
#
# The publisher resolves its repository root from its own location, so
# the scripts are copied into the scratch tree and run from there. That
# is the real publisher, not a reimplementation of it -- mutate
# tools/ci/publish-stestr-timing.sh and these cases fail.
start "set up a scratch repository with a file:// remote and a gh stub"
SCRATCH="${WORK}/scratch"
REMOTE="${WORK}/remote.git"
STUB_BIN="${WORK}/bin"
GH_LOG="${WORK}/gh-calls.log"
GH_OPEN_PR="${WORK}/gh-open-pr.txt"

mkdir -p "${STUB_BIN}"
cat > "${STUB_BIN}/gh" <<'STUB'
#!/usr/bin/env bash
# Stand-in for the GitHub CLI: records every call, and answers
# `gh pr list` from a file the test controls so the deduplication branch
# can be driven both ways without an API. Everything else succeeds
# silently, which is what `gh pr create` looks like from the publisher.
printf '%s\n' "$*" >> "${GH_STUB_LOG}"
if [ -n "${GH_STUB_FAIL_EDIT:-}" ] && [ "${1:-}" = "pr" ] && [ "${2:-}" = "edit" ]; then
    echo "stub: pr edit refused" >&2
    exit 1
fi
if [ "${1:-}" = "pr" ] && [ "${2:-}" = "list" ]; then
    cat "${GH_STUB_OPEN_PR}"
fi
STUB
chmod +x "${STUB_BIN}/gh"
: > "${GH_LOG}"
: > "${GH_OPEN_PR}"

mkdir -p "${SCRATCH}/tools/ci" "${SCRATCH}/tests"
git init -q "${SCRATCH}"
# symbolic-ref rather than `git init -b`, which needs git 2.28.
git -C "${SCRATCH}" symbolic-ref HEAD refs/heads/develop
git -C "${SCRATCH}" config user.name "Scratch Tester"
git -C "${SCRATCH}" config user.email "scratch@example.invalid"
cp "${REPO_ROOT}/tools/ci/publish-stestr-timing.sh" "${SCRATCH}/tools/ci/"
cp "${REPO_ROOT}/tools/ci/compare-stestr-timing.py" "${SCRATCH}/tools/ci/"
cp "${COMMITTED}" "${SCRATCH}/tests/stestr-timing.txt"
git -C "${SCRATCH}" add -A
git -C "${SCRATCH}" commit -q -m "Scratch tree"
git init -q --bare "${REMOTE}"
git -C "${SCRATCH}" remote add origin "file://${REMOTE}"
git -C "${SCRATCH}" push -q -u origin develop
if [ -f "${SCRATCH}/tools/ci/publish-stestr-timing.sh" ] &&
    git --git-dir="${REMOTE}" rev-parse --verify --quiet develop > /dev/null; then
    ok "scratch repository and bare remote ready"
else
    echo "FAIL: could not build the scratch repository" >&2
    exit 1
fi

run_scratch_publisher() {
    # run_scratch_publisher OUTFILE ARGS... -- run the copy of the
    # publisher inside the scratch tree, with the gh stub ahead of any
    # real gh on PATH.
    local out="$1"
    shift
    local status=0
    env PATH="${STUB_BIN}:${PATH}" \
        GH_TOKEN="stub-token" \
        GH_STUB_LOG="${GH_LOG}" \
        GH_STUB_OPEN_PR="${GH_OPEN_PR}" \
        GH_STUB_FAIL_EDIT="${GH_STUB_FAIL_EDIT:-}" \
        TIMING_PR_ASSIGNEE="${TIMING_PR_ASSIGNEE:-}" \
        BASE_BRANCH="develop" \
        WORKFLOW_URL="https://example.invalid/runs/1" \
        "${SCRATCH}/tools/ci/publish-stestr-timing.sh" "$@" > "${out}" 2>&1 || status=$?
    return "${status}"
}

start "a material measurement replaces the committed file and pushes a branch"
OUT="${WORK}/write-first.log"
STATUS=0
run_scratch_publisher "${OUT}" "${WORK}/halved.txt" || STATUS=$?
if [ "${STATUS}" -ne 0 ]; then
    fail "publishing for real exited ${STATUS}"
    sed 's/^/      /' "${OUT}" >&2
else
    ok "exited zero"
fi
if cmp -s "${SCRATCH}/tests/stestr-timing.txt" "${WORK}/halved.txt"; then
    ok "the committed file in the working tree is now the measurement"
else
    fail "the committed file was not replaced by the measurement"
fi
if git --git-dir="${REMOTE}" rev-parse --verify --quiet "stestr-timing/refresh" > /dev/null; then
    ok "the refresh branch reached the remote"
else
    fail "nothing was pushed to the remote"
fi
if git --git-dir="${REMOTE}" show "stestr-timing/refresh:tests/stestr-timing.txt" 2> /dev/null \
    | cmp -s - "${WORK}/halved.txt"; then
    ok "the pushed commit carries the measured timings, not the old ones"
else
    fail "the pushed commit does not carry the measurement"
fi
if grep -q "pr create" "${GH_LOG}"; then
    ok "a pull request was opened"
else
    fail "no pull request was opened"
fi
if grep -q "assignee" "${GH_LOG}"; then
    fail "assigned the pull request with no assignee asked for"
else
    ok "assigned nobody: no login is written into the publisher"
fi
if git --git-dir="${REMOTE}" rev-parse --verify --quiet develop > /dev/null &&
    [ "$(git --git-dir="${REMOTE}" rev-parse develop)" != \
        "$(git --git-dir="${REMOTE}" rev-parse stestr-timing/refresh 2> /dev/null || echo none)" ]; then
    ok "the base branch was left where it was"
else
    fail "the publisher moved the base branch"
fi
FIRST_SHA="$(git --git-dir="${REMOTE}" rev-parse stestr-timing/refresh 2> /dev/null || echo none)"

start "a second refresh with a pull request already open does not open another"
# The dedup that matters: one long-lived branch, force-pushed, so the
# open pull request updates in place. A second `gh pr create` here would
# be a pull request every night that the first one already covers.
echo "4242" > "${GH_OPEN_PR}"
: > "${GH_LOG}"
HEAVIEST2="$(awk -F '\t' '$2 > max { max = $2; id = $1 } END { print id }' \
    "${SCRATCH}/tests/stestr-timing.txt")"
awk -F '\t' -v id="${HEAVIEST2}" 'BEGIN { OFS = "\t" }
    $1 == id { $2 = sprintf("%.2f", $2 * 10); print; next }
    { print }' "${SCRATCH}/tests/stestr-timing.txt" > "${WORK}/tenfold.txt"
OUT="${WORK}/write-second.log"
STATUS=0
run_scratch_publisher "${OUT}" "${WORK}/tenfold.txt" || STATUS=$?
if [ "${STATUS}" -ne 0 ]; then
    fail "the second publish exited ${STATUS}"
    sed 's/^/      /' "${OUT}" >&2
else
    ok "exited zero"
fi
if grep -q "pr create" "${GH_LOG}"; then
    fail "opened a second pull request while one was already open"
else
    ok "opened no second pull request"
fi
if grep -q "pr list" "${GH_LOG}"; then
    ok "asked whether one was already open"
else
    fail "never checked for an open pull request"
fi
if grep -q "#4242" "${OUT}"; then
    ok "said which open pull request it updated"
else
    fail "did not name the open pull request"
fi
if [ "$(git --git-dir="${REMOTE}" rev-parse stestr-timing/refresh 2> /dev/null || echo none)" \
    != "${FIRST_SHA}" ] &&
    git --git-dir="${REMOTE}" show "stestr-timing/refresh:tests/stestr-timing.txt" 2> /dev/null \
        | cmp -s - "${WORK}/tenfold.txt"; then
    ok "the one branch was force-pushed to the new measurement"
else
    fail "the open pull request's branch was not updated"
fi

start "a measurement byte-identical to the committed file makes no empty commit"
# Reachable only with --force: the comparison calls it immaterial, and
# --force carries it past that into the write path, where the bytes turn
# out to match. An empty commit and a pull request for it would be worse
# than doing nothing.
cp "${SCRATCH}/tests/stestr-timing.txt" "${WORK}/same-as-scratch.txt"
SECOND_SHA="$(git --git-dir="${REMOTE}" rev-parse stestr-timing/refresh 2> /dev/null || echo none)"
: > "${GH_LOG}"
OUT="${WORK}/write-identical.log"
STATUS=0
run_scratch_publisher "${OUT}" "${WORK}/same-as-scratch.txt" --force || STATUS=$?
if [ "${STATUS}" -ne 0 ]; then
    fail "an identical forced measurement exited ${STATUS}"
else
    ok "exited zero"
fi
if grep -q "byte-identical" "${OUT}"; then
    ok "said there was nothing to publish"
else
    fail "did not say why it published nothing"
fi
if [ "$(git --git-dir="${REMOTE}" rev-parse stestr-timing/refresh 2> /dev/null || echo none)" \
    = "${SECOND_SHA}" ]; then
    ok "pushed nothing"
else
    fail "pushed an empty commit"
fi
if [ -s "${GH_LOG}" ]; then
    fail "called gh for a refresh it had nothing to publish"
else
    ok "called no GitHub API at all"
fi

start "an assignee asked for in the environment is set after the event"
# Asked for separately from opening the pull request, and asserted
# separately, because the two must not share a fate: an assignment that
# cannot be made is a warning and an opened pull request, never a failed
# nightly that filed an issue about a scheduling hint.
: > "${GH_OPEN_PR}"
: > "${GH_LOG}"
OUT="${WORK}/write-assignee.log"
STATUS=0
TIMING_PR_ASSIGNEE="someone" run_scratch_publisher "${OUT}" "${WORK}/halved.txt" || STATUS=$?
if [ "${STATUS}" -ne 0 ]; then
    fail "publishing with an assignee exited ${STATUS}"
    sed 's/^/      /' "${OUT}" >&2
else
    ok "exited zero"
fi
if grep -q "pr create" "${GH_LOG}"; then
    ok "opened the pull request"
else
    fail "opened no pull request"
fi
if grep -q "pr edit stestr-timing/refresh --add-assignee someone" "${GH_LOG}"; then
    ok "assigned the login the environment named"
else
    fail "did not assign the login the environment named"
fi

start "an assignment that fails leaves the pull request standing"
HEAVIEST3="$(awk -F '\t' '$2 > max { max = $2; id = $1 } END { print id }' \
    "${SCRATCH}/tests/stestr-timing.txt")"
awk -F '\t' -v id="${HEAVIEST3}" 'BEGIN { OFS = "\t" }
    $1 == id { $2 = sprintf("%.2f", $2 * 7); print; next }
    { print }' "${SCRATCH}/tests/stestr-timing.txt" > "${WORK}/sevenfold.txt"
: > "${GH_LOG}"
OUT="${WORK}/write-assignee-fails.log"
STATUS=0
GH_STUB_FAIL_EDIT=1 TIMING_PR_ASSIGNEE="departed" \
    run_scratch_publisher "${OUT}" "${WORK}/sevenfold.txt" || STATUS=$?
if [ "${STATUS}" -ne 0 ]; then
    fail "a refused assignment failed the publisher (exit ${STATUS})"
    sed 's/^/      /' "${OUT}" >&2
else
    ok "exited zero despite the refused assignment"
fi
if grep -q "could not assign departed" "${OUT}"; then
    ok "warned that the assignment did not happen"
else
    fail "said nothing about the failed assignment"
fi
if git --git-dir="${REMOTE}" show "stestr-timing/refresh:tests/stestr-timing.txt" 2> /dev/null \
    | cmp -s - "${WORK}/sevenfold.txt"; then
    ok "the refresh itself still reached the remote"
else
    fail "the refresh did not reach the remote"
fi

# --- Nothing was written -----------------------------------------------
# --dry-run must leave the tree exactly as it found it: these cases run
# inside the repository, and a publisher that copied the measurement over
# the committed file before deciding would be invisible here otherwise.
start "--dry-run left the committed file and the branch alone"
if git -C "${REPO_ROOT}" diff --quiet -- tests/stestr-timing.txt; then
    ok "tests/stestr-timing.txt is unmodified"
else
    fail "tests/stestr-timing.txt was modified by a dry run"
fi
if git -C "${REPO_ROOT}" rev-parse --verify --quiet "stestr-timing/refresh" > /dev/null; then
    fail "a dry run created the publishing branch"
else
    ok "no publishing branch was created"
fi

echo ""
if [ "${FAILURES}" -ne 0 ]; then
    echo "${FAILURES} check(s) failed"
    exit 1
fi
echo "All checks passed"
