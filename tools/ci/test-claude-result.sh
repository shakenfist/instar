#!/usr/bin/env bash
#
# Tests for tools/ci/claude-result.sh.
#
# Every input here is a shape the `claude` CLI was measured producing
# at 2.1.238, not one that seemed plausible. The two that matter most
# are the ones the phase plan was originally written without: turn
# exhaustion, which is the dominant outcome for a run with
# `--max-turns 30` and which carries no `.result` key at all, and a
# stream truncated mid-line by a killed process. Both used to produce
# an empty failure report in the GitHub issue comment, which is the
# regression these cases exist to pin.
#
# Self-contained: fixtures are built inline, nothing reaches the
# network, and `claude` is never invoked.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CLAUDE_RESULT="${REPO_ROOT}/tools/ci/claude-result.sh"

WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"' EXIT

FAILURES=0
CHECKS=0

start() { echo "--- $1"; }
ok() { CHECKS=$((CHECKS + 1)); echo "    ok: $1"; }
fail() {
    CHECKS=$((CHECKS + 1))
    FAILURES=$((FAILURES + 1))
    echo "    FAIL: $1" >&2
    echo "${FAILURES} failure(s); first failure aborts" >&2
    exit 1
}

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

lacks() {
    case "$2" in
        *"$3"*) fail "$1: '$3' unexpectedly in '$2'" ;;
        *) ok "$1" ;;
    esac
}

# Run and capture both output and status without tripping `set -e`.
run() {
    set +e
    OUT="$("${CLAUDE_RESULT}" "$@" 2>&1)"
    RC=$?
    set -e
}

# A result line with the given modelUsage object and nothing else
# interesting, for the trailer cases.
usage_stream() {
    # usage_stream FILE MODELUSAGE_JSON_OR_EMPTY
    if [ -z "$2" ]; then
        printf '%s\n' \
            '{"type":"result","subtype":"success","is_error":false,"num_turns":1,"result":"done"}' \
            > "$1"
    else
        printf '%s\n' \
            "{\"type\":\"result\",\"subtype\":\"success\",\"is_error\":false,\"num_turns\":1,\"result\":\"done\",\"modelUsage\":$2}" \
            > "$1"
    fi
}

trailer_line() {
    # The second line is the one under test; the first is constant.
    printf '%s\n' "${OUT}" | sed -n '2p'
}

STDERR="${WORK}/stderr.txt"
echo 'error: unknown option --nonsense' > "${STDERR}"

# --------------------------------------------------------------------
# --text
# --------------------------------------------------------------------

start "a successful stream prints the result string and no diagnostics"
SUCCESS="${WORK}/success.jsonl"
cat > "${SUCCESS}" <<'EOF'
{"type":"system","subtype":"init","session_id":"abc","model":"claude-opus-5"}
{"type":"assistant","message":{"content":[{"type":"text","text":"Reading the header parser."},{"type":"tool_use","id":"t1","name":"Read","input":{}}]}}
{"type":"user","message":{"content":[{"type":"tool_result","tool_use_id":"t1","content":"..."}]}}
{"type":"assistant","message":{"content":[{"type":"text","text":"Fixed the offset check."}]}}
{"type":"result","subtype":"success","is_error":false,"num_turns":3,"result":"Fixed the offset check.","modelUsage":{"claude-opus-5":{"outputTokens":4,"contextWindow":1000000,"canonicalModel":"claude-opus-5"}}}
EOF
run --text "${SUCCESS}" --raw-fallback "${STDERR}"
check "exit 0" "${RC}" "0"
# The old --output-format text semantics, exactly: the final result
# text and nothing else. The narration above it is NOT included --
# every consumer greps this output for a marker and one of them
# branches on the result, so a superset is not a safe superset.
check "the result string alone" "${OUT}" "Fixed the offset check."
lacks "the narration is not concatenated in" "${OUT}" "Reading the header parser."
lacks "no diagnostic block" "${OUT}" "==="
lacks "the stderr fallback is not used" "${OUT}" "unknown option"

# The regression this preference exists to stop. A run that drafts a
# marker block and then restates it used to have both drafts
# concatenated, and `sed -n '/START/,/END/p'` restarts its range on the
# second START -- so test-drift-fix.yml's commit message would hold
# both, the same defect that used to reach the retired fuzzer autofix
# loop's commits, and the comment addresser, which BRANCHED on a
# marker, threw a real fix away when a superseded DISAGREEMENT block
# came back.
start "a restated marker block does not reach the output twice"
RESTATED="${WORK}/restated.jsonl"
cat > "${RESTATED}" <<'EOF'
{"type":"assistant","message":{"content":[{"type":"text","text":"Let me draft this.\nCOMMIT_SUMMARY_START\nFix the thing (draft).\nCOMMIT_SUMMARY_END"}]}}
{"type":"assistant","message":{"content":[{"type":"text","text":"On reflection, better:\nCOMMIT_SUMMARY_START\nFix the thing properly.\nCOMMIT_SUMMARY_END"}]}}
{"type":"result","subtype":"success","is_error":false,"num_turns":2,"result":"COMMIT_SUMMARY_START\nFix the thing properly.\nCOMMIT_SUMMARY_END","modelUsage":{"claude-opus-5":{"outputTokens":9,"contextWindow":1000000,"canonicalModel":"claude-opus-5"}}}
EOF
run --text "${RESTATED}" --raw-fallback "${STDERR}"
check "exit 0" "${RC}" "0"
check "one START marker only" \
    "$(printf '%s\n' "${OUT}" | grep -c COMMIT_SUMMARY_START)" "1"
lacks "the superseded draft is gone" "${OUT}" "Fix the thing (draft)."
# The workflows' own extraction, run over this output verbatim.
check "the workflow extraction yields only the final block" \
    "$(printf '%s\n' "${OUT}" \
        | sed -n '/COMMIT_SUMMARY_START/,/COMMIT_SUMMARY_END/p' \
        | grep -v COMMIT_SUMMARY_START | grep -v COMMIT_SUMMARY_END | cat -s)" \
    "Fix the thing properly."

# ... and the other half: with no .result to prefer, the concatenation
# is all there is, and losing it would empty the failure report this
# script exists to fill. Same stream, turn-exhausted.
start "with no result string the concatenation is still kept"
RESTATED_MAXTURNS="${WORK}/restated-max-turns.jsonl"
head -n 2 "${RESTATED}" > "${RESTATED_MAXTURNS}"
printf '%s\n' \
    '{"type":"result","subtype":"error_max_turns","is_error":true,"terminal_reason":"max_turns","num_turns":2,"errors":["Reached maximum number of turns (2)"],"modelUsage":{"claude-opus-5":{"outputTokens":9,"contextWindow":1000000,"canonicalModel":"claude-opus-5"}}}' \
    >> "${RESTATED_MAXTURNS}"
run --text "${RESTATED_MAXTURNS}" --raw-fallback "${STDERR}"
check "exit 0" "${RC}" "0"
contains "the draft survives" "${OUT}" "Fix the thing (draft)."
contains "the restatement survives" "${OUT}" "Fix the thing properly."
check "both blocks are there" \
    "$(printf '%s\n' "${OUT}" | grep -c COMMIT_SUMMARY_START)" "2"
contains "and the failure is still diagnosed" "${OUT}" "terminal_reason: max_turns"

# The case the plan got wrong. .result is ABSENT, not empty, so a
# helper that read .result would report nothing at all here -- and this
# is what an automation with --max-turns 30 hits most often.
start "a turn-exhausted stream keeps the text AND names max_turns"
MAXTURNS="${WORK}/max-turns.jsonl"
cat > "${MAXTURNS}" <<'EOF'
{"type":"system","subtype":"init","session_id":"abc"}
{"type":"assistant","message":{"content":[{"type":"text","text":"I will start by reproducing the crash."}]}}
{"type":"result","subtype":"error_max_turns","is_error":true,"terminal_reason":"max_turns","num_turns":1,"duration_ms":9000,"errors":["Reached maximum number of turns (1)"],"modelUsage":{"claude-opus-5":{"outputTokens":91,"contextWindow":1000000,"canonicalModel":"claude-opus-5"}}}
EOF
run --text "${MAXTURNS}" --raw-fallback "${STDERR}"
check "exit 0" "${RC}" "0"
contains "the assistant text survives" "${OUT}" "I will start by reproducing the crash."
contains "the diagnostic names max_turns" "${OUT}" "max_turns"
contains "terminal_reason is reported" "${OUT}" "terminal_reason: max_turns"
contains "subtype is reported" "${OUT}" "subtype: error_max_turns"
contains "num_turns is reported" "${OUT}" "num_turns: 1"
contains "the errors array is reported" "${OUT}" "Reached maximum number of turns (1)"

start "a truncated stream with no result line says so and keeps the text"
TRUNCATED="${WORK}/truncated.jsonl"
printf '%s\n' \
    '{"type":"system","subtype":"init"}' \
    '{"type":"assistant","message":{"content":[{"type":"text","text":"Half of what it said."}]}}' \
    > "${TRUNCATED}"
printf '%s' '{"type":"assistant","message":{"content":[{"type":"te' >> "${TRUNCATED}"
run --text "${TRUNCATED}" --raw-fallback "${STDERR}"
check "exit 0" "${RC}" "0"
contains "the partial text survives" "${OUT}" "Half of what it said."
contains "the truncation is reported" "${OUT}" "did not finish"
lacks "the stderr fallback is not used" "${OUT}" "unknown option"

# jq exits non-zero on a line it cannot parse, which under `set -e`
# would kill the run and lose everything above the bad line.
start "a malformed last line does not lose the lines before it"
MALFORMED="${WORK}/malformed.jsonl"
printf '%s\n' \
    '{"type":"assistant","message":{"content":[{"type":"text","text":"Said before the corruption."}]}}' \
    '{"type":"result","subtype":"success","is_error":false,"num_turns":2,"result":"ok","modelUsage":{"claude-opus-5":{"outputTokens":3,"contextWindow":1000000,"canonicalModel":"claude-opus-5"}}}' \
    'not json at all {{{' \
    > "${MALFORMED}"
run --text "${MALFORMED}" --raw-fallback "${STDERR}"
check "exit 0" "${RC}" "0"
check "the result string survives the trailing garbage" "${OUT}" "ok"
lacks "the good result line is still found, so no truncation notice" "${OUT}" "did not finish"
run --trailer "${MALFORMED}"
check "trailer exit 0" "${RC}" "0"
check "the trailer still resolves the model" "$(trailer_line)" \
    "Co-Authored-By: Claude claude-opus-5 (1M context) <noreply@anthropic.com>"

start "a malformed line in the middle does not hide the lines after it"
MIDBAD="${WORK}/midbad.jsonl"
printf '%s\n' \
    '{"type":"assistant","message":{"content":[{"type":"text","text":"Before."}]}}' \
    '}{ garbage' \
    '{"type":"assistant","message":{"content":[{"type":"text","text":"After."}]}}' \
    > "${MIDBAD}"
run --text "${MIDBAD}" --raw-fallback "${STDERR}"
check "exit 0" "${RC}" "0"
contains "the text before survives" "${OUT}" "Before."
contains "the text after survives" "${OUT}" "After."

# A pre-flight CLI error -- a bad flag, an empty prompt -- writes zero
# bytes to stdout and a real message to stderr, and a CI step quotes
# this output into a GitHub issue comment.
start "an empty stream prints the raw stderr fallback verbatim"
EMPTY="${WORK}/empty.jsonl"
: > "${EMPTY}"
run --text "${EMPTY}" --raw-fallback "${STDERR}"
check "exit 0" "${RC}" "0"
check "verbatim, nothing added" "${OUT}" "$(cat "${STDERR}")"

start "a multi-line stderr fallback is printed whole"
BIGERR="${WORK}/bigerr.txt"
printf 'line one\nline two\nline three\n' > "${BIGERR}"
run --text "${EMPTY}" --raw-fallback "${BIGERR}"
check "exit 0" "${RC}" "0"
check "verbatim, nothing added" "${OUT}" "$(printf 'line one\nline two\nline three')"

# Both streams empty is the killed-process case. Reporting nothing
# would put a blank quote block in the issue comment, which is the
# failure this whole helper exists to prevent.
start "an empty stream and an empty fallback still report something"
NOERR="${WORK}/noerr.txt"
: > "${NOERR}"
run --text "${EMPTY}" --raw-fallback "${NOERR}"
check "exit 0" "${RC}" "0"
contains "says there was no output" "${OUT}" "no output at all"
run --text "${EMPTY}"
check "exit 0 without --raw-fallback at all" "${RC}" "0"
contains "says there was no output" "${OUT}" "no output at all"

# A non-empty stream holding nothing parseable is NOT the same as an
# empty one: bytes were captured and uploaded as an artifact, so the
# message must not tell the reader the process wrote nothing.
start "a non-empty but unusable stream says so distinctly"
PARTIAL="${WORK}/partial.jsonl"
printf '{"type":"system","subtype":"init","sess' > "${PARTIAL}"
run --text "${PARTIAL}" --raw-fallback "${NOERR}"
check "exit 0" "${RC}" "0"
contains "says no usable output" "${OUT}" "No usable output could be read"
contains "says it is not empty" "${OUT}" "It is not empty"
lacks "does not claim nothing was written" "${OUT}" "no output at all"
run --trailer "${PARTIAL}"
check "trailer exit 0" "${RC}" "0"
contains "unqualified trailer" "${OUT}" "Co-Authored-By: Claude <noreply@anthropic.com>"

start "a stream file that does not exist behaves like an empty one"
run --text "${WORK}/absent.jsonl" --raw-fallback "${STDERR}"
check "exit 0" "${RC}" "0"
check "the fallback is printed" "${OUT}" "$(cat "${STDERR}")"
run --trailer "${WORK}/absent.jsonl"
check "trailer exit 0" "${RC}" "0"
check "unqualified trailer" "$(trailer_line)" "Co-Authored-By: Claude <noreply@anthropic.com>"

# .subtype reads "success" on an API-level failure, so anything that
# branched on it would report this run as fine.
start "an API error is diagnosed even though its subtype says success"
APIERR="${WORK}/api-error.jsonl"
cat > "${APIERR}" <<'EOF'
{"type":"result","subtype":"success","is_error":true,"num_turns":1,"api_error_status":404,"result":"API Error: 404 model not found","modelUsage":{}}
EOF
run --text "${APIERR}" --raw-fallback "${STDERR}"
check "exit 0" "${RC}" "0"
contains "reported as a failure" "${OUT}" "reported a failure"
contains "the API status is named" "${OUT}" "api_error_status: 404"
lacks "the stderr fallback is not used" "${OUT}" "unknown option"

# Used to print nothing at all, because there was no assistant text to
# concatenate. The result string is text, and it is the only text this
# run produced.
start "a result line with is_error false and no assistant text prints the result"
QUIET="${WORK}/quiet.jsonl"
usage_stream "${QUIET}" '{"claude-opus-5":{"outputTokens":1,"contextWindow":1000000}}'
run --text "${QUIET}" --raw-fallback "${STDERR}"
check "exit 0" "${RC}" "0"
check "the result string" "${OUT}" "done"
lacks "no diagnostic block" "${OUT}" "==="

# Nothing reconstructible by either route. Silence here is an empty
# output file downstream, which reads exactly like a run that said
# nothing -- so it has to say why, and name the file to go and read.
start "a result line yielding no text at all says so instead of nothing"
NOTEXT="${WORK}/no-text.jsonl"
printf '%s\n' \
    '{"type":"result","subtype":"success","is_error":false,"num_turns":1,"modelUsage":{}}' \
    > "${NOTEXT}"
run --text "${NOTEXT}" --raw-fallback "${STDERR}"
check "exit 0" "${RC}" "0"
contains "says no text could be read" "${OUT}" "No text could be read"
contains "names the stream file" "${OUT}" "${NOTEXT}"
lacks "the stderr fallback is not used" "${OUT}" "unknown option"

# A future CLI could emit .message.content as a bare string rather than
# an array; `arrays` drops it, which is right, but the run must not
# then look silent. The result string covers it, being a plain string
# independent of the content-block schema.
start "content as a bare string still produces output"
BARESTR="${WORK}/bare-string.jsonl"
printf '%s\n' \
    '{"type":"assistant","message":{"content":"Fixed it in a new shape."}}' \
    '{"type":"result","subtype":"success","is_error":false,"num_turns":1,"result":"Fixed it in a new shape.","modelUsage":{}}' \
    > "${BARESTR}"
run --text "${BARESTR}" --raw-fallback "${STDERR}"
check "exit 0" "${RC}" "0"
check "the result string carries it" "${OUT}" "Fixed it in a new shape."

start "content as a bare string with no result string degrades visibly"
BARESTR2="${WORK}/bare-string-no-result.jsonl"
printf '%s\n' \
    '{"type":"assistant","message":{"content":"Fixed it in a new shape."}}' \
    '{"type":"result","subtype":"success","is_error":false,"num_turns":1,"modelUsage":{}}' \
    > "${BARESTR2}"
run --text "${BARESTR2}" --raw-fallback "${STDERR}"
check "exit 0" "${RC}" "0"
contains "not an empty file" "${OUT}" "No text could be read"
contains "names the stream file" "${OUT}" "${BARESTR2}"

# Whitespace reaches a marker grep exactly as zero bytes do, and tells
# a human just as little, so it takes the same branch as no text.
start "an assistant text block of only whitespace counts as no text"
BLANK="${WORK}/blank-text.jsonl"
printf '%s\n' \
    '{"type":"assistant","message":{"content":[{"type":"text","text":"   \n  \t"}]}}' \
    '{"type":"result","subtype":"success","is_error":false,"num_turns":1,"modelUsage":{}}' \
    > "${BLANK}"
run --text "${BLANK}" --raw-fallback "${STDERR}"
check "exit 0" "${RC}" "0"
contains "reported rather than emitted as whitespace" "${OUT}" "No text could be read"

# A run that FINISHED is judged by its result string alone, even when
# that string is blank. Falling back to the narration here would let a
# marker Claude typed mid-run and moved past reach a consumer that
# branches on one -- which discards a real fix in the review-comment
# loop. The narration is still in the uploaded stream; what is given
# up is only its convenience, and only on a run that ended saying
# nothing.
start "a blank result string on a finished run does not fall back"
BLANKRESULT="${WORK}/blank-result.jsonl"
printf '%s\n' \
    '{"type":"assistant","message":{"content":[{"type":"text","text":"DISAGREEMENT_START\nnot really\nDISAGREEMENT_END"}]}}' \
    '{"type":"result","subtype":"success","is_error":false,"num_turns":1,"result":"   ","modelUsage":{}}' \
    > "${BLANKRESULT}"
run --text "${BLANKRESULT}" --raw-fallback "${STDERR}"
check "exit 0" "${RC}" "0"
lacks "the mid-run marker does not survive" "${OUT}" "DISAGREEMENT_START"
contains "says why there is no text" "${OUT}" "carries no"
contains "names the stream file" "${OUT}" "${BLANKRESULT}"

# --------------------------------------------------------------------
# --trailer
# --------------------------------------------------------------------

start "the trailer's first line is constant"
run --trailer "${SUCCESS}"
check "exit 0" "${RC}" "0"
check "Assisted-By" "$(printf '%s\n' "${OUT}" | sed -n '1p')" "Assisted-By: Claude Code"
check "exactly two lines" "$(printf '%s\n' "${OUT}" | wc -l | tr -d ' ')" "2"

# Definition of done item 4, checked as an exact string.
start "one modelUsage key gives the model and the rendered window"
run --trailer "${SUCCESS}"
check "the headline case, exactly" "$(trailer_line)" \
    "Co-Authored-By: Claude claude-opus-5 (1M context) <noreply@anthropic.com>"

start "turn exhaustion still names the model"
run --trailer "${MAXTURNS}"
check "exit 0" "${RC}" "0"
check "modelUsage survives the error" "$(trailer_line)" \
    "Co-Authored-By: Claude claude-opus-5 (1M context) <noreply@anthropic.com>"

start "an absent modelUsage falls back to the unqualified trailer"
NOUSAGE="${WORK}/no-usage.jsonl"
usage_stream "${NOUSAGE}" ''
run --trailer "${NOUSAGE}"
check "exit 0" "${RC}" "0"
check "unqualified" "$(trailer_line)" "Co-Authored-By: Claude <noreply@anthropic.com>"

start "an empty modelUsage falls back to the unqualified trailer"
EMPTYUSAGE="${WORK}/empty-usage.jsonl"
usage_stream "${EMPTYUSAGE}" '{}'
run --trailer "${EMPTYUSAGE}"
check "exit 0" "${RC}" "0"
check "unqualified" "$(trailer_line)" "Co-Authored-By: Claude <noreply@anthropic.com>"

start "no result line at all falls back to the unqualified trailer"
run --trailer "${TRUNCATED}"
check "exit 0" "${RC}" "0"
check "unqualified" "$(trailer_line)" "Co-Authored-By: Claude <noreply@anthropic.com>"

start "an empty file falls back to the unqualified trailer"
run --trailer "${EMPTY}"
check "exit 0" "${RC}" "0"
check "unqualified" "$(trailer_line)" "Co-Authored-By: Claude <noreply@anthropic.com>"

# .modelUsage grows a second key when a subagent ran on another model.
# The one that did the work is the one that emitted the most tokens.
start "two modelUsage keys pick the one with the most output tokens"
TWOKEYS="${WORK}/two-keys.jsonl"
usage_stream "${TWOKEYS}" '{"claude-haiku-4-5-20251001":{"outputTokens":12,"contextWindow":200000,"canonicalModel":"claude-haiku-4-5"},"claude-opus-5":{"outputTokens":4096,"contextWindow":1000000,"canonicalModel":"claude-opus-5"}}'
run --trailer "${TWOKEYS}"
check "the busier model wins" "$(trailer_line)" \
    "Co-Authored-By: Claude claude-opus-5 (1M context) <noreply@anthropic.com>"

start "the winner is by tokens, not by map order"
TWOKEYSREV="${WORK}/two-keys-reversed.jsonl"
usage_stream "${TWOKEYSREV}" '{"claude-opus-5":{"outputTokens":4,"contextWindow":1000000,"canonicalModel":"claude-opus-5"},"claude-haiku-4-5-20251001":{"outputTokens":9000,"contextWindow":200000,"canonicalModel":"claude-haiku-4-5"}}'
run --trailer "${TWOKEYSREV}"
check "the busier model wins whichever key came first" "$(trailer_line)" \
    "Co-Authored-By: Claude claude-haiku-4-5 (200K context) <noreply@anthropic.com>"

# Measured: for haiku the map key carries a date suffix that
# .canonicalModel does not.
start "canonicalModel wins over the map key when they differ"
HAIKU="${WORK}/haiku.jsonl"
usage_stream "${HAIKU}" '{"claude-haiku-4-5-20251001":{"outputTokens":12,"contextWindow":200000,"canonicalModel":"claude-haiku-4-5"}}'
run --trailer "${HAIKU}"
check "no date suffix" "$(trailer_line)" \
    "Co-Authored-By: Claude claude-haiku-4-5 (200K context) <noreply@anthropic.com>"

start "the map key is the fallback when canonicalModel is absent"
NOCANON="${WORK}/no-canonical.jsonl"
usage_stream "${NOCANON}" '{"claude-sonnet-4-5-20250929":{"outputTokens":12,"contextWindow":200000}}'
run --trailer "${NOCANON}"
check "the key is used" "$(trailer_line)" \
    "Co-Authored-By: Claude claude-sonnet-4-5-20250929 (200K context) <noreply@anthropic.com>"

# The `strings` filter is what makes an explicit null behave like an
# absent key rather than putting the word "null" in a commit trailer,
# and nothing exercised it.
start "a null canonicalModel falls back to the map key"
NULLCANON="${WORK}/null-canonical.jsonl"
usage_stream "${NULLCANON}" '{"claude-sonnet-4-5-20250929":{"outputTokens":12,"contextWindow":200000,"canonicalModel":null}}'
run --trailer "${NULLCANON}"
check "the key is used, not null" "$(trailer_line)" \
    "Co-Authored-By: Claude claude-sonnet-4-5-20250929 (200K context) <noreply@anthropic.com>"

# Likewise `numbers`: a window arriving as a JSON string must drop the
# parenthetical rather than render an unvalidated value into it.
start "a context window given as a string drops the parenthetical"
STRWINDOW="${WORK}/string-window.jsonl"
usage_stream "${STRWINDOW}" '{"claude-opus-5":{"outputTokens":1,"contextWindow":"1000000","canonicalModel":"claude-opus-5"}}'
run --trailer "${STRWINDOW}"
check "the model still lands, without a window" "$(trailer_line)" \
    "Co-Authored-By: Claude claude-opus-5 <noreply@anthropic.com>"

# Decision 2: no prettifying, no lookup table. The id goes out verbatim.
start "the model id is emitted verbatim, not prettified"
run --trailer "${SUCCESS}"
lacks "no display name" "${OUT}" "Opus"

start "the window renders 1000000 as 1M"
W1="${WORK}/w1m.jsonl"
usage_stream "${W1}" '{"claude-opus-5":{"outputTokens":1,"contextWindow":1000000,"canonicalModel":"claude-opus-5"}}'
run --trailer "${W1}"
contains "1M" "$(trailer_line)" "(1M context)"

start "the window renders 200000 as 200K"
W2="${WORK}/w200k.jsonl"
usage_stream "${W2}" '{"claude-opus-5":{"outputTokens":1,"contextWindow":200000,"canonicalModel":"claude-opus-5"}}'
run --trailer "${W2}"
contains "200K" "$(trailer_line)" "(200K context)"

start "a window that is not a clean multiple stays as raw digits"
W3="${WORK}/w123456.jsonl"
usage_stream "${W3}" '{"claude-opus-5":{"outputTokens":1,"contextWindow":123456,"canonicalModel":"claude-opus-5"}}'
run --trailer "${W3}"
contains "raw digits" "$(trailer_line)" "(123456 context)"

start "a multiple of 1000 that is not a multiple of 1000000 renders as K"
W4="${WORK}/w2m.jsonl"
usage_stream "${W4}" '{"claude-opus-5":{"outputTokens":1,"contextWindow":15000000,"canonicalModel":"claude-opus-5"}}'
run --trailer "${W4}"
contains "15M" "$(trailer_line)" "(15M context)"
W5="${WORK}/w500k.jsonl"
usage_stream "${W5}" '{"claude-opus-5":{"outputTokens":1,"contextWindow":500000,"canonicalModel":"claude-opus-5"}}'
run --trailer "${W5}"
contains "500K" "$(trailer_line)" "(500K context)"

start "a missing context window still names the model"
NOWINDOW="${WORK}/no-window.jsonl"
usage_stream "${NOWINDOW}" '{"claude-opus-5":{"outputTokens":1,"canonicalModel":"claude-opus-5"}}'
run --trailer "${NOWINDOW}"
check "no parenthetical" "$(trailer_line)" \
    "Co-Authored-By: Claude claude-opus-5 <noreply@anthropic.com>"

start "the last result line wins when a capture holds more than one"
TWORESULTS="${WORK}/two-results.jsonl"
printf '%s\n' \
    '{"type":"result","subtype":"success","is_error":false,"modelUsage":{"claude-haiku-4-5":{"outputTokens":9,"contextWindow":200000,"canonicalModel":"claude-haiku-4-5"}}}' \
    '{"type":"result","subtype":"success","is_error":false,"modelUsage":{"claude-opus-5":{"outputTokens":9,"contextWindow":1000000,"canonicalModel":"claude-opus-5"}}}' \
    > "${TWORESULTS}"
run --trailer "${TWORESULTS}"
check "the later line is used" "$(trailer_line)" \
    "Co-Authored-By: Claude claude-opus-5 (1M context) <noreply@anthropic.com>"

# --------------------------------------------------------------------
# A broken environment
# --------------------------------------------------------------------

# "It does not fail" has to hold for a missing jq too. This script runs
# under `set -euo pipefail`, and a caller invoking it from a `set -e`
# loop with no continue-on-error to catch an abort -- as the retired
# comment addresser did -- would have a non-zero exit here end the run
# and take its summary table with it. Only cat and tail are linked in, which is everything the
# degraded paths use, plus bash itself for the `/usr/bin/env bash`
# shebang.
NOJQ="${WORK}/nojq-bin"
mkdir -p "${NOJQ}"
for B in bash cat tail; do ln -sf "$(command -v "${B}")" "${NOJQ}/${B}"; done

run_nojq() {
    set +e
    OUT="$(PATH="${NOJQ}" "${CLAUDE_RESULT}" "$@" 2>&1)"
    RC=$?
    set -e
}

start "a missing jq degrades rather than exiting non-zero"
run_nojq --text "${SUCCESS}" --raw-fallback "${STDERR}"
check "exit 0" "${RC}" "0"
contains "says jq is missing" "${OUT}" "jq is not installed"
contains "names the stream to read by hand" "${OUT}" "${SUCCESS}"
contains "the stderr is still surfaced" "${OUT}" "unknown option"

start "a missing jq still emits usable trailers"
run_nojq --trailer "${SUCCESS}"
check "exit 0" "${RC}" "0"
check "Assisted-By" "$(printf '%s\n' "${OUT}" | sed -n '1p')" "Assisted-By: Claude Code"
check "unqualified Co-Authored-By" "$(trailer_line)" \
    "Co-Authored-By: Claude <noreply@anthropic.com>"
check "exactly two lines" "$(printf '%s\n' "${OUT}" | wc -l | tr -d ' ')" "2"

start "a missing jq does not turn a usage error into a success"
run_nojq --nonsense
check "still exits 2" "${RC}" "2"

# --------------------------------------------------------------------
# Usage
# --------------------------------------------------------------------

start "argument errors are rejected"
run
check "no arguments" "${RC}" "2"
contains "reports usage" "${OUT}" "usage:"
run --text
check "--text with no file" "${RC}" "2"
run --trailer
check "--trailer with no file" "${RC}" "2"
run --raw-fallback
check "--raw-fallback with no file" "${RC}" "2"
run --nonsense
check "unrecognised flag" "${RC}" "2"
run --text "${SUCCESS}" extra
check "a stray positional argument" "${RC}" "2"
run --trailer "${SUCCESS}" --raw-fallback "${STDERR}"
check "--raw-fallback is meaningless with --trailer" "${RC}" "2"
# Last-one-wins on a second mode flag would silently write a commit
# trailer into a file the caller greps for COMMIT_SUMMARY.
run --text "${SUCCESS}" --trailer "${SUCCESS}"
check "two different mode flags" "${RC}" "2"
run --trailer "${SUCCESS}" --text "${SUCCESS}"
check "two different mode flags, other order" "${RC}" "2"
run --text "${SUCCESS}" --text "${MALFORMED}"
check "the same mode flag twice" "${RC}" "2"
run --help
check "help exits 0" "${RC}" "0"
contains "help reports usage" "${OUT}" "usage:"

echo "all claude-result tests passed (${CHECKS} checks)"
