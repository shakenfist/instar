#!/usr/bin/env bash
#
# Read the JSONL stream a `claude -p --output-format stream-json
# --verbose` run leaves behind, and produce either the text the
# automation reports or the commit trailer naming the model that
# actually ran.
#
# Three automations run Claude Code unattended -- fuzz-autofix.yml,
# test-drift-fix.yml and tools/address-comments-with-claude.sh -- and
# every one of them used to hardcode the model in its Co-Authored-By
# trailer. By the time anyone looked they disagreed three ways
# (`Claude Opus 4.6 (1M context)` in one, `Claude Opus 4.5` in the
# other two) and none of them named the model the CLI actually
# resolves to today. The master plan justified the hardcoding by
# asserting that the workflow "cannot introspect which model the
# `claude` CLI resolves to". That was measured and it is false: the
# run's own output reports the resolved model and its context window
# in `.modelUsage`. Deriving the trailer here is the only version of
# this that cannot go stale a fourth time.
#
# WHAT IT DELIBERATELY DOES NOT DO
#
#   * It does not prettify the model id. The trailer says
#     `Claude claude-opus-5 (1M context)`, not `Claude Opus 5`, even
#     though human commits on this repo use the latter form. Turning
#     the id into a display name needs either a lookup table -- which
#     is precisely the staleness this script exists to delete, just
#     moved one file over -- or a mechanical de-slugging, which mangles
#     the cases it has to handle (`claude-haiku-4-5-20251001`). The id
#     is unambiguous, machine-checkable against the model roster, and
#     honest about what ran.
#
#   * It does not read the model name from the `.modelUsage` map key.
#     The key and `.canonicalModel` inside its value differ: for haiku
#     the key carries a date suffix (`claude-haiku-4-5-20251001`) and
#     `.canonicalModel` does not. The key is the fallback, not the
#     source.
#
#   * It does not trust `.subtype`. An API-level failure -- an unknown
#     `--model`, say -- reports `"subtype": "success"` alongside
#     `"is_error": true` and `"api_error_status": 404`. `.is_error` and
#     the process exit status are the error signals; `.subtype` is only
#     ever reported, never branched on.
#
#   * It does not fail. A truncated, malformed or entirely empty
#     stream is an expected input, not an exceptional one, and every
#     caller redirects this script's stdout into a file it then reads
#     for markers and publishes: fuzz-autofix.yml greps it for the
#     COMMIT_SUMMARY block and uploads it as a run artifact, and
#     address-comments-with-claude.sh greps it for DISAGREEMENT_START
#     and CHANGE_SUMMARY_START, whose contents reach the pull request's
#     summary comment. Exiting non-zero there would replace a partial
#     diagnosis with none at all. Whether the run failed is already
#     known from `claude`'s own exit status at the call site.
#
# WHY THE INPUT LOOKS LIKE THIS
#
# The automations used to capture `--output-format text` with stderr
# folded in. Plain `--output-format json` was measured as the
# replacement and rejected: turn exhaustion -- the dominant outcome for
# a run with `--max-turns 30` -- omits `.result` entirely and leaves
# stderr empty, so the failure report would have quoted an empty file
# into the issue; and the document is written atomically at exit, so a
# run killed by a timeout leaves zero bytes on both streams. The
# line-delimited stream fixes both: it tees for live CI output, a
# killed run still leaves a usable prefix, and the assistant text
# reconstructed from it is a superset of what `--output-format text`
# gave. The cost is that every read here has to tolerate a file that
# ends mid-line.
#
# Turn exhaustion is therefore the primary case, not an edge case. Its
# result line carries `"subtype":"error_max_turns"`, `"is_error":true`,
# `"terminal_reason":"max_turns"`, an `.errors` array, no `.result` key
# at all, and an intact `.modelUsage`. If you are changing this script,
# that is the fixture to run first.
#
# Usage:
#   tools/ci/claude-result.sh --text STREAM [--raw-fallback FILE]
#       Print the assistant text, followed by a diagnostic block if the
#       run reported an error or the stream has no result line. If
#       neither any assistant text nor any result line can be read,
#       print FILE verbatim instead -- that is the pre-flight CLI error
#       case, where `claude` wrote nothing to stdout but a real message
#       to stderr, and that message has to survive into the issue
#       comment.
#
#   tools/ci/claude-result.sh --trailer STREAM
#       Print two lines:
#           Assisted-By: Claude Code
#           Co-Authored-By: Claude MODEL (WINDOW context) <noreply@...>
#       falling back to an unqualified `Co-Authored-By: Claude
#       <noreply@anthropic.com>` when the stream does not say what ran.
#
# Covered by tools/ci/test-claude-result.sh.
#
# Exit codes: 0 always, except 2 for a usage error.

set -euo pipefail

usage() {
    echo "usage: $0 [--text STREAM [--raw-fallback FILE] | --trailer STREAM]"
}

MODE=
STREAM=
RAW_FALLBACK=
while [ "$#" -gt 0 ]; do
    case "$1" in
        --text)
            MODE=text
            STREAM="${2:-}"
            [ -n "${STREAM}" ] || { usage >&2; exit 2; }
            shift 2
            ;;
        --trailer)
            MODE=trailer
            STREAM="${2:-}"
            [ -n "${STREAM}" ] || { usage >&2; exit 2; }
            shift 2
            ;;
        --raw-fallback)
            RAW_FALLBACK="${2:-}"
            [ -n "${RAW_FALLBACK}" ] || { usage >&2; exit 2; }
            shift 2
            ;;
        -h|--help) usage; exit 0 ;;
        --) shift; break ;;
        *) usage >&2; exit 2 ;;
    esac
done

if [ "$#" -gt 0 ] || [ -z "${MODE}" ]; then
    usage >&2
    exit 2
fi

if [ "${MODE}" != text ] && [ -n "${RAW_FALLBACK}" ]; then
    usage >&2
    exit 2
fi

# Every read of the stream goes through one of these two, and both are
# built so that a line which is not parseable JSON, or is parseable but
# is not the object shape expected, contributes nothing and does not
# stop the read:
#
#   * `fromjson?` swallows the parse error a mid-line truncation
#     produces, so jq still exits 0 and `set -e` does not kill the run;
#   * `objects`, `arrays` and `strings` drop anything of the wrong type
#     rather than raising "cannot index" on it.
#
# The file is checked for existence and non-emptiness before jq is
# invoked at all: a pre-flight CLI error and a killed process both
# leave zero bytes, and that is a normal input here.

assistant_text() {
    [ -s "${STREAM}" ] || return 0
    jq -Rr '
        fromjson?
        | objects
        | select(.type == "assistant")
        | .message | objects
        | .content | arrays
        | .[] | objects
        | select(.type == "text")
        | .text | strings
    ' "${STREAM}"
}

# The last result line, compact, or nothing. Last rather than first:
# the stream carries one, but a concatenated or resumed capture could
# carry more, and the final one is the one that describes the outcome.
last_result() {
    [ -s "${STREAM}" ] || return 0
    jq -Rc '
        fromjson?
        | objects
        | select(.type == "result")
    ' "${STREAM}" | tail -n 1
}

emit_text() {
    local text result had_error diagnostics

    text="$(assistant_text)"
    result="$(last_result)"

    if [ -z "${text}" ] && [ -z "${result}" ]; then
        # Nothing usable in the stream. The real message is on
        # stderr: `claude` refuses a bad flag or an empty prompt
        # before it writes a single line of stdout, and this output is
        # the only place a human will look for the reason.
        if [ -n "${RAW_FALLBACK}" ] && [ -s "${RAW_FALLBACK}" ]; then
            cat "${RAW_FALLBACK}"
            return 0
        fi
        # Nothing on stderr either. Say so rather than reporting
        # nothing, so the issue comment is not a blank quote block --
        # but distinguish the two shapes, because they point at
        # different causes and this text is what a human reads first.
        if [ -s "${STREAM}" ]; then
            # Bytes, but not one complete assistant or result line.
            # The capture was cut before the first message finished.
            echo "No usable output could be read from ${STREAM}."
            echo "It is not empty, but it holds no complete assistant or result line,"
            echo "so the capture was cut before the first message finished. The raw"
            echo "stream is in this run's uploaded artifacts."
        else
            echo "claude produced no output at all: ${STREAM} is empty or missing,"
            echo "and no stderr was captured either. The process was most likely killed"
            echo "before it could write anything."
        fi
        return 0
    fi

    [ -z "${text}" ] || printf '%s\n' "${text}"

    if [ -z "${result}" ]; then
        [ -z "${text}" ] || echo
        echo "=== claude did not finish ==="
        echo "The stream ends without a result line, so the process was killed or"
        echo "the capture was truncated. Anything above is what it had said by then."
        return 0
    fi

    had_error="$(printf '%s' "${result}" | jq -r 'if (.is_error == true) then "yes" else "no" end')"
    [ "${had_error}" = yes ] || return 0

    # Report .subtype, never branch on it: it reads "success" on an
    # API error. Only the keys that are present are named, because
    # which ones are present is itself the diagnosis -- turn
    # exhaustion has .terminal_reason and .errors and no .result, an
    # API error has .api_error_status and a .result holding the error
    # string.
    diagnostics="$(printf '%s' "${result}" | jq -r '
        [
            (if has("terminal_reason") then "terminal_reason: \(.terminal_reason)" else empty end),
            (if has("subtype") then "subtype: \(.subtype)" else empty end),
            (if has("num_turns") then "num_turns: \(.num_turns)" else empty end),
            (if has("api_error_status") then "api_error_status: \(.api_error_status)" else empty end),
            (if (.errors | arrays | length) > 0 then
                "errors:", (.errors[] | if type == "string" then "    \(.)" else "    \(tojson)" end)
             else empty end)
        ] | .[]
    ')"

    [ -z "${text}" ] || echo
    echo "=== claude reported a failure ==="
    [ -z "${diagnostics}" ] || printf '%s\n' "${diagnostics}"
}

# 1000000 -> 1M, 200000 -> 200K, anything not a clean multiple of 1000
# -> the raw digits. Matches the (1M context) / (200K context) forms
# already in this repo's history.
render_window() {
    local n="$1"
    case "${n}" in
        ''|*[!0-9]*) return 1 ;;
    esac
    [ "${n}" -gt 0 ] || return 1
    if [ $((n % 1000000)) -eq 0 ]; then
        echo "$((n / 1000000))M"
    elif [ $((n % 1000)) -eq 0 ]; then
        echo "$((n / 1000))K"
    else
        echo "${n}"
    fi
}

emit_trailer() {
    local result info model window rendered

    echo "Assisted-By: Claude Code"

    result="$(last_result)"
    if [ -n "${result}" ]; then
        # The entry with the most output tokens is the model that did
        # the work: .modelUsage grows a second key when a subagent ran
        # on a different model (a same-model subagent collapses into
        # the one key), and it can also be {} outright on an API
        # error. .canonicalModel comes from the value, with the map key
        # as the fallback.
        info="$(printf '%s' "${result}" | jq -r '
            (.modelUsage | objects | to_entries
             | map(select((.value | type) == "object"))) as $entries
            | if ($entries | length) == 0 then empty
              else
                ($entries | max_by(.value.outputTokens // 0)) as $e
                | (($e.value.canonicalModel | strings // "") as $canonical
                   | if $canonical == "" then $e.key else $canonical end)
                  + "\t"
                  + (($e.value.contextWindow | numbers // "") | tostring)
              end
        ')"
    else
        info=
    fi

    if [ -z "${info}" ]; then
        echo "Co-Authored-By: Claude <noreply@anthropic.com>"
        return 0
    fi

    model="${info%%$'\t'*}"
    window="${info#*$'\t'}"

    if rendered="$(render_window "${window}")"; then
        echo "Co-Authored-By: Claude ${model} (${rendered} context) <noreply@anthropic.com>"
    else
        # A model with no reported context window still names the model,
        # which is the whole point; the parenthetical is dropped rather
        # than filled in with a guess.
        echo "Co-Authored-By: Claude ${model} <noreply@anthropic.com>"
    fi
}

case "${MODE}" in
    text) emit_text ;;
    trailer) emit_trailer ;;
esac
