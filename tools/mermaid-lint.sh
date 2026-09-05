#!/bin/bash
#
# Render every mermaid diagram in the repository's markdown and fail on
# any that does not parse.
#
# Copied from shakenfist/development at templates/mermaid-lint/. Keep
# it in step with that copy rather than editing it in place.
#
# Mermaid fails at render time, not at commit time, so a diagram with a
# syntax error is a silently broken documentation page: GitHub shows an
# error box and mkdocs shows nothing. Nothing else in CI reads a
# diagram, which is why this exists as its own lane.
#
# Rendering is what mermaid-cli does, and rendering needs a browser, so
# this runs in the upstream container rather than installing a
# chromium and a node toolchain onto a runner. There is no lighter
# path worth taking: mermaid's own parse() under plain node throws
# "DOMPurify.addHook is not a function" for flowchart and
# stateDiagram-v2 -- the two most common types here -- so a DOM-free
# checker reports false failures on exactly the diagrams that matter.
#
# Usage:
#   tools/mermaid-lint.sh            # every tracked markdown file
#   tools/mermaid-lint.sh a.md b.md  # just these

set -euo pipefail

# Pinned deliberately, by digest as well as by tag: a tag is mutable
# and this runs a third-party container on a runner with a docker
# daemon. The tag is for a human reading this; the digest is what
# actually pins. Renovate's stock managers do not read a docker
# reference out of a shell script, so this moves when somebody moves
# it; check for a newer tag when a mermaid feature is missing, and
# take the new digest from the pull rather than trusting the tag
# alone.
IMAGE_TAG="ghcr.io/mermaid-js/mermaid-cli/mermaid-cli:11.4.2"
IMAGE="${IMAGE_TAG}@sha256:99c983b3ab4e14033f2880bc1b9de17e5090b4515dabd63fe9cf8c0ae6130956"

repo_root=$(git rev-parse --show-toplevel)

# Named files are resolved against the caller's directory and turned
# into repository-relative paths, because everything below -- the cd,
# the /src mount, the paths printed in the output -- is relative to
# the repository root. A name that does not resolve is an error
# rather than an empty run: the documented per-file usage is exactly
# the invocation a typo reaches, and a linter that exits zero on a
# path it never read is the failure this script exists to prevent.
candidates=()
if [ "$#" -gt 0 ]; then
    for arg in "$@"; do
        if [ ! -f "${arg}" ]; then
            echo "mermaid-lint: no such file: ${arg}" >&2
            exit 1
        fi
        rel=$(realpath --relative-to="${repo_root}" "${arg}")
        if [ "${rel#../}" != "${rel}" ]; then
            echo "mermaid-lint: outside the repository: ${arg}" >&2
            exit 1
        fi
        candidates+=("${rel}")
    done
    cd "${repo_root}"
else
    # git ls-files rather than find, so vendored and ignored trees are
    # excluded for free. A Rust project's .cargo-cache alone holds
    # thousands of markdown files nobody here wrote, several of which
    # contain diagrams that are not ours to fix.
    cd "${repo_root}"
    # NUL-delimited, because git C-quotes a path it cannot print
    # literally: a non-ASCII byte unless core.quotePath is off, and a
    # double quote, a backslash or a control character whatever that
    # setting says. A quoted string names no file that exists and is
    # dropped by the -f test below -- another diagram unlinted behind
    # a green run. -z quotes nothing at all, so it subsumes the
    # setting rather than covering one more case than it did.
    #
    # REVIEWS.md is excluded to match the workflow's path filter, which
    # excludes it so that a review session or a bot prune does not cost
    # a virtual machine. The two have to agree: a lane that never runs
    # on the file that changed, but lints it on every other pull
    # request, reports a broken diagram to whoever next touched an
    # unrelated markdown file, and to every developer running the
    # pre-push audit. Excluded here rather than un-excluded there
    # because a diagram in generated review tracking is not what this
    # lane is for; name the file on the command line to lint it anyway.
    #
    # The pathspec is a literal, so it matches the file at the
    # repository root and not a docs/REVIEWS.md -- the same scope the
    # workflow's '!REVIEWS.md' has.
    mapfile -d '' -t candidates \
        < <(git ls-files -z '*.md' ':(exclude)REVIEWS.md')
fi

# Backticks only, and no space before the language: that is what mmdc
# recognises. Anything else renders nothing and exits zero, which is
# why check_mermaid_lint_ci in the development repository matches the
# same narrow form -- the audit must not call a repository covered for
# a diagram this script cannot see.
#
# GitHub renders both a tilde fence and a spaced info string as
# diagrams all the same, so either would otherwise ship unlinted
# through the exact gap this script exists to close. Rather than fail
# open, refuse the file and say what to change: the narrow
# mmdc-compatible form stays the only one that can be committed
# unnoticed.
#
# Which means the scan has to track fence state rather than match bare
# lines. A fence shown inside a longer fence is an example being
# written about, not a diagram to render, and the page most likely to
# contain one is the page explaining this very rule -- so a line
# match would fail the repository for documenting its own linter. The
# rules are CommonMark's: a fence opens on three or more backticks or
# tildes and closes on the same character, at least as long, with no
# info string, and only fences that open at the top level are
# classified. mmdc reads nested examples too, so a file selected for
# some other diagram is still rendered whole; what this decides is
# which files are worth starting a container for, and which are
# refused outright.
#
# Indented code blocks are deliberately not modelled. Four spaces
# before a fence is far more often a fence inside a list item, which
# must still be linted, than a fence being quoted -- so treating the
# indent as a code block would fail open on real diagrams to spare a
# rarer false positive. Quote a fence inside a longer fence instead;
# the template README says so.
#
# Blockquotes are not modelled either, and that one does fail open: a
# leading "> " leaves ch=">" and run=0, so the fence is neither
# selected nor refused, while GitHub renders it and mmdc reports "No
# mermaid charts found" -- measured against the pinned image, not
# assumed. It is left that way because the audit's regex does not see
# such a fence either, so the two halves agree and no repository is
# called covered for a diagram nothing renders; and because refusing
# one means deciding what a fence nested inside a blockquoted fence
# is, which is a new rule with a new blind spot. Put a diagram at the
# top level.
existing=()
newline_named=()
for candidate in "${candidates[@]}"; do
    # A newline in the name is refused rather than scanned. Everything
    # downstream of the scan is line oriented -- files.txt, and the
    # POSIX sh loop inside the container that reads it, which has no
    # read -d to switch. Such a path would be silently truncated into
    # a name that renders nothing, so it is named and the run made red
    # instead. The scan itself is NUL delimited and would carry it
    # fine; this is the container side that cannot.
    if [ "${candidate}" != "${candidate%%$'\n'*}" ]; then
        newline_named+=("${candidate%%$'\n'*}...")
        continue
    fi
    # Only reachable on the git ls-files path, where an entry can be
    # staged for deletion; a named file was checked above.
    if [ -f "${candidate}" ]; then
        # "./" prefixed, because awk reads an operand shaped like
        # name=value as a variable assignment rather than a file, and
        # a repository-root "a=b.md" would go unscanned. The prefix
        # is taken back off FILENAME before anything is printed.
        existing+=("./${candidate}")
    fi
done

# The workdir is made here rather than at the render step, because the
# scan writes into it too.
workdir=$(mktemp -d)
trap 'rm -rf "${workdir}"' EXIT

# Into a file rather than through a process substitution, so that an
# awk that dies takes the script with it under set -e. A scan that
# failed silently would report no diagrams and exit zero, which is the
# shape of failure this whole lane exists to prevent.
#
# A file rather than a variable because the records are NUL delimited
# and a bash variable cannot hold a NUL byte. NUL is what makes the
# name unambiguous: a tracked path may begin or end with a space, and
# a whitespace-delimited protocol here would undo the NUL-delimited
# listing above one step later, handing the renderer a name that
# matches no file.
#
# stdin is closed for the same reason the status is checked. awk with
# no file operands reads stdin, so a list that somehow reduced to none
# would not fail -- it would block forever waiting on a terminal, or
# read whatever CI happened to hand it.
: > "${workdir}/scan"
if [ "${#existing[@]}" -ne 0 ]; then
    awk '
        FNR == 1 {
            fence = ""; flen = 0; backtick = 0
        }
        {
            line = $0
            # A markdown file committed with CRLF endings would
            # otherwise carry the carriage return into the info
            # string, so no fence would open and none would close.
            # mmdc reads such a file perfectly well, so the whole
            # file would go unlinted while the run reported success.
            sub(/\r$/, "", line)
            sub(/^[ \t]*/, "", line)
            ch = substr(line, 1, 1)
            run = 0
            if (ch == "`" || ch == "~")
                while (substr(line, run + 1, 1) == ch)
                    run++
            if (run < 3)
                next

            # CommonMark: the info string of a backtick fence may
            # not contain a backtick. That one rule is what separates
            # an opening fence from a line of prose beginning with an
            # inline code span -- which is how a sentence quoting a
            # fence starts, and so how this very rule gets written
            # about. Miss it and such a line opens a fence nothing
            # closes, swallowing every diagram below it in the file
            # behind a "nothing to lint" and an exit 0.
            if (ch == "`" && index(substr(line, run + 1), "`"))
                next

            # Two readings of the info string. CommonMark allows
            # whitespace before it, and a closing fence is one that
            # carries nothing else, so the closing test uses the
            # stripped form. mmdc wants the language hard against the
            # backticks, so the opening test uses the raw form: `` `
            # mermaid `` is a fence GitHub renders and mmdc reads
            # nothing in, which is the same failure as a tilde fence
            # and is refused the same way.
            info = substr(line, run + 1)
            sub(/^[ \t]+/, "", info)
            sub(/[ \t].*$/, "", info)

            raw = substr(line, run + 1)
            sub(/[ \t].*$/, "", raw)

            if (fence != "") {
                if (ch == fence && run >= flen && info == "")
                    fence = ""
                next
            }

            fence = ch
            flen = run
            if (info != "mermaid")
                next

            name = FILENAME
            sub(/^\.\//, "", name)

            # Every refusal is printed, not just the first of its
            # kind in the file. Suppressing the rest would make an
            # author fix one fence, re-run, and be told about the
            # next -- the same round trip the refusals fall through
            # to the render step to avoid. The selection is deduped
            # instead, because each name printed there becomes an
            # operand for the renderer and a file listed twice would
            # be rendered twice.
            #
            # A record is kind, line and name joined by colons and
            # terminated by a NUL, because a tracked path may begin
            # or end with a space and a whitespace-delimited protocol
            # would lose it. kind carries no colon and the line is
            # digits, so the reader can split the two off the front
            # and keep everything after as the name.
            #
            # The fence character is tested before the info string,
            # so that a tilde fence with a space gets a remedy that
            # fixes it. Classified the other way it is told to remove
            # the space, which yields a tilde fence, which the next
            # run refuses -- the round trip again.
            if (ch == "~") {
                if (raw != "mermaid")
                    printf "%s:%d:%s%c", "tilde_spaced", FNR, name, 0
                else
                    printf "%s:%d:%s%c", "tilde", FNR, name, 0
                next
            }
            if (raw != "mermaid") {
                printf "%s:%d:%s%c", "spaced", FNR, name, 0
                next
            }
            if (!backtick) {
                backtick = 1
                printf "%s:%d:%s%c", "backtick", FNR, name, 0
            }
        }
    ' "${existing[@]}" < /dev/null > "${workdir}/scan"
fi

files=()
tilde_fenced=()
spaced_info=()
tilde_spaced=()
# IFS emptied and -d '' set, so a name keeping a leading or trailing
# space arrives intact. The default read would strip both.
while IFS= read -r -d '' record; do
    kind=${record%%:*}
    rest=${record#*:}
    lineno=${rest%%:*}
    scanned_file=${rest#*:}
    case "${kind}" in
        backtick) files+=("${scanned_file}") ;;
        tilde) tilde_fenced+=("${scanned_file}:${lineno}") ;;
        spaced) spaced_info+=("${scanned_file}:${lineno}") ;;
        tilde_spaced) tilde_spaced+=("${scanned_file}:${lineno}") ;;
    esac
done < "${workdir}/scan"

# Name the file, the line and the remedy. A linter that refuses a page
# without saying where and what to change turns this into a support
# burden, and the line number is free -- the scan is already there.
refuse() {
    local reason=$1
    shift
    local refused
    for refused in "$@"; do
        echo "mermaid-lint: ${refused}: ${reason}" >&2
    done
}

rc=0
docker_rc=0

if [ "${#tilde_fenced[@]}" -ne 0 ]; then
    refuse "mermaid in a tilde fence is not linted; use a backtick fence" \
        "${tilde_fenced[@]}"
    rc=1
fi

if [ "${#spaced_info[@]}" -ne 0 ]; then
    refuse "mermaid after a space is not linted; remove the space" \
        "${spaced_info[@]}"
    rc=1
fi

# One remedy, not two applied in sequence. Told only to remove the
# space, the author is left with a tilde fence the next run refuses.
if [ "${#tilde_spaced[@]}" -ne 0 ]; then
    both="mermaid in a spaced tilde fence is not linted;"
    refuse "${both} use a backtick fence with no space" \
        "${tilde_spaced[@]}"
    rc=1
fi

# A path the container's line-oriented loop cannot carry. Named rather
# than skipped, for the same reason a tilde fence is.
if [ "${#newline_named[@]}" -ne 0 ]; then
    refuse "a newline in the path is not linted; rename the file" \
        "${newline_named[@]}"
    rc=1
fi

# Both refusals fall through rather than exiting here. A repository
# with a refused fence and a diagram that does not parse should learn
# about both from one run: the virtual machine this lane needs is the
# expensive part, and the path filter exists to avoid spinning a
# second one to deliver the second half of the same answer.

if [ "${#files[@]}" -eq 0 ]; then
    if [ "${rc}" -eq 0 ]; then
        echo "No markdown files contain mermaid diagrams; nothing to lint."
    fi
    exit "${rc}"
fi

printf '%s\n' "${files[@]}" > "${workdir}/files.txt"

echo "Linting ${#files[@]} file(s) containing mermaid diagrams."

# One container for the whole run: startup dominates, so a container
# per file roughly doubles the cost. The image's entrypoint supplies
# -p /puppeteer-config.json, which the sandbox needs, so overriding
# the entrypoint means passing it back by hand.
#
# The exit status of docker run is the inner shell's, and it is the
# whole point of this script. Do not pipe this into tail or grep: the
# pipeline would report the filter's status and turn every failure
# green. Its status is captured rather than left to set -e, which
# would abort here and lose the refusals already counted; taking $?
# rather than a flat 1 keeps a 125 from a failed image pull
# distinguishable from a diagram that does not parse.
#
# --network none because rendering a diagram is a local operation and
# this is a third-party container driving a browser over repository
# content. Chromium and mmdc talk over loopback, which a none network
# still provides, so the sandbox is unaffected; what goes away is the
# ability to fetch a remote font or icon pack, and a diagram that
# needs one should fail loudly here rather than render differently on
# a runner with a different egress path. The daemon pulls a missing
# image before the container starts, so the pin still works.
docker run --rm --network none -u "$(id -u):$(id -g)" \
    -v "${repo_root}":/src:ro \
    -v "${workdir}":/work \
    --entrypoint /bin/sh "${IMAGE}" -c '
        mmdc=/home/mermaidcli/node_modules/.bin/mmdc
        rc=0
        while IFS= read -r f; do
            if "${mmdc}" -p /puppeteer-config.json \
                    -i "/src/${f}" -o /work/rendered.md \
                    >/work/log 2>&1; then
                echo "ok    ${f}"
            else
                rc=1
                echo "FAIL  ${f}"
                # Trim the puppeteer stack trace through mermaid.js,
                # which says nothing about the diagram. What is left
                # is the parse error and its caret, which is what a
                # person needs.
                sed "/mermaidcli\/node_modules/,\$d" /work/log \
                    | sed "s/^/        /"
            fi
        done < /work/files.txt
        exit "${rc}"
    ' || docker_rc=$?

# A refused fence outranks the renderer's status. Both are failures
# and either alone is reported as itself, but when they coincide the
# content failure is the one the author has to act on, and reporting
# it as a 125 would send them looking at the image pull.
if [ "${rc}" -eq 0 ]; then
    rc="${docker_rc}"
fi

exit "${rc}"
