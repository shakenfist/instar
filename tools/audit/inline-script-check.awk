# inline-script-check.awk -- flag long inline scripts in GitHub Actions
# workflows.
#
# CLAUDE.md asks for scripts of more than about five lines to live in
# tools/ and be called from the workflow, so this counts the non-blank
# body lines under every `run: |` and prints the blocks over that
# threshold. Advisory only: wave1.sh never fails on the result.
#
# Block termination follows YAML's own rule for a block scalar. The
# body's indentation is fixed by its first non-blank line, and the
# block ends at the first non-blank line indented less than that.
# Three earlier versions of this check got that rule wrong in three
# different ways, which is why test-inline-script-check.sh exists:
#
#   - NR instead of FNR numbered lines continuously across files, so
#     every reported line number after the first file was wrong.
#   - A blank line ended the block, truncating any body that opened
#     with `cd $DIR` followed by a blank line.
#   - Terminating only on a dedented *YAML key* ran straight through
#     the comments that sit between steps, so a four-line body
#     followed by eight lines of comment was reported as twelve.
#
# One known limitation remains: a heredoc whose content is indented
# less than the surrounding body ends the block early and undercounts.
# Nothing in this repository writes one, and for an advisory check the
# simpler rule is worth more than the edge case.

BEGIN { threshold = 5 }

function flush() {
    if (in_run && count > threshold) {
        print file ":" start ": run-block of " count " lines"
    }
    in_run = 0
}

# A block scalar cannot span files.
FNR == 1 { flush() }

{
    if (in_run) {
        if ($0 ~ /^[[:space:]]*$/) { next }
        indent = match($0, /[^ ]/) - 1
        if (body_indent < 0) {
            body_indent = indent
        } else if (indent < body_indent) {
            flush()
        }
    }
    if (!in_run && $0 ~ /run: \|/) {
        in_run = 1
        count = 0
        start = FNR
        file = FILENAME
        body_indent = -1
        next
    }
    if (in_run) { count++ }
}

END { flush() }
