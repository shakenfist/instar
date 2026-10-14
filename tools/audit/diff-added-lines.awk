# Read a unified diff on stdin; print each ADDED line as
# "<path>:<line>: <content>".
#
# The wave 2 checks for new `unsafe`, new `.unwrap()`/`.expect()` and
# new `#[allow(dead_code)]` used to grep the diff with `grep -n`, which
# numbers lines in the concatenated diff stream. That is a position in
# a temporary artefact: it matches neither the source file nor the
# scope.patch handed to the judgment agents (unless that was built
# byte-for-byte the same way), and over a 55,000-line union it looks
# like a location while pointing nowhere. The diff already carries the
# path in its `+++` header and the new-file line number in each hunk
# header, so the real location is derivable.
#
# <line> is the line's number in the file as that commit left it. For
# a single range that is the current file. For a --commits-file union
# it is the file as of that commit, which a later commit in the union
# may have shifted -- the path is always right, the number is right as
# of its own commit. Still far better than a stream offset, and the
# alternative (re-finding each line in HEAD) cannot work for a line a
# later commit changed again.
#
# Why the hunk bookkeeping, rather than matching `^+++ ` wherever it
# appears: a diff body line is its marker followed by the content, so
# an added line whose content starts with "++ " appears as "+++ ...",
# and a removed line whose content starts with "-- " appears as
# "--- ...". Matched blind, the first is read as a file header -- the
# line is dropped, and every later line in that file is attributed to
# a path invented from its content. Measured before this was fixed: a
# file containing "++ y" reported its next line as "y:1:", a path that
# does not exist. So the ranges in each hunk header are tracked, and
# only a "+++ " seen outside a hunk is a header. The same reasoning
# applies to "--- ", which is why that is not matched at all.
#
# Only added lines are emitted, so a grep downstream does not need to
# anchor on a leading "+", and context lines cannot match.
#
# This lives in its own file, like inline-script-check.awk, so
# test-diff-added-lines.sh can exercise it against fixtures.

BEGIN {
    in_hunk = 0
    # Named rather than left empty, so a malformed diff produces a
    # visibly wrong path instead of a plausible one beginning with ":".
    path = "(no +++ header seen)"
}

# "+++ b/path", only when not inside a hunk. The path is taken from the
# whole line rather than from $2: awk's field splitting would cut it at
# the first space, which turned "f2 with space.rs" into "f2" -- a
# wrong-but-plausible location of exactly the kind this file exists to
# stop reporting.
!in_hunk && /^\+\+\+ / {
    path = substr($0, 5)
    # git appends a TAB after the path when the path contains a space.
    sub(/\t.*$/, "", path)
    # git C-quotes a path with unusual bytes as "b/...". The readers
    # pass -c core.quotePath=false so non-ASCII comes through plain;
    # what is left quoted (an embedded tab or newline) keeps its quotes
    # and escapes, which is honest about what the path is rather than
    # guessing at an unescaping.
    if (path ~ /^".*"$/) {
        path = substr(path, 2, length(path) - 2)
    }
    sub(/^b\//, "", path)
    next
}

# "@@ -old[,count] +new[,count] @@ [section heading]". A hunk with a
# single line on a side omits that side's count.
/^@@ / {
    spec = $2
    sub(/^-/, "", spec)
    split(spec, old_range, ",")
    remaining_old = (2 in old_range) ? old_range[2] + 0 : 1

    spec = $3
    sub(/^\+/, "", spec)
    split(spec, new_range, ",")
    lineno = new_range[1] + 0
    remaining_new = (2 in new_range) ? new_range[2] + 0 : 1

    in_hunk = (remaining_old > 0 || remaining_new > 0)
    next
}

# A hunk body line. Its first byte is the marker, so the content is
# everything after it. An added line exists only in the new file; a
# removed line only in the old; a context line in both.
in_hunk {
    marker = substr($0, 1, 1)
    if (marker == "+") {
        print path ":" lineno ": " substr($0, 2)
        lineno++
        remaining_new--
    } else if (marker == "-") {
        remaining_old--
    } else if (marker == " " || $0 == "") {
        # An empty context line can reach us as a bare "" rather than
        # a single space, depending on what produced the diff.
        lineno++
        remaining_new--
        remaining_old--
    } else {
        # "\ No newline at end of file" belongs to the line before it
        # and consumes neither side.
        next
    }
    if (remaining_old <= 0 && remaining_new <= 0) {
        in_hunk = 0
    }
    next
}

# Outside a hunk: "diff --git", "index", "--- a/path", "old mode",
# "Binary files ... differ", and the "# commit ..." markers
# scope-patch.sh adds.
{ next }
