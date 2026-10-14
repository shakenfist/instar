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
# Only added lines are emitted, so a grep downstream does not need to
# anchor on a leading "+", and context lines cannot match.
#
# This lives in its own file, like inline-script-check.awk, so
# test-diff-added-lines.sh can exercise it against fixtures.

# "+++ b/path", or "+++ /dev/null" for a deleted file. Matched before
# the /^\+/ rule below, which would otherwise treat it as content.
/^\+\+\+ / {
    path = $2
    sub(/^b\//, "", path)
    next
}

# "@@ -old[,count] +new[,count] @@ optional section heading". $3 is the
# "+new[,count]" field; a hunk with a single added line omits the count.
/^@@ / {
    spec = $3
    sub(/^\+/, "", spec)
    split(spec, parts, ",")
    lineno = parts[1] + 0
    next
}

# An added line. Advances the new-file line counter.
/^\+/ {
    print path ":" lineno ": " substr($0, 2)
    lineno++
    next
}

# A removed line exists only in the old file, so it does not advance
# the new-file counter.
/^-/ { next }

# A context line is in both, so it does advance it. Written as a two
# character match because a context line is a space followed by the
# content, and an empty context line is a bare space.
/^ / {
    lineno++
    next
}

# Everything else -- "diff --git", "index", "--- a/path", "\ No newline
# at end of file", and the "# commit ..." markers scope-patch.sh adds.
{ next }
