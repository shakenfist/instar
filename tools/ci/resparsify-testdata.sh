#!/usr/bin/env bash
#
# Restore sparseness to the downloaded images in an instar-testdata tree.
#
# git and git-lfs write every file out fully allocated, so a clone, a
# reset or an `lfs pull` fills each image's holes with real blocks of
# zeros. Two things go wrong when that is left alone. The tree becomes
# about 7.5 GiB of mostly zeros, which is most of a runner's disk; and
# `qemu-img info` reports the allocated size it finds, so the tests that
# compare instar's disk_size against qemu-img's see an allocation that
# belongs to git rather than to the fixture.
#
# `cp --sparse=always` rewrites the holes. It is cheap and idempotent, so
# running it over a tree that is already sparse costs little and is the
# normal case on a cached tree.
#
# Scope is deliberately narrow, and widening it is a behaviour change
# rather than a tidy-up: only `downloaded/`, and only the five image
# extensions listed below. The `custom/` fixtures are left with whatever
# allocation their tests expect, and extensions that are not whole-disk
# images (`*.raw` backing files among them) are left alone.
#
# CONSUMERS OUTSIDE THIS REPOSITORY. private-ci's instar-testdata
# dependencies-disk image build fetches this file from instar's default
# branch over HTTPS and runs it as the `debian` user against its own
# clone, nowhere near GitHub Actions. Changing how this script is called
# breaks that nightly image build, so the interface is fixed:
#
#     resparsify-testdata.sh <testdata-tree>
#
#   - Exactly one positional argument, the path to the testdata tree,
#     and that one-argument form means "resparsify the whole tree"
#     permanently.
#   - No reliance on any GITHUB_* variable, or on any other environment
#     variable at all.
#   - A non-zero exit on any failure, so a caller that cannot fetch or
#     cannot run this fails loudly instead of quietly degrading to
#     unsparsified images and slower jobs. Matching no images at all
#     counts as a failure for that reason: the work not happening is the
#     thing being guarded against, and it cannot be seen from the
#     outside. A caller that wants to pass a tree with no images has to
#     stop calling this for such a tree.
#
# A caller that wants less than the whole tree -- resparsifying only the
# files a fetch changed, say -- must ask for that with further optional
# positional arguments or a flag after the tree path, never by changing
# what the one-argument form does. Extra arguments are rejected today so
# that such a caller cannot be silently taken for the whole-tree form
# while quietly doing less work than it asked for.

set -euo pipefail

if [ "$#" -ne 1 ]; then
    echo "usage: $(basename "$0") <testdata-tree>" >&2
    exit 1
fi

TREE="$1"

if [ ! -d "${TREE}" ]; then
    echo "resparsify-testdata: not a directory: ${TREE}" >&2
    exit 1
fi

SCOPE="${TREE}/downloaded"

# A tree with no downloaded/ is a wrong path, not an empty tree, and the
# whole point of this script is that its failures are loud: silently
# resparsifying nothing looks exactly like success and shows up only as
# a slow job much later.
if [ ! -d "${SCOPE}" ]; then
    echo "resparsify-testdata: ${TREE} has no downloaded/ directory, so it is not an" \
        "instar-testdata tree" >&2
    exit 1
fi

LIST="$(mktemp)"
trap 'rm -f "${LIST}"' EXIT

# Collected into a file rather than piped so that a failing find fails
# the script: the exit status of a pipeline's left-hand side, or of a
# process substitution, is not visible to the loop that reads it.
find "${SCOPE}" -type f \( \
    -name '*.qcow2' -o \
    -name '*.vmdk' -o \
    -name '*.vhd' -o \
    -name '*.vhdx' -o \
    -name '*.img' \
    \) -print0 > "${LIST}"

RESPARSIFIED=0
FAILED=0

while IFS= read -r -d '' file; do
    # A copy and a rename, because cp cannot rewrite a file's allocation
    # underneath itself. The && is load bearing: a mv that ran after a
    # failed cp would replace a good image with a truncated one.
    if cp --sparse=always "${file}" "${file}.resparsify" \
        && mv "${file}.resparsify" "${file}"; then
        RESPARSIFIED=$((RESPARSIFIED + 1))
    else
        echo "resparsify-testdata: failed to resparsify ${file}" >&2
        rm -f "${file}.resparsify"
        FAILED=$((FAILED + 1))
    fi
done < "${LIST}"

if [ "${FAILED}" -ne 0 ]; then
    echo "resparsify-testdata: ${FAILED} image(s) could not be resparsified" >&2
    exit 1
fi

# Zero matches inside an existing downloaded/ is a failure, not an empty
# tree. The directory is there, so the path is right; what is wrong is
# either the extension list below having been edited into something that
# matches nothing, or instar-testdata having moved its images. Both leave
# every consumer running against fully allocated images, which looks
# exactly like success and shows up much later as a slow job and as
# disk_size comparisons that measure git's allocation rather than the
# fixture's. The one-argument interface is unchanged -- only the exit
# code for a tree this script can do nothing with.
if [ "${RESPARSIFIED}" -eq 0 ]; then
    echo "resparsify-testdata: no images matched under ${SCOPE}" >&2
    echo "Expected at least one *.qcow2, *.vmdk, *.vhd, *.vhdx or *.img file somewhere" >&2
    echo "beneath it, because that is what an instar-testdata tree holds. Either the" >&2
    echo "extension list in this script no longer matches the images, or the tree's" >&2
    echo "layout changed; resparsifying nothing is indistinguishable from success and" >&2
    echo "must not be reported as it." >&2
    exit 1
fi

echo "resparsify-testdata: resparsified ${RESPARSIFIED} image(s) under ${SCOPE}"
