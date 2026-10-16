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
# `cp --sparse=always` rewrites the holes. It is idempotent -- a second
# run over an already-sparse image produces the same image -- but it is
# not free: it copies and renames every file it is given, sparse or not.
# On an ordinary filesystem that costs time. On a copy-on-write overlay,
# which is what a runner's testdata dependencies disk gives it, it also
# writes every one of those files into the overlay, which is the cost
# the disk exists to avoid. Hence the narrow mode below, and hence the
# whole-tree form being reserved for trees that genuinely need all of
# it.
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
# NARROWING IT, which is what everything below the tree path is for:
#
#     resparsify-testdata.sh <testdata-tree> [--files-from <list>]... \
#                            [--] [<file>...]
#
# A caller that wants less than the whole tree asks for it with these
# further optional arguments, never by changing what the one-argument
# form does -- that form has to keep meaning "the whole tree" for the
# cross-repository consumer above, which cannot be updated in step with
# this file.
#
# The caller that needs this is a runner whose testdata tree came off a
# pre-built dependencies disk: it is a copy-on-write overlay of an image
# that was already resparsified at build time, so `cp --sparse=always`
# over all of it would write the gigabytes into the overlay that the
# disk exists to avoid. But the job's own fetch and `git lfs pull` land
# the day's drift fully allocated, so skipping it outright is wrong in
# the other direction. Only what the fetch changed needs rewriting, and
# the caller knows that set -- it is the reset's `git diff --name-only`.
#
# Two ways in, because the caller has two different kinds of knowledge:
#
#   --files-from <list>   A newline-separated file of candidate paths: a
#                         changed-file list, which legitimately holds
#                         non-images, `custom/` fixtures and files the
#                         update deleted. Entries that are not in-scope
#                         images that exist are dropped and counted, so
#                         that the caller does not have to carry a
#                         second copy of the extension list below --
#                         mirrored copies of it drifting is the hazard
#                         this script was created to remove. May be
#                         given more than once.
#   <file>...             Paths named deliberately, one per argument. A
#                         named path that is not an in-scope image that
#                         exists is refused, because the caller asked
#                         for that specific file and silently doing
#                         nothing is the failure mode this script is
#                         built to make impossible.
#
# Either way a path that resolves outside the tree is refused outright,
# in both forms, and nothing is resparsified when any entry is refused.
# Paths may be tree-relative or absolute inside the tree, and a symlink
# is judged by what it points at: every rule above is applied to the
# resolved target, which is also the file that gets rewritten.
#
# An empty narrow set is success, unlike the whole-tree form: "nothing
# changed in this update" is the normal case on a cached tree, and the
# caller computed the set, so there is no misconfiguration for a
# non-zero exit to report.

set -euo pipefail

# The image extensions, single-sourced: the find expression below and
# the narrow mode's filter are both built from this, and --list-extensions
# publishes it so that a caller filtering its own list cannot drift from
# it either.
EXTENSIONS=(qcow2 vmdk vhd vhdx img)
SCOPE_REL='downloaded'

usage() {
    echo "usage: $(basename "$0") <testdata-tree>" >&2
    echo "       $(basename "$0") <testdata-tree> [--files-from <list>]... [--] [<file>...]" >&2
    echo "       $(basename "$0") --list-extensions" >&2
}

# "*.qcow2, *.vmdk, *.vhd, *.vhdx or *.img", for the messages.
extension_phrase() {
    local phrase='' index=0 last=$(( ${#EXTENSIONS[@]} - 1 ))
    for index in "${!EXTENSIONS[@]}"; do
        if [ "${index}" -eq 0 ]; then
            phrase="*.${EXTENSIONS[index]}"
        elif [ "${index}" -eq "${last}" ]; then
            phrase="${phrase} or *.${EXTENSIONS[index]}"
        else
            phrase="${phrase}, *.${EXTENSIONS[index]}"
        fi
    done
    echo "${phrase}"
}

if [ "$#" -eq 1 ] && [ "$1" = '--list-extensions' ]; then
    printf '%s\n' "${EXTENSIONS[@]}"
    exit 0
fi

if [ "$#" -lt 1 ]; then
    usage
    exit 1
fi

TREE="$1"
shift

# One argument is the whole tree, permanently. Anything after it is a
# request for less, and is parsed below.
NARROW=0
if [ "$#" -gt 0 ]; then
    NARROW=1
fi

LIST_FILES=()
NAMED=()

while [ "$#" -gt 0 ]; do
    case "$1" in
        --files-from)
            if [ "$#" -lt 2 ]; then
                echo "resparsify-testdata: --files-from needs a file" >&2
                exit 1
            fi
            LIST_FILES+=("$2")
            shift 2
            ;;
        --files-from=*)
            LIST_FILES+=("${1#--files-from=}")
            shift
            ;;
        --)
            shift
            while [ "$#" -gt 0 ]; do
                NAMED+=("$1")
                shift
            done
            ;;
        -*)
            echo "resparsify-testdata: unknown option: $1" >&2
            usage
            exit 1
            ;;
        *)
            NAMED+=("$1")
            shift
            ;;
    esac
done

if [ ! -d "${TREE}" ]; then
    echo "resparsify-testdata: not a directory: ${TREE}" >&2
    exit 1
fi

SCOPE="${TREE}/${SCOPE_REL}"

# A tree with no downloaded/ is a wrong path, not an empty tree, and the
# whole point of this script is that its failures are loud: silently
# resparsifying nothing looks exactly like success and shows up only as
# a slow job much later.
if [ ! -d "${SCOPE}" ]; then
    echo "resparsify-testdata: ${TREE} has no ${SCOPE_REL}/ directory, so it is not an" \
        "instar-testdata tree" >&2
    exit 1
fi

LIST="$(mktemp)"
trap 'rm -f "${LIST}"' EXIT

if [ "${NARROW}" -eq 0 ]; then
    FIND_EXPR=()
    for ext in "${EXTENSIONS[@]}"; do
        if [ "${#FIND_EXPR[@]}" -ne 0 ]; then
            FIND_EXPR+=(-o)
        fi
        FIND_EXPR+=(-name "*.${ext}")
    done

    # Collected into a file rather than piped so that a failing find fails
    # the script: the exit status of a pipeline's left-hand side, or of a
    # process substitution, is not visible to the loop that reads it.
    find "${SCOPE}" -type f \( "${FIND_EXPR[@]}" \) -print0 > "${LIST}"
else
    # Resolved once: every candidate is compared against it, and the
    # tree path itself may be reached through a symlink.
    TREE_REAL="$(realpath -- "${TREE}")"
    SKIPPED=0

    # classify CANDIDATE -> sets CLASSIFIED to the absolute path when it
    # is an in-scope image that exists, and REASON when it is not.
    # Returns 0 for accepted, 1 for outside the tree (never acceptable
    # from either form), 2 for inside the tree but not something this
    # script acts on (droppable from a changed-file list, refused when
    # named).
    classify() {
        local candidate="$1"
        local absolute resolved relative ext matched

        CLASSIFIED=''
        REASON=''

        if [ -z "${candidate}" ]; then
            REASON='empty path'
            return 1
        fi

        case "${candidate}" in
            /*) absolute="${candidate}" ;;
            *) absolute="${TREE_REAL}/${candidate}" ;;
        esac

        # -m so that a path naming a file the update deleted still
        # resolves and can be classified rather than erroring here. This
        # one check covers both an absolute path somewhere else entirely
        # and a relative path climbing out through "..".
        resolved="$(realpath -m -- "${absolute}")"
        case "${resolved}" in
            "${TREE_REAL}"/*) relative="${resolved#"${TREE_REAL}"/}" ;;
            *)
                REASON="resolves outside ${TREE_REAL}: ${resolved}"
                return 1
                ;;
        esac

        case "${relative}" in
            "${SCOPE_REL}"/*) ;;
            *)
                REASON="not under ${SCOPE_REL}/"
                return 2
                ;;
        esac

        matched=0
        for ext in "${EXTENSIONS[@]}"; do
            case "${relative}" in
                *".${ext}") matched=1; break ;;
            esac
        done
        if [ "${matched}" -eq 0 ]; then
            REASON="not one of $(extension_phrase)"
            return 2
        fi

        # No symlink check, on purpose, and please do not add one back:
        # realpath above has already resolved every component including
        # the last, so a test on ${resolved} can never see a symlink and
        # would be dead code. What matters is the target, and the target
        # is what the three checks around this one judge -- inside the
        # tree, under ${SCOPE_REL}/, an in-scope extension -- so a
        # symlink pointing anywhere this script would not write directly
        # is refused by the same rules as a plain path. One pointing at
        # an in-scope image is followed, which is harmless: the copy
        # below writes ${resolved}, the real file, leaving the symlink
        # itself alone, and whole-tree mode reaches the same file through
        # find. Resolving first also means naming both a link and its
        # target resparsifies the target once rather than twice.
        if [ ! -f "${resolved}" ]; then
            REASON='does not exist'
            return 2
        fi

        CLASSIFIED="${resolved}"
        return 0
    }

    declare -A SEEN=()

    # add_candidate CANDIDATE STRICT ORIGIN -- STRICT=1 for a path the
    # caller named, where anything this script will not act on is an
    # error. ORIGIN says where the path came from, and is carried into
    # every refusal: the two sources fail for different reasons and send
    # the reader to different repositories. A path on the command line
    # is this caller's mistake; a path in a list file came from whatever
    # produced that list -- for the cache path, the testdata update's own
    # diff -- and someone triaging a run that refused one needs to look
    # at that commit, not at this script.
    add_candidate() {
        local candidate="$1" strict="$2" origin="$3" status=0

        classify "${candidate}" || status=$?
        case "${status}" in
            0)
                if [ -z "${SEEN[${CLASSIFIED}]:-}" ]; then
                    SEEN["${CLASSIFIED}"]=1
                    printf '%s\0' "${CLASSIFIED}" >> "${LIST}"
                fi
                ;;
            1)
                echo "resparsify-testdata: refusing ${candidate}" \
                     "(${origin}): ${REASON}" >&2
                exit 1
                ;;
            *)
                if [ "${strict}" -eq 1 ]; then
                    echo "resparsify-testdata: refusing ${candidate}" \
                         "(${origin}): ${REASON}" >&2
                    exit 1
                fi
                SKIPPED=$((SKIPPED + 1))
                ;;
        esac
    }

    for list_file in ${LIST_FILES[@]+"${LIST_FILES[@]}"}; do
        if [ ! -f "${list_file}" ]; then
            echo "resparsify-testdata: --files-from file does not exist: ${list_file}" >&2
            exit 1
        fi
        # A trailing line without its newline is still a path, so the
        # read's non-zero exit at EOF is handled rather than trusted.
        while IFS= read -r line || [ -n "${line}" ]; do
            if [ -z "${line}" ]; then
                continue
            fi
            add_candidate "${line}" 0 "listed in ${list_file}"
        done < "${list_file}"
    done

    for named in ${NAMED[@]+"${NAMED[@]}"}; do
        add_candidate "${named}" 1 'named on the command line'
    done
fi

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

if [ "${NARROW}" -eq 1 ]; then
    # Zero here is the cached tree whose update changed no image, which
    # is the normal case and not a misconfiguration: the caller worked
    # out the set and this script was told what it was.
    echo "resparsify-testdata: resparsified ${RESPARSIFIED} named image(s) under ${SCOPE}," \
        "${SKIPPED} candidate(s) not in scope"
    exit 0
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
    echo "Expected at least one $(extension_phrase) file somewhere" >&2
    echo "beneath it, because that is what an instar-testdata tree holds. Either the" >&2
    echo "extension list in this script no longer matches the images, or the tree's" >&2
    echo "layout changed; resparsifying nothing is indistinguishable from success and" >&2
    echo "must not be reported as it." >&2
    exit 1
fi

echo "resparsify-testdata: resparsified ${RESPARSIFIED} image(s) under ${SCOPE}"
