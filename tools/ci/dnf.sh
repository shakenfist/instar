#!/usr/bin/env bash
#
# Run `dnf`, retrying a repository-metadata failure rather than failing
# the job on it. Every dnf that resolves against a distro repository in
# CI goes through this script.
#
#   tools/ci/dnf.sh install -y qemu-img
#   DNF='sudo dnf' tools/ci/dnf.sh install -y ./instar-0.3.0-1.x86_64.rpm
#
# Installing even a local .rpm resolves its Requires against the
# distro's repositories, so these legs depend on a third party's
# metadata being self-consistent at the moment they run -- and a point
# release's repodata rotation breaks that. A repomd.xml served from a
# stale mirror or edge cache names primary and filelists files the
# mirrors have already deleted, so every mirror answers 404 and dnf
# stops before it has looked at the package:
#
#   - Status code: 404 for https://.../9.9/AppStream/x86_64/os/
#       repodata/8dad4ae7...-primary.xml.gz
#   Error: Failed to download metadata for repo 'appstream': Yum repo
#   downloading error: ... Cannot download, all mirrors were already
#   tried without success
#
# That failed `package-smoke` on a pull request that touched none of it,
# and the same signature failed a Rocky functional leg from the merge
# queue. Nothing in this repository is wrong when it happens, and it is
# expensive: the matrix legs are the last to run, so a 404 in one of
# them can cost most of a day's queue wait.
#
# So a metadata failure is retried, with `clean metadata` in between so
# that the retry cannot be answered from the copy that just failed --
# dnf resolves the mirror list again, and the mirrors are current. One
# five-minute deadline covers all of it, long enough to outlast a
# rotation and short enough that a repository which is genuinely gone
# still fails the step.
#
# Any other failure is returned at once, unretried: an unknown package
# or an unsatisfied dependency is an answer about the package, and
# retrying it would only turn a clear failure into a slow one.
#
# DNF, DNF_RETRY_TIMEOUT and DNF_RETRY_INTERVAL exist so that
# tools/ci/test-dnf.sh can run this against a fake dnf.

set -uo pipefail

# dnf translates its errors, and a translated message would quietly turn
# every mirror failure into an ordinary one. sudo keeps LC_ALL by
# default.
export LC_ALL=C

read -ra dnf <<<"${DNF:-dnf}"
timeout="${DNF_RETRY_TIMEOUT:-300}"
interval="${DNF_RETRY_INTERVAL:-15}"

# dnf4 and dnf5 word this differently, and the mirror line comes from
# librepo rather than from dnf at all, so all three are matched.
metadata_failure='Failed to download metadata'
metadata_failure="${metadata_failure}|Failed to synchronize cache"
metadata_failure="${metadata_failure}|all mirrors were already tried"

log="$(mktemp)"
trap 'rm -f -- "${log}"' EXIT

deadline=$((SECONDS + timeout))
while true; do
    "${dnf[@]}" "$@" 2>&1 | tee "${log}" && exit 0
    status=$?

    if ! grep -qE "${metadata_failure}" "${log}"; then
        exit "${status}"
    fi
    if [ "${SECONDS}" -ge "${deadline}" ]; then
        echo "dnf.sh: repository metadata was still unusable after" \
            "${timeout}s" >&2
        exit "${status}"
    fi
    echo "dnf.sh: a repository's metadata would not download," \
        "discarding it and retrying in ${interval}s" >&2
    # A failed clean is not a reason to stop retrying: the next attempt
    # may still reach a mirror that has what the metadata names.
    "${dnf[@]}" clean metadata >/dev/null 2>&1 || true
    sleep "${interval}"
done
