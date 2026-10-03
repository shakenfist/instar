#!/usr/bin/env bash
#
# Run `sudo apt-get`, waiting for the apt locks rather than failing on
# them. Every host-side apt-get in CI goes through this script.
#
#   tools/ci/apt-get.sh update
#   tools/ci/apt-get.sh install -y jq
#
# A freshly booted runner can still be running its own apt job
# (apt-daily, or an unattended upgrade) when a job's first step arrives,
# and apt-get fails at once on a held lock unless told otherwise. That
# failed integration-convert-vhd on #617, a change that never touched
# it, with "Could not get lock /var/lib/dpkg/lock-frontend".
#
# `-o DPkg::Lock::Timeout` is not enough on its own. Measured against
# apt 3.0.3, the version on the debian-13 runners, it makes apt wait for
# the dpkg frontend lock only. The two locks apt-daily itself takes
# still fail at once with the option set:
#
#   - /var/lib/apt/lists/lock, which `update` takes;
#   - /var/cache/apt/archives/lock, which `install` takes to download.
#
# So this script passes the option for the frontend lock and also
# retries the whole command while it fails on any "Could not get lock".
# A command that could not take a lock did nothing, so retrying it is
# safe. One deadline covers all of it: five minutes is far longer than
# the competing job takes, and short enough that a genuinely wedged apt
# still fails the step. Any other failure is returned at once.
#
# APT_GET, APT_LOCK_TIMEOUT and APT_LOCK_RETRY_INTERVAL exist so that
# tools/ci/test-apt-get.sh can run this against a fake apt-get.

set -uo pipefail

# apt translates "Could not get lock", and a translated message would
# quietly turn every lock failure into an ordinary one. sudo keeps
# LC_ALL by default.
export LC_ALL=C

read -ra apt_get <<<"${APT_GET:-sudo apt-get}"
timeout="${APT_LOCK_TIMEOUT:-300}"
interval="${APT_LOCK_RETRY_INTERVAL:-5}"

log="$(mktemp)"
trap 'rm -f -- "${log}"' EXIT

deadline=$((SECONDS + timeout))
while true; do
    # The frontend wait gets only what is left of the deadline, so a
    # retry after a long frontend wait cannot extend the total. The
    # last sleep can overrun the deadline; that attempt waits for
    # nothing rather than passing apt a negative timeout.
    remaining=$((deadline - SECONDS))
    [ "${remaining}" -lt 0 ] && remaining=0
    "${apt_get[@]}" -o DPkg::Lock::Timeout="${remaining}" "$@" 2>&1 \
        | tee "${log}" && exit 0
    status=$?

    if ! grep -q 'Could not get lock' "${log}"; then
        exit "${status}"
    fi
    if [ "${SECONDS}" -ge "${deadline}" ]; then
        echo "apt-get.sh: an apt lock was still held after ${timeout}s" >&2
        exit "${status}"
    fi
    echo "apt-get.sh: an apt lock is held, retrying in ${interval}s" >&2
    sleep "${interval}"
done
