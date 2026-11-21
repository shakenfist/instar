#!/usr/bin/env bash
#
# Tests for tools/ci/dnf.sh, run against a fake dnf.
#
# The wrapper only does anything while a distro's repository metadata is
# inconsistent, which no CI run arranges on purpose. A retry loop that
# had stopped retrying, or that retried every failure, would pass every
# ordinary run and be discovered on the next unlucky mirror rotation --
# in a matrix leg, hours into a merge-queue run.
#
# Contract (see the script's header): the arguments reach dnf unchanged
# and in order, with nothing added; a metadata failure is retried, with
# `clean metadata` between attempts, until one deadline expires; any
# other failure is returned at once with its own status.
#
# Pure bash: no sudo, no dnf, no network.
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SCRIPT="${REPO_ROOT}/tools/ci/dnf.sh"
WORK="$(mktemp -d)"
trap 'rm -rf -- "${WORK}"' EXIT

# The fake fails with FAKE_MESSAGE for its first FAKE_FAILS resolving
# calls (forever if negative), then behaves as FAKE_RESULT says. A
# `clean` succeeds unless FAKE_CLEAN_FAILS is set, and is not counted as
# an attempt, so the assertions below can tell the two apart. Each call
# appends its arguments to calls.txt, the same arguments bracketed one
# by one to argv.txt (so a split or a join shows), and the LC_ALL it
# was given to lc_all.txt.
FAKE="${WORK}/fake-dnf"
cat >"${FAKE}" <<'EOF'
#!/usr/bin/env bash
echo "$*" >>"${FAKE_DIR}/calls.txt"
printf '[%s]' "$@" >>"${FAKE_DIR}/argv.txt"
echo >>"${FAKE_DIR}/argv.txt"
echo "${LC_ALL:-unset}" >>"${FAKE_DIR}/lc_all.txt"
if [ "${1:-}" = clean ]; then
    exit "${FAKE_CLEAN_FAILS:-0}"
fi
attempts=$(grep -cv '^clean' "${FAKE_DIR}/calls.txt")
if [ "${FAKE_FAILS}" -lt 0 ] || [ "${attempts}" -le "${FAKE_FAILS}" ]; then
    echo "${FAKE_MESSAGE}" >&2
    exit 1
fi
case "${FAKE_RESULT}" in
    ok) echo 'fake dnf: done'; exit 0 ;;
    *) echo 'Error: Unable to find a match: nonesuch' >&2; exit "${FAKE_RESULT}" ;;
esac
EOF
chmod +x "${FAKE}"

# The wordings a mirror failure arrives in: dnf4, dnf5 (two of them),
# and the mirror line, which comes from librepo rather than from dnf at
# all and is capitalised differently for repomd.xml than for the rest of
# the repodata. The repomd one is matched by nothing but that line,
# which is what pins the match as case-blind. The dnf5 and repomd
# wordings are as rockylinux:9 and fedora:latest printed them in
# 2026-11 for a repository answering 404.
DNF4_MESSAGE="Error: Failed to download metadata for repo 'appstream':"
DNF4_MESSAGE="${DNF4_MESSAGE} Yum repo downloading error"
DNF5_MESSAGE="Failed to synchronize cache for repo 'appstream'"
DNF5_URL_MESSAGE='Failed to download metadata (baseurl: "https://example/")'
DNF5_URL_MESSAGE="${DNF5_URL_MESSAGE} for repository \"appstream\": Usable URL not found"
MIRROR_MESSAGE='repodata/8dad4ae7-primary.xml.gz - Cannot download,'
MIRROR_MESSAGE="${MIRROR_MESSAGE} all mirrors were already tried without success"
REPOMD_MESSAGE='Cannot download repodata/repomd.xml: All mirrors were tried'

# A payload a rotation deleted, which the mirror line does not always
# cover: librepo reports the bare transfer error once it has spent its
# allowance of mirror failures, so these pin the wordings dnf itself
# wraps a failed payload in. dnf4's is from dnf/cli/cli.py and dnf5's
# from libdnf5/repo/package_downloader.cpp; the indented line beneath
# each is librepo's, reproduced here to show that the match does not
# depend on it.
DNF4_PAYLOAD_MESSAGE='Error downloading packages:'
DNF4_PAYLOAD_MESSAGE="${DNF4_PAYLOAD_MESSAGE}
  instar-0.3.0-1.x86_64.rpm: Status code: 404 for https://example/"
DNF5_PAYLOAD_MESSAGE='Failed to download packages'
DNF5_PAYLOAD_MESSAGE="${DNF5_PAYLOAD_MESSAGE}
 Librepo error: Status code: 404 for https://example/ (IP: 192.0.2.1)"

FAILURES=0

fail() {
    printf 'FAIL %s\n' "$1" >&2
    FAILURES=$((FAILURES + 1))
}

run() {
    # run FAILS RESULT TIMEOUT MESSAGE ARGS...
    #   -- sets STATUS, ATTEMPTS, CLEANS, OUTPUT
    # The outer timeout turns a wrapper that never gives up into a
    # failed assertion (exit 124) rather than a hung CI step.
    local fails="$1" result="$2" timeout="$3" message="$4"
    shift 4
    # RUN_DNF and FAKE_CLEAN_FAILS are set as a prefix assignment on the
    # call. Whether bash leaves such an assignment set in the shell once
    # the function returns has varied between versions and POSIX mode,
    # so read each one here and clear it: a later case then cannot
    # silently inherit a knob from an earlier one whichever bash is
    # running, and the fake is passed both explicitly below.
    local dnf_cmd="${RUN_DNF:-${FAKE}}" clean_status="${FAKE_CLEAN_FAILS:-0}"
    unset RUN_DNF FAKE_CLEAN_FAILS
    rm -f "${WORK}/calls.txt" "${WORK}/argv.txt" "${WORK}/lc_all.txt"
    touch "${WORK}/calls.txt"
    OUTPUT="$(FAKE_DIR="${WORK}" FAKE_FAILS="${fails}" \
        FAKE_RESULT="${result}" FAKE_MESSAGE="${message}" \
        FAKE_CLEAN_FAILS="${clean_status}" DNF="${dnf_cmd}" \
        DNF_RETRY_TIMEOUT="${timeout}" DNF_RETRY_INTERVAL=1 \
        timeout 20 "${SCRIPT}" "$@" 2>&1)"
    STATUS=$?
    ATTEMPTS=$(grep -cv '^clean' "${WORK}/calls.txt")
    CLEANS=$(grep -c '^clean' "${WORK}/calls.txt")
}

# Success first time: one call, the arguments in order and nothing
# added. The wrapper is a pass-through on the happy path, which is
# every run but the unlucky one.
run 0 ok 300 "${DNF4_MESSAGE}" install -y --setopt=install_weak_deps=False /pkg/instar.rpm
[ "${STATUS}" -eq 0 ] || fail "success: exit ${STATUS}, wanted 0"
[ "${ATTEMPTS}" -eq 1 ] || fail "success: ${ATTEMPTS} attempts, wanted 1"
[ "${CLEANS}" -eq 0 ] || fail "success: cleaned metadata without a failure"
WANTED='install -y --setopt=install_weak_deps=False /pkg/instar.rpm'
[ "$(cat "${WORK}/calls.txt")" = "${WANTED}" ] \
    || fail "success: dnf got '$(cat "${WORK}/calls.txt")'"
[[ "${OUTPUT}" == *'fake dnf: done'* ]] \
    || fail "success: dnf's output did not reach the caller"

# A metadata failure is retried until the mirrors agree again, and the
# stale copy is discarded before each retry rather than being asked
# the same question twice.
for message in "${DNF4_MESSAGE}" "${DNF5_MESSAGE}" "${DNF5_URL_MESSAGE}" \
        "${MIRROR_MESSAGE}" "${REPOMD_MESSAGE}" \
        "${DNF4_PAYLOAD_MESSAGE}" "${DNF5_PAYLOAD_MESSAGE}"; do
    run 2 ok 300 "${message}" install -y qemu-img
    [ "${STATUS}" -eq 0 ] || fail "retried (${message:0:40}): exit ${STATUS}, wanted 0"
    [ "${ATTEMPTS}" -eq 3 ] \
        || fail "retried (${message:0:40}): ${ATTEMPTS} attempts, wanted 3"
    [ "${CLEANS}" -eq 2 ] \
        || fail "retried (${message:0:40}): ${CLEANS} cleans, wanted 2"
    [ "$(sed -n 2p "${WORK}/calls.txt")" = 'clean metadata' ] \
        || fail "retried (${message:0:40}): the retry reused the metadata that failed"
done

# A clean that fails does not stop the retries: the next attempt may
# still reach a mirror that has what the metadata names.
FAKE_CLEAN_FAILS=1 run 2 ok 300 "${MIRROR_MESSAGE}" install -y qemu-img
[ "${STATUS}" -eq 0 ] || fail "failed clean: exit ${STATUS}, wanted 0"
[ "${ATTEMPTS}" -eq 3 ] || fail "failed clean: ${ATTEMPTS} attempts, wanted 3"

# A DNF of more than one word -- DNF='sudo dnf' is how
# validate-published-release.sh calls it -- is split into a command and
# its arguments, while the caller's arguments arrive one for one, an
# argument holding a space included.
RUN_DNF="env ${FAKE}" run 0 ok 300 "${DNF4_MESSAGE}" install -y 'two words'
[ "${STATUS}" -eq 0 ] || fail "multi-word DNF: exit ${STATUS}, wanted 0"
[ "$(cat "${WORK}/argv.txt")" = '[install][-y][two words]' ] \
    || fail "multi-word DNF: dnf got $(cat "${WORK}/argv.txt")"

# dnf runs with LC_ALL=C whatever the caller's locale, retry and clean
# alike: the failure match is against dnf's English messages.
LC_ALL=de_DE.UTF-8 run 1 ok 300 "${DNF4_MESSAGE}" install -y qemu-img
[ "$(sort -u "${WORK}/lc_all.txt")" = 'C' ] \
    || fail "locale: dnf ran with LC_ALL $(sort -u "${WORK}/lc_all.txt" | tr '\n' ' ')"
[ "$(wc -l <"${WORK}/lc_all.txt")" -eq 3 ] \
    || fail 'locale: wanted two attempts and a clean'

# Any other failure is returned at once, with its own status: an
# unknown package is an answer, not weather.
run 0 42 300 "${DNF4_MESSAGE}" install -y nonesuch
[ "${STATUS}" -eq 42 ] || fail "other failure: exit ${STATUS}, wanted 42"
[ "${ATTEMPTS}" -eq 1 ] \
    || fail "other failure: ${ATTEMPTS} attempts, wanted 1 (it was retried)"
[ "${CLEANS}" -eq 0 ] \
    || fail 'other failure: metadata was cleaned for an unrelated failure'

# The match is deliberately broad, and this is what that costs: a
# repository configured with skip_if_unavailable (the default on several
# Fedora and EPEL repositories) reports an unreachable mirror as a
# warning and carries on, so an unrelated failure in the same run still
# has a matching line above it and is retried until the deadline. The
# trade is one wasted deadline on a failure that would have failed
# anyway, against a mirror rotation going unretried because dnf worded
# it in a way the pattern did not cover.
SKIPPED_REPO_MESSAGE='Failed to download metadata for repo "epel": [skipped]'
SKIPPED_REPO_MESSAGE="${SKIPPED_REPO_MESSAGE}
Error: Unable to find a match: qemu-img"
run -1 ok 3 "${SKIPPED_REPO_MESSAGE}" install -y qemu-img
[ "${STATUS}" -eq 1 ] || fail "skipped repo: exit ${STATUS}, wanted 1"
[ "${ATTEMPTS}" -ge 2 ] \
    || fail "skipped repo: ${ATTEMPTS} attempts, wanted the deadline to be spent"
[[ "${OUTPUT}" == *'still unusable after 3s'* ]] \
    || fail 'skipped repo: the deadline was not what ended it'

# Metadata that never recovers fails the step once the deadline passes,
# with dnf's own status and a message saying why.
run -1 ok 3 "${MIRROR_MESSAGE}" install -y qemu-img
[ "${STATUS}" -eq 1 ] || fail "wedged mirrors: exit ${STATUS}, wanted 1"
[ "${ATTEMPTS}" -ge 2 ] || fail "wedged mirrors: ${ATTEMPTS} attempts, wanted at least 2"
[[ "${OUTPUT}" == *'still unusable after 3s'* ]] \
    || fail 'wedged mirrors: no message naming the deadline'

if [ "${FAILURES}" -ne 0 ]; then
    echo "dnf: ${FAILURES} assertion(s) failed" >&2
    exit 1
fi
echo 'dnf: contract holds'
