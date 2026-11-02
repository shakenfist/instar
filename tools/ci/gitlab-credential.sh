# shellcheck shell=bash
#
# Give git a GitLab token without writing it into any repository.
#
# Sourced, not run. The scripts that talk to private/instar-testdata
# used to put the token in the remote URL, which git records in the
# clone's .git/config. For the testdata tree that file sits on the
# runner's overlay of the instar-testdata disk, and the nightly fuzz job
# turned it into a published secret: the corpus push token was written
# into the remote by the old "Verify corpus push token" step, the seed
# extractor walked .git until 4757d5b1, the fuzzer kept .git/config as
# an input, and the nightly pushed it to instar-testdata, whose disk is
# mounted by runners running pull request code
# (shakenfist/shakenfist#4714).
#
# So the remote stays the clean URL, and git and git-lfs get the
# credential from git's own store helper reading a file on tmpfs, the
# same arrangement shakenfist/actions uses when it builds the
# instar-testdata disk. The helper is given through GIT_CONFIG_COUNT
# rather than `git -c`, so it reaches every git and git-lfs this shell
# starts -- git-lfs asks for credentials through `git credential`, which
# inherits it -- and is never written to a config file. The empty value
# first clears any helper the system or global configuration names, so
# the credential is neither looked up nor approved anywhere else.
#
# Usage:
#   . tools/ci/gitlab-credential.sh
#   stage_gitlab_credential TOKEN_VARIABLE_NAME
#   trap clear_gitlab_credential EXIT
#
# The token is passed by variable name, so it is never an argument, and
# the store line is written by printf, a builtin, so it is on no command
# line either. Keep shell tracing off in callers.

GITLAB_CREDENTIAL_HOST='gitlab.home.stillhq.com'
GITLAB_CREDENTIAL_DIR=''

# Percent-encode everything but RFC 3986 unreserved characters, which the
# store helper decodes again. GitLab tokens are URL-safe today; this is
# so that one which is not cannot end the userinfo early.
_gitlab_credential_urlencode() {
    local LC_ALL=C s="$1" out='' c i
    for (( i = 0; i < ${#s}; i++ )); do
        c="${s:i:1}"
        case "${c}" in
            [A-Za-z0-9._~-]) out+="${c}" ;;
            *) printf -v c '%%%02X' "'${c}"; out+="${c}" ;;
        esac
    done
    printf '%s' "${out}"
}

stage_gitlab_credential() {
    local name="$1" token count
    token="${!name:-}"
    if [ -z "${token}" ]; then
        echo "::error::${name} is not set; there is no GitLab credential" \
             "to stage." >&2
        return 1
    fi
    # tmpfs, so that the token is never written to a block device, where
    # removing the file would leave it in freed blocks.
    if [ "$(stat -f -c %T /dev/shm 2>/dev/null)" != 'tmpfs' ]; then
        echo "::error::/dev/shm is not a tmpfs on this runner, so there is" \
             "nowhere to stage the GitLab credential that is not a disk." >&2
        return 1
    fi
    # mktemp -d makes the directory 0700, which keeps the store private
    # even if the helper rewrites it with the umask's permissions on
    # approving a credential.
    GITLAB_CREDENTIAL_DIR="$(mktemp -d -p /dev/shm gitlab-credential.XXXXXX)"
    ( umask 077
      printf 'https://oauth2:%s@%s\n' \
          "$(_gitlab_credential_urlencode "${token}")" \
          "${GITLAB_CREDENTIAL_HOST}" > "${GITLAB_CREDENTIAL_DIR}/store" )

    count="${GIT_CONFIG_COUNT:-0}"
    export "GIT_CONFIG_KEY_${count}=credential.helper"
    export "GIT_CONFIG_VALUE_${count}="
    export "GIT_CONFIG_KEY_$((count + 1))=credential.helper"
    export "GIT_CONFIG_VALUE_$((count + 1))=store --file=${GITLAB_CREDENTIAL_DIR}/store"
    export GIT_CONFIG_COUNT=$((count + 2))
}

# Safe to call more than once, and when nothing was staged.
clear_gitlab_credential() {
    if [ -n "${GITLAB_CREDENTIAL_DIR}" ]; then
        rm -rf "${GITLAB_CREDENTIAL_DIR}"
        GITLAB_CREDENTIAL_DIR=''
    fi
}
