#!/bin/bash
# Install Sigstore's gitsign and replace the release tag with a keyless
# signed one, then force-push it. Run by release.yml's sign-tag job, on a
# throwaway runner: it installs gitsign with sudo and writes global git
# configuration, so the machine must be discarded afterwards.
#
# Keyless signing needs the job's OIDC token (id-token: write), and the
# push needs contents: write; the workflow grants both, to this job
# alone.
#
# Usage: tools/sign-release-tag.sh TAG_NAME COMMIT_SHA
#
# The signature can be checked afterwards with gitsign
# (https://github.com/sigstore/gitsign). Outside GitHub Actions, first
# set GITHUB_REPOSITORY to the repository's owner/name, for example
# GITHUB_REPOSITORY=shakenfist/ryll:
#   gitsign verify-tag TAG_NAME \
#     --certificate-identity-regexp "^https://github\.com/${GITHUB_REPOSITORY}/\.github/workflows/release\.yml@refs/tags/v" \
#     --certificate-oidc-issuer https://token.actions.githubusercontent.com
# The certificate's identity is the signing workflow and the ref it ran
# on, so this accepts release.yml run for a v* tag and nothing else:
# a pattern ending at the repository would accept any of its workflows.
#
# Template source: shakenfist/development/templates/release-automation-rust/

set -euo pipefail

TAG_NAME="${1:?usage: sign-release-tag.sh TAG_NAME COMMIT_SHA}"
COMMIT_SHA="${2:?usage: sign-release-tag.sh TAG_NAME COMMIT_SHA}"

# The workflow's guard already confines this job to a pushed v* tag. This
# is the second lock: a tag name taken from a branch ref would otherwise
# create a garbage tag and force-push it.
case "${TAG_NAME}" in
    v[0-9]*) ;;
    *)
        echo "refusing to sign ${TAG_NAME}: release tags are vX.Y.Z" >&2
        exit 1
        ;;
esac

# Kept in step across the fleet by hand: Renovate does not track it. The
# download is checked against a hash held here, not against the
# checksums.txt of the release it came from, which whoever could replace
# the binary could replace too. The version and the hash move together:
# take the new hash from the release's checksums.txt, and check it
# against a download of the binary.
GITSIGN_VERSION='0.14.0'
GITSIGN_SHA256='23fcc3d71e0abcbc635b1b95dbe758ac08773e3642b407646c32c3cf4c6def74'
BINARY="gitsign_${GITSIGN_VERSION}_linux_amd64"
BASE="https://github.com/sigstore/gitsign/releases/download/v${GITSIGN_VERSION}"

WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"' EXIT
curl -fsSL -o "${WORK}/${BINARY}" "${BASE}/${BINARY}"
echo "${GITSIGN_SHA256}  ${WORK}/${BINARY}" | sha256sum --strict -c -
chmod +x "${WORK}/${BINARY}"
sudo mv "${WORK}/${BINARY}" /usr/local/bin/gitsign

git config --global user.name 'github-actions[bot]'
git config --global user.email 'github-actions[bot]@users.noreply.github.com'
git config --global tag.gpgsign true
git config --global gpg.format x509
git config --global gpg.x509.program gitsign

echo "Signing tag ${TAG_NAME} at ${COMMIT_SHA}"
git tag -d "${TAG_NAME}" || true
git tag -s "${TAG_NAME}" -m "Release ${TAG_NAME}" "${COMMIT_SHA}"
git push origin "${TAG_NAME}" --force
