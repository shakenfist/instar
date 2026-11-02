#!/usr/bin/env bash
#
# Prove the corpus push token can write to instar-testdata before the
# nightly spends seven hours fuzzing, by committing a timestamp to the
# prepared testdata tree and pushing it.
#
# The token reaches git through tools/ci/gitlab-credential.sh and is
# never written into the tree's .git/config. It used to be, by `git
# remote set-url`, and from there it was seeded into the fuzz corpus and
# pushed to instar-testdata itself (shakenfist/shakenfist#4714). The
# remote stays the clean URL prepare-testdata.sh left it with.
#
# Inputs (environment):
#   PUSH_TOKEN     (required) GitLab oauth2 token with Maintainer rights
#                  on private/instar-testdata.
#   TESTDATA_PATH  (required) The tree prepare-testdata.sh prepared.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=tools/ci/gitlab-credential.sh
. "${SCRIPT_DIR}/gitlab-credential.sh"

if [ -z "${PUSH_TOKEN:-}" ]; then
    echo "::error::GITLAB_TESTDATA_PUSH_TOKEN is not set" >&2
    exit 1
fi
if [ -z "${TESTDATA_PATH:-}" ] || [ ! -d "${TESTDATA_PATH}/.git" ]; then
    echo "::error::TESTDATA_PATH does not name a prepared instar-testdata" \
         "tree; run tools/ci/prepare-testdata.sh first." >&2
    exit 1
fi

stage_gitlab_credential PUSH_TOKEN
trap clear_gitlab_credential EXIT

cd "${TESTDATA_PATH}"
mkdir -p custom/fuzz-corpus
date -u '+%Y-%m-%dT%H:%M:%SZ' > custom/fuzz-corpus/last-coverage-run.txt
git add custom/fuzz-corpus/last-coverage-run.txt
git -c user.name="CI Fuzzer" \
    -c user.email="bot@shakenfist.com" \
    commit -m "Coverage fuzz run started $(date -u +%Y-%m-%d)"
git push origin HEAD
echo "Corpus push token is valid (write verified)"
