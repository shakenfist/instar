#!/usr/bin/env bash
#
# Push newly discovered fuzz corpus entries to instar-testdata.
#
# Coverage-guided fuzzing only gets deeper if the corpus survives the
# run that produced it, so this step is the point of the nightly job
# rather than a tidy-up after it. It used to be the step the nightly
# died on: five of six scheduled runs in August were killed by the
# job's own `timeout-minutes: 480` while pushing, and the corpus they
# had spent seven hours building was discarded. See GitHub issue #519.
#
# The push measured 22 minutes because it asked for far more than it
# needs. instar-testdata is a 12 GB repository whose fixtures are
# git-LFS objects, and `custom/fuzz-corpus/` alone is ~2.7 GB across
# ~560,000 files. The old inline version cloned all of that (smudging
# every LFS image on the way past), then walked both trees in a nested
# shell loop that forked `basename` once per corpus file.
#
# None of that is required to add a file. What this script needs is the
# *names* already committed, which `git ls-tree` reads straight out of
# the tree objects, so:
#
#   - `--filter=blob:none --sparse` clones the history and trees but no
#     file contents, and checks out only the repository root. The
#     corpus blobs are never fetched.
#   - `GIT_LFS_SKIP_SMUDGE=1` keeps git-lfs from materialising fixtures
#     that are outside the sparse cone anyway. Belt and braces, and it
#     costs nothing.
#   - `comm` against the ls-tree listing picks out the genuinely new
#     entries, one `tar` pipeline copies them, and `git add --sparse`
#     stages those paths (the `--sparse` flag is required because they
#     lie outside the checked-out cone; without it git refuses).
#
# The index stays fully populated throughout, which is why the commit
# adds to the corpus rather than replacing it. Do not switch this to
# `git clone --no-checkout`: that leaves the index empty, and the
# resulting commit would delete every fixture in the repository.
#
# Inputs (environment):
#   PUSH_TOKEN  (required) GitLab oauth2 token with Maintainer rights on
#               private/instar-testdata -- `main` is protected, so a
#               Developer token cannot push. See the repository memory
#               note on GITLAB_TESTDATA_PUSH_TOKEN.
#   CORPUS_SRC  (optional) Local corpus root, default src/fuzz/corpus.
#   PUSH_URL    (optional) Override the clone URL. Exists so
#               test-push-fuzz-corpus.sh can drive the script against a
#               local repository; CI never sets it.
#
# Exits 0 without pushing when there is no token or no corpus, so a
# fork or a local dry run is not an error.

set -euo pipefail

CORPUS_SRC="${CORPUS_SRC:-src/fuzz/corpus}"
REPO_HOST='gitlab.home.stillhq.com'
REPO_PATH='private/instar-testdata.git'
CORPUS_PREFIX='custom/fuzz-corpus'

if [ -z "${PUSH_TOKEN:-}" ]; then
    echo "PUSH_TOKEN not set, skipping corpus push"
    exit 0
fi

if [ ! -d "${CORPUS_SRC}" ]; then
    echo "No corpus directory at ${CORPUS_SRC}, skipping"
    exit 0
fi

WORK=$(mktemp -d)
trap 'rm -rf "${WORK}"' EXIT
PUSH_DIR="${WORK}/testdata"

# Token only ever appears inside git command arguments, never in a
# traced or echoed line, so keep shell tracing off.
AUTHED_URL="${PUSH_URL:-https://oauth2:${PUSH_TOKEN}@${REPO_HOST}/${REPO_PATH}}"

echo "Cloning ${REPO_PATH} (trees only, root checkout only)..."
GIT_LFS_SKIP_SMUDGE=1 git clone \
    --depth 1 \
    --filter=blob:none \
    --sparse \
    "${AUTHED_URL}" "${PUSH_DIR}"

# What is already committed, as paths relative to the corpus root. This
# reads tree objects only -- no blob is fetched and no file is written.
git -C "${PUSH_DIR}" ls-tree -r --name-only HEAD -- "${CORPUS_PREFIX}" \
    | sed "s|^${CORPUS_PREFIX}/||" \
    | LC_ALL=C sort > "${WORK}/committed"

# What this run has locally. The seeding step populated this from the
# same repository, so most of it is the same set.
( cd "${CORPUS_SRC}" && find . -type f -printf '%P\n' ) \
    | LC_ALL=C sort > "${WORK}/local"

LC_ALL=C comm -23 "${WORK}/local" "${WORK}/committed" > "${WORK}/new"
NEW_COUNT=$(wc -l < "${WORK}/new")

echo "corpus: $(wc -l < "${WORK}/local") local," \
     "$(wc -l < "${WORK}/committed") committed," \
     "${NEW_COUNT} new"

if [ "${NEW_COUNT}" -eq 0 ]; then
    echo "No new corpus entries to push"
    exit 0
fi

# One pass over only the new entries. tar creates the target
# subdirectories, so a brand-new fuzz target needs no special case.
mkdir -p "${PUSH_DIR}/${CORPUS_PREFIX}"
tar -C "${CORPUS_SRC}" -cf - --files-from "${WORK}/new" \
    | tar -C "${PUSH_DIR}/${CORPUS_PREFIX}" -xf -

sed "s|^|${CORPUS_PREFIX}/|" "${WORK}/new" > "${WORK}/new-paths"
git -C "${PUSH_DIR}" add --sparse --pathspec-from-file="${WORK}/new-paths"

# Staging can still come to nothing if an entry is byte-identical to one
# already committed under the same name, which ls-tree would have caught
# -- but also if .gitignore excludes it. Check rather than commit empty.
if git -C "${PUSH_DIR}" diff --cached --quiet; then
    echo "Nothing staged after add, not committing"
    exit 0
fi

git -C "${PUSH_DIR}" \
    -c user.name="CI Fuzzer" \
    -c user.email="bot@shakenfist.com" \
    commit -q -m "Add ${NEW_COUNT} fuzz corpus entries from nightly run $(date -u +%Y-%m-%d)"
git -C "${PUSH_DIR}" push origin HEAD

echo "Pushed ${NEW_COUNT} new corpus entries to instar-testdata"
