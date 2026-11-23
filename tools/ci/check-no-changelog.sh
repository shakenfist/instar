#!/usr/bin/env bash
#
# Fail when the tree carries a changelog file.
#
# instar keeps no CHANGELOG.md: every pull request appended to it, so
# every pair of pull requests in flight conflicted there, and the
# record it kept is the commit messages and docs/ already. Release
# notes are written on the GitHub release instead; see "Releases" in
# docs/development.md. Older plans in docs/plans/ still say to add an
# entry, and an agent following one that finds no file to append to is
# as likely to create one somewhere plausible as at the root -- so the
# match is any path component named CHANGELOG, CHANGELOG.md or a
# case variant of either, not just the top-level file.
#
# It reads `git ls-files`, not the files a commit touches, so a file
# that landed by any route (--no-verify, the web editor, a checkout
# without hooks installed) fails every later run, and the same script
# serves pre-commit and CI. CI runs it in functional-tests.yml's
# check_paths job rather than ci-tooling, because a pull request that
# only adds a markdown file is docs-only and skips ci-tooling.
#
# Usage: tools/ci/check-no-changelog.sh
# Exits 0 with a one-line summary when the tree is clean, 1 naming every
# offending path otherwise, and 2 when git ls-files itself fails.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${REPO_ROOT}"

PATTERN='(^|/)changelog(\.md)?$'

# git ls-files failing outside a checkout must not read as "no files".
if ! FILES="$(git ls-files)"; then
    echo 'ERROR: git ls-files failed; not a git checkout?' >&2
    exit 2
fi

HITS="$(grep -iE "${PATTERN}" <<< "${FILES}" || true)"
if [ -n "${HITS}" ]; then
    while IFS= read -r hit; do
        echo "ERROR: changelog file in the tree: ${hit}" >&2
    done <<< "${HITS}"
    echo 'instar keeps no CHANGELOG.md. Describe the change in the commit' >&2
    echo 'message and docs/; see "Releases" in docs/development.md.' >&2
    exit 1
fi

echo 'check-no-changelog: the tree carries no changelog file.'
