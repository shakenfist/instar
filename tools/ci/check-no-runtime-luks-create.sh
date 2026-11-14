#!/usr/bin/env bash
#
# Fail when a test could make a LUKS image at runtime.
#
# Before it writes a LUKS header, qemu-img times a key derivation to
# choose the iteration count. On some builds (Debian 12's 7.2 among
# them) that timing reads zero CPU time about one time in three and the
# create fails with "Unable to get accurate CPU usage";
# encrypt.iter-time does not stop the timing. A test built like that
# ejected three unrelated pull requests from the merge queue (#905).
# Tests use the prebuilt qcow2-luks fixture instead, via
# get_image('qcow2-luks'); docs/testing.md states the convention.
#
# The match is deliberately the option, not the command shape: any
# `encrypt.format=luks` and any `luksFormat` (cryptsetup derives a key
# the same way) in a Python or shell file under tests/. An earlier
# version matched a qemu-img create or convert argv list instead, and a
# literal `]` anywhere in the list -- a subscript in an f-string, a
# nested `*[...]` -- ended the match early and let a real offender
# through. Matching the option has no such bypass; what it costs is
# that a legitimate mention has to be exempted by name, below, where a
# reviewer can see it.
#
# The generators under scripts/ build fixtures once, by hand, and are
# not read.
#
# Usage: tools/ci/check-no-runtime-luks-create.sh
# Exits 0 with a one-line summary when the tree is clean, 1 naming every
# hit by file and line otherwise, and 2 when git grep itself fails.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${REPO_ROOT}"

PATTERN='encrypt\.format=luks|luksFormat'

# Files that mention the option without making an image. Each entry
# needs its reason; widen this rather than the pattern.
#   tests/test_measure.py: passes `-o encrypt.format=luks` to instar
#     measure, which refuses it and creates nothing.
EXEMPT=(
    'tests/test_measure.py'
)

PATHSPEC=(':(glob)tests/**/*.py' ':(glob)tests/**/*.sh')
for f in "${EXEMPT[@]}"; do
    PATHSPEC+=(":(exclude)${f}")
done

# git grep exits 1 when nothing matches, which is the clean case, but
# above 1 is an error: outside a checkout it exits 128, and treating
# that as "no matches" would make this guard pass having read nothing.
set +e
HITS="$(git grep -nIE "${PATTERN}" -- "${PATHSPEC[@]}")"
GREP_STATUS=$?
set -e
if [ "${GREP_STATUS}" -gt 1 ]; then
    echo "ERROR: git grep failed (exit ${GREP_STATUS}); not a git checkout?" >&2
    exit 2
fi

if [ "${GREP_STATUS}" -eq 0 ]; then
    while IFS= read -r hit; do
        echo "ERROR: runtime LUKS create in a test: ${hit}" >&2
    done <<< "${HITS}"
    echo "check-no-runtime-luks-create: $(grep -c . <<< "${HITS}") problem(s) found." >&2
    echo "Use the prebuilt qcow2-luks fixture; see docs/testing.md." >&2
    exit 1
fi

echo 'check-no-runtime-luks-create: no test makes a LUKS image at runtime.'
