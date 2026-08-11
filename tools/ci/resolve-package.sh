#!/bin/bash
# Resolve the single built package of a given kind to a path.
#
# The merge-queue distro matrix builds one .deb and one .rpm in a single
# job and hands the pair to every matrix entry (see
# docs/plans/PLAN-distro-matrix-ci-phase-04-workflow.md, D3). Each entry
# then needs the one file its distro family installs. That is a glob,
# and a glob that matches two files -- or none -- must fail loudly here
# rather than expand into a confusing argument list inside the runner.
#
# Usage:
#   tools/ci/resolve-package.sh <deb|rpm> [package-dir]
#
# package-dir defaults to $PACKAGE_DIR, then to the in-tree build
# layout, so this works both on a matrix runner (where the artifact was
# downloaded to one flat directory) and locally after a `make package`.
#
# Prints the resolved absolute path on stdout. Everything else goes to
# stderr, so the caller can use "$(tools/ci/resolve-package.sh deb)"
# directly.

set -euo pipefail

PKG_KIND="${1:-}"
PKG_DIR="${2:-${PACKAGE_DIR:-}}"

case "$PKG_KIND" in
    deb|rpm) ;;
    *)
        echo "Usage: $0 <deb|rpm> [package-dir]" >&2
        exit 2
        ;;
esac

REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)

# Search order: an explicit directory if given, otherwise the in-tree
# layout that `make deb` / `make rpm` write to.
if [ -n "$PKG_DIR" ]; then
    SEARCH_DIRS=("$PKG_DIR")
elif [ "$PKG_KIND" = 'deb' ]; then
    SEARCH_DIRS=("$REPO_ROOT/src/target/debian")
else
    SEARCH_DIRS=("$REPO_ROOT/src/target/generate-rpm")
fi

MATCHES=()
for dir in "${SEARCH_DIRS[@]}"; do
    if [ ! -d "$dir" ]; then
        continue
    fi
    while IFS= read -r -d '' f; do
        MATCHES+=("$f")
    done < <(find "$dir" -maxdepth 1 -type f -name "*.${PKG_KIND}" -print0 | sort -z)
done

if [ "${#MATCHES[@]}" -eq 0 ]; then
    echo "Error: no .${PKG_KIND} found in: ${SEARCH_DIRS[*]}" >&2
    echo "Run 'make package' first, or point PACKAGE_DIR at the artifact." >&2
    exit 1
fi

if [ "${#MATCHES[@]}" -gt 1 ]; then
    echo "Error: ${#MATCHES[@]} .${PKG_KIND} files found; expected exactly one:" >&2
    printf '  %s\n' "${MATCHES[@]}" >&2
    echo "A stale package from an earlier build is the usual cause." >&2
    exit 1
fi

echo "${MATCHES[0]}"
