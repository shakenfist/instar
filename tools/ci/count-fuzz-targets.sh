#!/usr/bin/env bash
#
# Print the number of fuzz targets declared in src/fuzz/Cargo.toml.
#
# Used by .github/workflows/coverage-fuzz.yml to size the manual-dispatch
# duration cap (450 * 60 / N_TARGETS) against the real target count
# instead of a hardcoded number that drifts as targets are added.
#
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/../.."
grep -c '^\[\[bin\]\]' src/fuzz/Cargo.toml
