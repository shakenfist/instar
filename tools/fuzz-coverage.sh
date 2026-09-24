#!/bin/bash
#
# Per-function coverage for one cargo-fuzz target, run inside the
# devcontainer by `make fuzz-coverage`.
#
# This exists because a target that runs clean while reaching none of
# the code it claims to fuzz is indistinguishable, from the outside,
# from a target that found no bug. The per-function hit counts are what
# tell those two apart.
#
# `cargo cov` is not used to render the report: cargo-fuzz 0.12 passes
# `--no-default-features` through to a clap parser that rejects it and
# panics, so llvm-cov is invoked directly against the instrumented
# binary cargo-fuzz builds under target/<triple>/coverage/.
#
# Usage: tools/fuzz-coverage.sh <target> [name-filter-regex]

set -euo pipefail

TARGET="${1:?usage: fuzz-coverage.sh <target> [name-filter-regex]}"
FILTER="${2:-}"

cargo fuzz coverage "${TARGET}"

PROFDATA="coverage/${TARGET}/coverage.profdata"
if [ ! -f "${PROFDATA}" ]; then
  echo "no profdata at ${PROFDATA}: did the coverage run fail?" >&2
  exit 1
fi

TRIPLE="$(rustc -vV | awk '/^host:/ {print $2}')"
BINARY="target/${TRIPLE}/coverage/${TRIPLE}/release/${TARGET}"
if [ ! -x "${BINARY}" ]; then
  echo "no instrumented binary at ${BINARY}" >&2
  exit 1
fi

LLVM_COV="$(rustc --print sysroot)/lib/rustlib/${TRIPLE}/bin/llvm-cov"
if [ ! -x "${LLVM_COV}" ]; then
  LLVM_COV="$(command -v llvm-cov || true)"
fi
if [ -z "${LLVM_COV}" ] || [ ! -x "${LLVM_COV}" ]; then
  echo "no llvm-cov found; is the llvm-tools component installed?" >&2
  exit 1
fi

ARGS=(report "${BINARY}"
      "--instr-profile=${PROFDATA}"
      --ignore-filename-regex='/build/|/registry/|/rustc/')
if [ -n "${FILTER}" ]; then
  ARGS=(report "${BINARY}"
        "--instr-profile=${PROFDATA}"
        --ignore-filename-regex='/build/|/registry/|/rustc/'
        --show-functions
        "--name-regex=${FILTER}"
        ../crates/vhd/src/lib.rs ../crates/vhdx/src/lib.rs)
fi

"${LLVM_COV}" "${ARGS[@]}"
