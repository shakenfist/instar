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
# A name filter switches the report to per-function counts, which needs
# the source files those functions live in. Those default to every crate
# rather than to the pair this was first written for: the filter is a
# regex over function names, so pointing it at one crate while asking
# about another produces an empty report and no indication why.
#
# Usage: tools/fuzz-coverage.sh <target> [name-filter-regex] [source...]

set -euo pipefail

TARGET="${1:?usage: fuzz-coverage.sh <target> [name-filter-regex] [source...]}"
FILTER="${2:-}"
shift $(($# > 2 ? 2 : $#))
SOURCES=("$@")

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
  if [ "${#SOURCES[@]}" -eq 0 ]; then
    # Relative to the working directory make(1) uses for this script,
    # which is /workspace/src/fuzz.
    mapfile -t SOURCES < <(compgen -G '../crates/*/src/lib.rs' || true)
  fi
  if [ "${#SOURCES[@]}" -eq 0 ]; then
    echo "no crate sources found for the filtered report" >&2
    exit 1
  fi
  ARGS+=(--show-functions "--name-regex=${FILTER}" "${SOURCES[@]}")
fi

"${LLVM_COV}" "${ARGS[@]}"
