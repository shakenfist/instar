#!/usr/bin/env bash
# Run a cargo command inside the instar-build devcontainer image,
# matching the volume / env wiring the Makefile's test-rust target
# uses. Intended for fast targeted iteration (e.g.
# `tools/cargo-in-container.sh test --release -p shared`) without
# rebuilding the whole workspace. Rust toolchains stay in Docker.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
IMAGE="${INSTAR_IMAGE:-instar-build}"
CARGO_CACHE_DIR="${CARGO_CACHE_DIR:-.cargo-cache}"

mkdir -p "${REPO_ROOT}/${CARGO_CACHE_DIR}/registry" \
         "${REPO_ROOT}/${CARGO_CACHE_DIR}/git"

exec docker run --rm \
  -u "$(id -u):$(id -g)" \
  -e HOME=/build \
  -e CARGO_HOME=/build/.cargo \
  -v "${REPO_ROOT}:/workspace" \
  -v "${REPO_ROOT}/${CARGO_CACHE_DIR}/registry:/build/.cargo/registry" \
  -v "${REPO_ROOT}/${CARGO_CACHE_DIR}/git:/build/.cargo/git" \
  -w /workspace/src \
  "${IMAGE}" \
  cargo "$@"
