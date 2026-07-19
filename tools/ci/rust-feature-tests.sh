#!/usr/bin/env bash
#
# Feature-gated Rust crate tests for CI.
#
# The functional-tests workflow's main cargo-test step runs the
# workspace with default features only, which silently skips every
# feature-gated test target: the luks crypto tests, the qcow2 create
# tests, the qcow2 chain-reader-arm tests (vdi/parallels/qcow1/dmg
# input), and the create crate. The 2026-07 pre-push audit found those
# had never run in GitHub Actions, only via local `make test-rust`
# (the "guest code silently dropping out of CI" failure class).
#
# This script mirrors the feature-gated tail of the Makefile's
# test-rust target exactly. If you add a feature-gated test invocation
# to the Makefile, add it here too (structural drift-proofing is
# tracked in PLAN-format-coverage.md future work).
#
# Expects the instar-build image to exist (the workflow builds it via
# `make instar` earlier in the job).
set -euo pipefail

cd "$(dirname "$0")/../.."

docker run --rm \
  -u "$(id -u):$(id -g)" \
  -e HOME=/build \
  -e CARGO_HOME=/build/.cargo \
  -e CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-2}" \
  -v "$(pwd):/workspace" \
  -v "$(pwd)/.cargo-cache/registry:/build/.cargo/registry" \
  -v "$(pwd)/.cargo-cache/git:/build/.cargo/git" \
  -w "/workspace/src" \
  instar-build \
  bash -c 'cargo test --release -p luks --features "decrypt,encrypt" && \
    cargo test --release -p qcow2 --features create && \
    cargo test --release -p qcow2 --features "create,vdi-input,parallels-input,qcow1-input,dmg-input" && \
    cargo test --release -p create'
