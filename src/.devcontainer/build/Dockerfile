# syntax=docker/dockerfile:1
#
# Minimal RELEASE BUILD image for instar.
#
# This image exists to fix the glibc floor of the released `instar`
# host binary. It is built on debian:bullseye (glibc 2.31) so a single
# artifact runs on every distro in the matrix CI down to Rocky/RHEL 9
# (glibc 2.34) and Ubuntu 22.04 LTS (2.35). glibc is forward-compatible
# only: build on the oldest glibc you intend to support.
#
# It carries ONLY the toolchain needed to produce the binary and the
# .deb/.rpm packages: a C toolchain (the host binary's linker),
# protobuf-compiler (micropb-gen codegen), a PINNED Rust nightly with
# rust-src + llvm-tools (the guest ops cross-build for
# x86_64-unknown-none via build-std), cargo-binutils (rust-objcopy,
# which flattens each guest ELF in build.sh), and cargo-deb /
# cargo-generate-rpm (packaging).
#
# It deliberately does NOT carry the test/fuzz tooling (qemu-utils, the
# libyal *-utils parsers, cargo-fuzz, cargo-audit, gh) — that lives on
# the separate dev/test image (src/.devcontainer/Dockerfile). See
# docs/plans/PLAN-distro-matrix-ci-phase-01-glibc-build.md.
#
# NOTE: debian:bullseye is minimal and ships no compiler, unlike the
# devcontainers base image the dev image builds on — build-essential is
# installed explicitly here for the host binary's linker.
#
# DO NOT BUMP THIS TAG. It is deliberately old: the base's glibc IS the
# product here, not an implementation detail, and a newer Debian is
# strictly worse for it. Renovate proposed trixie in #488 and the bump
# raised the binary's floor to GLIBC_2.39, which broke Rocky 9, Ubuntu
# 22.04 and Debian 12 in the merge queue matrix. renovate.json now
# excludes this file; tools/ci/check-glibc-floor.sh fails the build if
# the floor rises again by any other route.
#
# That instruction is not unconditional, it just is not yours to decide
# alone: bullseye LTS ends 2026-08-31, after which this image's
# apt-get layer will eventually break. The successors and what each
# costs in support matrix are written up under "When bullseye reaches
# end of life" in docs/development.md. Read that before changing this
# line -- bookworm is NOT a drop-in, it drops Rocky 9.
FROM debian:bullseye

# Build toolchain only:
# - build-essential: cc/ld for linking the host `instar` VMM binary
# - protobuf-compiler: protoc for micropb-gen (guest-protocol codegen)
# - curl, ca-certificates: fetch rustup
# - git: cargo fetching git dependencies, if any
# - rpm: NOT for building the package -- cargo-generate-rpm does that.
#   It is here purely so /usr/lib/rpm/find-requires exists. With
#   `auto-req = "auto"` (src/vmm/Cargo.toml) cargo-generate-rpm uses
#   find-requires when that path is present and otherwise falls back to
#   its builtin `ldd -v` parser, which is subtly wrong: it strips spaces
#   out of the ldd line, so a WEAK version reference prints as
#   "libc.so.6 (GLIBC_2.25) [WEAK]" and becomes the dependency
#   "libc.so.6(GLIBC_2.25)[WEAK](64bit)". Nothing Provides that, so the
#   .rpm is uninstallable on every RPM distro. rpm's own elfdeps ignores
#   VER_FLG_WEAK and emits the plain "libc.so.6(GLIBC_2.25)(64bit)".
#   This is latent until a toolchain starts marking glibc version needs
#   weak -- nightly-2026-08-17 did, and broke the whole RPM half of the
#   matrix. See docs/development.md, "RPM dependency generation".
RUN apt-get update && apt-get install -y \
    build-essential \
    ca-certificates \
    curl \
    git \
    protobuf-compiler \
    rpm \
    && rm -rf /var/lib/apt/lists/*

# Create a shared build directory that any user can use
RUN mkdir -p /build && chmod 777 /build

# Install Rust nightly via rustup into /build.
# Use umask 0000 so directories are world-writable (any host uid can
# write to the cargo cache when this image runs `docker run -u <uid>`).
#
# The nightly is PINNED, identical to the dev image
# (src/.devcontainer/Dockerfile). build.sh invokes cargo WITHOUT a
# `+nightly` override precisely so it uses this default toolchain; a
# floating nightly would arrive without rust-src and without the pin's
# protection against broken nightlies. Keep this ARG in lockstep with
# the dev image; .github/workflows/rust-nightly-bump.yml test-builds
# both images against a candidate nightly before bumping either.
ARG RUST_NIGHTLY=nightly-2026-08-17
ENV CARGO_HOME=/build/.cargo
ENV RUSTUP_HOME=/build/.rustup
RUN umask 0000 && curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | \
    sh -s -- -y --default-toolchain "${RUST_NIGHTLY}"

# Add cargo to PATH
ENV PATH="/build/.cargo/bin:${PATH}"

# Guest ops cross-build for x86_64-unknown-none via build-std, so
# rust-src and llvm-tools-preview are required (world-writable so any
# host uid can update).
RUN umask 0000 && rustup component add rust-src llvm-tools-preview

# cargo-binutils provides rust-objcopy (build.sh flattens each guest
# ELF to a flat .bin with it).
RUN --mount=type=cache,target=/build/.cargo/registry,sharing=locked \
    --mount=type=cache,target=/build/.cargo/git,sharing=locked \
    umask 0000 && cargo install cargo-binutils

# Packaging tools for `make deb` / `make rpm`. Both run with --no-build
# against artifacts produced by `make instar`, so they only package.
RUN --mount=type=cache,target=/build/.cargo/registry,sharing=locked \
    --mount=type=cache,target=/build/.cargo/git,sharing=locked \
    umask 0000 && cargo install cargo-deb cargo-generate-rpm

# Verify installation (mirrors the dev image's final check, minus the
# test/fuzz tools this image intentionally omits).
RUN rustc --version && cargo --version && rust-objcopy --version \
    && cargo deb --version && cargo generate-rpm --version \
    && protoc --version
