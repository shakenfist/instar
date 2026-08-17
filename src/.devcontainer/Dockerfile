# syntax=docker/dockerfile:1
#
# Dev/test image: the full Debian toolchain (qemu-utils, the libyal
# parsers, cargo-fuzz/audit, gh) used by the test and fuzz suites and
# the VS Code devcontainer. The release binary is built on the separate
# minimal build image (src/.devcontainer/build/Dockerfile,
# debian:bullseye) so its glibc floor is not tied to this base.
#
# The base is pinned by digest for reproducibility (the qemu-img this
# image ships is the differential fuzzer's reference oracle, so a
# silent base change would move that oracle). The :debian tag is kept
# alongside the digest so Renovate's Docker manager walks the digest
# forward with a PR whenever the rolling tag is rebuilt upstream; the
# renovate.json digest rule routes those as reviewable (non-automerged)
# PRs.
FROM mcr.microsoft.com/devcontainers/base:debian@sha256:025b74bb5f7ac53edd77e01aa7188c359aab100e23a2f6220bde50bbb9fd31dd

# Install build dependencies and test tools
# - protobuf-compiler: required for micropb-gen
# - python3, python3-pip, python3-venv: for running integration tests
# - qemu-utils: provides qemu-img and qemu-io for compare/convert tests
# - libqcow-utils, libvhdi-utils, libvmdk-utils: libyal forensic parsers
#   for differential fuzzing (independent QCOW2/VHD/VHDX/VMDK reference)
# - wget: for downloading gh CLI keyring
RUN apt-get update && apt-get install -y \
    libqcow-utils \
    libvhdi-utils \
    libvmdk-utils \
    protobuf-compiler \
    python3 \
    python3-pip \
    python3-venv \
    qemu-utils \
    wget \
    && rm -rf /var/lib/apt/lists/*

# Install GitHub CLI (used by differential fuzzer to file issues)
RUN mkdir -p -m 755 /etc/apt/keyrings \
    && wget -qO- https://cli.github.com/packages/githubcli-archive-keyring.gpg \
       | tee /etc/apt/keyrings/githubcli-archive-keyring.gpg >/dev/null \
    && chmod go+r /etc/apt/keyrings/githubcli-archive-keyring.gpg \
    && echo "deb [arch=$(dpkg --print-architecture) \
       signed-by=/etc/apt/keyrings/githubcli-archive-keyring.gpg] \
       https://cli.github.com/packages stable main" \
       | tee /etc/apt/sources.list.d/github-cli.list >/dev/null \
    && apt-get update && apt-get install -y gh \
    && rm -rf /var/lib/apt/lists/*

# Create a shared build directory that any user can use
RUN mkdir -p /build && chmod 777 /build

# Install Rust nightly via rustup into /build
# Use umask 0000 so directories are world-writable (any user can write to cargo cache)
#
# The nightly is PINNED, not floating. A broken nightly otherwise breaks
# every from-scratch build of this image: on 2026-07-24 the then-current
# nightly ICE'd compiling tokio during `cargo install cargo-audit`, which
# failed CI's "Build devcontainer" step until this pin was introduced.
# The pin is moved forward by .github/workflows/rust-nightly-bump.yml,
# which weekly test-builds this image (and instar itself) against the
# newest published nightly and opens a bump PR only when the full build
# succeeds. Renovate does not manage rustup toolchain pins, so do not
# expect it to bump this line.
ARG RUST_NIGHTLY=nightly-2026-08-17
ENV CARGO_HOME=/build/.cargo
ENV RUSTUP_HOME=/build/.rustup
RUN umask 0000 && curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | \
    sh -s -- -y --default-toolchain "${RUST_NIGHTLY}"

# Add cargo to PATH
ENV PATH="/build/.cargo/bin:${PATH}"

# Install required components (world-writable so any user can update)
RUN umask 0000 && rustup component add rust-src llvm-tools-preview

# Install cargo-binutils for rust-objcopy (cached registry for faster rebuilds)
RUN --mount=type=cache,target=/build/.cargo/registry,sharing=locked \
    --mount=type=cache,target=/build/.cargo/git,sharing=locked \
    umask 0000 && cargo install cargo-binutils

# Install cargo-fuzz for coverage-guided fuzzing of parser crates
RUN --mount=type=cache,target=/build/.cargo/registry,sharing=locked \
    --mount=type=cache,target=/build/.cargo/git,sharing=locked \
    umask 0000 && cargo install cargo-fuzz

# Install packaging tools for `make deb` / `make rpm`. Both run with
# --no-build against artifacts produced by `make instar`.
RUN --mount=type=cache,target=/build/.cargo/registry,sharing=locked \
    --mount=type=cache,target=/build/.cargo/git,sharing=locked \
    umask 0000 && cargo install cargo-deb cargo-generate-rpm

# Install cargo-audit for `make audit` (RUSTSEC advisory check
# against the workspace dependency tree).
RUN --mount=type=cache,target=/build/.cargo/registry,sharing=locked \
    --mount=type=cache,target=/build/.cargo/git,sharing=locked \
    umask 0000 && cargo install cargo-audit

# Verify installation
RUN rustc --version && cargo --version && rust-objcopy --version \
    && cargo fuzz --version && cargo deb --version \
    && cargo generate-rpm --version && cargo audit --version \
    && protoc --version
