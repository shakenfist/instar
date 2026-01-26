# syntax=docker/dockerfile:1
FROM mcr.microsoft.com/devcontainers/base:debian

# Install build dependencies and test tools
# - protobuf-compiler: required for micropb-gen
# - python3, python3-pip, python3-venv: for running integration tests
RUN apt-get update && apt-get install -y \
    protobuf-compiler \
    python3 \
    python3-pip \
    python3-venv \
    && rm -rf /var/lib/apt/lists/*

# Create a shared build directory that any user can use
RUN mkdir -p /build && chmod 777 /build

# Install Rust nightly via rustup into /build
# Use umask 0000 so directories are world-writable (any user can write to cargo cache)
ENV CARGO_HOME=/build/.cargo
ENV RUSTUP_HOME=/build/.rustup
RUN umask 0000 && curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | \
    sh -s -- -y --default-toolchain nightly

# Add cargo to PATH
ENV PATH="/build/.cargo/bin:${PATH}"

# Install required components (world-writable so any user can update)
RUN umask 0000 && rustup component add rust-src llvm-tools-preview

# Install cargo-binutils for rust-objcopy (cached registry for faster rebuilds)
RUN --mount=type=cache,target=/build/.cargo/registry,sharing=locked \
    --mount=type=cache,target=/build/.cargo/git,sharing=locked \
    umask 0000 && cargo install cargo-binutils

# Verify installation
RUN rustc --version && cargo --version && rust-objcopy --version && protoc --version
