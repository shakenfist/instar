# syntax=docker/dockerfile:1
FROM mcr.microsoft.com/devcontainers/base:debian

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

# Install cargo-fuzz for coverage-guided fuzzing of parser crates
RUN --mount=type=cache,target=/build/.cargo/registry,sharing=locked \
    --mount=type=cache,target=/build/.cargo/git,sharing=locked \
    umask 0000 && cargo install cargo-fuzz

# Verify installation
RUN rustc --version && cargo --version && rust-objcopy --version \
    && cargo fuzz --version && protoc --version
