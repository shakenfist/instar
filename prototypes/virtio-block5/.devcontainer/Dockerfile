FROM mcr.microsoft.com/devcontainers/base:debian

# Install protobuf compiler (required for micropb-gen)
RUN apt-get update && apt-get install -y protobuf-compiler && rm -rf /var/lib/apt/lists/*

# Install Rust nightly via rustup
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | \
    sh -s -- -y --default-toolchain nightly

# Add cargo to PATH for subsequent RUN commands
ENV PATH="/root/.cargo/bin:${PATH}"

# Switch to vscode user for rustup setup
USER vscode

# Install Rust for vscode user
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | \
    sh -s -- -y --default-toolchain nightly

# Add cargo to vscode user's PATH
ENV PATH="/home/vscode/.cargo/bin:${PATH}"

# Install required components
RUN rustup component add rust-src llvm-tools-preview

# Install cargo-binutils for rust-objcopy
RUN cargo install cargo-binutils

# Verify installation
RUN rustc --version && cargo --version && rust-objcopy --version && protoc --version
