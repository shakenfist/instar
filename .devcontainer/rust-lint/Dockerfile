# Devcontainer for Rust linting (rustfmt and clippy)
# Uses stable Rust for consistent, reliable lint checks

FROM rust:1.97

# Install protobuf compiler (required for micropb-gen in guest-protocol crate)
RUN apt-get update && apt-get install -y protobuf-compiler && rm -rf /var/lib/apt/lists/*

# Install rustfmt and clippy components
RUN rustup component add rustfmt clippy

# Set up working directory
WORKDIR /workspace
