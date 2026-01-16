# Devcontainer for Rust linting (rustfmt and clippy)
# Uses stable Rust for consistent, reliable lint checks

FROM rust:1.83

# Install rustfmt and clippy components
RUN rustup component add rustfmt clippy

# Set up working directory
WORKDIR /workspace
