#!/bin/bash
# Run rustfmt and clippy on all Rust prototypes
# Used by pre-commit hooks

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# Docker image to use for linting (stable Rust)
IMAGE="imago-rust-lint"

# Check if docker image exists
if ! docker image inspect "$IMAGE" &>/dev/null; then
    echo "Building $IMAGE docker image..."
    docker build -t "$IMAGE" "$PROJECT_ROOT/.devcontainer/rust-lint/"
fi

MODE="${1:-check}"  # "check" or "fix"

run_in_docker() {
    local dir="$1"
    shift
    docker run --rm \
        -v "$PROJECT_ROOT:/workspace" \
        -w "/workspace/$dir" \
        "$IMAGE" \
        "$@"
}

FAILED=0

# Check shared crates first
# Note: guest-protocol is skipped - it has micropb API issues and isn't integrated yet
# TODO: Fix micropb compatibility and re-enable
for crate in; do
    echo "=== Checking $crate ==="

    # Run rustfmt
    echo "Running rustfmt..."
    if [ "$MODE" = "fix" ]; then
        run_in_docker "$crate" cargo fmt -- || FAILED=1
    else
        run_in_docker "$crate" cargo fmt -- --check || FAILED=1
    fi

    # Run clippy
    echo "Running clippy..."
    run_in_docker "$crate" cargo clippy -- -D warnings || FAILED=1

    echo ""
done

# Check main imago implementation (src/)
if [ -d "$PROJECT_ROOT/src" ]; then
    echo "=== Checking src (main imago) ==="

    # Run rustfmt on all crates
    echo "Running rustfmt..."
    if [ "$MODE" = "fix" ]; then
        run_in_docker "src" cargo fmt --all || FAILED=1
    else
        run_in_docker "src" cargo fmt --all -- --check || FAILED=1
    fi

    # Run clippy only on imago crate (guest crates are no_std and don't support clippy)
    echo "Running clippy on imago..."
    run_in_docker "src" cargo clippy -p imago -- -D warnings || FAILED=1

    echo ""
fi

# Check prototypes
for prototype in prototypes/helloworld prototypes/helloworld2 \
                 prototypes/virtio-block prototypes/virtio-block2 \
                 prototypes/virtio-block3 prototypes/virtio-block4 \
                 prototypes/virtio-block5 prototypes/virtio-block6 \
                 prototypes/pluggable prototypes/pluggable2 \
                 prototypes/info; do
    # Skip if directory doesn't exist yet
    if [ ! -d "$PROJECT_ROOT/$prototype" ]; then
        continue
    fi

    echo "=== Checking $prototype ==="

    # Run rustfmt on all crates
    echo "Running rustfmt..."
    if [ "$MODE" = "fix" ]; then
        run_in_docker "$prototype" cargo fmt --all || FAILED=1
    else
        run_in_docker "$prototype" cargo fmt --all -- --check || FAILED=1
    fi

    # Run clippy only on VMM crate (guest crates are no_std and don't support clippy)
    # Note: info uses "imago" as the package name, others use "vmm"
    echo "Running clippy on vmm..."
    if [ "$prototype" = "prototypes/info" ]; then
        run_in_docker "$prototype" cargo clippy -p imago -- -D warnings || FAILED=1
    else
        run_in_docker "$prototype" cargo clippy -p vmm -- -D warnings || FAILED=1
    fi

    echo ""
done

if [ $FAILED -ne 0 ]; then
    echo "Some checks failed!"
    exit 1
fi

echo "All checks passed!"
