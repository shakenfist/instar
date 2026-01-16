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

for prototype in prototypes/helloworld prototypes/helloworld2; do
    echo "=== Checking $prototype ==="

    # Run rustfmt on all crates
    echo "Running rustfmt..."
    if [ "$MODE" = "fix" ]; then
        run_in_docker "$prototype" cargo fmt --all || FAILED=1
    else
        run_in_docker "$prototype" cargo fmt --all -- --check || FAILED=1
    fi

    # Run clippy only on VMM crate (guest crates are no_std and don't support clippy)
    echo "Running clippy on vmm..."
    run_in_docker "$prototype" cargo clippy -p vmm -- -D warnings || FAILED=1

    echo ""
done

if [ $FAILED -ne 0 ]; then
    echo "Some checks failed!"
    exit 1
fi

echo "All checks passed!"
