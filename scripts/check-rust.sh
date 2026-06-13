#!/bin/bash
# Run rustfmt and clippy on all Rust prototypes
# Used by pre-commit hooks

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# Docker image to use for linting (stable Rust)
IMAGE="instar-rust-lint"

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

# Note: guest-protocol crate is not in the workspace yet (micropb API issues).
# TODO: Fix micropb compatibility and add to src/Cargo.toml workspace members.

# Check main instar implementation (src/)
if [ -d "$PROJECT_ROOT/src" ]; then
    echo "=== Checking src (main instar) ==="

    # Run rustfmt on all crates
    echo "Running rustfmt..."
    if [ "$MODE" = "fix" ]; then
        run_in_docker "src" cargo fmt --all || FAILED=1
    else
        run_in_docker "src" cargo fmt --all -- --check || FAILED=1
    fi

    # Run clippy on all workspace crates except no_main guest binaries
    echo "Running clippy on workspace..."
    if [ "$MODE" = "fix" ]; then
        run_in_docker "src" cargo clippy --fix --allow-dirty --allow-staged --allow-no-vcs --workspace \
            --exclude core \
            --exclude info \
            --exclude copy \
            --exclude check-op \
            --exclude compare \
            --exclude convert \
            --exclude measure-op \
            --exclude create-op \
            --exclude rebase-op \
            --exclude resize-op \
            --exclude commit-op \
            --exclude map-op \
            --exclude snapshot-op \
            -- -D warnings || FAILED=1
    else
        run_in_docker "src" cargo clippy --workspace \
            --exclude core \
            --exclude info \
            --exclude copy \
            --exclude check-op \
            --exclude compare \
            --exclude convert \
            --exclude measure-op \
            --exclude create-op \
            --exclude rebase-op \
            --exclude resize-op \
            --exclude commit-op \
            --exclude map-op \
            --exclude snapshot-op \
            -- -D warnings || FAILED=1
    fi

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
    # Note: info uses "instar" as the package name, others use "vmm"
    echo "Running clippy on vmm..."
    if [ "$MODE" = "fix" ]; then
        if [ "$prototype" = "prototypes/info" ]; then
            run_in_docker "$prototype" cargo clippy --fix --allow-dirty --allow-staged --allow-no-vcs \
                -p instar -- -D warnings || FAILED=1
        else
            run_in_docker "$prototype" cargo clippy --fix --allow-dirty --allow-staged --allow-no-vcs \
                -p vmm -- -D warnings || FAILED=1
        fi
    else
        if [ "$prototype" = "prototypes/info" ]; then
            run_in_docker "$prototype" cargo clippy -p instar -- -D warnings || FAILED=1
        else
            run_in_docker "$prototype" cargo clippy -p vmm -- -D warnings || FAILED=1
        fi
    fi

    echo ""
done

if [ $FAILED -ne 0 ]; then
    echo "Some checks failed!"
    exit 1
fi

echo "All checks passed!"
