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

# Run the lint container as the host user so build artifacts (target/,
# Cargo.lock, the cargo cache) are written owned by us rather than root.
# The Makefile's build/test targets already run as -u $(id -u):$(id -g);
# matching that here keeps a `pre-commit` lint run from leaving root-owned
# files that later break `make instar` / `make test-rust` with "Permission
# denied" and that cannot be removed (e.g. worktree cleanup) without sudo.
UID_VAL="$(id -u)"
GID_VAL="$(id -g)"

# Docker creates missing bind-mount dirs as root, and any earlier root-owned
# lint run can leave the cargo cache, target/, or Cargo.lock owned by root --
# either blocks a later run as the host user. Create the cache dirs up front,
# then fix ownership of anything already root-owned using a throwaway
# container (no sudo required). Globs that match nothing are skipped.
mkdir -p "$PROJECT_ROOT/.cargo-cache/registry" "$PROJECT_ROOT/.cargo-cache/git"
fix_ownership() {
    local path
    for path in "$@"; do
        if [ -e "$path" ] && [ ! -w "$path" ]; then
            echo "Fixing ownership of $path ..."
            docker run --rm -v "$path:/fixme" alpine \
                chown -R "$UID_VAL:$GID_VAL" /fixme
        fi
    done
}
fix_ownership "$PROJECT_ROOT/.cargo-cache/registry" "$PROJECT_ROOT/.cargo-cache/git" \
    "$PROJECT_ROOT/src/Cargo.lock" "$PROJECT_ROOT/src/target" \
    "$PROJECT_ROOT"/prototypes/*/Cargo.lock "$PROJECT_ROOT"/prototypes/*/target

run_in_docker() {
    local dir="$1"
    shift
    docker run --rm \
        -u "$UID_VAL:$GID_VAL" \
        -e HOME=/build \
        -e CARGO_HOME=/build/.cargo \
        -v "$PROJECT_ROOT:/workspace" \
        -v "$PROJECT_ROOT/.cargo-cache/registry:/build/.cargo/registry" \
        -v "$PROJECT_ROOT/.cargo-cache/git:/build/.cargo/git" \
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
            --exclude amend-op \
            --exclude bitmap-op \
            --exclude bench-op \
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
            --exclude amend-op \
            --exclude bitmap-op \
            --exclude bench-op \
            -- -D warnings || FAILED=1
    fi

    # Feature-gated code (the luks crypto paths, qcow2 create, and the
    # qcow2 chain-reader arms for vdi/parallels/qcow1/dmg input) is
    # invisible to the workspace clippy run above, which uses default
    # features only. Lint it explicitly, mirroring the Makefile's
    # test-rust feature matrix.
    echo "Running clippy on feature-gated crates..."
    if [ "$MODE" = "fix" ]; then
        run_in_docker "src" cargo clippy --fix --allow-dirty --allow-staged --allow-no-vcs \
            -p luks --features "decrypt,encrypt" || FAILED=1
        run_in_docker "src" cargo clippy --fix --allow-dirty --allow-staged --allow-no-vcs \
            -p qcow2 --features "create,vdi-input,parallels-input,qcow1-input,dmg-input" || FAILED=1
    else
        run_in_docker "src" cargo clippy \
            -p luks --features "decrypt,encrypt" \
            -- -D warnings || FAILED=1
        run_in_docker "src" cargo clippy \
            -p qcow2 --features "create,vdi-input,parallels-input,qcow1-input,dmg-input" \
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
    # Prototypes declare clippy::unwrap_used at warn (rust-unwrap-lint
    # audit) but are archived proofs-of-concept: surface the warning
    # locally, do not gate CI on it (-A overrides the blanket -D).
    echo "Running clippy on vmm..."
    if [ "$MODE" = "fix" ]; then
        if [ "$prototype" = "prototypes/info" ]; then
            run_in_docker "$prototype" cargo clippy --fix --allow-dirty --allow-staged --allow-no-vcs \
                -p instar -- -D warnings -A clippy::unwrap-used || FAILED=1
        else
            run_in_docker "$prototype" cargo clippy --fix --allow-dirty --allow-staged --allow-no-vcs \
                -p vmm -- -D warnings -A clippy::unwrap-used || FAILED=1
        fi
    else
        if [ "$prototype" = "prototypes/info" ]; then
            run_in_docker "$prototype" cargo clippy -p instar -- -D warnings -A clippy::unwrap-used || FAILED=1
        else
            run_in_docker "$prototype" cargo clippy -p vmm -- -D warnings -A clippy::unwrap-used || FAILED=1
        fi
    fi

    echo ""
done

if [ $FAILED -ne 0 ]; then
    echo "Some checks failed!"
    exit 1
fi

echo "All checks passed!"
