#!/bin/bash
# Build script for info prototype (image format detection and copy)
#
# This prototype provides safe, sandboxed disk image operations.
# The instar binary loads:
#   - core.bin at 0x10000 (device initialization, call table)
#   - info.bin at 0x20000 (format detection operation)
#   - copy.bin at 0x20000 (copy operation, same address as info)

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "=== Building core binary ==="
cd core
cargo +nightly build --release
cd ..

# Convert core ELF to flat binary
echo "=== Converting core ELF to flat binary ==="
CORE_ELF="target/x86_64-unknown-none/release/core"
CORE_BIN="core.bin"

if [ -f "$CORE_ELF" ]; then
    rust-objcopy -O binary "$CORE_ELF" "$CORE_BIN"
    echo "Created $CORE_BIN ($(wc -c < "$CORE_BIN") bytes)"
else
    echo "Error: Core ELF not found at $CORE_ELF"
    exit 1
fi

echo ""
echo "=== Building info operation ==="
cd operations/info
cargo +nightly build --release
cd ../..

# Convert info ELF to flat binary
echo "=== Converting info ELF to flat binary ==="
INFO_ELF="target/x86_64-unknown-none/release/info"
INFO_BIN="info.bin"

if [ -f "$INFO_ELF" ]; then
    rust-objcopy -O binary "$INFO_ELF" "$INFO_BIN"
    echo "Created $INFO_BIN ($(wc -c < "$INFO_BIN") bytes)"
else
    echo "Error: Info ELF not found at $INFO_ELF"
    exit 1
fi

echo ""
echo "=== Building copy operation ==="
cd operations/copy
cargo +nightly build --release
cd ../..

# Convert copy ELF to flat binary
echo "=== Converting copy ELF to flat binary ==="
COPY_ELF="target/x86_64-unknown-none/release/copy"
COPY_BIN="copy.bin"

if [ -f "$COPY_ELF" ]; then
    rust-objcopy -O binary "$COPY_ELF" "$COPY_BIN"
    echo "Created $COPY_BIN ($(wc -c < "$COPY_BIN") bytes)"
else
    echo "Error: Copy ELF not found at $COPY_ELF"
    exit 1
fi

echo ""
echo "=== Building instar ==="
cd vmm
cargo build --release
cd ..

# Copy binaries to target/release/ so they're co-located with instar
echo ""
echo "=== Copying binaries to target/release/ ==="
cp "$CORE_BIN" target/release/
cp "$INFO_BIN" target/release/
cp "$COPY_BIN" target/release/
echo "Copied core.bin, info.bin, and copy.bin to target/release/"

echo ""
echo "=== Build complete ==="
echo ""
echo "Binaries (all in target/release/):"
echo "  - instar          Safe, sandboxed disk image operations"
echo "  - core.bin       Core guest (device init, call table) - loaded at 0x10000"
echo "  - info.bin       Info operation (format detection) - loaded at 0x20000"
echo "  - copy.bin       Copy operation (file copy) - loaded at 0x20000"
echo ""
echo "To run:"
echo "  sudo ./target/release/instar info image.qcow2"
echo "  sudo ./target/release/instar copy input.qcow2 output.raw"
echo ""
echo "For help:"
echo "  ./target/release/instar --help"
echo "  ./target/release/instar info --help"
echo "  ./target/release/instar copy --help"
echo ""
echo "Note: Running requires /dev/kvm access (root or kvm group)"
