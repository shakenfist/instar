#!/bin/bash
# Build script for pluggable2 prototype (separate operation binaries)
#
# This prototype loads operations as separate binaries for reduced attack surface.
# The VMM loads:
#   - core.bin at 0x10000 (device initialization, call table)
#   - operation.bin at 0x20000 (copy, info, etc.)

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
echo "=== Building VMM ==="
cd vmm
cargo build --release
cd ..

echo ""
echo "=== Build complete ==="
echo ""
echo "Binaries:"
echo "  - core.bin       Core guest (device init, call table) - loaded at 0x10000"
echo "  - copy.bin       Copy operation - loaded at 0x20000"
echo "  - vmm            Virtual machine monitor"
echo ""
echo "To run:"
echo "  sudo ./target/release/vmm --core core.bin --operation copy.bin \\"
echo "       --input source.bin --output dest.bin"
echo ""
echo "Note: Running requires /dev/kvm access (root or kvm group)"
