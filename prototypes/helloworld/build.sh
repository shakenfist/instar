#!/bin/bash
# Build script for KVM hello world prototype

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "=== Building guest binary ==="
cd guest
cargo +nightly build --release
cd ..

# Convert ELF to flat binary
echo "=== Converting guest ELF to flat binary ==="
GUEST_ELF="target/x86_64-unknown-none/release/guest"
GUEST_BIN="guest.bin"

if [ -f "$GUEST_ELF" ]; then
    rust-objcopy -O binary "$GUEST_ELF" "$GUEST_BIN"
    echo "Created $GUEST_BIN ($(wc -c < "$GUEST_BIN") bytes)"
else
    echo "Error: Guest ELF not found at $GUEST_ELF"
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
echo "To run:"
echo "  sudo ./target/release/vmm guest.bin"
echo ""
echo "Note: Running requires /dev/kvm access (root or kvm group)"
