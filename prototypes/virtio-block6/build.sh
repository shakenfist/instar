#!/bin/bash
# Build script for virtio-block6 prototype (sparse output support)

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
echo "To run (sparse output, grows on demand):"
echo "  sudo ./target/release/vmm --input source.bin --output dest.bin guest.bin"
echo ""
echo "To run with custom output capacity:"
echo "  sudo ./target/release/vmm --input source.bin --output dest.bin \\"
echo "       --max-output-size 1073741824 guest.bin  # 1GB capacity"
echo ""
echo "To run with pre-allocated output (traditional behavior):"
echo "  sudo ./target/release/vmm --input source.bin --output dest.bin \\"
echo "       --preallocate-output guest.bin"
echo ""
echo "Example (copy with sparse output):"
echo "  dd if=/dev/urandom of=test.bin bs=4096 count=100"
echo "  sudo ./target/release/vmm --input test.bin --output out.bin guest.bin"
echo "  ls -lsh out.bin  # Check apparent vs allocated size"
echo "  sha256sum test.bin out.bin  # Should match"
echo ""
echo "Note: Running requires /dev/kvm access (root or kvm group)"
