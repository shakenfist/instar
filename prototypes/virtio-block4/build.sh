#!/bin/bash
# Build script for virtio-block4 prototype (with performance statistics)

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
echo "To run (default 512-byte sectors):"
echo "  sudo ./target/release/vmm --input source.bin --output dest.bin guest.bin"
echo ""
echo "To run with larger sector sizes:"
echo "  sudo ./target/release/vmm --input source.bin --output dest.bin \\"
echo "       --input-sector-size 4096 --output-sector-size 4096 guest.bin"
echo ""
echo "Example (copy a file with 4KB sectors):"
echo "  dd if=/dev/urandom of=test.bin bs=4096 count=100"
echo "  sudo ./target/release/vmm --input test.bin --output out.bin \\"
echo "       --input-sector-size 4096 --output-sector-size 4096 guest.bin"
echo "  sha256sum test.bin out.bin  # Should match"
echo ""
echo "Note: Running requires /dev/kvm access (root or kvm group)"
