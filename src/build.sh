#!/bin/bash
# Build script for instar (safe, sandboxed disk image converter)
#
# Instar provides safe, sandboxed disk image operations using KVM isolation.
# The instar binary loads:
#   - core.bin at 0x10000 (device initialization, call table)
#   - info.bin at 0x20000 (format detection operation)
#   - copy.bin at 0x20000 (copy operation, same address as info)
#   - check.bin at 0x20000 (integrity check operation, same address as info)
#   - compare.bin at 0x20000 (image comparison operation, same address as info)
#   - convert.bin at 0x20000 (image conversion operation, same address as info)
#   - measure.bin at 0x20000 (disk measurement operation, same address as info)

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
echo "=== Building check operation ==="
cd operations/check
cargo +nightly build --release
cd ../..

# Convert check ELF to flat binary
echo "=== Converting check ELF to flat binary ==="
CHECK_ELF="target/x86_64-unknown-none/release/check"
CHECK_BIN="check.bin"

if [ -f "$CHECK_ELF" ]; then
    rust-objcopy -O binary "$CHECK_ELF" "$CHECK_BIN"
    echo "Created $CHECK_BIN ($(wc -c < "$CHECK_BIN") bytes)"
else
    echo "Error: Check ELF not found at $CHECK_ELF"
    exit 1
fi

echo ""
echo "=== Building compare operation ==="
cd operations/compare
cargo +nightly build --release
cd ../..

# Convert compare ELF to flat binary
echo "=== Converting compare ELF to flat binary ==="
COMPARE_ELF="target/x86_64-unknown-none/release/compare"
COMPARE_BIN="compare.bin"

if [ -f "$COMPARE_ELF" ]; then
    rust-objcopy -O binary "$COMPARE_ELF" "$COMPARE_BIN"
    echo "Created $COMPARE_BIN ($(wc -c < "$COMPARE_BIN") bytes)"
else
    echo "Error: Compare ELF not found at $COMPARE_ELF"
    exit 1
fi

echo ""
echo "=== Building convert operation ==="
cd operations/convert
cargo +nightly build --release
cd ../..

# Convert convert ELF to flat binary
echo "=== Converting convert ELF to flat binary ==="
CONVERT_ELF="target/x86_64-unknown-none/release/convert"
CONVERT_BIN="convert.bin"

if [ -f "$CONVERT_ELF" ]; then
    rust-objcopy -O binary "$CONVERT_ELF" "$CONVERT_BIN"
    echo "Created $CONVERT_BIN ($(wc -c < "$CONVERT_BIN") bytes)"
else
    echo "Error: Convert ELF not found at $CONVERT_ELF"
    exit 1
fi

echo ""
echo "=== Building measure operation ==="
cd operations/measure
cargo +nightly build --release
cd ../..

# Convert measure ELF to flat binary
echo "=== Converting measure ELF to flat binary ==="
MEASURE_ELF="target/x86_64-unknown-none/release/measure"
MEASURE_BIN="measure.bin"

if [ -f "$MEASURE_ELF" ]; then
    rust-objcopy -O binary "$MEASURE_ELF" "$MEASURE_BIN"
    echo "Created $MEASURE_BIN ($(wc -c < "$MEASURE_BIN") bytes)"
else
    echo "Error: Measure ELF not found at $MEASURE_ELF"
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
cp "$CHECK_BIN" target/release/
cp "$COMPARE_BIN" target/release/
cp "$CONVERT_BIN" target/release/
cp "$MEASURE_BIN" target/release/
echo "Copied core.bin, info.bin, copy.bin, check.bin, compare.bin, convert.bin, and measure.bin to target/release/"

# Check binary sizes against memory layout limits
# Memory layout (from shared/src/lib.rs):
#   - Core loads at 0x10000, must fit before operations at 0x20000 (max 64KB)
#   - Operations load at 0x20000, must fit before configs at 0x80000 (max 384KB)
echo ""
echo "=== Checking binary sizes against memory layout ==="
CORE_MAX=$((0x10000))      # 64KB
OP_MAX=$((0x60000))        # 384KB
FAILED=0

check_size() {
    local name="$1"
    local file="$2"
    local max="$3"
    local size
    size=$(wc -c < "$file")
    local percent=$((size * 100 / max))
    local max_kb=$((max / 1024))
    local size_kb=$((size / 1024))

    if [ "$size" -gt "$max" ]; then
        echo "FAIL: $name is ${size_kb}KB, max ${max_kb}KB (${percent}%)"
        return 1
    else
        echo "OK:   $name - ${size_kb}KB / ${max_kb}KB (${percent}%)"
        return 0
    fi
}

check_size "core.bin" "target/release/$CORE_BIN" "$CORE_MAX" || FAILED=1
check_size "info.bin" "target/release/$INFO_BIN" "$OP_MAX" || FAILED=1
check_size "copy.bin" "target/release/$COPY_BIN" "$OP_MAX" || FAILED=1
check_size "check.bin" "target/release/$CHECK_BIN" "$OP_MAX" || FAILED=1
check_size "compare.bin" "target/release/$COMPARE_BIN" "$OP_MAX" || FAILED=1
check_size "convert.bin" "target/release/$CONVERT_BIN" "$OP_MAX" || FAILED=1
check_size "measure.bin" "target/release/$MEASURE_BIN" "$OP_MAX" || FAILED=1

if [ "$FAILED" -eq 1 ]; then
    echo ""
    echo "ERROR: Binary size check failed - memory overlap will occur!"
    echo "Fix: reduce binary size or adjust memory layout in shared/src/lib.rs"
    exit 1
fi

echo ""
echo "=== Build complete ==="
echo ""
echo "Binaries (all in target/release/):"
echo "  - instar          Safe, sandboxed disk image operations"
echo "  - core.bin       Core guest (device init, call table) - loaded at 0x10000"
echo "  - info.bin       Info operation (format detection) - loaded at 0x20000"
echo "  - copy.bin       Copy operation (file copy) - loaded at 0x20000"
echo "  - check.bin      Check operation (integrity validation) - loaded at 0x20000"
echo "  - compare.bin    Compare operation (image comparison) - loaded at 0x20000"
echo "  - convert.bin    Convert operation (image conversion) - loaded at 0x20000"
echo "  - measure.bin    Measure operation (disk measurement) - loaded at 0x20000"
echo ""
echo "To run:"
echo "  sudo ./target/release/instar info image.qcow2"
echo "  sudo ./target/release/instar copy input.qcow2 output.raw"
echo "  sudo ./target/release/instar check image.qcow2"
echo "  sudo ./target/release/instar compare image1.raw image2.raw"
echo "  sudo ./target/release/instar convert input.qcow2 output.raw"
echo "  sudo ./target/release/instar measure image.qcow2"
echo ""
echo "For help:"
echo "  ./target/release/instar --help"
echo "  ./target/release/instar info --help"
echo "  ./target/release/instar copy --help"
echo "  ./target/release/instar check --help"
echo "  ./target/release/instar compare --help"
echo "  ./target/release/instar convert --help"
echo "  ./target/release/instar measure --help"
echo ""
echo "Note: Running requires /dev/kvm access (root or kvm group)"
