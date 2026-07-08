#!/bin/bash
# Build script for instar (safe, sandboxed disk image converter)
#
# Instar provides safe, sandboxed disk image operations using KVM isolation.
# The instar binary loads:
#   - core.bin at 0x10000 (device initialization, call table)
#   - info.bin at 0x30000 (format detection operation)
#   - copy.bin at 0x30000 (copy operation, same address as info)
#   - check.bin at 0x30000 (integrity check operation, same address as info)
#   - compare.bin at 0x30000 (image comparison operation, same address as info)
#   - convert.bin at 0x30000 (image conversion operation, same address as info)
#   - measure.bin at 0x30000 (disk measurement operation, same address as info)
#   - create.bin at 0x30000 (image creation operation, same address as info)
#   - map.bin at 0x30000 (allocation map operation, same address as info)
#   - snapshot.bin at 0x30000 (snapshot operation, same address as info)
#   - bench.bin at 0x30000 (read/write throughput benchmark, same address as info)

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
echo "=== Building create operation ==="
cd operations/create
cargo +nightly build --release
cd ../..

# Convert create ELF to flat binary
echo "=== Converting create ELF to flat binary ==="
CREATE_ELF="target/x86_64-unknown-none/release/create"
CREATE_BIN="create.bin"

if [ -f "$CREATE_ELF" ]; then
    rust-objcopy -O binary "$CREATE_ELF" "$CREATE_BIN"
    echo "Created $CREATE_BIN ($(wc -c < "$CREATE_BIN") bytes)"
else
    echo "Error: Create ELF not found at $CREATE_ELF"
    exit 1
fi

echo ""
echo "=== Building resize operation ==="
cd operations/resize
cargo +nightly build --release
cd ../..

# Convert resize ELF to flat binary
echo "=== Converting resize ELF to flat binary ==="
RESIZE_ELF="target/x86_64-unknown-none/release/resize"
RESIZE_BIN="resize.bin"

if [ -f "$RESIZE_ELF" ]; then
    rust-objcopy -O binary "$RESIZE_ELF" "$RESIZE_BIN"
    echo "Created $RESIZE_BIN ($(wc -c < "$RESIZE_BIN") bytes)"
else
    echo "Error: Resize ELF not found at $RESIZE_ELF"
    exit 1
fi

echo ""
echo "=== Building rebase operation ==="
cd operations/rebase
cargo +nightly build --release
cd ../..

# Convert rebase ELF to flat binary
echo "=== Converting rebase ELF to flat binary ==="
REBASE_ELF="target/x86_64-unknown-none/release/rebase"
REBASE_BIN="rebase.bin"

if [ -f "$REBASE_ELF" ]; then
    rust-objcopy -O binary "$REBASE_ELF" "$REBASE_BIN"
    echo "Created $REBASE_BIN ($(wc -c < "$REBASE_BIN") bytes)"
else
    echo "Error: Rebase ELF not found at $REBASE_ELF"
    exit 1
fi

echo ""
echo "=== Building commit operation ==="
cd operations/commit
cargo +nightly build --release
cd ../..

# Convert commit ELF to flat binary
echo "=== Converting commit ELF to flat binary ==="
COMMIT_ELF="target/x86_64-unknown-none/release/commit"
COMMIT_BIN="commit.bin"

if [ -f "$COMMIT_ELF" ]; then
    rust-objcopy -O binary "$COMMIT_ELF" "$COMMIT_BIN"
    echo "Created $COMMIT_BIN ($(wc -c < "$COMMIT_BIN") bytes)"
else
    echo "Error: Commit ELF not found at $COMMIT_ELF"
    exit 1
fi

echo ""
echo "=== Building map operation ==="
cd operations/map
cargo +nightly build --release
cd ../..

# Convert map ELF to flat binary
echo "=== Converting map ELF to flat binary ==="
MAP_ELF="target/x86_64-unknown-none/release/map"
MAP_BIN="map.bin"

if [ -f "$MAP_ELF" ]; then
    rust-objcopy -O binary "$MAP_ELF" "$MAP_BIN"
    echo "Created $MAP_BIN ($(wc -c < "$MAP_BIN") bytes)"
else
    echo "Error: Map ELF not found at $MAP_ELF"
    exit 1
fi

echo ""
echo "=== Building snapshot operation ==="
cd operations/snapshot
cargo +nightly build --release
cd ../..

# Convert snapshot ELF to flat binary
echo "=== Converting snapshot ELF to flat binary ==="
SNAPSHOT_ELF="target/x86_64-unknown-none/release/snapshot"
SNAPSHOT_BIN="snapshot.bin"

if [ -f "$SNAPSHOT_ELF" ]; then
    rust-objcopy -O binary "$SNAPSHOT_ELF" "$SNAPSHOT_BIN"
    echo "Created $SNAPSHOT_BIN ($(wc -c < "$SNAPSHOT_BIN") bytes)"
else
    echo "Error: Snapshot ELF not found at $SNAPSHOT_ELF"
    exit 1
fi

echo ""
echo "=== Building amend operation ==="
cd operations/amend
cargo +nightly build --release
cd ../..

# Convert amend ELF to flat binary
echo "=== Converting amend ELF to flat binary ==="
AMEND_ELF="target/x86_64-unknown-none/release/amend"
AMEND_BIN="amend.bin"

if [ -f "$AMEND_ELF" ]; then
    rust-objcopy -O binary "$AMEND_ELF" "$AMEND_BIN"
    echo "Created $AMEND_BIN ($(wc -c < "$AMEND_BIN") bytes)"
else
    echo "Error: Amend ELF not found at $AMEND_ELF"
    exit 1
fi

echo ""
echo "=== Building bitmap operation ==="
cd operations/bitmap
cargo +nightly build --release
cd ../..

# Convert bitmap ELF to flat binary
echo "=== Converting bitmap ELF to flat binary ==="
BITMAP_ELF="target/x86_64-unknown-none/release/bitmap"
BITMAP_BIN="bitmap.bin"

if [ -f "$BITMAP_ELF" ]; then
    rust-objcopy -O binary "$BITMAP_ELF" "$BITMAP_BIN"
    echo "Created $BITMAP_BIN ($(wc -c < "$BITMAP_BIN") bytes)"
else
    echo "Error: Bitmap ELF not found at $BITMAP_ELF"
    exit 1
fi

echo ""
echo "=== Building bench operation ==="
cd operations/bench
cargo +nightly build --release
cd ../..

# Convert bench ELF to flat binary
echo "=== Converting bench ELF to flat binary ==="
BENCH_ELF="target/x86_64-unknown-none/release/bench"
BENCH_BIN="bench.bin"

if [ -f "$BENCH_ELF" ]; then
    rust-objcopy -O binary "$BENCH_ELF" "$BENCH_BIN"
    echo "Created $BENCH_BIN ($(wc -c < "$BENCH_BIN") bytes)"
else
    echo "Error: Bench ELF not found at $BENCH_ELF"
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
cp "$CREATE_BIN" target/release/
cp "$RESIZE_BIN" target/release/
cp "$REBASE_BIN" target/release/
cp "$COMMIT_BIN" target/release/
cp "$MAP_BIN" target/release/
cp "$SNAPSHOT_BIN" target/release/
cp "$AMEND_BIN" target/release/
cp "$BITMAP_BIN" target/release/
cp "$BENCH_BIN" target/release/
echo "Copied core.bin, info.bin, copy.bin, check.bin, compare.bin, convert.bin, measure.bin, create.bin, resize.bin, rebase.bin, commit.bin, map.bin, snapshot.bin, amend.bin, bitmap.bin, and bench.bin to target/release/"

# Check binary sizes against memory layout limits.
#
# Memory layout (from shared/src/lib.rs): core loads at 0x10000 and must
# fit before operations at 0x30000 (128KB); operations load at 0x30000 and
# must fit before the call table at 0xF0000 (768KB).
#
# This is a coarse build-time guard on the flat .bin file size, which does
# NOT include .bss. The AUTHORITATIVE check is scripts/check-binary-sizes.sh
# (run by `make check-binary-sizes`, the pre-commit hook, and CI), which
# measures the .bss-inclusive ELF memory extent — keep the limits here in
# sync with it. (We don't delegate to that script here because this runs in
# the rust-objcopy/LLVM build container, which lacks GNU readelf.)
echo ""
echo "=== Checking binary sizes against memory layout ==="
CORE_MAX=$((0x30000 - 0x10000))   # 128KB: 0x10000..0x30000
OP_MAX=$((0xF0000 - 0x30000))     # 768KB: 0x30000..0xF0000
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
check_size "create.bin" "target/release/$CREATE_BIN" "$OP_MAX" || FAILED=1
check_size "resize.bin" "target/release/$RESIZE_BIN" "$OP_MAX" || FAILED=1
check_size "rebase.bin" "target/release/$REBASE_BIN" "$OP_MAX" || FAILED=1
check_size "commit.bin" "target/release/$COMMIT_BIN" "$OP_MAX" || FAILED=1
check_size "map.bin" "target/release/$MAP_BIN" "$OP_MAX" || FAILED=1
check_size "snapshot.bin" "target/release/$SNAPSHOT_BIN" "$OP_MAX" || FAILED=1
check_size "amend.bin" "target/release/$AMEND_BIN" "$OP_MAX" || FAILED=1
check_size "bitmap.bin" "target/release/$BITMAP_BIN" "$OP_MAX" || FAILED=1
check_size "bench.bin" "target/release/$BENCH_BIN" "$OP_MAX" || FAILED=1

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
echo "  - info.bin       Info operation (format detection) - loaded at 0x30000"
echo "  - copy.bin       Copy operation (file copy) - loaded at 0x30000"
echo "  - check.bin      Check operation (integrity validation) - loaded at 0x30000"
echo "  - compare.bin    Compare operation (image comparison) - loaded at 0x30000"
echo "  - convert.bin    Convert operation (image conversion) - loaded at 0x30000"
echo "  - measure.bin    Measure operation (disk measurement) - loaded at 0x30000"
echo "  - create.bin     Create operation (empty image creation) - loaded at 0x30000"
echo "  - resize.bin     Resize operation (in-place image resize) - loaded at 0x30000"
echo "  - rebase.bin     Rebase operation (change backing-file reference) - loaded at 0x30000"
echo "  - commit.bin     Commit operation (merge overlay into backing) - loaded at 0x30000"
echo "  - map.bin        Map operation (stream allocation map) - loaded at 0x30000"
echo "  - snapshot.bin   Snapshot operation (list/apply/create/delete) - loaded at 0x30000"
echo "  - amend.bin      Amend operation (change qcow2 compat / lazy refcounts) - loaded at 0x30000"
echo "  - bitmap.bin     Bitmap operation (mutate qcow2 persistent dirty bitmaps) - loaded at 0x30000"
echo "  - bench.bin      Bench operation (read/write throughput benchmark) - loaded at 0x30000"
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
