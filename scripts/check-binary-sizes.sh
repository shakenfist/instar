#!/bin/bash
#
# Check that guest binaries fit within their memory regions.
#
# Memory layout (from shared/src/lib.rs):
#   - Core loads at 0x10000, must fit before operations at 0x20000 (max 64KB)
#   - Operations load at 0x20000, must fit before configs at 0x80000 (max 384KB)
#
# This prevents memory overlap bugs like the VM crashes we had when core.bin
# grew past 0x18000 and corrupted the config area.

set -e

# Memory layout constants (in bytes)
CORE_MAX_SIZE=$((0x10000))      # 64KB - must fit between 0x10000 and 0x20000
OPERATION_MAX_SIZE=$((0x60000)) # 384KB - must fit between 0x20000 and 0x80000

# Binary locations
RELEASE_DIR="src/target/release"

check_size() {
    local binary="$1"
    local max_size="$2"
    local description="$3"

    if [[ ! -f "$binary" ]]; then
        echo "SKIP: $binary not found (not built yet)"
        return 0
    fi

    local size
    size=$(stat -c%s "$binary" 2>/dev/null || stat -f%z "$binary" 2>/dev/null)

    if [[ -z "$size" ]]; then
        echo "ERROR: Could not determine size of $binary"
        return 1
    fi

    local max_kb=$((max_size / 1024))
    local size_kb=$((size / 1024))
    local percent=$((size * 100 / max_size))

    if [[ "$size" -gt "$max_size" ]]; then
        echo "FAIL: $description"
        echo "      $binary is ${size_kb}KB, max is ${max_kb}KB (${percent}% of limit)"
        echo "      This will cause memory overlap and VM crashes!"
        return 1
    else
        echo "OK:   $description - ${size_kb}KB / ${max_kb}KB (${percent}%)"
        return 0
    fi
}

echo "Checking guest binary sizes against memory layout limits..."
echo ""

failed=0

# Check core binary
if ! check_size "$RELEASE_DIR/core.bin" "$CORE_MAX_SIZE" "core.bin (0x10000-0x20000)"; then
    failed=1
fi

# Check operation binaries
for op in info copy check compare convert measure create rebase resize commit snapshot amend; do
    if ! check_size "$RELEASE_DIR/${op}.bin" "$OPERATION_MAX_SIZE" "${op}.bin (0x20000-0x80000)"; then
        failed=1
    fi
done

echo ""

if [[ "$failed" -eq 1 ]]; then
    echo "Binary size check FAILED - memory overlap will occur!"
    echo ""
    echo "To fix: reduce binary size or adjust memory layout in shared/src/lib.rs"
    exit 1
else
    echo "All binaries fit within their memory regions."
    exit 0
fi
