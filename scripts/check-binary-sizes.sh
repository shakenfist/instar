#!/bin/bash
#
# Check that guest binaries fit within their memory regions.
#
# Memory layout (from shared/src/lib.rs):
#   - Core loads at 0x10000, must fit before operations at 0x22000 (max 72KB)
#   - Operations load at 0x22000, must fit before the call table at 0x80000
#     (max 376KB)
#
# IMPORTANT: this checks each binary's *runtime memory footprint* (the
# .bss-inclusive ELF extent), NOT the flat .bin file size. The flat
# binary excludes .bss (zero-initialised, not stored on disk), so a
# binary whose .bin fits can still overflow its region at runtime once
# .bss is laid down. That is exactly the bug this check now guards
# against: core's .bss (the INPUT_DEVICES / OUTPUT_DEVICE virtio statics)
# once overflowed past 0x20000 and core's device init wrote the
# VirtioBlock struct over the loaded operation's code, corrupting amend's
# header cross-check. The old file-size-only check missed it because the
# .bin was under budget. OPERATION_LOAD_ADDR was raised 0x20000 -> 0x22000
# to give core room, and this check now uses the ELF memory extent.

set -e

# Memory layout constants (in bytes). Keep in sync with shared/src/lib.rs:
#   GUEST_CODE_BASE = 0x10000, OPERATION_LOAD_ADDR = 0x22000,
#   CALL_TABLE_ADDR = 0x80000.
CORE_BASE=$((0x10000))
OPERATION_BASE=$((0x22000))
CALL_TABLE_ADDR=$((0x80000))
CORE_MAX_SIZE=$((OPERATION_BASE - CORE_BASE))           # 72KB: 0x10000..0x22000
OPERATION_MAX_SIZE=$((CALL_TABLE_ADDR - OPERATION_BASE)) # 376KB: 0x22000..0x80000

# Early-warning threshold: a binary at or above this percent of its
# region is flagged (without failing) so the layout gets attention
# before it overflows. The .bss overflow this check now guards against
# was preceded by core sitting at ~99% of its old budget; a warning here
# gives runway to act. Override with WARN_PCT=NN to tune.
WARN_PCT=${WARN_PCT:-85}

# Binary locations. The flat .bin is what the VMM loads; the ELF (no
# extension, under the target triple dir) carries the section/segment
# info we need for the .bss-inclusive memory extent.
RELEASE_DIR="src/target/release"
ELF_DIR="src/target/x86_64-unknown-none/release"

# Compute a binary's runtime memory footprint in bytes: the highest
# (VirtAddr + MemSiz) across the ELF's LOAD segments, minus its load
# base. MemSiz (unlike FileSiz) includes .bss.
mem_footprint() {
    local elf="$1"
    local base="$2"
    readelf -lW "$elf" 2>/dev/null | awk -v base="$base" '
        $1 == "LOAD" {
            v = strtonum($3); m = strtonum($6); e = v + m
            if (e > max) max = e
        }
        END { if (max > 0) print max - base; else print -1 }'
}

check_size() {
    local name="$1"
    local base="$2"
    local max_size="$3"
    local description="$4"

    local elf="$ELF_DIR/$name"
    local bin="$RELEASE_DIR/$name.bin"

    if [[ ! -f "$elf" ]]; then
        echo "SKIP: $elf not found (not built yet)"
        return 0
    fi

    local size
    size=$(mem_footprint "$elf" "$base")
    if [[ -z "$size" || "$size" -lt 0 ]]; then
        echo "ERROR: Could not determine memory extent of $elf"
        return 1
    fi

    # Report the flat .bin size too, for context (it is what's loaded;
    # the gap between it and the memory extent is .bss).
    local bin_size="?"
    [[ -f "$bin" ]] && bin_size=$(stat -c%s "$bin" 2>/dev/null || stat -f%z "$bin" 2>/dev/null)

    local max_kb=$((max_size / 1024))
    local size_kb=$((size / 1024))
    local percent=$((size * 100 / max_size))

    if [[ "$size" -gt "$max_size" ]]; then
        echo "FAIL: $description"
        echo "      $name runtime memory extent (.bss-inclusive) is ${size}B" \
             "(${size_kb}KB), max is ${max_kb}KB (${percent}% of limit)"
        echo "      .bin file size is ${bin_size}B; the overflow is in .bss."
        echo "      This will cause memory overlap and VM crashes!"
        return 1
    elif [[ "$percent" -ge "$WARN_PCT" ]]; then
        echo "WARN: $description - ${size_kb}KB / ${max_kb}KB (${percent}%, .bin=${bin_size}B)"
        echo "      at/over ${WARN_PCT}% of its region; shrink it or raise the"
        echo "      memory layout in shared/src/lib.rs before it overflows."
        return 0
    else
        echo "OK:   $description - ${size_kb}KB / ${max_kb}KB (${percent}%, .bin=${bin_size}B)"
        return 0
    fi
}

echo "Checking guest binary runtime memory footprints against layout limits..."
echo ""

failed=0

# Check core binary
if ! check_size "core" "$CORE_BASE" "$CORE_MAX_SIZE" "core (0x10000-0x22000)"; then
    failed=1
fi

# Check operation binaries
for op in info copy check compare convert measure create rebase resize commit snapshot amend; do
    if ! check_size "$op" "$OPERATION_BASE" "$OPERATION_MAX_SIZE" "${op} (0x22000-0x80000)"; then
        failed=1
    fi
done

echo ""

if [[ "$failed" -eq 1 ]]; then
    echo "Binary size check FAILED - memory overlap will occur!"
    echo ""
    echo "To fix: reduce the binary's runtime footprint (.text/.rodata/.data/.bss)"
    echo "or adjust the memory layout in shared/src/lib.rs."
    exit 1
else
    echo "All binaries fit within their memory regions."
    exit 0
fi
