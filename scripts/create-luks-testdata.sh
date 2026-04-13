#!/bin/bash
# Create full LUKS test containers with inner formats.
#
# Requires: cryptsetup, qemu-img, losetup, root privileges
#           (or a user in the disk group with loop device access).
#
# These containers have real encrypted payloads and can be used
# for decryption testing (Phase 12c/12e). For header-only
# parsing tests, use create-luks-headers.py instead.
#
# Usage: sudo ./create-luks-testdata.sh <output_dir>

set -euo pipefail

PASSPHRASE='test-passphrase'

if [ $# -lt 1 ]; then
    echo "Usage: $0 <output_dir>" >&2
    exit 1
fi

OUTPUT_DIR="$1"
mkdir -p "$OUTPUT_DIR"

# Check for required tools
for cmd in cryptsetup qemu-img losetup dd; do
    if ! command -v "$cmd" &>/dev/null; then
        echo "Error: $cmd not found" >&2
        exit 1
    fi
done

if [ "$(id -u)" -ne 0 ]; then
    echo "Error: must run as root (cryptsetup needs it)" >&2
    exit 1
fi

TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT

create_luks_container() {
    local luks_version="$1"
    local inner_format="$2"
    local output_name="$3"
    local container_size_mb=16

    echo "Creating $output_name (LUKS v${luks_version}, inner: ${inner_format})..."

    local img="$TMPDIR/${output_name}"
    dd if=/dev/zero of="$img" bs=1M count=$container_size_mb \
        status=none

    # Format as LUKS
    echo -n "$PASSPHRASE" | cryptsetup luksFormat \
        --type "luks${luks_version}" \
        --key-file=- \
        --batch-mode \
        "$img"

    # Open the container
    local dm_name="instar-test-$$-${output_name%.img}"
    echo -n "$PASSPHRASE" | cryptsetup open \
        --type "luks${luks_version}" \
        --key-file=- \
        "$img" "$dm_name"

    # Write inner content
    case "$inner_format" in
        raw-gpt)
            # Create a small GPT-partitioned raw image and
            # write it into the LUKS container
            local inner_img="$TMPDIR/inner-gpt.img"
            dd if=/dev/zero of="$inner_img" bs=1M count=8 \
                status=none
            # Write a protective MBR + GPT header
            printf '\x00' | dd of="$inner_img" bs=1 \
                seek=446 count=1 conv=notrunc status=none
            # EFI signature at 512
            printf 'EFI PART' | dd of="$inner_img" bs=1 \
                seek=512 conv=notrunc status=none
            dd if="$inner_img" \
                of="/dev/mapper/$dm_name" bs=1M \
                status=none
            rm -f "$inner_img"
            ;;
        qcow2)
            local inner_img="$TMPDIR/inner.qcow2"
            qemu-img create -f qcow2 "$inner_img" 1G \
                >/dev/null 2>&1
            dd if="$inner_img" \
                of="/dev/mapper/$dm_name" bs=1M \
                status=none
            rm -f "$inner_img"
            ;;
    esac

    cryptsetup close "$dm_name"

    # Copy to output
    cp "$img" "$OUTPUT_DIR/${output_name}"
    echo "  Created: $OUTPUT_DIR/${output_name} ($(stat -c%s "$OUTPUT_DIR/${output_name}") bytes)"
}

# LUKS v1 containers
create_luks_container 1 raw-gpt luks-v1-raw-gpt.img
create_luks_container 1 qcow2 luks-v1-qcow2.img

# LUKS v2 containers
create_luks_container 2 raw-gpt luks-v2-raw-gpt.img

echo ""
echo "All LUKS test containers created in $OUTPUT_DIR"
echo "Passphrase for all containers: $PASSPHRASE"
