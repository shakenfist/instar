#!/bin/bash
# Generate VMDK twoGbMaxExtentSparse test fixtures for instar integration tests.
#
# Usage:
#   ./scripts/create-vmdk-split-testdata.sh [output-dir]
#
# Default output: ../instar-testdata/custom/format-coverage/
#
# Environment:
#   QEMU_IMG              qemu-img to use. Defaults to the static 10.2.0 build
#                         under $INSTAR_TESTDATA_PATH (default ../instar-testdata).
#                         There is deliberately no fallback to the host's
#                         qemu-img: the descriptor and extent geometry vary
#                         between qemu versions, so the host must not be an
#                         input to a committed fixture.
#
# Creates four qemu-written twoGbMaxExtentSparse images:
#
#   vmdk-split-sparse-2049m          2 extents, 1 MiB tail
#   vmdk-split-sparse-5g             3 extents, 1 GiB tail
#   vmdk-split-sparse-5g-boundary    as above, with 128 KiB of 0xAB straddling
#                                    the first extent boundary
#   vmdk-split-sparse-33g            17 extents, 1 GiB tail
#
# Only split-sparse images are stored. A split-sparse extent is a small
# hole-bearing file (a few hundred KiB), but a split-flat extent is a
# full-length sparse file (2 GiB apparent each) and git-LFS stores holes as
# real bytes, so a split-flat fixture would cost its whole virtual size.
# Split-flat images must be built at test time instead.
#
# The descriptor's CID is random, so regenerating never reproduces the
# committed bytes exactly. Generate once and commit.

set -euo pipefail

OUTDIR="${1:-../instar-testdata/custom/format-coverage}"
TESTDATA="${INSTAR_TESTDATA_PATH:-../instar-testdata}"
QEMU_IMG="${QEMU_IMG:-$TESTDATA/qemu-img-binaries/x86_64/10.2.0/qemu-img}"

if [ ! -x "$QEMU_IMG" ]; then
    echo "ERROR: qemu-img is not an executable file: $QEMU_IMG" >&2
    echo "Set QEMU_IMG, or INSTAR_TESTDATA_PATH to a testdata checkout." >&2
    exit 1
fi

mkdir -p "$OUTDIR"

WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT

echo "Creating VMDK twoGbMaxExtentSparse test images in $OUTDIR"
echo "using $QEMU_IMG..."

# Remove a descriptor and its extents. Extent names are derived, not globbed:
# qemu names them <base>-s001.vmdk, <base>-s002.vmdk and so on, and a glob
# would also delete unrelated fixtures that share a prefix (the 5g glob would
# match the 5g-boundary files).
remove_image() {
    local base="$1"
    local count="$2"
    local i
    rm -f "$OUTDIR/$base.vmdk"
    for i in $(seq 1 "$count"); do
        rm -f "$OUTDIR/$base-$(printf 's%03d' "$i").vmdk"
    done
}

# Second argument is the extent count qemu produces: 2049M is a 2 GiB extent
# plus a 1 MiB tail, 5G is 2+2+1 GiB, 33G is sixteen full extents and a 1 GiB tail.
remove_image vmdk-split-sparse-2049m 2
remove_image vmdk-split-sparse-5g 3
remove_image vmdk-split-sparse-5g-boundary 3
remove_image vmdk-split-sparse-33g 17

# --- 2049M: the smallest non-multiple of 2 GiB ---
# The second extent is one grain-and-a-bit (2048 sectors, 1 MiB).
"$QEMU_IMG" create -f vmdk -o subformat=twoGbMaxExtentSparse \
    "$OUTDIR/vmdk-split-sparse-2049m.vmdk" 2049M

# --- 5G: the reference geometry ---
# Three extents of 4194304, 4194304 and 2097152 sectors.
"$QEMU_IMG" create -f vmdk -o subformat=twoGbMaxExtentSparse \
    "$OUTDIR/vmdk-split-sparse-5g.vmdk" 5G

# --- 5G with data across the first extent boundary ---
# The static qemu builds ship no qemu-io, so data cannot be written into a
# sparse extent after creation. Converting from a holey raw source does it
# in one step: 128 KiB of 0xAB starting 64 KiB below 2 GiB lands half in the
# first extent and half in the second, so a rotation bug shows as wrong
# bytes rather than just a wrong size. The raw source is 5 GiB apparent but
# almost entirely holes, and is removed on exit; it is written under
# TMPDIR, so set that if /tmp cannot hold a large sparse file.
#
# Note that convert does not write the same descriptor create does: it pads
# to a 512-byte sector with NULs, where create writes exactly the bytes it
# needs. That difference is part of what this fixture records.
python3 -c '
import sys
with open(sys.argv[1], "wb") as f:
    f.truncate(5 * 1024 * 1024 * 1024)
    f.seek(2 * 1024 * 1024 * 1024 - 64 * 1024)
    f.write(b"\xAB" * (128 * 1024))
' "$WORKDIR/boundary.raw"
"$QEMU_IMG" convert -f raw -O vmdk -o subformat=twoGbMaxExtentSparse \
    "$WORKDIR/boundary.raw" "$OUTDIR/vmdk-split-sparse-5g-boundary.vmdk"
rm -f "$WORKDIR/boundary.raw"

# --- 33G: past the 15-extent device-slot ceiling ---
# Sixteen full 2 GiB extents and a 1 GiB tail: 17 extents.
"$QEMU_IMG" create -f vmdk -o subformat=twoGbMaxExtentSparse \
    "$OUTDIR/vmdk-split-sparse-33g.vmdk" 33G

echo "Done."
ls -la "$OUTDIR"/vmdk-split-sparse-*
