#!/bin/bash
# Generate synthetic VHD test images for instar integration tests.
#
# Usage:
#   ./scripts/create-vhd-testdata.sh [output-dir] [audit-dir]
#
# Default output: ../instar-testdata/custom/format-coverage/
# Default audit output: ../instar-testdata/custom/audit/
#
# The adversarial parent-locator fixtures below go to the audit directory,
# which is where tests/manifest.json and docs/testing.md say they live; every
# other file goes to the output directory.
#
# Creates:
#   vhd-fixed.vhd         - 10 MiB fixed VHD (disk_type=2)
#   vhd-differencing.vhd  - Differencing VHD (disk_type=4), a type marker with
#                           no parent: qemu-img cannot create a differencing
#                           VHD, so a dynamic one is patched
#
# and three real differencing chains, each with the raw image it is intended
# to compose to:
#
#   vhd-diff-parent.vhd            - 16 MiB dynamic VHD, shared by both
#                                    children
#   vhd-diff-child-aligned.vhd     - differencing child, byte-aligned bitmap
#   vhd-diff-aligned-composed.raw  - the composition of those two
#   vhd-diff-child-mixed.vhd       - differencing child, mixed bitmap bytes
#   vhd-diff-mixed-composed.raw    - the composition of that child and the
#                                    parent
#   vhdx-diff-parent.vhdx          - 16 MiB dynamic VHDX, 1 MiB blocks
#   vhdx-diff-child.vhdx           - differencing child exercising all three
#                                    payload block states
#   vhdx-diff-composed.raw         - the composition of those two
#
# and six adversarial parent-locator fixtures, written to the AUDIT
# directory, each a well-formed differencing VHD that differs from
# vhd-diff-child-aligned.vhd only in its parent unicode name and locator table
# (instar-testdata docs/plans/PLAN-extra-coverage.md priority 7):
#
#   vhd-diff-locator-etc-passwd.vhd  - absolute /etc/passwd
#   vhd-diff-locator-dotdot.vhd      - relative ../../../etc/passwd
#   vhd-diff-locator-unc.vhd         - UNC \\attacker\share\probe
#   vhd-diff-locator-url.vhd         - http://attacker.example/probe
#   vhd-diff-locator-overlong.vhd    - a name filling the whole 512-byte field
#   vhd-diff-locator-conflicting.vhd - eight mutually disagreeing locators
#
# Priority 7 names these vhd-diff-parent-etc-passwd.vhd, -dotdot, -unc, -url
# and -conflicting. They are named vhd-diff-locator-* here because they are
# differencing CHILDREN with a hostile parent reference, and a set of children
# matching vhd-diff-parent* would trap anyone globbing for the real parent,
# vhd-diff-parent.vhd. The over-long fixture has no counterpart in priority 7.
#
# Those six carry hostile path strings as DATA. This script writes them and
# never opens, stats or resolves any of them, and they have no composed .raw
# sibling because there is no correct composition for a hostile parent
# reference.
#
# Reproducibility: every file here is byte-reproducible except the two VHDX
# files, where qemu-img generates fresh header, log and virtual-disk-id GUIDs
# that this script does not rewrite. The two VHDX files must therefore be
# regenerated and shipped as a pair: the child parent_linkage value binds to
# the parent DataWriteGuid, so a child paired with a differently generated
# parent will not resolve.
#
# Because they are not reproducible, the VHDX pair is OPT IN: it is skipped
# when both files already exist, so a run made to prove the VHD half is
# idempotent does not replace 24 MiB of committed LFS objects with
# functionally identical but byte-different ones. Pass REGEN_VHDX=1 to
# regenerate them, and commit both files when you do.
#
# Shape: these chains are deliberately qemu-shaped, not Hyper-V-shaped. The
# creator application is 'qem2' (see vhd_footer below for why that is load
# bearing) and vhd_geometry picks any exact CHS factorisation rather than the
# sectors-per-track values from {17, 31, 63, 255} that real VHD producers and
# qemu's own vpc geometry emit. Both are legal and both read back correctly,
# but a later phase must not treat these images as evidence about what
# Hyper-V writes.
#
# vhd-differencing.vhd is reproducible only because the patch step below pins
# the timestamp and unique id qemu-img randomises.

set -euo pipefail

OUTDIR="${1:-../instar-testdata/custom/format-coverage}"
AUDITDIR="${2:-../instar-testdata/custom/audit}"
mkdir -p "$OUTDIR" "$AUDITDIR"

echo "Creating VHD test images in $OUTDIR..."
echo "Creating adversarial parent-locator images in $AUDITDIR..."

# --- Fixed VHD (disk_type=2) ---
#
# Structure: raw data (10 MiB) + 512-byte footer at EOF.
# MBR signature at bytes 510-511 so instar detects as vpc.
# Recognizable 0xBE pattern at 1 MiB offset for content verification.

python3 -c '
import struct, sys, os

outdir = sys.argv[1]
disk_size = 10 * 1024 * 1024  # 10 MiB

def compute_vhd_geometry(size):
    """VPC/Hyper-V CHS geometry algorithm."""
    total_sectors = size // 512
    total_sectors = min(total_sectors, 65535 * 16 * 255)

    if total_sectors >= 65535 * 16 * 63:
        return (65535, 16, 255)

    if total_sectors >= 65535 * 3 * 17:
        spt = 255
        heads = 16
        cyls = total_sectors // (255 * 16)
        return (cyls, heads, spt)

    spt = 17
    cth = total_sectors // spt
    heads = max(4, (cth + 1023) // 1024)

    if cth >= heads * 1024 or heads > 16:
        spt = 31
        heads = 16
        cth = total_sectors // spt

    if cth >= heads * 1024:
        spt = 63
        heads = 16
        cth = total_sectors // spt

    cyls = cth // heads
    return (cyls, heads, spt)


def build_footer(disk_size, disk_type):
    """Build a 512-byte VHD footer."""
    cookie = b"conectix"
    features = 0x00000002  # FEATURES_RESERVED
    fmt_version = 0x00010000
    # Fixed: data_offset = 0xFFFFFFFFFFFFFFFF
    data_offset = 0xFFFFFFFFFFFFFFFF
    timestamp = 0
    # Deliberately NOT the marker instar itself writes. instar stamps
    # "qem2" so that qemu-img < 10.0 trusts current_size instead of
    # recomputing the size from CHS geometry, which can under-address it
    # and silently truncate the tail (docs/quirks.md, "unknown creator
    # apps under emulated qemu < 10.0"). This generator mimics a
    # third-party writer, so it keeps the unknown-creator marker on
    # purpose: these fixtures are how that read path stays exercised.
    # Do not "fix" this to qem2.
    #
    # NB: this whole block is inside python3 -c with single quotes, so
    # an apostrophe here terminates the shell string and breaks the
    # script. Keep the prose apostrophe-free.
    creator_app = b"imgo"
    creator_ver = 0x00010000
    creator_os = b"Wi2k"
    original_size = disk_size
    current_size = disk_size

    cyls, heads, spt = compute_vhd_geometry(disk_size)
    geometry = struct.pack(">HBB", cyls, heads, spt)

    uuid = b"\x01\x02\x03\x04\x05\x06\x07\x08"
    uuid += b"\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10"

    # Pack footer without checksum
    footer = bytearray(512)
    footer[0:8] = cookie
    struct.pack_into(">I", footer, 8, features)
    struct.pack_into(">I", footer, 12, fmt_version)
    struct.pack_into(">Q", footer, 16, data_offset)
    struct.pack_into(">I", footer, 24, timestamp)
    footer[28:32] = creator_app
    struct.pack_into(">I", footer, 32, creator_ver)
    footer[36:40] = creator_os
    struct.pack_into(">Q", footer, 40, original_size)
    struct.pack_into(">Q", footer, 48, current_size)
    footer[56:60] = geometry
    struct.pack_into(">I", footer, 60, disk_type)
    # checksum at offset 64, set to 0 for now
    footer[68:84] = uuid
    footer[84] = 0  # saved_state

    # Compute checksum: ones complement of sum of all bytes
    total = 0
    for b in footer:
        total = (total + b) & 0xFFFFFFFF
    checksum = (~total) & 0xFFFFFFFF
    struct.pack_into(">I", footer, 64, checksum)

    return bytes(footer)


# Build fixed VHD
path = os.path.join(outdir, "vhd-fixed.vhd")
with open(path, "wb") as f:
    # Write 10 MiB of raw data
    data = bytearray(disk_size)

    # MBR signature at bytes 510-511
    data[510] = 0x55
    data[511] = 0xAA

    # Recognizable pattern at 1 MiB
    offset_1m = 1024 * 1024
    for i in range(512):
        data[offset_1m + i] = 0xBE

    f.write(data)

    # Append 512-byte footer
    footer = build_footer(disk_size, 2)  # disk_type=2 (fixed)
    f.write(footer)

print(f"  Created {path} ({os.path.getsize(path)} bytes)")
' "$OUTDIR"

# --- Differencing VHD (disk_type=4) ---
#
# qemu-img does not support creating differencing VHDs directly.
# Strategy: create a dynamic VHD, then patch disk_type from 3 to 4
# in both the copy footer (sector 0) and the real footer (last 512
# bytes), recomputing checksums. This exercises DISK_TYPE_DIFFERENCING
# acceptance in VhdState::init().
#
# The same patch step also pins the footer timestamp and unique id.
# qemu-img create stamps a real creation time and a random uid, which
# made this the one fixture here that could not be regenerated
# byte-identically. The pinned values are the ones already in
# instar-testdata, so a regeneration reproduces the shipped image;
# two tests in tests/test_check_formats.py depend on that image.

echo "  Creating vhd-differencing.vhd..."
qemu-img create -f vpc -o subformat=dynamic \
    "$OUTDIR/vhd-differencing.vhd" 10M >/dev/null 2>&1

# Write some data so the BAT has allocated blocks
qemu-io -f vpc -c "write -P 0xCD 2097152 512" \
    "$OUTDIR/vhd-differencing.vhd" >/dev/null 2>&1

# Patch disk_type from 3 (dynamic) to 4 (differencing) in both footers,
# and pin the two fields qemu-img randomises, so the output is stable
python3 -c '
import struct, sys, os

path = sys.argv[1]

# The timestamp and unique id qemu-img wrote into the image that is already
# in instar-testdata. Pinning them is what makes this generator idempotent:
# qemu-img create stamps the current time at footer+24 and a fresh random
# uid at footer+68, so without this the fixture changes on every run. Do not
# update these values to "refresh" the fixture; two tests read the image
# these bytes describe.
PINNED_TIMESTAMP = 0x313FD2DB
PINNED_UID = bytes.fromhex("dc88a571f60a4517a1b9be9f24d573cf")

def patch_footer_at(data, offset):
    """Patch disk_type to 4, pin timestamp and uid, recompute the checksum."""
    # disk_type is at footer+60 (big-endian u32)
    struct.pack_into(">I", data, offset + 60, 4)
    # timestamp at footer+24 (big-endian u32), unique id at footer+68
    struct.pack_into(">I", data, offset + 24, PINNED_TIMESTAMP)
    data[offset + 68:offset + 84] = PINNED_UID
    # Zero out checksum field before recomputing
    struct.pack_into(">I", data, offset + 64, 0)
    # Compute ones-complement checksum over 512-byte footer
    total = 0
    for i in range(512):
        total = (total + data[offset + i]) & 0xFFFFFFFF
    checksum = (~total) & 0xFFFFFFFF
    struct.pack_into(">I", data, offset + 64, checksum)

with open(path, "r+b") as f:
    data = bytearray(f.read())

    # Patch copy footer at sector 0
    patch_footer_at(data, 0)

    # Patch real footer at last 512 bytes
    patch_footer_at(data, len(data) - 512)

    f.seek(0)
    f.write(data)

print(f"  Patched {path} to disk_type=4 ({os.path.getsize(path)} bytes)")
' "$OUTDIR/vhd-differencing.vhd"


# --- Differencing chains (real parent/child pairs) ---
#
# Three chains, each with the raw image it is intended to compose to:
#
#   vhd-diff-parent.vhd        dynamic VHD (disk_type=3), shared by both
#                              children
#   vhd-diff-child-aligned.vhd differencing VHD, byte-aligned sector bitmap
#   vhd-diff-child-mixed.vhd   differencing VHD, mixed sector bitmap bytes
#   vhdx-diff-parent.vhdx      dynamic VHDX, 1 MiB blocks
#   vhdx-diff-child.vhdx       differencing VHDX
#
# The structure facts encoded below were measured against Hyper-V produced
# images in docs/plans/PLAN-differencing-phase-01-pin.md; that plan section is
# the authority on every byte offset used here.

echo "  Creating differencing chains..."

python3 - "$OUTDIR" "$AUDITDIR" "${REGEN_VHDX:-0}" <<'PYTHON_DIFF'
"""Generate real VHD and VHDX differencing chains plus their compositions.

Structure facts encoded here, each measured against a Hyper-V produced image
from the log2timeline/dfvfs corpus rather than taken from the spec text.  See
"The structure pin" in docs/plans/PLAN-differencing-phase-01-pin.md.

  * VHD footer disk type is at offset 60, 4 == differencing.
  * The VHD dynamic header sits at footer.data_offset (512 here); the parent
    unique id is at header+40 (absolute 552), the parent timestamp at +56
    (568), the parent unicode name at +64 (576) and the eight 24 byte parent
    locator entries at +576 (1088).
  * The parent unicode name is UTF-16 BIG endian.  The parent locator platform
    data for W2ku/W2ru is UTF-16 LITTLE endian; MacX is UTF-8 and 'Mac ' is
    an opaque blob, so the encoding is keyed off the platform code (see
    vhd_locator_platform_data).
  * Parent locator platform_data_space is a BYTE count, not the sector count
    the Microsoft spec wording implies.
  * Both VHD checksums are the ones complement of the sum of the structure
    bytes with the checksum field zeroed.
  * The VHD per block sector bitmap is most significant bit first: virtual
    sector i of the block is bit (7 - i % 8) of byte i // 8.  A set bit means
    the sector lives in this file, a clear bit means read it from the parent.
  * VHDX has_parent is bit 1 (0x2) of the file parameters flags.
  * The VHDX parent locator metadata item is
    A8D35F2D-B30B-454D-ABF7-D3D84834AB0C with locator type
    B04AEFB7-D19E-4A81-B789-25B8E9445913; keys and values are UTF-16 LITTLE
    endian and are not NUL terminated.
  * The VHDX parent_linkage value is the parent DataWriteGuid rendered as a
    braced GUID string.
  * The VHDX sector bitmap is least significant bit first, the opposite of VHD.
"""

import os
import struct
import subprocess
import sys
import tempfile
import uuid

SECTOR = 512
IMAGE_SIZE = 16 * 1024 * 1024
IMAGE_SECTORS = IMAGE_SIZE // SECTOR                # 32768

VHD_BLOCK_SIZE = 2 * 1024 * 1024
VHD_SECTORS_PER_BLOCK = VHD_BLOCK_SIZE // SECTOR    # 4096

VHDX_BLOCK_SIZE = 1024 * 1024
VHDX_SECTORS_PER_BLOCK = VHDX_BLOCK_SIZE // SECTOR  # 2048

VHD_DISK_TYPE_DYNAMIC = 3
VHD_DISK_TYPE_DIFFERENCING = 4

# A fixed VHD timestamp so the VHD half of this generator is reproducible.
# 1757030400 is 2025-09-05T00:00:00Z; the VHD epoch is 2000-01-01T00:00:00Z.
VHD_EPOCH = 946684800
VHD_TIMESTAMP = 1757030400 - VHD_EPOCH

# --- content plan -----------------------------------------------------------
#
# VHD: 2 MiB blocks, so block b covers sectors [b * 4096, (b + 1) * 4096).
# Each child allocates blocks 0 and 2 only, and inside those blocks its sector
# bitmap claims only the sectors it actually wrote.  Everything else, including
# sectors inside blocks 0 and 2 that the child did not claim, must come from
# the parent.
#
# Two children share one parent.  The "aligned" child keeps every sector it
# claims in a bitmap byte of its own, with no parent owned sector in the same
# byte, so the chain composes exactly even through libvhdi defect A (an
# unmasked shift that makes every sector after a set bit in the same bitmap
# byte read as present in the child).  The "mixed" child deliberately shares a
# bitmap byte with parent owned sectors, which is what a real differencing disk
# looks like and what the parser must survive.
#
# The parent sector list is the union of the two per chain lists in the phase 1
# appendix, so that one parent file serves both children and each child still
# has a sector the parent also owns (8 for aligned, 1 for mixed) where the
# child must win.  Sector 1 is invisible to the aligned child (no bitmap bit is
# set in the byte covering sectors 0 to 7) and sector 8 is invisible to the
# mixed child (no bitmap bit is set in the byte covering sectors 8 to 15), so
# neither addition perturbs the other chain.
VHD_PARENT_SECTORS = [0, 1, 2, 8, 100, 4096, 5000, 28672, 32767]
VHD_CHILD_SECTORS_ALIGNED = [8, 200, 8192, 9000]
VHD_CHILD_SECTORS_MIXED = [1, 3, 200, 8192, 9000]

# VHDX: 1 MiB blocks, so block b covers sectors [b * 2048, (b + 1) * 2048).
#   block 0  PAYLOAD_BLOCK_PARTIALLY_PRESENT + a real sector bitmap block
#   block 3  PAYLOAD_BLOCK_FULLY_PRESENT     (shadows the parent completely)
#   others   PAYLOAD_BLOCK_NOT_PRESENT       (read from the parent)
VHDX_PARENT_SECTORS = [0, 5, 2048, 3000, 7000, 10240, 32767]
VHDX_CHILD_SECTORS = [1, 5, 6144, 6200]
VHDX_CHILD_BLOCKS_PARTIAL = [0]
VHDX_CHILD_BLOCKS_FULL = [3]

# Synthetic identifiers, so that the fixtures are reproducible and obviously
# not a real disk.  The VHD parent unique id is what a child repeats at
# absolute offset 552 and what libvhdi enforces when a parent is attached.
VHD_PARENT_UID = uuid.UUID("11111111-2222-3333-4444-555555555555").bytes
VHD_CHILD_ALIGNED_UID = uuid.UUID("66666666-7777-8888-9999-aaaaaaaaaaaa").bytes
VHD_CHILD_MIXED_UID = uuid.UUID("bbbbbbbb-cccc-dddd-eeee-ffffffffffff").bytes

# The locator paths are fabricated and reference nothing on any real
# filesystem.  The parent unicode name carries the relative path a resolver
# would follow; the W2ku entry carries a Windows shaped absolute path in the
# shape Hyper-V writes, so that a parser sees both locator flavours.
VHD_PARENT_BASENAME = "vhd-diff-parent.vhd"
VHDX_PARENT_RELATIVE = ".\\vhdx-diff-parent.vhdx"
VHDX_PARENT_ABSOLUTE = "C:\\instar-testdata\\vhdx-diff-parent.vhdx"

# Two entries on purpose, which is what Hyper-V writes.  instar's own emitter
# is specified to write exactly ONE entry, whichever platform code describes
# the path the user typed, because the guest has only that one string and
# fabricating the other would be worse than omitting it.  That rule is about
# the emitter; a fixture exists to feed the parser, and the parser has to
# handle a table with both flavours populated.  Do not "fix" these fixtures to
# match the emitter -- doing so would delete the only coverage of the
# two-entry case.
VHD_HAPPY_LOCATORS = [
    (b"W2ru", ".\\vhd-diff-parent.vhd"),
    (b"W2ku", "C:\\instar-testdata\\vhd-diff-parent.vhd"),
]

# --- adversarial parent locator fixtures ------------------------------------
#
# instar-testdata/docs/plans/PLAN-extra-coverage.md priority 7.  Each of these
# is the byte-aligned child with nothing changed but the parent unicode name
# and the parent locator table: the same footer, the same dynamic header
# geometry, the same BAT, the same allocated blocks and correct checksums
# throughout.  A parser that reaches the hostile path has therefore already
# passed every structural test, which is the entire point -- an image that
# fails at the header proves nothing about locator handling.
#
# THESE STRINGS ARE DATA.  This generator writes them and never opens, stats,
# resolves or otherwise touches them, and the fixtures must stay safe to hand
# to a parser on a machine where the paths they name exist.  Nothing here
# refers to a file outside the output directory.
#
# The over-long name is exactly 256 UTF-16 code units, which fills the
# 512-byte parent unicode name field at offset 576 completely and leaves no
# terminator: a reader that scans for a NUL runs straight on into the locator
# table at offset 1088.
OVERLONG_PARENT_NAME = (("/overlong-" + "a" * 40 + "/") * 8)[:252] + ".vhd"

# Eight entries that disagree with each other and with the parent unicode
# name, so that picking the first, the last, the first Windows entry or the
# first non-deprecated entry each yields a different parent.
#
# Which should win?  SPEC(VHD) fixes no precedence: it neither orders the
# entries nor says what to do when two carry the same platform code, so there
# is no spec-blessed answer and a parser that silently picks one is inventing
# policy.  Two things are defensible and both are worth asserting: a reader
# should select by platform code rather than by slot (entries 3 and 4 are the
# deprecated Wi2r/Wi2k codes and should lose to entries 1 and 2), and a table
# with two entries sharing a platform code and disagreeing (1 versus 7, 2
# versus 8) should be refused rather than resolved.  For reference, libvhdi
# ignores this table entirely and reads the parent unicode name at offset 576,
# which here names a ninth, different parent.
VHD_CONFLICTING_LOCATORS = [
    (b"W2ru", ".\\conflict-one.vhd"),
    (b"W2ku", "C:\\conflict\\two.vhd"),
    (b"Wi2r", ".\\conflict-three.vhd"),
    (b"Wi2k", "C:\\conflict\\four.vhd"),
    (b"MacX", "file:///conflict/five.vhd"),
    (b"Mac ", "conflict-six.vhd"),
    (b"W2ru", ".\\conflict-seven.vhd"),
    (b"W2ku", "/etc/passwd"),
]

def hostile_pair(path):
    """The happy-path locator table with a hostile string in both entries.

    Using the same two platform codes in the same order as
    VHD_HAPPY_LOCATORS keeps the file layout identical to
    vhd-diff-child-aligned.vhd, so each of these fixtures differs from the
    happy-path child only in its locator paths, its parent unicode name, its
    unique id and the two checksums those force.  It also means one of the two
    codes always disagrees with the shape of the path it carries, which is
    itself worth testing: a parser must not trust the platform code to
    describe the data.
    """
    return [(b"W2ru", path), (b"W2ku", path)]


# (filename, child unique id, parent unicode name, locator table).  Every one
# of these claims VHD_PARENT_UID, so the parent identity check a reader runs
# after resolving the path would also pass; only the path is hostile.
VHD_ADVERSARIAL_FIXTURES = [
    # A POSIX absolute path where the spec expects an absolute Windows path.
    # Resolving it reads a file the image chose.
    ("vhd-diff-locator-etc-passwd.vhd",
     "a0000001-0000-4000-8000-000000000001",
     "/etc/passwd",
     hostile_pair("/etc/passwd")),
    # Relative traversal out of the directory holding the child.
    ("vhd-diff-locator-dotdot.vhd",
     "a0000002-0000-4000-8000-000000000002",
     "../../../etc/passwd",
     hostile_pair("../../../etc/passwd")),
    # A UNC path: resolving it means a network fetch to a host the image
    # chose.
    ("vhd-diff-locator-unc.vhd",
     "a0000003-0000-4000-8000-000000000003",
     "\\\\attacker\\share\\probe",
     hostile_pair("\\\\attacker\\share\\probe")),
    # A URL.  The same class as the UNC fixture -- a parent reference that is
    # not a local file -- but over a protocol a resolver is more likely to
    # hand to a URL library than to open(2).  instar must resolve neither, and
    # this fixture is what proves it.
    ("vhd-diff-locator-url.vhd",
     "a0000006-0000-4000-8000-000000000006",
     "http://attacker.example/probe",
     hostile_pair("http://attacker.example/probe")),
    # The 512-byte parent name field filled to the last byte, with no
    # terminator, and locators whose data_length equals their data_space.
    ("vhd-diff-locator-overlong.vhd",
     "a0000004-0000-4000-8000-000000000004",
     OVERLONG_PARENT_NAME,
     hostile_pair(OVERLONG_PARENT_NAME)),
    # All eight slots populated and mutually contradictory.  This one cannot
    # keep the happy-path layout: eight locator data sectors push the BAT from
    # 2560 to 5632, which is a legitimate layout and exactly what a producer
    # writing eight locators would emit.
    ("vhd-diff-locator-conflicting.vhd",
     "a0000005-0000-4000-8000-000000000005",
     "conflict-parent-name.vhd",
     VHD_CONFLICTING_LOCATORS),
]


def marker(tag, n):
    """A 512 byte sector naming its origin and its sector number."""
    stamp = ("%s-sector-%06d." % (tag, n)).encode("ascii")
    return (stamp * (SECTOR // len(stamp) + 1))[:SECTOR]


def build_raw(sectors, tag, size=IMAGE_SIZE):
    data = bytearray(size)
    for n in sectors:
        data[n * SECTOR:(n + 1) * SECTOR] = marker(tag, n)
    return bytes(data)


# --- VHD --------------------------------------------------------------------

def vhd_checksum(buf, offset):
    tmp = bytearray(buf)
    tmp[offset:offset + 4] = b"\x00\x00\x00\x00"
    return (~sum(tmp)) & 0xFFFFFFFF


def vhd_geometry(total_sectors):
    """A CHS triple whose product is exactly total_sectors, for 16 MiB."""
    for heads in (16, 8, 4, 2, 1):
        for spt in (63, 32, 17, 16, 8):
            if total_sectors % (heads * spt) == 0:
                cyls = total_sectors // (heads * spt)
                if 0 < cyls <= 0xFFFF:
                    return cyls, heads, spt
    raise ValueError("no exact geometry for %d sectors" % total_sectors)


def vhd_footer(disk_type, size, unique_id, timestamp, data_offset=512):
    cyls, heads, spt = vhd_geometry(size // SECTOR)
    buf = bytearray(512)
    struct.pack_into(">8sIIQI4sI4sQQHBBI", buf, 0,
                     b"conectix",        # cookie
                     0x00000002,         # features: reserved bit
                     0x00010000,         # file format version 1.0
                     data_offset,        # data offset -> dynamic header
                     timestamp,
                     # qem2 is load bearing: without it every qemu before 10.0
                     # derives the size from the CHS geometry and can silently
                     # truncate the tail.  These chains are read by qemu-img in
                     # verification, so they carry it.  The fixed VHD above
                     # deliberately does not, for the opposite reason.
                     b"qem2",            # creator application
                     0x00010000,         # creator version
                     b"Wi2k",            # creator host OS
                     size,               # original size
                     size,               # current size
                     cyls, heads, spt,   # disk geometry
                     disk_type)
    buf[68:84] = unique_id
    buf[84] = 0                          # saved state
    struct.pack_into(">I", buf, 64, vhd_checksum(buf, 64))
    return bytes(buf)


def vhd_locator_platform_data(platform_code, text):
    """Encode one parent locator's platform data the way its code demands.

    SPEC(VHD) does not give every platform code the same encoding, and a
    fixture that pretends otherwise teaches a parser the wrong rule for
    exactly the codes it has no other example of:

      * W2ru / W2ku (and the deprecated Wi2r / Wi2k) carry a Windows path as
        UTF-16.  Hyper-V writes it little endian, which is the opposite of
        the parent unicode name at offset 576.
      * MacX carries a UTF-8 file:// URL.
      * 'Mac ' carries a Mac OS alias record, which is an opaque binary blob
        and not text in any encoding.

    The 'Mac ' blob below is a deliberate stand-in rather than a synthesised
    alias record: it starts with bytes that decode as neither UTF-8 nor
    UTF-16 so that a parser treating this field as a path is caught here,
    and it carries the fixture's name in ASCII afterwards only so a human
    reading a hex dump can tell which entry it is.
    """
    if platform_code == b"MacX":
        return text.encode("utf-8")
    if platform_code == b"Mac ":
        return b"\x00\x00\x00\x00\x00\x96\x00\x02" + text.encode("ascii")
    return text.encode("utf-16-le")


def vhd_locator_entry(platform_code, data_space, data_length, data_offset):
    return struct.pack(">4sIIIQ", platform_code, data_space, data_length, 0,
                       data_offset)


def vhd_dynamic_header(table_offset, max_entries, block_size,
                       parent_uid=b"\x00" * 16, parent_timestamp=0,
                       parent_name="", locators=()):
    buf = bytearray(1024)
    struct.pack_into(">8sQQIII", buf, 0,
                     b"cxsparse",
                     0xFFFFFFFFFFFFFFFF,   # next offset
                     table_offset,
                     0x00010000,           # header version 1.0
                     max_entries,
                     block_size)
    buf[40:56] = parent_uid
    struct.pack_into(">I", buf, 56, parent_timestamp)
    struct.pack_into(">I", buf, 60, 0)     # reserved
    name = parent_name.encode("utf-16-be")
    if len(name) > 512:
        raise ValueError("parent name too long")
    buf[64:64 + len(name)] = name
    for i, entry in enumerate(locators):
        buf[576 + i * 24:576 + (i + 1) * 24] = entry
    struct.pack_into(">I", buf, 36, vhd_checksum(buf, 36))
    return bytes(buf)


def vhd_sector_bitmap(sector_numbers, block_index):
    """MSB first per block bitmap, one 512 byte sector for 2 MiB blocks."""
    nbytes = VHD_SECTORS_PER_BLOCK // 8
    nbytes = ((nbytes + SECTOR - 1) // SECTOR) * SECTOR
    bitmap = bytearray(nbytes)
    first = block_index * VHD_SECTORS_PER_BLOCK
    for n in sector_numbers:
        if first <= n < first + VHD_SECTORS_PER_BLOCK:
            i = n - first
            bitmap[i // 8] |= 0x80 >> (i % 8)
    return bytes(bitmap)


def write_dynamic_vhd(path, content, unique_id, timestamp):
    """A plain dynamic VHD; every non-zero block of content is allocated."""
    nblocks = (len(content) + VHD_BLOCK_SIZE - 1) // VHD_BLOCK_SIZE
    bat_offset = 1536
    bat_bytes = ((nblocks * 4 + SECTOR - 1) // SECTOR) * SECTOR
    data_start = bat_offset + bat_bytes
    bitmap_bytes = len(vhd_sector_bitmap([], 0))

    bat = [0xFFFFFFFF] * nblocks
    blocks = []
    cursor = data_start
    for b in range(nblocks):
        chunk = content[b * VHD_BLOCK_SIZE:(b + 1) * VHD_BLOCK_SIZE]
        if not any(chunk):
            continue
        bat[b] = cursor // SECTOR
        blocks.append((cursor, b"\xff" * bitmap_bytes + chunk))
        cursor += bitmap_bytes + VHD_BLOCK_SIZE

    footer = vhd_footer(VHD_DISK_TYPE_DYNAMIC, len(content), unique_id,
                        timestamp)
    header = vhd_dynamic_header(bat_offset, nblocks, VHD_BLOCK_SIZE)

    with open(path, "wb") as fh:
        fh.write(footer)
        fh.write(header)
        fh.write(struct.pack(">%dI" % nblocks, *bat))
        fh.write(b"\x00" * (bat_bytes - nblocks * 4))
        for offset, payload in blocks:
            fh.seek(offset)
            fh.write(payload)
        fh.seek(cursor)
        fh.write(footer)


def write_differencing_vhd(path, child_sectors, size, unique_id, timestamp,
                           parent_uid, parent_name, locators):
    """A differencing VHD whose sector bitmaps claim only child_sectors.

    locators is a sequence of at most eight (platform_code, path) pairs.  Each
    gets one 512 byte sector of platform data, encoded according to its
    platform code by vhd_locator_platform_data, laid out in order from offset
    1536, and one entry in the eight entry table at absolute offset 1088.  The
    path strings are written verbatim and are never opened, stated or resolved
    by this generator.
    """
    nblocks = (size + VHD_BLOCK_SIZE - 1) // VHD_BLOCK_SIZE
    bitmap_bytes = len(vhd_sector_bitmap([], 0))
    if not 1 <= len(locators) <= 8:
        raise ValueError("a VHD dynamic header holds one to eight locators")

    # Layout: footer copy | dynamic header | locator data | BAT | blocks |
    # footer.
    loc_base = 1536
    bat_offset = loc_base + len(locators) * SECTOR
    bat_bytes = ((nblocks * 4 + SECTOR - 1) // SECTOR) * SECTOR
    data_start = bat_offset + bat_bytes

    blobs = []
    entries = []
    for i, (platform_code, text) in enumerate(locators):
        blob = vhd_locator_platform_data(platform_code, text)
        if len(blob) > SECTOR:
            raise ValueError("locator data does not fit in one sector")
        offset = loc_base + i * SECTOR
        blobs.append((offset, blob))
        # data_space is a byte count: that is what Hyper-V writes, despite the
        # Microsoft spec describing it as a sector count.
        entries.append(vhd_locator_entry(platform_code, SECTOR, len(blob),
                                         offset))

    touched = {}
    for n in child_sectors:
        touched.setdefault(n // VHD_SECTORS_PER_BLOCK, []).append(n)

    bat = [0xFFFFFFFF] * nblocks
    blocks = []
    cursor = data_start
    for b in sorted(touched):
        payload = bytearray(VHD_BLOCK_SIZE)
        first = b * VHD_SECTORS_PER_BLOCK
        for n in touched[b]:
            i = n - first
            payload[i * SECTOR:(i + 1) * SECTOR] = marker("CHILD", n)
        bat[b] = cursor // SECTOR
        blocks.append((cursor,
                       vhd_sector_bitmap(touched[b], b) + bytes(payload)))
        cursor += bitmap_bytes + VHD_BLOCK_SIZE

    footer = vhd_footer(VHD_DISK_TYPE_DIFFERENCING, size, unique_id, timestamp)
    header = vhd_dynamic_header(bat_offset, nblocks, VHD_BLOCK_SIZE,
                                parent_uid=parent_uid,
                                # Hyper-V writes zero here in both of its
                                # differencing VHDs; nothing reads the field.
                                parent_timestamp=0,
                                parent_name=parent_name,
                                locators=entries)

    with open(path, "wb") as fh:
        fh.write(footer)
        fh.write(header)
        for offset, blob in blobs:
            fh.seek(offset)
            fh.write(blob)
        fh.seek(bat_offset)
        fh.write(struct.pack(">%dI" % nblocks, *bat))
        fh.write(b"\x00" * (bat_bytes - nblocks * 4))
        for offset, payload in blocks:
            fh.seek(offset)
            fh.write(payload)
        fh.seek(cursor)
        fh.write(footer)


def vhd_composition(parent_sectors, child_sectors, size=IMAGE_SIZE):
    """The raw image a correct reader must produce for parent + child."""
    data = bytearray(build_raw(parent_sectors, "PARENT", size))
    for n in child_sectors:
        data[n * SECTOR:(n + 1) * SECTOR] = marker("CHILD", n)
    return bytes(data)


# --- VHDX -------------------------------------------------------------------

REGION_BAT = uuid.UUID("2DC27766-F623-4200-9D64-115E9BFD4A08")
REGION_METADATA = uuid.UUID("8B7CA206-4790-4B9A-B8FE-575F050F886E")
META_FILE_PARAMETERS = uuid.UUID("CAA16737-FA36-4D43-B3B6-33F0AA44E76B")
META_PARENT_LOCATOR = uuid.UUID("A8D35F2D-B30B-454D-ABF7-D3D84834AB0C")
PARENT_LOCATOR_TYPE = uuid.UUID("B04AEFB7-D19E-4A81-B789-25B8E9445913")

VHDX_BAT_NOT_PRESENT = 0
VHDX_BAT_FULLY_PRESENT = 6
VHDX_BAT_PARTIALLY_PRESENT = 7
VHDX_SB_PRESENT = 6

# Metadata item table entry flags.  SPEC(VHDX) gives the parent locator item
# IsUser=false, IsVirtualDisk=true, IsRequired=true, i.e. 0x6 -- the same
# shape as the four virtual-disk items qemu-img writes (VirtualDiskSize,
# Page83Data, LogicalSectorSize, PhysicalSectorSize).  File parameters is a
# file-scoped item and correctly carries 0x4 alone.
METADATA_FLAG_IS_VIRTUAL_DISK = 0x2
METADATA_FLAG_IS_REQUIRED = 0x4
METADATA_FLAGS_PARENT_LOCATOR = (METADATA_FLAG_IS_VIRTUAL_DISK
                                 | METADATA_FLAG_IS_REQUIRED)


def qemu_img(*args):
    subprocess.run(["qemu-img"] + list(args), check=True,
                   stdout=subprocess.PIPE, stderr=subprocess.STDOUT)


def vhdx_regions(data):
    out = {}
    off = 0x30000
    sig, _csum, count, _res = struct.unpack_from("<4sIII", data, off)
    assert sig == b"regi", sig
    for i in range(count):
        eo = off + 16 + i * 32
        guid = uuid.UUID(bytes_le=bytes(data[eo:eo + 16]))
        fo, ln, _req = struct.unpack_from("<QII", data, eo + 16)
        out[guid] = (fo, ln)
    return out


def vhdx_metadata_items(data, region_offset):
    sig, _res, count, _res2 = struct.unpack_from("<8sHHI", data, region_offset)
    assert sig == b"metadata", sig
    items = []
    for i in range(count):
        eo = region_offset + 32 + i * 32
        guid = uuid.UUID(bytes_le=bytes(data[eo:eo + 16]))
        ioff, ilen, flags, _res3 = struct.unpack_from("<IIII", data, eo + 16)
        items.append((guid, ioff, ilen, flags, eo))
    return count, items


def crc32c(data):
    """CRC-32C (Castagnoli), the checksum VHDX uses for its structures.

    Bitwise rather than table driven: this runs over two 4 KiB headers per
    image, so the table would cost more to read than it saves to run.
    Verified against the checksums qemu-img writes into both header copies.
    """
    crc = 0xFFFFFFFF
    for byte in data:
        crc ^= byte
        for _ in range(8):
            crc = (crc >> 1) ^ (0x82F63B78 if crc & 1 else 0)
    return crc ^ 0xFFFFFFFF


def vhdx_data_write_guid(data):
    """The DataWriteGuid of the header with the higher sequence number."""
    best = None
    for off in (0x10000, 0x20000):
        sig, csum, seq = struct.unpack_from("<4sIQ", data, off)
        if sig != b"head":
            continue
        # A torn header keeps its old sequence number but not its checksum, so
        # check the CRC before letting a higher sequence win.
        header = bytearray(data[off:off + 4096])
        struct.pack_into("<I", header, 4, 0)
        if crc32c(header) != csum:
            continue
        if best is None or seq > best[0]:
            best = (seq, uuid.UUID(bytes_le=data[off + 32:off + 48]))
    if best is None:
        raise ValueError("no valid VHDX header found in this image")
    return best[1]


def vhdx_parent_locator_item(parent_data_write_guid, relative_path,
                             absolute_path):
    """Serialise a VHDX parent locator metadata item.

    Header: 16 byte locator type GUID, 2 reserved, 2 key/value count.
    Then one 12 byte entry per pair: key offset, value offset, key length,
    value length, all offsets relative to the start of the item.
    Keys and values are UTF-16LE and are not NUL terminated.
    """
    # parent_linkage is rendered lowercase, which is what qemu and Python's
    # uuid produce; Hyper-V writes braced GUIDs uppercase.  SPEC(VHDX) fixes
    # no case, so this fixture deliberately exercises the lowercase form and
    # a reader must compare case-insensitively -- a case-sensitive comparison
    # calibrated against this file would pass here and fail on Hyper-V.
    pairs = [
        ("parent_linkage", "{%s}" % parent_data_write_guid),
        ("relative_path", relative_path),
        ("absolute_win32_path", absolute_path),
    ]
    header = struct.pack("<16sHH", PARENT_LOCATOR_TYPE.bytes_le, 0, len(pairs))
    entries = bytearray()
    blob = bytearray()
    base = len(header) + 12 * len(pairs)
    for key, value in pairs:
        kb = key.encode("utf-16-le")
        vb = value.encode("utf-16-le")
        koff = base + len(blob)
        blob += kb
        voff = base + len(blob)
        blob += vb
        entries += struct.pack("<IIHH", koff, voff, len(kb), len(vb))
    return bytes(header) + bytes(entries) + bytes(blob)


def vhdx_sector_bitmap_block(sector_numbers):
    """A 1 MiB VHDX sector bitmap block; least significant bit first."""
    bitmap = bytearray(1024 * 1024)
    for n in sector_numbers:
        bitmap[n // 8] |= 1 << (n % 8)
    return bytes(bitmap)


def patch_vhdx_child(path, parent_absolute, parent_relative,
                     parent_data_write_guid, partial_blocks, full_blocks,
                     child_sectors):
    with open(path, "rb") as fh:
        data = bytearray(fh.read())
    regions = vhdx_regions(data)
    meta_off, meta_len = regions[REGION_METADATA]
    bat_off, bat_len = regions[REGION_BAT]
    count, items = vhdx_metadata_items(data, meta_off)

    # 1. Set the HasParent bit in the file parameters item.
    fp = [it for it in items if it[0] == META_FILE_PARAMETERS]
    assert len(fp) == 1, "expected exactly one file parameters item"
    _guid, ioff, ilen, _flags, _eo = fp[0]
    block_size, fp_flags = struct.unpack_from("<II", data, meta_off + ioff)
    struct.pack_into("<II", data, meta_off + ioff, block_size, fp_flags | 0x2)

    # 2. Append a parent locator item after the last item data.
    end = max(ioff + ilen for _g, ioff, ilen, _f, _e in items)
    item_off = (end + 15) & ~15
    item = vhdx_parent_locator_item(parent_data_write_guid, parent_relative,
                                    parent_absolute)
    assert item_off + len(item) <= meta_len, "metadata region too small"
    data[meta_off + item_off:meta_off + item_off + len(item)] = item
    entry_off = meta_off + 32 + count * 32
    data[entry_off:entry_off + 16] = META_PARENT_LOCATOR.bytes_le
    struct.pack_into("<IIII", data, entry_off + 16,
                     item_off, len(item), METADATA_FLAGS_PARENT_LOCATOR, 0)
    struct.pack_into("<H", data, meta_off + 10, count + 1)

    # 3. Rewrite the BAT: only the blocks the child owns stay present.
    nblocks = (IMAGE_SIZE + block_size - 1) // block_size
    chunk_ratio = (0x800000 * SECTOR) // block_size
    # The VHDX BAT interleaves one sector-bitmap entry after every chunk_ratio
    # payload entries.  The flat b * 8 indexing below is only correct while
    # every block falls inside chunk 0; assert that rather than leaving a
    # silent wrong answer for whoever grows VHDX_BLOCK_SIZE or IMAGE_SIZE.
    assert nblocks <= chunk_ratio, (
        "flat BAT indexing needs every block in chunk 0: %d blocks, "
        "chunk ratio %d" % (nblocks, chunk_ratio))
    for b in range(nblocks):
        eo = bat_off + b * 8
        (entry,) = struct.unpack_from("<Q", data, eo)
        file_offset_mb = (entry >> 20) & 0xFFFFFFFFFFF
        if b in partial_blocks:
            state = VHDX_BAT_PARTIALLY_PRESENT
        elif b in full_blocks:
            state = VHDX_BAT_FULLY_PRESENT
        else:
            state = VHDX_BAT_NOT_PRESENT
            file_offset_mb = 0
        struct.pack_into("<Q", data, eo, (file_offset_mb << 20) | state)

    # 4. If any block is partially present, append a sector bitmap block and
    #    point the chunk sector bitmap BAT entry at it.
    if partial_blocks:
        claimed = []
        for n in child_sectors:
            if n // (block_size // SECTOR) in partial_blocks:
                claimed.append(n)
        sb_offset = (len(data) + 0xFFFFF) & ~0xFFFFF
        data.extend(b"\x00" * (sb_offset - len(data)))
        data.extend(vhdx_sector_bitmap_block(claimed))
        sb_index = chunk_ratio
        assert (sb_index + 1) * 8 <= bat_len, "BAT region too small"
        struct.pack_into("<Q", data, bat_off + sb_index * 8,
                         ((sb_offset // (1024 * 1024)) << 20)
                         | VHDX_SB_PRESENT)

    with open(path, "wb") as fh:
        fh.write(bytes(data))
    return block_size, chunk_ratio


def vhdx_composition(block_size):
    """The raw image a correct reader must produce for parent + child."""
    data = bytearray(IMAGE_SIZE)
    spb = block_size // SECTOR
    assert spb == VHDX_SECTORS_PER_BLOCK, "qemu-img ignored the block size"
    for n in range(IMAGE_SECTORS):
        b = n // spb
        if b in VHDX_CHILD_BLOCKS_FULL:
            # Fully present: the whole block comes from the child file, which
            # is zero everywhere the child did not write, so the parent is
            # shadowed even where it holds data.
            if n in VHDX_CHILD_SECTORS:
                data[n * SECTOR:(n + 1) * SECTOR] = marker("CHILD", n)
        elif b in VHDX_CHILD_BLOCKS_PARTIAL:
            if n in VHDX_CHILD_SECTORS:
                data[n * SECTOR:(n + 1) * SECTOR] = marker("CHILD", n)
            elif n in VHDX_PARENT_SECTORS:
                data[n * SECTOR:(n + 1) * SECTOR] = marker("PARENT", n)
        elif n in VHDX_PARENT_SECTORS:
            data[n * SECTOR:(n + 1) * SECTOR] = marker("PARENT", n)
    return bytes(data)


# --- driver -----------------------------------------------------------------

def main():
    outdir = os.path.abspath(sys.argv[1])
    auditdir = os.path.abspath(sys.argv[2])
    regen_vhdx = sys.argv[3] not in ("", "0")
    written = []
    audited = []

    def p(name):
        return os.path.join(outdir, name)

    def a(name):
        return os.path.join(auditdir, name)

    # ---------------- VHD ----------------
    write_dynamic_vhd(p("vhd-diff-parent.vhd"),
                      build_raw(VHD_PARENT_SECTORS, "PARENT"),
                      VHD_PARENT_UID, VHD_TIMESTAMP)
    written.append("vhd-diff-parent.vhd")

    for suffix, sectors, child_uid in (
            ("aligned", VHD_CHILD_SECTORS_ALIGNED, VHD_CHILD_ALIGNED_UID),
            ("mixed", VHD_CHILD_SECTORS_MIXED, VHD_CHILD_MIXED_UID)):
        child = "vhd-diff-child-%s.vhd" % suffix
        write_differencing_vhd(p(child), sectors, IMAGE_SIZE, child_uid,
                               VHD_TIMESTAMP, VHD_PARENT_UID,
                               parent_name=VHD_PARENT_BASENAME,
                               locators=VHD_HAPPY_LOCATORS)
        written.append(child)
        composed = "vhd-diff-%s-composed.raw" % suffix
        with open(p(composed), "wb") as fh:
            fh.write(vhd_composition(VHD_PARENT_SECTORS, sectors))
        written.append(composed)

    # ------- adversarial parent locators -------
    #
    # No composed .raw sibling for these: there is no correct composition for
    # a fixture whose parent reference is hostile, and shipping one would
    # invite a test to try to resolve it.  They exist for the parse layer.
    #
    # These go to the audit directory, not the format-coverage one: that is
    # where tests/manifest.json declares their path and where every other
    # adversarial generator writes.
    for name, child_uid, parent_name, locators in VHD_ADVERSARIAL_FIXTURES:
        write_differencing_vhd(a(name), VHD_CHILD_SECTORS_ALIGNED, IMAGE_SIZE,
                               uuid.UUID(child_uid).bytes, VHD_TIMESTAMP,
                               VHD_PARENT_UID, parent_name=parent_name,
                               locators=locators)
        audited.append(name)

    # ---------------- VHDX ----------------
    #
    # Opt in, because this half is not reproducible: qemu-img stamps fresh
    # header, log and virtual-disk-id GUIDs on every run, so regenerating
    # rewrites both committed LFS objects for no behavioural change.  The
    # patch step below is also not idempotent -- it appends a parent locator
    # metadata item -- so the guard covers the convert and the patch as one
    # unit rather than only the convert.
    vhdx_names = ("vhdx-diff-parent.vhdx", "vhdx-diff-child.vhdx")
    skip_vhdx = (not regen_vhdx
                 and all(os.path.exists(p(n)) for n in vhdx_names))
    if skip_vhdx:
        print("  Skipping the VHDX pair: both files exist and they are not "
              "byte-reproducible.  Pass REGEN_VHDX=1 to rebuild them.")
        # The composed .raw is reproducible even though the pair is not, so it
        # is still written: it is derived from the block size this script asks
        # qemu-img for, which the assert in vhdx_composition checks was
        # honoured when the pair was generated.
        block_size = VHDX_BLOCK_SIZE
    else:
        block_size = write_vhdx_pair(p, written)

    with open(p("vhdx-diff-composed.raw"), "wb") as fh:
        fh.write(vhdx_composition(block_size))
    written.append("vhdx-diff-composed.raw")

    for name in written:
        print("  Created %s (%d bytes)" % (p(name), os.path.getsize(p(name))))
    for name in audited:
        print("  Created %s (%d bytes)" % (a(name), os.path.getsize(a(name))))
    return 0


def write_vhdx_pair(p, written):
    """Convert and patch the VHDX parent/child pair; return the block size."""
    for name in ("vhdx-diff-parent.vhdx", "vhdx-diff-child.vhdx"):
        if os.path.exists(p(name)):
            os.unlink(p(name))

    with tempfile.TemporaryDirectory() as tmp:
        parent_src = os.path.join(tmp, "parent.raw")
        child_src = os.path.join(tmp, "child.raw")
        with open(parent_src, "wb") as fh:
            fh.write(build_raw(VHDX_PARENT_SECTORS, "PARENT"))
        with open(child_src, "wb") as fh:
            fh.write(build_raw(VHDX_CHILD_SECTORS, "CHILD"))
        opts = "block_size=%d,log_size=1M" % VHDX_BLOCK_SIZE
        qemu_img("convert", "-f", "raw", "-O", "vhdx", "-o", opts,
                 parent_src, p("vhdx-diff-parent.vhdx"))
        qemu_img("convert", "-f", "raw", "-O", "vhdx", "-o", opts,
                 child_src, p("vhdx-diff-child.vhdx"))
    written.append("vhdx-diff-parent.vhdx")
    written.append("vhdx-diff-child.vhdx")

    with open(p("vhdx-diff-parent.vhdx"), "rb") as fh:
        parent_dwg = vhdx_data_write_guid(fh.read())
    block_size, _chunk_ratio = patch_vhdx_child(
        p("vhdx-diff-child.vhdx"),
        parent_absolute=VHDX_PARENT_ABSOLUTE,
        parent_relative=VHDX_PARENT_RELATIVE,
        parent_data_write_guid=parent_dwg,
        partial_blocks=set(VHDX_CHILD_BLOCKS_PARTIAL),
        full_blocks=set(VHDX_CHILD_BLOCKS_FULL),
        child_sectors=VHDX_CHILD_SECTORS)

    return block_size


if __name__ == "__main__":
    sys.exit(main())
PYTHON_DIFF

echo "Done. Verify with: qemu-img info $OUTDIR/vhd-fixed.vhd"
