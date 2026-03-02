#!/usr/bin/env python3
"""Generate synthetic LUKS v1 and v2 header test images.

These headers have realistic field values for testing header
parsing (Phase 12b). They are NOT valid encrypted containers
(no actual key material or encrypted payload), so they cannot
be used for decryption testing (Phase 12c).

For full LUKS containers with inner formats, use
create-luks-testdata.sh instead (requires cryptsetup).
"""

import os
import struct
import sys


# LUKS v1 header constants
LUKS_MAGIC = b'LUKS\xba\xbe'
LUKS_V1_VERSION = 1
LUKS_V1_HEADER_SIZE = 592
LUKS_V1_KEY_SLOT_SIZE = 48
LUKS_V1_NUM_SLOTS = 8

# Key slot states
KEY_SLOT_ACTIVE = 0x00AC71F3
KEY_SLOT_INACTIVE = 0x0000DEAD


def pad_string(s, length):
    """Null-pad a string to a fixed length."""
    encoded = s.encode('ascii')
    if len(encoded) >= length:
        return encoded[:length]
    return encoded + b'\x00' * (length - len(encoded))


def build_luks_v1_header():
    """Build a realistic LUKS v1 header (592 bytes).

    Field layout:
      Offset  Size  Description
      0       6     Magic
      6       2     Version (1)
      8       32    Cipher name ("aes")
      40      32    Cipher mode ("xts-plain64")
      72      32    Hash spec ("sha256")
      104     4     Payload offset (sectors)
      108     4     Key bytes (master key length)
      112     20    MK digest (PBKDF2 verification hash)
      132     32    MK digest salt
      164     4     MK digest iterations
      168     36    UUID
      204     4     Padding
      208     384   Key slots (8 x 48 bytes)
    """
    header = bytearray(LUKS_V1_HEADER_SIZE)

    # Magic + version
    header[0:6] = LUKS_MAGIC
    struct.pack_into('>H', header, 6, LUKS_V1_VERSION)

    # Cipher name (32 bytes, null-padded)
    header[8:40] = pad_string('aes', 32)

    # Cipher mode (32 bytes, null-padded)
    header[40:72] = pad_string('xts-plain64', 32)

    # Hash spec (32 bytes, null-padded)
    header[72:104] = pad_string('sha256', 32)

    # Payload offset in 512-byte sectors (4096 = 2MB typical)
    struct.pack_into('>I', header, 104, 4096)

    # Key bytes (64 for AES-256-XTS: 2 x 32-byte keys)
    struct.pack_into('>I', header, 108, 64)

    # MK digest (20 bytes of deterministic "hash" for testing)
    header[112:132] = bytes(range(20))

    # MK digest salt (32 bytes of deterministic "salt")
    header[132:164] = bytes(range(32, 64))

    # MK digest iterations
    struct.pack_into('>I', header, 164, 123456)

    # UUID (36 bytes, null-padded)
    header[168:204] = pad_string(
        '12345678-1234-1234-1234-123456789abc', 36
    )

    # Key slot 0: active
    slot0_offset = 208
    struct.pack_into('>I', header, slot0_offset, KEY_SLOT_ACTIVE)
    struct.pack_into('>I', header, slot0_offset + 4, 234567)
    # Salt (32 bytes of deterministic data)
    header[slot0_offset + 8:slot0_offset + 40] = bytes(
        range(64, 96)
    )
    # Key material offset (sectors)
    struct.pack_into('>I', header, slot0_offset + 40, 8)
    # Stripes
    struct.pack_into('>I', header, slot0_offset + 44, 4000)

    # Key slots 1-7: inactive
    for i in range(1, LUKS_V1_NUM_SLOTS):
        slot_offset = 208 + i * LUKS_V1_KEY_SLOT_SIZE
        struct.pack_into(
            '>I', header, slot_offset, KEY_SLOT_INACTIVE
        )

    return bytes(header)


def build_luks_v2_header():
    """Build a LUKS v2 header with JSON metadata (16 KiB).

    LUKS v2 has a 4096-byte binary header followed by a JSON
    metadata area. For testing, we create both with realistic
    field values per the LUKS2 on-disk format spec v1.1.

    Binary header layout (4096 bytes):
      Offset  Size  Description
      0       6     Magic ("LUKS\\xba\\xbe")
      6       2     Version (2)
      8       8     Header size (binary + JSON, bytes)
      16      8     Sequence ID
      24      48    Label (null-padded ASCII)
      72      32    Checksum algorithm (null-padded)
      104     64    Salt
      168     40    UUID (null-terminated ASCII)
      208     48    Subsystem label (null-padded)
      256     8     Header offset
      264     184   Padding
      448     64    Checksum
      512     3584  Padding
    """
    # Total header = 16384 bytes (4096 binary + 12288 JSON)
    total_size = 16384
    header = bytearray(total_size)

    # Magic + version
    header[0:6] = LUKS_MAGIC
    struct.pack_into('>H', header, 6, 2)

    # Header size (uint64 big-endian) — total primary area
    struct.pack_into('>Q', header, 8, total_size)

    # Sequence ID
    struct.pack_into('>Q', header, 16, 1)

    # Label (48 bytes, null-padded, at offset 24)
    header[24:72] = pad_string('test-luks2-volume', 48)

    # Checksum algorithm (32 bytes, null-padded, at offset 72)
    header[72:104] = pad_string('sha256', 32)

    # Salt (64 bytes, at offset 104)
    header[104:168] = bytes(range(100, 164))

    # UUID (40 bytes, null-terminated, at offset 168)
    header[168:208] = pad_string(
        'abcdef01-2345-6789-abcd-ef0123456789', 40
    )

    # JSON metadata area starts at offset 4096 (after binary
    # header), null-terminated within the 12288-byte area.
    json_area = (
        '{\n'
        '  "config": {\n'
        '    "json_size": 12288\n'
        '  },\n'
        '  "keyslots": {\n'
        '    "0": {\n'
        '      "type": "luks2",\n'
        '      "key_size": 64,\n'
        '      "kdf": {\n'
        '        "type": "argon2id",\n'
        '        "time": 4,\n'
        '        "memory": 1048576,\n'
        '        "cpus": 4,\n'
        '        "salt": "'
        + 'aa' * 32
        + '"\n'
        '      },\n'
        '      "af": {\n'
        '        "type": "luks1",\n'
        '        "stripes": 4000,\n'
        '        "hash": "sha256"\n'
        '      },\n'
        '      "area": {\n'
        '        "type": "raw",\n'
        '        "offset": "32768",\n'
        '        "size": "258048",\n'
        '        "encryption": "aes-xts-plain64"\n'
        '      }\n'
        '    }\n'
        '  },\n'
        '  "segments": {\n'
        '    "0": {\n'
        '      "type": "crypt",\n'
        '      "offset": "4194304",\n'
        '      "size": "dynamic",\n'
        '      "iv_tweak": "0",\n'
        '      "encryption": "aes-xts-plain64",\n'
        '      "sector_size": 512\n'
        '    }\n'
        '  },\n'
        '  "digests": {\n'
        '    "0": {\n'
        '      "type": "pbkdf2",\n'
        '      "keyslots": ["0"],\n'
        '      "segments": ["0"],\n'
        '      "hash": "sha256",\n'
        '      "iterations": 123456,\n'
        '      "salt": "'
        + 'bb' * 32
        + '"\n'
        '      }\n'
        '  }\n'
        '}\n'
    )
    json_bytes = json_area.encode('utf-8')
    json_offset = 4096  # JSON area starts after binary header
    header[json_offset:json_offset + len(json_bytes)] = (
        json_bytes
    )

    return bytes(header)


def main():
    if len(sys.argv) < 2:
        print(
            f'Usage: {sys.argv[0]} <output_dir>',
            file=sys.stderr,
        )
        sys.exit(1)

    output_dir = sys.argv[1]
    os.makedirs(output_dir, exist_ok=True)

    # Generate LUKS v1 header
    v1_path = os.path.join(output_dir, 'luks-v1.luks')
    with open(v1_path, 'wb') as f:
        f.write(build_luks_v1_header())
    print(f'Created: {v1_path} ({LUKS_V1_HEADER_SIZE} bytes)')

    # Generate LUKS v2 header
    v2_path = os.path.join(output_dir, 'luks-v2.luks')
    v2_data = build_luks_v2_header()
    with open(v2_path, 'wb') as f:
        f.write(v2_data)
    print(f'Created: {v2_path} ({len(v2_data)} bytes)')


if __name__ == '__main__':
    main()
