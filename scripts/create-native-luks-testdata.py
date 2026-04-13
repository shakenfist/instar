#!/usr/bin/env python3
"""Create LUKS v1 and v2 test images with known encrypted content.

This script builds complete LUKS containers without requiring
cryptsetup or root privileges. It creates the headers, derives key
slots using PBKDF2 (v1) or Argon2id (v2), AFsplitter-encodes the
master key, and encrypts known plaintext data using AES-XTS-plain64.

The resulting images can be used to test instar's native LUKS decryption.

Usage: python3 create-native-luks-testdata.py <output_dir>

Dependencies: cryptography, argon2-cffi (for v2 images)
"""

import base64
import hashlib
import json
import os
import struct
import sys

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


PASSPHRASE = b'test-passphrase'
SECTOR_SIZE = 512

# LUKS v1 header layout
LUKS_MAGIC = b'LUKS\xba\xbe'
LUKS_VERSION = 1
CIPHER_NAME = b'aes'
CIPHER_MODE = b'xts-plain64'
HASH_SPEC = b'sha256'
KEY_BYTES = 64  # AES-256-XTS = two 256-bit keys
PAYLOAD_OFFSET_SECTORS = 4096  # 2MB header area
STRIPES = 4000
SLOT_ITERATIONS = 1000  # Low for fast testing
MK_DIGEST_ITERATIONS = 1000  # Low for fast testing

# Inner content: 8MB of known patterns
INNER_SIZE = 8 * 1024 * 1024
TOTAL_SIZE = PAYLOAD_OFFSET_SECTORS * SECTOR_SIZE + INNER_SIZE


def pbkdf2_sha256(password, salt, iterations, dklen):
    return hashlib.pbkdf2_hmac('sha256', password, salt, iterations, dklen=dklen)


def af_diffuse_sha256(data, key_bytes):
    """AFsplitter diffuse function using SHA-256."""
    digest_size = 32
    result = bytearray(data)
    full_blocks = key_bytes // digest_size
    remainder = key_bytes % digest_size

    for i in range(full_blocks):
        offset = i * digest_size
        block_num = struct.pack('>I', i)
        h = hashlib.sha256()
        h.update(block_num)
        h.update(result[offset:offset + digest_size])
        result[offset:offset + digest_size] = h.digest()

    if remainder > 0:
        offset = full_blocks * digest_size
        block_num = struct.pack('>I', full_blocks)
        h = hashlib.sha256()
        h.update(block_num)
        h.update(result[offset:offset + remainder])
        result[offset:offset + remainder] = h.digest()[:remainder]

    return bytes(result)


def af_split(master_key, key_bytes, stripes):
    """AFsplitter split: split master key into stripes.

    This is the inverse of the merge operation used during
    key recovery. We generate random stripes and compute the
    final stripe such that merge(stripes) = master_key.
    """
    # Generate random stripes for all but the last
    material = bytearray(key_bytes * stripes)
    for i in range(stripes - 1):
        stripe = os.urandom(key_bytes)
        material[i * key_bytes:(i + 1) * key_bytes] = stripe

    # Compute the running XOR + diffuse for stripes 0..N-2
    d = bytearray(key_bytes)
    d[:] = material[0:key_bytes]
    for i in range(1, stripes - 1):
        d = bytearray(af_diffuse_sha256(bytes(d), key_bytes))
        stripe_offset = i * key_bytes
        for j in range(key_bytes):
            d[j] ^= material[stripe_offset + j]

    # Diffuse one more time, then XOR with master key to get final stripe
    d = bytearray(af_diffuse_sha256(bytes(d), key_bytes))
    final_stripe = bytearray(key_bytes)
    for j in range(key_bytes):
        final_stripe[j] = d[j] ^ master_key[j]
    material[(stripes - 1) * key_bytes:stripes * key_bytes] = final_stripe

    return bytes(material)


def aes_xts_encrypt(key, data, sector_size, first_sector):
    """Encrypt data using AES-XTS with plain64 IV generation."""
    result = bytearray()
    num_sectors = len(data) // sector_size

    for i in range(num_sectors):
        sector_num = first_sector + i
        # plain64 IV: sector number as little-endian 16-byte value
        tweak = struct.pack('<QQ', sector_num, 0)
        cipher = Cipher(algorithms.AES(key), modes.XTS(tweak))
        encryptor = cipher.encryptor()
        sector_data = data[i * sector_size:(i + 1) * sector_size]
        result.extend(encryptor.update(sector_data) + encryptor.finalize())

    return bytes(result)


def aes_xts_decrypt(key, data, sector_size, first_sector):
    """Decrypt data using AES-XTS with plain64 IV generation."""
    result = bytearray()
    num_sectors = len(data) // sector_size

    for i in range(num_sectors):
        sector_num = first_sector + i
        tweak = struct.pack('<QQ', sector_num, 0)
        cipher = Cipher(algorithms.AES(key), modes.XTS(tweak))
        decryptor = cipher.decryptor()
        sector_data = data[i * sector_size:(i + 1) * sector_size]
        result.extend(decryptor.update(sector_data) + decryptor.finalize())

    return bytes(result)


def create_luks_v1_image(output_path):
    """Create a complete LUKS v1 image with known encrypted content."""
    # Generate random master key
    master_key = os.urandom(KEY_BYTES)

    # Generate random salts
    mk_digest_salt = os.urandom(32)
    slot_salt = os.urandom(32)

    # Compute master key digest for verification
    mk_digest = pbkdf2_sha256(master_key, mk_digest_salt, MK_DIGEST_ITERATIONS, 20)

    # Build LUKS v1 header (592 bytes)
    header = bytearray(PAYLOAD_OFFSET_SECTORS * SECTOR_SIZE)

    # Magic + version
    header[0:6] = LUKS_MAGIC
    struct.pack_into('>H', header, 6, LUKS_VERSION)

    # Cipher name (32 bytes, null-padded)
    header[8:8 + len(CIPHER_NAME)] = CIPHER_NAME

    # Cipher mode (32 bytes, null-padded)
    header[40:40 + len(CIPHER_MODE)] = CIPHER_MODE

    # Hash spec (32 bytes, null-padded)
    header[72:72 + len(HASH_SPEC)] = HASH_SPEC

    # Payload offset (sectors)
    struct.pack_into('>I', header, 104, PAYLOAD_OFFSET_SECTORS)

    # Key bytes
    struct.pack_into('>I', header, 108, KEY_BYTES)

    # Master key digest (20 bytes)
    header[112:132] = mk_digest

    # Master key digest salt (32 bytes)
    header[132:164] = mk_digest_salt

    # Master key digest iterations
    struct.pack_into('>I', header, 164, MK_DIGEST_ITERATIONS)

    # UUID (40 bytes, null-padded)
    uuid = b'deadbeef-1234-5678-9abc-def012345678'
    header[168:168 + len(uuid)] = uuid

    # Key slot 0 (active)
    slot_base = 208
    struct.pack_into('>I', header, slot_base, 0x00AC71F3)  # ACTIVE
    struct.pack_into('>I', header, slot_base + 4, SLOT_ITERATIONS)
    header[slot_base + 8:slot_base + 40] = slot_salt
    km_offset_sectors = 8  # Key material starts at sector 8
    struct.pack_into('>I', header, slot_base + 40, km_offset_sectors)
    struct.pack_into('>I', header, slot_base + 44, STRIPES)

    # Key slots 1-7 (dead)
    for i in range(1, 8):
        base = 208 + i * 48
        struct.pack_into('>I', header, base, 0x0000DEAD)

    # AFsplit the master key
    km_material = af_split(master_key, KEY_BYTES, STRIPES)

    # Derive the split key from passphrase
    derived_key = pbkdf2_sha256(PASSPHRASE, slot_salt, SLOT_ITERATIONS, KEY_BYTES)

    # AES-XTS encrypt the key material
    encrypted_km = aes_xts_encrypt(derived_key, km_material, SECTOR_SIZE, 0)

    # Write key material at km_offset
    km_byte_offset = km_offset_sectors * SECTOR_SIZE
    header[km_byte_offset:km_byte_offset + len(encrypted_km)] = encrypted_km

    # Create inner content (plaintext)
    # Sector 0: protective MBR signature
    inner = bytearray(INNER_SIZE)
    # Write 0xAA at regular offsets for easy pattern detection
    inner[0:8] = b'\xaa' * 8
    # MBR signature at end of first sector
    inner[510] = 0x55
    inner[511] = 0xAA
    # EFI PART at sector 1
    inner[512:520] = b'EFI PART'
    # Fill some sectors with recognizable patterns
    for i in range(4, 64):
        offset = i * SECTOR_SIZE
        inner[offset:offset + 8] = struct.pack('<Q', i)  # sector number
        inner[offset + 8:offset + SECTOR_SIZE] = bytes([i & 0xFF]) * (SECTOR_SIZE - 8)

    # Encrypt inner content using AES-XTS with plain64 IV
    # For native LUKS, IV starts at sector 0 of the payload
    encrypted_payload = aes_xts_encrypt(master_key, bytes(inner), SECTOR_SIZE, 0)

    # Write the complete image
    with open(output_path, 'wb') as f:
        f.write(bytes(header))
        f.write(encrypted_payload)

    # Verify by decrypting sector 0 and checking
    decrypted = aes_xts_decrypt(master_key, encrypted_payload[:SECTOR_SIZE], SECTOR_SIZE, 0)
    assert decrypted[:8] == b'\xaa' * 8, f'Self-test failed: {decrypted[:8].hex()}'
    assert decrypted[510:512] == b'\x55\xaa', 'Self-test failed: no MBR signature'

    decrypted_s1 = aes_xts_decrypt(master_key, encrypted_payload[SECTOR_SIZE:2 * SECTOR_SIZE], SECTOR_SIZE, 1)
    assert decrypted_s1[:8] == b'EFI PART', f'Self-test failed: no EFI PART at sector 1, got {decrypted_s1[:8].hex()}'

    # Also verify key derivation round-trip
    dk_verify = pbkdf2_sha256(PASSPHRASE, slot_salt, SLOT_ITERATIONS, KEY_BYTES)
    km_decrypted = aes_xts_decrypt(dk_verify, encrypted_km, SECTOR_SIZE, 0)

    # AF merge
    d = bytearray(km_decrypted[:KEY_BYTES])
    for i in range(1, STRIPES):
        d = bytearray(af_diffuse_sha256(bytes(d), KEY_BYTES))
        stripe_offset = i * KEY_BYTES
        for j in range(KEY_BYTES):
            d[j] ^= km_decrypted[stripe_offset + j]

    assert bytes(d) == master_key, 'Self-test failed: key derivation round-trip'

    # Verify master key digest
    digest_verify = pbkdf2_sha256(master_key, mk_digest_salt, MK_DIGEST_ITERATIONS, 20)
    assert digest_verify == mk_digest, 'Self-test failed: master key digest mismatch'

    print(f'Created {output_path} ({os.path.getsize(output_path)} bytes)')
    print(f'  Cipher: aes-xts-plain64, key_bytes: {KEY_BYTES}')
    print(f'  Payload offset: {PAYLOAD_OFFSET_SECTORS} sectors ({PAYLOAD_OFFSET_SECTORS * 512} bytes)')
    print(f'  Inner size: {INNER_SIZE} bytes')
    print(f'  Passphrase: {PASSPHRASE.decode()}')
    print(f'  Slot iterations: {SLOT_ITERATIONS}')
    print(f'  MK digest iterations: {MK_DIGEST_ITERATIONS}')
    print(f'  Master key (hex): {master_key.hex()}')
    print(f'  Self-test: PASSED')

    # Write the expected raw inner content for comparison
    raw_path = output_path.replace('.img', '-inner.raw')
    with open(raw_path, 'wb') as f:
        f.write(bytes(inner))
    print(f'  Expected inner content: {raw_path}')


def create_luks_v2_image(output_path):
    """Create a complete LUKS v2 image with known encrypted content.

    Uses Argon2id KDF with very low parameters for fast testing.
    """
    from argon2.low_level import hash_secret_raw, Type

    ARGON2_MEMORY = 8192     # 8 MiB (low for fast testing)
    ARGON2_TIME = 1          # 1 iteration
    ARGON2_PARALLELISM = 1   # 1 thread

    # Key material placement: binary header (4096) + JSON area (16384) = 20480
    KM_BYTE_OFFSET = 20480
    KM_TOTAL_BYTES = KEY_BYTES * STRIPES  # 64 * 4000 = 256000

    # Payload must start AFTER key material area ends.
    # Round up to 65536 (max sector size) so the total image size is
    # sector-aligned and avoids rounding artifacts in device capacity.
    PAYLOAD_OFFSET_BYTES = ((KM_BYTE_OFFSET + KM_TOTAL_BYTES + 65535) // 65536) * 65536  # 327680
    PAYLOAD_OFFSET_SECTORS = PAYLOAD_OFFSET_BYTES // SECTOR_SIZE

    # Generate random master key and salts
    master_key = os.urandom(KEY_BYTES)
    slot_salt = os.urandom(32)
    mk_digest_salt = os.urandom(32)

    # Derive the split key from passphrase using Argon2id
    derived_key = hash_secret_raw(
        PASSPHRASE,
        slot_salt,
        time_cost=ARGON2_TIME,
        memory_cost=ARGON2_MEMORY,
        parallelism=ARGON2_PARALLELISM,
        hash_len=KEY_BYTES,
        type=Type.ID,
    )

    # AFsplit the master key
    km_material = af_split(master_key, KEY_BYTES, STRIPES)

    # AES-XTS encrypt the key material
    encrypted_km = aes_xts_encrypt(derived_key, km_material, SECTOR_SIZE, 0)

    # Compute master key digest for verification (LUKS v2 uses PBKDF2
    # for digest even with Argon2id KDF)
    mk_digest = pbkdf2_sha256(master_key, mk_digest_salt, MK_DIGEST_ITERATIONS, 32)

    # Key material placement uses constants defined above
    km_byte_offset = KM_BYTE_OFFSET
    km_total_bytes = len(encrypted_km)

    # Build LUKS v2 binary header (4096 bytes)
    binary_header = bytearray(4096)
    binary_header[0:6] = LUKS_MAGIC
    struct.pack_into('>H', binary_header, 6, 2)  # version = 2
    # Header size (u64 at offset 8)
    struct.pack_into('>Q', binary_header, 8, 16384)  # hdr_size
    # Sequence ID (u64 at offset 16)
    struct.pack_into('>Q', binary_header, 16, 1)
    # Label (48 bytes at offset 24) - leave empty
    # Checksum algorithm (32 bytes at offset 72)
    binary_header[72:78] = b'sha256'
    # Salt (64 bytes at offset 104) - for header integrity
    binary_header[104:136] = os.urandom(32)
    # UUID (40 bytes at offset 168)
    uuid = b'abcdef01-2345-6789-abcd-ef0123456789'
    binary_header[168:168 + len(uuid)] = uuid

    # Build JSON metadata area
    json_metadata = {
        'keyslots': {
            '0': {
                'type': 'luks2',
                'key_size': KEY_BYTES,
                'af': {
                    'type': 'luks1',
                    'stripes': STRIPES,
                    'hash': 'sha256',
                },
                'area': {
                    'type': 'raw',
                    'offset': str(km_byte_offset),
                    'size': str(km_total_bytes),
                    'encryption': 'aes-xts-plain64',
                    'key_size': KEY_BYTES,
                },
                'kdf': {
                    'type': 'argon2id',
                    'time': ARGON2_TIME,
                    'memory': ARGON2_MEMORY,
                    'cpus': ARGON2_PARALLELISM,
                    'salt': base64.b64encode(slot_salt).decode(),
                },
            },
        },
        'tokens': {},
        'segments': {
            '0': {
                'type': 'crypt',
                'offset': str(PAYLOAD_OFFSET_BYTES),
                'size': 'dynamic',
                'iv_tweak': '0',
                'encryption': 'aes-xts-plain64',
                'sector_size': SECTOR_SIZE,
            },
        },
        'digests': {
            '0': {
                'type': 'pbkdf2',
                'keyslots': ['0'],
                'segments': ['0'],
                'hash': 'sha256',
                'iterations': MK_DIGEST_ITERATIONS,
                'salt': base64.b64encode(mk_digest_salt).decode(),
                'digest': base64.b64encode(mk_digest).decode(),
            },
        },
        'config': {
            'json_size': '12288',
            'keyslots_size': '16744448',
        },
    }

    json_bytes = json.dumps(json_metadata, separators=(',', ':')).encode()

    # Build the complete image
    image = bytearray(PAYLOAD_OFFSET_BYTES + INNER_SIZE)

    # Write binary header
    image[0:4096] = binary_header

    # Write JSON metadata (starts at offset 4096)
    image[4096:4096 + len(json_bytes)] = json_bytes
    # Null-terminate the JSON
    if 4096 + len(json_bytes) < km_byte_offset:
        image[4096 + len(json_bytes)] = 0

    # Write encrypted key material
    image[km_byte_offset:km_byte_offset + km_total_bytes] = encrypted_km

    # Create inner content (plaintext) — same pattern as v1
    inner = bytearray(INNER_SIZE)
    inner[0:8] = b'\xaa' * 8
    inner[510] = 0x55
    inner[511] = 0xAA
    inner[512:520] = b'EFI PART'
    for i in range(4, 64):
        offset = i * SECTOR_SIZE
        inner[offset:offset + 8] = struct.pack('<Q', i)
        inner[offset + 8:offset + SECTOR_SIZE] = bytes([i & 0xFF]) * (SECTOR_SIZE - 8)

    # Encrypt inner content
    encrypted_payload = aes_xts_encrypt(master_key, bytes(inner), SECTOR_SIZE, 0)
    image[PAYLOAD_OFFSET_BYTES:PAYLOAD_OFFSET_BYTES + INNER_SIZE] = encrypted_payload

    # Self-test: verify decryption works
    decrypted = aes_xts_decrypt(master_key, encrypted_payload[:SECTOR_SIZE], SECTOR_SIZE, 0)
    assert decrypted[:8] == b'\xaa' * 8, f'Self-test failed: {decrypted[:8].hex()}'
    assert decrypted[510:512] == b'\x55\xaa', 'Self-test failed: no MBR signature'

    # Verify key derivation round-trip
    dk_verify = hash_secret_raw(
        PASSPHRASE,
        slot_salt,
        time_cost=ARGON2_TIME,
        memory_cost=ARGON2_MEMORY,
        parallelism=ARGON2_PARALLELISM,
        hash_len=KEY_BYTES,
        type=Type.ID,
    )
    km_decrypted = aes_xts_decrypt(dk_verify, encrypted_km, SECTOR_SIZE, 0)

    # AF merge
    d = bytearray(km_decrypted[:KEY_BYTES])
    for i in range(1, STRIPES):
        d = bytearray(af_diffuse_sha256(bytes(d), KEY_BYTES))
        stripe_offset = i * KEY_BYTES
        for j in range(KEY_BYTES):
            d[j] ^= km_decrypted[stripe_offset + j]

    assert bytes(d) == master_key, 'Self-test failed: key derivation round-trip'

    # Verify master key digest
    digest_verify = pbkdf2_sha256(master_key, mk_digest_salt, MK_DIGEST_ITERATIONS, 32)
    assert digest_verify == mk_digest, 'Self-test failed: master key digest mismatch'

    with open(output_path, 'wb') as f:
        f.write(bytes(image))

    print(f'Created {output_path} ({os.path.getsize(output_path)} bytes)')
    print(f'  LUKS version: 2')
    print(f'  Cipher: aes-xts-plain64, key_bytes: {KEY_BYTES}')
    print(f'  KDF: argon2id (memory={ARGON2_MEMORY}, time={ARGON2_TIME}, cpus={ARGON2_PARALLELISM})')
    print(f'  Payload offset: {PAYLOAD_OFFSET_BYTES} bytes ({PAYLOAD_OFFSET_SECTORS} sectors)')
    print(f'  Inner size: {INNER_SIZE} bytes')
    print(f'  Passphrase: {PASSPHRASE.decode()}')
    print(f'  MK digest iterations: {MK_DIGEST_ITERATIONS}')
    print(f'  Master key (hex): {master_key.hex()}')
    print(f'  Self-test: PASSED')

    # Write the expected raw inner content for comparison
    raw_path = output_path.replace('.img', '-inner.raw')
    with open(raw_path, 'wb') as f:
        f.write(bytes(inner))
    print(f'  Expected inner content: {raw_path}')


def build_qcow2_image(virtual_size, inner_content):
    """Build a minimal QCOW2 v2 image wrapping the given raw content.

    Creates a simple QCOW2 with 64KB clusters, no compression,
    no encryption, no snapshots. All clusters are allocated
    sequentially after the L1 table.

    Returns the QCOW2 image as bytes.
    """
    cluster_size = 65536
    cluster_bits = 16

    # Calculate L2/L1 structure
    l2_entries = cluster_size // 8  # 8192 entries per L2
    l2_coverage = l2_entries * cluster_size  # 512MB per L2 table
    num_l2_tables = (virtual_size + l2_coverage - 1) // l2_coverage
    l1_size = num_l2_tables

    # Layout:
    #   Cluster 0: QCOW2 header (72 bytes) + refcount table
    #   Cluster 1: L1 table
    #   Cluster 2..2+num_l2: L2 tables
    #   After L2 tables: refcount blocks
    #   After refcount blocks: data clusters
    header_cluster = 0
    l1_cluster = 1
    l2_start_cluster = 2
    refblock_cluster = l2_start_cluster + num_l2_tables
    data_start_cluster = refblock_cluster + 1  # one refcount block

    num_data_clusters = (virtual_size + cluster_size - 1) // cluster_size
    total_clusters = data_start_cluster + num_data_clusters

    # Build the image
    image = bytearray(total_clusters * cluster_size)

    # QCOW2 header (72 bytes for v2)
    struct.pack_into('>I', image, 0, 0x514649FB)   # magic
    struct.pack_into('>I', image, 4, 2)              # version
    struct.pack_into('>Q', image, 8, 0)              # backing_file_offset
    struct.pack_into('>I', image, 16, 0)             # backing_file_size
    struct.pack_into('>I', image, 20, cluster_bits)  # cluster_bits
    struct.pack_into('>Q', image, 24, virtual_size)  # size
    struct.pack_into('>I', image, 32, 0)             # crypt_method
    struct.pack_into('>I', image, 36, l1_size)       # l1_size
    l1_table_offset = l1_cluster * cluster_size
    struct.pack_into('>Q', image, 40, l1_table_offset)  # l1_table_offset
    refcount_table_offset = header_cluster * cluster_size + 72  # after header
    struct.pack_into('>Q', image, 48, refcount_table_offset)  # refcount_table_offset
    struct.pack_into('>I', image, 56, 1)             # refcount_table_clusters (1 entry)
    struct.pack_into('>I', image, 60, 0)             # nb_snapshots
    struct.pack_into('>Q', image, 64, 0)             # snapshots_offset

    # Refcount table: one entry pointing to the refcount block
    refblock_offset = refblock_cluster * cluster_size
    struct.pack_into('>Q', image, refcount_table_offset, refblock_offset)

    # Refcount block: set refcount=1 for all used clusters
    for c in range(min(total_clusters, cluster_size // 2)):
        struct.pack_into('>H', image, refblock_offset + c * 2, 1)

    # L1 table: entries pointing to L2 tables
    for i in range(l1_size):
        l2_offset = (l2_start_cluster + i) * cluster_size
        struct.pack_into('>Q', image, l1_table_offset + i * 8, l2_offset)

    # L2 tables: entries pointing to data clusters
    for i in range(l1_size):
        l2_offset = (l2_start_cluster + i) * cluster_size
        for j in range(l2_entries):
            data_idx = i * l2_entries + j
            if data_idx >= num_data_clusters:
                break
            data_offset = (data_start_cluster + data_idx) * cluster_size
            struct.pack_into('>Q', image, l2_offset + j * 8, data_offset)

    # Data clusters: write inner content
    for i in range(num_data_clusters):
        src_offset = i * cluster_size
        dst_offset = (data_start_cluster + i) * cluster_size
        remaining = min(cluster_size, len(inner_content) - src_offset)
        if remaining > 0:
            image[dst_offset:dst_offset + remaining] = inner_content[src_offset:src_offset + remaining]

    return bytes(image)


def create_luks_v1_wrapping_qcow2(output_path):
    """Create a LUKS v1 container wrapping a QCOW2 image.

    The inner QCOW2 contains known raw data for verification.
    """
    # Create inner raw content (1MB, known pattern)
    raw_size = 1 * 1024 * 1024
    inner_raw = bytearray(raw_size)
    inner_raw[0:8] = b'\xbb' * 8  # recognizable pattern
    inner_raw[510] = 0x55
    inner_raw[511] = 0xAA
    inner_raw[512:520] = b'EFI PART'
    for i in range(4, 32):
        offset = i * 512
        inner_raw[offset:offset + 8] = struct.pack('<Q', i)
        inner_raw[offset + 8:offset + 512] = bytes([i & 0xFF]) * (512 - 8)

    # Build QCOW2 image wrapping the raw content
    qcow2_data = build_qcow2_image(raw_size, inner_raw)

    # Pad QCOW2 to sector boundary
    qcow2_padded_size = ((len(qcow2_data) + SECTOR_SIZE - 1) // SECTOR_SIZE) * SECTOR_SIZE
    qcow2_padded = bytearray(qcow2_padded_size)
    qcow2_padded[:len(qcow2_data)] = qcow2_data

    # Now create LUKS v1 container wrapping the QCOW2
    master_key = os.urandom(KEY_BYTES)
    mk_digest_salt = os.urandom(32)
    slot_salt = os.urandom(32)
    mk_digest = pbkdf2_sha256(master_key, mk_digest_salt, MK_DIGEST_ITERATIONS, 20)

    # LUKS v1 payload offset must fit header + key material.
    # Use same layout as create_luks_v1_image.
    payload_offset_sectors = PAYLOAD_OFFSET_SECTORS

    # Round total size to 65536-byte boundary for clean sector alignment
    total_size = payload_offset_sectors * SECTOR_SIZE + qcow2_padded_size
    total_aligned = ((total_size + 65535) // 65536) * 65536
    # Pad the QCOW2 data to fill
    extra_pad = total_aligned - total_size
    if extra_pad > 0:
        qcow2_padded.extend(b'\x00' * extra_pad)
        qcow2_padded_size += extra_pad

    header = bytearray(payload_offset_sectors * SECTOR_SIZE)

    # LUKS header
    header[0:6] = LUKS_MAGIC
    struct.pack_into('>H', header, 6, LUKS_VERSION)
    header[8:8 + len(CIPHER_NAME)] = CIPHER_NAME
    header[40:40 + len(CIPHER_MODE)] = CIPHER_MODE
    header[72:72 + len(HASH_SPEC)] = HASH_SPEC
    struct.pack_into('>I', header, 104, payload_offset_sectors)
    struct.pack_into('>I', header, 108, KEY_BYTES)
    header[112:132] = mk_digest
    header[132:164] = mk_digest_salt
    struct.pack_into('>I', header, 164, MK_DIGEST_ITERATIONS)
    uuid = b'deadbeef-aaaa-bbbb-cccc-qcow2wrapped'
    header[168:168 + len(uuid)] = uuid

    # Key slot 0
    slot_base = 208
    struct.pack_into('>I', header, slot_base, 0x00AC71F3)
    struct.pack_into('>I', header, slot_base + 4, SLOT_ITERATIONS)
    header[slot_base + 8:slot_base + 40] = slot_salt
    km_offset_sectors = 8
    struct.pack_into('>I', header, slot_base + 40, km_offset_sectors)
    struct.pack_into('>I', header, slot_base + 44, STRIPES)

    for i in range(1, 8):
        base = 208 + i * 48
        struct.pack_into('>I', header, base, 0x0000DEAD)

    km_material = af_split(master_key, KEY_BYTES, STRIPES)
    derived_key = pbkdf2_sha256(PASSPHRASE, slot_salt, SLOT_ITERATIONS, KEY_BYTES)
    encrypted_km = aes_xts_encrypt(derived_key, km_material, SECTOR_SIZE, 0)
    km_byte_offset = km_offset_sectors * SECTOR_SIZE
    header[km_byte_offset:km_byte_offset + len(encrypted_km)] = encrypted_km

    # Encrypt the QCOW2 data as LUKS payload
    encrypted_payload = aes_xts_encrypt(master_key, bytes(qcow2_padded), SECTOR_SIZE, 0)

    # Write the complete image
    with open(output_path, 'wb') as f:
        f.write(bytes(header))
        f.write(encrypted_payload)

    # Self-test: decrypt first sector and check QCOW2 magic
    decrypted_s0 = aes_xts_decrypt(master_key, encrypted_payload[:SECTOR_SIZE], SECTOR_SIZE, 0)
    qcow2_magic = struct.unpack('>I', decrypted_s0[:4])[0]
    assert qcow2_magic == 0x514649FB, f'Inner QCOW2 magic check failed: {qcow2_magic:#x}'
    print(f'  Self-test: PASSED (inner QCOW2 magic verified)')

    # Write the expected raw inner content for comparison
    raw_path = output_path.replace('.img', '-inner.raw')
    with open(raw_path, 'wb') as f:
        f.write(bytes(inner_raw))
    print(f'  Expected inner content: {raw_path}')

    total_bytes = len(header) + len(encrypted_payload)
    print(f'Created {output_path} ({total_bytes} bytes)')
    print(f'  LUKS version: 1')
    print(f'  Inner format: QCOW2 ({len(qcow2_data)} bytes, padded to {qcow2_padded_size})')
    print(f'  Inner virtual size: {raw_size} bytes')
    print(f'  Cipher: aes-xts-plain64, key_bytes: {KEY_BYTES}')
    print(f'  Payload offset: {payload_offset_sectors} sectors ({payload_offset_sectors * SECTOR_SIZE} bytes)')
    print(f'  Passphrase: {PASSPHRASE.decode()}')


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print(f'Usage: {sys.argv[0]} <output_dir>', file=sys.stderr)
        sys.exit(1)

    output_dir = sys.argv[1]
    os.makedirs(output_dir, exist_ok=True)

    create_luks_v1_image(os.path.join(output_dir, 'luks-v1-aes-xts.img'))
    create_luks_v2_image(os.path.join(output_dir, 'luks-v2-aes-xts.img'))
    create_luks_v1_wrapping_qcow2(os.path.join(output_dir, 'luks-v1-qcow2-inner.img'))
