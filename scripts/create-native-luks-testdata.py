#!/usr/bin/env python3
"""Create a LUKS v1 test image with known encrypted content.

This script builds a complete LUKS v1 container without requiring
cryptsetup or root privileges. It creates the header, derives key
slots using PBKDF2, AFsplitter-encodes the master key, and encrypts
known plaintext data using AES-XTS-plain64.

The resulting image can be used to test imago's native LUKS decryption.

Usage: python3 create-native-luks-testdata.py <output_dir>
"""

import hashlib
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


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print(f'Usage: {sys.argv[0]} <output_dir>', file=sys.stderr)
        sys.exit(1)

    output_dir = sys.argv[1]
    os.makedirs(output_dir, exist_ok=True)

    create_luks_v1_image(os.path.join(output_dir, 'luks-v1-aes-xts.img'))
