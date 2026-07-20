//! LUKS v1/v2 header parsing and key derivation.
//!
//! This crate provides I/O-agnostic LUKS functionality for bare-metal
//! guest operations. Callers are responsible for reading raw bytes from
//! disk and passing them as byte slices.

#![no_std]

// LUKS header magic: "LUKS\xba\xbe"
pub const LUKS_MAGIC: [u8; 6] = [0x4c, 0x55, 0x4b, 0x53, 0xba, 0xbe];

// LUKS v1 binary header field offsets
pub const LUKS_VERSION_OFFSET: usize = 6;
pub const LUKS_CIPHER_NAME_OFFSET: usize = 8;
pub const LUKS_CIPHER_MODE_OFFSET: usize = 40;
pub const LUKS_HASH_SPEC_OFFSET: usize = 72;
pub const LUKS_PAYLOAD_OFFSET_OFFSET: usize = 104;
pub const LUKS_KEY_BYTES_OFFSET: usize = 108;
pub const LUKS_MK_DIGEST_OFFSET: usize = 112;
pub const LUKS_MK_DIGEST_SALT_OFFSET: usize = 132;
pub const LUKS_MK_DIGEST_ITER_OFFSET: usize = 164;
pub const LUKS_UUID_OFFSET: usize = 168;
pub const LUKS_KEY_SLOT_BASE: usize = 208;
pub const LUKS_KEY_SLOT_SIZE: usize = 48;
pub const LUKS_NUM_KEY_SLOTS: usize = 8;
pub const LUKS_KEY_SLOT_ACTIVE: u32 = 0x00AC71F3;
pub const LUKS_V1_HEADER_SIZE: usize = 592;

// Key slot sub-field offsets (relative to slot start)
pub const LUKS_SLOT_ITERATIONS_OFFSET: usize = 4;
pub const LUKS_SLOT_SALT_OFFSET: usize = 8;
pub const LUKS_SLOT_KEY_MATERIAL_OFFSET: usize = 40;
pub const LUKS_SLOT_STRIPES_OFFSET: usize = 44;

// LUKS v2 binary header offsets
pub const LUKS2_HEADER_SIZE_OFFSET: usize = 8;
pub const LUKS2_UUID_OFFSET: usize = 168;
pub const LUKS2_BINARY_HEADER_SIZE: usize = 4096;
pub const LUKS2_JSON_SCAN_SIZE: usize = 16384;

// ─── Parsed header structures ───────────────────────────────────────

/// LUKS v1 key slot parameters.
pub struct LuksV1KeySlot {
    pub active: bool,
    pub iterations: u32,
    pub salt: [u8; 32],
    pub key_material_offset: u32,
    pub stripes: u32,
}

/// Parsed LUKS v1 header fields.
pub struct LuksV1Header {
    pub version: u16,
    pub cipher: [u8; 32],
    pub cipher_mode: [u8; 32],
    pub hash_spec: [u8; 32],
    pub payload_offset: u32,
    pub key_bytes: u32,
    pub mk_digest: [u8; 20],
    pub mk_digest_salt: [u8; 32],
    pub mk_digest_iter: u32,
    pub uuid: [u8; 40],
    pub slots: [LuksV1KeySlot; 8],
}

/// LUKS v2 key slot parameters extracted from JSON metadata.
pub struct LuksV2KeySlot {
    pub kdf_type_argon2id: bool,
    pub kdf_time: u32,
    pub kdf_memory: u32,
    pub kdf_cpus: u32,
    pub kdf_salt: [u8; 32],
    pub kdf_salt_len: usize,
    pub area_offset: u64,
    pub area_size: u64,
    pub af_stripes: u32,
    pub af_hash_sha256: bool,
    pub key_size: u32,
}

/// LUKS v2 digest parameters extracted from JSON metadata.
pub struct LuksV2Digest {
    pub digest_type_pbkdf2: bool,
    pub hash_sha256: bool,
    pub iterations: u32,
    pub salt: [u8; 32],
    pub salt_len: usize,
    pub digest: [u8; 32],
    pub digest_len: usize,
}

/// Result of successful LUKS key derivation.
pub struct LuksDerivedKey {
    pub key: [u8; 64],
    pub key_len: usize,
    pub luks_sector_size: u64,
}

// ─── Header parsing ─────────────────────────────────────────────────

/// Parse a LUKS v1 binary header from a byte buffer (>= 592 bytes).
pub fn parse_v1_header(buf: &[u8]) -> Option<LuksV1Header> {
    if buf.len() < LUKS_V1_HEADER_SIZE {
        return None;
    }

    // Verify magic
    if buf[0..6] != LUKS_MAGIC {
        return None;
    }

    let version = u16::from_be_bytes([buf[LUKS_VERSION_OFFSET], buf[LUKS_VERSION_OFFSET + 1]]);
    if version != 1 {
        return None;
    }

    let mut cipher = [0u8; 32];
    cipher.copy_from_slice(&buf[LUKS_CIPHER_NAME_OFFSET..LUKS_CIPHER_NAME_OFFSET + 32]);

    let mut cipher_mode = [0u8; 32];
    cipher_mode.copy_from_slice(&buf[LUKS_CIPHER_MODE_OFFSET..LUKS_CIPHER_MODE_OFFSET + 32]);

    let mut hash_spec = [0u8; 32];
    hash_spec.copy_from_slice(&buf[LUKS_HASH_SPEC_OFFSET..LUKS_HASH_SPEC_OFFSET + 32]);

    let payload_offset = u32::from_be_bytes([
        buf[LUKS_PAYLOAD_OFFSET_OFFSET],
        buf[LUKS_PAYLOAD_OFFSET_OFFSET + 1],
        buf[LUKS_PAYLOAD_OFFSET_OFFSET + 2],
        buf[LUKS_PAYLOAD_OFFSET_OFFSET + 3],
    ]);

    let key_bytes = u32::from_be_bytes([
        buf[LUKS_KEY_BYTES_OFFSET],
        buf[LUKS_KEY_BYTES_OFFSET + 1],
        buf[LUKS_KEY_BYTES_OFFSET + 2],
        buf[LUKS_KEY_BYTES_OFFSET + 3],
    ]);

    let mut mk_digest = [0u8; 20];
    mk_digest.copy_from_slice(&buf[LUKS_MK_DIGEST_OFFSET..LUKS_MK_DIGEST_OFFSET + 20]);

    let mut mk_digest_salt = [0u8; 32];
    mk_digest_salt
        .copy_from_slice(&buf[LUKS_MK_DIGEST_SALT_OFFSET..LUKS_MK_DIGEST_SALT_OFFSET + 32]);

    let mk_digest_iter = u32::from_be_bytes([
        buf[LUKS_MK_DIGEST_ITER_OFFSET],
        buf[LUKS_MK_DIGEST_ITER_OFFSET + 1],
        buf[LUKS_MK_DIGEST_ITER_OFFSET + 2],
        buf[LUKS_MK_DIGEST_ITER_OFFSET + 3],
    ]);

    let mut uuid = [0u8; 40];
    let uuid_src = &buf[LUKS_UUID_OFFSET..LUKS_UUID_OFFSET + 36];
    uuid[..36].copy_from_slice(uuid_src);

    // Parse key slots
    let mut slots: [LuksV1KeySlot; 8] = core::array::from_fn(|_| LuksV1KeySlot {
        active: false,
        iterations: 0,
        salt: [0u8; 32],
        key_material_offset: 0,
        stripes: 0,
    });

    for (i, slot) in slots.iter_mut().enumerate().take(LUKS_NUM_KEY_SLOTS) {
        let base = LUKS_KEY_SLOT_BASE + i * LUKS_KEY_SLOT_SIZE;
        let state = u32::from_be_bytes([buf[base], buf[base + 1], buf[base + 2], buf[base + 3]]);

        if state == LUKS_KEY_SLOT_ACTIVE {
            slot.active = true;
            slot.iterations = u32::from_be_bytes([
                buf[base + LUKS_SLOT_ITERATIONS_OFFSET],
                buf[base + LUKS_SLOT_ITERATIONS_OFFSET + 1],
                buf[base + LUKS_SLOT_ITERATIONS_OFFSET + 2],
                buf[base + LUKS_SLOT_ITERATIONS_OFFSET + 3],
            ]);
            slot.salt.copy_from_slice(
                &buf[base + LUKS_SLOT_SALT_OFFSET..base + LUKS_SLOT_SALT_OFFSET + 32],
            );
            slot.key_material_offset = u32::from_be_bytes([
                buf[base + LUKS_SLOT_KEY_MATERIAL_OFFSET],
                buf[base + LUKS_SLOT_KEY_MATERIAL_OFFSET + 1],
                buf[base + LUKS_SLOT_KEY_MATERIAL_OFFSET + 2],
                buf[base + LUKS_SLOT_KEY_MATERIAL_OFFSET + 3],
            ]);
            slot.stripes = u32::from_be_bytes([
                buf[base + LUKS_SLOT_STRIPES_OFFSET],
                buf[base + LUKS_SLOT_STRIPES_OFFSET + 1],
                buf[base + LUKS_SLOT_STRIPES_OFFSET + 2],
                buf[base + LUKS_SLOT_STRIPES_OFFSET + 3],
            ]);
        }
    }

    Some(LuksV1Header {
        version,
        cipher,
        cipher_mode,
        hash_spec,
        payload_offset,
        key_bytes,
        mk_digest,
        mk_digest_salt,
        mk_digest_iter,
        uuid,
        slots,
    })
}

/// Get the LUKS version from a header buffer (>= 8 bytes).
pub fn get_version(buf: &[u8]) -> Option<u16> {
    if buf.len() < 8 || buf[0..6] != LUKS_MAGIC {
        return None;
    }
    Some(u16::from_be_bytes([
        buf[LUKS_VERSION_OFFSET],
        buf[LUKS_VERSION_OFFSET + 1],
    ]))
}

/// Find the first active key slot in a LUKS v1 header.
pub fn find_active_v1_slot(header: &LuksV1Header) -> Option<usize> {
    header.slots.iter().position(|s| s.active)
}

/// Compare a null-padded header field against expected bytes.
pub fn field_eq(header: &[u8], offset: usize, max_len: usize, expected: &[u8]) -> bool {
    let end = (offset + max_len).min(header.len());
    let field = &header[offset..end];
    let nul_pos = field.iter().position(|&b| b == 0).unwrap_or(field.len());
    &field[..nul_pos] == expected
}

/// Extract a null-terminated string from a fixed-size header field.
pub fn field_as_str(buf: &[u8], offset: usize, max_len: usize) -> &str {
    let field = &buf[offset..offset + max_len];
    let end = field.iter().position(|&b| b == 0).unwrap_or(max_len);
    core::str::from_utf8(&field[..end]).unwrap_or("")
}

/// Check whether a LUKS v1 header has aes-xts-plain64 cipher.
pub fn v1_is_aes_xts(header: &LuksV1Header) -> bool {
    field_eq(&header.cipher, 0, 32, b"aes") && field_eq(&header.cipher_mode, 0, 32, b"xts-plain64")
}

/// Get the hash spec from a LUKS v1 header as a string.
pub fn v1_hash_spec(header: &LuksV1Header) -> &str {
    field_as_str(&header.hash_spec, 0, 32)
}

/// Count active key slots in a LUKS v1 header.
pub fn v1_active_slot_count(header: &LuksV1Header) -> u32 {
    header.slots.iter().filter(|s| s.active).count() as u32
}

/// Calculate key material byte offset and total size for a LUKS v1 slot.
///
/// Returns `(byte_offset, total_bytes)` or `None` on overflow.
pub fn v1_key_material_region(slot: &LuksV1KeySlot, key_bytes: u32) -> Option<(u64, usize)> {
    let total = (key_bytes as usize).checked_mul(slot.stripes as usize)?;
    let byte_offset = slot.key_material_offset as u64 * 512;
    Some((byte_offset, total))
}

// ─── LUKS v2 JSON parsing ───────────────────────────────────────────

/// Find a byte pattern in a slice, returning the position.
pub fn find_pattern(data: &[u8], pattern: &[u8]) -> Option<usize> {
    if pattern.len() > data.len() {
        return None;
    }
    (0..=data.len() - pattern.len()).find(|&i| data[i..i + pattern.len()] == *pattern)
}

/// Extract a JSON string value following a key pattern.
pub fn extract_json_string<'a>(data: &'a [u8], key: &[u8]) -> Option<&'a [u8]> {
    let key_pos = find_pattern(data, key)?;
    let after_key = key_pos + key.len();
    let search_end = (after_key + 256).min(data.len());
    let rest = &data[after_key..search_end];

    let colon_pos = rest.iter().position(|&b| b == b':')?;
    let after_colon = &rest[colon_pos + 1..];
    let quote_start = after_colon.iter().position(|&b| b == b'"')?;
    let value_start = quote_start + 1;
    let value_bytes = &after_colon[value_start..];
    let quote_end = value_bytes.iter().position(|&b| b == b'"')?;

    Some(&value_bytes[..quote_end])
}

/// Extract a JSON numeric value following a key pattern.
pub fn extract_json_number(data: &[u8], key: &[u8]) -> Option<u64> {
    let key_pos = find_pattern(data, key)?;
    let after_key = key_pos + key.len();
    let search_end = (after_key + 64).min(data.len());
    let rest = &data[after_key..search_end];

    let colon_pos = rest.iter().position(|&b| b == b':')?;
    let after_colon = &rest[colon_pos + 1..];
    let digit_start = after_colon.iter().position(|&b| b.is_ascii_digit())?;
    let digits = &after_colon[digit_start..];
    let digit_end = digits
        .iter()
        .position(|&b| !b.is_ascii_digit())
        .unwrap_or(digits.len());

    Some(parse_ascii_u64(&digits[..digit_end]))
}

/// Parse an ASCII decimal number from a byte slice.
pub fn parse_ascii_u64(data: &[u8]) -> u64 {
    let mut result: u64 = 0;
    for &b in data {
        if b.is_ascii_digit() {
            result = result.saturating_mul(10).saturating_add((b - b'0') as u64);
        }
    }
    result
}

/// Decode standard base64 into output buffer. Returns bytes written.
pub fn base64_decode(input: &[u8], output: &mut [u8]) -> usize {
    #[inline]
    fn decode_char(c: u8) -> Option<u8> {
        match c {
            b'A'..=b'Z' => Some(c - b'A'),
            b'a'..=b'z' => Some(c - b'a' + 26),
            b'0'..=b'9' => Some(c - b'0' + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    }

    let mut out_pos = 0;
    let mut i = 0;
    let end = input
        .iter()
        .rposition(|&b| b != b'=')
        .map(|p| p + 1)
        .unwrap_or(0);

    while i + 1 < end {
        let n = match (i + 1..end.min(i + 4)).count() + 1 {
            c if c >= 2 => c,
            _ => break,
        };

        let a = match decode_char(input[i]) {
            Some(v) => v as u32,
            None => return out_pos,
        };
        let b = match decode_char(input[i + 1]) {
            Some(v) => v as u32,
            None => return out_pos,
        };

        if out_pos >= output.len() {
            return out_pos;
        }
        output[out_pos] = ((a << 2) | (b >> 4)) as u8;
        out_pos += 1;

        if n > 2 && i + 2 < end {
            let c = match decode_char(input[i + 2]) {
                Some(v) => v as u32,
                None => return out_pos,
            };
            if out_pos >= output.len() {
                return out_pos;
            }
            output[out_pos] = ((b << 4) | (c >> 2)) as u8;
            out_pos += 1;

            if n > 3 && i + 3 < end {
                let d = match decode_char(input[i + 3]) {
                    Some(v) => v as u32,
                    None => return out_pos,
                };
                if out_pos >= output.len() {
                    return out_pos;
                }
                output[out_pos] = ((c << 6) | d) as u8;
                out_pos += 1;
            }
        }

        i += 4;
    }
    out_pos
}

/// Parse LUKS v2 keyslot parameters from JSON metadata.
pub fn parse_v2_keyslot(json: &[u8]) -> Option<LuksV2KeySlot> {
    let ks_pos = find_pattern(json, b"\"keyslots\"")?;
    let ks_data = &json[ks_pos..];

    let ks_end = find_pattern(ks_data, b"\"tokens\"")
        .or_else(|| find_pattern(ks_data, b"\"segments\""))
        .unwrap_or(ks_data.len());
    let ks_section = &ks_data[..ks_end];

    // Check KDF type
    let kdf_pos = find_pattern(ks_section, b"\"kdf\"")?;
    let kdf_data = &ks_section[kdf_pos..];
    let kdf_type = extract_json_string(kdf_data, b"\"type\"")?;
    let kdf_type_argon2id = kdf_type == b"argon2id";

    let kdf_time = extract_json_number(kdf_data, b"\"time\"")? as u32;
    let kdf_memory = extract_json_number(kdf_data, b"\"memory\"")? as u32;
    let kdf_cpus = extract_json_number(kdf_data, b"\"cpus\"")? as u32;

    let salt_b64 = extract_json_string(kdf_data, b"\"salt\"")?;
    let mut kdf_salt = [0u8; 32];
    let kdf_salt_len = base64_decode(salt_b64, &mut kdf_salt);
    if kdf_salt_len == 0 {
        return None;
    }

    let key_size = extract_json_number(ks_section, b"\"key_size\"")? as u32;

    let af_pos = find_pattern(ks_section, b"\"af\"")?;
    let af_data = &ks_section[af_pos..];
    let af_stripes = extract_json_number(af_data, b"\"stripes\"").unwrap_or(4000) as u32;
    let af_hash = extract_json_string(af_data, b"\"hash\"").unwrap_or(b"sha256");
    let af_hash_sha256 = af_hash == b"sha256";

    let area_pos = find_pattern(ks_section, b"\"area\"")?;
    let area_data = &ks_section[area_pos..];
    let area_offset_str = extract_json_string(area_data, b"\"offset\"")?;
    let area_offset = parse_ascii_u64(area_offset_str);
    let area_size_str = extract_json_string(area_data, b"\"size\"")?;
    let area_size = parse_ascii_u64(area_size_str);

    Some(LuksV2KeySlot {
        kdf_type_argon2id,
        kdf_time,
        kdf_memory,
        kdf_cpus,
        kdf_salt,
        kdf_salt_len,
        area_offset,
        area_size,
        af_stripes,
        af_hash_sha256,
        key_size,
    })
}

/// Parse LUKS v2 digest parameters from JSON metadata.
pub fn parse_v2_digest(json: &[u8]) -> Option<LuksV2Digest> {
    let dig_pos = find_pattern(json, b"\"digests\"")?;
    let dig_data = &json[dig_pos..];

    let dig_end = find_pattern(dig_data, b"\"config\"").unwrap_or(dig_data.len());
    let dig_section = &dig_data[..dig_end];

    let dig_type = extract_json_string(dig_section, b"\"type\"")?;
    let digest_type_pbkdf2 = dig_type == b"pbkdf2";

    let hash = extract_json_string(dig_section, b"\"hash\"").unwrap_or(b"sha256");
    let hash_sha256 = hash == b"sha256";

    let iterations = extract_json_number(dig_section, b"\"iterations\"").unwrap_or(0) as u32;

    let salt_b64 = extract_json_string(dig_section, b"\"salt\"")?;
    let mut salt = [0u8; 32];
    let salt_len = base64_decode(salt_b64, &mut salt);

    let digest_b64 = extract_json_string(dig_section, b"\"digest\"")?;
    let mut digest = [0u8; 32];
    let digest_len = base64_decode(digest_b64, &mut digest);

    Some(LuksV2Digest {
        digest_type_pbkdf2,
        hash_sha256,
        iterations,
        salt,
        salt_len,
        digest,
        digest_len,
    })
}

/// Parse LUKS v2 JSON to extract cipher, mode, hash, payload offset,
/// key size, and active slot count into provided buffers.
///
/// This populates fields matching the LuksInfo shared struct pattern:
/// cipher, cipher_mode, hash, payload_offset, master_key_length,
/// active_key_slots.
pub fn parse_v2_json_metadata(
    json: &[u8],
    cipher: &mut [u8; 32],
    cipher_mode: &mut [u8; 32],
    hash: &mut [u8; 32],
    payload_offset_sectors: &mut u32,
    master_key_length: &mut u32,
    active_key_slots: &mut u32,
) {
    // Extract encryption string from segments section
    if let Some(seg_pos) = find_pattern(json, b"\"segments\"") {
        if let Some(enc) = extract_json_string(&json[seg_pos..], b"\"encryption\"") {
            if let Some(dash_pos) = enc.iter().position(|&b| b == b'-') {
                copy_null_padded(&enc[..dash_pos], cipher);
                copy_null_padded(&enc[dash_pos + 1..], cipher_mode);
            } else {
                copy_null_padded(enc, cipher);
            }
        }

        if let Some(off_str) = extract_json_string(&json[seg_pos..], b"\"offset\"") {
            let offset_bytes = parse_ascii_u64(off_str);
            if offset_bytes > 0 {
                *payload_offset_sectors = (offset_bytes / 512) as u32;
            }
        }
    }

    // Extract hash from digests section
    if let Some(dig_pos) = find_pattern(json, b"\"digests\"") {
        if let Some(h) = extract_json_string(&json[dig_pos..], b"\"hash\"") {
            copy_null_padded(h, hash);
        }
    }

    // Extract key_size and count active key slots
    if let Some(ks_pos) = find_pattern(json, b"\"keyslots\"") {
        if let Some(ks_val) = extract_json_number(&json[ks_pos..], b"\"key_size\"") {
            *master_key_length = ks_val as u32;
        }

        let ks_end = find_pattern(&json[ks_pos..], b"\"segments\"")
            .map(|p| ks_pos + p)
            .unwrap_or(json.len());
        let ks_section = &json[ks_pos..ks_end];
        let mut active = 0u32;
        let mut search_from = 0;
        while let Some(pos) = find_pattern(&ks_section[search_from..], b"\"kdf\"") {
            active += 1;
            search_from += pos + 5;
            if search_from >= ks_section.len() {
                break;
            }
        }
        *active_key_slots = active;
    }
}

/// Copy a null-padded string from source to destination buffer.
pub fn copy_null_padded(src: &[u8], dst: &mut [u8]) {
    let end = src.iter().position(|&b| b == 0).unwrap_or(src.len());
    let copy_len = end.min(dst.len() - 1);
    dst[..copy_len].copy_from_slice(&src[..copy_len]);
    dst[copy_len] = 0;
}

// ─── AFsplitter ─────────────────────────────────────────────────────

#[cfg(any(feature = "decrypt", feature = "encrypt"))]
use sha1::Sha1;

#[cfg(any(feature = "decrypt", feature = "encrypt", feature = "kdf-argon2"))]
use sha2::{Digest, Sha256};

/// AFsplitter diffuse function using SHA-1 (for LUKS v1 with sha1 hash).
#[cfg(any(feature = "decrypt", feature = "encrypt"))]
pub fn af_diffuse_sha1(data: &mut [u8], key_bytes: usize) {
    let digest_size = 20;
    let full_blocks = key_bytes / digest_size;
    let remainder = key_bytes % digest_size;

    for i in 0..full_blocks {
        let offset = i * digest_size;
        let block_num = (i as u32).to_be_bytes();
        let mut hasher = Sha1::new();
        hasher.update(block_num);
        hasher.update(&data[offset..offset + digest_size]);
        let result = hasher.finalize();
        data[offset..offset + digest_size].copy_from_slice(&result);
    }
    if remainder > 0 {
        let offset = full_blocks * digest_size;
        let block_num = (full_blocks as u32).to_be_bytes();
        let mut hasher = Sha1::new();
        hasher.update(block_num);
        hasher.update(&data[offset..offset + remainder]);
        let result = hasher.finalize();
        data[offset..offset + remainder].copy_from_slice(&result[..remainder]);
    }
}

/// AFsplitter diffuse function using SHA-256 (for LUKS v2 or v1 with sha256 hash).
#[cfg(any(feature = "decrypt", feature = "encrypt", feature = "kdf-argon2"))]
pub fn af_diffuse_sha256(data: &mut [u8], key_bytes: usize) {
    let digest_size = 32;
    let full_blocks = key_bytes / digest_size;
    let remainder = key_bytes % digest_size;

    for i in 0..full_blocks {
        let offset = i * digest_size;
        let block_num = (i as u32).to_be_bytes();
        let mut hasher = Sha256::new();
        hasher.update(block_num);
        hasher.update(&data[offset..offset + digest_size]);
        let result = hasher.finalize();
        data[offset..offset + digest_size].copy_from_slice(&result);
    }
    if remainder > 0 {
        let offset = full_blocks * digest_size;
        let block_num = (full_blocks as u32).to_be_bytes();
        let mut hasher = Sha256::new();
        hasher.update(block_num);
        hasher.update(&data[offset..offset + remainder]);
        let result = hasher.finalize();
        data[offset..offset + remainder].copy_from_slice(&result[..remainder]);
    }
}

/// AFsplitter merge: recover master key from striped key material.
///
/// `km_buf` contains `stripes * key_bytes` bytes of decrypted key material.
/// `out_key` receives the merged master key (must be >= `key_bytes`).
/// `use_sha256` selects SHA-256 diffuse (true) vs SHA-1 diffuse (false).
#[cfg(any(feature = "decrypt", feature = "encrypt"))]
pub fn af_merge(
    km_buf: &[u8],
    key_bytes: usize,
    stripes: usize,
    use_sha256: bool,
    out_key: &mut [u8],
) {
    out_key[..key_bytes].copy_from_slice(&km_buf[..key_bytes]);

    for i in 1..stripes {
        if use_sha256 {
            af_diffuse_sha256(&mut out_key[..key_bytes], key_bytes);
        } else {
            af_diffuse_sha1(&mut out_key[..key_bytes], key_bytes);
        }

        let stripe_offset = i * key_bytes;
        for j in 0..key_bytes {
            out_key[j] ^= km_buf[stripe_offset + j];
        }
    }
}

/// AFsplitter split: distribute a master key across striped key material.
///
/// This is the inverse of `af_merge`. Given `master_key` (key_bytes)
/// and `km_buf` pre-filled with random data in stripes 0..stripes-2,
/// this function computes the final stripe so that
/// `af_merge(km_buf, key_bytes, stripes, use_sha256, out)` recovers
/// `master_key`.
///
/// `km_buf` must be `stripes * key_bytes` bytes. Stripes 0 through
/// stripes-2 must be pre-filled with random data by the caller.
/// The final stripe (at offset `(stripes-1) * key_bytes`) is computed
/// by this function.
#[cfg(feature = "encrypt")]
pub fn af_split(
    master_key: &[u8],
    key_bytes: usize,
    stripes: usize,
    use_sha256: bool,
    km_buf: &mut [u8],
) {
    // Replay the merge accumulation on stripes 0..stripes-2
    let mut accum = [0u8; 64];
    accum[..key_bytes].copy_from_slice(&km_buf[..key_bytes]);

    for i in 1..stripes - 1 {
        if use_sha256 {
            af_diffuse_sha256(&mut accum[..key_bytes], key_bytes);
        } else {
            af_diffuse_sha1(&mut accum[..key_bytes], key_bytes);
        }
        let stripe_offset = i * key_bytes;
        for j in 0..key_bytes {
            accum[j] ^= km_buf[stripe_offset + j];
        }
    }

    // One more diffuse, then XOR with master key to get final stripe
    if use_sha256 {
        af_diffuse_sha256(&mut accum[..key_bytes], key_bytes);
    } else {
        af_diffuse_sha1(&mut accum[..key_bytes], key_bytes);
    }
    let last_offset = (stripes - 1) * key_bytes;
    for j in 0..key_bytes {
        km_buf[last_offset + j] = accum[j] ^ master_key[j];
    }
}

// ─── LUKS v1 header construction ────────────────────────────────────

/// Default number of AFsplitter stripes for LUKS v1 key slots.
pub const LUKS_DEFAULT_STRIPES: u32 = 4000;

/// LUKS v1 key slot inactive marker.
pub const LUKS_KEY_SLOT_DEAD: u32 = 0x0000DEAD;

/// Parameters for building a LUKS v1 header.
pub struct LuksV1BuildParams<'a> {
    /// AES master key (32 bytes for AES-128-XTS, 64 for AES-256-XTS).
    pub master_key: &'a [u8],
    /// User passphrase.
    pub passphrase: &'a [u8],
    /// PBKDF2 iteration count for key slot derivation.
    pub iterations: u32,
    /// PBKDF2 iteration count for master key digest verification.
    pub mk_digest_iterations: u32,
    /// Random salt for master key digest (32 bytes).
    pub mk_digest_salt: &'a [u8; 32],
    /// Random salt for key slot 0 (32 bytes).
    pub slot_salt: &'a [u8; 32],
    /// Random data for AFsplitter stripes (must be
    /// `(LUKS_DEFAULT_STRIPES - 1) * master_key.len()` bytes).
    pub af_random: &'a [u8],
    /// UUID string (36 bytes ASCII, e.g. "12345678-1234-1234-1234-123456789abc").
    pub uuid: &'a [u8; 36],
    /// Use SHA-256 (true) or SHA-1 (false) for PBKDF2 and AFsplitter.
    pub use_sha256: bool,
}

/// Build a LUKS v1 binary header + encrypted key material into `out`.
///
/// Writes the 592-byte header followed by the encrypted key material
/// for slot 0. Returns the total number of bytes written, or None
/// on failure.
///
/// The key material is placed at sector 8 (byte 4096) to match the
/// conventional LUKS v1 layout. The payload offset is set to 0
/// because in QCOW2 crypt_method=2, the LUKS header is metadata
/// only — encrypted data is at each cluster's host offset.
///
/// `out` must be large enough for the header (592 bytes) + padding
/// to sector 8 + key material (key_bytes * LUKS_DEFAULT_STRIPES).
/// A safe size is `4096 + 64 * 4000 = 260096` bytes.
#[cfg(feature = "encrypt")]
pub fn build_v1_header(params: &LuksV1BuildParams, out: &mut [u8]) -> Option<usize> {
    let key_bytes = params.master_key.len();
    if key_bytes != 32 && key_bytes != 64 {
        return None;
    }
    let stripes = LUKS_DEFAULT_STRIPES as usize;
    let km_size = key_bytes * stripes;
    // Key material starts at sector 8 (byte 4096)
    let km_sector_offset: u32 = 8;
    let km_byte_offset = km_sector_offset as usize * 512;
    let total_size = km_byte_offset + km_size;

    if out.len() < total_size {
        return None;
    }
    if params.af_random.len() < (stripes - 1) * key_bytes {
        return None;
    }

    // Zero the output buffer up to total_size
    for b in out[..total_size].iter_mut() {
        *b = 0;
    }

    // ── Write binary header ──

    // Magic
    out[0..6].copy_from_slice(&LUKS_MAGIC);
    // Version = 1
    out[LUKS_VERSION_OFFSET..LUKS_VERSION_OFFSET + 2].copy_from_slice(&1u16.to_be_bytes());
    // Cipher name: "aes"
    out[LUKS_CIPHER_NAME_OFFSET..LUKS_CIPHER_NAME_OFFSET + 3].copy_from_slice(b"aes");
    // Cipher mode: "xts-plain64"
    out[LUKS_CIPHER_MODE_OFFSET..LUKS_CIPHER_MODE_OFFSET + 11].copy_from_slice(b"xts-plain64");
    // Hash spec
    let hash_name = if params.use_sha256 {
        b"sha256\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"
    } else {
        b"sha1\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"
    };
    let hash_len = if params.use_sha256 { 6 } else { 4 };
    out[LUKS_HASH_SPEC_OFFSET..LUKS_HASH_SPEC_OFFSET + hash_len]
        .copy_from_slice(&hash_name[..hash_len]);
    // Payload offset = 0 (QCOW2 crypt_method=2: no payload in LUKS area)
    out[LUKS_PAYLOAD_OFFSET_OFFSET..LUKS_PAYLOAD_OFFSET_OFFSET + 4]
        .copy_from_slice(&0u32.to_be_bytes());
    // Key bytes
    out[LUKS_KEY_BYTES_OFFSET..LUKS_KEY_BYTES_OFFSET + 4]
        .copy_from_slice(&(key_bytes as u32).to_be_bytes());

    // MK digest salt
    out[LUKS_MK_DIGEST_SALT_OFFSET..LUKS_MK_DIGEST_SALT_OFFSET + 32]
        .copy_from_slice(params.mk_digest_salt);
    // MK digest iterations
    out[LUKS_MK_DIGEST_ITER_OFFSET..LUKS_MK_DIGEST_ITER_OFFSET + 4]
        .copy_from_slice(&params.mk_digest_iterations.to_be_bytes());

    // Compute MK digest: PBKDF2(master_key, mk_digest_salt, mk_digest_iter)
    let mut mk_digest = [0u8; 20];
    pbkdf2_derive(
        params.master_key,
        params.mk_digest_salt,
        params.mk_digest_iterations,
        &mut mk_digest,
        params.use_sha256,
    );
    out[LUKS_MK_DIGEST_OFFSET..LUKS_MK_DIGEST_OFFSET + 20].copy_from_slice(&mk_digest);

    // UUID
    out[LUKS_UUID_OFFSET..LUKS_UUID_OFFSET + 36].copy_from_slice(params.uuid);

    // ── Key slot 0 (active) ──
    let slot_base = LUKS_KEY_SLOT_BASE;
    out[slot_base..slot_base + 4].copy_from_slice(&LUKS_KEY_SLOT_ACTIVE.to_be_bytes());
    out[slot_base + LUKS_SLOT_ITERATIONS_OFFSET..slot_base + LUKS_SLOT_ITERATIONS_OFFSET + 4]
        .copy_from_slice(&params.iterations.to_be_bytes());
    out[slot_base + LUKS_SLOT_SALT_OFFSET..slot_base + LUKS_SLOT_SALT_OFFSET + 32]
        .copy_from_slice(params.slot_salt);
    out[slot_base + LUKS_SLOT_KEY_MATERIAL_OFFSET..slot_base + LUKS_SLOT_KEY_MATERIAL_OFFSET + 4]
        .copy_from_slice(&km_sector_offset.to_be_bytes());
    out[slot_base + LUKS_SLOT_STRIPES_OFFSET..slot_base + LUKS_SLOT_STRIPES_OFFSET + 4]
        .copy_from_slice(&(stripes as u32).to_be_bytes());

    // ── Key slots 1-7 (inactive) ──
    for i in 1..LUKS_NUM_KEY_SLOTS {
        let base = LUKS_KEY_SLOT_BASE + i * LUKS_KEY_SLOT_SIZE;
        out[base..base + 4].copy_from_slice(&LUKS_KEY_SLOT_DEAD.to_be_bytes());
    }

    // ── Prepare and encrypt key material ──

    // Fill key material buffer with AF random stripes + computed final stripe
    let km_buf = &mut out[km_byte_offset..km_byte_offset + km_size];
    // Copy random stripes 0..stripes-2
    km_buf[..((stripes - 1) * key_bytes)]
        .copy_from_slice(&params.af_random[..(stripes - 1) * key_bytes]);

    // Compute final stripe via af_split
    af_split(
        params.master_key,
        key_bytes,
        stripes,
        params.use_sha256,
        km_buf,
    );

    // Derive the split key from passphrase (same length as master key)
    let mut split_key = [0u8; 64];
    pbkdf2_derive(
        params.passphrase,
        params.slot_salt,
        params.iterations,
        &mut split_key[..key_bytes],
        params.use_sha256,
    );

    // Encrypt key material with AES-XTS using the derived split key
    aes_xts_encrypt(km_buf, &split_key[..key_bytes], 0);

    Some(total_size)
}

// ─── Key derivation ─────────────────────────────────────────────────

#[cfg(any(feature = "decrypt", feature = "encrypt"))]
use aes::cipher::{Array, KeyInit};
#[cfg(any(feature = "decrypt", feature = "encrypt"))]
use aes::{Aes128, Aes256};
#[cfg(any(feature = "decrypt", feature = "encrypt"))]
use hmac::Hmac;
#[cfg(any(feature = "decrypt", feature = "encrypt"))]
use pbkdf2::pbkdf2;

/// AES-XTS decrypt a buffer in place.
///
/// Splits the key in half: first half = data key, second = tweak key.
/// Uses 512-byte sectors starting at the given sector index.
#[cfg(feature = "decrypt")]
pub fn aes_xts_decrypt(buf: &mut [u8], key: &[u8], start_sector: u64) {
    let half = key.len() / 2;
    if half == 16 {
        let c1 = Aes128::new(<&Array<u8, _>>::try_from(&key[..16]).expect("slice length is fixed"));
        let c2 =
            Aes128::new(<&Array<u8, _>>::try_from(&key[16..32]).expect("slice length is fixed"));
        let xts = xts_mode::Xts128::<Aes128>::new(c1, c2);
        xts.decrypt_area(buf, 512, start_sector as u128, xts_mode::get_tweak_default);
    } else if half == 32 {
        let c1 = Aes256::new(<&Array<u8, _>>::try_from(&key[..32]).expect("slice length is fixed"));
        let c2 =
            Aes256::new(<&Array<u8, _>>::try_from(&key[32..64]).expect("slice length is fixed"));
        let xts = xts_mode::Xts128::<Aes256>::new(c1, c2);
        xts.decrypt_area(buf, 512, start_sector as u128, xts_mode::get_tweak_default);
    }
}

/// AES-XTS encrypt a buffer in place.
///
/// Splits the key in half: first half = data key, second = tweak key.
/// Uses 512-byte sectors starting at the given sector index.
/// This is the inverse of `aes_xts_decrypt`.
#[cfg(feature = "encrypt")]
pub fn aes_xts_encrypt(buf: &mut [u8], key: &[u8], start_sector: u64) {
    let half = key.len() / 2;
    if half == 16 {
        let c1 = Aes128::new(<&Array<u8, _>>::try_from(&key[..16]).expect("slice length is fixed"));
        let c2 =
            Aes128::new(<&Array<u8, _>>::try_from(&key[16..32]).expect("slice length is fixed"));
        let xts = xts_mode::Xts128::<Aes128>::new(c1, c2);
        xts.encrypt_area(buf, 512, start_sector as u128, xts_mode::get_tweak_default);
    } else if half == 32 {
        let c1 = Aes256::new(<&Array<u8, _>>::try_from(&key[..32]).expect("slice length is fixed"));
        let c2 =
            Aes256::new(<&Array<u8, _>>::try_from(&key[32..64]).expect("slice length is fixed"));
        let xts = xts_mode::Xts128::<Aes256>::new(c1, c2);
        xts.encrypt_area(buf, 512, start_sector as u128, xts_mode::get_tweak_default);
    }
}

/// PBKDF2 key derivation with SHA-256 or SHA-1.
#[cfg(any(feature = "decrypt", feature = "encrypt"))]
pub fn pbkdf2_derive(
    passphrase: &[u8],
    salt: &[u8],
    iterations: u32,
    output: &mut [u8],
    use_sha256: bool,
) {
    if use_sha256 {
        pbkdf2::<Hmac<Sha256>>(passphrase, salt, iterations, output).unwrap_or(());
    } else {
        pbkdf2::<Hmac<Sha1>>(passphrase, salt, iterations, output).unwrap_or(());
    }
}

/// Derive LUKS v1 master key from a parsed header and pre-read key material.
///
/// `key_material` must contain the raw encrypted key material bytes
/// (key_bytes * stripes), already read from disk. This buffer is
/// modified in place during decryption.
///
/// Returns `LuksDerivedKey` on success, or `None` if:
/// - cipher is not aes-xts-plain64
/// - key_bytes is not 32 or 64
/// - no active key slot found
/// - passphrase is wrong (verification fails)
#[cfg(feature = "decrypt")]
pub fn derive_v1_master_key(
    header: &LuksV1Header,
    passphrase: &[u8],
    key_material: &mut [u8],
) -> Option<LuksDerivedKey> {
    if !v1_is_aes_xts(header) {
        return None;
    }

    let key_bytes = header.key_bytes as usize;
    if key_bytes != 32 && key_bytes != 64 {
        return None;
    }

    let slot_idx = find_active_v1_slot(header)?;
    let slot = &header.slots[slot_idx];

    let hash = v1_hash_spec(header);
    let use_sha256 = hash == "sha256";

    // Step 1: PBKDF2 to derive split key
    let mut derived_key = [0u8; 64];
    let dk = &mut derived_key[..key_bytes];
    pbkdf2_derive(passphrase, &slot.salt, slot.iterations, dk, use_sha256);

    // Step 2: AES-XTS decrypt key material
    aes_xts_decrypt(key_material, dk, 0);

    // Step 3: AFsplitter merge
    let mut candidate = [0u8; 64];
    af_merge(
        key_material,
        key_bytes,
        slot.stripes as usize,
        use_sha256,
        &mut candidate,
    );

    // Step 4: Verify master key via PBKDF2 digest
    let mut verify = [0u8; 20];
    pbkdf2_derive(
        &candidate[..key_bytes],
        &header.mk_digest_salt,
        header.mk_digest_iter,
        &mut verify,
        use_sha256,
    );

    if verify != header.mk_digest {
        return None;
    }

    let mut result = LuksDerivedKey {
        key: [0u8; 64],
        key_len: key_bytes,
        luks_sector_size: 512,
    };
    result.key[..key_bytes].copy_from_slice(&candidate[..key_bytes]);
    Some(result)
}

/// Derive LUKS v2 master key using Argon2id KDF.
///
/// `key_material` must contain the raw encrypted key material bytes,
/// already read from disk. This buffer is modified in place.
///
/// `argon2_memory` must point to pre-allocated memory blocks for
/// Argon2id working memory (kdf_memory KiB worth of blocks).
///
/// Returns `LuksDerivedKey` on success, or `None` on failure.
#[cfg(feature = "kdf-argon2")]
pub fn derive_v2_master_key(
    slot: &LuksV2KeySlot,
    digest_params: &LuksV2Digest,
    passphrase: &[u8],
    key_material: &mut [u8],
    argon2_memory: &mut [argon2::Block],
) -> Option<LuksDerivedKey> {
    let key_bytes = slot.key_size as usize;
    if key_bytes != 32 && key_bytes != 64 {
        return None;
    }

    if !slot.kdf_type_argon2id {
        return None;
    }

    // Step 1: Argon2id key derivation
    let params = argon2::Params::new(slot.kdf_memory, slot.kdf_time, slot.kdf_cpus, None).ok()?;
    let argon2_ctx =
        argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);

    let mut derived_key = [0u8; 64];
    let dk = &mut derived_key[..key_bytes];

    // Zero the memory blocks before use
    for block in argon2_memory.iter_mut() {
        *block = argon2::Block::default();
    }

    if argon2_ctx
        .hash_password_into_with_memory(
            passphrase,
            &slot.kdf_salt[..slot.kdf_salt_len],
            dk,
            argon2_memory,
        )
        .is_err()
    {
        return None;
    }

    // Step 2: AES-XTS decrypt key material
    aes_xts_decrypt(key_material, dk, 0);

    // Step 3: AFsplitter merge
    let mut candidate = [0u8; 64];
    af_merge(
        key_material,
        key_bytes,
        slot.af_stripes as usize,
        slot.af_hash_sha256,
        &mut candidate,
    );

    // Step 4: Verify master key via digest
    if digest_params.digest_type_pbkdf2 && digest_params.iterations > 0 {
        let mut verify_digest = [0u8; 32];
        let verify_len = digest_params.digest_len.min(32);

        if digest_params.hash_sha256 {
            pbkdf2_derive(
                &candidate[..key_bytes],
                &digest_params.salt[..digest_params.salt_len],
                digest_params.iterations,
                &mut verify_digest[..verify_len],
                true,
            );
        } else {
            let mut verify_20 = [0u8; 20];
            let vlen = verify_len.min(20);
            pbkdf2_derive(
                &candidate[..key_bytes],
                &digest_params.salt[..digest_params.salt_len],
                digest_params.iterations,
                &mut verify_20[..vlen],
                false,
            );
            verify_digest[..vlen].copy_from_slice(&verify_20[..vlen]);
        }

        if verify_digest[..digest_params.digest_len]
            != digest_params.digest[..digest_params.digest_len]
        {
            return None;
        }
    }

    let mut result = LuksDerivedKey {
        key: [0u8; 64],
        key_len: key_bytes,
        luks_sector_size: 512,
    };
    result.key[..key_bytes].copy_from_slice(&candidate[..key_bytes]);
    Some(result)
}

// ─── Unit tests ─────────────────────────────────────────────────────

#[cfg(test)]
#[cfg(all(feature = "decrypt", feature = "encrypt"))]
mod encrypt_tests {
    use super::*;
    extern crate alloc;
    use alloc::vec;

    #[test]
    fn test_aes_xts_encrypt_decrypt_roundtrip_128() {
        let key = [0x42u8; 32]; // AES-128-XTS: 16+16
        let original = [0xABu8; 512];
        let mut buf = original;
        aes_xts_encrypt(&mut buf, &key, 0);
        assert_ne!(buf, original, "encrypted data should differ");
        aes_xts_decrypt(&mut buf, &key, 0);
        assert_eq!(buf, original, "round-trip should recover original");
    }

    #[test]
    fn test_aes_xts_encrypt_decrypt_roundtrip_256() {
        let key = [0x55u8; 64]; // AES-256-XTS: 32+32
        let mut data = [0u8; 1024];
        for (i, b) in data.iter_mut().enumerate() {
            *b = (i & 0xFF) as u8;
        }
        let original = data;
        aes_xts_encrypt(&mut data, &key, 7);
        assert_ne!(data, original);
        aes_xts_decrypt(&mut data, &key, 7);
        assert_eq!(data, original);
    }

    #[test]
    fn test_af_split_merge_roundtrip() {
        let master_key = [
            0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A,
            0x0B, 0x0C, 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xA0, 0xB0, 0xC0,
            0xD0, 0xE0, 0xF0, 0xFF,
        ];
        let key_bytes = 32;
        let stripes = 10;
        let mut km_buf = vec![0x42u8; key_bytes * stripes];
        af_split(&master_key, key_bytes, stripes, true, &mut km_buf);
        let mut recovered = [0u8; 64];
        af_merge(&km_buf, key_bytes, stripes, true, &mut recovered);
        assert_eq!(
            &recovered[..key_bytes],
            &master_key[..],
            "af_split then af_merge should recover master key"
        );
    }

    #[test]
    fn test_build_v1_header_and_parse_roundtrip() {
        let master_key = [0x11u8; 64];
        let passphrase = b"test-passphrase";
        let mk_digest_salt = [0x22u8; 32];
        let slot_salt = [0x33u8; 32];
        let uuid = b"00000000-0000-4000-8000-000000000000";
        let key_bytes = 64;
        let stripes = LUKS_DEFAULT_STRIPES as usize;
        let af_random = vec![0x44u8; (stripes - 1) * key_bytes];
        let params = LuksV1BuildParams {
            master_key: &master_key,
            passphrase,
            iterations: 1,
            mk_digest_iterations: 1,
            mk_digest_salt: &mk_digest_salt,
            slot_salt: &slot_salt,
            af_random: &af_random,
            uuid: &uuid,
            use_sha256: true,
        };
        let mut out = vec![0u8; 4096 + key_bytes * stripes];
        let total = build_v1_header(&params, &mut out).expect("build should succeed");
        assert!(total > LUKS_V1_HEADER_SIZE);
        let parsed = parse_v1_header(&out).expect("parse should succeed");
        assert_eq!(parsed.version, 1);
        assert_eq!(parsed.key_bytes as usize, key_bytes);
        assert!(v1_is_aes_xts(&parsed));
        assert!(parsed.slots[0].active);
        assert_eq!(parsed.slots[0].stripes as usize, stripes);
        for i in 1..8 {
            assert!(!parsed.slots[i].active);
        }
    }

    #[test]
    fn test_build_v1_header_invalid_key_size() {
        let params = LuksV1BuildParams {
            master_key: &[0u8; 48],
            passphrase: b"test",
            iterations: 1,
            mk_digest_iterations: 1,
            mk_digest_salt: &[0u8; 32],
            slot_salt: &[0u8; 32],
            af_random: &[0u8; 1000],
            uuid: b"00000000-0000-4000-8000-000000000000",
            use_sha256: true,
        };
        let mut out = vec![0u8; 300000];
        assert!(build_v1_header(&params, &mut out).is_none());
    }
}
