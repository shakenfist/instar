//! Convert operation: read from any supported input format and write
//! to raw or QCOW2 output.
//!
//! Reads virtual content from an input image that may have a QCOW2
//! backing chain, and writes it to an output device in the requested
//! format. Compressed and standard clusters are handled transparently
//! via the shared qcow2 crate's chain-walking reader.
//!
//! Progress is reported via send_progress() and completion via
//! send_complete(). No special result message is needed (matching
//! qemu-img convert which produces no stdout on success).

#![no_std]
#![no_main]

extern crate alloc;

use core::panic::PanicInfo;

// Bump allocator backed by scratch memory for miniz_oxide compression
// and ruzstd ZSTD decoding. Reset HEAP_POS to 0 between operations.
shared::bump_allocator!();

use shared::{
    is_all_zeros_ptr, should_report_progress, validate_call_table, verify_sector_sizes, CallTable,
    ChainConfig, ConvertConfig, ImageFormat, ALLOC_HEAP_BASE, ARGON2_MEM_BASE, CALL_TABLE_ADDR,
    CHAIN_CONFIG_ADDR, COMPRESSED_BUF_SIZE, MAX_CHAIN_DEVICES, MAX_CLUSTER_SIZE, MAX_SECTOR_SIZE,
    OPERATION_CONFIG_ADDR, SCRATCH_MEM_BASE, SCRATCH_MEM_SIZE,
};

// LUKS key derivation is now in the luks crate

// ================================================================
// Scratch memory layout
// ================================================================
// Buffer sizes depend on the output cluster size (up to 2MB for
// QCOW2, MAX_SECTOR_SIZE for other formats). Layout computed at
// runtime via ScratchLayout::new().
//
//   BUF_COMPRESSED    (2MB+64KB): compressed input/output data
//   BUF_MULTIPURPOSE  (cluster_size): shared buffer for L2 table,
//                     header cluster, and refcount block (these
//                     are used in non-overlapping phases)
//   BUF_DATA          (cluster_size): input/output data buffer
//   DYNAMIC_START:    L1/L2 caches, staging buffer, L1 table, etc.
//
// For non-QCOW2 output, BUF_MULTIPURPOSE and BUF_DATA are
// MAX_SECTOR_SIZE (64KB), matching the previous fixed layout.
//
// Dynamic region: L1/L2 caches for input QCOW2 devices
//   (2 × MAX_SECTOR_SIZE per device)
//
// After dynamic caches: decompression staging buffer (2MB)
//   for compressed clusters larger than chunk_size
//
// After staging buffer: output L1 table (QCOW2 path only,
//   size computed at runtime)
//
// For compressed QCOW2 output (after L1 table):
//   Refcount array: u16 per host cluster, remaining scratch

/// Scratch memory layout computed from output cluster size.
struct ScratchLayout {
    /// Compressed input/output buffer (COMPRESSED_BUF_SIZE).
    buf_compressed: usize,
    /// Shared buffer for L2 table, header, and refcount block.
    /// Size = max(MAX_SECTOR_SIZE, output_cluster_size).
    buf_multipurpose: usize,
    /// Data buffer for reading/writing cluster data.
    /// Size = max(MAX_SECTOR_SIZE, output_cluster_size).
    buf_data: usize,
    /// Size of buf_multipurpose and buf_data.
    buf_size: usize,
    /// Start of dynamic allocations (caches, staging, L1, etc).
    dynamic_start: usize,
}

impl ScratchLayout {
    fn new(output_cluster_size: usize) -> Self {
        let buf_size = if output_cluster_size > MAX_SECTOR_SIZE {
            output_cluster_size
        } else {
            MAX_SECTOR_SIZE
        };
        let buf_compressed = SCRATCH_MEM_BASE;
        let buf_multipurpose = buf_compressed + COMPRESSED_BUF_SIZE;
        let buf_data = buf_multipurpose + buf_size;
        let dynamic_start = buf_data + buf_size;
        Self {
            buf_compressed,
            buf_multipurpose,
            buf_data,
            buf_size,
            dynamic_start,
        }
    }
}

// Verify worst-case layout fits: 2MB output clusters + 16 input
// devices + staging buffer.
const _: () = assert!(
    // BUF_COMPRESSED + BUF_MULTIPURPOSE(2MB) + BUF_DATA(2MB)
    // + 16 device caches + staging buffer
    SCRATCH_MEM_BASE
        + COMPRESSED_BUF_SIZE
        + MAX_CLUSTER_SIZE * 2
        + MAX_CHAIN_DEVICES * 2 * MAX_SECTOR_SIZE
        + MAX_CLUSTER_SIZE
        <= ALLOC_HEAP_BASE,
    "Scratch memory too small for max layout"
);

// ================================================================
// LUKS-wrapping-QCOW2: transparent decryption layer
// ================================================================
// When a native LUKS container wraps a QCOW2 image, we interpose on
// the CallTable read functions so that the QCOW2 chain reader
// transparently reads decrypted data. This avoids modifying the
// qcow2 crate at all — the function pointer replacement makes the
// inner QCOW2 look like a normal (unencrypted) device.

/// Static context for the LUKS read wrapper functions.
/// Only one LUKS-wrapped conversion can be active at a time (single-threaded guest).
static mut LUKS_WRAP_ORIG_READ: unsafe extern "C" fn(u32, u64, *mut u8, usize) -> bool = {
    unsafe extern "C" fn dummy(_: u32, _: u64, _: *mut u8, _: usize) -> bool {
        false
    }
    dummy
};
static mut LUKS_WRAP_ORIG_CAP: unsafe extern "C" fn(u32) -> u64 = {
    unsafe extern "C" fn dummy(_: u32) -> u64 {
        0
    }
    dummy
};
static mut LUKS_WRAP_KEY: [u8; 64] = [0u8; 64];
static mut LUKS_WRAP_KEY_LEN: usize = 0;
static mut LUKS_WRAP_LUKS_SECTOR_SIZE: u64 = 512;
static mut LUKS_WRAP_PAYLOAD_OFFSET: u64 = 0;
static mut LUKS_WRAP_INNER_SECTORS: u64 = 0;
static mut LUKS_WRAP_DEVICE_SECTOR_SIZE: usize = 0;

/// Wrapped read_input_sector: offsets and decrypts reads from device 0.
unsafe extern "C" fn luks_wrapped_read(
    device_idx: u32,
    sector: u64,
    buf: *mut u8,
    sector_size: usize,
) -> bool {
    if device_idx == 0 {
        let offset_sectors = LUKS_WRAP_PAYLOAD_OFFSET / LUKS_WRAP_DEVICE_SECTOR_SIZE as u64;
        if !LUKS_WRAP_ORIG_READ(device_idx, sector + offset_sectors, buf, sector_size) {
            return false;
        }
        // Decrypt in-place. IV is based on the byte offset within the
        // LUKS payload (= sector * sector_size for the inner device).
        let virtual_byte_offset = sector * sector_size as u64;
        qcow2::decrypt_cluster_aes_xts(
            buf,
            sector_size as u64,
            virtual_byte_offset,
            &LUKS_WRAP_KEY[..LUKS_WRAP_KEY_LEN],
            LUKS_WRAP_LUKS_SECTOR_SIZE,
        );
        true
    } else {
        LUKS_WRAP_ORIG_READ(device_idx, sector, buf, sector_size)
    }
}

/// Wrapped get_input_capacity: returns inner payload capacity for device 0.
unsafe extern "C" fn luks_wrapped_capacity(device_idx: u32) -> u64 {
    if device_idx == 0 {
        LUKS_WRAP_INNER_SECTORS
    } else {
        LUKS_WRAP_ORIG_CAP(device_idx)
    }
}

/// Entry point called by core after devices are initialized.
#[no_mangle]
pub unsafe extern "C" fn _start() -> u64 {
    let call_table = get_call_table();

    validate_call_table!(call_table, "convert");

    (call_table.verbose_print)(b"convert: start\n\0".as_ptr());

    // Read ConvertConfig
    let config_ptr = OPERATION_CONFIG_ADDR as *const ConvertConfig;
    let config = &*config_ptr;

    let (input_device_count, skip_zeros) = if config.is_valid() {
        (
            config.input_device_count() as usize,
            config.should_skip_zeros(),
        )
    } else {
        (1, false)
    };

    if input_device_count < 1 || input_device_count > MAX_CHAIN_DEVICES {
        (call_table.debug_print)(b"convert: invalid device count\n\0".as_ptr());
        (call_table.send_complete)(b"convert\0".as_ptr(), 0, false);
        return 0;
    }

    // Read ChainConfig
    let chain_config = &*(CHAIN_CONFIG_ADDR as *const ChainConfig);
    if !chain_config.is_valid() {
        (call_table.debug_print)(b"convert: missing chain config\n\0".as_ptr());
        (call_table.send_complete)(b"convert\0".as_ptr(), 0, false);
        return 0;
    }

    // Verify input sector sizes are consistent
    let sector_size = match verify_sector_sizes(call_table, input_device_count) {
        Some(ss) => ss,
        None => {
            (call_table.debug_print)(b"convert: sector size mismatch\n\0".as_ptr());
            (call_table.send_complete)(b"convert\0".as_ptr(), 0, false);
            return 0;
        }
    };

    let mut bytes_read: u64 = 0;

    // Compute scratch layout based on output cluster size.
    // For QCOW2 output, buffers scale with cluster size (up to 2MB).
    // For other formats, use MAX_SECTOR_SIZE (64KB).
    let output_cluster_size = if config.target_format() == ImageFormat::Qcow2 {
        1usize << config.output_cluster_bits()
    } else {
        MAX_SECTOR_SIZE
    };
    let layout = ScratchLayout::new(output_cluster_size);

    // Get virtual size from top-of-chain device
    let top_dev = &chain_config.devices[0];
    let virtual_size = top_dev.virtual_size;
    if virtual_size == 0 {
        (call_table.send_complete)(b"convert\0".as_ptr(), 0, false);
        return 0;
    }

    // Native LUKS container: decrypt and convert inner payload
    if top_dev.format == ImageFormat::Luks as u32 {
        if !config.has_passphrase() {
            (call_table.debug_print)(
                b"convert: LUKS container requires --luks-passphrase\n\0".as_ptr(),
            );
            (call_table.send_complete)(b"convert\0".as_ptr(), 0, false);
            return 0;
        }
        return convert_native_luks(
            call_table,
            config,
            sector_size,
            virtual_size,
            skip_zeros,
            &layout,
        );
    }

    (call_table.verbose_print)(b"convert: initializing chain states\n\0".as_ptr());

    // Initialize format-specific state for each input device
    let mut chain_states = qcow2::ChainStates::default();

    if !qcow2::init_chain_states(
        call_table,
        chain_config,
        &mut chain_states,
        input_device_count,
        sector_size,
        layout.dynamic_start,
        &mut bytes_read,
    ) {
        (call_table.debug_print)(b"convert: failed to init chain states\n\0".as_ptr());
        (call_table.send_complete)(b"convert\0".as_ptr(), bytes_read, false);
        return bytes_read;
    }

    // Reject QCOW2 images with unsupported incompatible features
    for state in chain_states.qcow2_states.iter().flatten() {
        let unsupported = state.unsupported_incompat_features(qcow2::SUPPORTED_INCOMPAT_FEATURES);
        if unsupported != 0 {
            (call_table.debug_print)(b"convert: unsupported incompatible features\n\0".as_ptr());
            (call_table.send_complete)(b"convert\0".as_ptr(), bytes_read, false);
            return bytes_read;
        }
    }

    // Construct AES key from passphrase if provided (for QCOW2 crypt_method=1)
    let aes_key: Option<[u8; 16]> = if config.has_passphrase() {
        let mut key = [0u8; 16];
        let pass = config.passphrase_bytes();
        let copy_len = if pass.len() < 16 { pass.len() } else { 16 };
        key[..copy_len].copy_from_slice(&pass[..copy_len]);
        Some(key)
    } else {
        None
    };

    // LUKS master key for crypt_method=2 (derived later if needed)
    let mut luks_master_key = [0u8; 64];
    let mut luks_master_key_len: usize = 0;
    let mut luks_sector_size: u64 = 512;

    // Derive LUKS master key if top-of-chain is encrypted QCOW2 (crypt_method=2)
    if let Some(ref state) = chain_states.qcow2_states[0] {
        if state.crypt_method == 2 && config.has_passphrase() {
            if state.luks_ext_offset == 0 || state.luks_ext_len == 0 {
                (call_table.debug_print)(
                    b"convert: crypt_method=2 but no LUKS extension found\n\0".as_ptr(),
                );
                (call_table.send_complete)(b"convert\0".as_ptr(), bytes_read, false);
                return bytes_read;
            }

            let result = derive_luks_master_key(
                call_table,
                state.device_idx,
                state.luks_ext_offset,
                state.luks_ext_len,
                config.passphrase_bytes(),
                sector_size,
                &mut luks_master_key,
                &mut bytes_read,
            );
            match result {
                Some((key_len, sec_size)) => {
                    luks_master_key_len = key_len;
                    luks_sector_size = sec_size;
                    (call_table.verbose_print)(
                        b"convert: LUKS master key derived successfully\n\0".as_ptr(),
                    );
                }
                None => {
                    (call_table.debug_print)(b"convert: LUKS key derivation failed\n\0".as_ptr());
                    (call_table.send_complete)(b"convert\0".as_ptr(), bytes_read, false);
                    return bytes_read;
                }
            }
        } else if state.crypt_method == 2 && !config.has_passphrase() {
            (call_table.debug_print)(
                b"convert: LUKS-encrypted QCOW2 requires --luks-passphrase\n\0".as_ptr(),
            );
            (call_table.send_complete)(b"convert\0".as_ptr(), bytes_read, false);
            return bytes_read;
        }
    }

    // If a snapshot ID was specified, find the snapshot and override L1 table
    if config.has_snapshot_id() {
        let snap_id = config.snapshot_id_bytes();
        // The top-of-chain device must be QCOW2 with snapshots
        if let Some(ref mut qcow2_state) = chain_states.qcow2_states[0] {
            // Read nb_snapshots and snapshots_offset from header
            let nb_snapshots = match qcow2::read_u32_be_cached(
                call_table,
                0,
                qcow2::NB_SNAPSHOTS_OFFSET as u64,
                sector_size,
                (call_table.get_input_capacity)(0),
                &mut qcow2_state.l1_cached_sector,
                qcow2_state.l1_cache_buf,
                &mut bytes_read,
            ) {
                Some(v) => v,
                None => {
                    (call_table.debug_print)(
                        b"convert: failed to read snapshot count\n\0".as_ptr(),
                    );
                    (call_table.send_complete)(b"convert\0".as_ptr(), bytes_read, false);
                    return bytes_read;
                }
            };
            let snapshots_offset = match qcow2::read_u64_be_cached(
                call_table,
                0,
                qcow2::SNAPSHOTS_OFFSET_OFFSET as u64,
                sector_size,
                (call_table.get_input_capacity)(0),
                &mut qcow2_state.l1_cached_sector,
                qcow2_state.l1_cache_buf,
                &mut bytes_read,
            ) {
                Some(v) => v,
                None => {
                    (call_table.debug_print)(
                        b"convert: failed to read snapshot offset\n\0".as_ptr(),
                    );
                    (call_table.send_complete)(b"convert\0".as_ptr(), bytes_read, false);
                    return bytes_read;
                }
            };

            if nb_snapshots == 0 {
                (call_table.debug_print)(b"convert: no snapshots in image\n\0".as_ptr());
                (call_table.send_complete)(b"convert\0".as_ptr(), bytes_read, false);
                return bytes_read;
            }

            // Use L2 cache buffer as scratch for snapshot parsing
            let snap_cache = qcow2_state.l2_cache_buf;
            let snap_table = qcow2::parse_snapshot_table(
                call_table,
                0,
                nb_snapshots,
                snapshots_offset,
                sector_size,
                (call_table.get_input_capacity)(0),
                snap_cache,
                &mut bytes_read,
            );
            // Invalidate L2 cache since we used it as scratch
            qcow2_state.l2_cached_sector = u64::MAX;

            match qcow2::find_snapshot(&snap_table, snap_id) {
                Some(idx) => {
                    let snap = &snap_table.entries[idx];
                    qcow2_state.l1_table_offset = snap.l1_table_offset;
                    qcow2_state.l1_size = snap.l1_size;
                    // Invalidate L1 cache since we changed L1 table
                    qcow2_state.l1_cached_sector = u64::MAX;
                    (call_table.verbose_print)(b"convert: using snapshot L1 table\n\0".as_ptr());
                }
                None => {
                    (call_table.debug_print)(b"convert: snapshot not found\n\0".as_ptr());
                    (call_table.send_complete)(b"convert\0".as_ptr(), bytes_read, false);
                    return bytes_read;
                }
            }
        } else {
            (call_table.debug_print)(b"convert: snapshot requires QCOW2 input\n\0".as_ptr());
            (call_table.send_complete)(b"convert\0".as_ptr(), bytes_read, false);
            return bytes_read;
        }
    }

    // Construct LUKS key slice if master key was derived
    let luks_key: Option<&[u8]> = if luks_master_key_len > 0 {
        Some(&luks_master_key[..luks_master_key_len])
    } else {
        None
    };

    // Dispatch based on target format
    let target = config.target_format();
    match target {
        ImageFormat::Qcow2 => {
            if config.should_compress() {
                convert_to_qcow2_compressed(
                    call_table,
                    config,
                    chain_config,
                    &mut chain_states,
                    input_device_count,
                    virtual_size,
                    sector_size,
                    skip_zeros,
                    aes_key.as_ref(),
                    luks_key,
                    luks_sector_size,
                    &mut bytes_read,
                    &layout,
                )
            } else {
                convert_to_qcow2(
                    call_table,
                    config,
                    chain_config,
                    &mut chain_states,
                    input_device_count,
                    virtual_size,
                    sector_size,
                    skip_zeros,
                    aes_key.as_ref(),
                    luks_key,
                    luks_sector_size,
                    &mut bytes_read,
                    &layout,
                )
            }
        }
        ImageFormat::Vmdk4 => {
            if config.should_compress() {
                convert_to_vmdk_compressed(
                    call_table,
                    chain_config,
                    &mut chain_states,
                    input_device_count,
                    virtual_size,
                    sector_size,
                    skip_zeros,
                    aes_key.as_ref(),
                    luks_key,
                    luks_sector_size,
                    &mut bytes_read,
                    &layout,
                )
            } else {
                convert_to_vmdk(
                    call_table,
                    chain_config,
                    &mut chain_states,
                    input_device_count,
                    virtual_size,
                    sector_size,
                    skip_zeros,
                    aes_key.as_ref(),
                    luks_key,
                    luks_sector_size,
                    &mut bytes_read,
                    &layout,
                )
            }
        }
        ImageFormat::Vhd => convert_to_vhd(
            call_table,
            chain_config,
            &mut chain_states,
            input_device_count,
            virtual_size,
            sector_size,
            skip_zeros,
            aes_key.as_ref(),
            luks_key,
            luks_sector_size,
            &mut bytes_read,
            &layout,
        ),
        ImageFormat::Vhdx => convert_to_vhdx(
            call_table,
            chain_config,
            &mut chain_states,
            input_device_count,
            virtual_size,
            sector_size,
            skip_zeros,
            aes_key.as_ref(),
            luks_key,
            luks_sector_size,
            &mut bytes_read,
            &layout,
        ),
        _ => convert_to_raw(
            call_table,
            chain_config,
            &mut chain_states,
            input_device_count,
            virtual_size,
            sector_size,
            skip_zeros,
            aes_key.as_ref(),
            luks_key,
            luks_sector_size,
            &mut bytes_read,
            &layout,
        ),
    }
}

// ================================================================
// Native LUKS container conversion (decrypt + output raw)
// ================================================================

/// Convert a native LUKS container to raw by decrypting the payload area.
///
/// Reads the LUKS header from device 0 at offset 0, derives the master key,
/// then reads the payload area sector by sector, decrypts with AES-XTS
/// (plain64 IV), and writes to the output device.
///
/// Supports LUKS v1 (PBKDF2) and LUKS v2 (Argon2id) with raw inner format.
/// The output is always raw regardless of the target_format setting.
unsafe fn convert_native_luks(
    call_table: &CallTable,
    config: &ConvertConfig,
    sector_size: usize,
    virtual_size: u64,
    skip_zeros: bool,
    layout: &ScratchLayout,
) -> u64 {
    let mut bytes_read: u64 = 0;

    (call_table.verbose_print)(b"convert: native LUKS container detected\n\0".as_ptr());

    // Read first sector to detect LUKS version
    let mut hdr_buf = [0u8; MAX_SECTOR_SIZE];
    if !(call_table.read_input_sector)(0, 0, hdr_buf.as_mut_ptr(), sector_size) {
        (call_table.debug_print)(b"convert: failed to read LUKS header\n\0".as_ptr());
        (call_table.send_complete)(b"convert\0".as_ptr(), bytes_read, false);
        return bytes_read;
    }
    bytes_read += sector_size as u64;

    let luks_version = match luks::get_version(&hdr_buf) {
        Some(v) => v,
        None => {
            (call_table.debug_print)(b"convert: invalid LUKS magic\n\0".as_ptr());
            (call_table.send_complete)(b"convert\0".as_ptr(), bytes_read, false);
            return bytes_read;
        }
    };

    let mut luks_master_key = [0u8; 64];
    let (key_len, luks_sector_size, payload_byte_offset);

    if luks_version == 1 {
        // LUKS v1: derive master key via PBKDF2
        let result = derive_luks_master_key(
            call_table,
            0, // device index
            0, // LUKS header at offset 0
            luks::LUKS_V1_HEADER_SIZE as u64,
            config.passphrase_bytes(),
            sector_size,
            &mut luks_master_key,
            &mut bytes_read,
        );

        let (kl, ls) = match result {
            Some(v) => v,
            None => {
                (call_table.debug_print)(b"convert: LUKS v1 key derivation failed\n\0".as_ptr());
                (call_table.send_complete)(b"convert\0".as_ptr(), bytes_read, false);
                return bytes_read;
            }
        };
        key_len = kl;
        luks_sector_size = ls;

        // Read payload offset from LUKS v1 header (512-byte sectors)
        let payload_offset_sectors = u32::from_be_bytes([
            hdr_buf[luks::LUKS_PAYLOAD_OFFSET_OFFSET],
            hdr_buf[luks::LUKS_PAYLOAD_OFFSET_OFFSET + 1],
            hdr_buf[luks::LUKS_PAYLOAD_OFFSET_OFFSET + 2],
            hdr_buf[luks::LUKS_PAYLOAD_OFFSET_OFFSET + 3],
        ]) as u64;
        payload_byte_offset = payload_offset_sectors * 512;
    } else if luks_version == 2 {
        // LUKS v2: derive master key via Argon2id
        let result = derive_luks_v2_master_key(
            call_table,
            config,
            sector_size,
            &mut luks_master_key,
            &mut bytes_read,
        );

        let (kl, ls, pbo) = match result {
            Some(v) => v,
            None => {
                (call_table.debug_print)(b"convert: LUKS v2 key derivation failed\n\0".as_ptr());
                (call_table.send_complete)(b"convert\0".as_ptr(), bytes_read, false);
                return bytes_read;
            }
        };
        key_len = kl;
        luks_sector_size = ls;
        payload_byte_offset = pbo;
    } else {
        (call_table.debug_print)(b"convert: unsupported LUKS version\n\0".as_ptr());
        (call_table.send_complete)(b"convert\0".as_ptr(), bytes_read, false);
        return bytes_read;
    }

    (call_table.verbose_print)(b"convert: LUKS master key derived\n\0".as_ptr());

    let luks_key = &luks_master_key[..key_len];
    let input_capacity = (call_table.get_input_capacity)(0);

    // Compute the inner payload size. Use the chain virtual_size
    // (from info) as the primary size, but cap at the device capacity
    // minus the payload offset to avoid reading past the device.
    let input_bytes = input_capacity * sector_size as u64;
    let capacity_based_size = if input_bytes > payload_byte_offset {
        input_bytes - payload_byte_offset
    } else {
        0
    };
    let inner_size = if capacity_based_size > 0 && virtual_size > capacity_based_size {
        capacity_based_size
    } else {
        virtual_size
    };

    // Detect inner format by decrypting first sector of payload
    {
        let buf = layout.buf_data as *mut u8;
        let payload_sector = payload_byte_offset / sector_size as u64;
        if payload_sector < input_capacity
            && (call_table.read_input_sector)(0, payload_sector, buf, sector_size)
        {
            let offset_in_sector = (payload_byte_offset % sector_size as u64) as usize;
            // Decrypt the sector to inspect the inner header
            qcow2::decrypt_cluster_aes_xts(
                buf,
                sector_size as u64,
                0, // IV starts at 0 (first payload sector)
                luks_key,
                luks_sector_size,
            );
            bytes_read += sector_size as u64;

            // Check for QCOW2 magic at the start of the decrypted payload
            if offset_in_sector + 4 <= sector_size {
                let p = buf.add(offset_in_sector);
                let magic = u32::from_be_bytes([*p, *p.add(1), *p.add(2), *p.add(3)]);
                if magic == qcow2::QCOW2_MAGIC {
                    (call_table.verbose_print)(
                        b"convert: inner format is QCOW2, switching to chain reader\n\0".as_ptr(),
                    );
                    return convert_luks_wrapped_qcow2(
                        call_table,
                        config,
                        sector_size,
                        &luks_master_key,
                        key_len,
                        luks_sector_size,
                        payload_byte_offset,
                        inner_size,
                        skip_zeros,
                        &mut bytes_read,
                        layout,
                    );
                }
            }
        }
    }

    (call_table.verbose_print)(b"convert: starting LUKS decryption\n\0".as_ptr());

    // Read payload sequentially, decrypt, write to output
    let output_sector_size = (call_table.get_output_sector_size)();
    let progress_interval = (call_table.get_progress_interval)();

    // Use sector_size as the chunk size for reading
    let chunk_size = sector_size as u64;
    let buf = layout.buf_data as *mut u8;
    let mut payload_offset: u64 = 0;
    let mut last_percent: u32 = 0;
    let mut chunks_done: u64 = 0;
    let total_chunks = (inner_size + chunk_size - 1) / chunk_size;

    while payload_offset < inner_size {
        let remaining = inner_size - payload_offset;
        let this_chunk = if remaining < chunk_size {
            remaining
        } else {
            chunk_size
        };

        // Read the encrypted sector from the payload area
        let physical_byte_offset = payload_byte_offset + payload_offset;
        let read_sector = physical_byte_offset / sector_size as u64;

        if read_sector >= input_capacity {
            // Past end of device, fill with zeros
            core::ptr::write_bytes(buf, 0, this_chunk as usize);
        } else {
            if !(call_table.read_input_sector)(0, read_sector, buf, sector_size) {
                (call_table.send_error)(b"convert\0".as_ptr(), b"input\0".as_ptr(), read_sector, 1);
                (call_table.send_complete)(b"convert\0".as_ptr(), bytes_read, false);
                return bytes_read;
            }
            bytes_read += sector_size as u64;

            // Handle sub-sector offset if payload doesn't start on sector boundary
            let offset_in_sector = (physical_byte_offset % sector_size as u64) as usize;
            if offset_in_sector != 0 {
                // Shift data to start of buffer
                core::ptr::copy(buf.add(offset_in_sector), buf, this_chunk as usize);
            }

            // Decrypt the sector using AES-XTS with plain64 IV.
            // For native LUKS, the IV is the sector number relative to
            // the start of the payload area.
            qcow2::decrypt_cluster_aes_xts(
                buf,
                this_chunk,
                payload_offset,
                luks_key,
                luks_sector_size,
            );
        }

        // Skip zero-filled sectors
        if skip_zeros && is_all_zeros_ptr(buf, this_chunk as usize) {
            payload_offset += this_chunk;
            chunks_done += 1;
            let percent = (chunks_done * 100 / total_chunks) as u32;
            if should_report_progress(progress_interval, percent, last_percent, chunks_done) {
                (call_table.send_progress)(
                    b"convert\0".as_ptr(),
                    chunks_done,
                    total_chunks,
                    percent,
                );
                last_percent = percent;
            }
            continue;
        }

        // Write decrypted data to output
        let output_first_sector = payload_offset / output_sector_size as u64;
        let sectors_per_chunk =
            (this_chunk + output_sector_size as u64 - 1) / output_sector_size as u64;

        for s in 0..sectors_per_chunk {
            let sector_offset = s * output_sector_size as u64;
            let write_len = core::cmp::min(output_sector_size as u64, this_chunk - sector_offset);
            if write_len > 0 {
                if !(call_table.write_output_sector)(
                    output_first_sector + s,
                    buf.add(sector_offset as usize),
                    write_len as usize,
                ) {
                    (call_table.send_error)(
                        b"convert\0".as_ptr(),
                        b"output\0".as_ptr(),
                        output_first_sector + s,
                        1,
                    );
                    (call_table.send_complete)(b"convert\0".as_ptr(), bytes_read, false);
                    return bytes_read;
                }
            }
        }

        payload_offset += this_chunk;
        chunks_done += 1;
        let percent = (chunks_done * 100 / total_chunks) as u32;
        if should_report_progress(progress_interval, percent, last_percent, chunks_done) {
            (call_table.send_progress)(b"convert\0".as_ptr(), chunks_done, total_chunks, percent);
            last_percent = percent;
        }
    }

    (call_table.send_complete)(b"convert\0".as_ptr(), bytes_read, true);
    (call_table.verbose_print)(b"convert: done\n\0".as_ptr());
    bytes_read
}

// ================================================================
// LUKS-wrapping-QCOW2 conversion
// ================================================================

/// Convert a LUKS container whose inner payload is a QCOW2 image.
///
/// Sets up transparent decryption via function pointer wrapping in
/// the CallTable, then delegates to the normal QCOW2 chain reader
/// and output conversion path.
#[allow(clippy::too_many_arguments)]
unsafe fn convert_luks_wrapped_qcow2(
    call_table: &CallTable,
    config: &ConvertConfig,
    sector_size: usize,
    luks_key: &[u8; 64],
    key_len: usize,
    luks_sector_size: u64,
    payload_byte_offset: u64,
    inner_payload_size: u64,
    skip_zeros: bool,
    bytes_read: &mut u64,
    layout: &ScratchLayout,
) -> u64 {
    // Set up the static LUKS wrapper context
    LUKS_WRAP_ORIG_READ = call_table.read_input_sector;
    LUKS_WRAP_ORIG_CAP = call_table.get_input_capacity;
    LUKS_WRAP_KEY[..key_len].copy_from_slice(&luks_key[..key_len]);
    LUKS_WRAP_KEY_LEN = key_len;
    LUKS_WRAP_LUKS_SECTOR_SIZE = luks_sector_size;
    LUKS_WRAP_PAYLOAD_OFFSET = payload_byte_offset;
    LUKS_WRAP_INNER_SECTORS = inner_payload_size / sector_size as u64;
    LUKS_WRAP_DEVICE_SECTOR_SIZE = sector_size;

    // Create a wrapped call table with decryption-aware read functions
    let mut wrapped_ct: CallTable = core::ptr::read(call_table);
    wrapped_ct.read_input_sector = luks_wrapped_read;
    wrapped_ct.get_input_capacity = luks_wrapped_capacity;

    // Read the inner QCOW2 header via the wrapped (decrypted) read path
    let mut hdr_buf = [0u8; MAX_SECTOR_SIZE];
    if !(wrapped_ct.read_input_sector)(0, 0, hdr_buf.as_mut_ptr(), sector_size) {
        (call_table.debug_print)(b"convert: failed to read inner QCOW2 header\n\0".as_ptr());
        (call_table.send_complete)(b"convert\0".as_ptr(), *bytes_read, false);
        return *bytes_read;
    }
    *bytes_read += sector_size as u64;

    // Parse virtual_size and cluster_bits from QCOW2 header
    let inner_virtual_size = u64::from_be_bytes([
        hdr_buf[24],
        hdr_buf[25],
        hdr_buf[26],
        hdr_buf[27],
        hdr_buf[28],
        hdr_buf[29],
        hdr_buf[30],
        hdr_buf[31],
    ]);
    let cluster_bits = u32::from_be_bytes([hdr_buf[20], hdr_buf[21], hdr_buf[22], hdr_buf[23]]);

    if inner_virtual_size == 0 || cluster_bits < 9 || cluster_bits > 21 {
        (call_table.debug_print)(b"convert: invalid inner QCOW2 header\n\0".as_ptr());
        (call_table.send_complete)(b"convert\0".as_ptr(), *bytes_read, false);
        return *bytes_read;
    }

    // Build a chain config for the inner QCOW2
    let chain_config = &*(CHAIN_CONFIG_ADDR as *mut ChainConfig);
    let orig_format = chain_config.devices[0].format;
    let orig_virtual_size = chain_config.devices[0].virtual_size;
    let orig_cluster_size = chain_config.devices[0].cluster_size;

    // Temporarily modify device 0 to look like QCOW2
    let chain_config_mut = &mut *(CHAIN_CONFIG_ADDR as *mut ChainConfig);
    chain_config_mut.devices[0].format = ImageFormat::Qcow2 as u32;
    chain_config_mut.devices[0].virtual_size = inner_virtual_size;
    chain_config_mut.devices[0].cluster_size = 1u32 << cluster_bits;

    // Initialize QCOW2 chain states using the wrapped call table
    let mut chain_states = qcow2::ChainStates::default();
    if !qcow2::init_chain_states(
        &wrapped_ct,
        chain_config_mut,
        &mut chain_states,
        1,
        sector_size,
        layout.dynamic_start,
        bytes_read,
    ) {
        (call_table.debug_print)(b"convert: failed to init inner QCOW2 chain states\n\0".as_ptr());
        // Restore original chain config
        chain_config_mut.devices[0].format = orig_format;
        chain_config_mut.devices[0].virtual_size = orig_virtual_size;
        chain_config_mut.devices[0].cluster_size = orig_cluster_size;
        (call_table.send_complete)(b"convert\0".as_ptr(), *bytes_read, false);
        return *bytes_read;
    }

    // Reject unsupported incompatible features
    for state in chain_states.qcow2_states.iter().flatten() {
        let unsupported = state.unsupported_incompat_features(qcow2::SUPPORTED_INCOMPAT_FEATURES);
        if unsupported != 0 {
            (call_table.debug_print)(b"convert: inner QCOW2 has unsupported features\n\0".as_ptr());
            chain_config_mut.devices[0].format = orig_format;
            chain_config_mut.devices[0].virtual_size = orig_virtual_size;
            chain_config_mut.devices[0].cluster_size = orig_cluster_size;
            (call_table.send_complete)(b"convert\0".as_ptr(), *bytes_read, false);
            return *bytes_read;
        }
    }

    (call_table.verbose_print)(b"convert: converting inner QCOW2 via chain reader\n\0".as_ptr());

    // Dispatch based on target format (same logic as main path)
    let target = config.target_format();
    let result = match target {
        ImageFormat::Qcow2 => {
            if config.should_compress() {
                convert_to_qcow2_compressed(
                    &wrapped_ct,
                    config,
                    chain_config_mut,
                    &mut chain_states,
                    1,
                    inner_virtual_size,
                    sector_size,
                    skip_zeros,
                    None,
                    None,
                    512,
                    bytes_read,
                    layout,
                )
            } else {
                convert_to_qcow2(
                    &wrapped_ct,
                    config,
                    chain_config_mut,
                    &mut chain_states,
                    1,
                    inner_virtual_size,
                    sector_size,
                    skip_zeros,
                    None,
                    None,
                    512,
                    bytes_read,
                    layout,
                )
            }
        }
        ImageFormat::Vmdk4 => {
            if config.should_compress() {
                convert_to_vmdk_compressed(
                    &wrapped_ct,
                    chain_config_mut,
                    &mut chain_states,
                    1,
                    inner_virtual_size,
                    sector_size,
                    skip_zeros,
                    None,
                    None,
                    512,
                    bytes_read,
                    layout,
                )
            } else {
                convert_to_vmdk(
                    &wrapped_ct,
                    chain_config_mut,
                    &mut chain_states,
                    1,
                    inner_virtual_size,
                    sector_size,
                    skip_zeros,
                    None,
                    None,
                    512,
                    bytes_read,
                    layout,
                )
            }
        }
        ImageFormat::Vhd => convert_to_vhd(
            &wrapped_ct,
            chain_config_mut,
            &mut chain_states,
            1,
            inner_virtual_size,
            sector_size,
            skip_zeros,
            None,
            None,
            512,
            bytes_read,
            layout,
        ),
        ImageFormat::Vhdx => convert_to_vhdx(
            &wrapped_ct,
            chain_config_mut,
            &mut chain_states,
            1,
            inner_virtual_size,
            sector_size,
            skip_zeros,
            None,
            None,
            512,
            bytes_read,
            layout,
        ),
        _ => convert_to_raw(
            &wrapped_ct,
            chain_config_mut,
            &mut chain_states,
            1,
            inner_virtual_size,
            sector_size,
            skip_zeros,
            None,
            None,
            512,
            bytes_read,
            layout,
        ),
    };

    // Restore original chain config
    chain_config_mut.devices[0].format = orig_format;
    chain_config_mut.devices[0].virtual_size = orig_virtual_size;
    chain_config_mut.devices[0].cluster_size = orig_cluster_size;

    result
}

// ================================================================
// LUKS-in-QCOW2 key derivation (crypt_method=2)
// ================================================================

/// Derive LUKS v1 master key from an embedded LUKS header in QCOW2.
///
/// Reads the LUKS binary header and key material from the QCOW2 LUKS
/// extension area, then delegates to the luks crate for PBKDF2 key
/// derivation, AES-XTS decryption, AFsplitter merge, and verification.
///
/// Returns (key_len, luks_sector_size) on success. The derived key is
/// written to `out_key` (up to 64 bytes).
unsafe fn derive_luks_master_key(
    call_table: &CallTable,
    device_idx: u32,
    luks_ext_offset: u64,
    _luks_ext_len: u64,
    passphrase: &[u8],
    sector_size: usize,
    out_key: &mut [u8; 64],
    bytes_read: &mut u64,
) -> Option<(usize, u64)> {
    // Read the LUKS binary header from the extension area
    let mut hdr_buf = [0u8; luks::LUKS_V1_HEADER_SIZE];

    let hdr_start_sector = luks_ext_offset / sector_size as u64;
    let hdr_offset_in_sector = (luks_ext_offset % sector_size as u64) as usize;
    let mut sector_buf = [0u8; MAX_SECTOR_SIZE];
    let mut hdr_pos = 0usize;

    while hdr_pos < luks::LUKS_V1_HEADER_SIZE {
        let cur_sector =
            hdr_start_sector + (hdr_offset_in_sector + hdr_pos) as u64 / sector_size as u64;
        let off_in_sec = (hdr_offset_in_sector + hdr_pos) % sector_size;
        if !(call_table.read_input_sector)(
            device_idx,
            cur_sector,
            sector_buf.as_mut_ptr(),
            sector_size,
        ) {
            (call_table.debug_print)(b"luks-qcow2: failed to read LUKS header\n\0".as_ptr());
            return None;
        }
        *bytes_read += sector_size as u64;
        let avail = sector_size - off_in_sec;
        let needed = luks::LUKS_V1_HEADER_SIZE - hdr_pos;
        let to_copy = avail.min(needed);
        hdr_buf[hdr_pos..hdr_pos + to_copy]
            .copy_from_slice(&sector_buf[off_in_sec..off_in_sec + to_copy]);
        hdr_pos += to_copy;
    }

    // Parse header using luks crate
    let parsed = match luks::parse_v1_header(&hdr_buf) {
        Some(h) => h,
        None => {
            (call_table.debug_print)(b"luks-qcow2: bad LUKS header\n\0".as_ptr());
            return None;
        }
    };

    if !luks::v1_is_aes_xts(&parsed) {
        (call_table.debug_print)(b"luks-qcow2: unsupported cipher/mode\n\0".as_ptr());
        return None;
    }

    let key_bytes = parsed.key_bytes as usize;
    if key_bytes != 32 && key_bytes != 64 {
        (call_table.debug_print)(b"luks-qcow2: unsupported key size\n\0".as_ptr());
        return None;
    }

    let slot_idx = match luks::find_active_v1_slot(&parsed) {
        Some(i) => i,
        None => {
            (call_table.debug_print)(b"luks-qcow2: no active key slot\n\0".as_ptr());
            return None;
        }
    };

    (call_table.verbose_print)(b"luks-qcow2: reading key material\n\0".as_ptr());

    // Read encrypted key material from LUKS extension
    let (km_byte_offset_rel, km_total_bytes) =
        match luks::v1_key_material_region(&parsed.slots[slot_idx], parsed.key_bytes) {
            Some(v) => v,
            None => {
                (call_table.debug_print)(b"luks-qcow2: key material too large\n\0".as_ptr());
                return None;
            }
        };

    if km_total_bytes == 0 || km_total_bytes > SCRATCH_MEM_SIZE {
        (call_table.debug_print)(b"luks-qcow2: key material too large\n\0".as_ptr());
        return None;
    }

    let km_buf = core::slice::from_raw_parts_mut(SCRATCH_MEM_BASE as *mut u8, km_total_bytes);
    let km_byte_offset = luks_ext_offset + km_byte_offset_rel;
    let km_start_sector = km_byte_offset / sector_size as u64;
    let km_end_byte = km_byte_offset + km_total_bytes as u64;
    let km_end_sector = (km_end_byte + sector_size as u64 - 1) / sector_size as u64;
    let km_sectors_needed = (km_end_sector - km_start_sector) as usize;

    let mut km_pos = 0usize;
    for s in 0..km_sectors_needed {
        let sector_idx = km_start_sector + s as u64;
        if !(call_table.read_input_sector)(
            device_idx,
            sector_idx,
            sector_buf.as_mut_ptr(),
            sector_size,
        ) {
            (call_table.debug_print)(b"luks-qcow2: failed to read key material\n\0".as_ptr());
            return None;
        }
        *bytes_read += sector_size as u64;
        let off_in_sec = if s == 0 {
            (km_byte_offset % sector_size as u64) as usize
        } else {
            0
        };
        let avail = sector_size - off_in_sec;
        let to_copy = avail.min(km_total_bytes - km_pos);
        km_buf[km_pos..km_pos + to_copy]
            .copy_from_slice(&sector_buf[off_in_sec..off_in_sec + to_copy]);
        km_pos += to_copy;
        if km_pos >= km_total_bytes {
            break;
        }
    }

    (call_table.verbose_print)(b"luks-qcow2: deriving master key\n\0".as_ptr());

    // Derive master key using the luks crate (PBKDF2 + AES-XTS + AFsplit + verify)
    let derived = match luks::derive_v1_master_key(&parsed, passphrase, km_buf) {
        Some(d) => d,
        None => {
            (call_table.debug_print)(b"luks-qcow2: master key verification failed\n\0".as_ptr());
            return None;
        }
    };

    (call_table.verbose_print)(b"luks-qcow2: master key verified\n\0".as_ptr());

    out_key[..derived.key_len].copy_from_slice(&derived.key[..derived.key_len]);
    Some((derived.key_len, derived.luks_sector_size))
}

// ================================================================
// Native LUKS v2 key derivation (Argon2id)
// ================================================================

/// Derive LUKS v2 master key from a native LUKS v2 container.
///
/// Reads the JSON metadata area, parses keyslot and digest parameters,
/// then uses Argon2id key derivation via the luks crate.
///
/// Returns (key_len, luks_sector_size, payload_byte_offset) on success.
/// The derived key is written to `out_key` (up to 64 bytes).
unsafe fn derive_luks_v2_master_key(
    call_table: &CallTable,
    config: &ConvertConfig,
    sector_size: usize,
    out_key: &mut [u8; 64],
    bytes_read: &mut u64,
) -> Option<(usize, u64, u64)> {
    if config.argon2_mem_size == 0 {
        (call_table.debug_print)(
            b"convert: LUKS v2 requires --max-guest-memory for Argon2id\n\0".as_ptr(),
        );
        return None;
    }

    // Read JSON metadata area (starts at 4KB, scan up to 16KB)
    let json_buf =
        core::slice::from_raw_parts_mut(SCRATCH_MEM_BASE as *mut u8, luks::LUKS2_JSON_SCAN_SIZE);
    let json_start_sector = luks::LUKS2_BINARY_HEADER_SIZE / sector_size;
    let sectors_to_read = luks::LUKS2_JSON_SCAN_SIZE / sector_size;
    let mut json_bytes_read = 0usize;

    // For large sector sizes (>= 4KB), the JSON may be in the first sector
    if sector_size >= luks::LUKS2_BINARY_HEADER_SIZE {
        // Re-read sector 0 which contains both binary header and start of JSON
        let mut sector_buf = [0u8; MAX_SECTOR_SIZE];
        if !(call_table.read_input_sector)(0, 0, sector_buf.as_mut_ptr(), sector_size) {
            (call_table.debug_print)(b"convert: failed to read LUKS v2 header\n\0".as_ptr());
            return None;
        }
        *bytes_read += sector_size as u64;
        let json_offset = luks::LUKS2_BINARY_HEADER_SIZE;
        let avail = sector_size - json_offset;
        let to_copy = avail.min(luks::LUKS2_JSON_SCAN_SIZE);
        json_buf[..to_copy].copy_from_slice(&sector_buf[json_offset..json_offset + to_copy]);
        json_bytes_read = to_copy;
    } else {
        for i in 0..sectors_to_read {
            let sector = (json_start_sector + i) as u64;
            let offset = i * sector_size;
            if !(call_table.read_input_sector)(
                0,
                sector,
                json_buf[offset..].as_mut_ptr(),
                sector_size,
            ) {
                break;
            }
            *bytes_read += sector_size as u64;
            json_bytes_read = offset + sector_size;
        }
    }

    if json_bytes_read == 0 {
        (call_table.debug_print)(b"convert: failed to read LUKS v2 JSON area\n\0".as_ptr());
        return None;
    }

    // Find null terminator in JSON data
    let json_len = json_buf[..json_bytes_read]
        .iter()
        .position(|&b| b == 0)
        .unwrap_or(json_bytes_read);
    let json = &json_buf[..json_len];

    // Parse keyslot and digest parameters
    let slot = match luks::parse_v2_keyslot(json) {
        Some(s) => s,
        None => {
            (call_table.debug_print)(b"convert: failed to parse LUKS v2 keyslot\n\0".as_ptr());
            return None;
        }
    };

    let digest_params = match luks::parse_v2_digest(json) {
        Some(d) => d,
        None => {
            (call_table.debug_print)(b"convert: failed to parse LUKS v2 digest\n\0".as_ptr());
            return None;
        }
    };

    let key_bytes = slot.key_size as usize;
    if key_bytes != 32 && key_bytes != 64 {
        (call_table.debug_print)(b"convert: unsupported LUKS v2 key size\n\0".as_ptr());
        return None;
    }

    // Parse payload offset from JSON BEFORE key material read overwrites
    // SCRATCH_MEM_BASE (which shares memory with json_buf).
    let mut payload_offset_sectors = 0u32;
    let mut cipher = [0u8; 32];
    let mut cipher_mode = [0u8; 32];
    let mut hash = [0u8; 32];
    let mut mk_len = 0u32;
    let mut active_slots = 0u32;
    luks::parse_v2_json_metadata(
        json,
        &mut cipher,
        &mut cipher_mode,
        &mut hash,
        &mut payload_offset_sectors,
        &mut mk_len,
        &mut active_slots,
    );
    let payload_byte_offset = payload_offset_sectors as u64 * 512;

    // Verify we have enough Argon2 memory
    let needed_kib = slot.kdf_memory as u64;
    let available_kib = config.argon2_mem_size / 1024;
    if needed_kib > available_kib {
        (call_table.debug_print)(
            b"convert: insufficient Argon2 memory (use larger --max-guest-memory)\n\0".as_ptr(),
        );
        return None;
    }

    (call_table.verbose_print)(b"convert: reading LUKS v2 key material\n\0".as_ptr());

    // Read encrypted key material from disk
    let km_total_bytes = (key_bytes as u64)
        .checked_mul(slot.af_stripes as u64)
        .unwrap_or(0) as usize;
    if km_total_bytes == 0 || km_total_bytes > SCRATCH_MEM_SIZE {
        (call_table.debug_print)(b"convert: LUKS v2 key material size invalid\n\0".as_ptr());
        return None;
    }

    let km_buf = core::slice::from_raw_parts_mut(SCRATCH_MEM_BASE as *mut u8, km_total_bytes);
    let km_byte_offset = slot.area_offset;

    let cap = (call_table.get_input_capacity)(0) * sector_size as u64;
    if km_byte_offset + km_total_bytes as u64 > cap {
        (call_table.debug_print)(
            b"convert: LUKS v2 key material exceeds device capacity\n\0".as_ptr(),
        );
        return None;
    }

    let km_start_sector = km_byte_offset / sector_size as u64;
    let km_end_byte = km_byte_offset + km_total_bytes as u64;
    let km_end_sector = (km_end_byte + sector_size as u64 - 1) / sector_size as u64;
    let km_sectors_needed = (km_end_sector - km_start_sector) as usize;

    let mut sector_buf = [0u8; MAX_SECTOR_SIZE];
    let mut km_pos = 0usize;

    for s in 0..km_sectors_needed {
        let sector_idx = km_start_sector + s as u64;
        if !(call_table.read_input_sector)(0, sector_idx, sector_buf.as_mut_ptr(), sector_size) {
            (call_table.debug_print)(b"convert: failed to read LUKS v2 key material\n\0".as_ptr());
            return None;
        }
        *bytes_read += sector_size as u64;

        let offset_in_sector = if s == 0 {
            (km_byte_offset % sector_size as u64) as usize
        } else {
            0
        };
        let available = sector_size - offset_in_sector;
        let to_copy = available.min(km_total_bytes - km_pos);
        km_buf[km_pos..km_pos + to_copy]
            .copy_from_slice(&sector_buf[offset_in_sector..offset_in_sector + to_copy]);
        km_pos += to_copy;

        if km_pos >= km_total_bytes {
            break;
        }
    }

    (call_table.verbose_print)(b"convert: deriving LUKS v2 master key (Argon2id)\n\0".as_ptr());

    // Allocate Argon2 memory at ARGON2_MEM_BASE
    let num_blocks = (slot.kdf_memory as usize * 1024) / 1024;
    let memory_ptr = ARGON2_MEM_BASE as *mut argon2::Block;
    let memory_blocks = core::slice::from_raw_parts_mut(memory_ptr, num_blocks);

    let passphrase = config.passphrase_bytes();
    let derived = match luks::derive_v2_master_key(
        &slot,
        &digest_params,
        passphrase,
        km_buf,
        memory_blocks,
    ) {
        Some(d) => d,
        None => {
            (call_table.debug_print)(b"convert: LUKS v2 master key derivation failed\n\0".as_ptr());
            return None;
        }
    };

    (call_table.verbose_print)(b"convert: LUKS v2 master key verified\n\0".as_ptr());

    out_key[..derived.key_len].copy_from_slice(&derived.key[..derived.key_len]);

    Some((
        derived.key_len,
        derived.luks_sector_size,
        payload_byte_offset,
    ))
}

// ================================================================
// Raw output path (existing Phase 3 logic)
// ================================================================

unsafe fn convert_to_raw(
    call_table: &CallTable,
    chain_config: &ChainConfig,
    chain_states: &mut qcow2::ChainStates,
    input_device_count: usize,
    virtual_size: u64,
    sector_size: usize,
    skip_zeros: bool,
    aes_key: Option<&[u8; 16]>,
    luks_key: Option<&[u8]>,
    luks_sector_size: u64,
    bytes_read: &mut u64,
    layout: &ScratchLayout,
) -> u64 {
    let output_sector_size = (call_table.get_output_sector_size)();
    let output_capacity = (call_table.get_output_capacity)();
    let progress_interval = (call_table.get_progress_interval)();

    let top_dev = &chain_config.devices[0];
    let cluster_size = if top_dev.cluster_size > 0 {
        top_dev.cluster_size as u64
    } else {
        sector_size as u64
    };

    let chunk_size = if cluster_size > MAX_SECTOR_SIZE as u64 {
        MAX_SECTOR_SIZE as u64
    } else {
        cluster_size
    };

    if chunk_size < output_sector_size as u64 {
        (call_table.debug_print)(b"convert: chunk < output sector size\n\0".as_ptr());
        (call_table.send_complete)(b"convert\0".as_ptr(), 0, false);
        return 0;
    }

    (call_table.verbose_print)(b"convert: starting raw conversion\n\0".as_ptr());

    // Staging buffer for decompressing clusters larger than chunk_size
    let staging_buf_addr = layout.dynamic_start + input_device_count * 2 * MAX_SECTOR_SIZE;
    let staging_buf = staging_buf_addr as *mut u8;
    let mut staging_cluster_offset: u64 = u64::MAX;

    let buf = layout.buf_data as *mut u8;
    let mut virtual_offset: u64 = 0;
    let mut last_percent: u32 = 0;
    let mut chunks_done: u64 = 0;
    let total_chunks = (virtual_size + chunk_size - 1) / chunk_size;

    while virtual_offset < virtual_size {
        let remaining = virtual_size - virtual_offset;
        let this_chunk = if remaining < chunk_size {
            remaining
        } else {
            chunk_size
        };

        // Reset bump allocator before ZSTD decompression
        HEAP_POS.store(0, core::sync::atomic::Ordering::Relaxed);

        if !qcow2::read_chain_virtual_cluster(
            call_table,
            0,
            input_device_count,
            virtual_offset,
            buf,
            this_chunk,
            sector_size,
            chain_config,
            chain_states,
            layout.buf_compressed as *mut u8,
            staging_buf,
            &mut staging_cluster_offset,
            aes_key,
            luks_key,
            luks_sector_size,
            bytes_read,
        ) {
            (call_table.send_error)(
                b"convert\0".as_ptr(),
                b"input\0".as_ptr(),
                virtual_offset / sector_size as u64,
                1,
            );
            (call_table.send_complete)(b"convert\0".as_ptr(), *bytes_read, false);
            return *bytes_read;
        }

        if skip_zeros && is_all_zeros_ptr(buf, this_chunk as usize) {
            virtual_offset += this_chunk;
            chunks_done += 1;
            let percent = (chunks_done * 100 / total_chunks) as u32;
            if should_report_progress(progress_interval, percent, last_percent, chunks_done) {
                (call_table.send_progress)(
                    b"convert\0".as_ptr(),
                    chunks_done,
                    total_chunks,
                    percent,
                );
                last_percent = percent;
            }
            continue;
        }

        let output_first_sector = virtual_offset / output_sector_size as u64;
        let sectors_per_chunk =
            (this_chunk + output_sector_size as u64 - 1) / output_sector_size as u64;

        for i in 0..sectors_per_chunk {
            let output_sector = output_first_sector + i;
            if output_sector >= output_capacity {
                break;
            }
            let offset = (i as usize) * output_sector_size;
            if !(call_table.write_output_sector)(output_sector, buf.add(offset), output_sector_size)
            {
                (call_table.send_error)(
                    b"convert\0".as_ptr(),
                    b"output\0".as_ptr(),
                    output_sector,
                    2,
                );
                (call_table.send_complete)(b"convert\0".as_ptr(), *bytes_read, false);
                return *bytes_read;
            }
        }

        virtual_offset += this_chunk;
        chunks_done += 1;

        let percent = (chunks_done * 100 / total_chunks) as u32;
        if should_report_progress(progress_interval, percent, last_percent, chunks_done) {
            (call_table.send_progress)(b"convert\0".as_ptr(), chunks_done, total_chunks, percent);
            last_percent = percent;
        }
    }

    (call_table.send_complete)(b"convert\0".as_ptr(), *bytes_read, true);
    (call_table.verbose_print)(b"convert: done\n\0".as_ptr());
    *bytes_read
}

// ================================================================
// QCOW2 output path
// ================================================================

/// Write a cluster-sized buffer to the output device at the given
/// byte offset. Returns false on I/O error.
unsafe fn write_cluster_to_output(
    call_table: &CallTable,
    buf: *const u8,
    byte_offset: u64,
    cluster_size: u64,
    output_sector_size: usize,
    output_capacity: u64,
) -> bool {
    write_bytes_to_output(
        call_table,
        buf,
        byte_offset,
        cluster_size,
        output_sector_size,
        output_capacity,
    )
}

/// Write an arbitrary number of bytes to the output device at the
/// given byte offset. byte_count is rounded up to the output
/// sector size for the final sector write. Returns false on I/O
/// error.
unsafe fn write_bytes_to_output(
    call_table: &CallTable,
    buf: *const u8,
    byte_offset: u64,
    byte_count: u64,
    output_sector_size: usize,
    output_capacity: u64,
) -> bool {
    let first_sector = byte_offset / output_sector_size as u64;
    let sectors = (byte_count + output_sector_size as u64 - 1) / output_sector_size as u64;
    for i in 0..sectors {
        let sector = first_sector + i;
        if sector >= output_capacity {
            return false;
        }
        if !(call_table.write_output_sector)(
            sector,
            buf.add(i as usize * output_sector_size),
            output_sector_size,
        ) {
            return false;
        }
    }
    true
}

/// Calculate refcount table layout. Returns
/// (reftable_clusters, refblock_count, total_clusters).
fn calculate_refcount_layout(used_clusters: u64, cluster_size: u64) -> (u64, u64, u64) {
    // 16-bit refcounts: entries per refcount block
    let entries_per_refblock = cluster_size / 2;

    // Iterate: metadata size depends on total clusters,
    // which includes the metadata itself.
    let mut reftable_clusters: u64 = 1;
    let mut refblock_count: u64 = 1;

    for _ in 0..10 {
        let total = used_clusters + reftable_clusters + refblock_count;
        let new_refblock_count = (total + entries_per_refblock - 1) / entries_per_refblock;
        // Each reftable entry is 8 bytes (u64 offset)
        let reftable_entries = new_refblock_count;
        let new_reftable_clusters = (reftable_entries * 8 + cluster_size - 1) / cluster_size;
        if new_refblock_count == refblock_count && new_reftable_clusters == reftable_clusters {
            break;
        }
        refblock_count = new_refblock_count;
        reftable_clusters = new_reftable_clusters;
    }

    let total = used_clusters + reftable_clusters + refblock_count;
    (reftable_clusters, refblock_count, total)
}

/// Write the QCOW2 v3 header at cluster 0.
unsafe fn write_qcow2_header(
    call_table: &CallTable,
    cluster_bits: u32,
    cluster_size: u64,
    virtual_size: u64,
    l1_size: u32,
    l1_offset: u64,
    reftable_offset: u64,
    reftable_clusters: u64,
    output_sector_size: usize,
    output_capacity: u64,
    scratch_layout: &ScratchLayout,
) -> bool {
    // BUF_HEADER: use multipurpose buffer for header cluster
    let buf_hdr = scratch_layout.buf_multipurpose as *mut u8;
    core::ptr::write_bytes(buf_hdr, 0, cluster_size as usize);
    let hdr = core::slice::from_raw_parts_mut(buf_hdr, cluster_size as usize);

    shared::write_be_u32(hdr, 0, qcow2::QCOW2_MAGIC);
    shared::write_be_u32(hdr, 4, qcow2::QCOW2_VERSION_3);
    // backing_file_offset (8) and backing_file_size (16) = 0
    shared::write_be_u32(hdr, 20, cluster_bits);
    shared::write_be_u64(hdr, 24, virtual_size);
    // crypt_method (32) = 0
    shared::write_be_u32(hdr, 36, l1_size);
    shared::write_be_u64(hdr, 40, l1_offset);
    shared::write_be_u64(hdr, 48, reftable_offset);
    shared::write_be_u32(hdr, 56, reftable_clusters as u32);
    // nb_snapshots (60) = 0, snapshots_offset (64) = 0
    // incompatible_features (72) = 0
    // compatible_features (80) = 0
    // autoclear_features (88) = 0
    shared::write_be_u32(hdr, 96, qcow2::QCOW2_DEFAULT_REFCOUNT_ORDER); // refcount_order
    shared::write_be_u32(hdr, 100, qcow2::QCOW2_HEADER_LENGTH_V3); // header_length

    write_cluster_to_output(
        call_table,
        buf_hdr,
        0,
        cluster_size,
        output_sector_size,
        output_capacity,
    )
}

// ================================================================
// Shared QCOW2 output helpers
// ================================================================

/// Computed layout parameters for QCOW2 output. Used by both
/// uncompressed and compressed paths to avoid duplicating the
/// initialization logic.
struct Qcow2OutputLayout {
    cluster_bits: u32,
    cluster_size: u64,
    entries_per_l2: u32,
    l1_size: u32,
    l1_buf: *mut u8,
    l1_clusters: u64,
    l1_write_bytes: usize,
    /// First byte after the L1 buffer in scratch memory.
    l1_buf_end: usize,
    total_virtual_clusters: u64,
    output_sector_size: usize,
    output_capacity: u64,
    progress_interval: u32,
}

/// Compute QCOW2 output layout from config. Returns None and
/// sends an error if the L1 table doesn't fit in scratch memory.
unsafe fn init_qcow2_output_layout(
    call_table: &CallTable,
    config: &ConvertConfig,
    input_device_count: usize,
    virtual_size: u64,
    bytes_read: &mut u64,
    layout: &ScratchLayout,
) -> Option<Qcow2OutputLayout> {
    let output_sector_size = (call_table.get_output_sector_size)();
    let output_capacity = (call_table.get_output_capacity)();
    let progress_interval = (call_table.get_progress_interval)();

    let cluster_bits = config.output_cluster_bits();
    let cluster_size = 1u64 << cluster_bits;
    let entries_per_l2 = (cluster_size / 8) as u32;
    let l2_coverage = cluster_size * entries_per_l2 as u64;
    let l1_size = ((virtual_size + l2_coverage - 1) / l2_coverage) as u32;

    // L1 table starts after dynamic caches + staging buffer
    let l1_buf_addr =
        layout.dynamic_start + input_device_count * 2 * MAX_SECTOR_SIZE + MAX_CLUSTER_SIZE;
    let l1_size_bytes = l1_size as usize * 8;
    let l1_clusters = ((l1_size_bytes as u64 + cluster_size - 1) / cluster_size).max(1);
    let l1_write_bytes = l1_clusters as usize * cluster_size as usize;

    if l1_buf_addr + l1_write_bytes > ALLOC_HEAP_BASE {
        (call_table.debug_print)(b"convert: L1 too large for scratch\n\0".as_ptr());
        (call_table.send_complete)(b"convert\0".as_ptr(), *bytes_read, false);
        return None;
    }

    let l1_buf = l1_buf_addr as *mut u8;
    core::ptr::write_bytes(l1_buf, 0, l1_write_bytes);

    let total_virtual_clusters = (virtual_size + cluster_size - 1) / cluster_size;

    Some(Qcow2OutputLayout {
        cluster_bits,
        cluster_size,
        entries_per_l2,
        l1_size,
        l1_buf,
        l1_clusters,
        l1_write_bytes,
        l1_buf_end: l1_buf_addr + l1_write_bytes,
        total_virtual_clusters,
        output_sector_size,
        output_capacity,
        progress_interval,
    })
}

/// Write QCOW2 metadata: L1 table, refcount structures, and
/// header. Used by both uncompressed and compressed paths.
///
/// `data_end_offset` is the byte offset where data ends and
/// metadata begins (must be cluster-aligned).
///
/// When `refcount_array` is Some, refcount values are read from
/// the tracked array (compressed path). When None, all clusters
/// get refcount=1 (uncompressed path where every cluster is
/// allocated exactly once).
///
/// Returns true on success.
#[allow(clippy::too_many_arguments)]
unsafe fn write_qcow2_metadata(
    call_table: &CallTable,
    layout: &Qcow2OutputLayout,
    virtual_size: u64,
    data_end_offset: u64,
    refcount_array: Option<(*mut u16, usize)>,
    bytes_read: &mut u64,
    scratch_layout: &ScratchLayout,
) -> bool {
    let cs = layout.cluster_size;
    let oss = layout.output_sector_size;
    let oc = layout.output_capacity;

    // L1 table
    let l1_offset = data_end_offset;
    for c in 0..layout.l1_clusters {
        let off = l1_offset + c * cs;
        let ptr = layout.l1_buf.add(c as usize * cs as usize);
        if !write_cluster_to_output(call_table, ptr, off, cs, oss, oc) {
            (call_table.send_complete)(b"convert\0".as_ptr(), *bytes_read, false);
            return false;
        }
        if let Some((arr, max)) = refcount_array {
            inc_refcount(arr, off / cs, max);
        }
    }

    let clusters_before_refcount = if refcount_array.is_some() {
        // Compressed: also track header cluster
        let (arr, max) = refcount_array.unwrap();
        inc_refcount(arr, 0, max);
        (l1_offset + layout.l1_clusters * cs) / cs
    } else {
        // Uncompressed: simple cluster count
        data_end_offset / cs + layout.l1_clusters
    };

    // Refcount structures
    let (reftable_clusters, refblock_count, total_clusters) =
        calculate_refcount_layout(clusters_before_refcount, cs);

    let reftable_offset = clusters_before_refcount * cs;
    let refblock_base_offset = reftable_offset + reftable_clusters * cs;
    let entries_per_refblock = cs / 2;

    // Track refcounts for reftable/refblock clusters
    if let Some((arr, max)) = refcount_array {
        for c in clusters_before_refcount..total_clusters {
            inc_refcount(arr, c, max);
        }
    }

    // Write refcount blocks (BUF_REFCOUNT: multipurpose buffer)
    let buf_rc = scratch_layout.buf_multipurpose as *mut u8;
    for rb in 0..refblock_count {
        core::ptr::write_bytes(buf_rc, 0, cs as usize);
        let rc_slice = core::slice::from_raw_parts_mut(buf_rc, cs as usize);

        let first_in_block = rb * entries_per_refblock;
        let entries = core::cmp::min(
            entries_per_refblock,
            total_clusters.saturating_sub(first_in_block),
        );
        for e in 0..entries {
            let refcount = if let Some((arr, max)) = refcount_array {
                let idx = (first_in_block + e) as usize;
                if idx < max {
                    core::ptr::read(arr.add(idx))
                } else {
                    1
                }
            } else {
                1
            };
            shared::write_be_u16(rc_slice, e as usize * 2, refcount);
        }

        let rb_offset = refblock_base_offset + rb * cs;
        if !write_cluster_to_output(call_table, buf_rc, rb_offset, cs, oss, oc) {
            (call_table.send_complete)(b"convert\0".as_ptr(), *bytes_read, false);
            return false;
        }
    }

    // Write refcount table
    if !write_refcount_table(
        call_table,
        cs,
        reftable_offset,
        reftable_clusters,
        refblock_base_offset,
        refblock_count,
        oss,
        oc,
        scratch_layout,
    ) {
        (call_table.send_complete)(b"convert\0".as_ptr(), *bytes_read, false);
        return false;
    }

    // Write header
    if !write_qcow2_header(
        call_table,
        layout.cluster_bits,
        cs,
        virtual_size,
        layout.l1_size,
        l1_offset,
        reftable_offset,
        reftable_clusters,
        oss,
        oc,
        scratch_layout,
    ) {
        (call_table.send_complete)(b"convert\0".as_ptr(), *bytes_read, false);
        return false;
    }

    true
}

// ================================================================
// Uncompressed QCOW2 output (Phase 4)
// ================================================================

#[allow(clippy::too_many_arguments)]
unsafe fn convert_to_qcow2(
    call_table: &CallTable,
    config: &ConvertConfig,
    chain_config: &ChainConfig,
    chain_states: &mut qcow2::ChainStates,
    input_device_count: usize,
    virtual_size: u64,
    sector_size: usize,
    skip_zeros: bool,
    aes_key: Option<&[u8; 16]>,
    luks_key: Option<&[u8]>,
    luks_sector_size: u64,
    bytes_read: &mut u64,
    scratch_layout: &ScratchLayout,
) -> u64 {
    let layout = match init_qcow2_output_layout(
        call_table,
        config,
        input_device_count,
        virtual_size,
        bytes_read,
        scratch_layout,
    ) {
        Some(l) => l,
        None => return *bytes_read,
    };

    let buf_data = scratch_layout.buf_data as *mut u8;
    // BUF_L2_OUT: use multipurpose buffer for L2 table
    let buf_l2 = scratch_layout.buf_multipurpose as *mut u8;

    // Staging buffer for decompressing clusters larger than chunk_size
    let staging_buf_addr = scratch_layout.dynamic_start + input_device_count * 2 * MAX_SECTOR_SIZE;
    let staging_buf = staging_buf_addr as *mut u8;
    let mut staging_cluster_offset: u64 = u64::MAX;

    (call_table.verbose_print)(b"convert: starting qcow2 conversion\n\0".as_ptr());

    // Linear cluster allocator. Cluster 0 is the header.
    let mut next_free: u64 = 1;

    let mut clusters_done: u64 = 0;
    let mut last_percent: u32 = 0;

    // Process each L2 range
    for l1_idx in 0..layout.l1_size {
        // Zero the L2 buffer
        core::ptr::write_bytes(buf_l2, 0, layout.cluster_size as usize);

        let mut l2_allocated = false;
        let mut l2_cluster: u64 = 0;

        let first_vc = l1_idx as u64 * layout.entries_per_l2 as u64;
        let last_vc = core::cmp::min(
            first_vc + layout.entries_per_l2 as u64,
            layout.total_virtual_clusters,
        );

        for vc in first_vc..last_vc {
            let virtual_offset = vc * layout.cluster_size;
            let remaining = virtual_size - virtual_offset;
            let this_chunk = core::cmp::min(remaining, layout.cluster_size);

            // Reset bump allocator before ZSTD decompression
            HEAP_POS.store(0, core::sync::atomic::Ordering::Relaxed);

            // Read input data
            if !qcow2::read_chain_virtual_cluster(
                call_table,
                0,
                input_device_count,
                virtual_offset,
                buf_data,
                this_chunk,
                sector_size,
                chain_config,
                chain_states,
                scratch_layout.buf_compressed as *mut u8,
                staging_buf,
                &mut staging_cluster_offset,
                aes_key,
                luks_key,
                luks_sector_size,
                bytes_read,
            ) {
                (call_table.send_error)(
                    b"convert\0".as_ptr(),
                    b"input\0".as_ptr(),
                    virtual_offset / sector_size as u64,
                    1,
                );
                (call_table.send_complete)(b"convert\0".as_ptr(), *bytes_read, false);
                return *bytes_read;
            }

            // Skip zero clusters when configured
            if skip_zeros && is_all_zeros_ptr(buf_data, this_chunk as usize) {
                clusters_done += 1;
                let pct = (clusters_done * 100 / layout.total_virtual_clusters) as u32;
                if should_report_progress(
                    layout.progress_interval,
                    pct,
                    last_percent,
                    clusters_done,
                ) {
                    (call_table.send_progress)(
                        b"convert\0".as_ptr(),
                        clusters_done,
                        layout.total_virtual_clusters,
                        pct,
                    );
                    last_percent = pct;
                }
                continue;
            }

            // Allocate L2 table on first non-zero cluster
            if !l2_allocated {
                l2_cluster = next_free;
                next_free += 1;
                l2_allocated = true;
            }

            // Allocate data cluster
            let data_cluster = next_free;
            next_free += 1;
            let data_offset = data_cluster * layout.cluster_size;

            // Zero-pad if this is a partial final cluster
            if this_chunk < layout.cluster_size {
                core::ptr::write_bytes(
                    buf_data.add(this_chunk as usize),
                    0,
                    (layout.cluster_size - this_chunk) as usize,
                );
            }

            // Write data cluster to output
            if !write_cluster_to_output(
                call_table,
                buf_data,
                data_offset,
                layout.cluster_size,
                layout.output_sector_size,
                layout.output_capacity,
            ) {
                (call_table.send_error)(
                    b"convert\0".as_ptr(),
                    b"output\0".as_ptr(),
                    data_offset / layout.output_sector_size as u64,
                    2,
                );
                (call_table.send_complete)(b"convert\0".as_ptr(), *bytes_read, false);
                return *bytes_read;
            }

            // Set L2 entry: standard cluster at data_offset
            // OFLAG_COPIED (bit 63) must be set when refcount=1
            let l2_entry_idx = (vc - first_vc) as usize;
            let l2_slice = core::slice::from_raw_parts_mut(buf_l2, layout.cluster_size as usize);
            shared::write_be_u64(l2_slice, l2_entry_idx * 8, data_offset | (1u64 << 63));

            clusters_done += 1;
            let pct = (clusters_done * 100 / layout.total_virtual_clusters) as u32;
            if should_report_progress(layout.progress_interval, pct, last_percent, clusters_done) {
                (call_table.send_progress)(
                    b"convert\0".as_ptr(),
                    clusters_done,
                    layout.total_virtual_clusters,
                    pct,
                );
                last_percent = pct;
            }
        }

        // Flush L2 table if any data was written
        if l2_allocated {
            let l2_offset = l2_cluster * layout.cluster_size;
            if !write_cluster_to_output(
                call_table,
                buf_l2,
                l2_offset,
                layout.cluster_size,
                layout.output_sector_size,
                layout.output_capacity,
            ) {
                (call_table.send_error)(
                    b"convert\0".as_ptr(),
                    b"output\0".as_ptr(),
                    l2_offset / layout.output_sector_size as u64,
                    2,
                );
                (call_table.send_complete)(b"convert\0".as_ptr(), *bytes_read, false);
                return *bytes_read;
            }

            // Record L2 offset in L1 table
            // OFLAG_COPIED (bit 63) must be set when refcount=1
            let l1_slice = core::slice::from_raw_parts_mut(layout.l1_buf, layout.l1_write_bytes);
            shared::write_be_u64(l1_slice, l1_idx as usize * 8, l2_offset | (1u64 << 63));
        }
    }

    // -- Write metadata at end --
    let data_end_offset = next_free * layout.cluster_size;
    if !write_qcow2_metadata(
        call_table,
        &layout,
        virtual_size,
        data_end_offset,
        None,
        bytes_read,
        scratch_layout,
    ) {
        return *bytes_read;
    }

    (call_table.send_complete)(b"convert\0".as_ptr(), *bytes_read, true);
    (call_table.verbose_print)(b"convert: done\n\0".as_ptr());
    *bytes_read
}

/// Write the refcount table (array of u64 offsets to refcount
/// blocks).
unsafe fn write_refcount_table(
    call_table: &CallTable,
    cluster_size: u64,
    reftable_offset: u64,
    reftable_clusters: u64,
    refblock_base_offset: u64,
    refblock_count: u64,
    output_sector_size: usize,
    output_capacity: u64,
    scratch_layout: &ScratchLayout,
) -> bool {
    // BUF_REFCOUNT: use multipurpose buffer for refcount table
    let buf_rc = scratch_layout.buf_multipurpose as *mut u8;
    for rt_cluster in 0..reftable_clusters {
        core::ptr::write_bytes(buf_rc, 0, cluster_size as usize);
        let rt_slice = core::slice::from_raw_parts_mut(buf_rc, cluster_size as usize);

        let entries_per_rt_cluster = cluster_size / 8;
        let first_entry = rt_cluster * entries_per_rt_cluster;
        let count = core::cmp::min(
            entries_per_rt_cluster,
            refblock_count.saturating_sub(first_entry),
        );
        for e in 0..count {
            let rb_idx = first_entry + e;
            let rb_off = refblock_base_offset + rb_idx * cluster_size;
            shared::write_be_u64(rt_slice, e as usize * 8, rb_off);
        }

        let rt_off = reftable_offset + rt_cluster * cluster_size;
        if !write_cluster_to_output(
            call_table,
            buf_rc,
            rt_off,
            cluster_size,
            output_sector_size,
            output_capacity,
        ) {
            return false;
        }
    }
    true
}

// ================================================================
// Compressed QCOW2 output (Phase 5)
// ================================================================

/// Increment the refcount for a host cluster in the tracking
/// array. Silently caps at u16::MAX if it would overflow.
#[inline]
unsafe fn inc_refcount(refcount_array: *mut u16, host_cluster: u64, max_entries: usize) {
    let idx = host_cluster as usize;
    if idx < max_entries {
        let ptr = refcount_array.add(idx);
        let val = core::ptr::read(ptr);
        if val < u16::MAX {
            core::ptr::write(ptr, val + 1);
        }
    }
}

#[allow(clippy::too_many_arguments)]
unsafe fn convert_to_qcow2_compressed(
    call_table: &CallTable,
    config: &ConvertConfig,
    chain_config: &ChainConfig,
    chain_states: &mut qcow2::ChainStates,
    input_device_count: usize,
    virtual_size: u64,
    sector_size: usize,
    skip_zeros: bool,
    aes_key: Option<&[u8; 16]>,
    luks_key: Option<&[u8]>,
    luks_sector_size: u64,
    bytes_read: &mut u64,
    scratch_layout: &ScratchLayout,
) -> u64 {
    let layout = match init_qcow2_output_layout(
        call_table,
        config,
        input_device_count,
        virtual_size,
        bytes_read,
        scratch_layout,
    ) {
        Some(l) => l,
        None => return *bytes_read,
    };

    // CompressorOxide state follows L1 table (too large for
    // 64KB guest stack at ~200KB). Align to 8 bytes.
    let compressor_addr = (layout.l1_buf_end + 7) & !7;
    let compressor_size = qcow2::COMPRESSOR_STATE_SIZE;

    // Refcount tracking array follows compressor state
    let refcount_array_addr = (compressor_addr + compressor_size + 1) & !1;
    let refcount_array_bytes = ALLOC_HEAP_BASE - refcount_array_addr;
    let max_refcount_entries = refcount_array_bytes / 2;

    if refcount_array_addr >= ALLOC_HEAP_BASE || max_refcount_entries < 64 {
        (call_table.debug_print)(b"convert: no room for refcount array\n\0".as_ptr());
        (call_table.send_complete)(b"convert\0".as_ptr(), *bytes_read, false);
        return *bytes_read;
    }

    let buf_data = scratch_layout.buf_data as *mut u8;
    // BUF_L2_OUT: use multipurpose buffer for L2 table
    let buf_l2 = scratch_layout.buf_multipurpose as *mut u8;

    // Staging buffer for decompressing clusters larger than chunk_size
    let staging_buf_addr = scratch_layout.dynamic_start + input_device_count * 2 * MAX_SECTOR_SIZE;
    let staging_buf = staging_buf_addr as *mut u8;
    let mut staging_cluster_offset: u64 = u64::MAX;

    // Reuse BUF_COMPRESSED_IN for compressed output (it's free
    // after read_chain_virtual_cluster returns).
    let buf_compressed_out = scratch_layout.buf_compressed as *mut u8;
    let compressor_mem = compressor_addr as *mut u8;
    let refcount_array = refcount_array_addr as *mut u16;

    // Zero refcount array
    core::ptr::write_bytes(refcount_array as *mut u8, 0, max_refcount_entries * 2);

    (call_table.verbose_print)(b"convert: starting compressed qcow2\n\0".as_ptr());

    // Byte-level write position. Cluster 0 is reserved for
    // the header (written last).
    let mut write_pos: u64 = layout.cluster_size;

    let mut clusters_done: u64 = 0;
    let mut last_percent: u32 = 0;

    // Process each L2 range
    for l1_idx in 0..layout.l1_size {
        core::ptr::write_bytes(buf_l2, 0, layout.cluster_size as usize);
        let mut l2_has_data = false;

        let first_vc = l1_idx as u64 * layout.entries_per_l2 as u64;
        let last_vc = core::cmp::min(
            first_vc + layout.entries_per_l2 as u64,
            layout.total_virtual_clusters,
        );

        for vc in first_vc..last_vc {
            let virtual_offset = vc * layout.cluster_size;
            let remaining = virtual_size - virtual_offset;
            let this_chunk = core::cmp::min(remaining, layout.cluster_size);

            // Reset bump allocator before ZSTD decompression
            HEAP_POS.store(0, core::sync::atomic::Ordering::Relaxed);

            // Read input data
            if !qcow2::read_chain_virtual_cluster(
                call_table,
                0,
                input_device_count,
                virtual_offset,
                buf_data,
                this_chunk,
                sector_size,
                chain_config,
                chain_states,
                scratch_layout.buf_compressed as *mut u8,
                staging_buf,
                &mut staging_cluster_offset,
                aes_key,
                luks_key,
                luks_sector_size,
                bytes_read,
            ) {
                (call_table.send_error)(
                    b"convert\0".as_ptr(),
                    b"input\0".as_ptr(),
                    virtual_offset / sector_size as u64,
                    1,
                );
                (call_table.send_complete)(b"convert\0".as_ptr(), *bytes_read, false);
                return *bytes_read;
            }

            // Skip zero clusters
            if skip_zeros && is_all_zeros_ptr(buf_data, this_chunk as usize) {
                clusters_done += 1;
                let pct = (clusters_done * 100 / layout.total_virtual_clusters) as u32;
                if should_report_progress(
                    layout.progress_interval,
                    pct,
                    last_percent,
                    clusters_done,
                ) {
                    (call_table.send_progress)(
                        b"convert\0".as_ptr(),
                        clusters_done,
                        layout.total_virtual_clusters,
                        pct,
                    );
                    last_percent = pct;
                }
                continue;
            }

            // Zero-pad partial final cluster
            if this_chunk < layout.cluster_size {
                core::ptr::write_bytes(
                    buf_data.add(this_chunk as usize),
                    0,
                    (layout.cluster_size - this_chunk) as usize,
                );
            }

            // Reset bump allocator before each compression
            HEAP_POS.store(0, core::sync::atomic::Ordering::Relaxed);

            // Compress the cluster
            let compressed_len = qcow2::compress_cluster_zlib(
                compressor_mem,
                buf_data,
                layout.cluster_size as usize,
                buf_compressed_out,
                layout.cluster_size as usize,
            );

            let l2_entry_idx = (vc - first_vc) as usize;
            let l2_slice = core::slice::from_raw_parts_mut(buf_l2, layout.cluster_size as usize);

            if compressed_len > 0 {
                // Compression succeeded: write packed at
                // sector-aligned position.
                let padded = ((compressed_len as u64) + 511) & !511;

                // Zero tail of compressed buffer for clean
                // sector writes
                if compressed_len < padded as usize {
                    core::ptr::write_bytes(
                        buf_compressed_out.add(compressed_len),
                        0,
                        padded as usize - compressed_len,
                    );
                }

                if !write_bytes_to_output(
                    call_table,
                    buf_compressed_out,
                    write_pos,
                    padded,
                    layout.output_sector_size,
                    layout.output_capacity,
                ) {
                    (call_table.send_error)(
                        b"convert\0".as_ptr(),
                        b"output\0".as_ptr(),
                        write_pos / layout.output_sector_size as u64,
                        2,
                    );
                    (call_table.send_complete)(b"convert\0".as_ptr(), *bytes_read, false);
                    return *bytes_read;
                }

                // Compressed L2 entry
                let l2_entry = qcow2::encode_compressed_l2_entry(
                    write_pos,
                    compressed_len as u64,
                    layout.cluster_bits,
                );
                shared::write_be_u64(l2_slice, l2_entry_idx * 8, l2_entry);

                // Track refcounts for touched host clusters
                let first_host = write_pos / layout.cluster_size;
                let last_host = (write_pos + padded - 1) / layout.cluster_size;
                for h in first_host..=last_host {
                    inc_refcount(refcount_array, h, max_refcount_entries);
                }

                write_pos += padded;
            } else {
                // Compression didn't help: write uncompressed
                // at cluster-aligned offset.
                write_pos = (write_pos + layout.cluster_size - 1) & !(layout.cluster_size - 1);

                if !write_cluster_to_output(
                    call_table,
                    buf_data,
                    write_pos,
                    layout.cluster_size,
                    layout.output_sector_size,
                    layout.output_capacity,
                ) {
                    (call_table.send_error)(
                        b"convert\0".as_ptr(),
                        b"output\0".as_ptr(),
                        write_pos / layout.output_sector_size as u64,
                        2,
                    );
                    (call_table.send_complete)(b"convert\0".as_ptr(), *bytes_read, false);
                    return *bytes_read;
                }

                // Standard L2 entry with OFLAG_COPIED
                shared::write_be_u64(l2_slice, l2_entry_idx * 8, write_pos | (1u64 << 63));

                inc_refcount(
                    refcount_array,
                    write_pos / layout.cluster_size,
                    max_refcount_entries,
                );

                write_pos += layout.cluster_size;
            }

            l2_has_data = true;
            clusters_done += 1;
            let pct = (clusters_done * 100 / layout.total_virtual_clusters) as u32;
            if should_report_progress(layout.progress_interval, pct, last_percent, clusters_done) {
                (call_table.send_progress)(
                    b"convert\0".as_ptr(),
                    clusters_done,
                    layout.total_virtual_clusters,
                    pct,
                );
                last_percent = pct;
            }
        }

        // Flush L2 table if any data was written
        if l2_has_data {
            // Pad to cluster boundary
            write_pos = (write_pos + layout.cluster_size - 1) & !(layout.cluster_size - 1);

            if !write_cluster_to_output(
                call_table,
                buf_l2,
                write_pos,
                layout.cluster_size,
                layout.output_sector_size,
                layout.output_capacity,
            ) {
                (call_table.send_error)(
                    b"convert\0".as_ptr(),
                    b"output\0".as_ptr(),
                    write_pos / layout.output_sector_size as u64,
                    2,
                );
                (call_table.send_complete)(b"convert\0".as_ptr(), *bytes_read, false);
                return *bytes_read;
            }

            // Refcount for L2 cluster
            inc_refcount(
                refcount_array,
                write_pos / layout.cluster_size,
                max_refcount_entries,
            );

            // Record L2 offset in L1 table (OFLAG_COPIED)
            let l1_slice = core::slice::from_raw_parts_mut(layout.l1_buf, layout.l1_write_bytes);
            shared::write_be_u64(l1_slice, l1_idx as usize * 8, write_pos | (1u64 << 63));

            write_pos += layout.cluster_size;
        }
    }

    // -- Write metadata at end --
    // write_pos should already be cluster-aligned here.
    if !write_qcow2_metadata(
        call_table,
        &layout,
        virtual_size,
        write_pos,
        Some((refcount_array, max_refcount_entries)),
        bytes_read,
        scratch_layout,
    ) {
        return *bytes_read;
    }

    (call_table.send_complete)(b"convert\0".as_ptr(), *bytes_read, true);
    (call_table.verbose_print)(b"convert: done\n\0".as_ptr());
    *bytes_read
}

// ================================================================
// VMDK monolithicSparse output (Phase 8d)
// ================================================================

/// VMDK grain size in 512-byte sectors (64KB grains).
const VMDK_GRAIN_SIZE_SECTORS: u64 = 128;
/// VMDK grain size in bytes.
const VMDK_GRAIN_SIZE_BYTES: u64 = VMDK_GRAIN_SIZE_SECTORS * 512;
/// Number of grain table entries per grain table.
const VMDK_GTES_PER_GT: u32 = 512;
/// Grain table size in bytes (512 × 4-byte entries).
const VMDK_GT_BYTES: u64 = VMDK_GTES_PER_GT as u64 * 4;

/// Computed layout for VMDK output.
struct VmdkOutputLayout {
    capacity_sectors: u64,
    total_grains: u64,
    num_gd_entries: u32,
    output_sector_size: usize,
    output_capacity: u64,
    progress_interval: u32,
    /// Byte offset where grain data starts (after header+descriptor,
    /// aligned to output sector size).
    grain_data_start: u64,
    /// Scratch memory address of the GD buffer.
    gd_buf: *mut u8,
    /// Size of the GD in bytes.
    gd_bytes: usize,
}

/// Compute the VMDK output layout. Returns None on error.
unsafe fn init_vmdk_output_layout(
    call_table: &CallTable,
    input_device_count: usize,
    virtual_size: u64,
    bytes_read: &mut u64,
    layout: &ScratchLayout,
) -> Option<VmdkOutputLayout> {
    let output_sector_size = (call_table.get_output_sector_size)();
    let output_capacity = (call_table.get_output_capacity)();
    let progress_interval = (call_table.get_progress_interval)();

    let capacity_sectors = (virtual_size + 511) / 512;
    let total_grains = (capacity_sectors + VMDK_GRAIN_SIZE_SECTORS - 1) / VMDK_GRAIN_SIZE_SECTORS;

    // Sectors covered by one grain table
    let sectors_per_gt = VMDK_GTES_PER_GT as u64 * VMDK_GRAIN_SIZE_SECTORS;
    let num_gd_entries = ((capacity_sectors + sectors_per_gt - 1) / sectors_per_gt) as u32;

    // Header (512 bytes) + descriptor (DESC_SECTORS × 512 bytes)
    let desc_end = 512 + vmdk::DESC_SECTORS * 512;
    // Align grain data start to output sector size
    let grain_data_start = (desc_end + output_sector_size as u64 - 1) / output_sector_size as u64
        * output_sector_size as u64;

    // Allocate GD buffer after dynamic input caches + staging buffer
    let gd_buf_addr =
        layout.dynamic_start + input_device_count * 2 * MAX_SECTOR_SIZE + MAX_CLUSTER_SIZE;
    let gd_bytes = num_gd_entries as usize * 4;
    // Round up to 8-byte alignment for safety
    let gd_alloc = (gd_bytes + 7) & !7;

    if gd_buf_addr + gd_alloc > ALLOC_HEAP_BASE {
        (call_table.debug_print)(b"convert: VMDK GD too large for scratch\n\0".as_ptr());
        (call_table.send_complete)(b"convert\0".as_ptr(), *bytes_read, false);
        return None;
    }

    let gd_buf = gd_buf_addr as *mut u8;
    core::ptr::write_bytes(gd_buf, 0, gd_alloc);

    Some(VmdkOutputLayout {
        capacity_sectors,
        total_grains,
        num_gd_entries,
        output_sector_size,
        output_capacity,
        progress_interval,
        grain_data_start,
        gd_buf,
        gd_bytes,
    })
}

/// Convert input to VMDK monolithicSparse format.
///
/// Layout: Header (512B) | Descriptor | Grain data | GTs | GD
///
/// GTs and GD are written at the end so their positions are known
/// after all grain data is written. Each GT allocation is padded
/// to the output sector size.
#[allow(clippy::too_many_arguments)]
unsafe fn convert_to_vmdk(
    call_table: &CallTable,
    chain_config: &ChainConfig,
    chain_states: &mut qcow2::ChainStates,
    input_device_count: usize,
    virtual_size: u64,
    sector_size: usize,
    skip_zeros: bool,
    aes_key: Option<&[u8; 16]>,
    luks_key: Option<&[u8]>,
    luks_sector_size: u64,
    bytes_read: &mut u64,
    scratch_layout: &ScratchLayout,
) -> u64 {
    let layout = match init_vmdk_output_layout(
        call_table,
        input_device_count,
        virtual_size,
        bytes_read,
        scratch_layout,
    ) {
        Some(l) => l,
        None => return *bytes_read,
    };

    let buf_data = scratch_layout.buf_data as *mut u8;
    // BUF_L2_OUT: use multipurpose buffer for GT
    let buf_gt = scratch_layout.buf_multipurpose as *mut u8;
    let oss = layout.output_sector_size;
    let oc = layout.output_capacity;

    // Staging buffer for decompressing clusters larger than chunk_size
    let staging_buf_addr = scratch_layout.dynamic_start + input_device_count * 2 * MAX_SECTOR_SIZE;
    let staging_buf = staging_buf_addr as *mut u8;
    let mut staging_cluster_offset: u64 = u64::MAX;

    (call_table.verbose_print)(b"convert: starting vmdk conversion\n\0".as_ptr());

    // Byte offset allocator (grain data starts after
    // header+descriptor, aligned to output sector).
    let mut next_free_byte = layout.grain_data_start;
    let mut grains_done: u64 = 0;
    let mut last_percent: u32 = 0;

    // GD slice for recording GT positions (in 512-byte sectors)
    let gd_slice = core::slice::from_raw_parts_mut(layout.gd_buf, layout.gd_bytes);

    // Process each GD entry (L1-equivalent)
    for gd_idx in 0..layout.num_gd_entries {
        // Zero the GT buffer
        core::ptr::write_bytes(buf_gt, 0, oss);

        let mut gt_allocated = false;
        let mut gt_byte_offset: u64 = 0;

        // Range of grains covered by this GD entry
        let first_grain = gd_idx as u64 * VMDK_GTES_PER_GT as u64;
        let last_grain = core::cmp::min(first_grain + VMDK_GTES_PER_GT as u64, layout.total_grains);

        for grain in first_grain..last_grain {
            let virtual_offset = grain * VMDK_GRAIN_SIZE_BYTES;
            let remaining = virtual_size - virtual_offset;
            let this_chunk = if remaining < VMDK_GRAIN_SIZE_BYTES {
                remaining
            } else {
                VMDK_GRAIN_SIZE_BYTES
            };

            // Reset bump allocator before ZSTD decompression
            HEAP_POS.store(0, core::sync::atomic::Ordering::Relaxed);

            // Read input data
            if !qcow2::read_chain_virtual_cluster(
                call_table,
                0,
                input_device_count,
                virtual_offset,
                buf_data,
                this_chunk,
                sector_size,
                chain_config,
                chain_states,
                scratch_layout.buf_compressed as *mut u8,
                staging_buf,
                &mut staging_cluster_offset,
                aes_key,
                luks_key,
                luks_sector_size,
                bytes_read,
            ) {
                (call_table.send_error)(
                    b"convert\0".as_ptr(),
                    b"input\0".as_ptr(),
                    virtual_offset / sector_size as u64,
                    1,
                );
                (call_table.send_complete)(b"convert\0".as_ptr(), *bytes_read, false);
                return *bytes_read;
            }

            // Skip zero grains when configured
            if skip_zeros && is_all_zeros_ptr(buf_data, this_chunk as usize) {
                grains_done += 1;
                let pct = (grains_done * 100 / layout.total_grains) as u32;
                if should_report_progress(layout.progress_interval, pct, last_percent, grains_done)
                {
                    (call_table.send_progress)(
                        b"convert\0".as_ptr(),
                        grains_done,
                        layout.total_grains,
                        pct,
                    );
                    last_percent = pct;
                }
                continue;
            }

            // Allocate GT on first non-zero grain in this group
            if !gt_allocated {
                // Align to output sector
                gt_byte_offset = align_up(next_free_byte, oss);
                let gt_alloc = align_up(VMDK_GT_BYTES, oss);
                next_free_byte = gt_byte_offset + gt_alloc;
                gt_allocated = true;
            }

            // Allocate grain
            let grain_byte_offset = align_up(next_free_byte, oss);
            let grain_alloc = align_up(VMDK_GRAIN_SIZE_BYTES, oss);
            next_free_byte = grain_byte_offset + grain_alloc;

            // Zero-pad partial final grain
            if this_chunk < VMDK_GRAIN_SIZE_BYTES {
                core::ptr::write_bytes(
                    buf_data.add(this_chunk as usize),
                    0,
                    (VMDK_GRAIN_SIZE_BYTES - this_chunk) as usize,
                );
            }

            // Write grain data
            if !write_bytes_to_output(
                call_table,
                buf_data,
                grain_byte_offset,
                VMDK_GRAIN_SIZE_BYTES,
                oss,
                oc,
            ) {
                (call_table.send_error)(
                    b"convert\0".as_ptr(),
                    b"output\0".as_ptr(),
                    grain_byte_offset / oss as u64,
                    2,
                );
                (call_table.send_complete)(b"convert\0".as_ptr(), *bytes_read, false);
                return *bytes_read;
            }

            // Set GTE (sector offset in 512-byte sectors)
            let gt_idx = (grain - first_grain) as usize;
            let gt_slice = core::slice::from_raw_parts_mut(buf_gt, VMDK_GT_BYTES as usize);
            shared::write_le_u32(gt_slice, gt_idx * 4, (grain_byte_offset / 512) as u32);

            grains_done += 1;
            let pct = (grains_done * 100 / layout.total_grains) as u32;
            if should_report_progress(layout.progress_interval, pct, last_percent, grains_done) {
                (call_table.send_progress)(
                    b"convert\0".as_ptr(),
                    grains_done,
                    layout.total_grains,
                    pct,
                );
                last_percent = pct;
            }
        }

        // Flush GT if any grains were written
        if gt_allocated {
            // Write GT (padded to output sector size)
            let gt_write_bytes = align_up(VMDK_GT_BYTES, oss);
            if !write_bytes_to_output(call_table, buf_gt, gt_byte_offset, gt_write_bytes, oss, oc) {
                (call_table.send_error)(
                    b"convert\0".as_ptr(),
                    b"output\0".as_ptr(),
                    gt_byte_offset / oss as u64,
                    2,
                );
                (call_table.send_complete)(b"convert\0".as_ptr(), *bytes_read, false);
                return *bytes_read;
            }

            // Record GD entry (GT sector in 512-byte sectors)
            shared::write_le_u32(gd_slice, gd_idx as usize * 4, (gt_byte_offset / 512) as u32);
        }
        // else: GD[gd_idx] stays 0 (unallocated)
    }

    // -- Write GD at end --
    let gd_byte_offset = align_up(next_free_byte, oss);
    let gd_write_bytes = align_up(layout.gd_bytes as u64, oss).max(oss as u64);
    // Copy GD to the GT buffer (reuse it) for sector-aligned write
    core::ptr::write_bytes(buf_gt, 0, oss);
    core::ptr::copy_nonoverlapping(layout.gd_buf, buf_gt, layout.gd_bytes);
    if !write_bytes_to_output(call_table, buf_gt, gd_byte_offset, gd_write_bytes, oss, oc) {
        (call_table.send_complete)(b"convert\0".as_ptr(), *bytes_read, false);
        return *bytes_read;
    }

    // -- Write header + descriptor --
    // BUF_HEADER: use multipurpose buffer for header
    let buf_hdr = scratch_layout.buf_multipurpose as *mut u8;
    core::ptr::write_bytes(buf_hdr, 0, oss);
    let hdr_slice = core::slice::from_raw_parts_mut(buf_hdr, oss);

    // Overhead: everything before grain data in 512-byte sectors
    let overhead_sectors = layout.grain_data_start / 512;

    vmdk::build_sparse_header(
        hdr_slice,
        layout.capacity_sectors,
        VMDK_GRAIN_SIZE_SECTORS,
        VMDK_GTES_PER_GT,
        gd_byte_offset / 512,
        overhead_sectors,
    );

    // Descriptor starts at byte 512 within the header sector
    if oss >= 512 + (vmdk::DESC_SECTORS as usize * 512) {
        // Header + descriptor fit in one output sector
        vmdk::build_descriptor(hdr_slice, 512, layout.capacity_sectors);
        if !write_bytes_to_output(call_table, buf_hdr, 0, oss as u64, oss, oc) {
            (call_table.send_complete)(b"convert\0".as_ptr(), *bytes_read, false);
            return *bytes_read;
        }
    } else {
        // Write header sector(s) first, then descriptor sector(s)
        let hdr_write = align_up(512, oss);
        if !write_bytes_to_output(call_table, buf_hdr, 0, hdr_write, oss, oc) {
            (call_table.send_complete)(b"convert\0".as_ptr(), *bytes_read, false);
            return *bytes_read;
        }

        // Build descriptor in a separate buffer (BUF_REFCOUNT: multipurpose)
        let buf_desc = scratch_layout.buf_multipurpose as *mut u8;
        core::ptr::write_bytes(buf_desc, 0, oss);
        let desc_slice = core::slice::from_raw_parts_mut(buf_desc, oss);
        vmdk::build_descriptor(desc_slice, 0, layout.capacity_sectors);
        let desc_write = align_up(vmdk::DESC_SECTORS * 512, oss);
        if !write_bytes_to_output(call_table, buf_desc, 512, desc_write, oss, oc) {
            (call_table.send_complete)(b"convert\0".as_ptr(), *bytes_read, false);
            return *bytes_read;
        }
    }

    (call_table.send_complete)(b"convert\0".as_ptr(), *bytes_read, true);
    (call_table.verbose_print)(b"convert: done\n\0".as_ptr());
    *bytes_read
}

// ================================================================
// streamOptimized VMDK output (Phase 8e)
// ================================================================

/// Convert input to streamOptimized VMDK format with DEFLATE
/// compression.
///
/// Layout:
///   Header (512B, gd_offset=GD_AT_END) | Descriptor |
///   Grain markers + compressed data | GTs | GD |
///   Footer (512B, real gd_offset) | EOS marker (512B zeros)
#[allow(clippy::too_many_arguments)]
unsafe fn convert_to_vmdk_compressed(
    call_table: &CallTable,
    chain_config: &ChainConfig,
    chain_states: &mut qcow2::ChainStates,
    input_device_count: usize,
    virtual_size: u64,
    sector_size: usize,
    skip_zeros: bool,
    aes_key: Option<&[u8; 16]>,
    luks_key: Option<&[u8]>,
    luks_sector_size: u64,
    bytes_read: &mut u64,
    scratch_layout: &ScratchLayout,
) -> u64 {
    let layout = match init_vmdk_output_layout(
        call_table,
        input_device_count,
        virtual_size,
        bytes_read,
        scratch_layout,
    ) {
        Some(l) => l,
        None => return *bytes_read,
    };

    let buf_data = scratch_layout.buf_data as *mut u8;
    // BUF_L2_OUT: use multipurpose buffer for GT
    let buf_gt = scratch_layout.buf_multipurpose as *mut u8;
    // SAFETY: buf_staging intentionally aliases BUF_COMPRESSED_IN.
    // BUF_COMPRESSED_IN is also passed to read_chain_virtual_cluster()
    // as the input decompression buffer.  The read completes and its
    // result is copied into buf_data *before* we touch buf_staging for
    // output compression, so the two uses never overlap in time.
    // Do NOT reorder: output compression must stay after the read call.
    let buf_staging = scratch_layout.buf_compressed as *mut u8;
    let oss = layout.output_sector_size;

    // Staging buffer for decompressing clusters larger than chunk_size
    let staging_buf_addr = scratch_layout.dynamic_start + input_device_count * 2 * MAX_SECTOR_SIZE;
    let staging_buf = staging_buf_addr as *mut u8;
    let mut staging_cluster_offset: u64 = u64::MAX;
    let oc = layout.output_capacity;

    // CompressorOxide state follows GD buffer in scratch memory
    let gd_buf_end = (layout.gd_buf as usize) + ((layout.gd_bytes + 7) & !7);
    let compressor_addr = (gd_buf_end + 7) & !7;
    let compressor_size = qcow2::COMPRESSOR_STATE_SIZE;
    if compressor_addr + compressor_size > ALLOC_HEAP_BASE {
        (call_table.debug_print)(b"convert: no room for compressor state\n\0".as_ptr());
        (call_table.send_complete)(b"convert\0".as_ptr(), *bytes_read, false);
        return *bytes_read;
    }
    let compressor_mem = compressor_addr as *mut u8;

    (call_table.verbose_print)(b"convert: starting streamOptimized vmdk\n\0".as_ptr());
    // Write position starts after header+descriptor (sector-aligned)
    let mut write_pos = layout.grain_data_start;
    let mut grains_done: u64 = 0;
    let mut last_percent: u32 = 0;

    let gd_slice = core::slice::from_raw_parts_mut(layout.gd_buf, layout.gd_bytes);

    // Process each GD entry
    for gd_idx in 0..layout.num_gd_entries {
        // Zero the GT buffer
        core::ptr::write_bytes(buf_gt, 0, MAX_SECTOR_SIZE);

        let mut gt_has_data = false;

        let first_grain = gd_idx as u64 * VMDK_GTES_PER_GT as u64;
        let last_grain = core::cmp::min(first_grain + VMDK_GTES_PER_GT as u64, layout.total_grains);

        for grain in first_grain..last_grain {
            let virtual_offset = grain * VMDK_GRAIN_SIZE_BYTES;
            let remaining = virtual_size - virtual_offset;
            let this_chunk = if remaining < VMDK_GRAIN_SIZE_BYTES {
                remaining
            } else {
                VMDK_GRAIN_SIZE_BYTES
            };

            // Reset bump allocator before ZSTD decompression
            HEAP_POS.store(0, core::sync::atomic::Ordering::Relaxed);

            // Read input data
            if !qcow2::read_chain_virtual_cluster(
                call_table,
                0,
                input_device_count,
                virtual_offset,
                buf_data,
                this_chunk,
                sector_size,
                chain_config,
                chain_states,
                scratch_layout.buf_compressed as *mut u8,
                staging_buf,
                &mut staging_cluster_offset,
                aes_key,
                luks_key,
                luks_sector_size,
                bytes_read,
            ) {
                (call_table.send_error)(
                    b"convert\0".as_ptr(),
                    b"input\0".as_ptr(),
                    virtual_offset / sector_size as u64,
                    1,
                );
                (call_table.send_complete)(b"convert\0".as_ptr(), *bytes_read, false);
                return *bytes_read;
            }
            // Skip zero grains
            if skip_zeros && is_all_zeros_ptr(buf_data, this_chunk as usize) {
                grains_done += 1;
                let pct = (grains_done * 100 / layout.total_grains) as u32;
                if should_report_progress(layout.progress_interval, pct, last_percent, grains_done)
                {
                    (call_table.send_progress)(
                        b"convert\0".as_ptr(),
                        grains_done,
                        layout.total_grains,
                        pct,
                    );
                    last_percent = pct;
                }
                continue;
            }

            // Zero-pad partial final grain
            if this_chunk < VMDK_GRAIN_SIZE_BYTES {
                core::ptr::write_bytes(
                    buf_data.add(this_chunk as usize),
                    0,
                    (VMDK_GRAIN_SIZE_BYTES - this_chunk) as usize,
                );
            }

            // Reset bump allocator before compression
            HEAP_POS.store(0, core::sync::atomic::Ordering::Relaxed);

            // Compress the grain into staging buffer at offset 12
            // (leaving room for the grain marker header).
            let compress_out = buf_staging.add(vmdk::GRAIN_MARKER_SIZE);
            let compress_cap = COMPRESSED_BUF_SIZE - vmdk::GRAIN_MARKER_SIZE;
            let compressed_len = qcow2::compress_deflate_raw(
                compressor_mem,
                buf_data,
                VMDK_GRAIN_SIZE_BYTES as usize,
                compress_out,
                compress_cap,
            );

            if compressed_len == 0 {
                (call_table.debug_print)(b"convert: vmdk compression error\n\0".as_ptr());
                (call_table.send_complete)(b"convert\0".as_ptr(), *bytes_read, false);
                return *bytes_read;
            }

            // Build grain marker: 12 bytes (u64 LBA + u32 size)
            // followed by compressed data, padded to 512 bytes.
            let lba = virtual_offset / 512;
            let marker_plus_data = vmdk::GRAIN_MARKER_SIZE as u64 + compressed_len as u64;
            let padded = (marker_plus_data + 511) & !511;

            // Write marker header into the first 12 bytes
            let staging = core::slice::from_raw_parts_mut(buf_staging, padded as usize);
            shared::write_le_u64(staging, 0, lba);
            shared::write_le_u32(staging, 8, compressed_len as u32);
            // Zero padding after compressed data
            let data_end = vmdk::GRAIN_MARKER_SIZE + compressed_len;
            if data_end < padded as usize {
                core::ptr::write_bytes(buf_staging.add(data_end), 0, padded as usize - data_end);
            }

            // Write marker + compressed data to output
            if !write_bytes_to_output(call_table, buf_staging, write_pos, padded, oss, oc) {
                (call_table.send_error)(
                    b"convert\0".as_ptr(),
                    b"output\0".as_ptr(),
                    write_pos / oss as u64,
                    2,
                );
                (call_table.send_complete)(b"convert\0".as_ptr(), *bytes_read, false);
                return *bytes_read;
            }

            // Record GTE: sector offset of grain marker
            let gt_idx = (grain - first_grain) as usize;
            let gt_slice = core::slice::from_raw_parts_mut(buf_gt, VMDK_GT_BYTES as usize);
            shared::write_le_u32(gt_slice, gt_idx * 4, (write_pos / 512) as u32);

            write_pos += padded;
            gt_has_data = true;
            grains_done += 1;

            let pct = (grains_done * 100 / layout.total_grains) as u32;
            if should_report_progress(layout.progress_interval, pct, last_percent, grains_done) {
                (call_table.send_progress)(
                    b"convert\0".as_ptr(),
                    grains_done,
                    layout.total_grains,
                    pct,
                );
                last_percent = pct;
            }
        }

        // Write GT if any grains were written
        if gt_has_data {
            write_pos = (write_pos + 511) & !511;

            let gt_write_bytes = (VMDK_GT_BYTES + 511) & !511;
            let gt_sectors = gt_write_bytes / 512;

            // Write GT marker before the GT data (BUF_REFCOUNT: multipurpose)
            let buf_marker = scratch_layout.buf_multipurpose as *mut u8;
            core::ptr::write_bytes(buf_marker, 0, 512);
            let marker_slice = core::slice::from_raw_parts_mut(buf_marker, 512);
            vmdk::build_metadata_marker(marker_slice, gt_sectors as u64, vmdk::MARKER_GT);
            if !write_bytes_to_output(call_table, buf_marker, write_pos, 512, oss, oc) {
                (call_table.send_complete)(b"convert\0".as_ptr(), *bytes_read, false);
                return *bytes_read;
            }
            write_pos += 512;

            // Write GT data
            if !write_bytes_to_output(call_table, buf_gt, write_pos, gt_write_bytes, oss, oc) {
                (call_table.send_complete)(b"convert\0".as_ptr(), *bytes_read, false);
                return *bytes_read;
            }

            // GD entry points to the GT data (after marker)
            shared::write_le_u32(gd_slice, gd_idx as usize * 4, (write_pos / 512) as u32);
            write_pos += gt_write_bytes;
        }
    }

    // -- Write GD marker + GD --
    write_pos = (write_pos + 511) & !511;
    let gd_write_bytes = ((layout.gd_bytes as u64 + 511) & !511).max(512);
    let gd_sectors = gd_write_bytes / 512;

    // GD marker (BUF_REFCOUNT: multipurpose)
    let buf_marker = scratch_layout.buf_multipurpose as *mut u8;
    core::ptr::write_bytes(buf_marker, 0, 512);
    let marker_slice = core::slice::from_raw_parts_mut(buf_marker, 512);
    vmdk::build_metadata_marker(marker_slice, gd_sectors as u64, vmdk::MARKER_GD);
    if !write_bytes_to_output(call_table, buf_marker, write_pos, 512, oss, oc) {
        (call_table.send_complete)(b"convert\0".as_ptr(), *bytes_read, false);
        return *bytes_read;
    }
    write_pos += 512;

    // GD data
    let gd_byte_offset = write_pos;
    // BUF_HEADER: use multipurpose buffer for GD staging
    let buf_staging = scratch_layout.buf_multipurpose as *mut u8;
    core::ptr::write_bytes(buf_staging, 0, gd_write_bytes as usize);
    core::ptr::copy_nonoverlapping(layout.gd_buf, buf_staging, layout.gd_bytes);
    if !write_bytes_to_output(
        call_table,
        buf_staging,
        gd_byte_offset,
        gd_write_bytes,
        oss,
        oc,
    ) {
        (call_table.send_complete)(b"convert\0".as_ptr(), *bytes_read, false);
        return *bytes_read;
    }
    write_pos += gd_write_bytes;

    // -- Pad to MAX_SECTOR_SIZE boundary --
    // The footer structure (marker + footer + EOS = 3 sectors) must
    // be at the very end of the file. Pad so that the total file
    // size (write_pos + 1536) is a multiple of MAX_SECTOR_SIZE.
    // This ensures the VMDK can be read back with any sector size
    // up to MAX_SECTOR_SIZE without the capacity rounding up and
    // misaligning the footer.
    let footer_tail = 3 * 512u64; // marker + footer + EOS
    let total_before_pad = write_pos + footer_tail;
    let padded_total =
        (total_before_pad + MAX_SECTOR_SIZE as u64 - 1) & !(MAX_SECTOR_SIZE as u64 - 1);
    let pad_bytes = padded_total - total_before_pad;
    if pad_bytes > 0 {
        // Write zero-filled padding sectors (BUF_REFCOUNT: multipurpose)
        let buf_pad = scratch_layout.buf_multipurpose as *mut u8;
        core::ptr::write_bytes(buf_pad, 0, MAX_SECTOR_SIZE);
        let mut remaining = pad_bytes;
        while remaining > 0 {
            let chunk = core::cmp::min(remaining, oss as u64);
            if !write_bytes_to_output(call_table, buf_pad, write_pos, chunk, oss, oc) {
                (call_table.send_complete)(b"convert\0".as_ptr(), *bytes_read, false);
                return *bytes_read;
            }
            write_pos += chunk;
            remaining -= chunk;
        }
    }

    // -- Write footer marker + footer --
    // Footer marker
    core::ptr::write_bytes(buf_marker, 0, 512);
    let marker_slice = core::slice::from_raw_parts_mut(buf_marker, 512);
    vmdk::build_metadata_marker(
        marker_slice,
        1, // footer is 1 sector
        vmdk::MARKER_FOOTER,
    );
    if !write_bytes_to_output(call_table, buf_marker, write_pos, 512, oss, oc) {
        (call_table.send_complete)(b"convert\0".as_ptr(), *bytes_read, false);
        return *bytes_read;
    }
    write_pos += 512;

    // Footer (header copy with real GD offset) (BUF_HEADER: multipurpose)
    let buf_footer = scratch_layout.buf_multipurpose as *mut u8;
    core::ptr::write_bytes(buf_footer, 0, 512);
    let footer_slice = core::slice::from_raw_parts_mut(buf_footer, 512);
    let overhead_sectors = layout.grain_data_start / 512;
    vmdk::build_streamoptimized_header(
        footer_slice,
        layout.capacity_sectors,
        VMDK_GRAIN_SIZE_SECTORS,
        VMDK_GTES_PER_GT,
        gd_byte_offset / 512, // Real GD offset in the footer
        overhead_sectors,
    );
    if !write_bytes_to_output(call_table, buf_footer, write_pos, 512, oss, oc) {
        (call_table.send_complete)(b"convert\0".as_ptr(), *bytes_read, false);
        return *bytes_read;
    }
    write_pos += 512;

    // -- Write EOS marker (sector of zeros) --
    core::ptr::write_bytes(buf_footer, 0, 512);
    if !write_bytes_to_output(call_table, buf_footer, write_pos, 512, oss, oc) {
        (call_table.send_complete)(b"convert\0".as_ptr(), *bytes_read, false);
        return *bytes_read;
    }

    // -- Write header at offset 0 (gd_offset = GD_AT_END) --
    // BUF_HEADER: use multipurpose buffer for header
    let buf_hdr = scratch_layout.buf_multipurpose as *mut u8;
    core::ptr::write_bytes(buf_hdr, 0, 512);
    let hdr_slice = core::slice::from_raw_parts_mut(buf_hdr, 512);
    vmdk::build_streamoptimized_header(
        hdr_slice,
        layout.capacity_sectors,
        VMDK_GRAIN_SIZE_SECTORS,
        VMDK_GTES_PER_GT,
        vmdk::GD_AT_END, // GD_AT_END sentinel (raw value)
        overhead_sectors,
    );
    if !write_bytes_to_output(call_table, buf_hdr, 0, 512, oss, oc) {
        (call_table.send_complete)(b"convert\0".as_ptr(), *bytes_read, false);
        return *bytes_read;
    }

    // -- Write descriptor at offset 512 --
    // BUF_REFCOUNT: use multipurpose buffer for descriptor
    let buf_desc = scratch_layout.buf_multipurpose as *mut u8;
    let desc_bytes = vmdk::DESC_SECTORS * 512;
    core::ptr::write_bytes(buf_desc, 0, desc_bytes as usize);
    let desc_slice = core::slice::from_raw_parts_mut(buf_desc, desc_bytes as usize);
    vmdk::build_streamoptimized_descriptor(desc_slice, 0, layout.capacity_sectors);
    if !write_bytes_to_output(call_table, buf_desc, 512, desc_bytes, oss, oc) {
        (call_table.send_complete)(b"convert\0".as_ptr(), *bytes_read, false);
        return *bytes_read;
    }

    (call_table.send_complete)(b"convert\0".as_ptr(), *bytes_read, true);
    (call_table.verbose_print)(b"convert: done\n\0".as_ptr());
    *bytes_read
}

// ================================================================
// VHD output path
// ================================================================

/// Convert input to VHD dynamic format.
///
/// Layout:
/// ```text
/// [0]        Footer copy (512 bytes, padded to output sector)
/// [oss]      Dynamic header (1024 bytes, padded to output sector)
/// [bat_off]  BAT (max_table_entries × 4, padded to output sector)
/// [data]     Block data: sector bitmap + block_size per block
/// [EOF-oss]  Footer (512 bytes, padded to output sector)
/// ```
///
/// Blocks are written sequentially. The BAT is written as all-
/// unallocated initially, then rewritten with actual offsets after
/// all blocks are emitted.
#[allow(clippy::too_many_arguments)]
unsafe fn convert_to_vhd(
    call_table: &CallTable,
    chain_config: &ChainConfig,
    chain_states: &mut qcow2::ChainStates,
    input_device_count: usize,
    virtual_size: u64,
    sector_size: usize,
    skip_zeros: bool,
    aes_key: Option<&[u8; 16]>,
    luks_key: Option<&[u8]>,
    luks_sector_size: u64,
    bytes_read: &mut u64,
    layout: &ScratchLayout,
) -> u64 {
    let oss = (call_table.get_output_sector_size)();
    let oc = (call_table.get_output_capacity)();
    let progress_interval = (call_table.get_progress_interval)();

    let block_size = vhd::DEFAULT_BLOCK_SIZE as u64; // 2 MiB
    let max_table_entries = ((virtual_size + block_size - 1) / block_size) as u32;

    // Sector bitmap: ceil(block_size / 512 / 8) rounded up to 512
    let sectors_per_block = block_size / 512;
    let bitmap_bytes = ((sectors_per_block + 7) / 8 + 511) & !511;

    // Layout offsets (all aligned to output sector size)
    let footer_copy_offset: u64 = 0;
    let dyn_header_offset = align_up(vhd::FOOTER_SIZE as u64, oss);
    let bat_offset = align_up(dyn_header_offset + vhd::DYNAMIC_HEADER_SIZE as u64, oss);
    let bat_size_bytes = max_table_entries as u64 * 4;
    let bat_padded = align_up(bat_size_bytes, oss);
    let data_start = bat_offset + bat_padded;

    // BAT buffer — allocate after dynamic input caches + staging buffer
    let bat_buf_addr =
        layout.dynamic_start + input_device_count * 2 * MAX_SECTOR_SIZE + MAX_CLUSTER_SIZE;
    let bat_alloc = align_up(bat_size_bytes, 8) as usize;

    if bat_buf_addr + bat_alloc > ALLOC_HEAP_BASE {
        (call_table.debug_print)(b"convert: VHD BAT too large for scratch\n\0".as_ptr());
        (call_table.send_complete)(b"convert\0".as_ptr(), *bytes_read, false);
        return *bytes_read;
    }

    let bat_buf = bat_buf_addr as *mut u8;
    // Initialize all BAT entries to 0xFFFFFFFF (unallocated)
    core::ptr::write_bytes(bat_buf, 0xFF, bat_alloc);

    // Staging buffer for decompressing clusters larger than chunk_size
    let staging_buf_addr = layout.dynamic_start + input_device_count * 2 * MAX_SECTOR_SIZE;
    let staging_buf = staging_buf_addr as *mut u8;
    let mut staging_cluster_offset: u64 = u64::MAX;

    (call_table.verbose_print)(b"convert: starting VHD conversion\n\0".as_ptr());

    // Generate a deterministic UUID from virtual_size
    let mut uuid = [0u8; 16];
    let size_bytes = virtual_size.to_le_bytes();
    uuid[0..8].copy_from_slice(&size_bytes);
    // Mark as UUID version 4, variant 1 for basic conformance
    uuid[6] = (uuid[6] & 0x0F) | 0x40; // version 4
    uuid[8] = (uuid[8] & 0x3F) | 0x80; // variant 1

    // Write initial footer copy at offset 0
    // BUF_HEADER: use multipurpose buffer for header
    let buf_hdr = layout.buf_multipurpose as *mut u8;
    core::ptr::write_bytes(buf_hdr, 0, oss);
    let footer_slice = core::slice::from_raw_parts_mut(buf_hdr, vhd::FOOTER_SIZE);
    vhd::build_footer(
        footer_slice,
        virtual_size,
        vhd::DISK_TYPE_DYNAMIC,
        dyn_header_offset,
        &uuid,
    );
    if !write_bytes_to_output(
        call_table,
        buf_hdr,
        footer_copy_offset,
        align_up(vhd::FOOTER_SIZE as u64, oss),
        oss,
        oc,
    ) {
        (call_table.send_error)(b"convert\0".as_ptr(), b"output\0".as_ptr(), 0, 2);
        (call_table.send_complete)(b"convert\0".as_ptr(), *bytes_read, false);
        return *bytes_read;
    }

    // Write dynamic header
    core::ptr::write_bytes(buf_hdr, 0, oss);
    let dyn_slice = core::slice::from_raw_parts_mut(buf_hdr, vhd::DYNAMIC_HEADER_SIZE);
    vhd::build_dynamic_header(dyn_slice, bat_offset, max_table_entries, block_size as u32);
    if !write_bytes_to_output(
        call_table,
        buf_hdr,
        dyn_header_offset,
        align_up(vhd::DYNAMIC_HEADER_SIZE as u64, oss),
        oss,
        oc,
    ) {
        (call_table.send_error)(
            b"convert\0".as_ptr(),
            b"output\0".as_ptr(),
            dyn_header_offset / oss as u64,
            2,
        );
        (call_table.send_complete)(b"convert\0".as_ptr(), *bytes_read, false);
        return *bytes_read;
    }

    // Write placeholder BAT (all 0xFFFFFFFF)
    // Write in output-sector-sized chunks
    // BUF_L2_OUT: use multipurpose buffer for BAT write
    let bat_write_buf = layout.buf_multipurpose as *mut u8;
    let mut bat_written: u64 = 0;
    while bat_written < bat_padded {
        core::ptr::write_bytes(bat_write_buf, 0xFF, oss);
        if !write_bytes_to_output(
            call_table,
            bat_write_buf,
            bat_offset + bat_written,
            oss as u64,
            oss,
            oc,
        ) {
            (call_table.send_complete)(b"convert\0".as_ptr(), *bytes_read, false);
            return *bytes_read;
        }
        bat_written += oss as u64;
    }

    // Write block data
    let buf_data = layout.buf_data as *mut u8;
    let mut next_free_byte = data_start;
    let mut blocks_done: u64 = 0;
    let total_blocks = max_table_entries as u64;
    let mut last_percent: u32 = 0;

    // Prepare a sector bitmap with all bits set (all sectors present)
    // Reuse BUF_REFCOUNT (multipurpose buffer) for bitmap
    let bitmap_buf = layout.buf_multipurpose as *mut u8;
    core::ptr::write_bytes(bitmap_buf, 0xFF, bitmap_bytes as usize);

    for block_idx in 0..max_table_entries {
        let virtual_offset = block_idx as u64 * block_size;
        let remaining = virtual_size - virtual_offset;
        let this_block = if remaining < block_size {
            remaining
        } else {
            block_size
        };

        // Reset bump allocator before ZSTD decompression
        HEAP_POS.store(0, core::sync::atomic::Ordering::Relaxed);

        // Read input data (block_size may be > MAX_SECTOR_SIZE,
        // so read in chunks)
        let mut block_all_zeros = true;
        let chunk_size = MAX_SECTOR_SIZE as u64;
        let mut intra_offset: u64 = 0;

        // First pass: check if entire block is zeros
        while intra_offset < this_block {
            let chunk_remaining = this_block - intra_offset;
            let this_chunk = if chunk_remaining < chunk_size {
                chunk_remaining
            } else {
                chunk_size
            };

            HEAP_POS.store(0, core::sync::atomic::Ordering::Relaxed);

            if !qcow2::read_chain_virtual_cluster(
                call_table,
                0,
                input_device_count,
                virtual_offset + intra_offset,
                buf_data,
                this_chunk,
                sector_size,
                chain_config,
                chain_states,
                layout.buf_compressed as *mut u8,
                staging_buf,
                &mut staging_cluster_offset,
                aes_key,
                luks_key,
                luks_sector_size,
                bytes_read,
            ) {
                (call_table.send_error)(
                    b"convert\0".as_ptr(),
                    b"input\0".as_ptr(),
                    (virtual_offset + intra_offset) / sector_size as u64,
                    1,
                );
                (call_table.send_complete)(b"convert\0".as_ptr(), *bytes_read, false);
                return *bytes_read;
            }

            if !is_all_zeros_ptr(buf_data, this_chunk as usize) {
                block_all_zeros = false;
                break;
            }

            intra_offset += this_chunk;
        }

        // Skip zero blocks when configured
        if skip_zeros && block_all_zeros {
            blocks_done += 1;
            let pct = (blocks_done * 100 / total_blocks) as u32;
            if should_report_progress(progress_interval, pct, last_percent, blocks_done) {
                (call_table.send_progress)(b"convert\0".as_ptr(), blocks_done, total_blocks, pct);
                last_percent = pct;
            }
            continue;
        }

        // Allocate block aligned to output sector size. The bitmap
        // and data form a contiguous stream; they must be written
        // together because the output sector size can exceed 512
        // bytes, and separate writes would clobber each other when
        // bitmap and data share the same output sector.
        let block_byte_offset = align_up(next_free_byte, oss);
        let block_raw_bytes = bitmap_bytes + block_size;
        let block_aligned = (block_raw_bytes + oss as u64 - 1) & !(oss as u64 - 1);
        next_free_byte = block_byte_offset + block_aligned;

        // Record BAT entry (absolute sector in 512-byte sectors)
        let bat_slice = core::slice::from_raw_parts_mut(bat_buf, bat_alloc);
        shared::write_be_u32(
            bat_slice,
            block_idx as usize * 4,
            (block_byte_offset / 512) as u32,
        );

        // Write bitmap + data as sector-aligned I/O. Input reads
        // must stay sector-aligned; the bitmap shifts data by
        // bitmap_bytes so each output sector is assembled from a
        // carry (leftover from previous read) plus a fresh read.
        // BUF_L2_OUT: use multipurpose buffer for read buffer
        let read_buf = layout.buf_multipurpose as *mut u8;
        // BUF_HEADER: use compressed buffer for carry (non-overlapping use)
        let carry_buf = layout.buf_compressed as *mut u8;
        let mut carry_len: usize = 0;
        let mut vdata_read: u64 = 0;
        let total_sectors = block_aligned / oss as u64;

        for s in 0..total_sectors {
            let write_offset = block_byte_offset + s * chunk_size;

            // Zero the output buffer (padding is automatic)
            core::ptr::write_bytes(buf_data, 0, chunk_size as usize);
            let mut out_pos: usize = 0;

            // First sector: prepend bitmap
            if s == 0 {
                core::ptr::copy_nonoverlapping(bitmap_buf, buf_data, bitmap_bytes as usize);
                out_pos = bitmap_bytes as usize;
            }

            // Prepend carry from previous read
            if carry_len > 0 {
                core::ptr::copy_nonoverlapping(carry_buf, buf_data.add(out_pos), carry_len);
                out_pos += carry_len;
                carry_len = 0;
            }

            // Read a sector-aligned chunk of virtual data
            let space = chunk_size as usize - out_pos;
            if space > 0 && vdata_read < this_block {
                let remaining = this_block - vdata_read;
                let to_read = if remaining < chunk_size {
                    remaining
                } else {
                    chunk_size
                };

                HEAP_POS.store(0, core::sync::atomic::Ordering::Relaxed);

                if !qcow2::read_chain_virtual_cluster(
                    call_table,
                    0,
                    input_device_count,
                    virtual_offset + vdata_read,
                    read_buf,
                    to_read,
                    sector_size,
                    chain_config,
                    chain_states,
                    layout.buf_compressed as *mut u8,
                    staging_buf,
                    &mut staging_cluster_offset,
                    aes_key,
                    luks_key,
                    luks_sector_size,
                    bytes_read,
                ) {
                    (call_table.send_error)(
                        b"convert\0".as_ptr(),
                        b"input\0".as_ptr(),
                        (virtual_offset + vdata_read) / sector_size as u64,
                        1,
                    );
                    (call_table.send_complete)(b"convert\0".as_ptr(), *bytes_read, false);
                    return *bytes_read;
                }
                vdata_read += to_read;

                // Copy what fits into the output sector
                let copy_len = if (to_read as usize) <= space {
                    to_read as usize
                } else {
                    space
                };
                core::ptr::copy_nonoverlapping(read_buf, buf_data.add(out_pos), copy_len);

                // Save excess as carry for next sector
                if (to_read as usize) > space {
                    carry_len = to_read as usize - space;
                    core::ptr::copy_nonoverlapping(read_buf.add(space), carry_buf, carry_len);
                }
            }

            // Write full sector (unused bytes are already zeroed)
            if !write_bytes_to_output(call_table, buf_data, write_offset, chunk_size, oss, oc) {
                (call_table.send_error)(
                    b"convert\0".as_ptr(),
                    b"output\0".as_ptr(),
                    write_offset / oss as u64,
                    2,
                );
                (call_table.send_complete)(b"convert\0".as_ptr(), *bytes_read, false);
                return *bytes_read;
            }
        }

        blocks_done += 1;
        let pct = (blocks_done * 100 / total_blocks) as u32;
        if should_report_progress(progress_interval, pct, last_percent, blocks_done) {
            (call_table.send_progress)(b"convert\0".as_ptr(), blocks_done, total_blocks, pct);
            last_percent = pct;
        }
    }

    // Rewrite BAT with actual offsets
    let mut bat_rewritten: u64 = 0;
    while bat_rewritten < bat_padded {
        let write_len = oss as u64;
        // Copy from BAT buffer to write buffer
        let src_off = bat_rewritten as usize;
        let copy_len = if src_off + oss <= bat_alloc {
            oss
        } else {
            bat_alloc - src_off
        };
        core::ptr::write_bytes(bat_write_buf, 0xFF, oss);
        if copy_len > 0 {
            core::ptr::copy_nonoverlapping(bat_buf.add(src_off), bat_write_buf, copy_len);
        }
        if !write_bytes_to_output(
            call_table,
            bat_write_buf,
            bat_offset + bat_rewritten,
            write_len,
            oss,
            oc,
        ) {
            (call_table.send_complete)(b"convert\0".as_ptr(), *bytes_read, false);
            return *bytes_read;
        }
        bat_rewritten += write_len;
    }

    // Write final footer at end of file
    let footer_end_offset = align_up(next_free_byte, oss);
    core::ptr::write_bytes(buf_hdr, 0, oss);
    let footer_slice = core::slice::from_raw_parts_mut(buf_hdr, vhd::FOOTER_SIZE);
    vhd::build_footer(
        footer_slice,
        virtual_size,
        vhd::DISK_TYPE_DYNAMIC,
        dyn_header_offset,
        &uuid,
    );
    if !write_bytes_to_output(
        call_table,
        buf_hdr,
        footer_end_offset,
        align_up(vhd::FOOTER_SIZE as u64, oss),
        oss,
        oc,
    ) {
        (call_table.send_complete)(b"convert\0".as_ptr(), *bytes_read, false);
        return *bytes_read;
    }

    (call_table.send_complete)(b"convert\0".as_ptr(), *bytes_read, true);
    (call_table.verbose_print)(b"convert: VHD done\n\0".as_ptr());
    *bytes_read
}

// ================================================================
// VHDX output path
// ================================================================

/// Convert input to VHDX dynamic output.
///
/// VHDX output layout (all regions 1MB-aligned):
///   0x00000     File Identifier (64KB)
///   0x10000     Header 1 (64KB)
///   0x20000     Header 2 (64KB)
///   0x30000     Region Table 1 (64KB)
///   0x40000     Region Table 2 (64KB)
///   0x100000    Log region (1MB, empty/reserved)
///   0x200000    BAT region (1MB-aligned)
///   next 1MB    Metadata region (1MB)
///   next 1MB    Payload blocks (block_size each)
#[allow(clippy::too_many_arguments)]
unsafe fn convert_to_vhdx(
    call_table: &CallTable,
    chain_config: &ChainConfig,
    chain_states: &mut qcow2::ChainStates,
    input_device_count: usize,
    virtual_size: u64,
    sector_size: usize,
    skip_zeros: bool,
    aes_key: Option<&[u8; 16]>,
    luks_key: Option<&[u8]>,
    luks_sector_size: u64,
    bytes_read: &mut u64,
    layout: &ScratchLayout,
) -> u64 {
    let oss = (call_table.get_output_sector_size)();
    let oc = (call_table.get_output_capacity)();
    let progress_interval = (call_table.get_progress_interval)();

    let block_size = vhdx::DEFAULT_BLOCK_SIZE as u64; // 32 MiB
    let logical_sector_size: u32 = 512;
    let physical_sector_size: u32 = 4096;

    let (total_bat_entries, chunk_ratio, total_payload_blocks) =
        match vhdx::calculate_bat_layout(virtual_size, block_size as u32, logical_sector_size) {
            Some(v) => v,
            None => {
                (call_table.send_error)(
                    b"convert\0".as_ptr(),
                    b"VHDX BAT layout overflow\0".as_ptr(),
                    0,
                    1,
                );
                return 1;
            }
        };

    // Layout offsets (all 1MB-aligned per VHDX spec)
    let file_id_offset: u64 = 0; // 64KB
    let _header1_offset: u64 = 0x10000; // 64KB
    let _header2_offset: u64 = 0x20000; // 64KB
    let _rt1_offset: u64 = 0x30000; // 64KB
    let _rt2_offset: u64 = 0x40000; // 64KB
    let log_offset: u64 = 0x10_0000; // 1MB
    let bat_offset: u64 = 0x20_0000; // 2MB
    let bat_size_bytes = total_bat_entries as u64 * 8;
    let bat_region_size = align_up(bat_size_bytes, vhdx::MB_ALIGN as usize);
    let metadata_offset = bat_offset + bat_region_size;
    let metadata_region_size = vhdx::MB_ALIGN; // 1MB
    let payload_start = metadata_offset + metadata_region_size;

    // BAT buffer — allocate after dynamic input caches + staging buffer
    let bat_buf_addr =
        layout.dynamic_start + input_device_count * 2 * MAX_SECTOR_SIZE + MAX_CLUSTER_SIZE;
    let bat_alloc = align_up(bat_size_bytes, 8) as usize;

    if bat_buf_addr + bat_alloc > ALLOC_HEAP_BASE {
        (call_table.debug_print)(b"convert: VHDX BAT too large for scratch\n\0".as_ptr());
        (call_table.send_complete)(b"convert\0".as_ptr(), *bytes_read, false);
        return *bytes_read;
    }

    let bat_buf = bat_buf_addr as *mut u8;
    // Initialize all BAT entries to 0 (NOT_PRESENT)
    core::ptr::write_bytes(bat_buf, 0, bat_alloc);

    // Staging buffer for decompressing clusters larger than chunk_size
    let staging_buf_addr = layout.dynamic_start + input_device_count * 2 * MAX_SECTOR_SIZE;
    let staging_buf = staging_buf_addr as *mut u8;
    let mut staging_cluster_offset: u64 = u64::MAX;

    (call_table.verbose_print)(b"convert: starting VHDX conversion\n\0".as_ptr());

    // --- Write file identifier (64KB) ---
    // BUF_HEADER: use multipurpose buffer for header
    let buf_hdr = layout.buf_multipurpose as *mut u8;
    core::ptr::write_bytes(buf_hdr, 0, MAX_SECTOR_SIZE);
    let fi_slice = core::slice::from_raw_parts_mut(buf_hdr, MAX_SECTOR_SIZE);
    vhdx::build_file_identifier(fi_slice);
    if !write_bytes_to_output(
        call_table,
        buf_hdr,
        file_id_offset,
        MAX_SECTOR_SIZE as u64,
        oss,
        oc,
    ) {
        (call_table.send_error)(b"convert\0".as_ptr(), b"output\0".as_ptr(), 0, 2);
        (call_table.send_complete)(b"convert\0".as_ptr(), *bytes_read, false);
        return *bytes_read;
    }

    // --- Write Header 1 (4KB header in 64KB region) ---
    core::ptr::write_bytes(buf_hdr, 0, MAX_SECTOR_SIZE);
    let hdr_slice = core::slice::from_raw_parts_mut(buf_hdr, vhdx::HEADER_SIZE);
    vhdx::build_header(hdr_slice, 1); // sequence_number = 1
                                      // Write as 64KB region (pad remaining with zeros — already zeroed)
    if !write_bytes_to_output(
        call_table,
        buf_hdr,
        vhdx::HEADER1_OFFSET,
        MAX_SECTOR_SIZE as u64,
        oss,
        oc,
    ) {
        (call_table.send_error)(
            b"convert\0".as_ptr(),
            b"output\0".as_ptr(),
            vhdx::HEADER1_OFFSET / oss as u64,
            2,
        );
        (call_table.send_complete)(b"convert\0".as_ptr(), *bytes_read, false);
        return *bytes_read;
    }

    // --- Write Header 2 (copy with sequence_number = 2) ---
    core::ptr::write_bytes(buf_hdr, 0, MAX_SECTOR_SIZE);
    let hdr_slice = core::slice::from_raw_parts_mut(buf_hdr, vhdx::HEADER_SIZE);
    vhdx::build_header(hdr_slice, 2); // sequence_number = 2
    if !write_bytes_to_output(
        call_table,
        buf_hdr,
        vhdx::HEADER2_OFFSET,
        MAX_SECTOR_SIZE as u64,
        oss,
        oc,
    ) {
        (call_table.send_error)(
            b"convert\0".as_ptr(),
            b"output\0".as_ptr(),
            vhdx::HEADER2_OFFSET / oss as u64,
            2,
        );
        (call_table.send_complete)(b"convert\0".as_ptr(), *bytes_read, false);
        return *bytes_read;
    }

    // --- Write Region Table 1 (64KB) ---
    core::ptr::write_bytes(buf_hdr, 0, MAX_SECTOR_SIZE);
    let rt_slice = core::slice::from_raw_parts_mut(buf_hdr, MAX_SECTOR_SIZE);
    vhdx::build_region_table(
        rt_slice,
        bat_offset,
        bat_region_size as u32,
        metadata_offset,
        metadata_region_size as u32,
    );
    if !write_bytes_to_output(
        call_table,
        buf_hdr,
        vhdx::REGION_TABLE1_OFFSET,
        MAX_SECTOR_SIZE as u64,
        oss,
        oc,
    ) {
        (call_table.send_complete)(b"convert\0".as_ptr(), *bytes_read, false);
        return *bytes_read;
    }

    // --- Write Region Table 2 (copy) ---
    if !write_bytes_to_output(
        call_table,
        buf_hdr,
        vhdx::REGION_TABLE2_OFFSET,
        MAX_SECTOR_SIZE as u64,
        oss,
        oc,
    ) {
        (call_table.send_complete)(b"convert\0".as_ptr(), *bytes_read, false);
        return *bytes_read;
    }

    // --- Write log region (1MB of zeros, just ensure it exists) ---
    // The log region is at 0x100000, 1MB. Since output is pre-zeroed
    // for sparse formats, we only need to ensure the region exists
    // by writing at least one sector.
    core::ptr::write_bytes(buf_hdr, 0, oss);
    if !write_bytes_to_output(call_table, buf_hdr, log_offset, oss as u64, oss, oc) {
        (call_table.send_complete)(b"convert\0".as_ptr(), *bytes_read, false);
        return *bytes_read;
    }

    // --- Write placeholder BAT (all NOT_PRESENT = 0x00) ---
    // BUF_L2_OUT: use multipurpose buffer for BAT write
    let bat_write_buf = layout.buf_multipurpose as *mut u8;
    let mut bat_written: u64 = 0;
    let bat_padded = align_up(bat_size_bytes, oss);
    while bat_written < bat_padded {
        core::ptr::write_bytes(bat_write_buf, 0, oss);
        if !write_bytes_to_output(
            call_table,
            bat_write_buf,
            bat_offset + bat_written,
            oss as u64,
            oss,
            oc,
        ) {
            (call_table.send_complete)(b"convert\0".as_ptr(), *bytes_read, false);
            return *bytes_read;
        }
        bat_written += oss as u64;
    }

    // --- Write metadata region ---
    // Metadata table is in the first sector, items at offset 0x10000
    // within the metadata region. We need to write both parts.

    // Write metadata table header (first 64KB of metadata region)
    core::ptr::write_bytes(buf_hdr, 0, MAX_SECTOR_SIZE);
    let md_slice = core::slice::from_raw_parts_mut(buf_hdr, MAX_SECTOR_SIZE);
    vhdx::build_metadata(
        md_slice,
        block_size as u32,
        virtual_size,
        logical_sector_size,
        physical_sector_size,
        false, // no parent
    );
    if !write_bytes_to_output(
        call_table,
        buf_hdr,
        metadata_offset,
        MAX_SECTOR_SIZE as u64,
        oss,
        oc,
    ) {
        (call_table.send_complete)(b"convert\0".as_ptr(), *bytes_read, false);
        return *bytes_read;
    }

    // The metadata items are at metadata_offset + 0x10000. The
    // build_metadata() wrote them into the buffer at offset 0x10000
    // if the buffer was large enough. Since MAX_SECTOR_SIZE = 64KB
    // = 0x10000, the items are at the very end of our 64KB buffer.
    // We need to write them as a separate sector.
    // Actually, build_metadata writes items at buf[0x10000..], but
    // our buffer is exactly 0x10000 (64KB), so items_base is at
    // the buffer boundary. Let's handle this by writing metadata
    // items separately.
    let buf_data = layout.buf_data as *mut u8;
    core::ptr::write_bytes(buf_data, 0, oss);
    let item_slice = core::slice::from_raw_parts_mut(buf_data, oss);
    // File Parameters: block_size (u32) + flags (u32)
    shared::write_le_u32(item_slice, 0, block_size as u32);
    shared::write_le_u32(item_slice, 4, 0); // flags: no parent
                                            // Virtual Disk Size (u64) at offset 8
    shared::write_le_u64(item_slice, 8, virtual_size);
    // Logical Sector Size (u32) at offset 16
    shared::write_le_u32(item_slice, 16, logical_sector_size);
    // Physical Sector Size (u32) at offset 20
    shared::write_le_u32(item_slice, 20, physical_sector_size);
    // Virtual Disk ID (16 bytes) at offset 24
    let size_bytes = virtual_size.to_le_bytes();
    item_slice[24..32].copy_from_slice(&size_bytes);
    let bs_bytes = (block_size as u32).to_le_bytes();
    item_slice[32..36].copy_from_slice(&bs_bytes);
    item_slice[36] = b'V';
    item_slice[37] = b'H';
    item_slice[38] = b'D';
    item_slice[39] = b'X';

    if !write_bytes_to_output(
        call_table,
        buf_data,
        metadata_offset + 0x10000,
        oss as u64,
        oss,
        oc,
    ) {
        (call_table.send_complete)(b"convert\0".as_ptr(), *bytes_read, false);
        return *bytes_read;
    }

    // --- Write payload blocks ---
    let mut next_free_offset = payload_start;
    let mut blocks_done: u64 = 0;
    let total_blocks = total_payload_blocks as u64;
    let mut last_percent: u32 = 0;
    let chunk_size = MAX_SECTOR_SIZE as u64;

    for block_idx in 0..total_payload_blocks {
        let virtual_offset = block_idx as u64 * block_size;
        let remaining = virtual_size - virtual_offset;
        let this_block = if remaining < block_size {
            remaining
        } else {
            block_size
        };

        HEAP_POS.store(0, core::sync::atomic::Ordering::Relaxed);

        // First pass: check if block is all zeros
        let mut block_all_zeros = true;
        let mut intra_offset: u64 = 0;

        while intra_offset < this_block {
            let chunk_remaining = this_block - intra_offset;
            let this_chunk = if chunk_remaining < chunk_size {
                chunk_remaining
            } else {
                chunk_size
            };

            HEAP_POS.store(0, core::sync::atomic::Ordering::Relaxed);

            if !qcow2::read_chain_virtual_cluster(
                call_table,
                0,
                input_device_count,
                virtual_offset + intra_offset,
                buf_data,
                this_chunk,
                sector_size,
                chain_config,
                chain_states,
                layout.buf_compressed as *mut u8,
                staging_buf,
                &mut staging_cluster_offset,
                aes_key,
                luks_key,
                luks_sector_size,
                bytes_read,
            ) {
                (call_table.send_error)(
                    b"convert\0".as_ptr(),
                    b"input\0".as_ptr(),
                    (virtual_offset + intra_offset) / sector_size as u64,
                    1,
                );
                (call_table.send_complete)(b"convert\0".as_ptr(), *bytes_read, false);
                return *bytes_read;
            }

            if !is_all_zeros_ptr(buf_data, this_chunk as usize) {
                block_all_zeros = false;
                break;
            }

            intra_offset += this_chunk;
        }

        // Skip zero blocks when configured
        if skip_zeros && block_all_zeros {
            blocks_done += 1;
            let pct = (blocks_done * 100 / total_blocks) as u32;
            if should_report_progress(progress_interval, pct, last_percent, blocks_done) {
                (call_table.send_progress)(b"convert\0".as_ptr(), blocks_done, total_blocks, pct);
                last_percent = pct;
            }
            continue;
        }

        // Allocate block (must be 1MB-aligned per VHDX spec)
        let block_file_offset = align_up(next_free_offset, vhdx::MB_ALIGN as usize);
        next_free_offset = block_file_offset + block_size;

        // Record BAT entry: state=FULLY_PRESENT, offset=block_file_offset
        let bat_index = vhdx_payload_bat_index(block_idx, chunk_ratio);
        let entry = vhdx::build_bat_entry(vhdx::PAYLOAD_BLOCK_FULLY_PRESENT, block_file_offset);
        let bat_slice = core::slice::from_raw_parts_mut(bat_buf, bat_alloc);
        shared::write_le_u64(bat_slice, bat_index as usize * 8, entry);

        // Write block data in chunks
        intra_offset = 0;
        while intra_offset < this_block {
            let chunk_remaining = this_block - intra_offset;
            let this_chunk = if chunk_remaining < chunk_size {
                chunk_remaining
            } else {
                chunk_size
            };

            HEAP_POS.store(0, core::sync::atomic::Ordering::Relaxed);

            if !qcow2::read_chain_virtual_cluster(
                call_table,
                0,
                input_device_count,
                virtual_offset + intra_offset,
                buf_data,
                this_chunk,
                sector_size,
                chain_config,
                chain_states,
                layout.buf_compressed as *mut u8,
                staging_buf,
                &mut staging_cluster_offset,
                aes_key,
                luks_key,
                luks_sector_size,
                bytes_read,
            ) {
                (call_table.send_error)(
                    b"convert\0".as_ptr(),
                    b"input\0".as_ptr(),
                    (virtual_offset + intra_offset) / sector_size as u64,
                    1,
                );
                (call_table.send_complete)(b"convert\0".as_ptr(), *bytes_read, false);
                return *bytes_read;
            }

            // Zero-pad partial final chunk
            if this_chunk < chunk_size {
                core::ptr::write_bytes(
                    buf_data.add(this_chunk as usize),
                    0,
                    (chunk_size - this_chunk) as usize,
                );
            }

            if !write_bytes_to_output(
                call_table,
                buf_data,
                block_file_offset + intra_offset,
                this_chunk,
                oss,
                oc,
            ) {
                (call_table.send_error)(
                    b"convert\0".as_ptr(),
                    b"output\0".as_ptr(),
                    (block_file_offset + intra_offset) / oss as u64,
                    2,
                );
                (call_table.send_complete)(b"convert\0".as_ptr(), *bytes_read, false);
                return *bytes_read;
            }

            intra_offset += this_chunk;
        }

        // Zero-pad remaining block data if this_block < block_size
        if this_block < block_size {
            let pad_start = block_file_offset + this_block;
            let pad_len = block_size - this_block;
            let mut pad_written: u64 = 0;
            core::ptr::write_bytes(buf_data, 0, chunk_size as usize);
            while pad_written < pad_len {
                let write_len = if pad_len - pad_written < chunk_size {
                    pad_len - pad_written
                } else {
                    chunk_size
                };
                if !write_bytes_to_output(
                    call_table,
                    buf_data,
                    pad_start + pad_written,
                    write_len,
                    oss,
                    oc,
                ) {
                    (call_table.send_complete)(b"convert\0".as_ptr(), *bytes_read, false);
                    return *bytes_read;
                }
                pad_written += write_len;
            }
        }

        blocks_done += 1;
        let pct = (blocks_done * 100 / total_blocks) as u32;
        if should_report_progress(progress_interval, pct, last_percent, blocks_done) {
            (call_table.send_progress)(b"convert\0".as_ptr(), blocks_done, total_blocks, pct);
            last_percent = pct;
        }
    }

    // --- Rewrite BAT with actual offsets ---
    let mut bat_rewritten: u64 = 0;
    while bat_rewritten < bat_padded {
        let write_len = oss as u64;
        let src_off = bat_rewritten as usize;
        let copy_len = if src_off + oss <= bat_alloc {
            oss
        } else if bat_alloc > src_off {
            bat_alloc - src_off
        } else {
            0
        };
        core::ptr::write_bytes(bat_write_buf, 0, oss);
        if copy_len > 0 {
            core::ptr::copy_nonoverlapping(bat_buf.add(src_off), bat_write_buf, copy_len);
        }
        if !write_bytes_to_output(
            call_table,
            bat_write_buf,
            bat_offset + bat_rewritten,
            write_len,
            oss,
            oc,
        ) {
            (call_table.send_complete)(b"convert\0".as_ptr(), *bytes_read, false);
            return *bytes_read;
        }
        bat_rewritten += write_len;
    }

    (call_table.send_complete)(b"convert\0".as_ptr(), *bytes_read, true);
    (call_table.verbose_print)(b"convert: VHDX done\n\0".as_ptr());
    *bytes_read
}

/// Compute the BAT array index for a payload block, accounting for
/// interleaved sector bitmap entries.
#[inline]
fn vhdx_payload_bat_index(payload_block_idx: u32, chunk_ratio: u32) -> u32 {
    let sb_entries_before = payload_block_idx / chunk_ratio;
    payload_block_idx + sb_entries_before
}

/// Round `val` up to the next multiple of `align`.
/// `align` must be a power of 2.
#[inline]
fn align_up(val: u64, align: usize) -> u64 {
    let a = align as u64;
    (val + a - 1) & !(a - 1)
}

// ================================================================
// Utility
// ================================================================

/// Get the call table from the fixed address.
unsafe fn get_call_table() -> &'static CallTable {
    &*(CALL_TABLE_ADDR as *const CallTable)
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    unsafe {
        let call_table = get_call_table();
        if call_table.magic == CallTable::MAGIC {
            (call_table.send_error)(b"panic\0".as_ptr(), b"convert\0".as_ptr(), 0, 0xDEAD);
        }
    }
    loop {
        core::hint::spin_loop();
    }
}
