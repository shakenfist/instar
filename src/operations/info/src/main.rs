//! Info operation: detect image format and report metadata.
//!
//! This operation reads the first sector(s) from the input virtio-block device
//! to detect the image format based on magic numbers and header structures.
//! Results are sent via protobuf InfoResultMessage over the serial command channel.

#![no_std]
#![no_main]

use core::panic::PanicInfo;

use shared::{CallTable, ImageFormat, InfoConfig, InfoResult, CALL_TABLE_ADDR, MAX_SECTOR_SIZE};

// Magic numbers for format detection (big-endian where noted)
const QCOW2_MAGIC: u32 = 0x514649fb; // "QFI\xfb" (big-endian at offset 0)
const QCOW1_MAGIC: u32 = 0x514649; // "QFI" (big-endian at offset 0, 3 bytes)
const VMDK4_MAGIC: u32 = 0x564d444b; // "VMDK" (little-endian at offset 0)
const VMDK3_MAGIC: u32 = 0x434f5744; // "COWD" (little-endian at offset 0)

// QCOW2 header offsets (big-endian)
const QCOW2_VERSION_OFFSET: usize = 4;
const QCOW2_BACKING_FILE_OFFSET_OFFSET: usize = 8;
const QCOW2_BACKING_FILE_SIZE_OFFSET: usize = 16;
const QCOW2_CLUSTER_BITS_OFFSET: usize = 20;
const QCOW2_SIZE_OFFSET: usize = 24;
const QCOW2_CRYPT_METHOD_OFFSET: usize = 32;
const QCOW2_INCOMPATIBLE_FEATURES_OFFSET: usize = 72; // v3 only

// QCOW2 incompatible feature bits
const QCOW2_INCOMPAT_DIRTY: u64 = 1 << 0;
const QCOW2_INCOMPAT_CORRUPT: u64 = 1 << 1;
const QCOW2_INCOMPAT_EXTERNAL_DATA: u64 = 1 << 2;
const QCOW2_INCOMPAT_COMPRESSION: u64 = 1 << 3;

// VMDK4 header offsets (little-endian)
const VMDK4_VERSION_OFFSET: usize = 4;
const VMDK4_CAPACITY_OFFSET: usize = 12;
const VMDK4_GRAIN_SIZE_OFFSET: usize = 20;

/// Entry point called by core after devices are initialized.
///
/// Returns the number of bytes read.
#[no_mangle]
pub unsafe extern "C" fn _start() -> u64 {
    let call_table = get_call_table();

    // Verify call table is valid
    if call_table.magic != CallTable::MAGIC {
        (call_table.debug_print)(b"info: bad magic\n\0".as_ptr());
        return 0;
    }
    if call_table.version != CallTable::VERSION {
        (call_table.debug_print)(b"info: bad version\n\0".as_ptr());
        return 0;
    }

    (call_table.debug_print)(b"info: start\n\0".as_ptr());

    // Get operation config (optional)
    let config_result = (call_table.get_operation_config)();
    let config = &*(config_result.ptr as *const InfoConfig);
    let detailed = if config.is_valid() {
        config.should_report_detailed()
    } else {
        true // Default to detailed
    };

    // Get device parameters
    let input_capacity = (call_table.get_input_capacity)();
    let input_sector_size = (call_table.get_input_sector_size)();

    // Calculate actual file size
    let actual_size = input_capacity * input_sector_size as u64;

    (call_table.debug_print)(b"info: reading header\n\0".as_ptr());

    // Buffer for reading data
    let mut buffer = [0u8; MAX_SECTOR_SIZE];

    // Read first sector
    if !(call_table.read_input_sector)(0, buffer.as_mut_ptr(), input_sector_size) {
        (call_table.send_error)(b"info\0".as_ptr(), b"input\0".as_ptr(), 0, 1);
        return 0;
    }

    let bytes_read = input_sector_size as u64;

    // Initialize result structure
    let mut result = InfoResult::new();
    result.actual_size = actual_size;

    // Detect format based on magic numbers
    let format = detect_format(&buffer, input_sector_size);
    result.format = format as u32;

    (call_table.debug_print)(b"info: detected format\n\0".as_ptr());

    // Parse format-specific metadata if detailed reporting enabled
    if detailed {
        match format {
            ImageFormat::Qcow2 => {
                parse_qcow2_header(&buffer, &mut result, call_table);
            }
            ImageFormat::Vmdk4 => {
                parse_vmdk4_header(&buffer, &mut result);
            }
            _ => {
                // For raw and unknown formats, virtual size = actual size
                result.virtual_size = actual_size;
            }
        }
    }

    // Get format string for protobuf message
    let format_str = format_to_str(format);

    // Send result via protobuf over serial
    (call_table.send_info_result)(
        format_str,
        result.version,
        result.virtual_size,
        result.actual_size,
        result.cluster_size,
        result.flags,
        b"\0".as_ptr(), // backing_file (empty for now)
        b"\0".as_ptr(), // external_data_file (empty for now)
    );

    (call_table.send_complete)(b"info\0".as_ptr(), bytes_read, true);
    (call_table.debug_print)(b"info: done\n\0".as_ptr());

    bytes_read
}

/// Convert ImageFormat to a null-terminated C string
fn format_to_str(format: ImageFormat) -> *const u8 {
    match format {
        ImageFormat::Unknown => b"unknown\0".as_ptr(),
        ImageFormat::Raw => b"raw\0".as_ptr(),
        ImageFormat::Qcow2 => b"qcow2\0".as_ptr(),
        ImageFormat::Qcow1 => b"qcow1\0".as_ptr(),
        ImageFormat::Vmdk4 => b"vmdk\0".as_ptr(),
        ImageFormat::Vmdk3 => b"vmdk3\0".as_ptr(),
        ImageFormat::Vhd => b"vhd\0".as_ptr(),
        ImageFormat::Vhdx => b"vhdx\0".as_ptr(),
    }
}

/// Detect image format based on magic numbers
fn detect_format(buffer: &[u8], len: usize) -> ImageFormat {
    if len < 8 {
        return ImageFormat::Unknown;
    }

    // Check QCOW2/QCOW1 magic (big-endian)
    let magic_be = u32::from_be_bytes([buffer[0], buffer[1], buffer[2], buffer[3]]);
    if magic_be == QCOW2_MAGIC {
        return ImageFormat::Qcow2;
    }
    // QCOW1 has 3-byte magic
    if (magic_be >> 8) == QCOW1_MAGIC {
        return ImageFormat::Qcow1;
    }

    // Check VMDK magic (little-endian)
    let magic_le = u32::from_le_bytes([buffer[0], buffer[1], buffer[2], buffer[3]]);
    if magic_le == VMDK4_MAGIC {
        return ImageFormat::Vmdk4;
    }
    if magic_le == VMDK3_MAGIC {
        return ImageFormat::Vmdk3;
    }

    // Check VHDX magic (little-endian, "vhdxfile" signature)
    let vhdx_sig = u64::from_le_bytes([
        buffer[0], buffer[1], buffer[2], buffer[3], buffer[4], buffer[5], buffer[6], buffer[7],
    ]);
    // "vhdxfile" in little-endian
    if vhdx_sig == 0x656c696678646876 {
        return ImageFormat::Vhdx;
    }

    // VHD has its signature at the end of the file, so we can't detect it
    // from the first sector alone. We'd need to read the last 512 bytes.
    // For now, we'll fall through to raw.

    // If no known format detected, assume raw
    ImageFormat::Raw
}

/// Parse QCOW2 header and populate result
unsafe fn parse_qcow2_header(buffer: &[u8], result: &mut InfoResult, call_table: &CallTable) {
    // Version (big-endian u32 at offset 4)
    let version = u32::from_be_bytes([
        buffer[QCOW2_VERSION_OFFSET],
        buffer[QCOW2_VERSION_OFFSET + 1],
        buffer[QCOW2_VERSION_OFFSET + 2],
        buffer[QCOW2_VERSION_OFFSET + 3],
    ]);
    result.version = version;

    // Cluster bits (big-endian u32 at offset 20)
    let cluster_bits = u32::from_be_bytes([
        buffer[QCOW2_CLUSTER_BITS_OFFSET],
        buffer[QCOW2_CLUSTER_BITS_OFFSET + 1],
        buffer[QCOW2_CLUSTER_BITS_OFFSET + 2],
        buffer[QCOW2_CLUSTER_BITS_OFFSET + 3],
    ]);
    result.cluster_size = 1u32 << cluster_bits;

    // Virtual size (big-endian u64 at offset 24)
    result.virtual_size = u64::from_be_bytes([
        buffer[QCOW2_SIZE_OFFSET],
        buffer[QCOW2_SIZE_OFFSET + 1],
        buffer[QCOW2_SIZE_OFFSET + 2],
        buffer[QCOW2_SIZE_OFFSET + 3],
        buffer[QCOW2_SIZE_OFFSET + 4],
        buffer[QCOW2_SIZE_OFFSET + 5],
        buffer[QCOW2_SIZE_OFFSET + 6],
        buffer[QCOW2_SIZE_OFFSET + 7],
    ]);

    // Encryption method (big-endian u32 at offset 32)
    let crypt_method = u32::from_be_bytes([
        buffer[QCOW2_CRYPT_METHOD_OFFSET],
        buffer[QCOW2_CRYPT_METHOD_OFFSET + 1],
        buffer[QCOW2_CRYPT_METHOD_OFFSET + 2],
        buffer[QCOW2_CRYPT_METHOD_OFFSET + 3],
    ]);
    if crypt_method != 0 {
        result.flags |= InfoResult::FLAG_ENCRYPTED;
    }

    // Backing file offset and size
    let backing_offset = u64::from_be_bytes([
        buffer[QCOW2_BACKING_FILE_OFFSET_OFFSET],
        buffer[QCOW2_BACKING_FILE_OFFSET_OFFSET + 1],
        buffer[QCOW2_BACKING_FILE_OFFSET_OFFSET + 2],
        buffer[QCOW2_BACKING_FILE_OFFSET_OFFSET + 3],
        buffer[QCOW2_BACKING_FILE_OFFSET_OFFSET + 4],
        buffer[QCOW2_BACKING_FILE_OFFSET_OFFSET + 5],
        buffer[QCOW2_BACKING_FILE_OFFSET_OFFSET + 6],
        buffer[QCOW2_BACKING_FILE_OFFSET_OFFSET + 7],
    ]);
    let backing_size = u32::from_be_bytes([
        buffer[QCOW2_BACKING_FILE_SIZE_OFFSET],
        buffer[QCOW2_BACKING_FILE_SIZE_OFFSET + 1],
        buffer[QCOW2_BACKING_FILE_SIZE_OFFSET + 2],
        buffer[QCOW2_BACKING_FILE_SIZE_OFFSET + 3],
    ]);

    if backing_offset != 0 && backing_size > 0 {
        result.flags |= InfoResult::FLAG_HAS_BACKING_FILE;
        // Note: The backing file path is embedded in the header, often right
        // after the header structure. We would need to extract it from the
        // buffer if it fits, or read more sectors if it doesn't.
        // For now, just flag that it exists.
        (call_table.debug_print)(b"info: has backing file\n\0".as_ptr());
    }

    // Version 3 specific features
    if version >= 3 {
        // Incompatible features (big-endian u64 at offset 72)
        let incompat = u64::from_be_bytes([
            buffer[QCOW2_INCOMPATIBLE_FEATURES_OFFSET],
            buffer[QCOW2_INCOMPATIBLE_FEATURES_OFFSET + 1],
            buffer[QCOW2_INCOMPATIBLE_FEATURES_OFFSET + 2],
            buffer[QCOW2_INCOMPATIBLE_FEATURES_OFFSET + 3],
            buffer[QCOW2_INCOMPATIBLE_FEATURES_OFFSET + 4],
            buffer[QCOW2_INCOMPATIBLE_FEATURES_OFFSET + 5],
            buffer[QCOW2_INCOMPATIBLE_FEATURES_OFFSET + 6],
            buffer[QCOW2_INCOMPATIBLE_FEATURES_OFFSET + 7],
        ]);

        if (incompat & QCOW2_INCOMPAT_DIRTY) != 0 {
            result.flags |= InfoResult::FLAG_DIRTY;
        }
        if (incompat & QCOW2_INCOMPAT_CORRUPT) != 0 {
            result.flags |= InfoResult::FLAG_CORRUPT;
        }
        if (incompat & QCOW2_INCOMPAT_EXTERNAL_DATA) != 0 {
            result.flags |= InfoResult::FLAG_HAS_EXTERNAL_DATA;
            (call_table.debug_print)(b"info: has external data\n\0".as_ptr());
        }
        if (incompat & QCOW2_INCOMPAT_COMPRESSION) != 0 {
            result.flags |= InfoResult::FLAG_COMPRESSED;
        }
    }
}

/// Parse VMDK4 header and populate result
fn parse_vmdk4_header(buffer: &[u8], result: &mut InfoResult) {
    // Version (little-endian u32 at offset 4)
    let version = u32::from_le_bytes([
        buffer[VMDK4_VERSION_OFFSET],
        buffer[VMDK4_VERSION_OFFSET + 1],
        buffer[VMDK4_VERSION_OFFSET + 2],
        buffer[VMDK4_VERSION_OFFSET + 3],
    ]);
    result.version = version;

    // Capacity in sectors (little-endian u64 at offset 12)
    let capacity_sectors = u64::from_le_bytes([
        buffer[VMDK4_CAPACITY_OFFSET],
        buffer[VMDK4_CAPACITY_OFFSET + 1],
        buffer[VMDK4_CAPACITY_OFFSET + 2],
        buffer[VMDK4_CAPACITY_OFFSET + 3],
        buffer[VMDK4_CAPACITY_OFFSET + 4],
        buffer[VMDK4_CAPACITY_OFFSET + 5],
        buffer[VMDK4_CAPACITY_OFFSET + 6],
        buffer[VMDK4_CAPACITY_OFFSET + 7],
    ]);
    // VMDK uses 512-byte sectors for capacity
    result.virtual_size = capacity_sectors * 512;

    // Grain size in sectors (little-endian u64 at offset 20)
    let grain_size = u64::from_le_bytes([
        buffer[VMDK4_GRAIN_SIZE_OFFSET],
        buffer[VMDK4_GRAIN_SIZE_OFFSET + 1],
        buffer[VMDK4_GRAIN_SIZE_OFFSET + 2],
        buffer[VMDK4_GRAIN_SIZE_OFFSET + 3],
        buffer[VMDK4_GRAIN_SIZE_OFFSET + 4],
        buffer[VMDK4_GRAIN_SIZE_OFFSET + 5],
        buffer[VMDK4_GRAIN_SIZE_OFFSET + 6],
        buffer[VMDK4_GRAIN_SIZE_OFFSET + 7],
    ]);
    // Grain size is similar to cluster size
    result.cluster_size = (grain_size * 512) as u32;

    // VMDK can have embedded descriptors that reference other files,
    // but detecting this requires parsing the descriptor text.
    // For now, we just report the basic header info.
}

/// Get the call table from the fixed address
unsafe fn get_call_table() -> &'static CallTable {
    &*(CALL_TABLE_ADDR as *const CallTable)
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    unsafe {
        let call_table = get_call_table();
        if call_table.magic == CallTable::MAGIC {
            (call_table.send_error)(b"panic\0".as_ptr(), b"info\0".as_ptr(), 0, 0xDEAD);
        }
    }
    loop {
        core::hint::spin_loop();
    }
}
