//! VDI (VirtualBox Disk Image) format parsing.
//!
//! Provides VDI header parsing and block-map lookup for the convert /
//! compare / dd read path. Mirrors qemu's `block/vdi.c` open-time
//! validation and read semantics exactly: the header is validated with
//! the same twelve checks qemu applies, odd `disk_size` values are
//! rounded up to the next 512-byte multiple rather than rejected, and
//! block-map lookups never reject host offsets past end-of-file — qemu
//! performs no file-length validation and zero-fills past-EOF reads, so
//! that classification is left to the chain reader.

#![no_std]
#![allow(clippy::too_many_arguments)]

use shared::{le_u32, le_u64, CallTable, MAX_SECTOR_SIZE};

// ============================================================================
// VDI header field offsets (all little-endian)
// ============================================================================

/// Header size in bytes.
pub const HEADER_SIZE: usize = 512;

/// Signature offset (u32 LE): 0xbeda107f.
pub const SIGNATURE_OFFSET: usize = 0x40;
/// Version offset (u32 LE): major.minor, 0x00010001 (1.1) only.
pub const VERSION_OFFSET: usize = 0x44;
/// Image type offset (u32 LE): 1 dynamic, 2 static; not validated.
pub const IMAGE_TYPE_OFFSET: usize = 0x4c;
/// Block map byte offset (u32 LE): must be 512-aligned.
pub const OFFSET_BMAP_OFFSET: usize = 0x154;
/// Data region byte offset (u32 LE): must be 512-aligned.
pub const OFFSET_DATA_OFFSET: usize = 0x158;
/// Sector size offset (u32 LE): must be 512.
pub const SECTOR_SIZE_OFFSET: usize = 0x168;
/// Virtual disk size in bytes offset (u64 LE).
pub const DISK_SIZE_OFFSET: usize = 0x170;
/// Block size offset (u32 LE): must be exactly 1 MiB.
pub const BLOCK_SIZE_OFFSET: usize = 0x178;
/// Extra bytes per block offset (u32 LE): parsed but ignored by qemu.
pub const BLOCK_EXTRA_OFFSET: usize = 0x17c;
/// Blocks-in-image offset (u32 LE): block-map entry count.
pub const BLOCKS_IN_IMAGE_OFFSET: usize = 0x180;
/// Link (backing) UUID offset (16 bytes): must be all-zero.
pub const UUID_LINK_OFFSET: usize = 0x1a8;
/// Parent UUID offset (16 bytes): must be all-zero.
pub const UUID_PARENT_OFFSET: usize = 0x1b8;

// ============================================================================
// VDI constants
// ============================================================================

/// VDI header signature ("magic").
pub const VDI_SIGNATURE: u32 = 0xbeda_107f;

/// Only supported version: 1.1, stored as major.minor in a u32.
pub const VDI_VERSION_1_1: u32 = 0x0001_0001;

/// Mandatory sector size (qemu refuses anything else).
pub const VDI_SECTOR_SIZE: u32 = 512;

/// Mandatory block size, 1 MiB (qemu hard-fixes this).
pub const VDI_BLOCK_SIZE: u32 = 1024 * 1024;

/// Image type: static (identity block map, pre-allocated geometry).
pub const VDI_IMAGE_TYPE_STATIC: u32 = 2;

/// Maximum number of block-map entries qemu will open.
pub const VDI_BLOCKS_IN_IMAGE_MAX: u32 = 536_870_784;

/// Maximum virtual disk size in bytes (`VDI_BLOCKS_IN_IMAGE_MAX` blocks
/// of `VDI_BLOCK_SIZE`), ≈512 TiB.
pub const VDI_DISK_SIZE_MAX: u64 = VDI_BLOCKS_IN_IMAGE_MAX as u64 * VDI_BLOCK_SIZE as u64;

/// Block-map sentinel for an unallocated (never written) block.
pub const VDI_BLOCK_UNALLOCATED: u32 = 0xffff_ffff;
/// Block-map sentinel for a discarded block. Reads as zeros, exactly
/// like an unallocated block.
pub const VDI_BLOCK_DISCARDED: u32 = 0xffff_fffe;

// ============================================================================
// VDI header parsing
// ============================================================================

/// Parsed VDI header fields the read path needs.
///
/// `disk_size` is the rounded value (odd on-disk sizes are rounded up
/// to the next 512-byte multiple at parse time, matching qemu). All
/// other fields are stored verbatim.
pub struct VdiHeader {
    pub signature: u32,
    pub version: u32,
    pub image_type: u32,
    pub offset_bmap: u32,
    pub offset_data: u32,
    pub sector_size: u32,
    pub disk_size: u64,
    pub block_size: u32,
    pub block_extra: u32,
    pub blocks_in_image: u32,
}

/// Round `value` up to the next multiple of 512, or `None` on overflow.
fn round_up_512(value: u64) -> Option<u64> {
    value.checked_add(511).map(|v| v & !511)
}

impl VdiHeader {
    /// Parse and validate a VDI header from raw bytes.
    ///
    /// Enforces qemu `vdi_open`'s twelve open-time checks with the same
    /// limits. Odd `disk_size` values are rounded up to the next
    /// 512-byte multiple (not an error); any `image_type` is accepted;
    /// `block_extra` is parsed but never used. Returns `None` if the
    /// buffer is too small or any check fails.
    pub fn parse(buf: &[u8]) -> Option<Self> {
        if buf.len() < HEADER_SIZE {
            return None;
        }

        let signature = le_u32(buf, SIGNATURE_OFFSET);
        if signature != VDI_SIGNATURE {
            return None;
        }

        let version = le_u32(buf, VERSION_OFFSET);
        if version != VDI_VERSION_1_1 {
            return None;
        }

        let raw_disk_size = le_u64(buf, DISK_SIZE_OFFSET);
        if raw_disk_size > VDI_DISK_SIZE_MAX {
            return None;
        }
        let disk_size = round_up_512(raw_disk_size)?;

        let offset_bmap = le_u32(buf, OFFSET_BMAP_OFFSET);
        if !offset_bmap.is_multiple_of(VDI_SECTOR_SIZE) {
            return None;
        }

        let offset_data = le_u32(buf, OFFSET_DATA_OFFSET);
        if !offset_data.is_multiple_of(VDI_SECTOR_SIZE) {
            return None;
        }

        let sector_size = le_u32(buf, SECTOR_SIZE_OFFSET);
        if sector_size != VDI_SECTOR_SIZE {
            return None;
        }

        let block_size = le_u32(buf, BLOCK_SIZE_OFFSET);
        if block_size != VDI_BLOCK_SIZE {
            return None;
        }

        let blocks_in_image = le_u32(buf, BLOCKS_IN_IMAGE_OFFSET);
        if blocks_in_image > VDI_BLOCKS_IN_IMAGE_MAX {
            return None;
        }

        // The rounded disk size must fit within the declared geometry.
        let geometry_bytes = (blocks_in_image as u64).checked_mul(block_size as u64)?;
        if disk_size > geometry_bytes {
            return None;
        }

        if !is_all_zero(&buf[UUID_LINK_OFFSET..UUID_LINK_OFFSET + 16]) {
            return None;
        }
        if !is_all_zero(&buf[UUID_PARENT_OFFSET..UUID_PARENT_OFFSET + 16]) {
            return None;
        }

        let image_type = le_u32(buf, IMAGE_TYPE_OFFSET);
        let block_extra = le_u32(buf, BLOCK_EXTRA_OFFSET);

        Some(VdiHeader {
            signature,
            version,
            image_type,
            offset_bmap,
            offset_data,
            sector_size,
            disk_size,
            block_size,
            block_extra,
            blocks_in_image,
        })
    }

    /// True for static images (identity block map). The read path treats
    /// static and dynamic images identically; this is informational.
    pub fn is_static(&self) -> bool {
        self.image_type == VDI_IMAGE_TYPE_STATIC
    }
}

/// True if every byte in `bytes` is zero.
fn is_all_zero(bytes: &[u8]) -> bool {
    bytes.iter().all(|&b| b == 0)
}

// ============================================================================
// Block lookup result
// ============================================================================

/// Result of looking up a virtual offset in the VDI block map.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VdiBlockLookup {
    /// The block is not allocated (unallocated or discarded); reads as
    /// zeros. A VDI can never have a lower device in the chain, so the
    /// caller zero-fills.
    Unallocated,
    /// The block is allocated at the given host byte offset in the data
    /// region.
    Allocated { host_byte_offset: u64 },
}

// ============================================================================
// VDI state for block-map I/O
// ============================================================================

/// Runtime state for reading VDI blocks from a device.
///
/// Analogous to `vhd::VhdState`. Maintains a sector cache for block-map
/// reads; the second cache buffer mirrors the VHD state's layout for a
/// uniform init signature and is unused by the block-map walk.
pub struct VdiState {
    pub device_idx: u32,
    pub offset_bmap: u64,
    pub offset_data: u64,
    pub block_size: u64,
    pub blocks_in_image: u32,
    pub disk_size: u64,
    // Sector cache for block-map reads.
    pub bmap_cached_sector: u64,
    pub bmap_cache_buf: *mut u8,
    // Second cache buffer, held for init-signature parity with VhdState.
    pub data_cached_sector: u64,
    pub data_cache_buf: *mut u8,
}

impl VdiState {
    /// Initialize VDI state by reading and validating the header.
    ///
    /// Reads the first sector (the 512-byte header lives at offset 0),
    /// validates it via [`VdiHeader::parse`], and checks that the
    /// block-map region address arithmetic is sound (no overflow). Per
    /// qemu, the block map is NOT required to fit within
    /// `input_capacity` — file length is never validated.
    ///
    /// Returns `None` if the header is invalid, the header sector read
    /// fails, or block-map region addressing would overflow.
    ///
    /// # Safety
    ///
    /// `bmap_cache_buf` and `data_cache_buf` must each point to at least
    /// `MAX_SECTOR_SIZE` writable bytes. `call_table` must be valid.
    pub unsafe fn init(
        call_table: &CallTable,
        device_idx: u32,
        sector_size: usize,
        input_capacity: u64,
        bmap_cache_buf: *mut u8,
        data_cache_buf: *mut u8,
        bytes_read: &mut u64,
    ) -> Option<Self> {
        let _ = input_capacity;

        let mut header_sector = [0u8; MAX_SECTOR_SIZE];
        if !(call_table.read_input_sector)(device_idx, 0, header_sector.as_mut_ptr(), sector_size) {
            return None;
        }
        *bytes_read += sector_size as u64;

        let header = VdiHeader::parse(&header_sector)?;

        // Ensure the block-map region (offset_bmap + entries*4, rounded
        // up to a sector boundary) is arithmetically sound. This does NOT
        // require the region to lie within the file — qemu never checks.
        let bmap_bytes = (header.blocks_in_image as u64).checked_mul(4)?;
        let bmap_end = (header.offset_bmap as u64).checked_add(bmap_bytes)?;
        bmap_end.checked_add(sector_size as u64 - 1)?;

        Some(VdiState {
            device_idx,
            offset_bmap: header.offset_bmap as u64,
            offset_data: header.offset_data as u64,
            block_size: header.block_size as u64,
            blocks_in_image: header.blocks_in_image,
            disk_size: header.disk_size,
            bmap_cached_sector: u64::MAX,
            bmap_cache_buf,
            data_cached_sector: u64::MAX,
            data_cache_buf,
        })
    }

    /// Look up the host location for a given virtual byte offset.
    ///
    /// Reads the block-map entry for the containing block. Unallocated
    /// (`0xffffffff`) and discarded (`0xfffffffe`) entries both map to
    /// [`VdiBlockLookup::Unallocated`]; any smaller value is an
    /// allocation-order index whose host offset is
    /// `offset_data + entry * block_size + offset_in_block`. `block_extra`
    /// never participates. Host offsets past `input_capacity` are NOT
    /// rejected — the caller zero-fills past-EOF reads.
    ///
    /// Returns `None` only if the block-map sector read itself fails or
    /// offset arithmetic overflows.
    ///
    /// # Safety
    ///
    /// `call_table` must be valid. Cache buffers must still be valid.
    pub unsafe fn block_lookup(
        &mut self,
        call_table: &CallTable,
        virtual_offset: u64,
        sector_size: usize,
        input_capacity: u64,
        bytes_read: &mut u64,
    ) -> Option<VdiBlockLookup> {
        let block_idx = virtual_offset / self.block_size;

        if block_idx >= self.blocks_in_image as u64 {
            return Some(VdiBlockLookup::Unallocated);
        }

        let entry_offset = self.offset_bmap.checked_add(block_idx.checked_mul(4)?)?;

        let entry = read_u32_le_cached(
            call_table,
            self.device_idx,
            entry_offset,
            sector_size,
            input_capacity,
            &mut self.bmap_cached_sector,
            self.bmap_cache_buf,
            bytes_read,
        )?;

        if entry >= VDI_BLOCK_DISCARDED {
            return Some(VdiBlockLookup::Unallocated);
        }

        let block_host_offset = (entry as u64).checked_mul(self.block_size)?;
        let block_start = self.offset_data.checked_add(block_host_offset)?;
        let offset_in_block = virtual_offset % self.block_size;

        Some(VdiBlockLookup::Allocated {
            host_byte_offset: block_start.checked_add(offset_in_block)?,
        })
    }
}

// ============================================================================
// Cached sector read helper (little-endian u32)
// ============================================================================

shared::cached_read!(read_u32_le_cached, u32, le, 4);

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
extern crate std;

#[cfg(test)]
mod tests {
    use super::*;
    use shared::{write_le_u32, write_le_u64};
    use std::sync::Mutex;

    // ====================================================================
    // Header builder
    // ====================================================================

    /// Fields for building a synthetic, otherwise-valid VDI header. Every
    /// field defaults to a value that passes validation; individual tests
    /// mutate the one field under test.
    struct HeaderSpec {
        signature: u32,
        version: u32,
        image_type: u32,
        offset_bmap: u32,
        offset_data: u32,
        sector_size: u32,
        disk_size: u64,
        block_size: u32,
        block_extra: u32,
        blocks_in_image: u32,
        uuid_link: [u8; 16],
        uuid_parent: [u8; 16],
    }

    impl Default for HeaderSpec {
        fn default() -> Self {
            // 8 MiB virtual, 8 one-MiB blocks: a minimal valid header.
            HeaderSpec {
                signature: VDI_SIGNATURE,
                version: VDI_VERSION_1_1,
                image_type: 1,
                offset_bmap: 512,
                offset_data: 1024,
                sector_size: VDI_SECTOR_SIZE,
                disk_size: 8 * 1024 * 1024,
                block_size: VDI_BLOCK_SIZE,
                block_extra: 0,
                blocks_in_image: 8,
                uuid_link: [0u8; 16],
                uuid_parent: [0u8; 16],
            }
        }
    }

    fn build_header(spec: &HeaderSpec) -> [u8; 512] {
        let mut buf = [0u8; 512];
        write_le_u32(&mut buf, SIGNATURE_OFFSET, spec.signature);
        write_le_u32(&mut buf, VERSION_OFFSET, spec.version);
        write_le_u32(&mut buf, IMAGE_TYPE_OFFSET, spec.image_type);
        write_le_u32(&mut buf, OFFSET_BMAP_OFFSET, spec.offset_bmap);
        write_le_u32(&mut buf, OFFSET_DATA_OFFSET, spec.offset_data);
        write_le_u32(&mut buf, SECTOR_SIZE_OFFSET, spec.sector_size);
        write_le_u64(&mut buf, DISK_SIZE_OFFSET, spec.disk_size);
        write_le_u32(&mut buf, BLOCK_SIZE_OFFSET, spec.block_size);
        write_le_u32(&mut buf, BLOCK_EXTRA_OFFSET, spec.block_extra);
        write_le_u32(&mut buf, BLOCKS_IN_IMAGE_OFFSET, spec.blocks_in_image);
        buf[UUID_LINK_OFFSET..UUID_LINK_OFFSET + 16].copy_from_slice(&spec.uuid_link);
        buf[UUID_PARENT_OFFSET..UUID_PARENT_OFFSET + 16].copy_from_slice(&spec.uuid_parent);
        buf
    }

    // ====================================================================
    // round_up_512
    // ====================================================================

    #[test]
    fn round_up_512_examples() {
        assert_eq!(round_up_512(0), Some(0));
        assert_eq!(round_up_512(1), Some(512));
        assert_eq!(round_up_512(511), Some(512));
        assert_eq!(round_up_512(512), Some(512));
        assert_eq!(round_up_512(513), Some(1024));
        // The plan's worked example: 12801 rounds up to 13312 (26 * 512).
        assert_eq!(round_up_512(12801), Some(13312));
        assert_eq!(round_up_512(13312), Some(13312));
        assert_eq!(round_up_512(u64::MAX), None);
    }

    // ====================================================================
    // VdiHeader::parse — acceptance and per-rule rejection
    // ====================================================================

    #[test]
    fn parse_valid_header() {
        let buf = build_header(&HeaderSpec::default());
        let hdr = VdiHeader::parse(&buf).unwrap();
        assert_eq!(hdr.signature, VDI_SIGNATURE);
        assert_eq!(hdr.version, VDI_VERSION_1_1);
        assert_eq!(hdr.offset_bmap, 512);
        assert_eq!(hdr.offset_data, 1024);
        assert_eq!(hdr.block_size, VDI_BLOCK_SIZE);
        assert_eq!(hdr.blocks_in_image, 8);
        assert_eq!(hdr.disk_size, 8 * 1024 * 1024);
    }

    #[test]
    fn parse_short_buffer() {
        assert!(VdiHeader::parse(&[0u8; 511]).is_none());
        assert!(VdiHeader::parse(&[0u8; 0]).is_none());
    }

    #[test]
    fn parse_rejects_bad_signature() {
        let spec = HeaderSpec {
            signature: 0xdead_beef,
            ..HeaderSpec::default()
        };
        assert!(VdiHeader::parse(&build_header(&spec)).is_none());
    }

    #[test]
    fn parse_rejects_bad_version() {
        // 2.0 — the only accepted version is 1.1.
        let spec = HeaderSpec {
            version: 0x0002_0000,
            ..HeaderSpec::default()
        };
        assert!(VdiHeader::parse(&build_header(&spec)).is_none());
    }

    #[test]
    fn parse_rejects_unaligned_offset_bmap() {
        let spec = HeaderSpec {
            offset_bmap: 513,
            ..HeaderSpec::default()
        };
        assert!(VdiHeader::parse(&build_header(&spec)).is_none());
    }

    #[test]
    fn parse_rejects_unaligned_offset_data() {
        let spec = HeaderSpec {
            offset_data: 1025,
            ..HeaderSpec::default()
        };
        assert!(VdiHeader::parse(&build_header(&spec)).is_none());
    }

    #[test]
    fn parse_rejects_wrong_sector_size() {
        let spec = HeaderSpec {
            sector_size: 4096,
            ..HeaderSpec::default()
        };
        assert!(VdiHeader::parse(&build_header(&spec)).is_none());
    }

    #[test]
    fn parse_block_size_boundaries() {
        // Only exactly 1 MiB is accepted.
        let low = HeaderSpec {
            block_size: 1_048_575,
            ..HeaderSpec::default()
        };
        assert!(VdiHeader::parse(&build_header(&low)).is_none());

        let exact = HeaderSpec {
            block_size: 1_048_576,
            ..HeaderSpec::default()
        };
        assert!(VdiHeader::parse(&build_header(&exact)).is_some());

        let high = HeaderSpec {
            block_size: 1_048_577,
            ..HeaderSpec::default()
        };
        assert!(VdiHeader::parse(&build_header(&high)).is_none());
    }

    #[test]
    fn parse_disk_size_max_boundary() {
        // At the max (blocks_in_image raised to cover it): accepted.
        let at_max = HeaderSpec {
            disk_size: VDI_DISK_SIZE_MAX,
            blocks_in_image: VDI_BLOCKS_IN_IMAGE_MAX,
            ..HeaderSpec::default()
        };
        assert!(VdiHeader::parse(&build_header(&at_max)).is_some());

        // Just over the max: rejected regardless of geometry.
        let over_max = HeaderSpec {
            disk_size: VDI_DISK_SIZE_MAX + 1,
            blocks_in_image: VDI_BLOCKS_IN_IMAGE_MAX,
            ..HeaderSpec::default()
        };
        assert!(VdiHeader::parse(&build_header(&over_max)).is_none());
    }

    #[test]
    fn parse_blocks_in_image_boundary() {
        let at_max = HeaderSpec {
            blocks_in_image: VDI_BLOCKS_IN_IMAGE_MAX,
            ..HeaderSpec::default()
        };
        assert!(VdiHeader::parse(&build_header(&at_max)).is_some());

        let over_max = HeaderSpec {
            blocks_in_image: VDI_BLOCKS_IN_IMAGE_MAX + 1,
            ..HeaderSpec::default()
        };
        assert!(VdiHeader::parse(&build_header(&over_max)).is_none());
    }

    #[test]
    fn parse_rejects_disk_size_exceeding_geometry() {
        // 8 blocks hold 8 MiB; a 9 MiB disk_size exceeds the geometry.
        let spec = HeaderSpec {
            disk_size: 9 * 1024 * 1024,
            blocks_in_image: 8,
            ..HeaderSpec::default()
        };
        assert!(VdiHeader::parse(&build_header(&spec)).is_none());
    }

    #[test]
    fn parse_geometry_check_uses_rounded_disk_size() {
        // Geometry is exactly one block (1 MiB). A raw disk_size one byte
        // over 1 MiB rounds up to 1 MiB + 512, which exceeds the geometry
        // and must be rejected using the ROUNDED value.
        let spec = HeaderSpec {
            disk_size: VDI_BLOCK_SIZE as u64 + 1,
            blocks_in_image: 1,
            ..HeaderSpec::default()
        };
        assert!(VdiHeader::parse(&build_header(&spec)).is_none());
    }

    #[test]
    fn parse_rounds_odd_disk_size_up() {
        // The plan's worked example: 12801 rounds up to 13312.
        let spec = HeaderSpec {
            disk_size: 12801,
            blocks_in_image: 1,
            ..HeaderSpec::default()
        };
        let hdr = VdiHeader::parse(&build_header(&spec)).unwrap();
        assert_eq!(hdr.disk_size, 13312);
    }

    #[test]
    fn parse_rejects_nonnull_uuid_link() {
        // A single nonzero byte anywhere in the 16 must reject.
        for i in 0..16 {
            let mut uuid = [0u8; 16];
            uuid[i] = 1;
            let spec = HeaderSpec {
                uuid_link: uuid,
                ..HeaderSpec::default()
            };
            assert!(
                VdiHeader::parse(&build_header(&spec)).is_none(),
                "nonzero uuid_link byte {i} must reject"
            );
        }
    }

    #[test]
    fn parse_rejects_nonnull_uuid_parent() {
        for i in 0..16 {
            let mut uuid = [0u8; 16];
            uuid[i] = 0x80;
            let spec = HeaderSpec {
                uuid_parent: uuid,
                ..HeaderSpec::default()
            };
            assert!(
                VdiHeader::parse(&build_header(&spec)).is_none(),
                "nonzero uuid_parent byte {i} must reject"
            );
        }
    }

    #[test]
    fn parse_accepts_all_image_types() {
        for image_type in [0u32, 1, 2, 3, 4] {
            let spec = HeaderSpec {
                image_type,
                ..HeaderSpec::default()
            };
            let hdr = VdiHeader::parse(&build_header(&spec)).unwrap();
            assert_eq!(hdr.image_type, image_type);
            assert_eq!(hdr.is_static(), image_type == VDI_IMAGE_TYPE_STATIC);
        }
    }

    #[test]
    fn parse_ignores_block_extra() {
        // A nonzero block_extra is parsed but must not affect acceptance.
        let spec = HeaderSpec {
            block_extra: 0xdead_beef,
            ..HeaderSpec::default()
        };
        let hdr = VdiHeader::parse(&build_header(&spec)).unwrap();
        assert_eq!(hdr.block_extra, 0xdead_beef);
    }

    // ====================================================================
    // Mock CallTable backed by an in-memory image
    // ====================================================================

    // The `read_input_sector` callback is an `extern "C" fn` and can only
    // close over `'static` state, so the mock image lives in a global
    // buffer guarded by a lock that serializes the block-map tests.
    const MOCK_LEN: usize = 64 * 1024;
    static MOCK_LOCK: Mutex<()> = Mutex::new(());
    static mut MOCK_IMAGE: [u8; MOCK_LEN] = [0u8; MOCK_LEN];

    unsafe extern "C" fn mock_read_input_sector(
        _device_idx: u32,
        sector: u64,
        out_buf: *mut u8,
        sector_size: usize,
    ) -> bool {
        let start = match (sector as usize).checked_mul(sector_size) {
            Some(s) => s,
            None => return false,
        };
        if start + sector_size > MOCK_LEN {
            return false;
        }
        let src = core::ptr::addr_of!(MOCK_IMAGE) as *const u8;
        core::ptr::copy_nonoverlapping(src.add(start), out_buf, sector_size);
        true
    }

    fn stub_call_table() -> shared::CallTable {
        unsafe extern "C" fn s_dev_count() -> u32 {
            1
        }
        unsafe extern "C" fn s_in_cap(_: u32) -> u64 {
            (MOCK_LEN / 512) as u64
        }
        unsafe extern "C" fn s_in_secsz(_: u32) -> usize {
            512
        }
        unsafe extern "C" fn s_write_out(_: u64, _: *const u8, _: usize) -> bool {
            false
        }
        unsafe extern "C" fn s_out_cap() -> u64 {
            0
        }
        unsafe extern "C" fn s_out_secsz() -> usize {
            512
        }
        unsafe extern "C" fn s_prog_int() -> u32 {
            100
        }
        unsafe extern "C" fn s_send_prog(_: *const u8, _: u64, _: u64, _: u32) {}
        unsafe extern "C" fn s_send_err(_: *const u8, _: *const u8, _: u64, _: u32) {}
        unsafe extern "C" fn s_send_complete(_: *const u8, _: u64, _: bool) {}
        unsafe extern "C" fn s_dbg(_: *const u8) {}
        unsafe extern "C" fn s_verb(_: *const u8) {}
        unsafe extern "C" fn s_get_op_cfg() -> shared::ConfigResult {
            shared::ConfigResult {
                ptr: core::ptr::null(),
                len: 0,
            }
        }
        unsafe extern "C" fn s_get_chain_cfg() -> shared::ConfigResult {
            shared::ConfigResult {
                ptr: core::ptr::null(),
                len: 0,
            }
        }
        unsafe extern "C" fn s_send_info(
            _: *const u8,
            _: u32,
            _: u64,
            _: u64,
            _: u32,
            _: u32,
            _: *const u8,
            _: *const u8,
        ) {
        }
        unsafe extern "C" fn s_send_info_q(
            _: *const u8,
            _: u32,
            _: u64,
            _: u64,
            _: u32,
            _: u32,
            _: *const u8,
            _: *const u8,
            _: *const shared::Qcow2Info,
        ) {
        }
        unsafe extern "C" fn s_send_info_v(
            _: *const u8,
            _: u32,
            _: u64,
            _: u64,
            _: u32,
            _: u32,
            _: *const u8,
            _: *const u8,
            _: *const shared::VmdkInfo,
        ) {
        }
        unsafe extern "C" fn s_send_info_vdi(
            _: *const u8,
            _: u32,
            _: u64,
            _: u64,
            _: u32,
            _: u32,
            _: *const u8,
            _: *const u8,
            _: *const shared::VdiInfo,
        ) {
        }
        unsafe extern "C" fn s_send_info_l(
            _: *const u8,
            _: u32,
            _: u64,
            _: u64,
            _: u32,
            _: u32,
            _: *const u8,
            _: *const u8,
            _: *const shared::LuksInfo,
        ) {
        }
        unsafe extern "C" fn s_send_check(_: *const shared::CheckResult) {}
        unsafe extern "C" fn s_send_compare(_: *const shared::CompareResult) {}
        unsafe extern "C" fn s_send_measure(_: *const shared::MeasureResult) {}
        unsafe extern "C" fn s_send_create(_: *const shared::CreateResult) {}
        unsafe extern "C" fn s_read_out(_: u64, _: *mut u8, _: usize) -> bool {
            false
        }
        unsafe extern "C" fn s_send_resize(_: *const shared::ResizeResult) {}
        unsafe extern "C" fn s_send_rebase(_: *const shared::RebaseResult) {}
        unsafe extern "C" fn s_send_commit(_: *const shared::CommitResult) {}
        unsafe extern "C" fn s_write_in(_: u32, _: u64, _: *const u8, _: usize) -> bool {
            false
        }
        unsafe extern "C" fn s_send_map_ex(_: *const shared::MapExtentRecord) {}
        unsafe extern "C" fn s_send_map_res(_: *const shared::MapResult) {}
        unsafe extern "C" fn s_send_snap_ent(_: *const shared::SnapshotEntryRecord) {}
        unsafe extern "C" fn s_send_snap_res(_: *const shared::SnapshotResult) {}
        unsafe extern "C" fn s_fsync_in(_: u32) -> bool {
            true
        }
        unsafe extern "C" fn s_send_amend(_: *const shared::AmendResult) {}
        unsafe extern "C" fn s_send_bitmap(_: *const shared::BitmapResult) {}
        unsafe extern "C" fn s_send_bench_start() {}
        unsafe extern "C" fn s_send_bench_result(_: *const shared::BenchResult) {}
        shared::CallTable {
            magic: shared::CallTable::MAGIC,
            version: shared::CallTable::VERSION,
            get_input_device_count: s_dev_count,
            read_input_sector: mock_read_input_sector,
            get_input_capacity: s_in_cap,
            get_input_sector_size: s_in_secsz,
            write_output_sector: s_write_out,
            get_output_capacity: s_out_cap,
            get_output_sector_size: s_out_secsz,
            get_progress_interval: s_prog_int,
            send_progress: s_send_prog,
            send_error: s_send_err,
            send_complete: s_send_complete,
            debug_print: s_dbg,
            verbose_print: s_verb,
            get_operation_config: s_get_op_cfg,
            get_chain_config: s_get_chain_cfg,
            send_info_result: s_send_info,
            send_info_result_qcow2: s_send_info_q,
            send_info_result_vmdk: s_send_info_v,
            send_info_result_vdi: s_send_info_vdi,
            send_info_result_luks: s_send_info_l,
            send_check_result: s_send_check,
            send_compare_result: s_send_compare,
            send_measure_result: s_send_measure,
            send_create_result: s_send_create,
            read_output_sector: s_read_out,
            send_resize_result: s_send_resize,
            send_rebase_result: s_send_rebase,
            send_commit_result: s_send_commit,
            write_input_sector: s_write_in,
            send_map_extent: s_send_map_ex,
            send_map_result: s_send_map_res,
            send_snapshot_entry: s_send_snap_ent,
            send_snapshot_result: s_send_snap_res,
            fsync_input: s_fsync_in,
            send_amend_result: s_send_amend,
            send_bitmap_result: s_send_bitmap,
            send_bench_start: s_send_bench_start,
            send_bench_result: s_send_bench_result,
        }
    }

    /// Install `header` at offset 0 and `bmap` (u32 LE entries) at
    /// `offset_bmap` in the mock image, zeroing the rest. Returns a guard
    /// holding the lock for the duration of the test.
    fn install_image(
        header: &[u8; 512],
        offset_bmap: usize,
        bmap: &[u32],
    ) -> std::sync::MutexGuard<'static, ()> {
        let guard = MOCK_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            let img = core::ptr::addr_of_mut!(MOCK_IMAGE) as *mut u8;
            core::ptr::write_bytes(img, 0, MOCK_LEN);
            core::ptr::copy_nonoverlapping(header.as_ptr(), img, 512);
            for (i, &entry) in bmap.iter().enumerate() {
                let off = offset_bmap + i * 4;
                let bytes = entry.to_le_bytes();
                core::ptr::copy_nonoverlapping(bytes.as_ptr(), img.add(off), 4);
            }
        }
        guard
    }

    // ====================================================================
    // VdiState::init + block_lookup against the mock image
    // ====================================================================

    #[test]
    fn init_rejects_malformed_header() {
        let _guard = {
            let bad = HeaderSpec {
                signature: 0,
                ..HeaderSpec::default()
            };
            install_image(&build_header(&bad), 512, &[])
        };
        let ct = stub_call_table();
        let mut bmap_buf = [0u8; MAX_SECTOR_SIZE];
        let mut data_buf = [0u8; MAX_SECTOR_SIZE];
        let mut bytes_read = 0u64;
        let state = unsafe {
            VdiState::init(
                &ct,
                0,
                512,
                (MOCK_LEN / 512) as u64,
                bmap_buf.as_mut_ptr(),
                data_buf.as_mut_ptr(),
                &mut bytes_read,
            )
        };
        assert!(state.is_none());
    }

    #[test]
    fn block_lookup_sentinels_and_allocation_order() {
        // bmap [unallocated, 0, discarded, 1]: a non-identity allocation
        // order (entry index 3 → block 1, index 1 → block 0). block_size
        // is 1 MiB and offset_data is 0x400 (1024), matching the plan's
        // verified example (entry 1 → host offset 0x100400).
        let spec = HeaderSpec {
            offset_bmap: 512,
            offset_data: 0x400,
            disk_size: 4 * 1024 * 1024,
            blocks_in_image: 4,
            ..HeaderSpec::default()
        };
        let header = build_header(&spec);
        let bmap = [VDI_BLOCK_UNALLOCATED, 0u32, VDI_BLOCK_DISCARDED, 1u32];
        let _guard = install_image(&header, 512, &bmap);

        let ct = stub_call_table();
        let mut bmap_buf = [0u8; MAX_SECTOR_SIZE];
        let mut data_buf = [0u8; MAX_SECTOR_SIZE];
        let mut bytes_read = 0u64;
        let cap = (MOCK_LEN / 512) as u64;
        let block = VDI_BLOCK_SIZE as u64;

        let mut state = unsafe {
            VdiState::init(
                &ct,
                0,
                512,
                cap,
                bmap_buf.as_mut_ptr(),
                data_buf.as_mut_ptr(),
                &mut bytes_read,
            )
        }
        .unwrap();

        // Block 0 → unallocated sentinel.
        let l0 = unsafe { state.block_lookup(&ct, 0, 512, cap, &mut bytes_read) };
        assert_eq!(l0, Some(VdiBlockLookup::Unallocated));

        // Block 1 → entry 0, allocated: host = 0x400 + 0 * 1 MiB + 0.
        let l1 = unsafe { state.block_lookup(&ct, block, 512, cap, &mut bytes_read) };
        assert_eq!(
            l1,
            Some(VdiBlockLookup::Allocated {
                host_byte_offset: 0x400,
            })
        );

        // Block 2 → discarded sentinel, treated as unallocated.
        let l2 = unsafe { state.block_lookup(&ct, 2 * block, 512, cap, &mut bytes_read) };
        assert_eq!(l2, Some(VdiBlockLookup::Unallocated));

        // Block 3 → entry 1, allocated: host = 0x400 + 1 * 1 MiB = 0x100400
        // (the plan's verified spot-check, at in-block offset 0).
        let l3 = unsafe { state.block_lookup(&ct, 3 * block, 512, cap, &mut bytes_read) };
        assert_eq!(
            l3,
            Some(VdiBlockLookup::Allocated {
                host_byte_offset: 0x100400,
            })
        );
    }

    #[test]
    fn block_lookup_intra_block_offset_and_past_map() {
        let spec = HeaderSpec {
            offset_bmap: 512,
            offset_data: 0x400,
            disk_size: 4 * 1024 * 1024,
            blocks_in_image: 4,
            ..HeaderSpec::default()
        };
        let header = build_header(&spec);
        let bmap = [
            3u32,
            VDI_BLOCK_UNALLOCATED,
            VDI_BLOCK_UNALLOCATED,
            VDI_BLOCK_UNALLOCATED,
        ];
        let _guard = install_image(&header, 512, &bmap);

        let ct = stub_call_table();
        let mut bmap_buf = [0u8; MAX_SECTOR_SIZE];
        let mut data_buf = [0u8; MAX_SECTOR_SIZE];
        let mut bytes_read = 0u64;
        let cap = (MOCK_LEN / 512) as u64;
        let block = VDI_BLOCK_SIZE as u64;

        let mut state = unsafe {
            VdiState::init(
                &ct,
                0,
                512,
                cap,
                bmap_buf.as_mut_ptr(),
                data_buf.as_mut_ptr(),
                &mut bytes_read,
            )
        }
        .unwrap();

        // Block 0 → entry 3: host = 0x400 + 3 * 1 MiB + 0x1234 in-block.
        let off_in_block = 0x1234u64;
        let l = unsafe { state.block_lookup(&ct, off_in_block, 512, cap, &mut bytes_read) };
        assert_eq!(
            l,
            Some(VdiBlockLookup::Allocated {
                host_byte_offset: 0x400 + 3 * block + off_in_block,
            })
        );

        // A virtual offset in block 4 is past blocks_in_image (4) → the
        // block map does not cover it, so it reads as zeros.
        let past = unsafe { state.block_lookup(&ct, 4 * block, 512, cap, &mut bytes_read) };
        assert_eq!(past, Some(VdiBlockLookup::Unallocated));
    }

    #[test]
    fn block_lookup_allows_past_eof_host_offset() {
        // An allocated entry whose host offset lands past the mock image
        // length must NOT be rejected — past-EOF classification is the
        // caller's job. entry 100 → host = 0x400 + 100 * 1 MiB, far past
        // the 64 KiB mock capacity.
        let spec = HeaderSpec {
            offset_bmap: 512,
            offset_data: 0x400,
            disk_size: 4 * 1024 * 1024,
            blocks_in_image: 4,
            ..HeaderSpec::default()
        };
        let header = build_header(&spec);
        let bmap = [
            100u32,
            VDI_BLOCK_UNALLOCATED,
            VDI_BLOCK_UNALLOCATED,
            VDI_BLOCK_UNALLOCATED,
        ];
        let _guard = install_image(&header, 512, &bmap);

        let ct = stub_call_table();
        let mut bmap_buf = [0u8; MAX_SECTOR_SIZE];
        let mut data_buf = [0u8; MAX_SECTOR_SIZE];
        let mut bytes_read = 0u64;
        let cap = (MOCK_LEN / 512) as u64;

        let mut state = unsafe {
            VdiState::init(
                &ct,
                0,
                512,
                cap,
                bmap_buf.as_mut_ptr(),
                data_buf.as_mut_ptr(),
                &mut bytes_read,
            )
        }
        .unwrap();

        let l = unsafe { state.block_lookup(&ct, 0, 512, cap, &mut bytes_read) };
        assert_eq!(
            l,
            Some(VdiBlockLookup::Allocated {
                host_byte_offset: 0x400 + 100 * VDI_BLOCK_SIZE as u64,
            })
        );
    }

    #[test]
    fn block_lookup_fails_when_bmap_sector_unreadable() {
        // offset_bmap points past the mock image so the block-map sector
        // read fails; the lookup must surface that as None.
        let spec = HeaderSpec {
            offset_bmap: (MOCK_LEN as u32) + 512,
            offset_data: 0x400,
            disk_size: 4 * 1024 * 1024,
            blocks_in_image: 4,
            ..HeaderSpec::default()
        };
        let header = build_header(&spec);
        let _guard = install_image(&header, 512, &[]);

        let ct = stub_call_table();
        let mut bmap_buf = [0u8; MAX_SECTOR_SIZE];
        let mut data_buf = [0u8; MAX_SECTOR_SIZE];
        let mut bytes_read = 0u64;
        let cap = (MOCK_LEN / 512) as u64;
        let block = VDI_BLOCK_SIZE as u64;

        let mut state = unsafe {
            VdiState::init(
                &ct,
                0,
                512,
                cap,
                bmap_buf.as_mut_ptr(),
                data_buf.as_mut_ptr(),
                &mut bytes_read,
            )
        }
        .unwrap();

        let l = unsafe { state.block_lookup(&ct, block, 512, cap, &mut bytes_read) };
        assert!(l.is_none());
    }
}
