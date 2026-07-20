//! Unit tests for the DMG (UDIF) parser.
//!
//! Synthetic koly + plist/resource-fork + mish images are assembled in
//! memory and served through a mock call table (the same global-static +
//! lock pattern the qcow1/parallels crates use, since `read_input_sector`
//! is an `extern "C" fn` that can only close over `'static` state). Chunk
//! `comp_offset` values are arbitrary — 5a never reads the data fork, so
//! lookups simply echo the composed host offsets.

use super::*;
use core::sync::atomic::{AtomicU64, Ordering};
use shared::{write_be_u32, write_be_u64};
use std::string::String;
use std::sync::Mutex;
use std::vec::Vec;

// ============================================================================
// Image assembly helpers
// ============================================================================

/// One synthetic chunk entry.
#[derive(Clone, Copy)]
struct ChunkSpec {
    ctype: u32,
    sector: u64,
    sector_count: u64,
    comp_offset: u64,
    comp_len: u64,
}

impl ChunkSpec {
    fn new(ctype: u32, sector: u64, sector_count: u64, comp_offset: u64, comp_len: u64) -> Self {
        ChunkSpec {
            ctype,
            sector,
            sector_count,
            comp_offset,
            comp_len,
        }
    }
}

/// Build a mish block: 204-byte header (magic @0, out_offset @8,
/// data_offset @0x18) followed by 40-byte BE chunk entries.
fn build_mish(out_offset: u64, data_offset: u64, chunks: &[ChunkSpec]) -> Vec<u8> {
    let mut b = std::vec![0u8; MISH_HEADER_LEN + chunks.len() * MISH_ENTRY_LEN];
    write_be_u32(&mut b, 0, MISH_MAGIC);
    write_be_u64(&mut b, 8, out_offset);
    write_be_u64(&mut b, 0x18, data_offset);
    let mut off = MISH_HEADER_LEN;
    for c in chunks {
        write_be_u32(&mut b, off, c.ctype);
        write_be_u64(&mut b, off + 8, c.sector);
        write_be_u64(&mut b, off + 0x10, c.sector_count);
        write_be_u64(&mut b, off + 0x18, c.comp_offset);
        write_be_u64(&mut b, off + 0x20, c.comp_len);
        off += MISH_ENTRY_LEN;
    }
    b
}

/// Standard base64 encoder (for embedding mish blocks in a plist).
fn base64_encode(data: &[u8]) -> String {
    const ALPHA: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = if chunk.len() > 1 { chunk[1] as u32 } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] as u32 } else { 0 };
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(ALPHA[((n >> 18) & 63) as usize] as char);
        out.push(ALPHA[((n >> 12) & 63) as usize] as char);
        if chunk.len() > 1 {
            out.push(ALPHA[((n >> 6) & 63) as usize] as char);
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(ALPHA[(n & 63) as usize] as char);
        } else {
            out.push('=');
        }
    }
    out
}

/// koly trailer field spec.
struct KolySpec {
    magic: bool,
    data_fork_offset: u64,
    rsrc_fork_offset: u64,
    rsrc_fork_length: u64,
    xml_offset: u64,
    xml_length: u64,
    sector_count: u64,
}

fn build_koly(spec: &KolySpec) -> [u8; 512] {
    let mut b = [0u8; 512];
    if spec.magic {
        b[0..4].copy_from_slice(b"koly");
    }
    write_be_u64(&mut b, 0x18, spec.data_fork_offset);
    write_be_u64(&mut b, 0x28, spec.rsrc_fork_offset);
    write_be_u64(&mut b, 0x30, spec.rsrc_fork_length);
    write_be_u64(&mut b, 0xd8, spec.xml_offset);
    write_be_u64(&mut b, 0xe0, spec.xml_length);
    write_be_u64(&mut b, 0x1ec, spec.sector_count);
    b
}

/// Assemble a plist-path image: [512-byte data-fork prefix][xml][koly].
/// data_fork_offset and mish data_offset are 0, so composed host offsets
/// equal each chunk's raw `comp_offset`.
fn assemble_plist_image_xml(xml: &str, sector_count: u64) -> Vec<u8> {
    let prefix = 512usize;
    let xml_bytes = xml.as_bytes();
    let xml_offset = prefix;
    let koly_offset = xml_offset + xml_bytes.len();
    let total = koly_offset + 512;
    let mut bytes = std::vec![0u8; total];
    bytes[xml_offset..xml_offset + xml_bytes.len()].copy_from_slice(xml_bytes);
    let koly = build_koly(&KolySpec {
        magic: true,
        data_fork_offset: 0,
        rsrc_fork_offset: 0,
        rsrc_fork_length: 0,
        xml_offset: xml_offset as u64,
        xml_length: xml_bytes.len() as u64,
        sector_count,
    });
    bytes[koly_offset..koly_offset + 512].copy_from_slice(&koly);
    bytes
}

/// Wrap mish blocks in a `<data>…</data>` plist and assemble an image.
fn assemble_plist_image(mish_blocks: &[Vec<u8>], sector_count: u64) -> Vec<u8> {
    let mut xml = String::from("<plist><dict><key>blkx</key><array>");
    for m in mish_blocks {
        xml.push_str("<data>");
        xml.push_str(&base64_encode(m));
        xml.push_str("</data>");
    }
    xml.push_str("</array></dict></plist>");
    assemble_plist_image_xml(&xml, sector_count)
}

/// Build a resource-fork region: [u32 rsrc_data_offset][u32 pad][u32
/// count] then, at rsrc_data_offset, per-resource `[u32 size][mish]`.
fn build_rsrc_region(mish_blocks: &[Vec<u8>]) -> Vec<u8> {
    let rsrc_data_offset = 16usize;
    let mut rd = Vec::new();
    for m in mish_blocks {
        rd.extend_from_slice(&(m.len() as u32).to_be_bytes());
        rd.extend_from_slice(m);
    }
    let count = rd.len();
    let region_len = rsrc_data_offset + count;
    let mut region = std::vec![0u8; region_len];
    write_be_u32(&mut region, 0, rsrc_data_offset as u32);
    write_be_u32(&mut region, 8, count as u32);
    region[rsrc_data_offset..rsrc_data_offset + count].copy_from_slice(&rd);
    region
}

/// Assemble a resource-fork-path image: [512 prefix][rsrc region][koly].
fn assemble_rsrc_image(region: &[u8], sector_count: u64) -> Vec<u8> {
    let prefix = 512usize;
    let rsrc_offset = prefix;
    let koly_offset = rsrc_offset + region.len();
    let total = koly_offset + 512;
    let mut bytes = std::vec![0u8; total];
    bytes[rsrc_offset..rsrc_offset + region.len()].copy_from_slice(region);
    let koly = build_koly(&KolySpec {
        magic: true,
        data_fork_offset: 0,
        rsrc_fork_offset: rsrc_offset as u64,
        rsrc_fork_length: region.len() as u64,
        xml_offset: 0,
        xml_length: 0,
        sector_count,
    });
    bytes[koly_offset..koly_offset + 512].copy_from_slice(&koly);
    bytes
}

// ============================================================================
// Mock CallTable backed by an in-memory image
// ============================================================================

// Large enough to hold the >1 MiB image the RegionTooLarge test needs
// (its koly must sit past the 1 MiB region cap so the region-bounds check
// passes and the cap is what refuses).
const MOCK_LEN: usize = 2 * 1024 * 1024;
static MOCK_LOCK: Mutex<()> = Mutex::new(());
static mut MOCK_IMAGE: [u8; MOCK_LEN] = [0u8; MOCK_LEN];

// A single sector index whose read the failing mock (`mock_read_fail`)
// refuses; `u64::MAX` disables it. Used to reach the staged-region
// read-failure path while letting the koly read (a different sector)
// succeed. Only consulted by `mock_read_fail`, so the default mock is
// unaffected.
static MOCK_FAIL_SECTOR: AtomicU64 = AtomicU64::new(u64::MAX);

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

/// Like [`mock_read_input_sector`] but refuses the one sector recorded in
/// [`MOCK_FAIL_SECTOR`], modelling a device read that fails mid-parse.
unsafe extern "C" fn mock_read_fail(
    device_idx: u32,
    sector: u64,
    out_buf: *mut u8,
    sector_size: usize,
) -> bool {
    if sector == MOCK_FAIL_SECTOR.load(Ordering::Relaxed) {
        return false;
    }
    mock_read_input_sector(device_idx, sector, out_buf, sector_size)
}

/// Install an image into the mock buffer and return (guard, capacity).
fn install_image(bytes: &[u8]) -> (std::sync::MutexGuard<'static, ()>, u64) {
    assert!(bytes.len() <= MOCK_LEN, "image too big for mock buffer");
    let guard = MOCK_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    unsafe {
        let img = core::ptr::addr_of_mut!(MOCK_IMAGE) as *mut u8;
        core::ptr::write_bytes(img, 0, MOCK_LEN);
        core::ptr::copy_nonoverlapping(bytes.as_ptr(), img, bytes.len());
    }
    let cap = ((bytes.len() + 511) / 512) as u64;
    (guard, cap)
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

/// Owns a scratch region across a test; `init` serves an image through the
/// mock while holding the lock only for the parse.
struct Harness {
    scratch: Vec<u8>,
}

impl Harness {
    fn new() -> Self {
        Harness {
            scratch: std::vec![0u8; DMG_REQUIRED_SCRATCH],
        }
    }

    /// Init against `bytes` with the real computed capacity.
    unsafe fn init(&mut self, bytes: &[u8]) -> Result<DmgState, DmgRefusal> {
        let (_guard, cap) = install_image(bytes);
        let ct = stub_call_table();
        let mut br = 0u64;
        DmgState::init(
            &ct,
            0,
            512,
            cap,
            self.scratch.as_mut_ptr(),
            self.scratch.len(),
            &mut br,
        )
    }

    /// Init with an explicitly-overridden capacity (for edge cases).
    unsafe fn init_cap(&mut self, bytes: &[u8], cap: u64) -> Result<DmgState, DmgRefusal> {
        let (_guard, _real) = install_image(bytes);
        let ct = stub_call_table();
        let mut br = 0u64;
        DmgState::init(
            &ct,
            0,
            512,
            cap,
            self.scratch.as_mut_ptr(),
            self.scratch.len(),
            &mut br,
        )
    }

    /// Init while device sector `fail_sector` refuses reads (all other
    /// sectors serve `bytes` normally). Lets a test fail a staged-region
    /// read while the koly read — which touches different sectors — still
    /// succeeds.
    unsafe fn init_failing(
        &mut self,
        bytes: &[u8],
        fail_sector: u64,
    ) -> Result<DmgState, DmgRefusal> {
        let (_guard, cap) = install_image(bytes);
        MOCK_FAIL_SECTOR.store(fail_sector, Ordering::Relaxed);
        let mut ct = stub_call_table();
        ct.read_input_sector = mock_read_fail;
        let mut br = 0u64;
        let r = DmgState::init(
            &ct,
            0,
            512,
            cap,
            self.scratch.as_mut_ptr(),
            self.scratch.len(),
            &mut br,
        );
        MOCK_FAIL_SECTOR.store(u64::MAX, Ordering::Relaxed);
        r
    }
}

/// A minimal single-zlib-chunk plist image with `sector_count` sectors.
fn simple_zlib_image() -> Vec<u8> {
    let mish = build_mish(0, 0, &[ChunkSpec::new(CHUNK_ZLIB, 0, 8, 4096, 100)]);
    assemble_plist_image(&[mish], 8)
}

// ============================================================================
// koly acceptance / validation
// ============================================================================

#[test]
fn init_accepts_simple_plist_image() {
    let mut h = Harness::new();
    let img = simple_zlib_image();
    let state = unsafe { h.init(&img) }.expect("valid image");
    assert_eq!(state.chunk_count, 1);
    assert_eq!(state.virtual_sectors, 8);
    assert_eq!(state.virtual_size, 8 * 512);
}

#[test]
fn init_rejects_zero_capacity() {
    let mut h = Harness::new();
    let img = simple_zlib_image();
    let r = unsafe { h.init_cap(&img, 0) };
    assert_eq!(r, Err(DmgRefusal::TrailerNotFound));
}

#[test]
fn init_rejects_missing_koly_magic() {
    // Same layout but with the koly magic cleared.
    let mish = build_mish(0, 0, &[ChunkSpec::new(CHUNK_ZLIB, 0, 8, 4096, 100)]);
    let mut xml = String::from("<data>");
    xml.push_str(&base64_encode(&mish));
    xml.push_str("</data>");
    let mut img = assemble_plist_image_xml(&xml, 8);
    // Wipe the koly magic (last 512 bytes start).
    let koly_start = img.len() - 512;
    for b in &mut img[koly_start..koly_start + 4] {
        *b = 0;
    }
    let mut h = Harness::new();
    let r = unsafe { h.init(&img) };
    assert_eq!(r, Err(DmgRefusal::TrailerNotFound));
}

#[test]
fn init_rejects_negative_sector_count() {
    let mish = build_mish(0, 0, &[ChunkSpec::new(CHUNK_ZLIB, 0, 8, 4096, 100)]);
    let img = assemble_plist_image(&[mish], 1u64 << 63);
    let mut h = Harness::new();
    let r = unsafe { h.init(&img) };
    assert_eq!(r, Err(DmgRefusal::NegativeSectorCount));
}

#[test]
fn init_rejects_bad_data_fork_offset() {
    // Craft a koly whose DataForkOffset exceeds the koly offset.
    let mish = build_mish(0, 0, &[ChunkSpec::new(CHUNK_ZLIB, 0, 8, 4096, 100)]);
    let mut xml = String::from("<data>");
    xml.push_str(&base64_encode(&mish));
    xml.push_str("</data>");
    let xml_bytes = xml.into_bytes();
    let prefix = 512usize;
    let xml_offset = prefix;
    let koly_offset = xml_offset + xml_bytes.len();
    let total = koly_offset + 512;
    let mut bytes = std::vec![0u8; total];
    bytes[xml_offset..xml_offset + xml_bytes.len()].copy_from_slice(&xml_bytes);
    let koly = build_koly(&KolySpec {
        magic: true,
        data_fork_offset: (koly_offset as u64) + 1, // > koly offset
        rsrc_fork_offset: 0,
        rsrc_fork_length: 0,
        xml_offset: xml_offset as u64,
        xml_length: xml_bytes.len() as u64,
        sector_count: 8,
    });
    bytes[koly_offset..koly_offset + 512].copy_from_slice(&koly);
    let mut h = Harness::new();
    assert_eq!(
        unsafe { h.init(&bytes) },
        Err(DmgRefusal::BadDataForkOffset)
    );
}

#[test]
fn init_rejects_bad_xml_region() {
    // xml_offset >= koly offset.
    let mish = build_mish(0, 0, &[ChunkSpec::new(CHUNK_ZLIB, 0, 8, 4096, 100)]);
    let img0 = assemble_plist_image(&[mish], 8);
    let koly_offset = img0.len() - 512;
    let mut img = img0;
    // Overwrite XMLOffset with a value >= koly offset.
    write_be_u64(&mut img[koly_offset..], 0xd8, koly_offset as u64);
    let mut h = Harness::new();
    assert_eq!(unsafe { h.init(&img) }, Err(DmgRefusal::BadXmlRegion));
}

#[test]
fn init_rejects_bad_rsrc_region() {
    // rsrc_fork_length != 0 but rsrc_fork_offset >= koly offset.
    let mish = build_mish(0, 0, &[ChunkSpec::new(CHUNK_ZLIB, 0, 8, 4096, 100)]);
    let img0 = assemble_plist_image(&[mish], 8);
    let koly_offset = img0.len() - 512;
    let mut img = img0;
    write_be_u64(&mut img[koly_offset..], 0x28, koly_offset as u64); // rsrc offset
    write_be_u64(&mut img[koly_offset..], 0x30, 16); // rsrc length != 0
    let mut h = Harness::new();
    assert_eq!(unsafe { h.init(&img) }, Err(DmgRefusal::BadRsrcForkRegion));
}

#[test]
fn init_rejects_no_chunk_source() {
    // Both rsrc and xml lengths zero.
    let prefix = 512usize;
    let koly_offset = prefix;
    let total = koly_offset + 512;
    let mut bytes = std::vec![0u8; total];
    let koly = build_koly(&KolySpec {
        magic: true,
        data_fork_offset: 0,
        rsrc_fork_offset: 0,
        rsrc_fork_length: 0,
        xml_offset: 0,
        xml_length: 0,
        sector_count: 8,
    });
    bytes[koly_offset..koly_offset + 512].copy_from_slice(&koly);
    let mut h = Harness::new();
    assert_eq!(unsafe { h.init(&bytes) }, Err(DmgRefusal::NoChunkSource));
}

#[test]
fn init_rejects_small_scratch() {
    let img = simple_zlib_image();
    let (_guard, cap) = install_image(&img);
    let ct = stub_call_table();
    let mut small = std::vec![0u8; DMG_REQUIRED_SCRATCH - 1];
    let mut br = 0u64;
    let r = unsafe { DmgState::init(&ct, 0, 512, cap, small.as_mut_ptr(), small.len(), &mut br) };
    assert_eq!(r, Err(DmgRefusal::ScratchTooSmall));
}

#[test]
fn path_selection_prefers_rsrc_over_xml() {
    // Build an image with BOTH a resource fork (2 chunks) and an XML plist
    // (1 chunk). qemu (and instar) select the resource fork.
    let rsrc_mish = build_mish(
        0,
        0,
        &[
            ChunkSpec::new(CHUNK_ZERO, 0, 4, 0, 0),
            ChunkSpec::new(CHUNK_RAW, 4, 4, 8192, 2048),
        ],
    );
    let region = build_rsrc_region(&[rsrc_mish]);

    let xml_mish = build_mish(0, 0, &[ChunkSpec::new(CHUNK_ZLIB, 0, 8, 4096, 100)]);
    let mut xml = String::from("<data>");
    xml.push_str(&base64_encode(&xml_mish));
    xml.push_str("</data>");
    let xml_bytes = xml.into_bytes();

    // Layout: [512 prefix][rsrc region][xml][koly].
    let prefix = 512usize;
    let rsrc_offset = prefix;
    let xml_offset = rsrc_offset + region.len();
    let koly_offset = xml_offset + xml_bytes.len();
    let total = koly_offset + 512;
    let mut bytes = std::vec![0u8; total];
    bytes[rsrc_offset..rsrc_offset + region.len()].copy_from_slice(&region);
    bytes[xml_offset..xml_offset + xml_bytes.len()].copy_from_slice(&xml_bytes);
    let koly = build_koly(&KolySpec {
        magic: true,
        data_fork_offset: 0,
        rsrc_fork_offset: rsrc_offset as u64,
        rsrc_fork_length: region.len() as u64,
        xml_offset: xml_offset as u64,
        xml_length: xml_bytes.len() as u64,
        sector_count: 8,
    });
    bytes[koly_offset..koly_offset + 512].copy_from_slice(&koly);

    let mut h = Harness::new();
    let state = unsafe { h.init(&bytes) }.expect("valid");
    // Resource fork has 2 chunks; the XML path (1 chunk) was not taken.
    assert_eq!(state.chunk_count, 2);
}

// ============================================================================
// plist scan
// ============================================================================

#[test]
fn plist_multiple_data_blocks() {
    let m0 = build_mish(0, 0, &[ChunkSpec::new(CHUNK_ZERO, 0, 4, 0, 0)]);
    let m1 = build_mish(0, 0, &[ChunkSpec::new(CHUNK_RAW, 4, 4, 8192, 2048)]);
    let img = assemble_plist_image(&[m0, m1], 8);
    let mut h = Harness::new();
    let state = unsafe { h.init(&img) }.expect("valid");
    assert_eq!(state.chunk_count, 2);
}

#[test]
fn plist_non_mish_block_ignored() {
    // A <data> block whose bytes are not a mish is silently ignored; the
    // valid one is kept.
    let junk = std::vec![0xAAu8; 300]; // >= 244 bytes but wrong magic
    let good = build_mish(0, 0, &[ChunkSpec::new(CHUNK_ZLIB, 0, 8, 4096, 100)]);
    let mut xml = String::from("<data>");
    xml.push_str(&base64_encode(&junk));
    xml.push_str("</data><data>");
    xml.push_str(&base64_encode(&good));
    xml.push_str("</data>");
    let img = assemble_plist_image_xml(&xml, 8);
    let mut h = Harness::new();
    let state = unsafe { h.init(&img) }.expect("valid");
    assert_eq!(state.chunk_count, 1);
}

#[test]
fn plist_mish_too_short_ignored_then_empty() {
    // A <data> block decoding to < 244 bytes is skipped; with no other
    // block the table is empty → EmptyChunkTable.
    let short = std::vec![0u8; 100];
    let mut xml = String::from("<data>");
    xml.push_str(&base64_encode(&short));
    xml.push_str("</data>");
    let img = assemble_plist_image_xml(&xml, 8);
    let mut h = Harness::new();
    assert_eq!(unsafe { h.init(&img) }, Err(DmgRefusal::EmptyChunkTable));
}

#[test]
fn plist_missing_close_tag_refused() {
    let good = build_mish(0, 0, &[ChunkSpec::new(CHUNK_ZLIB, 0, 8, 4096, 100)]);
    let mut xml = String::from("<data>");
    xml.push_str(&base64_encode(&good));
    // no </data>
    let img = assemble_plist_image_xml(&xml, 8);
    let mut h = Harness::new();
    assert_eq!(unsafe { h.init(&img) }, Err(DmgRefusal::MalformedXml));
}

#[test]
fn plist_no_data_blocks_is_empty_table() {
    let img = assemble_plist_image_xml("<plist>no data here</plist>", 8);
    let mut h = Harness::new();
    assert_eq!(unsafe { h.init(&img) }, Err(DmgRefusal::EmptyChunkTable));
}

// ============================================================================
// lenient base64 (glib semantics)
// ============================================================================

#[test]
fn base64_glib_vector_skips_whitespace_and_invalid() {
    // "SGVsbG8=" decodes to "Hello". glib skips characters outside the
    // alphabet, so injected whitespace and punctuation must not change the
    // result.
    let mut out = [0u8; 16];
    let n = glib_base64_decode(b"SGVsbG8=", &mut out);
    assert_eq!(&out[..n], b"Hello");

    let n2 = glib_base64_decode(b"SG!Vs\n bG8=", &mut out);
    assert_eq!(&out[..n2], b"Hello");

    // Padding: "TWE=" → "Ma" (2 bytes); "TQ==" → "M" (1 byte).
    let n3 = glib_base64_decode(b"TWE=", &mut out);
    assert_eq!(&out[..n3], b"Ma");
    let n4 = glib_base64_decode(b"TQ==", &mut out);
    assert_eq!(&out[..n4], b"M");

    // A trailing partial group (fewer than 4 symbols, no padding) is
    // discarded, exactly like glib.
    let n5 = glib_base64_decode(b"TWFuTW", &mut out);
    assert_eq!(&out[..n5], b"Man");
}

#[test]
fn base64_lenient_whitespace_still_opens_image() {
    // A real mish, base64-encoded with newlines every 16 chars (hdiutil
    // wraps plist data), still parses.
    let mish = build_mish(0, 0, &[ChunkSpec::new(CHUNK_ZLIB, 0, 8, 4096, 100)]);
    let enc = base64_encode(&mish);
    let mut wrapped = String::new();
    for (i, ch) in enc.chars().enumerate() {
        if i % 16 == 0 {
            wrapped.push('\n');
        }
        wrapped.push(ch);
    }
    let mut xml = String::from("<data>");
    xml.push_str(&wrapped);
    xml.push_str("</data>");
    let img = assemble_plist_image_xml(&xml, 8);
    let mut h = Harness::new();
    let state = unsafe { h.init(&img) }.expect("valid despite whitespace");
    assert_eq!(state.chunk_count, 1);
}

// ============================================================================
// mish decode: out_offset / data_offset / DataForkOffset arithmetic
// ============================================================================

#[test]
fn mish_offset_arithmetic_composed() {
    // out_offset shifts sectors; data_offset + DataForkOffset shift host
    // offsets. Use the resource-fork path so we can set DataForkOffset != 0
    // (host offsets need not point at real data in 5a).
    let out_offset = 100u64;
    let data_offset = 4096u64;
    let comp_offset = 512u64;
    let mish = build_mish(
        out_offset,
        data_offset,
        &[ChunkSpec::new(CHUNK_ZLIB, 5, 8, comp_offset, 128)],
    );
    let region = build_rsrc_region(&[mish]);

    // Assemble with a non-zero DataForkOffset in the koly. It must be
    // <= the koly offset (qemu's rule), which is small for this tiny image.
    let data_fork_offset = 128u64;
    let prefix = 512usize;
    let rsrc_offset = prefix;
    let koly_offset = rsrc_offset + region.len();
    let total = koly_offset + 512;
    let mut bytes = std::vec![0u8; total];
    bytes[rsrc_offset..rsrc_offset + region.len()].copy_from_slice(&region);
    let koly = build_koly(&KolySpec {
        magic: true,
        data_fork_offset,
        rsrc_fork_offset: rsrc_offset as u64,
        rsrc_fork_length: region.len() as u64,
        xml_offset: 0,
        xml_length: 0,
        sector_count: 200,
    });
    bytes[koly_offset..koly_offset + 512].copy_from_slice(&koly);

    let mut h = Harness::new();
    let state = unsafe { h.init(&bytes) }.expect("valid");
    // The chunk starts at sector 5 + out_offset(100) = 105.
    let l = unsafe { state.chunk_lookup(105) };
    match l {
        DmgLookup::Zlib {
            host_offset,
            comp_len,
            chunk_first_sector,
            chunk_sector_count,
        } => {
            assert_eq!(chunk_first_sector, 105);
            assert_eq!(chunk_sector_count, 8);
            assert_eq!(comp_len, 128);
            // host = comp_offset + data_offset + data_fork_offset.
            assert_eq!(host_offset, comp_offset + data_offset + data_fork_offset);
        }
        other => panic!("expected zlib, got {other:?}"),
    }
}

// ============================================================================
// qemu caps and the zero/ignore exemption
// ============================================================================

#[test]
fn qemu_sector_count_cap_boundary() {
    // 131073 sectors on a raw chunk trips qemu's cap first.
    let over = build_mish(
        0,
        0,
        &[ChunkSpec::new(CHUNK_RAW, 0, DMG_SECTORCOUNTS_MAX + 1, 0, 0)],
    );
    let img = assemble_plist_image(&[over], DMG_SECTORCOUNTS_MAX + 1);
    let mut h = Harness::new();
    assert_eq!(
        unsafe { h.init(&img) },
        Err(DmgRefusal::QemuSectorCountTooLarge)
    );

    // Exactly at qemu's cap it passes qemu but then trips instar's tighter
    // staging cap (a distinct reason).
    let at = build_mish(
        0,
        0,
        &[ChunkSpec::new(CHUNK_RAW, 0, DMG_SECTORCOUNTS_MAX, 0, 0)],
    );
    let img2 = assemble_plist_image(&[at], DMG_SECTORCOUNTS_MAX);
    let mut h2 = Harness::new();
    assert_eq!(
        unsafe { h2.init(&img2) },
        Err(DmgRefusal::StagedSectorCountTooLarge)
    );
}

#[test]
fn qemu_length_cap_boundary() {
    // comp_len 64 MiB + 1 trips qemu's length cap first.
    let over = build_mish(
        0,
        0,
        &[ChunkSpec::new(CHUNK_ZLIB, 0, 1, 0, DMG_LENGTHS_MAX + 1)],
    );
    let img = assemble_plist_image(&[over], 8);
    let mut h = Harness::new();
    assert_eq!(
        unsafe { h.init(&img) },
        Err(DmgRefusal::QemuChunkLengthTooLarge)
    );

    // 64 MiB exactly passes qemu but trips instar's compressed-buffer cap.
    let at = build_mish(
        0,
        0,
        &[ChunkSpec::new(CHUNK_ZLIB, 0, 1, 0, DMG_LENGTHS_MAX)],
    );
    let img2 = assemble_plist_image(&[at], 8);
    let mut h2 = Harness::new();
    assert_eq!(
        unsafe { h2.init(&img2) },
        Err(DmgRefusal::StagedChunkLengthTooLarge)
    );
}

#[test]
fn zero_ignore_exempt_from_sector_cap() {
    // A zero chunk with a huge sector count is accepted (exempt from both
    // the qemu and instar sector caps).
    let big = DMG_SECTORCOUNTS_MAX + 100_000;
    let mish = build_mish(0, 0, &[ChunkSpec::new(CHUNK_ZERO, 0, big, 0, 0)]);
    let img = assemble_plist_image(&[mish], big);
    let mut h = Harness::new();
    let state = unsafe { h.init(&img) }.expect("zero chunk exempt");
    assert_eq!(state.chunk_count, 1);
    // The whole range is a single zero span.
    match unsafe { state.chunk_lookup(0) } {
        DmgLookup::Zero { span_sectors } => assert_eq!(span_sectors, big),
        other => panic!("expected zero, got {other:?}"),
    }
}

// ============================================================================
// instar bounded-memory caps
// ============================================================================

#[test]
fn instar_staged_sector_cap_boundary() {
    // 4096 sectors accepted; 4097 refused.
    let ok = build_mish(
        0,
        0,
        &[ChunkSpec::new(
            CHUNK_RAW,
            0,
            DMG_MAX_STAGED_SECTOR_COUNT,
            0,
            512,
        )],
    );
    let img = assemble_plist_image(&[ok], DMG_MAX_STAGED_SECTOR_COUNT);
    let mut h = Harness::new();
    assert!(unsafe { h.init(&img) }.is_ok());

    let over = build_mish(
        0,
        0,
        &[ChunkSpec::new(
            CHUNK_RAW,
            0,
            DMG_MAX_STAGED_SECTOR_COUNT + 1,
            0,
            512,
        )],
    );
    let img2 = assemble_plist_image(&[over], DMG_MAX_STAGED_SECTOR_COUNT + 1);
    let mut h2 = Harness::new();
    assert_eq!(
        unsafe { h2.init(&img2) },
        Err(DmgRefusal::StagedSectorCountTooLarge)
    );
}

#[test]
fn instar_staged_comp_len_cap_boundary() {
    let cap = shared::COMPRESSED_BUF_SIZE as u64;
    // comp_len == COMPRESSED_BUF_SIZE accepted.
    let ok = build_mish(0, 0, &[ChunkSpec::new(CHUNK_ZLIB, 0, 8, 0, cap)]);
    let img = assemble_plist_image(&[ok], 8);
    let mut h = Harness::new();
    assert!(unsafe { h.init(&img) }.is_ok());

    // + 1 refused.
    let over = build_mish(0, 0, &[ChunkSpec::new(CHUNK_ZLIB, 0, 8, 0, cap + 1)]);
    let img2 = assemble_plist_image(&[over], 8);
    let mut h2 = Harness::new();
    assert_eq!(
        unsafe { h2.init(&img2) },
        Err(DmgRefusal::StagedChunkLengthTooLarge)
    );
}

#[test]
fn instar_chunk_table_cap_via_builder() {
    // The 1 MiB region cap keeps a single staged source below 32768
    // chunks, so ChunkTableTooLarge is a backstop reached only by direct
    // over-filling of the builder. Exercise it white-box.
    let mut table = std::vec![0u8; DMG_TABLE_REGION];
    let mut builder = ChunkBuilder {
        base: table.as_mut_ptr() as *mut DmgChunk,
        count: 0,
    };
    let rec = DmgChunk {
        first_sector: 0,
        sector_count: 1,
        host_offset: 0,
        comp_len: 0,
        kind: DmgChunkKind::Zero,
        _pad: 0,
    };
    for _ in 0..DMG_MAX_CHUNKS {
        assert!(unsafe { builder.push(rec) }.is_ok());
    }
    assert_eq!(
        unsafe { builder.push(rec) },
        Err(DmgRefusal::ChunkTableTooLarge)
    );
}

#[test]
fn plist_region_too_large_refused() {
    // An XMLLength over the 1 MiB instar cap refuses before staging. The
    // koly must sit past the region so the koly XML-region bounds check
    // (which would otherwise fire as BadXmlRegion) passes first.
    let xml_len = DMG_REGION_STAGE_CAP as u64 + 1;
    let xml_offset = 512u64;
    let koly_offset = (xml_offset + xml_len) as usize; // region fits before koly
    let total = koly_offset + 512;
    let mut bytes = std::vec![0u8; total];
    let koly = build_koly(&KolySpec {
        magic: true,
        data_fork_offset: 0,
        rsrc_fork_offset: 0,
        rsrc_fork_length: 0,
        xml_offset,
        xml_length: xml_len,
        sector_count: 8,
    });
    bytes[koly_offset..koly_offset + 512].copy_from_slice(&koly);
    let mut h = Harness::new();
    assert_eq!(unsafe { h.init(&bytes) }, Err(DmgRefusal::RegionTooLarge));
}

// ============================================================================
// codec refusals (typed, code-naming)
// ============================================================================

#[test]
fn codec_refusals_name_the_code() {
    for code in [
        CHUNK_ADC,
        CHUNK_BZIP2,
        CHUNK_LZFSE,
        CHUNK_ZSTD,
        0x1234_5678u32, // arbitrary unknown
    ] {
        let mish = build_mish(0, 0, &[ChunkSpec::new(code, 0, 8, 4096, 100)]);
        let img = assemble_plist_image(&[mish], 8);
        let mut h = Harness::new();
        assert_eq!(
            unsafe { h.init(&img) },
            Err(DmgRefusal::UnsupportedCodec(code)),
            "code {code:#x}"
        );
    }
}

#[test]
fn comment_and_terminator_dropped() {
    // comment + valid zlib + terminator → only the zlib chunk is kept.
    let mish = build_mish(
        0,
        0,
        &[
            ChunkSpec::new(CHUNK_COMMENT, 0, 0, 0, 0),
            ChunkSpec::new(CHUNK_ZLIB, 0, 8, 4096, 100),
            ChunkSpec::new(CHUNK_TERMINATOR, 0, 0, 0, 0),
        ],
    );
    let img = assemble_plist_image(&[mish], 8);
    let mut h = Harness::new();
    let state = unsafe { h.init(&img) }.expect("valid");
    assert_eq!(state.chunk_count, 1);
}

#[test]
fn only_terminator_is_empty_table() {
    // A mish with just a terminator keeps no chunks → the qemu-segfault
    // case, refused cleanly.
    let mish = build_mish(0, 0, &[ChunkSpec::new(CHUNK_TERMINATOR, 0, 0, 0, 0)]);
    let img = assemble_plist_image(&[mish], 8);
    let mut h = Harness::new();
    assert_eq!(unsafe { h.init(&img) }, Err(DmgRefusal::EmptyChunkTable));
}

// ============================================================================
// sortedness / overlap
// ============================================================================

#[test]
fn unsorted_table_refused() {
    // Two chunks out of sector order within one mish.
    let mish = build_mish(
        0,
        0,
        &[
            ChunkSpec::new(CHUNK_ZERO, 100, 4, 0, 0),
            ChunkSpec::new(CHUNK_ZERO, 0, 4, 0, 0),
        ],
    );
    let img = assemble_plist_image(&[mish], 200);
    let mut h = Harness::new();
    assert_eq!(
        unsafe { h.init(&img) },
        Err(DmgRefusal::UnsortedOrOverlapping)
    );
}

#[test]
fn overlapping_table_refused() {
    // Chunk [0,10) then [5,15) overlap.
    let mish = build_mish(
        0,
        0,
        &[
            ChunkSpec::new(CHUNK_ZERO, 0, 10, 0, 0),
            ChunkSpec::new(CHUNK_RAW, 5, 10, 8192, 5120),
        ],
    );
    let img = assemble_plist_image(&[mish], 20);
    let mut h = Harness::new();
    assert_eq!(
        unsafe { h.init(&img) },
        Err(DmgRefusal::UnsortedOrOverlapping)
    );
}

// ============================================================================
// multipart composition
// ============================================================================

#[test]
fn multipart_absolute_sectors() {
    // Two mish blocks; the second uses out_offset to place its chunks
    // after the first. Convert of a multipart image == raw concatenation,
    // so absolute sectors must compose across blocks.
    let m0 = build_mish(
        0,
        0,
        &[
            ChunkSpec::new(CHUNK_ZERO, 0, 4, 0, 0),
            ChunkSpec::new(CHUNK_RAW, 4, 4, 8192, 2048),
        ],
    );
    // Second block's chunks are relative to out_offset=8.
    let m1 = build_mish(8, 0, &[ChunkSpec::new(CHUNK_ZLIB, 0, 8, 16384, 256)]);
    let img = assemble_plist_image(&[m0, m1], 16);
    let mut h = Harness::new();
    let state = unsafe { h.init(&img) }.expect("valid");
    assert_eq!(state.chunk_count, 3);

    // Sector 0..4 zero, 4..8 raw, 8..16 zlib (absolute, via out_offset).
    assert!(matches!(
        unsafe { state.chunk_lookup(0) },
        DmgLookup::Zero { .. }
    ));
    assert!(matches!(
        unsafe { state.chunk_lookup(4) },
        DmgLookup::Raw { .. }
    ));
    match unsafe { state.chunk_lookup(8) } {
        DmgLookup::Zlib {
            chunk_first_sector,
            chunk_sector_count,
            host_offset,
            comp_len,
        } => {
            assert_eq!(chunk_first_sector, 8);
            assert_eq!(chunk_sector_count, 8);
            assert_eq!(host_offset, 16384);
            assert_eq!(comp_len, 256);
        }
        other => panic!("expected zlib, got {other:?}"),
    }
}

// ============================================================================
// resource-fork path
// ============================================================================

#[test]
fn rsrc_fork_path_parses() {
    let mish = build_mish(
        0,
        0,
        &[
            ChunkSpec::new(CHUNK_ZERO, 0, 4, 0, 0),
            ChunkSpec::new(CHUNK_RAW, 4, 4, 8192, 2048),
        ],
    );
    let region = build_rsrc_region(&[mish]);
    let img = assemble_rsrc_image(&region, 8);
    let mut h = Harness::new();
    let state = unsafe { h.init(&img) }.expect("valid rsrc fork");
    assert_eq!(state.chunk_count, 2);
}

#[test]
fn rsrc_fork_malformed_refused() {
    // Corrupt the rsrc_data_offset to exceed the region length.
    let mish = build_mish(0, 0, &[ChunkSpec::new(CHUNK_ZERO, 0, 4, 0, 0)]);
    let mut region = build_rsrc_region(&[mish]);
    let bad_offset = region.len() as u32 + 1;
    write_be_u32(&mut region, 0, bad_offset);
    let img = assemble_rsrc_image(&region, 8);
    let mut h = Harness::new();
    assert_eq!(unsafe { h.init(&img) }, Err(DmgRefusal::RsrcForkMalformed));
}

// ============================================================================
// lookup walks
// ============================================================================

#[test]
fn lookup_zero_raw_zlib_hits_and_spans() {
    // Contiguous zero[0,4) raw[4,8) zlib[8,16).
    let mish = build_mish(
        0,
        0,
        &[
            ChunkSpec::new(CHUNK_ZERO, 0, 4, 0, 0),
            ChunkSpec::new(CHUNK_RAW, 4, 4, 8192, 2048),
            ChunkSpec::new(CHUNK_ZLIB, 8, 8, 16384, 256),
        ],
    );
    let img = assemble_plist_image(&[mish], 16);
    let mut h = Harness::new();
    let state = unsafe { h.init(&img) }.expect("valid");

    // Zero span from sector 1 runs to the chunk end (sector 4): 3 sectors.
    match unsafe { state.chunk_lookup(1) } {
        DmgLookup::Zero { span_sectors } => assert_eq!(span_sectors, 3),
        other => panic!("expected zero, got {other:?}"),
    }
    // Raw at sector 5: host advanced by 1 sector; span 3 to chunk end.
    match unsafe { state.chunk_lookup(5) } {
        DmgLookup::Raw {
            host_offset,
            span_sectors,
        } => {
            assert_eq!(host_offset, 8192 + 512);
            assert_eq!(span_sectors, 3);
        }
        other => panic!("expected raw, got {other:?}"),
    }
    // Zlib at sector 8: whole-chunk bounds reported.
    match unsafe { state.chunk_lookup(8) } {
        DmgLookup::Zlib {
            host_offset,
            comp_len,
            chunk_first_sector,
            chunk_sector_count,
        } => {
            assert_eq!(host_offset, 16384);
            assert_eq!(comp_len, 256);
            assert_eq!(chunk_first_sector, 8);
            assert_eq!(chunk_sector_count, 8);
        }
        other => panic!("expected zlib, got {other:?}"),
    }
}

#[test]
fn lookup_gap_between_chunks() {
    // zero[0,4) then raw[10,14); sectors 4..10 are a gap.
    let mish = build_mish(
        0,
        0,
        &[
            ChunkSpec::new(CHUNK_ZERO, 0, 4, 0, 0),
            ChunkSpec::new(CHUNK_RAW, 10, 4, 8192, 2048),
        ],
    );
    let img = assemble_plist_image(&[mish], 20);
    let mut h = Harness::new();
    let state = unsafe { h.init(&img) }.expect("valid");

    // Sector 5 is in the gap; span runs to the next chunk start (10): 5.
    match unsafe { state.chunk_lookup(5) } {
        DmgLookup::Gap { span_sectors } => assert_eq!(span_sectors, 5),
        other => panic!("expected gap, got {other:?}"),
    }
    // The sector exactly at the end of the first chunk (4) is a gap.
    match unsafe { state.chunk_lookup(4) } {
        DmgLookup::Gap { span_sectors } => assert_eq!(span_sectors, 6),
        other => panic!("expected gap, got {other:?}"),
    }
}

#[test]
fn lookup_tail_gap_to_virtual_end() {
    // One chunk [0,4); virtual disk is 10 sectors (koly SectorCount wins).
    let mish = build_mish(0, 0, &[ChunkSpec::new(CHUNK_ZERO, 0, 4, 0, 0)]);
    let img = assemble_plist_image(&[mish], 10);
    let mut h = Harness::new();
    let state = unsafe { h.init(&img) }.expect("valid");

    // Sector 6 is past the last chunk; span runs to virtual end (10): 4.
    match unsafe { state.chunk_lookup(6) } {
        DmgLookup::Gap { span_sectors } => assert_eq!(span_sectors, 4),
        other => panic!("expected tail gap, got {other:?}"),
    }
}

#[test]
fn lookup_exact_chunk_boundaries() {
    let mish = build_mish(
        0,
        0,
        &[
            ChunkSpec::new(CHUNK_RAW, 0, 4, 4096, 2048),
            ChunkSpec::new(CHUNK_RAW, 4, 4, 8192, 2048),
        ],
    );
    let img = assemble_plist_image(&[mish], 8);
    let mut h = Harness::new();
    let state = unsafe { h.init(&img) }.expect("valid");

    // First sector of the second chunk maps to its base.
    match unsafe { state.chunk_lookup(4) } {
        DmgLookup::Raw {
            host_offset,
            span_sectors,
        } => {
            assert_eq!(host_offset, 8192);
            assert_eq!(span_sectors, 4);
        }
        other => panic!("expected raw, got {other:?}"),
    }
    // Last sector of the first chunk (3) stays in the first chunk.
    match unsafe { state.chunk_lookup(3) } {
        DmgLookup::Raw {
            host_offset,
            span_sectors,
        } => {
            assert_eq!(host_offset, 4096 + 3 * 512);
            assert_eq!(span_sectors, 1);
        }
        other => panic!("expected raw, got {other:?}"),
    }
}

// ============================================================================
// read-failure and arithmetic-overflow refusals (pre-push audit coverage)
//
// These fill in the four DmgRefusal variants the earlier suite did not
// exercise directly: KolyRead, RegionReadFailed, ArithmeticOverflow (several
// call sites), and KolyFieldOutOfRange (a provably-unreachable backstop, so
// its underlying shared-helper contract is pinned instead).
// ============================================================================

#[test]
fn init_koly_read_failure() {
    // A capacity larger than the mock's physical buffer places the koly
    // trailer read past MOCK_LEN, so `read_input_sector` returns false and
    // read_koly attributes KolyRead (distinct from TrailerNotFound, which is
    // a successful read with no koly magic).
    let img = simple_zlib_image();
    let mut h = Harness::new();
    // MOCK_LEN / 512 == 4096 sectors; 5000 forces the last-sector read past
    // the end of the physical mock buffer.
    let r = unsafe { h.init_cap(&img, 5000) };
    assert_eq!(r, Err(DmgRefusal::KolyRead));
}

#[test]
fn init_region_read_failure_mid_parse() {
    // Build a plist image whose <data> region lives in device sector 1 but
    // whose koly sits far later (sector 10). A mock that fails ONLY sector 1
    // lets the koly read (sectors 9 and 10) succeed, then trips when
    // stage_region reads the plist region → RegionReadFailed.
    let mish = build_mish(0, 0, &[ChunkSpec::new(CHUNK_ZLIB, 0, 8, 4096, 100)]);
    let mut xml = String::from("<data>");
    xml.push_str(&base64_encode(&mish));
    xml.push_str("</data>");
    let xml_bytes = xml.into_bytes();
    let xml_offset = 512usize; // sector 1
    let koly_offset = 512 * 10usize; // sector 10, well past the region
    assert!(xml_offset + xml_bytes.len() <= koly_offset);
    let total = koly_offset + 512;
    let mut bytes = std::vec![0u8; total];
    bytes[xml_offset..xml_offset + xml_bytes.len()].copy_from_slice(&xml_bytes);
    let koly = build_koly(&KolySpec {
        magic: true,
        data_fork_offset: 0,
        rsrc_fork_offset: 0,
        rsrc_fork_length: 0,
        xml_offset: xml_offset as u64,
        xml_length: xml_bytes.len() as u64,
        sector_count: 8,
    });
    bytes[koly_offset..koly_offset + 512].copy_from_slice(&koly);
    let mut h = Harness::new();
    assert_eq!(
        unsafe { h.init_failing(&bytes, 1) },
        Err(DmgRefusal::RegionReadFailed)
    );
}

#[test]
fn init_arithmetic_overflow_virtual_size() {
    // koly SectorCount with the top bit clear (so NegativeSectorCount does
    // not fire) but whose `* 512` byte size overflows u64 (lib.rs ~:426).
    let mish = build_mish(0, 0, &[ChunkSpec::new(CHUNK_ZERO, 0, 4, 0, 0)]);
    let img = assemble_plist_image(&[mish], 1u64 << 55);
    let mut h = Harness::new();
    assert_eq!(unsafe { h.init(&img) }, Err(DmgRefusal::ArithmeticOverflow));
}

#[test]
fn init_arithmetic_overflow_sector_plus_out_offset() {
    // A mish out_offset of u64::MAX overflows `sector + out_offset` for a
    // chunk at sector 1 (lib.rs ~:959). The koly SectorCount is small, so
    // the virtual-size multiply (~:426) is not what trips.
    let mish = build_mish(u64::MAX, 0, &[ChunkSpec::new(CHUNK_ZERO, 1, 4, 0, 0)]);
    let img = assemble_plist_image(&[mish], 8);
    let mut h = Harness::new();
    assert_eq!(unsafe { h.init(&img) }, Err(DmgRefusal::ArithmeticOverflow));
}

#[test]
fn init_arithmetic_overflow_host_offset() {
    // mish data_offset and chunk comp_offset each 1<<63 overflow the host
    // offset `comp_offset + in_offset` (lib.rs ~:970). in_offset itself
    // (data_fork_offset 0 + data_offset) does not overflow.
    let mish = build_mish(
        0,
        1u64 << 63,
        &[ChunkSpec::new(CHUNK_ZERO, 0, 4, 1u64 << 63, 0)],
    );
    let img = assemble_plist_image(&[mish], 8);
    let mut h = Harness::new();
    assert_eq!(unsafe { h.init(&img) }, Err(DmgRefusal::ArithmeticOverflow));
}

#[test]
fn init_arithmetic_overflow_data_fork_plus_data_offset() {
    // A koly DataForkOffset of 1 (valid: <= koly offset) plus a mish
    // data_offset of u64::MAX overflows the in_offset base (lib.rs ~:941).
    let mish = build_mish(0, u64::MAX, &[ChunkSpec::new(CHUNK_ZERO, 0, 4, 0, 0)]);
    let mut xml = String::from("<data>");
    xml.push_str(&base64_encode(&mish));
    xml.push_str("</data>");
    let xml_bytes = xml.into_bytes();
    let xml_offset = 512usize;
    let koly_offset = xml_offset + xml_bytes.len();
    let total = koly_offset + 512;
    let mut bytes = std::vec![0u8; total];
    bytes[xml_offset..xml_offset + xml_bytes.len()].copy_from_slice(&xml_bytes);
    let koly = build_koly(&KolySpec {
        magic: true,
        data_fork_offset: 1,
        rsrc_fork_offset: 0,
        rsrc_fork_length: 0,
        xml_offset: xml_offset as u64,
        xml_length: xml_bytes.len() as u64,
        sector_count: 8,
    });
    bytes[koly_offset..koly_offset + 512].copy_from_slice(&koly);
    let mut h = Harness::new();
    assert_eq!(
        unsafe { h.init(&bytes) },
        Err(DmgRefusal::ArithmeticOverflow)
    );
}

#[test]
fn koly_field_out_of_range_shared_helper_contract() {
    // read_koly maps a `parse_dmg_koly` None to DmgRefusal::KolyFieldOutOfRange
    // (lib.rs ~:620). That arm is a defensive backstop that is unreachable
    // through DmgState::init: read_koly always hands parse_dmg_koly a slice
    // that extends a full DMG_KOLY_TRAILER_LEN (512) bytes past the detected
    // koly offset, and detect_dmg_koly_offset only returns an offset <=
    // len - 512, so every koly field is guaranteed in-bounds and the None
    // branch cannot fire. Pin the shared helper's out-of-range contract
    // directly instead: a koly_offset whose trailing SectorCount field would
    // run past the file length yields None. Behaviour pin from the pre-push
    // audit.
    //
    // koly_offset 20 in a 512-byte file pushes SectorCount (@ +0x1ec, 8 bytes
    // => ends at 20 + 0x1ec + 8 = 520) one byte past the 512-byte length.
    let buf = [0u8; 512];
    assert!(shared::format_detection::parse_dmg_koly(&buf, 512, 20).is_none());
    // A well-formed koly_offset (0 in a 512-byte file) parses to Some, so the
    // None above is genuinely the field-out-of-range guard, not a blanket
    // rejection.
    assert!(shared::format_detection::parse_dmg_koly(&buf, 512, 0).is_some());
}
