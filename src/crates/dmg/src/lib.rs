//! DMG (Apple UDIF) format parsing.
//!
//! Provides koly-trailer parsing, chunk-table assembly (from either the
//! XML-plist path or the old resource-fork path), and per-sector chunk
//! lookup for the convert / compare / dd read path. Mirrors qemu's
//! `block/dmg.c` (`dmg_open` + `dmg_read_mish_block` + the plist/resource
//! walks) read-only open-time behaviour, with a small set of deliberate,
//! documented divergences noted inline and summarised here:
//!
//! * **Empty chunk table is a clean refusal.** A valid koly with zero
//!   parsed chunks makes qemu dereference a NULL `sectors[]` and *SIGSEGV
//!   on the first read* (universal, 6.0.0 through host 10.0.11 — an
//!   upstream-report candidate; see [`DmgRefusal::EmptyChunkTable`]).
//!   instar refuses at init instead.
//! * **Unsupported codecs get a typed, code-naming refusal.** qemu drops
//!   ADC / bzip2 / lzfse / zstd / unknown chunk types from the table at
//!   open (leaving gaps that later EIO); instar refuses at init with the
//!   offending u32 in [`DmgRefusal::UnsupportedCodec`]. Both fail convert
//!   with a non-zero exit; instar's failure names the codec and can never
//!   mis-serve a partially-decodable image. (comment `0x7ffffffe` and
//!   terminator `0xffffffff` are still dropped silently, as in qemu.)
//! * **Bounded-memory caps.** The sandbox has a fixed scratch budget, so a
//!   qemu-legal chunk (up to 64 MiB uncompressed + 64 MiB compressed)
//!   cannot always be staged. instar enforces its own caps
//!   ([`DMG_REGION_STAGE_CAP`], [`DMG_MAX_CHUNKS`],
//!   [`DMG_MAX_STAGED_SECTOR_COUNT`], `COMPRESSED_BUF_SIZE`) as refusals
//!   *distinct* from qemu's own caps ([`DMG_LENGTHS_MAX`],
//!   [`DMG_SECTORCOUNTS_MAX`]).
//! * **Sortedness is verified.** qemu binary-searches the table assuming
//!   it is sorted-by-sector and non-overlapping (real images are);
//!   instar verifies this at init and refuses an unsorted/overlapping
//!   table rather than silently returning arbitrary data.
//!
//! The koly window scan and true-file-length recovery are factored into
//! shared helpers (`shared::format_detection::detect_dmg_koly_offset`,
//! `find_last_dmg_koly`, `parse_dmg_koly`) so this crate and the info op's
//! trailer probe share one source of truth for the trailer geometry.
//!
//! Chunk *decompression* (zlib inflate) and the actual byte copies live in
//! the reader arm (guest op, step 5b); this crate only parses metadata and
//! answers span-typed lookups. Codec decode support beyond zlib
//! (bzip2 / lzfse / ADC) is out of scope — the typed refusals above stand
//! in.

#![no_std]
#![allow(clippy::too_many_arguments)]

use shared::format_detection::{
    detect_dmg_koly_offset, find_last_dmg_koly, parse_dmg_koly, DmgKolyTrailer,
    DMG_KOLY_TRAILER_LEN,
};
use shared::{be_u32, be_u64, CallTable, COMPRESSED_BUF_SIZE, MAX_SECTOR_SIZE};

// ============================================================================
// mish / BLKX layout constants (all big-endian)
// ============================================================================

/// mish block magic (`0x6d697368`, `"mish"` big-endian) at block offset 0.
pub const MISH_MAGIC: u32 = 0x6d69_7368;
/// Fixed mish header size in bytes; chunk entries begin here.
pub const MISH_HEADER_LEN: usize = 204;
/// Size of a single 40-byte BE chunk entry.
pub const MISH_ENTRY_LEN: usize = 40;
/// Minimum decoded length qemu accepts as a mish block (`count < 244`
/// skipped): the 204-byte header plus at least one 40-byte entry.
pub const MISH_MIN_LEN: usize = 244;

/// Byte size of a sector (DMG sector counts are always 512-byte).
pub const SECTOR_BYTES: u64 = 512;

// ============================================================================
// Chunk-type codes (BE u32 at each entry's offset 0)
// ============================================================================

/// `UDZE` — all-zero chunk (memset zeros).
pub const CHUNK_ZERO: u32 = 0x0000_0000;
/// `UDRW` — raw/uncompressed chunk (byte copy).
pub const CHUNK_RAW: u32 = 0x0000_0001;
/// `UDIG` — ignore chunk (treated as zeros, same as [`CHUNK_ZERO`]).
pub const CHUNK_IGNORE: u32 = 0x0000_0002;
/// `UDCO` — ADC compression. Unsupported → typed refusal.
pub const CHUNK_ADC: u32 = 0x8000_0004;
/// `UDZO` — zlib (zlib-WRAPPED deflate) compression.
pub const CHUNK_ZLIB: u32 = 0x8000_0005;
/// `UDBZ` — bzip2 compression. Unsupported → typed refusal.
pub const CHUNK_BZIP2: u32 = 0x8000_0006;
/// `ULFO` — lzfse compression. Unsupported → typed refusal.
pub const CHUNK_LZFSE: u32 = 0x8000_0007;
/// zstd compression (unofficial). Unsupported → typed refusal.
pub const CHUNK_ZSTD: u32 = 0x8000_0008;
/// `UDCM` — comment entry; dropped silently (as in qemu).
pub const CHUNK_COMMENT: u32 = 0x7fff_fffe;
/// `UDLE` — last-entry / terminator; dropped silently (as in qemu).
pub const CHUNK_TERMINATOR: u32 = 0xffff_ffff;

// ============================================================================
// qemu's exact per-chunk caps (block/dmg.c `DMG_LENGTHS_MAX`)
// ============================================================================

/// qemu's `DMG_LENGTHS_MAX` — a chunk's compressed length must be
/// `<= 64 MiB` ("length N for chunk C is larger than max (67108864)").
/// Applies to every chunk type.
pub const DMG_LENGTHS_MAX: u64 = 64 * 1024 * 1024;
/// qemu's `DMG_SECTORCOUNTS_MAX` (`DMG_LENGTHS_MAX / 512` = 131072) — a
/// chunk's sector count must be `<= 131072` ("sector count N ... larger
/// than max (131072)"), EXCEPT zero/ignore chunks which are exempt (they
/// are memset, never materialised into a buffer).
pub const DMG_SECTORCOUNTS_MAX: u64 = DMG_LENGTHS_MAX / SECTOR_BYTES;

// ============================================================================
// instar's own bounded-memory caps (documented divergences)
// ============================================================================

/// Max plist / resource-fork region instar stages for parsing: **1 MiB**.
/// Real-world plists are a few KiB; qemu's own cap is 16 MiB. A region
/// over this refuses with [`DmgRefusal::RegionTooLarge`].
pub const DMG_REGION_STAGE_CAP: usize = 1024 * 1024;
/// Max total kept chunk entries: **32768** (~32 GiB of default 1 MiB UDZO
/// coverage; the compact table fits ~1.25 MiB of scratch). Over this
/// refuses with [`DmgRefusal::ChunkTableTooLarge`].
pub const DMG_MAX_CHUNKS: usize = 32768;
/// Max uncompressed sector count for a non-zero/ignore chunk that instar
/// will stage: **4096 sectors (2 MiB, = the staging buffer)**. hdiutil's
/// default UDZO chunking is 1 MiB, so real images fit with 2x headroom.
/// A qemu-legal-but-over-cap chunk refuses with
/// [`DmgRefusal::StagedSectorCountTooLarge`].
pub const DMG_MAX_STAGED_SECTOR_COUNT: u64 = 4096;

// ============================================================================
// Compact chunk record + caller scratch layout
// ============================================================================

/// Size of one packed [`DmgChunk`] record in the caller scratch table.
pub const DMG_CHUNK_RECORD_SIZE: usize = 40;
/// Bytes reserved for the persistent chunk table (`DMG_MAX_CHUNKS` * 40 =
/// 1,310,720 ≈ 1.25 MiB).
pub const DMG_TABLE_REGION: usize = DMG_MAX_CHUNKS * DMG_CHUNK_RECORD_SIZE;
/// Bytes reserved for the base64 decode scratch (a single `<data>` block
/// decodes here at a time; decoded bytes are `<= 3/4` of the staged
/// region, itself capped at [`DMG_REGION_STAGE_CAP`]).
pub const DMG_DECODE_CAP: usize = DMG_REGION_STAGE_CAP;
/// Total caller scratch [`DmgState::init`] requires.
///
/// **Scratch layout** (single region, offsets from the base pointer):
///
/// | range | purpose | lifetime |
/// |-------|---------|----------|
/// | `[0, DMG_TABLE_REGION)` | packed [`DmgChunk`] table | **persistent** (read by [`DmgState::chunk_lookup`]) |
/// | `[DMG_TABLE_REGION, +DMG_REGION_STAGE_CAP)` | staged plist / resource-fork bytes | transient (init only) |
/// | `[…, +DMG_DECODE_CAP)` | base64 decode buffer (plist path) | transient (init only) |
///
/// The table is placed FIRST so the caller need only keep the first
/// `chunk_count * 40` bytes alive for the [`DmgState`] lifetime; the
/// staging/decode suffix is free for reuse once `init` returns. The
/// [`DmgState`] retains a pointer into the table region only.
pub const DMG_REQUIRED_SCRATCH: usize = DMG_TABLE_REGION + DMG_REGION_STAGE_CAP + DMG_DECODE_CAP;

/// Disposition of a kept chunk, stored in the packed table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum DmgChunkKind {
    /// zero (`UDZE`) or ignore (`UDIG`) → serve zeros.
    Zero = 0,
    /// raw (`UDRW`) → byte copy from the data fork.
    Raw = 1,
    /// zlib (`UDZO`) → zlib-wrapped inflate of the whole chunk.
    Zlib = 2,
}

/// One packed chunk-table entry (40 bytes, `#[repr(C)]`).
///
/// All offsets are already *effective* — `first_sector` has the mish
/// `out_offset` folded in, and `host_offset` has the mish `data_offset`
/// and koly `DataForkOffset` folded in — so lookups need no further
/// arithmetic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct DmgChunk {
    /// Absolute (out_offset-adjusted) first virtual sector of the chunk.
    pub first_sector: u64,
    /// Chunk length in sectors.
    pub sector_count: u64,
    /// Effective host byte offset of the chunk's (compressed) data.
    pub host_offset: u64,
    /// Compressed length in bytes (0 for zero/ignore chunks).
    pub comp_len: u64,
    /// Chunk disposition.
    pub kind: DmgChunkKind,
    /// Padding to a 40-byte, 8-aligned record.
    pub _pad: u32,
}

// ============================================================================
// Typed refusal reasons
// ============================================================================

/// Why [`DmgState::init`] refused an image.
///
/// Each variant is a distinct, attributable reason so the reader arm can
/// print a typed message (and so fixtures can pin exact failures). qemu's
/// own caps and instar's bounded-memory caps are separate variants because
/// they are documented divergences with different fixtures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DmgRefusal {
    /// `scratch_len < DMG_REQUIRED_SCRATCH`.
    ScratchTooSmall,
    /// No koly trailer could be located in the device tail.
    TrailerNotFound,
    /// A device read of the koly trailer sector failed.
    KolyRead,
    /// A field of the located koly lies outside the readable tail buffer.
    KolyFieldOutOfRange,
    /// DataForkOffset > koly file offset (qemu `data_fork_offset > offset`).
    BadDataForkOffset,
    /// Resource-fork region out of bounds (qemu
    /// `rsrc_fork_offset >= offset || rsrc_fork_length > offset - rsrc_fork_offset`).
    BadRsrcForkRegion,
    /// XML region out of bounds (qemu
    /// `plist_xml_offset >= offset || plist_xml_length > offset - plist_xml_offset`).
    BadXmlRegion,
    /// SectorCount had its top bit set (qemu `bs->total_sectors < 0`).
    NegativeSectorCount,
    /// Neither a resource-fork nor an XML chunk source was present (qemu
    /// falls through to `-EINVAL`).
    NoChunkSource,
    /// The staged plist / resource-fork region exceeds
    /// [`DMG_REGION_STAGE_CAP`] (instar cap; qemu's is 16 MiB).
    RegionTooLarge,
    /// A device read while staging the plist / resource-fork region failed
    /// (short read past capacity, or the callback returned false).
    RegionReadFailed,
    /// A `<data>` block had no closing `</data>` (qemu "malformed XML"
    /// `-EINVAL`).
    MalformedXml,
    /// The resource-fork walk hit one of qemu's `-EINVAL` structural
    /// checks (bad `rsrc_data_offset`, zero/oversized resource count, a
    /// resource that runs past the staged region).
    RsrcForkMalformed,
    /// A non-zero/ignore chunk's sector count exceeded qemu's
    /// [`DMG_SECTORCOUNTS_MAX`].
    QemuSectorCountTooLarge,
    /// A chunk's compressed length exceeded qemu's [`DMG_LENGTHS_MAX`].
    QemuChunkLengthTooLarge,
    /// The kept chunk count exceeded instar's [`DMG_MAX_CHUNKS`].
    ChunkTableTooLarge,
    /// A non-zero/ignore chunk's sector count exceeded instar's
    /// [`DMG_MAX_STAGED_SECTOR_COUNT`] (the capacity-divergence case).
    StagedSectorCountTooLarge,
    /// A non-zero/ignore chunk's compressed length exceeded instar's
    /// `COMPRESSED_BUF_SIZE`.
    StagedChunkLengthTooLarge,
    /// A chunk carried an unsupported/unknown codec; the u32 is the raw
    /// chunk-type code (ADC / bzip2 / lzfse / zstd / anything else).
    UnsupportedCodec(u32),
    /// The assembled table had zero kept chunks — the qemu-segfault case,
    /// refused cleanly (see the crate docs).
    EmptyChunkTable,
    /// The assembled table was not sorted-by-sector or had overlapping
    /// chunks (qemu binary-searches assuming neither).
    UnsortedOrOverlapping,
    /// Checked arithmetic overflowed while composing an offset/sector.
    ArithmeticOverflow,
}

// ============================================================================
// Chunk lookup result
// ============================================================================

/// Result of [`DmgState::chunk_lookup`]: a span-typed view starting at the
/// queried sector.
///
/// `span_sectors` runs from the queried sector to the end of the
/// containing chunk (for a hit) or to the start of the next chunk / the
/// virtual-disk end (for a [`DmgLookup::Gap`]). The zlib variant reports
/// the whole containing chunk's bounds instead of a span, because the arm
/// must inflate the entire chunk before it can serve the queried sector.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DmgLookup {
    /// Zero/ignore span → write zeros for `span_sectors` sectors.
    Zero { span_sectors: u64 },
    /// Raw span → copy `span_sectors * 512` bytes from `host_offset`
    /// (`host_offset` is already advanced to the queried sector).
    Raw { host_offset: u64, span_sectors: u64 },
    /// Zlib chunk → read `comp_len` bytes at `host_offset`, inflate the
    /// whole chunk (`chunk_sector_count * 512` bytes) and serve from
    /// `(queried_sector - chunk_first_sector)`.
    Zlib {
        host_offset: u64,
        comp_len: u64,
        chunk_first_sector: u64,
        chunk_sector_count: u64,
    },
    /// No chunk covers the queried sector — a hole between chunks or the
    /// koly-SectorCount tail. `span_sectors` runs to the next chunk /
    /// virtual end. The reader arm must EIO (never zero-fill) here.
    Gap { span_sectors: u64 },
}

// ============================================================================
// DmgState
// ============================================================================

/// Runtime state for reading DMG chunks.
///
/// After [`DmgState::init`], the packed chunk table lives in the caller's
/// scratch (see [`DMG_REQUIRED_SCRATCH`]); `table_ptr` points at it. The
/// caller must keep at least the first `chunk_count * 40` bytes of that
/// scratch region valid for the lifetime of this `DmgState`.
///
/// `PartialEq`/`Debug` are derived for test ergonomics; equality includes
/// the raw `table_ptr`, so two states are equal only when they point at
/// the same scratch table.
#[derive(Debug, PartialEq, Eq)]
pub struct DmgState {
    /// Input device index (always 0 today; carried for symmetry).
    pub device_idx: u32,
    /// Virtual disk size in bytes (`SectorCount * 512`, koly-wins).
    pub virtual_size: u64,
    /// Virtual disk size in sectors (koly SectorCount).
    pub virtual_sectors: u64,
    /// Number of kept chunks in the table.
    pub chunk_count: usize,
    /// Pointer to the packed [`DmgChunk`] table in caller scratch.
    table_ptr: *const DmgChunk,
}

/// Accumulates chunk records into the caller scratch, enforcing
/// [`DMG_MAX_CHUNKS`].
struct ChunkBuilder {
    base: *mut DmgChunk,
    count: usize,
}

impl ChunkBuilder {
    /// Append one record. `base` may be unaligned, so writes are unaligned.
    ///
    /// # Safety
    ///
    /// `base` must point at [`DMG_TABLE_REGION`] writable bytes.
    unsafe fn push(&mut self, chunk: DmgChunk) -> Result<(), DmgRefusal> {
        if self.count >= DMG_MAX_CHUNKS {
            return Err(DmgRefusal::ChunkTableTooLarge);
        }
        core::ptr::write_unaligned(self.base.add(self.count), chunk);
        self.count += 1;
        Ok(())
    }
}

/// Read the packed record at `idx` from a (possibly unaligned) table base.
///
/// # Safety
///
/// `base` must point at a table with at least `idx + 1` records.
unsafe fn read_chunk(base: *const DmgChunk, idx: usize) -> DmgChunk {
    core::ptr::read_unaligned(base.add(idx))
}

impl DmgState {
    /// Parse a DMG image's koly trailer and chunk table from a device.
    ///
    /// Recovers the true file length via the shared last-sectors koly
    /// technique (the virtio capacity is sector-rounded-up, so the trailer
    /// sits in the file's final 512 bytes), validates the koly with
    /// qemu's exact field set, stages the plist / resource-fork region
    /// into `scratch` (bounded by [`DMG_REGION_STAGE_CAP`]), parses every
    /// mish block into the packed table, enforces qemu's *and* instar's
    /// per-chunk caps, refuses an empty or unsorted/overlapping table, and
    /// stores `virtual_size = SectorCount * 512`.
    ///
    /// Returns a typed [`DmgRefusal`] for every rejection path.
    ///
    /// # Safety
    ///
    /// `scratch` must point at `scratch_len` writable bytes. `call_table`
    /// must be valid. The first `chunk_count * 40` bytes of `scratch` must
    /// remain valid for the returned state's lifetime.
    pub unsafe fn init(
        call_table: &CallTable,
        device_idx: u32,
        sector_size: usize,
        input_capacity: u64,
        scratch: *mut u8,
        scratch_len: usize,
        bytes_read: &mut u64,
    ) -> Result<Self, DmgRefusal> {
        if scratch_len < DMG_REQUIRED_SCRATCH {
            return Err(DmgRefusal::ScratchTooSmall);
        }

        // Carve the scratch into its three sub-regions (see the layout
        // table on DMG_REQUIRED_SCRATCH).
        let table_base = scratch as *mut DmgChunk;
        let stage_ptr = scratch.add(DMG_TABLE_REGION);
        let decode_ptr = scratch.add(DMG_TABLE_REGION + DMG_REGION_STAGE_CAP);
        let stage = core::slice::from_raw_parts_mut(stage_ptr, DMG_REGION_STAGE_CAP);
        let decode = core::slice::from_raw_parts_mut(decode_ptr, DMG_DECODE_CAP);

        // 1. koly trailer + true file length.
        let trailer = read_koly(
            call_table,
            device_idx,
            sector_size,
            input_capacity,
            bytes_read,
        )?;

        // qemu's exact koly validation, one typed refusal per check.
        let koly_off = trailer.koly_offset;
        if trailer.data_fork_offset > koly_off {
            return Err(DmgRefusal::BadDataForkOffset);
        }
        if trailer.rsrc_fork_offset >= koly_off
            || trailer.rsrc_fork_length > koly_off - trailer.rsrc_fork_offset
        {
            return Err(DmgRefusal::BadRsrcForkRegion);
        }
        if trailer.xml_offset >= koly_off || trailer.xml_length > koly_off - trailer.xml_offset {
            return Err(DmgRefusal::BadXmlRegion);
        }
        if trailer.sector_count_raw & (1u64 << 63) != 0 {
            return Err(DmgRefusal::NegativeSectorCount);
        }
        let virtual_sectors = trailer.sector_count_raw;
        let virtual_size = virtual_sectors
            .checked_mul(SECTOR_BYTES)
            .ok_or(DmgRefusal::ArithmeticOverflow)?;

        // 2. Assemble the chunk table from whichever source qemu selects.
        let mut builder = ChunkBuilder {
            base: table_base,
            count: 0,
        };
        if trailer.rsrc_fork_length != 0 {
            parse_resource_fork(
                call_table,
                device_idx,
                sector_size,
                input_capacity,
                &trailer,
                stage,
                &mut builder,
                bytes_read,
            )?;
        } else if trailer.xml_length != 0 {
            parse_plist(
                call_table,
                device_idx,
                sector_size,
                input_capacity,
                &trailer,
                stage,
                decode,
                &mut builder,
                bytes_read,
            )?;
        } else {
            return Err(DmgRefusal::NoChunkSource);
        }

        // 3. Empty table → the qemu-segfault case, refused cleanly.
        if builder.count == 0 {
            return Err(DmgRefusal::EmptyChunkTable);
        }

        // 4. Sorted-by-sector + non-overlapping (qemu assumes both).
        verify_sorted(table_base, builder.count)?;

        Ok(DmgState {
            device_idx,
            virtual_size,
            virtual_sectors,
            chunk_count: builder.count,
            table_ptr: table_base as *const DmgChunk,
        })
    }

    /// Look up the chunk covering `sector`, returning a span-typed result.
    ///
    /// Binary-searches the sorted, non-overlapping table. A hit inside a
    /// chunk returns the [`DmgLookup`] for its type with the span to the
    /// chunk's end (zlib returns the whole chunk's bounds). A miss returns
    /// [`DmgLookup::Gap`] with the span to the next chunk's first sector,
    /// or to `virtual_sectors` (the koly-SectorCount tail) if none
    /// follows.
    ///
    /// # Safety
    ///
    /// The scratch table region established by [`DmgState::init`] must
    /// still be valid.
    pub unsafe fn chunk_lookup(&self, sector: u64) -> DmgLookup {
        let n = self.chunk_count;

        // upper_bound: first index whose first_sector > sector.
        let mut lo = 0usize;
        let mut hi = n;
        while lo < hi {
            let mid = lo + (hi - lo) / 2;
            let c = read_chunk(self.table_ptr, mid);
            if c.first_sector <= sector {
                lo = mid + 1;
            } else {
                hi = mid;
            }
        }

        // Candidate containing chunk is lo-1 (the last with first_sector <= sector).
        if lo > 0 {
            let c = read_chunk(self.table_ptr, lo - 1);
            let end = c.first_sector.saturating_add(c.sector_count);
            if sector < end {
                let span = end - sector;
                return match c.kind {
                    DmgChunkKind::Zero => DmgLookup::Zero { span_sectors: span },
                    DmgChunkKind::Raw => {
                        let delta = sector
                            .saturating_sub(c.first_sector)
                            .saturating_mul(SECTOR_BYTES);
                        DmgLookup::Raw {
                            host_offset: c.host_offset.saturating_add(delta),
                            span_sectors: span,
                        }
                    }
                    DmgChunkKind::Zlib => DmgLookup::Zlib {
                        host_offset: c.host_offset,
                        comp_len: c.comp_len,
                        chunk_first_sector: c.first_sector,
                        chunk_sector_count: c.sector_count,
                    },
                };
            }
        }

        // Gap: span to the next chunk's start, clamped to the virtual end.
        let next_start = if lo < n {
            read_chunk(self.table_ptr, lo).first_sector
        } else {
            self.virtual_sectors
        };
        let ceil = if next_start > self.virtual_sectors {
            self.virtual_sectors
        } else {
            next_start
        };
        DmgLookup::Gap {
            span_sectors: ceil.saturating_sub(sector),
        }
    }
}

// ============================================================================
// koly trailer read (true-length recovery + shared-helper validation)
// ============================================================================

/// Read the last one or two device sectors, locate the real koly trailer,
/// and extract its fields via the shared helpers.
///
/// `#[inline(never)]` with its own large tail buffer so a caller's stack
/// frame stays small (guest codegen is sensitive to oversized inlined
/// frames under `opt-level=z` + LTO — the same reason the info op's
/// `probe_dmg_trailer` is out-of-lined).
///
/// # Safety
///
/// `call_table` must be valid.
#[inline(never)]
unsafe fn read_koly(
    call_table: &CallTable,
    device_idx: u32,
    sector_size: usize,
    input_capacity: u64,
    bytes_read: &mut u64,
) -> Result<DmgKolyTrailer, DmgRefusal> {
    if input_capacity == 0 {
        return Err(DmgRefusal::TrailerNotFound);
    }

    // Read the last one or two device sectors into a contiguous buffer so a
    // koly straddling the final sector boundary is fully covered.
    let mut tail = [0u8; 2 * MAX_SECTOR_SIZE];
    let sectors_to_read = if input_capacity >= 2 { 2 } else { 1 };
    let base_sector = input_capacity - sectors_to_read;
    let base = base_sector
        .checked_mul(sector_size as u64)
        .ok_or(DmgRefusal::ArithmeticOverflow)?;
    let mut tail_len = 0usize;
    for i in 0..sectors_to_read {
        let off = i as usize * sector_size;
        if !(call_table.read_input_sector)(
            device_idx,
            base_sector + i,
            tail[off..].as_mut_ptr(),
            sector_size,
        ) {
            return Err(DmgRefusal::KolyRead);
        }
        *bytes_read += sector_size as u64;
        tail_len = off + sector_size;
    }
    let tail = &tail[..tail_len];

    // Find the LAST koly (the real trailer — the tail after it is virtio
    // zero-fill) and recover the true file length.
    let idx = find_last_dmg_koly(tail).ok_or(DmgRefusal::TrailerNotFound)?;
    if idx + DMG_KOLY_TRAILER_LEN > tail_len {
        return Err(DmgRefusal::TrailerNotFound);
    }
    let koly_abs = base
        .checked_add(idx as u64)
        .ok_or(DmgRefusal::ArithmeticOverflow)?;
    let real_len = koly_abs
        .checked_add(DMG_KOLY_TRAILER_LEN as u64)
        .ok_or(DmgRefusal::ArithmeticOverflow)?;

    // Slicing to end exactly at real_len makes the shared helpers'
    // buffer_base map back to `base`, reproducing qemu's window scan.
    let slice = &tail[..idx + DMG_KOLY_TRAILER_LEN];
    let koly_off =
        detect_dmg_koly_offset(slice, real_len as usize).ok_or(DmgRefusal::TrailerNotFound)?;
    parse_dmg_koly(slice, real_len as usize, koly_off).ok_or(DmgRefusal::KolyFieldOutOfRange)
}

// ============================================================================
// Region staging (device byte-range → scratch buffer)
// ============================================================================

/// Copy `len` bytes starting at device byte offset `start_byte` into `dst`.
///
/// Reads sector-by-sector (each covering sector once). Returns
/// [`DmgRefusal::RegionReadFailed`] if any sector lies past capacity or the
/// device read fails.
///
/// # Safety
///
/// `call_table` must be valid; `dst` must have at least `len` bytes.
#[inline(never)]
unsafe fn stage_region(
    call_table: &CallTable,
    device_idx: u32,
    sector_size: usize,
    input_capacity: u64,
    start_byte: u64,
    len: usize,
    dst: &mut [u8],
    bytes_read: &mut u64,
) -> Result<(), DmgRefusal> {
    if len > dst.len() {
        return Err(DmgRefusal::RegionReadFailed);
    }
    let mut tmp = [0u8; MAX_SECTOR_SIZE];
    let mut copied = 0usize;
    while copied < len {
        let abs = start_byte
            .checked_add(copied as u64)
            .ok_or(DmgRefusal::ArithmeticOverflow)?;
        let sector = abs / sector_size as u64;
        let within = (abs % sector_size as u64) as usize;
        if sector >= input_capacity {
            return Err(DmgRefusal::RegionReadFailed);
        }
        if !(call_table.read_input_sector)(device_idx, sector, tmp.as_mut_ptr(), sector_size) {
            return Err(DmgRefusal::RegionReadFailed);
        }
        *bytes_read += sector_size as u64;
        let n = core::cmp::min(sector_size - within, len - copied);
        dst[copied..copied + n].copy_from_slice(&tmp[within..within + n]);
        copied += n;
    }
    Ok(())
}

// ============================================================================
// Plist path: <data>…</data> string scan + lenient base64 + mish
// ============================================================================

/// Stage the XML plist region and parse every `<data>` block into chunks.
///
/// # Safety
///
/// `call_table` must be valid; the builder base must have room for
/// [`DMG_TABLE_REGION`].
unsafe fn parse_plist(
    call_table: &CallTable,
    device_idx: u32,
    sector_size: usize,
    input_capacity: u64,
    trailer: &DmgKolyTrailer,
    stage: &mut [u8],
    decode: &mut [u8],
    builder: &mut ChunkBuilder,
    bytes_read: &mut u64,
) -> Result<(), DmgRefusal> {
    let xml_len = trailer.xml_length;
    if xml_len > DMG_REGION_STAGE_CAP as u64 {
        return Err(DmgRefusal::RegionTooLarge);
    }
    let xml_len = xml_len as usize;
    stage_region(
        call_table,
        device_idx,
        sector_size,
        input_capacity,
        trailer.xml_offset,
        xml_len,
        stage,
        bytes_read,
    )?;
    let plist = &stage[..xml_len];

    // Scan for <data>…</data> exactly as qemu strstr's them.
    let mut pos = 0usize;
    while let Some(rel) = find_subslice(&plist[pos..], b"<data>") {
        let content_start = pos + rel + b"<data>".len();
        let close = match find_subslice(&plist[content_start..], b"</data>") {
            Some(r) => content_start + r,
            None => return Err(DmgRefusal::MalformedXml),
        };
        let content = &plist[content_start..close];
        let decoded_len = glib_base64_decode(content, decode);
        parse_mish_block(&decode[..decoded_len], trailer.data_fork_offset, builder)?;
        // qemu resumes strstr right after the '<' of the closing tag.
        pos = close + 1;
    }
    Ok(())
}

/// Find the first occurrence of `needle` in `hay`.
fn find_subslice(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() {
        return Some(0);
    }
    if hay.len() < needle.len() {
        return None;
    }
    let mut i = 0usize;
    let last = hay.len() - needle.len();
    while i <= last {
        if &hay[i..i + needle.len()] == needle {
            return Some(i);
        }
        i += 1;
    }
    None
}

/// glib `mime_base64_rank`: base64 value of `c`, or `0xff` for a character
/// outside the alphabet (skipped). `'='` ranks 0 (like `'A'`) and is
/// distinguished from data only via the padding tracking in
/// [`glib_base64_decode`].
fn base64_rank(c: u8) -> u8 {
    match c {
        b'A'..=b'Z' => c - b'A',
        b'a'..=b'z' => c - b'a' + 26,
        b'0'..=b'9' => c - b'0' + 52,
        b'+' => 62,
        b'/' => 63,
        b'=' => 0,
        _ => 0xff,
    }
}

/// Decode base64 with glib's `g_base64_decode` semantics into `out`.
///
/// LENIENT, byte-for-byte with glib: characters outside the base64
/// alphabet (whitespace, newlines, punctuation, anything) are skipped
/// rather than erroring; complete 4-symbol groups emit 1–3 bytes with
/// `'='` padding suppressing the trailing byte(s); a trailing partial
/// group is discarded. Garbage input yields garbage bytes, never an error
/// — parity requires decoding exactly the images qemu decodes. Returns the
/// number of bytes written (clamped to `out.len()`; the caller sizes
/// `out` at [`DMG_DECODE_CAP`], which always suffices).
// `last0`/`last1` are a two-slot shift register of the most recent symbols
// (glib's `last[2]`); their zero initialisers are always overwritten by the
// `last1 = last0` shift before any read, which the unused_assignments lint
// flags — the shift-register idiom is intentional, so allow it here.
#[allow(unused_assignments)]
fn glib_base64_decode(input: &[u8], out: &mut [u8]) -> usize {
    let mut state = 0i32; // count of accumulated symbols mod 4
    let mut v: u32 = 0;
    let mut last0 = 0u8;
    let mut last1 = 0u8;
    let mut outpos = 0usize;
    for &c in input {
        let rank = base64_rank(c);
        if rank == 0xff {
            continue;
        }
        last1 = last0;
        last0 = c;
        v = (v << 6) | rank as u32;
        state += 1;
        if state == 4 {
            if outpos < out.len() {
                out[outpos] = (v >> 16) as u8;
            }
            outpos += 1;
            if last1 != b'=' {
                if outpos < out.len() {
                    out[outpos] = (v >> 8) as u8;
                }
                outpos += 1;
            }
            if last0 != b'=' {
                if outpos < out.len() {
                    out[outpos] = v as u8;
                }
                outpos += 1;
            }
            state = 0;
        }
    }
    core::cmp::min(outpos, out.len())
}

// ============================================================================
// Resource-fork path
// ============================================================================

/// Stage the resource-fork region and walk its `[u32 size][mish]`
/// resources, modelled on qemu's `dmg_read_resource_fork`.
///
/// # Safety
///
/// `call_table` must be valid.
unsafe fn parse_resource_fork(
    call_table: &CallTable,
    device_idx: u32,
    sector_size: usize,
    input_capacity: u64,
    trailer: &DmgKolyTrailer,
    stage: &mut [u8],
    builder: &mut ChunkBuilder,
    bytes_read: &mut u64,
) -> Result<(), DmgRefusal> {
    let region_len = trailer.rsrc_fork_length;
    if region_len > DMG_REGION_STAGE_CAP as u64 {
        return Err(DmgRefusal::RegionTooLarge);
    }
    let region_len = region_len as usize;
    stage_region(
        call_table,
        device_idx,
        sector_size,
        input_capacity,
        trailer.rsrc_fork_offset,
        region_len,
        stage,
        bytes_read,
    )?;
    let region = &stage[..region_len];

    // rsrc_data_offset (u32 @0), resource-data length (u32 @8). All offsets
    // below are relative to the region start (qemu's info_begin).
    if region.len() < 12 {
        return Err(DmgRefusal::RsrcForkMalformed);
    }
    let rsrc_data_offset = be_u32(region, 0) as usize;
    if rsrc_data_offset as u64 > region_len as u64 {
        return Err(DmgRefusal::RsrcForkMalformed);
    }
    let count = be_u32(region, 8) as usize;
    // count == 0 || rsrc_data_offset + count > info_length.
    let data_end = rsrc_data_offset
        .checked_add(count)
        .ok_or(DmgRefusal::RsrcForkMalformed)?;
    if count == 0 || data_end > region_len {
        return Err(DmgRefusal::RsrcForkMalformed);
    }

    // Walk the resources: [u32 size][size bytes of mish].
    let mut offset = rsrc_data_offset;
    while offset < data_end {
        if offset + 4 > region.len() {
            return Err(DmgRefusal::RsrcForkMalformed);
        }
        let size = be_u32(region, offset) as usize;
        // size == 0 || size > info_end - offset (offset before the +=4).
        if size == 0 || size as u64 > (data_end - offset) as u64 {
            return Err(DmgRefusal::RsrcForkMalformed);
        }
        offset += 4;
        let mish_end = offset
            .checked_add(size)
            .ok_or(DmgRefusal::RsrcForkMalformed)?;
        if mish_end > region.len() {
            return Err(DmgRefusal::RsrcForkMalformed);
        }
        parse_mish_block(&region[offset..mish_end], trailer.data_fork_offset, builder)?;
        offset = mish_end;
    }
    Ok(())
}

// ============================================================================
// mish block → chunk entries
// ============================================================================

/// Classify a raw chunk-type code.
///
/// `Ok(Some(kind))` keeps the chunk, `Ok(None)` drops it silently
/// (comment / terminator, as in qemu), `Err(UnsupportedCodec)` refuses a
/// codec instar does not decode (ADC / bzip2 / lzfse / zstd / unknown) —
/// the deliberate divergence from qemu's drop-at-open.
fn classify_chunk_type(ctype: u32) -> Result<Option<DmgChunkKind>, DmgRefusal> {
    match ctype {
        CHUNK_ZERO | CHUNK_IGNORE => Ok(Some(DmgChunkKind::Zero)),
        CHUNK_RAW => Ok(Some(DmgChunkKind::Raw)),
        CHUNK_ZLIB => Ok(Some(DmgChunkKind::Zlib)),
        CHUNK_COMMENT | CHUNK_TERMINATOR => Ok(None),
        other => Err(DmgRefusal::UnsupportedCodec(other)),
    }
}

/// Parse one decoded/raw mish block, appending its kept chunks.
///
/// Mirrors qemu's `dmg_read_mish_block`: a block whose magic is wrong or
/// whose length is `< 244` is silently skipped (not an error). Effective
/// sector = `sector + out_offset`; effective host offset =
/// `comp_offset + data_offset + DataForkOffset`. qemu's caps are enforced
/// first (so an over-qemu-cap chunk attributes to the qemu variant), then
/// instar's tighter bounded-memory caps.
///
/// # Safety
///
/// The builder base must have room for [`DMG_TABLE_REGION`].
unsafe fn parse_mish_block(
    mish: &[u8],
    data_fork_offset: u64,
    builder: &mut ChunkBuilder,
) -> Result<(), DmgRefusal> {
    let count = mish.len();
    // qemu: skip data that is not a valid mish block (bad magic or too small).
    if count < MISH_MIN_LEN || be_u32(mish, 0) != MISH_MAGIC {
        return Ok(());
    }

    let out_offset = be_u64(mish, 8);
    let data_offset = be_u64(mish, 0x18);
    let in_offset = data_fork_offset
        .checked_add(data_offset)
        .ok_or(DmgRefusal::ArithmeticOverflow)?;

    let chunk_count = (count - MISH_HEADER_LEN) / MISH_ENTRY_LEN;
    let mut off = MISH_HEADER_LEN;
    for _ in 0..chunk_count {
        let ctype = be_u32(mish, off);
        let kind = match classify_chunk_type(ctype)? {
            Some(k) => k,
            None => {
                // comment / terminator dropped silently.
                off += MISH_ENTRY_LEN;
                continue;
            }
        };
        let is_zeroish = kind == DmgChunkKind::Zero;

        let sector = be_u64(mish, off + 8)
            .checked_add(out_offset)
            .ok_or(DmgRefusal::ArithmeticOverflow)?;
        let sector_count = be_u64(mish, off + 0x10);

        // qemu's sector cap (zero/ignore exempt) — checked before instar's.
        if !is_zeroish && sector_count > DMG_SECTORCOUNTS_MAX {
            return Err(DmgRefusal::QemuSectorCountTooLarge);
        }

        let comp_offset = be_u64(mish, off + 0x18);
        let host_offset = comp_offset
            .checked_add(in_offset)
            .ok_or(DmgRefusal::ArithmeticOverflow)?;
        let comp_len = be_u64(mish, off + 0x20);

        // qemu's length cap (all types) — checked before instar's.
        if comp_len > DMG_LENGTHS_MAX {
            return Err(DmgRefusal::QemuChunkLengthTooLarge);
        }

        // instar's bounded-memory caps (non-zero/ignore only).
        if !is_zeroish {
            if sector_count > DMG_MAX_STAGED_SECTOR_COUNT {
                return Err(DmgRefusal::StagedSectorCountTooLarge);
            }
            if comp_len > COMPRESSED_BUF_SIZE as u64 {
                return Err(DmgRefusal::StagedChunkLengthTooLarge);
            }
        }

        builder.push(DmgChunk {
            first_sector: sector,
            sector_count,
            host_offset,
            comp_len,
            kind,
            _pad: 0,
        })?;
        off += MISH_ENTRY_LEN;
    }
    Ok(())
}

// ============================================================================
// Sortedness / non-overlap verification
// ============================================================================

/// Verify the assembled table is sorted-by-first-sector and non-overlapping.
///
/// qemu's `search_chunk` binary-searches assuming both hold; a violation
/// would let a lookup return arbitrary data, so instar refuses instead.
///
/// # Safety
///
/// `base` must point at a table of at least `count` records.
unsafe fn verify_sorted(base: *const DmgChunk, count: usize) -> Result<(), DmgRefusal> {
    for i in 1..count {
        let prev = read_chunk(base, i - 1);
        let cur = read_chunk(base, i);
        let prev_end = prev
            .first_sector
            .checked_add(prev.sector_count)
            .ok_or(DmgRefusal::ArithmeticOverflow)?;
        // A start below the previous chunk's end is either unsorted
        // (cur.first_sector < prev.first_sector <= prev_end) or overlapping.
        if cur.first_sector < prev_end {
            return Err(DmgRefusal::UnsortedOrOverlapping);
        }
    }
    Ok(())
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
extern crate std;

#[cfg(test)]
mod tests;
