//! Guest-side literal executor for `qcow2-write` step programs.
//!
//! The production counterpart of the pure planner in
//! `crates/qcow2-write`, built to the settled decisions 1-2 of
//! `docs/plans/PLAN-qcow2-write-infrastructure-phase-04-commit.md`
//! (shared by the phase 4-6 op migrations). Where the planner is
//! I/O-free and address-free (qcow2-write decision 3), this crate
//! owns the other half of the split:
//!
//! - **(a) the `RegionId` → slice mapping** — [`Regions`] wraps
//!   the caller-carved staging slices (scratch-address carved by
//!   the op, never `static` — the `.bss`/HEADER_MISMATCH hazard
//!   class) and resolves every region reference with typed
//!   bounds checks.
//! - **(b) the `TargetDevice` → call-table mapping** —
//!   [`DeviceIo`] with the [`CallTableIo`] implementation
//!   (`Input0` → `read/write_input_sector(0, ..)` +
//!   `fsync_input(0)`; `Output` → `read/write_output_sector`, no
//!   fsync primitive). Host unit tests supply a mock
//!   implementation instead of a real `CallTable` (the
//!   `crates/qcow2` mock-call-table precedent).
//! - **(c) the byte-range layer** over the strictly
//!   sector-addressed call table — [`read_bytes`] /
//!   [`write_bytes`] / [`fill_bytes`] do the sector split plus
//!   sub-sector read-modify-write through a caller-provided
//!   bounce sector. This is the shared replacement for the
//!   per-op helpers commit/rebase/bench/bitmap each hand-roll
//!   today (e.g. `read/write_output_byte_range` in
//!   `src/operations/commit/src/main.rs` and
//!   `write_input_byte_range` in
//!   `src/operations/bench/src/main.rs`), byte-exact to their
//!   semantics.
//! - **(d) fill synthesis** for [`StepKind::ZeroRange`] /
//!   [`StepKind::FillRange`] via a caller-provided fill sector
//!   (bench's `WRITE_ZERO_SECTOR` / `WRITE_PATTERN_SECTOR`
//!   pattern).
//! - **(e) barrier policy** — all guest I/O is synchronous
//!   (issue order == completion order,
//!   `src/core/src/virtio.rs`), so
//!   [`BarrierClass::Ordering`] is a no-op and
//!   [`BarrierClass::Durability`] maps to `fsync_input(0)` on an
//!   fsync-capable `Input0` and degrades to `Ordering` where no
//!   fsync primitive exists (qcow2-write decision 4; phase-4
//!   divergence D8 accepts the degradation on `Output`). A
//!   degraded barrier succeeds; an fsync that runs and reports
//!   failure is an [`ExecError`].
//!
//! [`execute`] is a LITERAL interpreter of the [`StepKind`] doc
//! contracts: zero planning logic, zero classification, zero
//! allocation decisions. Every region access is bounds-checked
//! into a typed [`ExecError`] — this code runs in a guest whose
//! panic handler is `loop {}`, so refusing beats panicking.

#![no_std]

pub mod growth;

use qcow2_write::{BarrierClass, RegionId, Step, StepKind, TargetDevice};
use shared::CallTable;

// ---------------------------------------------------------------------------
// Errors and stats
// ---------------------------------------------------------------------------

/// Typed cause of a failed [`execute`] step (or byte-range call).
///
/// The `u32` codes ([`Self::code`]) are stable for host/op result
/// rendering, in the same style as `qcow2_write::WriteError::code`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecCause {
    /// A device sector read returned failure (including the
    /// hidden covering-sector reads of sub-sector RMW). Code 1.
    ReadFailed,
    /// A device sector write returned failure. Code 2.
    WriteFailed,
    /// A [`BarrierClass::Durability`] fsync ran and reported
    /// failure (a degraded barrier never fails — see the crate
    /// docs, policy (e)). Code 3.
    FsyncFailed,
    /// A region access fell outside the named region's bounds
    /// (for [`RegionId::L2Slot`], outside the slot's
    /// cluster-sized window). Code 4.
    RegionBounds,
    /// A [`RegionId::L2Slot`] index at or beyond the staged
    /// window's slot count. Code 5.
    UnknownSlot,
    /// The [`Regions`] geometry or service buffers cannot support
    /// the step: zero `cluster_size` on an L2-slot access, an
    /// `l2_window` that is not a whole number of cluster-sized
    /// slots, a zero device sector size, or an RMW/fill sector
    /// smaller than the device's sector size. Code 6.
    Geometry,
    /// Offset arithmetic overflowed. Code 7.
    Overflow,
    /// A malformed step violated its [`StepKind`] doc contract
    /// (a [`StepKind::LoadCluster`] / [`StepKind::WritebackCluster`]
    /// whose `len` is not exactly one cluster). Code 8.
    StepContract,
}

impl ExecCause {
    /// Stable code for host/op result rendering (see the variant
    /// docs).
    pub const fn code(self) -> u32 {
        match self {
            ExecCause::ReadFailed => 1,
            ExecCause::WriteFailed => 2,
            ExecCause::FsyncFailed => 3,
            ExecCause::RegionBounds => 4,
            ExecCause::UnknownSlot => 5,
            ExecCause::Geometry => 6,
            ExecCause::Overflow => 7,
            ExecCause::StepContract => 8,
        }
    }
}

/// A failed [`execute`]: which step failed and why.
///
/// `step_index` is the zero-based index into the `steps` window
/// passed to [`execute`]. Steps before it executed fully; the
/// failing step may have partially executed (a multi-sector
/// transfer fails mid-loop; the call table gives no rollback).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExecError {
    /// Zero-based index of the failing step within the window.
    pub step_index: usize,
    /// Typed cause.
    pub cause: ExecCause,
}

/// Accounting from a completed [`execute`] window (op result
/// accounting / debug).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ExecStats {
    /// Steps executed (equals the window length on success).
    pub steps_executed: u64,
    /// Durability barriers that performed a real fsync (degraded
    /// barriers are not counted).
    pub fsyncs: u64,
}

// ---------------------------------------------------------------------------
// Device access (decision 2(b))
// ---------------------------------------------------------------------------

/// Per-[`TargetDevice`] sector-addressed I/O.
///
/// The executor's device dimension: implemented by
/// [`CallTableIo`] in the guest and by Vec-backed mocks in host
/// unit tests (the `crates/qcow2` mock-call-table precedent).
/// All call-table I/O is strictly sector-addressed — one whole
/// sector per call — and synchronous; this trait mirrors that
/// exactly rather than hiding it.
pub trait DeviceIo {
    /// Sector size of `device` in bytes (nonzero on a healthy
    /// device; the byte-range layer refuses zero as
    /// [`ExecCause::Geometry`]).
    fn sector_size(&self, device: TargetDevice) -> usize;

    /// Read one whole sector. `buf.len()` must equal
    /// [`Self::sector_size`] for `device`. Returns `true` on
    /// success.
    fn read_sector(&mut self, device: TargetDevice, sector: u64, buf: &mut [u8]) -> bool;

    /// Write one whole sector. `buf.len()` must equal
    /// [`Self::sector_size`] for `device`. Returns `true` on
    /// success.
    fn write_sector(&mut self, device: TargetDevice, sector: u64, buf: &[u8]) -> bool;

    /// Make `device` durable, if it has an fsync primitive:
    /// `None` means no capability (a Durability barrier degrades
    /// to Ordering — decision 2(e)); `Some(ok)` reports the
    /// fsync's outcome.
    fn fsync(&mut self, device: TargetDevice) -> Option<bool>;
}

/// [`DeviceIo`] over the core-provided [`CallTable`] (the guest
/// production implementation).
///
/// Maps `Input0` to `read_input_sector(0, ..)` /
/// `write_input_sector(0, ..)` / `fsync_input(0)` and `Output`
/// to `read_output_sector` / `write_output_sector` with no fsync
/// primitive (the call table exposes only `fsync_input`;
/// `fsync_output` is recorded future work the phase 4-5
/// migrations must not take implicitly).
pub struct CallTableIo<'a> {
    call_table: &'a CallTable,
    input_sector_size: usize,
    output_sector_size: usize,
    input_fsync: bool,
}

impl<'a> CallTableIo<'a> {
    /// Wrap a validated call table, caching both sector sizes.
    ///
    /// `input_fsync` declares whether input slot 0 was opened RW
    /// by the host (the host-side `fsync_input` stub returns
    /// `false` for read-only slots, so advertising the capability
    /// on a read-only slot would turn every Durability barrier
    /// into a spurious [`ExecCause::FsyncFailed`]).
    ///
    /// # Safety
    ///
    /// `call_table` must be the core-provided call table (magic
    /// and version verified by the op) with every function
    /// pointer valid for the lifetime `'a`; the sector-size
    /// queries are performed here and the I/O entry points are
    /// called later through the safe [`DeviceIo`] methods on the
    /// strength of this contract.
    pub unsafe fn new(call_table: &'a CallTable, input_fsync: bool) -> CallTableIo<'a> {
        CallTableIo {
            call_table,
            input_sector_size: (call_table.get_input_sector_size)(0),
            output_sector_size: (call_table.get_output_sector_size)(),
            input_fsync,
        }
    }
}

impl DeviceIo for CallTableIo<'_> {
    fn sector_size(&self, device: TargetDevice) -> usize {
        match device {
            TargetDevice::Input0 => self.input_sector_size,
            TargetDevice::Output => self.output_sector_size,
        }
    }

    fn read_sector(&mut self, device: TargetDevice, sector: u64, buf: &mut [u8]) -> bool {
        if buf.len() != self.sector_size(device) {
            return false;
        }
        // SAFETY: the `CallTableIo::new` contract guarantees the
        // function pointers are valid; `buf` is a live slice of
        // exactly one device sector.
        unsafe {
            match device {
                TargetDevice::Input0 => {
                    (self.call_table.read_input_sector)(0, sector, buf.as_mut_ptr(), buf.len())
                }
                TargetDevice::Output => {
                    (self.call_table.read_output_sector)(sector, buf.as_mut_ptr(), buf.len())
                }
            }
        }
    }

    fn write_sector(&mut self, device: TargetDevice, sector: u64, buf: &[u8]) -> bool {
        if buf.len() != self.sector_size(device) {
            return false;
        }
        // SAFETY: as for `read_sector`.
        unsafe {
            match device {
                TargetDevice::Input0 => {
                    (self.call_table.write_input_sector)(0, sector, buf.as_ptr(), buf.len())
                }
                TargetDevice::Output => {
                    (self.call_table.write_output_sector)(sector, buf.as_ptr(), buf.len())
                }
            }
        }
    }

    fn fsync(&mut self, device: TargetDevice) -> Option<bool> {
        match device {
            TargetDevice::Input0 if self.input_fsync => {
                // SAFETY: as for `read_sector`.
                Some(unsafe { (self.call_table.fsync_input)(0) })
            }
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// Region mapping (decision 2(a))
// ---------------------------------------------------------------------------

/// The executor's `RegionId` → slice mapping plus its service
/// buffers, all carved by the op from scratch addresses and lent
/// per window (decision 2(a): never `static`).
///
/// The six region slices are the exact buffers the planner's
/// [`qcow2_write::StagedRegions`] views alias (same carve, other
/// half of the decision-1 loop); everything is `&mut` — the
/// union of the [`StepKind`] contracts writes into every region
/// kind (`PatchEntryU64` into L1/L2 slots, `LoadCluster` /
/// `ReadCluster` into their targets, and read-only uses don't
/// need the distinction).
///
/// The two service buffers are the executor's own (decision
/// 2(c)-(d)): `rmw_sector` is the sub-sector RMW bounce and
/// `fill_sector` synthesises `ZeroRange` / `FillRange` bytes.
/// Each must be at least the sector size of every device the
/// window touches (byte-range calls refuse shorter ones as
/// [`ExecCause::Geometry`]). One shared RMW sector serves both
/// devices because all call-table I/O is synchronous and steps
/// execute serially — the bounce is dead between calls.
pub struct Regions<'a> {
    /// [`RegionId::L1`]: the staged active L1 table.
    pub l1: &'a mut [u8],
    /// [`RegionId::L2Slot`]: the staged-L2 window, slot `i` at
    /// bytes `[i * cluster_size, (i + 1) * cluster_size)`. The
    /// length must be a whole number of slots.
    pub l2_window: &'a mut [u8],
    /// [`RegionId::RefcountTable`]: the staged refcount table.
    pub refcount_table: &'a mut [u8],
    /// [`RegionId::Refblocks`]: the staged refblocks (single
    /// copy, mutated in place by the planner — qcow2-write
    /// decision 6).
    pub refblocks: &'a mut [u8],
    /// [`RegionId::Bounce`]: the cluster-sized planner bounce
    /// region (filler in v1 programs; addressable regardless).
    pub bounce: &'a mut [u8],
    /// [`RegionId::CallerData`]: the caller's data buffer for
    /// [`qcow2_write::DataSource::CallerData`].
    pub caller_data: &'a mut [u8],
    /// Executor service buffer: sub-sector RMW bounce, at least
    /// one device sector.
    pub rmw_sector: &'a mut [u8],
    /// Executor service buffer: `ZeroRange` / `FillRange`
    /// synthesis, at least one device sector.
    pub fill_sector: &'a mut [u8],
    /// Cluster size in bytes; the [`RegionId::L2Slot`] slot
    /// geometry and the [`StepKind::LoadCluster`] /
    /// [`StepKind::WritebackCluster`] whole-cluster contract are
    /// validated against it.
    pub cluster_size: usize,
}

impl Regions<'_> {
    /// Resolve `region[region_offset .. region_offset + len]` to
    /// a mutable byte window, bounds-checked per the decision-3
    /// contract ([`RegionId::L2Slot`] resolves against the slot's
    /// cluster-sized window, never the whole `l2_window`).
    /// Returns the window plus a reborrow of `rmw_sector`, so a
    /// transfer can use the region and the RMW bounce in one
    /// call (they are disjoint fields).
    fn resolve(
        &mut self,
        region: RegionId,
        region_offset: u64,
        len: u64,
    ) -> Result<(&mut [u8], &mut [u8]), ExecCause> {
        let cs = self.cluster_size;
        let (buf, base, window): (&mut [u8], usize, usize) = match region {
            RegionId::L1 => {
                let n = self.l1.len();
                (&mut self.l1[..], 0, n)
            }
            RegionId::L2Slot(slot) => {
                if cs == 0 || !self.l2_window.len().is_multiple_of(cs) {
                    return Err(ExecCause::Geometry);
                }
                let idx = slot as usize;
                if idx >= self.l2_window.len() / cs {
                    return Err(ExecCause::UnknownSlot);
                }
                (&mut self.l2_window[..], idx * cs, cs)
            }
            RegionId::RefcountTable => {
                let n = self.refcount_table.len();
                (&mut self.refcount_table[..], 0, n)
            }
            RegionId::Refblocks => {
                let n = self.refblocks.len();
                (&mut self.refblocks[..], 0, n)
            }
            RegionId::Bounce => {
                let n = self.bounce.len();
                (&mut self.bounce[..], 0, n)
            }
            RegionId::CallerData => {
                let n = self.caller_data.len();
                (&mut self.caller_data[..], 0, n)
            }
        };
        let off = usize::try_from(region_offset).map_err(|_| ExecCause::Overflow)?;
        let len = usize::try_from(len).map_err(|_| ExecCause::Overflow)?;
        let end = off.checked_add(len).ok_or(ExecCause::Overflow)?;
        if end > window {
            return Err(ExecCause::RegionBounds);
        }
        Ok((&mut buf[base + off..base + end], &mut self.rmw_sector[..]))
    }
}

// ---------------------------------------------------------------------------
// Byte-range layer (decision 2(c))
// ---------------------------------------------------------------------------

/// Read `dst.len()` bytes from `device` at byte offset
/// `disk_offset`.
///
/// The shared replacement for the per-op byte-range helpers
/// (commit's `read_output_byte_range` /
/// `read_input_byte_range`, bitmap/bench's equivalents),
/// byte-exact to their semantics: whole aligned sectors transfer
/// directly into `dst`; a sub-sector head/tail reads the
/// covering sector into `rmw_sector` and copies the wanted
/// bytes out. Exposed for the op migrations' plain byte reads
/// (e.g. commit's overlay metadata staging in step 4b), not just
/// for [`execute`].
///
/// `rmw_sector` must be at least the device's sector size
/// ([`ExecCause::Geometry`] otherwise, checked even for fully
/// aligned transfers so a mis-carved buffer fails fast).
pub fn read_bytes(
    devices: &mut impl DeviceIo,
    device: TargetDevice,
    disk_offset: u64,
    dst: &mut [u8],
    rmw_sector: &mut [u8],
) -> Result<(), ExecCause> {
    if dst.is_empty() {
        return Ok(());
    }
    let ssz = devices.sector_size(device);
    if ssz == 0 || rmw_sector.len() < ssz {
        return Err(ExecCause::Geometry);
    }
    let bounce = &mut rmw_sector[..ssz];
    let mut done: usize = 0;
    let mut cur = disk_offset;
    while done < dst.len() {
        let sector = cur / ssz as u64;
        let in_off = (cur % ssz as u64) as usize;
        let take = (ssz - in_off).min(dst.len() - done);
        if in_off == 0 && take == ssz {
            if !devices.read_sector(device, sector, &mut dst[done..done + ssz]) {
                return Err(ExecCause::ReadFailed);
            }
        } else {
            if !devices.read_sector(device, sector, bounce) {
                return Err(ExecCause::ReadFailed);
            }
            dst[done..done + take].copy_from_slice(&bounce[in_off..in_off + take]);
        }
        done += take;
        cur = cur.checked_add(take as u64).ok_or(ExecCause::Overflow)?;
    }
    Ok(())
}

/// Write `src` to `device` at byte offset `disk_offset`.
///
/// The write-side twin of [`read_bytes`] (commit's
/// `write_output_byte_range` / `write_input_byte_range`
/// replacement): whole aligned sectors transfer directly from
/// `src`; a sub-sector head/tail performs a hidden
/// read-modify-write — read the covering sector into
/// `rmw_sector`, patch the affected bytes, write the covering
/// sector back — so neighbouring bytes in the sector are
/// preserved exactly.
pub fn write_bytes(
    devices: &mut impl DeviceIo,
    device: TargetDevice,
    disk_offset: u64,
    src: &[u8],
    rmw_sector: &mut [u8],
) -> Result<(), ExecCause> {
    if src.is_empty() {
        return Ok(());
    }
    let ssz = devices.sector_size(device);
    if ssz == 0 || rmw_sector.len() < ssz {
        return Err(ExecCause::Geometry);
    }
    let bounce = &mut rmw_sector[..ssz];
    let mut done: usize = 0;
    let mut cur = disk_offset;
    while done < src.len() {
        let sector = cur / ssz as u64;
        let in_off = (cur % ssz as u64) as usize;
        let take = (ssz - in_off).min(src.len() - done);
        if in_off == 0 && take == ssz {
            if !devices.write_sector(device, sector, &src[done..done + ssz]) {
                return Err(ExecCause::WriteFailed);
            }
        } else {
            if !devices.read_sector(device, sector, bounce) {
                return Err(ExecCause::ReadFailed);
            }
            bounce[in_off..in_off + take].copy_from_slice(&src[done..done + take]);
            if !devices.write_sector(device, sector, bounce) {
                return Err(ExecCause::WriteFailed);
            }
        }
        done += take;
        cur = cur.checked_add(take as u64).ok_or(ExecCause::Overflow)?;
    }
    Ok(())
}

/// Write `len` bytes of `byte` to `device` at `disk_offset`
/// (the [`StepKind::ZeroRange`] / [`StepKind::FillRange`]
/// lowering, decision 2(d)).
///
/// Fills `fill_sector` with the byte once, then loops
/// `min(sector_size, remaining)` chunks through [`write_bytes`]
/// (bench's `zero_cluster` / `write_pattern_range` shape) —
/// unaligned head/tail chunks RMW through `rmw_sector` exactly
/// like any other write.
pub fn fill_bytes(
    devices: &mut impl DeviceIo,
    device: TargetDevice,
    disk_offset: u64,
    len: u64,
    byte: u8,
    fill_sector: &mut [u8],
    rmw_sector: &mut [u8],
) -> Result<(), ExecCause> {
    if len == 0 {
        return Ok(());
    }
    let ssz = devices.sector_size(device);
    if ssz == 0 || fill_sector.len() < ssz || rmw_sector.len() < ssz {
        return Err(ExecCause::Geometry);
    }
    fill_sector[..ssz].fill(byte);
    let mut done: u64 = 0;
    while done < len {
        let chunk = (len - done).min(ssz as u64) as usize;
        let off = disk_offset.checked_add(done).ok_or(ExecCause::Overflow)?;
        write_bytes(devices, device, off, &fill_sector[..chunk], rmw_sector)?;
        done += chunk as u64;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// The executor
// ---------------------------------------------------------------------------

/// Apply one step per its [`StepKind`] doc contract.
fn exec_step(
    regions: &mut Regions<'_>,
    devices: &mut impl DeviceIo,
    step: &Step,
    stats: &mut ExecStats,
) -> Result<(), ExecCause> {
    match step.kind {
        StepKind::ReadCluster => {
            // "Read `len` bytes from `device` at `disk_offset`
            // into `region` at `region_offset`."
            let (dst, rmw) = regions.resolve(step.region, step.region_offset, step.len)?;
            read_bytes(devices, step.device, step.disk_offset, dst, rmw)
        }
        StepKind::WriteRange => {
            // "Write `len` bytes from `region` at `region_offset`
            // to `device` at `disk_offset`."
            let (src, rmw) = regions.resolve(step.region, step.region_offset, step.len)?;
            write_bytes(devices, step.device, step.disk_offset, src, rmw)
        }
        StepKind::ZeroRange => fill_bytes(
            devices,
            step.device,
            step.disk_offset,
            step.len,
            0,
            &mut regions.fill_sector[..],
            &mut regions.rmw_sector[..],
        ),
        StepKind::FillRange => fill_bytes(
            devices,
            step.device,
            step.disk_offset,
            step.len,
            // "the fill byte (the low 8 bits of `value`)".
            step.value as u8,
            &mut regions.fill_sector[..],
            &mut regions.rmw_sector[..],
        ),
        StepKind::PatchEntryU64 => {
            // "Store `value` as a big-endian u64 at
            // `region_offset` within `region`" — a pure memory
            // op; it must NOT touch disk (the patch reaches disk
            // via a later WriteRange / WritebackCluster, decision
            // 7 ordering). `step.len` is an unused filler field
            // for this kind.
            let (dst, _) = regions.resolve(step.region, step.region_offset, 8)?;
            dst.copy_from_slice(&step.value.to_be_bytes());
            Ok(())
        }
        StepKind::LoadCluster => {
            // "Load one cluster (`len == cluster_size`)":
            // enforce the whole-cluster contract, then a plain
            // disk -> region transfer.
            if regions.cluster_size == 0 {
                return Err(ExecCause::Geometry);
            }
            if step.len != regions.cluster_size as u64 {
                return Err(ExecCause::StepContract);
            }
            let (dst, rmw) = regions.resolve(step.region, step.region_offset, step.len)?;
            read_bytes(devices, step.device, step.disk_offset, dst, rmw)
        }
        StepKind::WritebackCluster => {
            // "Write one cluster (`len == cluster_size`)".
            if regions.cluster_size == 0 {
                return Err(ExecCause::Geometry);
            }
            if step.len != regions.cluster_size as u64 {
                return Err(ExecCause::StepContract);
            }
            let (src, rmw) = regions.resolve(step.region, step.region_offset, step.len)?;
            write_bytes(devices, step.device, step.disk_offset, src, rmw)
        }
        StepKind::ZeroRegion => {
            // "Zero `len` bytes within `region` at
            // `region_offset` (no device I/O)."
            let (dst, _) = regions.resolve(step.region, step.region_offset, step.len)?;
            dst.fill(0);
            Ok(())
        }
        StepKind::Barrier { class } => match class {
            // All call-table I/O is synchronous, so issue order
            // is completion order and an Ordering barrier is a
            // no-op (decision 2(e)).
            BarrierClass::Ordering => Ok(()),
            BarrierClass::Durability => match devices.fsync(step.device) {
                // No fsync primitive: degrade to Ordering
                // (divergence D8, accepted).
                None => Ok(()),
                Some(true) => {
                    stats.fsyncs += 1;
                    Ok(())
                }
                Some(false) => Err(ExecCause::FsyncFailed),
            },
        },
    }
}

/// Execute one planned window in emission order.
///
/// The production form of the decision-1 loop body: the op plans
/// into its step buffer until `Ok` or `BufFull`, calls `execute`
/// on the emitted window, resets the buffer and resumes. Each
/// step is applied literally per its [`StepKind`] doc contract;
/// the first failure aborts the window with the failing step's
/// index and a typed cause (steps are not transactional — see
/// [`ExecError`]).
pub fn execute(
    steps: &[Step],
    regions: &mut Regions<'_>,
    devices: &mut impl DeviceIo,
) -> Result<ExecStats, ExecError> {
    let mut stats = ExecStats::default();
    for (step_index, step) in steps.iter().enumerate() {
        exec_step(regions, devices, step, &mut stats)
            .map_err(|cause| ExecError { step_index, cause })?;
        stats.steps_executed += 1;
    }
    Ok(stats)
}

// ---------------------------------------------------------------------------
// Unit tests (host, mock DeviceIo — the crates/qcow2 precedent)
// ---------------------------------------------------------------------------

#[cfg(test)]
extern crate std;

#[cfg(test)]
mod tests {
    use super::*;
    use qcow2::{QcowHeader, L1_OFFSET_MASK, L2_OFFSET_MASK, OFLAG_COPIED};
    use qcow2_write::{
        new_state, plan_flush, plan_write, DataSource, StagedRegions, StagingConfig, StepBuf,
        WriteError, WriteState,
    };
    use std::collections::BTreeSet;
    use std::vec;
    use std::vec::Vec;

    const IN0: usize = 0;
    const OUT: usize = 1;

    fn dev_idx(device: TargetDevice) -> usize {
        match device {
            TargetDevice::Input0 => IN0,
            TargetDevice::Output => OUT,
        }
    }

    const BOTH_DEVICES: [TargetDevice; 2] = [TargetDevice::Input0, TargetDevice::Output];
    const BOTH_SECTOR_SIZES: [usize; 2] = [512, 4096];

    /// Sentinel for never-written bytes (any read of it is
    /// observable as neither old, new nor zero).
    const SENTINEL: u8 = 0xEE;

    /// Mock [`DeviceIo`]: two fixed-capacity Vec disks with
    /// per-device sector sizes, an event journal and failure
    /// injection.
    struct MockIo {
        disks: [Vec<u8>; 2],
        sector_sizes: [usize; 2],
        /// Whether Input0 advertises the fsync capability.
        input_fsync: bool,
        /// Outcome of a performed fsync.
        fsync_ok: bool,
        fsyncs: u64,
        reads: Vec<(usize, u64)>,
        writes: Vec<(usize, u64)>,
        fail_read: Option<(usize, u64)>,
        fail_write: Option<(usize, u64)>,
    }

    impl MockIo {
        fn new(ssz: usize, bytes: usize) -> MockIo {
            MockIo {
                disks: [vec![SENTINEL; bytes], vec![SENTINEL; bytes]],
                sector_sizes: [ssz, ssz],
                input_fsync: true,
                fsync_ok: true,
                fsyncs: 0,
                reads: Vec::new(),
                writes: Vec::new(),
                fail_read: None,
                fail_write: None,
            }
        }

        fn disk(&self, device: TargetDevice) -> &[u8] {
            &self.disks[dev_idx(device)]
        }

        fn disk_mut(&mut self, device: TargetDevice) -> &mut Vec<u8> {
            &mut self.disks[dev_idx(device)]
        }
    }

    impl DeviceIo for MockIo {
        fn sector_size(&self, device: TargetDevice) -> usize {
            self.sector_sizes[dev_idx(device)]
        }

        fn read_sector(&mut self, device: TargetDevice, sector: u64, buf: &mut [u8]) -> bool {
            let d = dev_idx(device);
            if self.fail_read == Some((d, sector)) {
                return false;
            }
            let ssz = self.sector_sizes[d];
            let start = sector as usize * ssz;
            if buf.len() != ssz || start + ssz > self.disks[d].len() {
                return false;
            }
            buf.copy_from_slice(&self.disks[d][start..start + ssz]);
            self.reads.push((d, sector));
            true
        }

        fn write_sector(&mut self, device: TargetDevice, sector: u64, buf: &[u8]) -> bool {
            let d = dev_idx(device);
            if self.fail_write == Some((d, sector)) {
                return false;
            }
            let ssz = self.sector_sizes[d];
            let start = sector as usize * ssz;
            if buf.len() != ssz || start + ssz > self.disks[d].len() {
                return false;
            }
            self.disks[d][start..start + ssz].copy_from_slice(buf);
            self.writes.push((d, sector));
            true
        }

        fn fsync(&mut self, device: TargetDevice) -> Option<bool> {
            match device {
                TargetDevice::Input0 if self.input_fsync => {
                    if self.fsync_ok {
                        self.fsyncs += 1;
                        Some(true)
                    } else {
                        Some(false)
                    }
                }
                _ => None,
            }
        }
    }

    /// Owned staging buffers a test lends to [`Regions`] per
    /// window (the executor never owns storage).
    struct Bufs {
        l1: Vec<u8>,
        l2win: Vec<u8>,
        rt: Vec<u8>,
        refblocks: Vec<u8>,
        bounce: Vec<u8>,
        caller: Vec<u8>,
        rmw: Vec<u8>,
        fill: Vec<u8>,
        cs: usize,
    }

    impl Bufs {
        fn new(cs: usize, l2_slots: usize, ssz: usize) -> Bufs {
            Bufs {
                l1: vec![0u8; 4 * 8],
                l2win: vec![SENTINEL; l2_slots * cs],
                rt: vec![0u8; cs],
                refblocks: vec![0u8; cs],
                bounce: vec![SENTINEL; cs],
                caller: vec![0u8; 4 * cs],
                rmw: vec![0u8; ssz],
                fill: vec![0u8; ssz],
                cs,
            }
        }

        fn regions(&mut self) -> Regions<'_> {
            Regions {
                l1: &mut self.l1,
                l2_window: &mut self.l2win,
                refcount_table: &mut self.rt,
                refblocks: &mut self.refblocks,
                bounce: &mut self.bounce,
                caller_data: &mut self.caller,
                rmw_sector: &mut self.rmw,
                fill_sector: &mut self.fill,
                cluster_size: self.cs,
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn mkstep(
        kind: StepKind,
        device: TargetDevice,
        region: RegionId,
        region_offset: u64,
        disk_offset: u64,
        len: u64,
        value: u64,
    ) -> Step {
        Step {
            kind,
            device,
            region,
            region_offset,
            disk_offset,
            len,
            value,
        }
    }

    /// Deterministic position-dependent byte (251 is prime, so
    /// the pattern never aligns with sector or cluster sizes).
    fn pattern(i: u64) -> u8 {
        (i % 251) as u8
    }

    fn pattern_fill(buf: &mut [u8], seed: u64) {
        for (i, b) in buf.iter_mut().enumerate() {
            *b = pattern(i as u64 + seed);
        }
    }

    // ---------------- byte-range layer ----------------

    #[test]
    fn write_bytes_matches_naive_model_all_alignments() {
        for ssz in BOTH_SECTOR_SIZES {
            for device in BOTH_DEVICES {
                let cases: &[(u64, usize)] = &[
                    (0, ssz),                  // one aligned sector
                    (0, 3 * ssz),              // aligned multi-sector
                    (3, 10),                   // sub-sector head-of-disk
                    (ssz as u64 / 2, 16),      // middle of a sector
                    (ssz as u64 - 5, 10),      // straddles a boundary
                    (ssz as u64 + 1, 2 * ssz), // unaligned start, spans sectors
                    (7, 3 * ssz + 11),         // unaligned both ends
                    (2 * ssz as u64 - 1, 1),   // single byte at sector end
                    (100, 0),                  // empty write is a no-op
                ];
                for &(off, len) in cases {
                    let mut mock = MockIo::new(ssz, 8 * ssz);
                    pattern_fill(mock.disk_mut(device), 0);
                    let mut model = mock.disk(device).to_vec();
                    let mut src = vec![0u8; len];
                    pattern_fill(&mut src, 97);
                    let mut rmw = vec![0u8; ssz];
                    write_bytes(&mut mock, device, off, &src, &mut rmw).unwrap();
                    model[off as usize..off as usize + len].copy_from_slice(&src);
                    assert_eq!(
                        mock.disk(device),
                        &model[..],
                        "ssz {ssz} dev {device:?} off {off} len {len}"
                    );
                }
            }
        }
    }

    #[test]
    fn read_bytes_matches_naive_model_all_alignments() {
        for ssz in BOTH_SECTOR_SIZES {
            for device in BOTH_DEVICES {
                let mut mock = MockIo::new(ssz, 8 * ssz);
                pattern_fill(mock.disk_mut(device), 11);
                let cases: &[(u64, usize)] = &[
                    (0, ssz),
                    (0, 2 * ssz),
                    (5, 9),
                    (ssz as u64 - 3, 7),
                    (ssz as u64 + 13, 3 * ssz + 5),
                    (3 * ssz as u64 - 1, 1),
                    (42, 0),
                ];
                for &(off, len) in cases {
                    let mut dst = vec![0xAB; len];
                    let mut rmw = vec![0u8; ssz];
                    read_bytes(&mut mock, device, off, &mut dst, &mut rmw).unwrap();
                    let expect = &mock.disk(device)[off as usize..off as usize + len];
                    assert_eq!(dst, expect, "ssz {ssz} dev {device:?} off {off} len {len}");
                }
            }
        }
    }

    #[test]
    fn write_bytes_rmw_hidden_read_accounting() {
        let ssz = 512;
        let mut mock = MockIo::new(ssz, 8 * ssz);
        let mut rmw = vec![0u8; ssz];

        // Aligned full-sector write: no hidden read.
        write_bytes(
            &mut mock,
            TargetDevice::Input0,
            512,
            &vec![1u8; 512],
            &mut rmw,
        )
        .unwrap();
        assert!(mock.reads.is_empty(), "aligned write must not RMW");
        assert_eq!(mock.writes, vec![(IN0, 1)]);

        // A write straddling a boundary with partial cover on
        // both sides: exactly one hidden read per partial sector.
        mock.reads.clear();
        mock.writes.clear();
        write_bytes(
            &mut mock,
            TargetDevice::Input0,
            512 - 4,
            &[2u8; 8],
            &mut rmw,
        )
        .unwrap();
        assert_eq!(mock.reads, vec![(IN0, 0), (IN0, 1)]);
        assert_eq!(mock.writes, vec![(IN0, 0), (IN0, 1)]);

        // Unaligned head + whole middle + partial tail: reads
        // only for the two partial covering sectors.
        mock.reads.clear();
        mock.writes.clear();
        write_bytes(
            &mut mock,
            TargetDevice::Input0,
            100,
            &vec![3u8; 512 * 2],
            &mut rmw,
        )
        .unwrap();
        assert_eq!(mock.reads, vec![(IN0, 0), (IN0, 2)]);
        assert_eq!(mock.writes, vec![(IN0, 0), (IN0, 1), (IN0, 2)]);
    }

    #[test]
    fn byte_range_refuses_undersized_service_buffers() {
        let ssz = 512;
        let mut mock = MockIo::new(ssz, 4 * ssz);
        let mut short = vec![0u8; ssz - 1];
        let mut ok = vec![0u8; ssz];
        let mut dst = [0u8; 8];
        assert_eq!(
            read_bytes(&mut mock, TargetDevice::Input0, 0, &mut dst, &mut short),
            Err(ExecCause::Geometry)
        );
        assert_eq!(
            write_bytes(&mut mock, TargetDevice::Input0, 0, &dst, &mut short),
            Err(ExecCause::Geometry)
        );
        assert_eq!(
            fill_bytes(
                &mut mock,
                TargetDevice::Input0,
                0,
                8,
                0,
                &mut short,
                &mut ok
            ),
            Err(ExecCause::Geometry)
        );
        assert_eq!(
            fill_bytes(
                &mut mock,
                TargetDevice::Input0,
                0,
                8,
                0,
                &mut ok,
                &mut short
            ),
            Err(ExecCause::Geometry)
        );
    }

    // ---------------- per-StepKind contracts ----------------

    /// Reference-model check for every disk-touching StepKind on
    /// both devices and both sector sizes: the mock disk after
    /// [`execute`] equals a naive byte-array model, and the
    /// staged regions equal their expected contents.
    #[test]
    fn every_step_kind_matches_reference_model() {
        for ssz in BOTH_SECTOR_SIZES {
            for device in BOTH_DEVICES {
                let cs = 4096usize;
                let mut bufs = Bufs::new(cs, 2, ssz);
                pattern_fill(&mut bufs.caller, 7);
                let mut mock = MockIo::new(ssz, 16 * cs);
                pattern_fill(mock.disk_mut(device), 23);
                let mut model = mock.disk(device).to_vec();

                let patch_a = 0x1122334455667788u64;
                let patch_b = 0x99aabbccddeeff00u64;
                let steps = [
                    // Slot 1 init, patch an entry into it, write
                    // it back to disk whole.
                    mkstep(
                        StepKind::ZeroRegion,
                        device,
                        RegionId::L2Slot(1),
                        0,
                        0,
                        cs as u64,
                        0,
                    ),
                    mkstep(
                        StepKind::PatchEntryU64,
                        device,
                        RegionId::L2Slot(1),
                        24,
                        0,
                        0,
                        patch_a,
                    ),
                    mkstep(
                        StepKind::WritebackCluster,
                        device,
                        RegionId::L2Slot(1),
                        0,
                        4 * cs as u64,
                        cs as u64,
                        0,
                    ),
                    // Load the same cluster into slot 0.
                    mkstep(
                        StepKind::LoadCluster,
                        device,
                        RegionId::L2Slot(0),
                        0,
                        4 * cs as u64,
                        cs as u64,
                        0,
                    ),
                    // L1 patch (memory-only) then an unaligned
                    // WriteRange of the whole L1.
                    mkstep(
                        StepKind::PatchEntryU64,
                        device,
                        RegionId::L1,
                        8,
                        0,
                        0,
                        patch_b,
                    ),
                    mkstep(
                        StepKind::WriteRange,
                        device,
                        RegionId::L1,
                        0,
                        3 * cs as u64 + 1,
                        32,
                        0,
                    ),
                    // Caller-data write at an unaligned offset.
                    mkstep(
                        StepKind::WriteRange,
                        device,
                        RegionId::CallerData,
                        13,
                        5 * cs as u64 + 9,
                        777,
                        0,
                    ),
                    // Disk -> Bounce region read.
                    mkstep(
                        StepKind::ReadCluster,
                        device,
                        RegionId::Bounce,
                        5,
                        4 * cs as u64 + 3,
                        100,
                        0,
                    ),
                    // Fill and zero ranges with unaligned ends.
                    mkstep(
                        StepKind::FillRange,
                        device,
                        RegionId::Bounce,
                        0,
                        6 * cs as u64 - 3,
                        ssz as u64 + 6,
                        0x17e, // low 8 bits used: 0x7e
                    ),
                    mkstep(
                        StepKind::ZeroRange,
                        device,
                        RegionId::Bounce,
                        0,
                        7 * cs as u64 + 1,
                        200,
                        0,
                    ),
                    mkstep(
                        StepKind::Barrier {
                            class: BarrierClass::Ordering,
                        },
                        device,
                        RegionId::Bounce,
                        0,
                        0,
                        0,
                        0,
                    ),
                ];

                let stats = {
                    let mut regions = bufs.regions();
                    execute(&steps, &mut regions, &mut mock).expect("program must execute")
                };
                assert_eq!(stats.steps_executed, steps.len() as u64);
                assert_eq!(stats.fsyncs, 0);

                // Expected slot-1 bytes: zeros + patch_a at 24.
                let mut slot1 = vec![0u8; cs];
                slot1[24..32].copy_from_slice(&patch_a.to_be_bytes());
                assert_eq!(&bufs.l2win[cs..2 * cs], &slot1[..], "slot 1 staged bytes");
                // WritebackCluster then LoadCluster round-trips
                // slot 1's bytes into slot 0.
                assert_eq!(&bufs.l2win[..cs], &slot1[..], "slot 0 loaded bytes");
                model[4 * cs..5 * cs].copy_from_slice(&slot1);

                // L1: patch_b at offset 8, then written to disk
                // at an unaligned offset.
                let mut l1 = vec![0u8; 32];
                l1[8..16].copy_from_slice(&patch_b.to_be_bytes());
                assert_eq!(&bufs.l1[..], &l1[..], "staged L1 bytes");
                model[3 * cs + 1..3 * cs + 33].copy_from_slice(&l1);

                // Caller-data write.
                model[5 * cs + 9..5 * cs + 9 + 777].copy_from_slice(&bufs.caller[13..13 + 777]);

                // ReadCluster: disk bytes landed in the bounce
                // region at offset 5 (from the already-updated
                // model — the writeback preceded it).
                assert_eq!(
                    &bufs.bounce[5..105],
                    &model[4 * cs + 3..4 * cs + 103],
                    "bounce region read"
                );

                // Fill / zero ranges.
                for b in &mut model[6 * cs - 3..6 * cs - 3 + ssz + 6] {
                    *b = 0x7e;
                }
                for b in &mut model[7 * cs + 1..7 * cs + 201] {
                    *b = 0;
                }

                assert_eq!(
                    mock.disk(device),
                    &model[..],
                    "final disk (ssz {ssz} dev {device:?})"
                );
                // The other device was never touched.
                let other = match device {
                    TargetDevice::Input0 => TargetDevice::Output,
                    TargetDevice::Output => TargetDevice::Input0,
                };
                assert!(mock.disk(other).iter().all(|&b| b == SENTINEL));
            }
        }
    }

    #[test]
    fn zero_and_fill_range_span_sectors_with_unaligned_ends() {
        for ssz in BOTH_SECTOR_SIZES {
            for (byte, value) in [(0u8, 0u64), (0xa5, 0xa5)] {
                let kind = if byte == 0 {
                    StepKind::ZeroRange
                } else {
                    StepKind::FillRange
                };
                let mut bufs = Bufs::new(4096, 2, ssz);
                let mut mock = MockIo::new(ssz, 8 * ssz);
                pattern_fill(mock.disk_mut(TargetDevice::Input0), 41);
                let mut model = mock.disk(TargetDevice::Input0).to_vec();
                let off = ssz as u64 - 3;
                let len = 2 * ssz as u64 + 7;
                let steps = [mkstep(
                    kind,
                    TargetDevice::Input0,
                    RegionId::Bounce,
                    0,
                    off,
                    len,
                    value,
                )];
                let mut regions = bufs.regions();
                execute(&steps, &mut regions, &mut mock).unwrap();
                for b in &mut model[off as usize..(off + len) as usize] {
                    *b = byte;
                }
                assert_eq!(
                    mock.disk(TargetDevice::Input0),
                    &model[..],
                    "ssz {ssz} byte {byte}"
                );
                // Boundary bytes preserved by the RMW.
                assert_eq!(
                    mock.disk(TargetDevice::Input0)[off as usize - 1],
                    model[off as usize - 1]
                );
                assert_eq!(
                    mock.disk(TargetDevice::Input0)[(off + len) as usize],
                    model[(off + len) as usize]
                );
            }
        }
    }

    #[test]
    fn patch_entry_u64_touches_no_disk() {
        let mut bufs = Bufs::new(4096, 2, 512);
        let mut mock = MockIo::new(512, 8 * 512);
        let steps = [mkstep(
            StepKind::PatchEntryU64,
            TargetDevice::Input0,
            RegionId::L1,
            16,
            0,
            0,
            0xdeadbeefcafef00d,
        )];
        let mut regions = bufs.regions();
        execute(&steps, &mut regions, &mut mock).unwrap();
        assert!(mock.reads.is_empty(), "patch must not read the disk");
        assert!(mock.writes.is_empty(), "patch must not write the disk");
        assert_eq!(mock.fsyncs, 0);
        assert_eq!(&bufs.l1[16..24], &0xdeadbeefcafef00du64.to_be_bytes());
    }

    // ---------------- barrier policy (decision 2(e)) ----------------

    fn barrier(device: TargetDevice, class: BarrierClass) -> Step {
        mkstep(
            StepKind::Barrier { class },
            device,
            RegionId::Bounce,
            0,
            0,
            0,
            0,
        )
    }

    #[test]
    fn durability_on_input0_fsyncs_once_per_barrier() {
        let mut bufs = Bufs::new(4096, 2, 512);
        let mut mock = MockIo::new(512, 8 * 512);
        let steps = [
            barrier(TargetDevice::Input0, BarrierClass::Durability),
            barrier(TargetDevice::Input0, BarrierClass::Durability),
        ];
        let mut regions = bufs.regions();
        let stats = execute(&steps, &mut regions, &mut mock).unwrap();
        assert_eq!(mock.fsyncs, 2, "one fsync per Durability barrier");
        assert_eq!(stats.fsyncs, 2);
    }

    #[test]
    fn durability_on_output_degrades_to_ordering() {
        // The output device has no fsync primitive (divergence
        // D8): the barrier degrades and succeeds silently.
        let mut bufs = Bufs::new(4096, 2, 512);
        let mut mock = MockIo::new(512, 8 * 512);
        let steps = [barrier(TargetDevice::Output, BarrierClass::Durability)];
        let mut regions = bufs.regions();
        let stats = execute(&steps, &mut regions, &mut mock).unwrap();
        assert_eq!(mock.fsyncs, 0, "no fsync recorded on Output");
        assert_eq!(stats.fsyncs, 0);
    }

    #[test]
    fn durability_degrades_without_input_fsync_capability() {
        let mut bufs = Bufs::new(4096, 2, 512);
        let mut mock = MockIo::new(512, 8 * 512);
        mock.input_fsync = false;
        let steps = [barrier(TargetDevice::Input0, BarrierClass::Durability)];
        let mut regions = bufs.regions();
        let stats = execute(&steps, &mut regions, &mut mock).unwrap();
        assert_eq!(mock.fsyncs, 0);
        assert_eq!(stats.fsyncs, 0);
    }

    #[test]
    fn ordering_barrier_is_a_no_op() {
        let mut bufs = Bufs::new(4096, 2, 512);
        let mut mock = MockIo::new(512, 8 * 512);
        let steps = [barrier(TargetDevice::Input0, BarrierClass::Ordering)];
        let mut regions = bufs.regions();
        let stats = execute(&steps, &mut regions, &mut mock).unwrap();
        assert_eq!(mock.fsyncs, 0, "Ordering must not fsync even where capable");
        assert_eq!(stats.fsyncs, 0);
        assert_eq!(stats.steps_executed, 1);
    }

    #[test]
    fn failed_fsync_surfaces_with_step_index() {
        let mut bufs = Bufs::new(4096, 2, 512);
        let mut mock = MockIo::new(512, 8 * 512);
        mock.fsync_ok = false;
        let steps = [
            barrier(TargetDevice::Input0, BarrierClass::Ordering),
            barrier(TargetDevice::Input0, BarrierClass::Durability),
        ];
        let mut regions = bufs.regions();
        let err = execute(&steps, &mut regions, &mut mock).unwrap_err();
        assert_eq!(
            err,
            ExecError {
                step_index: 1,
                cause: ExecCause::FsyncFailed
            }
        );
    }

    // ---------------- robustness: typed errors, no panics ----------------

    #[test]
    fn unknown_l2_slot_refused() {
        let mut bufs = Bufs::new(4096, 2, 512);
        let mut mock = MockIo::new(512, 8 * 512);
        let steps = [mkstep(
            StepKind::PatchEntryU64,
            TargetDevice::Input0,
            RegionId::L2Slot(2), // window has slots 0..2
            0,
            0,
            0,
            1,
        )];
        let mut regions = bufs.regions();
        let err = execute(&steps, &mut regions, &mut mock).unwrap_err();
        assert_eq!(err.cause, ExecCause::UnknownSlot);
        assert_eq!(err.step_index, 0);
    }

    #[test]
    fn region_bounds_violations_refused() {
        let cs = 4096u64;
        let cases = [
            // Patch running off the end of the L1 region.
            mkstep(
                StepKind::PatchEntryU64,
                TargetDevice::Input0,
                RegionId::L1,
                28,
                0,
                0,
                1,
            ),
            // Patch running off the end of an L2 slot (slot
            // geometry, not the whole window, bounds the access).
            mkstep(
                StepKind::PatchEntryU64,
                TargetDevice::Input0,
                RegionId::L2Slot(0),
                cs - 4,
                0,
                0,
                1,
            ),
            // WriteRange source beyond the caller region.
            mkstep(
                StepKind::WriteRange,
                TargetDevice::Input0,
                RegionId::CallerData,
                4 * cs - 8,
                0,
                16,
                0,
            ),
            // ReadCluster target beyond the bounce region.
            mkstep(
                StepKind::ReadCluster,
                TargetDevice::Input0,
                RegionId::Bounce,
                cs - 10,
                0,
                100,
                0,
            ),
            // ZeroRegion beyond an L2 slot.
            mkstep(
                StepKind::ZeroRegion,
                TargetDevice::Input0,
                RegionId::L2Slot(1),
                8,
                0,
                cs,
                0,
            ),
        ];
        for step in cases {
            let mut bufs = Bufs::new(cs as usize, 2, 512);
            let mut mock = MockIo::new(512, 8 * 512);
            let mut regions = bufs.regions();
            let err = execute(core::slice::from_ref(&step), &mut regions, &mut mock).unwrap_err();
            assert_eq!(err.cause, ExecCause::RegionBounds, "step {step:?}");
            assert!(mock.writes.is_empty(), "no disk mutation on refusal");
        }
    }

    #[test]
    fn load_and_writeback_enforce_whole_cluster_contract() {
        let cs = 4096u64;
        for kind in [StepKind::LoadCluster, StepKind::WritebackCluster] {
            let mut bufs = Bufs::new(cs as usize, 2, 512);
            let mut mock = MockIo::new(512, 16 * cs as usize);
            let steps = [mkstep(
                kind,
                TargetDevice::Input0,
                RegionId::L2Slot(0),
                0,
                4 * cs,
                cs - 1,
                0,
            )];
            let mut regions = bufs.regions();
            let err = execute(&steps, &mut regions, &mut mock).unwrap_err();
            assert_eq!(err.cause, ExecCause::StepContract, "{kind:?}");
        }
    }

    #[test]
    fn misaligned_l2_window_refused_as_geometry() {
        let cs = 4096usize;
        let mut bufs = Bufs::new(cs, 2, 512);
        bufs.l2win = vec![0u8; cs + 3]; // not a whole number of slots
        let mut mock = MockIo::new(512, 8 * 512);
        let steps = [mkstep(
            StepKind::PatchEntryU64,
            TargetDevice::Input0,
            RegionId::L2Slot(0),
            0,
            0,
            0,
            1,
        )];
        let mut regions = bufs.regions();
        let err = execute(&steps, &mut regions, &mut mock).unwrap_err();
        assert_eq!(err.cause, ExecCause::Geometry);
    }

    #[test]
    fn region_offset_overflow_refused() {
        let mut bufs = Bufs::new(4096, 2, 512);
        let mut mock = MockIo::new(512, 8 * 512);
        let steps = [mkstep(
            StepKind::PatchEntryU64,
            TargetDevice::Input0,
            RegionId::L1,
            u64::MAX,
            0,
            0,
            1,
        )];
        let mut regions = bufs.regions();
        let err = execute(&steps, &mut regions, &mut mock).unwrap_err();
        assert_eq!(err.cause, ExecCause::Overflow);
    }

    #[test]
    fn io_failures_surface_with_step_index() {
        let cs = 4096u64;
        // Read failure inside a LoadCluster.
        let mut bufs = Bufs::new(cs as usize, 2, 512);
        let mut mock = MockIo::new(512, 16 * cs as usize);
        mock.fail_read = Some((IN0, 4 * cs / 512 + 2));
        let steps = [
            barrier(TargetDevice::Input0, BarrierClass::Ordering),
            mkstep(
                StepKind::LoadCluster,
                TargetDevice::Input0,
                RegionId::L2Slot(0),
                0,
                4 * cs,
                cs,
                0,
            ),
        ];
        let mut regions = bufs.regions();
        let err = execute(&steps, &mut regions, &mut mock).unwrap_err();
        assert_eq!(
            err,
            ExecError {
                step_index: 1,
                cause: ExecCause::ReadFailed
            }
        );

        // Write failure inside a WritebackCluster.
        let mut bufs = Bufs::new(cs as usize, 2, 512);
        let mut mock = MockIo::new(512, 16 * cs as usize);
        mock.fail_write = Some((IN0, 4 * cs / 512));
        let steps = [mkstep(
            StepKind::WritebackCluster,
            TargetDevice::Input0,
            RegionId::L2Slot(0),
            0,
            4 * cs,
            cs,
            0,
        )];
        let mut regions = bufs.regions();
        let err = execute(&steps, &mut regions, &mut mock).unwrap_err();
        assert_eq!(
            err,
            ExecError {
                step_index: 0,
                cause: ExecCause::WriteFailed
            }
        );

        // A hidden RMW read failure reports ReadFailed even
        // though the step is a write.
        let mut bufs = Bufs::new(cs as usize, 2, 512);
        let mut mock = MockIo::new(512, 16 * cs as usize);
        mock.fail_read = Some((IN0, 0));
        let steps = [mkstep(
            StepKind::WriteRange,
            TargetDevice::Input0,
            RegionId::L1,
            0,
            1, // sub-sector: RMW must read covering sector 0
            8,
            0,
        )];
        let mut regions = bufs.regions();
        let err = execute(&steps, &mut regions, &mut mock).unwrap_err();
        assert_eq!(
            err,
            ExecError {
                step_index: 0,
                cause: ExecCause::ReadFailed
            }
        );
    }

    #[test]
    fn empty_window_executes_to_zero_stats() {
        let mut bufs = Bufs::new(4096, 2, 512);
        let mut mock = MockIo::new(512, 8 * 512);
        let mut regions = bufs.regions();
        let stats = execute(&[], &mut regions, &mut mock).unwrap();
        assert_eq!(stats, ExecStats::default());
    }

    // =====================================================================
    // End-to-end: qcow2-write planner programs executed by this
    // executor over a mock disk (the production decision-1 loop).
    // =====================================================================

    /// Parameterised v3 header (the qcow2-write test pattern).
    /// Layout: cluster 0 header, cluster 1 refcount table,
    /// cluster 2 refblock 0, cluster 3 L1, clusters 4+ free.
    fn build_header(cluster_bits: u32, virtual_size: u64, l1_size: u32) -> [u8; 4096] {
        let cs = 1u64 << cluster_bits;
        let mut h = [0u8; 4096];
        h[0..4].copy_from_slice(&qcow2::QCOW2_MAGIC.to_be_bytes());
        h[4..8].copy_from_slice(&3u32.to_be_bytes());
        h[20..24].copy_from_slice(&cluster_bits.to_be_bytes());
        h[24..32].copy_from_slice(&virtual_size.to_be_bytes());
        h[36..40].copy_from_slice(&l1_size.to_be_bytes());
        h[40..48].copy_from_slice(&(3 * cs).to_be_bytes());
        h[48..56].copy_from_slice(&cs.to_be_bytes());
        h[56..60].copy_from_slice(&1u32.to_be_bytes());
        h[96..100].copy_from_slice(&4u32.to_be_bytes());
        h[100..104].copy_from_slice(&104u32.to_be_bytes());
        h
    }

    fn be64(b: &[u8], off: usize) -> u64 {
        u64::from_be_bytes(b[off..off + 8].try_into().unwrap())
    }

    fn be16(b: &[u8], off: usize) -> u16 {
        u16::from_be_bytes(b[off..off + 2].try_into().unwrap())
    }

    /// The image under test: a mock Input0 disk holding a
    /// minimal valid qcow2, plus the staged buffers and planner
    /// state the decision-1 loop threads.
    struct Harness {
        mock: MockIo,
        bufs: Bufs,
        st: WriteState,
        hdr: QcowHeader,
        model: Vec<u8>,
    }

    const DISK_CLUSTERS: usize = 64;
    const L2_SLOTS: usize = 2;
    const STEP_CAP: usize = 7;

    fn harness(cluster_bits: u32, ssz: usize) -> Harness {
        let cs = 1usize << cluster_bits;
        let l2_coverage = (cs as u64 / 8) * cs as u64;
        let virtual_size = 4 * l2_coverage;
        let hdr_bytes = build_header(cluster_bits, virtual_size, 4);
        let hdr = QcowHeader::parse(&hdr_bytes).expect("synthetic header must parse");

        let mut mock = MockIo::new(ssz, DISK_CLUSTERS * cs);
        {
            let disk = mock.disk_mut(TargetDevice::Input0);
            // Metadata clusters 0..4 are zeroed, the rest stays
            // sentinel so missed zero-fills are observable.
            disk[..4 * cs].fill(0);
            let hlen = cs.min(hdr_bytes.len());
            disk[..hlen].copy_from_slice(&hdr_bytes[..hlen]);
            // Refcount table entry 0 -> refblock at cluster 2.
            disk[cs..cs + 8].copy_from_slice(&(2 * cs as u64).to_be_bytes());
            // Refblock 0: clusters 0..4 (header, RT, refblock,
            // L1) have refcount 1.
            for c in 0..4 {
                disk[2 * cs + c * 2..2 * cs + c * 2 + 2].copy_from_slice(&1u16.to_be_bytes());
            }
            // L1 (cluster 3) stays zero: empty image.
        }

        // Stage per the StagedRegions contract: L1 and refcount
        // table copied from disk, refblocks as the dense prefix,
        // sentinel L2 window.
        let mut bufs = Bufs::new(cs, L2_SLOTS, ssz);
        bufs.l1
            .copy_from_slice(&mock.disk(TargetDevice::Input0)[3 * cs..3 * cs + 32]);
        bufs.rt
            .copy_from_slice(&mock.disk(TargetDevice::Input0)[cs..2 * cs]);
        bufs.refblocks
            .copy_from_slice(&mock.disk(TargetDevice::Input0)[2 * cs..3 * cs]);
        pattern_fill(&mut bufs.caller, 0);

        let cfg = StagingConfig {
            l2_slots: L2_SLOTS,
            max_refblocks: 32,
            device: TargetDevice::Input0,
        };
        let st = new_state(&hdr, &cfg).expect("clean image must gate");
        let model = vec![0u8; virtual_size as usize];
        Harness {
            mock,
            bufs,
            st,
            hdr,
            model,
        }
    }

    /// The decision-1 loop for one request: plan a window,
    /// execute it with the production executor, reset, resume.
    fn run_write(h: &mut Harness, voff: u64, len: u64, data: DataSource) {
        let filler = mkstep(
            StepKind::ZeroRange,
            TargetDevice::Input0,
            RegionId::Bounce,
            0,
            0,
            0,
            0,
        );
        let mut storage = [filler; STEP_CAP];
        for _ in 0..100_000 {
            let mut buf = StepBuf::new(&mut storage);
            let r = {
                let mut sv = StagedRegions {
                    l1: &h.bufs.l1,
                    l2_window: &h.bufs.l2win,
                    refcount_table: &h.bufs.rt,
                    refblocks: &mut h.bufs.refblocks,
                };
                plan_write(&mut h.st, &mut sv, voff, len, data, &mut buf)
            };
            {
                let mut regions = h.bufs.regions();
                execute(buf.steps(), &mut regions, &mut h.mock).expect("window must execute");
            }
            match r {
                Ok(_) => break,
                Err(WriteError::BufFull) => continue,
                Err(e) => panic!("plan_write refused: {e:?}"),
            }
        }
        // Maintain the virtual-content reference model.
        match data {
            DataSource::CallerData { offset } => {
                let src = &h.bufs.caller[offset as usize..(offset + len) as usize];
                h.model[voff as usize..(voff + len) as usize].copy_from_slice(src);
            }
            DataSource::Fill { byte } => {
                for b in &mut h.model[voff as usize..(voff + len) as usize] {
                    *b = byte;
                }
            }
        }
    }

    fn run_flush(h: &mut Harness) {
        let filler = mkstep(
            StepKind::ZeroRange,
            TargetDevice::Input0,
            RegionId::Bounce,
            0,
            0,
            0,
            0,
        );
        let mut storage = [filler; STEP_CAP];
        for _ in 0..100_000 {
            let mut buf = StepBuf::new(&mut storage);
            let r = {
                let mut sv = StagedRegions {
                    l1: &h.bufs.l1,
                    l2_window: &h.bufs.l2win,
                    refcount_table: &h.bufs.rt,
                    refblocks: &mut h.bufs.refblocks,
                };
                plan_flush(&mut h.st, &mut sv, &mut buf)
            };
            {
                let mut regions = h.bufs.regions();
                execute(buf.steps(), &mut regions, &mut h.mock).expect("flush window");
            }
            match r {
                Ok(_) => return,
                Err(WriteError::BufFull) => continue,
                Err(e) => panic!("plan_flush refused: {e:?}"),
            }
        }
        panic!("flush failed to converge");
    }

    /// Walk the on-disk metadata (never the staged copies):
    /// materialise the virtual content and collect every
    /// referenced host cluster (metadata + data), asserting
    /// COPIED flags and alignment on the way — the same
    /// consistency posture as qcow2-write's simulation suite.
    fn walk_disk(h: &Harness) -> (Vec<u8>, BTreeSet<u64>) {
        let disk = h.mock.disk(TargetDevice::Input0);
        let hdr = QcowHeader::parse(&disk[..4096.min(disk.len())]).expect("header re-parses");
        assert_eq!(hdr.virtual_size, h.hdr.virtual_size, "header unchanged");
        let cs = hdr.cluster_size as usize;
        let entries_per_l2 = cs as u64 / 8;
        let mut content = vec![0u8; hdr.virtual_size as usize];
        // Metadata clusters: header, refcount table, refblock, L1.
        let mut referenced: BTreeSet<u64> = [0u64, 1, 2, 3].into_iter().collect();
        let l1_off = hdr.l1_table_offset as usize;
        for l1_idx in 0..hdr.l1_size as usize {
            let l1e = be64(disk, l1_off + l1_idx * 8);
            if l1e == 0 {
                continue;
            }
            assert_eq!(l1e & !(OFLAG_COPIED | L1_OFFSET_MASK), 0, "clean L1 entry");
            assert_ne!(l1e & OFLAG_COPIED, 0, "L1 entry carries COPIED");
            let l2_host = l1e & L1_OFFSET_MASK;
            assert!(l2_host.is_multiple_of(cs as u64), "aligned L2 offset");
            referenced.insert(l2_host / cs as u64);
            for j in 0..entries_per_l2 as usize {
                let e = be64(disk, l2_host as usize + j * 8);
                if e == 0 {
                    continue;
                }
                assert_eq!(e & !(OFLAG_COPIED | L2_OFFSET_MASK), 0, "clean L2 entry");
                assert_ne!(e & OFLAG_COPIED, 0, "L2 entry carries COPIED");
                let host = e & L2_OFFSET_MASK;
                assert!(host.is_multiple_of(cs as u64), "aligned data offset");
                referenced.insert(host / cs as u64);
                let voff = (l1_idx as u64 * entries_per_l2 + j as u64) * cs as u64;
                content[voff as usize..voff as usize + cs]
                    .copy_from_slice(&disk[host as usize..host as usize + cs]);
            }
        }
        (content, referenced)
    }

    /// End-to-end composition proof (the step-4a bar): planner
    /// programs driven through the production executor leave the
    /// mock disk in the state qcow2-write's simulation semantics
    /// define — virtual content equals the reference model and
    /// every referenced cluster has on-disk refcount exactly 1.
    fn end_to_end(cluster_bits: u32, ssz: usize) {
        let mut h = harness(cluster_bits, ssz);
        let cs = 1u64 << cluster_bits;
        let l2_coverage = (cs / 8) * cs;

        // Fresh sub-cluster write (head + tail zero-fill).
        run_write(&mut h, 100, 300, DataSource::CallerData { offset: 0 });
        // Full-cluster write.
        run_write(&mut h, cs, cs, DataSource::CallerData { offset: 64 });
        // Straddling write across a cluster boundary.
        run_write(
            &mut h,
            3 * cs - 50,
            cs,
            DataSource::CallerData { offset: 128 },
        );
        // Second L1 slot (forces LoadCluster window boundaries).
        run_write(
            &mut h,
            l2_coverage + 10,
            100,
            DataSource::CallerData { offset: 256 },
        );
        // Third L1 slot with a 2-slot window: forces eviction
        // (dirty victim writeback) and spans two clusters.
        run_write(
            &mut h,
            2 * l2_coverage + cs,
            2 * cs,
            DataSource::CallerData { offset: 512 },
        );
        // Back to L1 slot 0 (reload after eviction): in-place
        // overwrite of an owned cluster.
        run_write(&mut h, 150, 200, DataSource::CallerData { offset: 1024 });
        // Fill-source write into a fresh sub-cluster range.
        run_write(&mut h, 4 * cs + 8, 24, DataSource::Fill { byte: 0x99 });

        run_flush(&mut h);

        // 1. Virtual content equals the reference model.
        let (content, referenced) = walk_disk(&h);
        assert_eq!(
            content, h.model,
            "virtual content mismatch (cb {cluster_bits} ssz {ssz})"
        );

        // 2. Refcount check against the flushed on-disk refblock:
        // referenced clusters exactly 1, everything else 0.
        let disk = h.mock.disk(TargetDevice::Input0);
        let csz = cs as usize;
        let rb_host = be64(disk, csz); // RT entry 0
        assert_eq!(rb_host, 2 * cs, "refcount table entry unchanged");
        for c in 0..DISK_CLUSTERS as u64 {
            let rc = be16(disk, rb_host as usize + c as usize * 2);
            let expect = u16::from(referenced.contains(&c));
            assert_eq!(rc, expect, "refcount of cluster {c}");
        }

        // 3. The flush's Durability barriers really fsynced the
        // RW input device (decision 2(e)).
        assert!(h.mock.fsyncs > 0, "flush must fsync Input0");
        // 4. The output device was never touched.
        assert!(h
            .mock
            .disk(TargetDevice::Output)
            .iter()
            .all(|&b| b == SENTINEL));
    }

    #[test]
    fn planner_programs_compose_cb12_ssz512() {
        end_to_end(12, 512);
    }

    #[test]
    fn planner_programs_compose_cb12_ssz4096() {
        end_to_end(12, 4096);
    }

    #[test]
    fn planner_programs_compose_cb9_ssz512() {
        end_to_end(9, 512);
    }

    /// Sector larger than the cluster: every cluster transfer is
    /// a sub-sector RMW — the hardest exercise of the byte-range
    /// layer under real planner programs.
    #[test]
    fn planner_programs_compose_cb9_ssz4096() {
        end_to_end(9, 4096);
    }

    // ---------------- error code stability ----------------

    #[test]
    fn exec_cause_codes_distinct_and_stable() {
        let codes = [
            (ExecCause::ReadFailed, 1),
            (ExecCause::WriteFailed, 2),
            (ExecCause::FsyncFailed, 3),
            (ExecCause::RegionBounds, 4),
            (ExecCause::UnknownSlot, 5),
            (ExecCause::Geometry, 6),
            (ExecCause::Overflow, 7),
            (ExecCause::StepContract, 8),
        ];
        for (cause, expected) in codes {
            assert_eq!(cause.code(), expected, "{cause:?} code drifted");
        }
        for i in 0..codes.len() {
            for j in (i + 1)..codes.len() {
                assert_ne!(codes[i].1, codes[j].1, "codes {i} and {j} alias");
            }
        }
    }
}
