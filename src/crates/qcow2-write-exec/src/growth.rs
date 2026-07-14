//! Region-agnostic refcount-growth EXECUTION shared by the ops.
//!
//! The imperative twin of the pure planner in
//! `qcow2_write::growth`: where [`qcow2_write::growth::plan_refcount_growth`]
//! decides *how much* to grow (saturating arithmetic, no I/O), this
//! module *performs* the growth against a device — staging the extended
//! refcount table + new refblocks, refcounting the new structures,
//! materializing every provisioned refblock (#433), and running the
//! data-first / fsync / header-flip / old-RT-free dance in write order.
//!
//! Moved verbatim (behaviour byte-identical) out of
//! `src/operations/bench` by phase 7 (settled decision 5, mechanism A)
//! of `docs/plans/PLAN-qcow2-write-infrastructure-phase-07-write.md`,
//! generalized so `commit`/`rebase` can reuse it. Two mechanical
//! generalizations make it region-agnostic:
//!
//! - **the target device is a parameter** ([`TargetDevice`]) — bench
//!   passes `Input0`, commit/rebase will pass `Output`. All writes go
//!   through [`crate::write_bytes`] and all durability fsyncs through
//!   [`crate::DeviceIo::fsync`], so the census follows the device's
//!   fsync capability exactly (a fsync-capable `Input0` performs REAL
//!   fsyncs; an `Output` with no primitive degrades to ordering — the
//!   phase-4 divergence D8 policy, identical to the executor's
//!   `BarrierClass::Durability`).
//! - **the scratch buffers are borrowed slices** ([`GrowthBuffers`]) —
//!   the staged refcount table, the staged refblocks, and one RMW
//!   sector. The op carves them from its own scratch (bench's
//!   `WRITE_RT_BUF` / `WRITE_REFBLOCKS_BUF` / `WRITE_RMW_BOUNCE`); the
//!   header geometry it needs travels as plain values, so the crate
//!   never borrows a `QcowHeader`.

use crate::{write_bytes, DeviceIo};
use qcow2_write::growth::RefcountGrowthPlan;
use qcow2_write::{set_refcount_in_block, TargetDevice, L1_OFFSET_MASK, MAX_REFBLOCKS};

/// A failed growth execution, region-agnostically. The op renders each
/// to its own wire code (bench: `StageOutOfCoverage` →
/// `ERROR_PARSE_FAILED`, `WriteFailed` → `ERROR_IO_WRITE`, `FsyncFailed`
/// → `ERROR_IO_FLUSH`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GrowthExecError {
    /// A refcount to stage fell outside the staged coverage — the
    /// planner's self-coverage invariant was violated, a would-be
    /// internal bug rather than a data condition.
    StageOutOfCoverage,
    /// A device byte-range write returned failure.
    WriteFailed,
    /// A durability fsync ran and reported failure (a degraded barrier —
    /// no fsync primitive — never fails; see [`grow_refcounts`]).
    FsyncFailed,
}

/// The on-disk geometry of the image's refcount table, the only header
/// fields growth needs (passed as plain values so the crate stays
/// `QcowHeader`-agnostic).
#[derive(Debug, Clone, Copy)]
pub struct RefcountTable {
    /// `hdr.refcount_table_offset` — byte offset of the current RT.
    pub offset: u64,
    /// `hdr.refcount_table_clusters` — its cluster count (the relocating
    /// path frees these clusters after the header flip).
    pub clusters: u32,
}

/// The op-carved scratch the growth executor stages into and flushes
/// from. The three slices are disjoint regions of the op's scratch
/// carve (never `static` — the `.bss`/HEADER_MISMATCH hazard class):
///
/// - `refcount_table` — the staged refcount table. Must be large enough
///   for the full relocated table (`new_rt_clusters * cluster_size`) on
///   the relocating path, not just the populated prefix.
/// - `refblocks` — the staged refblocks, one cluster per slot, indexed
///   by slot. Must cover `needed_slots` clusters.
/// - `rmw_sector` — the sub-sector read-modify-write bounce for
///   [`crate::write_bytes`], at least one device sector.
pub struct GrowthBuffers<'a> {
    /// Staged refcount table bytes.
    pub refcount_table: &'a mut [u8],
    /// Staged refblock bytes (slot `k` at `[k*cs, (k+1)*cs)`).
    pub refblocks: &'a mut [u8],
    /// RMW bounce sector for the byte-range writes.
    pub rmw_sector: &'a mut [u8],
}

/// The growth executor's working state: the staged geometry plus the
/// per-refblock dirty bitset. Built with the populated refblock count;
/// [`grow_refcounts`] advances [`Self::refblock_count`] to the grown
/// slot set, which the op reads back after growth.
pub struct GrowthExec {
    cluster_size: u64,
    entries_per_refblock: u64,
    refblock_count: usize,
    /// Per-refblock dirty bitset (`MAX_REFBLOCKS` slots pack into words).
    dirty: [u64; MAX_REFBLOCKS / 64],
}

impl GrowthExec {
    /// Start from the populated staged set. `refblock_count` is the
    /// gap-free populated-refblock prefix the op staged (`<=
    /// MAX_REFBLOCKS`).
    pub fn new(cluster_size: u64, entries_per_refblock: u64, refblock_count: usize) -> GrowthExec {
        GrowthExec {
            cluster_size,
            entries_per_refblock,
            refblock_count,
            dirty: [0u64; MAX_REFBLOCKS / 64],
        }
    }

    /// The staged refblock slot count — the populated count before
    /// growth, the grown count after a successful [`grow_refcounts`].
    pub fn refblock_count(&self) -> usize {
        self.refblock_count
    }

    fn dirty_set(&mut self, slot: usize) {
        self.dirty[slot / 64] |= 1u64 << (slot % 64);
    }

    fn dirty_clear(&mut self, slot: usize) {
        self.dirty[slot / 64] &= !(1u64 << (slot % 64));
    }

    fn dirty_get(&self, slot: usize) -> bool {
        self.dirty[slot / 64] & (1u64 << (slot % 64)) != 0
    }
}

/// Read a big-endian u64 from `buf` at byte offset `off`.
fn read_u64_be(buf: &[u8], off: usize) -> u64 {
    u64::from_be_bytes([
        buf[off],
        buf[off + 1],
        buf[off + 2],
        buf[off + 3],
        buf[off + 4],
        buf[off + 5],
        buf[off + 6],
        buf[off + 7],
    ])
}

/// Set the staged refcount for host cluster `cluster` to `value` and
/// mark its covering refblock dirty (growth-time staging). Returns
/// `false` when the cluster falls outside the staged coverage —
/// impossible for planner-vetted growth inputs (self-coverage
/// invariant); the caller surfaces an internal-bug refusal rather than
/// corrupt on a would-be internal bug.
fn stage_refcount(exec: &mut GrowthExec, refblocks: &mut [u8], cluster: u64, value: u64) -> bool {
    let slot = (cluster / exec.entries_per_refblock) as usize;
    if slot >= exec.refblock_count {
        return false;
    }
    let cs = exec.cluster_size as usize;
    let block = &mut refblocks[slot * cs..slot * cs + cs];
    if set_refcount_in_block(block, cluster % exec.entries_per_refblock, 16, value).is_err() {
        return false;
    }
    exec.dirty_set(slot);
    true
}

/// Write back every dirty staged refblock to its host offset (refcounts
/// last) via the executor's byte-range layer, then clear the dirty
/// flags. The host offset for slot `k` comes from the staged refcount
/// table (`rt`).
fn flush_dirty_refblocks(
    devices: &mut impl DeviceIo,
    device: TargetDevice,
    exec: &mut GrowthExec,
    rt: &[u8],
    refblocks: &[u8],
    rmw: &mut [u8],
) -> bool {
    let cs = exec.cluster_size as usize;
    let mut slot = 0usize;
    while slot < exec.refblock_count {
        // Skip a whole all-clean 64-slot word in one step.
        if slot.is_multiple_of(64) && exec.dirty[slot / 64] == 0 {
            slot += 64;
            continue;
        }
        if exec.dirty_get(slot) {
            let host_off = read_u64_be(rt, slot * 8) & L1_OFFSET_MASK;
            let src = &refblocks[slot * cs..slot * cs + cs];
            if write_bytes(devices, device, host_off, src, rmw).is_err() {
                return false;
            }
            exec.dirty_clear(slot);
        }
        slot += 1;
    }
    true
}

/// Perform a growth-time durability fsync on `device`.
///
/// Mirrors the executor's `BarrierClass::Durability` policy (crate
/// docs, policy (e)) so the census is region-agnostic: a fsync-capable
/// device performs a REAL fsync (`Some(true)`); a device with no fsync
/// primitive degrades to ordering (`None`) and succeeds silently
/// (divergence D8); a fsync that runs and reports failure
/// (`Some(false)`) is a hard error. bench passes a fsync-ENABLED
/// `Input0`, so every growth fsync here is REAL — the phase-6 census (1
/// in-place / 2 relocation) is preserved exactly.
fn durability(devices: &mut impl DeviceIo, device: TargetDevice) -> Result<(), GrowthExecError> {
    match devices.fsync(device) {
        Some(false) => Err(GrowthExecError::FsyncFailed),
        _ => Ok(()),
    }
}

/// Grow the staged refcount coverage to `plan.needed_slots` refblocks,
/// pre-bracket (PLAN-bench-refcount-growth). New structures are placed
/// contiguously at the cluster-aligned current file end. Write ordering
/// (mirroring snapshot create's grouped fsync discipline): staged
/// refblocks → refcount table → fsync → header pointer flip (relocation
/// only) → fsync → the old RT's staged free. All I/O is routed through
/// the executor's byte-range layer against `device`; the durability
/// fsyncs follow `device`'s fsync capability (see [`durability`]).
///
/// The #433 fix (materialize every RT-referenced refblock) is
/// preserved: every newly provisioned refblock is marked dirty before
/// the eager flush, so even the refblocks an overwrite-only run leaves
/// at all-zero refcounts are written out.
///
/// On the relocating path the old-RT free is PERSISTED here (an extra
/// byte-range write, no extra fsync) rather than deferred to the run
/// cadence, because a migrated run flushes via `plan_flush` over its
/// OWN dirty state, which never sees this free.
///
/// Callers gate on `plan.new_refblocks > 0` before calling.
#[allow(clippy::too_many_arguments)]
pub fn grow_refcounts(
    devices: &mut impl DeviceIo,
    device: TargetDevice,
    exec: &mut GrowthExec,
    plan: &RefcountGrowthPlan,
    rt_table: RefcountTable,
    bufs: &mut GrowthBuffers<'_>,
) -> Result<(), GrowthExecError> {
    let cs = exec.cluster_size;
    let cluster_usize = cs as usize;
    let old_slots = exec.refblock_count;
    let new_slots = plan.needed_slots as usize;
    let relocating = plan.new_rt_clusters > 0;

    // ---- Stage the extended refcount-table image ----
    // In place: only the new slot entries. Relocating: the FULL new
    // table — the populated prefix is already staged; zero the tail then
    // fill the new entries (which also become the flush offset source).
    let rt_image_len = if relocating {
        (plan.new_rt_clusters * cs) as usize
    } else {
        new_slots * 8
    };
    {
        let rt_buf = &mut bufs.refcount_table[..rt_image_len];
        if relocating {
            rt_buf[old_slots * 8..].fill(0);
        }
        for j in 0..plan.new_refblocks as usize {
            let slot = old_slots + j;
            let host_off = (plan.refblocks_start + j as u64) * cs;
            rt_buf[slot * 8..slot * 8 + 8].copy_from_slice(&host_off.to_be_bytes());
        }
    }

    // ---- New refblocks: zeroed staging bytes ----
    bufs.refblocks[old_slots * cluster_usize..new_slots * cluster_usize].fill(0);

    // The flush and refcount staging below see the grown slot set.
    exec.refblock_count = new_slots;

    // ---- Refcount 1 for every new structure cluster ----
    for i in 0..plan.new_rt_clusters + plan.new_refblocks {
        if !stage_refcount(exec, &mut bufs.refblocks[..], plan.structures_start + i, 1) {
            return Err(GrowthExecError::StageOutOfCoverage);
        }
    }

    // ---- Materialize every newly provisioned refblock (#433) ----
    // Every RT-referenced refblock MUST exist on disk, even the ones an
    // overwrite-only run leaves at all-zero refcounts.
    for slot in old_slots..new_slots {
        exec.dirty_set(slot);
    }

    // ---- Eager flush of every dirty staged refblock ----
    if !flush_dirty_refblocks(
        devices,
        device,
        exec,
        &bufs.refcount_table[..],
        &bufs.refblocks[..],
        &mut bufs.rmw_sector[..],
    ) {
        return Err(GrowthExecError::WriteFailed);
    }

    // ---- Refcount table ----
    if relocating {
        if write_bytes(
            devices,
            device,
            plan.rt_start * cs,
            &bufs.refcount_table[..rt_image_len],
            &mut bufs.rmw_sector[..],
        )
        .is_err()
        {
            return Err(GrowthExecError::WriteFailed);
        }
    } else {
        let start = old_slots * 8;
        let len = (new_slots - old_slots) * 8;
        if write_bytes(
            devices,
            device,
            rt_table.offset + start as u64,
            &bufs.refcount_table[start..start + len],
            &mut bufs.rmw_sector[..],
        )
        .is_err()
        {
            return Err(GrowthExecError::WriteFailed);
        }
    }
    durability(devices, device)?;

    if relocating {
        // ----- The commit point: 12 header bytes at offset 48 -----
        let mut header_patch = [0u8; 12];
        header_patch[0..8].copy_from_slice(&(plan.rt_start * cs).to_be_bytes());
        header_patch[8..12].copy_from_slice(&(plan.new_rt_clusters as u32).to_be_bytes());
        if write_bytes(devices, device, 48, &header_patch, &mut bufs.rmw_sector[..]).is_err() {
            return Err(GrowthExecError::WriteFailed);
        }
        durability(devices, device)?;

        // ----- Free the old table (staged), then PERSIST it -----
        // AFTER the header flip. A crash in the window leaves the old
        // table refcounted-but-unreferenced — a repairable leak, the
        // op's documented crash class. Persisted here (no extra fsync —
        // the census stays 2) because a migrated run's plan_flush only
        // writes back the CRATE's own dirty refblocks, not this one.
        let first = rt_table.offset / cs;
        for c in 0..rt_table.clusters as u64 {
            if !stage_refcount(exec, &mut bufs.refblocks[..], first + c, 0) {
                return Err(GrowthExecError::StageOutOfCoverage);
            }
        }
        if !flush_dirty_refblocks(
            devices,
            device,
            exec,
            &bufs.refcount_table[..],
            &bufs.refblocks[..],
            &mut bufs.rmw_sector[..],
        ) {
            return Err(GrowthExecError::WriteFailed);
        }
    }
    Ok(())
}
