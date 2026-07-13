//! Simulation harness for the write planner (phase 8a lift).
//!
//! A minimal executor over Vec-backed staging + disk, mirroring what
//! the phase 4-6 guest ops do with the emitted programs. This module
//! was lifted **verbatim** out of the crate's `#[cfg(test)] mod tests`
//! so both the in-crate unit tests and the `fuzz_qcow2_write`
//! cargo-fuzz target can drive [`plan_write`]/[`plan_flush`] through
//! the same `BufFull`-resume loop and assert the same invariants
//! (refcounts, COPIED flags, snapshot-cluster preservation). It is a
//! pure move: the unit tests import it via `use super::sim::*` and
//! pass unchanged.
//!
//! Gated behind `cfg(any(test, feature = "sim"))` — OFF in the
//! production build, so no `std` links into the guest ops. The fuzz
//! crate enables the `sim` feature.

use crate::*;
use std::vec;
use std::vec::Vec;

/// Parameterised v3 header for the planner tests (the 3a
/// `header_bytes` keeps its fixed shape for the gate tests).
/// Layout convention: cluster 0 header, cluster 1 refcount
/// table, cluster 2 refblock 0, cluster 3 L1, clusters 4+
/// free.
pub fn build_header(
    cluster_bits: u32,
    virtual_size: u64,
    l1_size: u32,
    backing_off: u64,
) -> [u8; 4096] {
    let cs = 1u64 << cluster_bits;
    let mut h = [0u8; 4096];
    h[0..4].copy_from_slice(&qcow2::QCOW2_MAGIC.to_be_bytes());
    h[4..8].copy_from_slice(&3u32.to_be_bytes());
    h[8..16].copy_from_slice(&backing_off.to_be_bytes());
    if backing_off != 0 {
        h[16..20].copy_from_slice(&4u32.to_be_bytes());
    }
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

pub fn parse(h: &[u8]) -> QcowHeader {
    QcowHeader::parse(h).expect("synthetic header must parse")
}

pub fn step(kind: StepKind) -> Step {
    Step {
        kind,
        device: TargetDevice::Output,
        region: RegionId::Bounce,
        region_offset: 0,
        disk_offset: 0,
        len: 0,
        value: 0,
    }
}

/// Executor-side stand-in: the staged buffers an op carves
/// from scratch, plus a Vec-backed disk. Sentinel fills
/// (0xEE) make zero-fills and stale reads observable; the
/// disk grows on demand so far-flung allocations stay in
/// range.
pub struct TestImg {
    pub hdr: QcowHeader,
    pub cs: usize,
    pub disk: Vec<u8>,
    pub l1: Vec<u8>,
    pub l2win: Vec<u8>,
    pub rt: Vec<u8>,
    pub refblocks: Vec<u8>,
    pub caller: Vec<u8>,
    /// Cluster-sized bounce buffer for COW pre-image reads
    /// (`ReadCluster` -> `RegionId::Bounce`).
    pub bounce: Vec<u8>,
    pub barriers: Vec<BarrierClass>,
}

/// Build a clean image (no backing) plus its gated state:
/// `virtual_size` = 4 L2 tables of coverage, `l1_size` = 4.
pub fn mk(cluster_bits: u32, l2_slots: usize, backing: bool) -> (TestImg, WriteState) {
    let cs = 1usize << cluster_bits;
    let l2_coverage = (cs as u64 / 8) * cs as u64;
    mk_vs(cluster_bits, l2_slots, backing, 4 * l2_coverage)
}

/// [`mk`] with an explicit `virtual_size` (still `l1_size` =
/// 4): the EOV-tail tests need unaligned sizes (the phase-4
/// plan's amended decision 7).
pub fn mk_vs(
    cluster_bits: u32,
    l2_slots: usize,
    backing: bool,
    virtual_size: u64,
) -> (TestImg, WriteState) {
    let cs = 1usize << cluster_bits;
    let hdr = parse(&build_header(
        cluster_bits,
        virtual_size,
        4,
        if backing { 200 } else { 0 },
    ));
    let mut refblocks = vec![0u8; cs];
    for c in 0..4u64 {
        snapshot::qcow2::set_refcount_in_block(&mut refblocks, c, 16, 1).unwrap();
    }
    let img = TestImg {
        hdr,
        cs,
        disk: vec![0xEE; 16 * cs],
        l1: vec![0u8; 4 * 8],
        l2win: vec![0xEE; l2_slots * cs],
        rt: (2 * cs as u64).to_be_bytes().to_vec(),
        refblocks,
        caller: (0..4 * cs).map(|i| (i % 251) as u8).collect(),
        bounce: vec![0xEE; cs],
        barriers: Vec::new(),
    };
    let cfg = StagingConfig {
        l2_slots,
        max_refblocks: 32,
        device: TargetDevice::Input0,
    };
    let st = new_state(&img.hdr, &cfg).unwrap();
    (img, st)
}

/// Set an L1 entry in the staged copy AND on disk.
pub fn set_l1(img: &mut TestImg, idx: usize, value: u64) {
    img.l1[idx * 8..idx * 8 + 8].copy_from_slice(&value.to_be_bytes());
    let off = 3 * img.cs + idx * 8;
    img.disk[off..off + 8].copy_from_slice(&value.to_be_bytes());
}

pub fn put_disk_u64(img: &mut TestImg, off: usize, value: u64) {
    img.disk[off..off + 8].copy_from_slice(&value.to_be_bytes());
}

pub fn set_rc(img: &mut TestImg, cluster: u64, value: u64) {
    snapshot::qcow2::set_refcount_in_block(&mut img.refblocks, cluster, 16, value).unwrap();
}

pub fn rc_of(img: &TestImg, cluster: u64) -> u64 {
    snapshot::qcow2::read_refcount_in_block(&img.refblocks, cluster, 16).unwrap()
}

/// Persist an allocated mapping: L2 table at cluster 4
/// (zeroed on disk), data cluster 5 mapped at `l2_idx` of L1
/// slot 0, refcounts 1.
pub fn add_allocated_cluster(img: &mut TestImg, l2_idx: usize, l1_flags: u64, l2_flags: u64) {
    let cs = img.cs;
    set_l1(img, 0, (4 * cs as u64) | l1_flags);
    for b in &mut img.disk[4 * cs..5 * cs] {
        *b = 0;
    }
    put_disk_u64(img, 4 * cs + l2_idx * 8, (5 * cs as u64) | l2_flags);
    set_rc(img, 4, 1);
    set_rc(img, 5, 1);
}

fn region_mut(img: &mut TestImg, region: RegionId) -> (&mut [u8], usize) {
    let cs = img.cs;
    match region {
        RegionId::L1 => (img.l1.as_mut_slice(), 0),
        RegionId::L2Slot(v) => (img.l2win.as_mut_slice(), v as usize * cs),
        RegionId::RefcountTable => (img.rt.as_mut_slice(), 0),
        RegionId::Refblocks => (img.refblocks.as_mut_slice(), 0),
        RegionId::CallerData => (img.caller.as_mut_slice(), 0),
        RegionId::Bounce => (img.bounce.as_mut_slice(), 0),
    }
}

fn region_bytes(img: &mut TestImg, region: RegionId, off: usize, len: usize) -> Vec<u8> {
    let (buf, base) = region_mut(img, region);
    buf[base + off..base + off + len].to_vec()
}

/// Apply an emitted window literally (the executor role).
pub fn exec(img: &mut TestImg, steps: &[Step]) {
    let cs = img.cs;
    for s in steps {
        let dof = s.disk_offset as usize;
        let len = s.len as usize;
        if matches!(
            s.kind,
            StepKind::WriteRange
                | StepKind::ZeroRange
                | StepKind::FillRange
                | StepKind::WritebackCluster
        ) && img.disk.len() < dof + len
        {
            img.disk.resize(dof + len, 0xEE);
        }
        match s.kind {
            StepKind::WriteRange => {
                let src = region_bytes(img, s.region, s.region_offset as usize, len);
                img.disk[dof..dof + len].copy_from_slice(&src);
            }
            StepKind::ZeroRange => img.disk[dof..dof + len].fill(0),
            StepKind::FillRange => img.disk[dof..dof + len].fill(s.value as u8),
            StepKind::PatchEntryU64 => {
                let value = s.value;
                let (buf, base) = region_mut(img, s.region);
                let off = base + s.region_offset as usize;
                buf[off..off + 8].copy_from_slice(&value.to_be_bytes());
            }
            StepKind::LoadCluster => {
                let src = img.disk[dof..dof + cs].to_vec();
                let (buf, base) = region_mut(img, s.region);
                let off = base + s.region_offset as usize;
                buf[off..off + cs].copy_from_slice(&src);
            }
            StepKind::WritebackCluster => {
                let src = region_bytes(img, s.region, s.region_offset as usize, cs);
                img.disk[dof..dof + cs].copy_from_slice(&src);
            }
            StepKind::ZeroRegion => {
                let (buf, base) = region_mut(img, s.region);
                let off = base + s.region_offset as usize;
                buf[off..off + len].fill(0);
            }
            StepKind::Barrier { class } => img.barriers.push(class),
            StepKind::ReadCluster => {
                // COW pre-image read: device -> region (Bounce).
                let src = img.disk[dof..dof + len].to_vec();
                let (buf, base) = region_mut(img, s.region);
                let off = base + s.region_offset as usize;
                buf[off..off + len].copy_from_slice(&src);
            }
        }
    }
}

/// The decision-1 executor loop for one write request:
/// plan / execute / reset until `Ok` or a real error.
/// Returns the concatenated program (all windows in order).
pub fn run_write(
    img: &mut TestImg,
    st: &mut WriteState,
    voff: u64,
    len: u64,
    data: DataSource,
    cap: usize,
) -> Result<Vec<Step>, (WriteError, Vec<Step>)> {
    let mut all = Vec::new();
    let mut storage = vec![step(StepKind::ZeroRange); cap];
    for _ in 0..100_000 {
        let mut buf = StepBuf::new(&mut storage);
        let r = {
            let mut sv = StagedRegions {
                l1: &img.l1,
                l2_window: &img.l2win,
                refcount_table: &img.rt,
                refblocks: &mut img.refblocks,
            };
            plan_write(st, &mut sv, voff, len, data, &mut buf)
        };
        let emitted = buf.steps().to_vec();
        exec(img, &emitted);
        all.extend(emitted);
        match r {
            Ok(_) => return Ok(all),
            Err(WriteError::BufFull) => continue,
            Err(e) => return Err((e, all)),
        }
    }
    panic!("write request failed to converge");
}

pub fn run_write_ok(
    img: &mut TestImg,
    st: &mut WriteState,
    voff: u64,
    len: u64,
    data: DataSource,
    cap: usize,
) -> Vec<Step> {
    run_write(img, st, voff, len, data, cap).expect("write must plan cleanly")
}

pub fn run_write_err(
    img: &mut TestImg,
    st: &mut WriteState,
    voff: u64,
    len: u64,
    data: DataSource,
) -> WriteError {
    run_write(img, st, voff, len, data, 128)
        .expect_err("write must refuse")
        .0
}

/// The executor loop for a flush.
pub fn run_flush(
    img: &mut TestImg,
    st: &mut WriteState,
    cap: usize,
) -> Result<Vec<Step>, (WriteError, Vec<Step>)> {
    let mut all = Vec::new();
    let mut storage = vec![step(StepKind::ZeroRange); cap];
    for _ in 0..100_000 {
        let mut buf = StepBuf::new(&mut storage);
        let r = {
            let mut sv = StagedRegions {
                l1: &img.l1,
                l2_window: &img.l2win,
                refcount_table: &img.rt,
                refblocks: &mut img.refblocks,
            };
            plan_flush(st, &mut sv, &mut buf)
        };
        let emitted = buf.steps().to_vec();
        exec(img, &emitted);
        all.extend(emitted);
        match r {
            Ok(_) => return Ok(all),
            Err(WriteError::BufFull) => continue,
            Err(e) => return Err((e, all)),
        }
    }
    panic!("flush failed to converge");
}

pub fn run_flush_ok(img: &mut TestImg, st: &mut WriteState, cap: usize) -> Vec<Step> {
    run_flush(img, st, cap).expect("flush must plan cleanly")
}

pub fn kinds(steps: &[Step]) -> Vec<StepKind> {
    steps.iter().map(|s| s.kind).collect()
}

pub fn caller_data() -> DataSource {
    DataSource::CallerData { offset: 0 }
}

// =====================================================================
// Phase 7 copy-on-write (C1-C4) fixtures + assertion helpers. The
// `mk`/`exec`/`run_write`/`run_flush` harness above is the simulation:
// it applies every emitted step to the Vec-backed image, so each
// test's/target's post-state assertions (refcounts, COPIED flags,
// snapshot clusters intact, structural validity) verify the schedule
// end to end.
// =====================================================================

/// A copy-on-write state over the same clean image `mk` builds
/// (`new_state_cow`, so snapshot-shared clusters COW instead of
/// refusing).
pub fn mk_cow(cluster_bits: u32, l2_slots: usize) -> (TestImg, WriteState) {
    let (img, _) = mk(cluster_bits, l2_slots, false);
    let cfg = StagingConfig {
        l2_slots,
        max_refblocks: 32,
        device: TargetDevice::Input0,
    };
    let st = new_state_cow(&img.hdr, &cfg).unwrap();
    (img, st)
}

/// Highest staged refcount over clusters `[0, upto)`. The
/// corruption signature COW must NEVER produce is any rc >= 3
/// (a child bumped past its snapshot-creation rc of 2).
pub fn max_rc(img: &TestImg, upto: u64) -> u64 {
    (0..upto).map(|c| rc_of(img, c)).max().unwrap_or(0)
}

pub fn disk_u64(img: &TestImg, off: usize) -> u64 {
    read_u64_be(&img.disk, off)
}

/// Owned L2 table T at cluster 4 (L1[0] -> 4 | COPIED, rc 1),
/// zeroed on disk. The caller sets L2[0] and the child rc.
pub fn add_owned_l2(img: &mut TestImg) {
    let cs = img.cs;
    set_l1(img, 0, 4 * cs as u64 | OFLAG_COPIED);
    for b in &mut img.disk[4 * cs..5 * cs] {
        *b = 0;
    }
    set_rc(img, 4, 1);
}

/// Owned L2 table (cluster 4) with a snapshot-shared child data
/// cluster D at cluster 5, index `l2_idx`: COPIED clear + rc 2.
pub fn add_shared_data(img: &mut TestImg, l2_idx: usize) {
    add_allocated_cluster(img, l2_idx, OFLAG_COPIED, 0); // child COPIED clear
    set_rc(img, 5, 2); // shared with a snapshot
}

/// Snapshot-shared L2 table T (cluster 4, COPIED clear, rc 2)
/// with two shared children D0 (cluster 5, index 0) and D1
/// (cluster 6, index 1), both COPIED clear + rc 2 — the nested
/// (shared-L2-over-shared-data) fixture (7p probe5).
pub fn add_shared_l2_two_children(img: &mut TestImg) {
    let cs = img.cs;
    set_l1(img, 0, 4 * cs as u64); // T, COPIED clear -> shared
    for b in &mut img.disk[4 * cs..5 * cs] {
        *b = 0;
    }
    put_disk_u64(img, 4 * cs, 5 * cs as u64); // idx 0 -> D0 shared
    put_disk_u64(img, 4 * cs + 8, 6 * cs as u64); // idx 1 -> D1 shared
    set_rc(img, 4, 2);
    set_rc(img, 5, 2);
    set_rc(img, 6, 2);
}
