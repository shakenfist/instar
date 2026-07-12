//! Step-3d simulation harness for the qcow2-write planner
//! (`docs/plans/PLAN-qcow2-write-infrastructure-phase-03-crate.md`).
//!
//! A `Sim` executor (Vec<u8>-backed `SimDisk` per device) applies
//! emitted step programs literally — the full `StepKind`
//! vocabulary, per the doc contracts — and honours barriers by
//! epoch-tagging every disk write with the count of barriers that
//! preceded it. Images are built programmatically with the
//! `create` dev-dependency (the `crates/commit` test precedent).
//!
//! For a grid of {cluster size 512 / 4096 / 65536 / 2 MiB ×
//! image size × write pattern (sequential, sparse, straddling,
//! sub-cluster, repeated overwrite)} each scenario runs the
//! decision-1 loop (plan a window, execute it, resume) to
//! completion plus `plan_flush`, then asserts three families:
//!
//! 1. `assert_virtual_content_matches_model` — the re-parsed
//!    image's virtual content equals a `BTreeMap<u64, Vec<u8>>`
//!    reference model maintained alongside the writes.
//! 2. `full_consistency_walk` — L1/L2/refcount consistency:
//!    every reachable cluster has refcount exactly 1 (v1, no
//!    snapshots), COPIED set on every allocated entry, no
//!    double-allocation, refblock coverage of every allocated
//!    cluster, no leaked refcounts, and sane file-length growth.
//! 3. `crash_consistency_scan` — the executed step stream is
//!    truncated at EVERY Durability barrier boundary (barriers
//!    are data in the journal); each truncated image passes a
//!    structural walk (no L1/L2 pointer references a cluster
//!    whose data/init writes were not yet replayed) and its
//!    virtual content is byte-wise old-or-new relative to the
//!    barrier's flush epoch.
//!
//! The staged refblocks are mutated by the PLANNER at plan time
//! (decision 6); the disk sees refcount changes only via
//! `plan_flush`'s write-back steps, so the crash checks replay
//! refblock bytes from the journal (the bytes captured when the
//! write-back executed), never from planner state.
//!
//! Deviations the harness cannot express (reported, not
//! weakened): at intermediate truncation points the FULL
//! refcount walk cannot hold by design — decision 7(c) orders
//! refcount write-backs last, so a truncation after the L1/L2
//! write-backs but before the refblock write-backs legitimately
//! shows reachable clusters with on-disk refcount 0. The full
//! walk therefore runs on completed epochs; truncation points
//! get the structural + content checks above.

use std::collections::{BTreeMap, BTreeSet};

use create::{plan_qcow2, BackingRef, Qcow2CreateOpts, QCOW2_MAX_METADATA_SCRATCH};
use qcow2::{QcowHeader, L1_OFFSET_MASK, L2_OFFSET_MASK, OFLAG_COMPRESSED, OFLAG_COPIED};
use qcow2_write::{
    new_state, plan_flush, plan_write, BarrierClass, DataSource, RegionId, StagingConfig, Step,
    StepBuf, StepKind, TargetDevice, WriteError, WriteState,
};
use shared::ImageFormat;

/// Deliberately small step window so every scenario exercises
/// multi-window resume (window-invariance itself is step 3c's
/// property; here windows just have to compose correctly).
const STEP_CAP: usize = 12;

/// L2 window slots: small enough that multi-L2 scenarios evict.
const L2_SLOTS: usize = 2;

const MAX_REFBLOCKS: usize = 32;

/// Sentinel for never-written disk growth and staged-slot bytes;
/// any read of it is observable as neither old, new nor zero.
const SENTINEL: u8 = 0xEE;

fn be64(b: &[u8], off: usize) -> u64 {
    u64::from_be_bytes(b[off..off + 8].try_into().unwrap())
}

fn be16(b: &[u8], off: usize) -> u16 {
    u16::from_be_bytes(b[off..off + 2].try_into().unwrap())
}

/// Deterministic caller-data byte (no RNG anywhere in the
/// harness): a fixed function of the write's seed and position.
fn pattern_byte(seed: u8, i: u64) -> u8 {
    (i.wrapping_mul(131).wrapping_add(seed as u64 * 7) % 251) as u8
}

// ---------------------------------------------------------------------------
// Programmatic image construction (crates/commit's precedent)
// ---------------------------------------------------------------------------

/// Build a minimal valid qcow2 v3 image via `create::plan_qcow2`
/// and materialise it into bytes (header cluster, empty L1,
/// refcount table, refblocks — Preallocation::Off).
fn build_image(
    cluster_bits: u32,
    virtual_size: u64,
    backing: Option<&[u8]>,
) -> (Vec<u8>, QcowHeader) {
    let opts = Qcow2CreateOpts {
        virtual_size,
        cluster_size: 1u32 << cluster_bits,
        refcount_bits: 16,
        extended_l2: false,
        lazy_refcounts: false,
        compat_v3: true,
        backing: backing.map(|path| BackingRef {
            path,
            format: Some(ImageFormat::Qcow2),
        }),
        preallocation: qcow2::create::Preallocation::Off,
    };
    let mut scratch = vec![0u8; QCOW2_MAX_METADATA_SCRATCH];
    let plan = plan_qcow2(&opts, &mut scratch).expect("create plan");
    let mut bytes = vec![0u8; plan.minimum_file_size as usize];
    for w in plan.writes() {
        let start = w.byte_offset as usize;
        bytes[start..start + w.bytes.len()].copy_from_slice(w.bytes);
    }
    let hdr = QcowHeader::parse(&bytes[..bytes.len().min(4096)]).expect("parse built image");
    (bytes, hdr)
}

fn parse_disk_header(disk: &[u8]) -> QcowHeader {
    QcowHeader::parse(&disk[..disk.len().min(4096)]).expect("parse image under test")
}

// ---------------------------------------------------------------------------
// Reference model: BTreeMap of written byte ranges
// ---------------------------------------------------------------------------

/// The virtual-content reference model: non-overlapping written
/// ranges keyed by start offset; unwritten bytes are zero
/// (backing-less images).
struct RefModel {
    ranges: BTreeMap<u64, Vec<u8>>,
    virtual_size: u64,
}

impl RefModel {
    fn new(virtual_size: u64) -> RefModel {
        RefModel {
            ranges: BTreeMap::new(),
            virtual_size,
        }
    }

    /// Record a write, splicing any overlapped older ranges.
    fn write(&mut self, off: u64, bytes: &[u8]) {
        let end = off + bytes.len() as u64;
        assert!(end <= self.virtual_size, "model write out of bounds");
        let mut affected: Vec<u64> = self.ranges.range(off..end).map(|(k, _)| *k).collect();
        if let Some((&k, v)) = self.ranges.range(..off).next_back() {
            if k + v.len() as u64 > off {
                affected.push(k);
            }
        }
        for k in affected {
            let v = self.ranges.remove(&k).unwrap();
            let kend = k + v.len() as u64;
            if k < off {
                self.ranges.insert(k, v[..(off - k) as usize].to_vec());
            }
            if kend > end {
                self.ranges.insert(end, v[(end - k) as usize..].to_vec());
            }
        }
        self.ranges.insert(off, bytes.to_vec());
    }

    /// Materialise the model into a full virtual-content buffer.
    fn materialise(&self) -> Vec<u8> {
        let mut out = vec![0u8; self.virtual_size as usize];
        for (&start, bytes) in &self.ranges {
            out[start as usize..start as usize + bytes.len()].copy_from_slice(bytes);
        }
        out
    }
}

// ---------------------------------------------------------------------------
// SimDisk executor
// ---------------------------------------------------------------------------

const DEV_IN0: usize = 0;
const DEV_OUT: usize = 1;

/// One materialised disk write in the executed step stream,
/// epoch-tagged with the number of barriers that preceded it
/// (the executor's barrier honouring: a write's tag proves which
/// side of every barrier it executed on).
struct JournalWrite {
    device: usize,
    off: usize,
    bytes: Vec<u8>,
    epoch_tag: u64,
}

/// The executed step stream as data: disk writes plus barriers
/// (each barrier remembers which flush epoch emitted it).
enum JournalEntry {
    Write(JournalWrite),
    Barrier {
        class: BarrierClass,
        flush_idx: usize,
    },
}

/// The executor: Vec<u8>-backed disks (one per `TargetDevice`)
/// plus the staged regions the planner's `RegionId`s map onto,
/// initialised per the `StagedRegions` doc contract.
struct Sim {
    disks: [Vec<u8>; 2],
    l1: Vec<u8>,
    l2win: Vec<u8>,
    rt: Vec<u8>,
    refblocks: Vec<u8>,
    bounce: Vec<u8>,
    caller: Vec<u8>,
    cs: usize,
    journal: Vec<JournalEntry>,
    barrier_count: u64,
    flush_idx: usize,
}

impl Sim {
    /// Stage the image per the `StagedRegions` contract: the L1
    /// copy from disk, sentinel-filled L2 window slots, the
    /// refcount table bytes, and the refblocks as a dense prefix
    /// covering host clusters from offset zero (refcount-table
    /// entries 0..N in order).
    fn new(hdr: &QcowHeader, disk: Vec<u8>) -> Sim {
        let cs = hdr.cluster_size as usize;
        let l1_off = hdr.l1_table_offset as usize;
        let l1 = disk[l1_off..l1_off + hdr.l1_size as usize * 8].to_vec();
        let rt_off = hdr.refcount_table_offset as usize;
        let rt = disk[rt_off..rt_off + hdr.refcount_table_clusters as usize * cs].to_vec();
        let mut refblocks = Vec::new();
        let mut populated = 0;
        while populated * 8 < rt.len() {
            let entry = be64(&rt, populated * 8);
            if entry == 0 {
                break;
            }
            assert!(
                entry.is_multiple_of(cs as u64),
                "refblock offset must be aligned"
            );
            let start = entry as usize;
            refblocks.extend_from_slice(&disk[start..start + cs]);
            populated += 1;
        }
        for j in populated..rt.len() / 8 {
            assert_eq!(be64(&rt, j * 8), 0, "refcount table must be a dense prefix");
        }
        assert!((1..=MAX_REFBLOCKS).contains(&populated));
        Sim {
            disks: [disk, Vec::new()],
            l1,
            l2win: vec![SENTINEL; L2_SLOTS * cs],
            rt,
            refblocks,
            bounce: vec![0u8; cs],
            caller: Vec::new(),
            cs,
            journal: Vec::new(),
            barrier_count: 0,
            flush_idx: 0,
        }
    }

    fn set_caller(&mut self, bytes: &[u8]) {
        self.caller.clear();
        self.caller.extend_from_slice(bytes);
    }

    fn dev_idx(device: TargetDevice) -> usize {
        match device {
            TargetDevice::Input0 => DEV_IN0,
            TargetDevice::Output => DEV_OUT,
        }
    }

    fn region_ref(&mut self, region: RegionId) -> (&mut Vec<u8>, usize) {
        let cs = self.cs;
        match region {
            RegionId::L1 => (&mut self.l1, 0),
            RegionId::L2Slot(v) => (&mut self.l2win, v as usize * cs),
            RegionId::RefcountTable => (&mut self.rt, 0),
            RegionId::Refblocks => (&mut self.refblocks, 0),
            RegionId::Bounce => (&mut self.bounce, 0),
            RegionId::CallerData => (&mut self.caller, 0),
        }
    }

    fn region_bytes(&mut self, region: RegionId, off: usize, len: usize) -> Vec<u8> {
        let (buf, base) = self.region_ref(region);
        buf[base + off..base + off + len].to_vec()
    }

    /// Every disk mutation funnels through here: grow with
    /// sentinel (never-written bytes stay observable), apply,
    /// journal the materialised bytes with the current epoch tag.
    fn write_disk(&mut self, device: usize, off: usize, bytes: Vec<u8>) {
        let end = off + bytes.len();
        if self.disks[device].len() < end {
            self.disks[device].resize(end, SENTINEL);
        }
        self.disks[device][off..end].copy_from_slice(&bytes);
        self.journal.push(JournalEntry::Write(JournalWrite {
            device,
            off,
            bytes,
            epoch_tag: self.barrier_count,
        }));
    }

    /// Apply one emitted window literally, implementing the full
    /// `StepKind` vocabulary per the doc contracts.
    fn exec(&mut self, steps: &[Step]) {
        for s in steps {
            let dev = Sim::dev_idx(s.device);
            let dof = s.disk_offset as usize;
            let len = s.len as usize;
            match s.kind {
                StepKind::ReadCluster => {
                    // disk -> region (COW/RMW source reads; the v1
                    // planner does not emit it, but the executor
                    // implements the whole vocabulary).
                    let src = self.disks[dev][dof..dof + len].to_vec();
                    let (buf, base) = self.region_ref(s.region);
                    let off = base + s.region_offset as usize;
                    buf[off..off + len].copy_from_slice(&src);
                }
                StepKind::WriteRange => {
                    let src = self.region_bytes(s.region, s.region_offset as usize, len);
                    self.write_disk(dev, dof, src);
                }
                StepKind::ZeroRange => {
                    self.write_disk(dev, dof, vec![0u8; len]);
                }
                StepKind::FillRange => {
                    self.write_disk(dev, dof, vec![s.value as u8; len]);
                }
                StepKind::PatchEntryU64 => {
                    let value = s.value;
                    let (buf, base) = self.region_ref(s.region);
                    let off = base + s.region_offset as usize;
                    buf[off..off + 8].copy_from_slice(&value.to_be_bytes());
                }
                StepKind::LoadCluster => {
                    assert_eq!(len, self.cs, "LoadCluster must move one cluster");
                    let src = self.disks[dev][dof..dof + len].to_vec();
                    let (buf, base) = self.region_ref(s.region);
                    let off = base + s.region_offset as usize;
                    buf[off..off + len].copy_from_slice(&src);
                }
                StepKind::WritebackCluster => {
                    assert_eq!(len, self.cs, "WritebackCluster must move one cluster");
                    let src = self.region_bytes(s.region, s.region_offset as usize, len);
                    self.write_disk(dev, dof, src);
                }
                StepKind::ZeroRegion => {
                    let (buf, base) = self.region_ref(s.region);
                    let off = base + s.region_offset as usize;
                    buf[off..off + len].fill(0);
                }
                StepKind::Barrier { class } => {
                    self.journal.push(JournalEntry::Barrier {
                        class,
                        flush_idx: self.flush_idx,
                    });
                    self.barrier_count += 1;
                }
            }
        }
    }
}

fn blank_step() -> Step {
    Step {
        kind: StepKind::ZeroRange,
        device: TargetDevice::Input0,
        region: RegionId::Bounce,
        region_offset: 0,
        disk_offset: 0,
        len: 0,
        value: 0,
    }
}

fn staging_config() -> StagingConfig {
    StagingConfig {
        l2_slots: L2_SLOTS,
        max_refblocks: MAX_REFBLOCKS,
        device: TargetDevice::Input0,
    }
}

/// The decision-1 executor loop for one write request: plan a
/// window, execute it, reset, resume until `Ok` or a real error.
/// Returns the concatenated executed program.
fn run_write(
    sim: &mut Sim,
    st: &mut WriteState,
    voff: u64,
    len: u64,
    data: DataSource,
) -> Result<Vec<Step>, (WriteError, Vec<Step>)> {
    let mut all = Vec::new();
    let mut storage = vec![blank_step(); STEP_CAP];
    for _ in 0..100_000 {
        let mut buf = StepBuf::new(&mut storage);
        let r = {
            let mut staged = qcow2_write::StagedRegions {
                l1: &sim.l1,
                l2_window: &sim.l2win,
                refcount_table: &sim.rt,
                refblocks: &mut sim.refblocks,
            };
            plan_write(st, &mut staged, voff, len, data, &mut buf)
        };
        let emitted = buf.steps().to_vec();
        sim.exec(&emitted);
        all.extend(emitted);
        match r {
            Ok(_) => return Ok(all),
            Err(WriteError::BufFull) => continue,
            Err(e) => return Err((e, all)),
        }
    }
    panic!("write request failed to converge");
}

fn run_write_ok(
    sim: &mut Sim,
    st: &mut WriteState,
    voff: u64,
    len: u64,
    data: DataSource,
) -> Vec<Step> {
    run_write(sim, st, voff, len, data).expect("write must plan cleanly")
}

/// The executor loop for a flush; bumps the epoch index on
/// completion so journal barriers are attributed to their flush.
fn run_flush_ok(sim: &mut Sim, st: &mut WriteState) -> Vec<Step> {
    let mut all = Vec::new();
    let mut storage = vec![blank_step(); STEP_CAP];
    for _ in 0..100_000 {
        let mut buf = StepBuf::new(&mut storage);
        let r = {
            let mut staged = qcow2_write::StagedRegions {
                l1: &sim.l1,
                l2_window: &sim.l2win,
                refcount_table: &sim.rt,
                refblocks: &mut sim.refblocks,
            };
            plan_flush(st, &mut staged, &mut buf)
        };
        let emitted = buf.steps().to_vec();
        sim.exec(&emitted);
        all.extend(emitted);
        match r {
            Ok(_) => {
                sim.flush_idx += 1;
                return all;
            }
            Err(WriteError::BufFull) => continue,
            Err(e) => panic!("flush must plan cleanly, got {e:?}"),
        }
    }
    panic!("flush failed to converge");
}

// ---------------------------------------------------------------------------
// Assertion family 1: virtual content vs the reference model
// ---------------------------------------------------------------------------

/// Re-parse the image and read its full virtual content by
/// walking L1/L2 (overlay-local: unallocated clusters read as
/// zero; the grid uses backing-less images).
fn read_virtual(disk: &[u8]) -> Vec<u8> {
    let hdr = parse_disk_header(disk);
    let cs = hdr.cluster_size as usize;
    let epl2 = cs / 8;
    let mut out = vec![0u8; hdr.virtual_size as usize];
    let l1_off = hdr.l1_table_offset as usize;
    let nclusters = (hdr.virtual_size as usize).div_ceil(cs);
    for c in 0..nclusters {
        let l1_idx = c / epl2;
        assert!(l1_idx < hdr.l1_size as usize);
        let l1e = be64(disk, l1_off + l1_idx * 8);
        if l1e == 0 {
            continue;
        }
        let l2_host = (l1e & L1_OFFSET_MASK) as usize;
        let l2e = be64(disk, l2_host + (c % epl2) * 8);
        if l2e == 0 {
            continue;
        }
        let host = (l2e & L2_OFFSET_MASK) as usize;
        let vlen = cs.min(out.len() - c * cs);
        out[c * cs..c * cs + vlen].copy_from_slice(&disk[host..host + vlen]);
    }
    out
}

/// Family 1: the image's virtual content equals the reference
/// model — every written range byte-exact, every unwritten byte
/// zero.
fn assert_virtual_content_matches_model(disk: &[u8], model: &RefModel) {
    let content = read_virtual(disk);
    assert_eq!(content.len() as u64, model.virtual_size);
    let mut pos = 0usize;
    for (&start, bytes) in &model.ranges {
        let start = start as usize;
        assert!(
            content[pos..start].iter().all(|&b| b == 0),
            "unwritten virtual bytes [{pos:#x}, {start:#x}) must read zero"
        );
        assert_eq!(
            &content[start..start + bytes.len()],
            &bytes[..],
            "written range at {start:#x} (+{}) diverges from the model",
            bytes.len()
        );
        pos = start + bytes.len();
    }
    assert!(
        content[pos..].iter().all(|&b| b == 0),
        "trailing unwritten virtual bytes must read zero"
    );
}

// ---------------------------------------------------------------------------
// Assertion family 2: full metadata consistency walk
// ---------------------------------------------------------------------------

/// Family 2: walk L1/L2/refcounts of a completed image and
/// assert full consistency. Returns the on-disk refcount map
/// (host cluster index -> refcount) for cross-epoch comparisons.
///
/// Asserted here:
/// - every reachable cluster (header, L1, refcount table,
///   refblocks, L2 tables, data clusters) has refcount >= 1
///   (exactly 1 in the v1 no-snapshot envelope);
/// - no refcounted cluster is unreachable (no leaks after a
///   completed epoch);
/// - COPIED is set on every allocated L1/L2 entry, no compressed
///   entries, no unknown bits, aligned offsets;
/// - no double-allocation: no two pointers (or metadata roles)
///   name the same host cluster;
/// - refblock coverage: every allocated cluster's refcount is
///   reachable through the refcount table (a missing refblock
///   fails the refcount lookup);
/// - file-length growth is sane: the file ends exactly at the
///   end of the highest refcounted cluster and never shrank.
fn full_consistency_walk(disk: &[u8], initial_len: usize) -> BTreeMap<u64, u64> {
    let hdr = parse_disk_header(disk);
    let cs = hdr.cluster_size;
    let epl2 = (cs / 8) as usize;
    let epr = cs * 8 / 16; // 16-bit refcounts (envelope-gated)

    // On-disk refcounts via the refcount table.
    let rt_off = hdr.refcount_table_offset as usize;
    let rt_entries = hdr.refcount_table_clusters as usize * cs as usize / 8;
    let mut refcounts: BTreeMap<u64, u64> = BTreeMap::new();
    let mut refblock_clusters = Vec::new();
    for i in 0..rt_entries {
        let entry = be64(disk, rt_off + i * 8);
        if entry == 0 {
            continue;
        }
        assert!(
            entry.is_multiple_of(cs),
            "refblock offset must be cluster-aligned"
        );
        assert!(
            entry + cs <= disk.len() as u64,
            "refblock must lie within the file"
        );
        refblock_clusters.push(entry / cs);
        for e in 0..epr {
            let rc = be16(disk, entry as usize + e as usize * 2) as u64;
            if rc > 0 {
                refcounts.insert(i as u64 * epr + e, rc);
            }
        }
    }

    // Reachable clusters, with what reaches them (double-alloc
    // diagnostics).
    let mut reachable: Vec<(u64, String)> = vec![(0, "header".into())];
    let l1_off = hdr.l1_table_offset;
    let l1_bytes = hdr.l1_size as u64 * 8;
    for c in l1_off / cs..(l1_off + l1_bytes).div_ceil(cs) {
        reachable.push((c, "L1 table".into()));
    }
    for c in 0..hdr.refcount_table_clusters as u64 {
        reachable.push((hdr.refcount_table_offset / cs + c, "refcount table".into()));
    }
    for &c in &refblock_clusters {
        reachable.push((c, "refblock".into()));
    }
    for i in 0..hdr.l1_size as usize {
        let raw = be64(disk, l1_off as usize + i * 8);
        if raw == 0 {
            continue;
        }
        assert_eq!(
            raw & !(OFLAG_COPIED | L1_OFFSET_MASK),
            0,
            "L1 entry {i} carries unknown bits: {raw:#x}"
        );
        assert_ne!(raw & OFLAG_COPIED, 0, "L1 entry {i} must be COPIED (owned)");
        let l2_host = raw & L1_OFFSET_MASK;
        assert!(l2_host.is_multiple_of(cs), "L1 entry {i} misaligned");
        assert!(
            l2_host + cs <= disk.len() as u64,
            "L2 table outside the file"
        );
        reachable.push((l2_host / cs, format!("L2 table (L1 idx {i})")));
        for e in 0..epl2 {
            let l2e = be64(disk, l2_host as usize + e * 8);
            if l2e == 0 {
                continue;
            }
            assert_eq!(
                l2e & OFLAG_COMPRESSED,
                0,
                "no compressed entries in v1 images"
            );
            assert_eq!(
                l2e & !(OFLAG_COPIED | L2_OFFSET_MASK),
                0,
                "L2 entry {i}/{e} carries unknown bits: {l2e:#x}"
            );
            assert_ne!(
                l2e & OFLAG_COPIED,
                0,
                "L2 entry {i}/{e} must be COPIED (owned)"
            );
            let host = l2e & L2_OFFSET_MASK;
            assert!(host.is_multiple_of(cs), "L2 entry {i}/{e} misaligned");
            assert!(
                host + cs <= disk.len() as u64,
                "data cluster outside the file"
            );
            reachable.push((host / cs, format!("data cluster (L1 {i}, L2 {e})")));
        }
    }

    // No double-allocation.
    let mut seen: BTreeMap<u64, String> = BTreeMap::new();
    for (c, what) in &reachable {
        if let Some(prev) = seen.insert(*c, what.clone()) {
            panic!("host cluster {c} double-referenced: {prev} and {what}");
        }
    }

    // Refcount <-> reachability: exact correspondence in v1.
    for (c, what) in &reachable {
        assert_eq!(
            refcounts.get(c),
            Some(&1),
            "reachable cluster {c} ({what}) must have refcount 1"
        );
    }
    for (c, rc) in &refcounts {
        assert!(
            seen.contains_key(c),
            "refcounted cluster {c} (rc {rc}) is unreachable (leak)"
        );
    }

    // File-length growth sanity.
    let max_cluster = *refcounts.keys().max().expect("image has refcounts");
    assert_eq!(
        disk.len() as u64,
        (max_cluster + 1) * cs,
        "file must end exactly at the highest refcounted cluster"
    );
    assert!(disk.len() >= initial_len, "the file never shrinks");

    refcounts
}

// ---------------------------------------------------------------------------
// Assertion family 3: crash consistency at every barrier
// ---------------------------------------------------------------------------

/// Structural walk of a truncated image: every on-disk L1/L2
/// pointer must reference a cluster whose bytes were fully
/// present — either part of the initial image or covered by
/// replayed writes. This is decision 7's payoff: a pointer never
/// becomes durable before the data/init writes it references.
fn crash_structural_walk(disk: &[u8], covered: &[bool], ctx: &str) {
    let hdr = parse_disk_header(disk);
    let cs = hdr.cluster_size as usize;
    let epl2 = cs / 8;
    let l1_off = hdr.l1_table_offset as usize;
    let mut seen: BTreeSet<u64> = BTreeSet::new();
    for i in 0..hdr.l1_size as usize {
        let raw = be64(disk, l1_off + i * 8);
        if raw == 0 {
            continue;
        }
        assert_eq!(
            raw & !(OFLAG_COPIED | L1_OFFSET_MASK),
            0,
            "{ctx}: bad L1 entry {i}"
        );
        let l2_host = (raw & L1_OFFSET_MASK) as usize;
        assert!(l2_host.is_multiple_of(cs), "{ctx}: misaligned L1 entry {i}");
        assert!(
            l2_host + cs <= disk.len(),
            "{ctx}: L1 entry {i} outside the file"
        );
        assert!(
            covered[l2_host..l2_host + cs].iter().all(|&b| b),
            "{ctx}: L1 entry {i} references an L2 cluster whose init/writeback was not yet replayed"
        );
        assert!(
            seen.insert(l2_host as u64),
            "{ctx}: double-referenced L2 cluster"
        );
        for e in 0..epl2 {
            let l2e = be64(disk, l2_host + e * 8);
            if l2e == 0 {
                continue;
            }
            assert_eq!(
                l2e & OFLAG_COMPRESSED,
                0,
                "{ctx}: compressed L2 entry {i}/{e}"
            );
            assert_eq!(
                l2e & !(OFLAG_COPIED | L2_OFFSET_MASK),
                0,
                "{ctx}: bad L2 entry {i}/{e}"
            );
            let host = (l2e & L2_OFFSET_MASK) as usize;
            assert!(
                host.is_multiple_of(cs),
                "{ctx}: misaligned L2 entry {i}/{e}"
            );
            assert!(
                host + cs <= disk.len(),
                "{ctx}: L2 entry {i}/{e} outside the file"
            );
            assert!(
                covered[host..host + cs].iter().all(|&b| b),
                "{ctx}: L2 entry {i}/{e} references a data cluster whose writes were not yet replayed"
            );
            assert!(
                seen.insert(host as u64),
                "{ctx}: double-referenced data cluster"
            );
        }
    }
}

/// Byte-wise old-or-new: every virtual byte of the truncated
/// image reads as either the pre-epoch model or the post-epoch
/// model (chunked slice compares keep the debug-build cost low).
fn assert_content_old_or_new(content: &[u8], old: &[u8], new: &[u8], ctx: &str) {
    assert_eq!(content.len(), old.len());
    assert_eq!(content.len(), new.len());
    let mut pos = 0usize;
    while pos < content.len() {
        let end = (pos + 4096).min(content.len());
        if content[pos..end] != new[pos..end] && content[pos..end] != old[pos..end] {
            for i in pos..end {
                assert!(
                    content[i] == old[i] || content[i] == new[i],
                    "{ctx}: virtual byte {i:#x} = {:#04x} is neither old ({:#04x}) nor new ({:#04x})",
                    content[i],
                    old[i],
                    new[i]
                );
            }
        }
        pos = end;
    }
}

/// Family 3: replay the journal from the initial image and stop
/// at EVERY Durability barrier boundary (all v1 barriers are
/// Durability). At each boundary: structural walk (nothing
/// references unwritten bytes) + old-or-new content vs the
/// barrier's flush epoch. Finally the fully replayed disk must
/// equal the executed disk (the journal captured every write).
/// Returns the number of truncation points exercised.
fn crash_consistency_scan(
    sim: &Sim,
    initial_disk: &[u8],
    epoch_models: &[(Vec<u8>, Vec<u8>)],
) -> usize {
    let mut disk = initial_disk.to_vec();
    let mut covered = vec![true; initial_disk.len()];
    let mut barriers_seen: u64 = 0;
    let mut checked = 0usize;
    for entry in &sim.journal {
        match entry {
            JournalEntry::Write(w) => {
                assert_eq!(w.device, DEV_IN0, "the grid writes one device");
                assert_eq!(
                    w.epoch_tag, barriers_seen,
                    "epoch tag must match the write's barrier position"
                );
                let end = w.off + w.bytes.len();
                if disk.len() < end {
                    disk.resize(end, SENTINEL);
                    covered.resize(end, false);
                }
                disk[w.off..end].copy_from_slice(&w.bytes);
                covered[w.off..end].fill(true);
            }
            JournalEntry::Barrier { class, flush_idx } => {
                assert_eq!(
                    *class,
                    BarrierClass::Durability,
                    "v1 flush barriers are all Durability"
                );
                barriers_seen += 1;
                let ctx = format!("truncated at barrier {barriers_seen} (flush {flush_idx})");
                crash_structural_walk(&disk, &covered, &ctx);
                let content = read_virtual(&disk);
                let (old, new) = &epoch_models[*flush_idx];
                assert_content_old_or_new(&content, old, new, &ctx);
                checked += 1;
            }
        }
    }
    assert!(
        disk == sim.disks[DEV_IN0],
        "full journal replay must reproduce the executed disk"
    );
    checked
}

// ---------------------------------------------------------------------------
// Scenario driver and the write-pattern grid
// ---------------------------------------------------------------------------

#[derive(Clone, Copy)]
enum Src {
    /// Caller-data bytes from `pattern_byte(seed, ..)`.
    Data(u8),
    /// `DataSource::Fill` with this byte.
    Fill(u8),
}

#[derive(Clone, Copy)]
struct Wr {
    voff: u64,
    len: u64,
    src: Src,
}

impl Wr {
    fn expected_bytes(&self) -> Vec<u8> {
        match self.src {
            Src::Data(seed) => (0..self.len).map(|i| pattern_byte(seed, i)).collect(),
            Src::Fill(b) => vec![b; self.len as usize],
        }
    }
}

/// Plan+execute one write request and mirror it into the model.
fn apply_write(sim: &mut Sim, st: &mut WriteState, model: &mut RefModel, w: &Wr) -> Vec<Step> {
    let bytes = w.expected_bytes();
    let data = match w.src {
        Src::Data(_) => {
            sim.set_caller(&bytes);
            DataSource::CallerData { offset: 0 }
        }
        Src::Fill(b) => DataSource::Fill { byte: b },
    };
    let steps = run_write_ok(sim, st, w.voff, w.len, data);
    model.write(w.voff, &bytes);
    steps
}

/// Run a scenario (epochs of writes, each closed by a flush) and
/// apply all three assertion families. Returns the number of
/// barrier truncation points exercised.
fn run_scenario(cluster_bits: u32, virtual_size: u64, epochs: &[Vec<Wr>]) -> usize {
    let (initial_disk, hdr) = build_image(cluster_bits, virtual_size, None);
    let mut sim = Sim::new(&hdr, initial_disk.clone());
    let mut st = new_state(&hdr, &staging_config()).expect("image inside the envelope");
    let mut model = RefModel::new(virtual_size);
    let mut epoch_models: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
    for epoch in epochs {
        let old = model.materialise();
        for w in epoch {
            apply_write(&mut sim, &mut st, &mut model, w);
        }
        let new = model.materialise();
        run_flush_ok(&mut sim, &mut st);
        epoch_models.push((old, new));
    }

    // Family 1: virtual content vs the reference model.
    assert_virtual_content_matches_model(&sim.disks[DEV_IN0], &model);
    // Family 2: full metadata consistency of the completed image.
    full_consistency_walk(&sim.disks[DEV_IN0], initial_disk.len());
    // Family 3: crash consistency at every Durability barrier.
    let barriers = crash_consistency_scan(&sim, &initial_disk, &epoch_models);
    assert!(
        barriers >= epochs.len(),
        "every flush must contribute at least one barrier"
    );
    barriers
}

/// The two image sizes per cluster size (grid dimension 2). Kept
/// small at 2 MiB clusters — the point there is geometry
/// arithmetic, not volume.
fn grid_sizes(cluster_bits: u32) -> [u64; 2] {
    match cluster_bits {
        9 => [32 << 10, 96 << 10], // 1 vs 3 L2 tables
        12 => [1 << 20, 4 << 20],  // 1 vs 2 L2 tables
        16 => [1 << 20, 4 << 20],  // 16 vs 64 clusters
        21 => [4 << 20, 8 << 20],  // 2 vs 4 clusters
        _ => unreachable!("outside the grid"),
    }
}

/// Sequential: full-cluster writes at consecutive offsets.
fn pattern_sequential(cs: u64, vsize: u64) -> Vec<Wr> {
    (0..(vsize / cs).min(4))
        .map(|c| Wr {
            voff: c * cs,
            len: cs,
            src: Src::Data(c as u8 + 1),
        })
        .collect()
}

/// Sparse: scattered writes (start, middle, tail), the middle
/// one a Fill source so FillRange is exercised.
fn pattern_sparse(cs: u64, vsize: u64) -> Vec<Wr> {
    vec![
        Wr {
            voff: cs / 4,
            len: cs / 2,
            src: Src::Data(11),
        },
        Wr {
            voff: (vsize / 2 / cs) * cs,
            len: cs,
            src: Src::Fill(0x5a),
        },
        Wr {
            voff: vsize - cs / 2,
            len: cs / 2,
            src: Src::Data(13),
        },
    ]
}

/// Straddling: writes crossing cluster boundaries, an L2-table
/// boundary where the image spans one, and a three-cluster span
/// where it fits.
fn pattern_straddling(cs: u64, vsize: u64) -> Vec<Wr> {
    let a = cs / 4;
    let l2_cov = (cs / 8) * cs;
    let mut writes = vec![Wr {
        voff: cs - a,
        len: 2 * a,
        src: Src::Data(21),
    }];
    if vsize > l2_cov {
        writes.push(Wr {
            voff: l2_cov - a,
            len: 2 * a,
            src: Src::Data(22),
        });
    }
    if vsize >= 4 * cs {
        writes.push(Wr {
            voff: 2 * cs - a,
            len: cs + 2 * a,
            src: Src::Data(23),
        });
    }
    writes
}

/// Sub-cluster: small unaligned writes inside single clusters
/// (fresh-cluster RMW zero-fill plus owned sub-range overwrite).
fn pattern_subcluster(cs: u64, vsize: u64) -> Vec<Wr> {
    vec![
        Wr {
            voff: 3,
            len: 7,
            src: Src::Data(31),
        },
        Wr {
            voff: cs / 2 + 1,
            len: (cs / 16).max(1),
            src: Src::Data(32),
        },
        Wr {
            voff: vsize - cs + 5,
            len: 11,
            src: Src::Data(33),
        },
    ]
}

fn run_pattern_grid(cluster_bits: u32, pattern: fn(u64, u64) -> Vec<Wr>, name: &str) {
    let cs = 1u64 << cluster_bits;
    for vsize in grid_sizes(cluster_bits) {
        let epochs = vec![pattern(cs, vsize)];
        let barriers = run_scenario(cluster_bits, vsize, &epochs);
        eprintln!("{name} cs={cs} vsize={vsize}: {barriers} barrier truncation points");
    }
}

/// Repeated overwrite: the same virtual range written twice via
/// separate `plan_write` calls (windows executed between calls),
/// then once more after a flush. Both repeat passes must
/// classify owned — an in-place overwrite with no metadata churn
/// and unchanged refcounts.
fn run_repeated_overwrite(cluster_bits: u32, vsize: u64) -> usize {
    let cs = 1u64 << cluster_bits;
    let (initial_disk, hdr) = build_image(cluster_bits, vsize, None);
    let mut sim = Sim::new(&hdr, initial_disk.clone());
    let mut st = new_state(&hdr, &staging_config()).expect("image inside the envelope");
    let mut model = RefModel::new(vsize);
    let mut epoch_models: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
    // A range straddling two clusters of one L2 table.
    let (voff, len) = (cs / 2, cs);
    assert!(voff + len <= vsize);

    // Epoch 0: allocate, then overwrite the same range in a
    // second plan_write call.
    let old = model.materialise();
    apply_write(
        &mut sim,
        &mut st,
        &mut model,
        &Wr {
            voff,
            len,
            src: Src::Data(41),
        },
    );
    let assert_no_churn = |sim: &mut Sim, st: &mut WriteState, model: &mut RefModel, seed: u8| {
        let alloc_before = st.alloc_cursor().allocated;
        let refblocks_before = sim.refblocks.clone();
        let steps = apply_write(
            sim,
            st,
            model,
            &Wr {
                voff,
                len,
                src: Src::Data(seed),
            },
        );
        assert!(!steps.is_empty());
        for s in &steps {
            assert_eq!(
                s.kind,
                StepKind::WriteRange,
                "repeat pass must be a pure in-place overwrite"
            );
        }
        assert_eq!(
            st.alloc_cursor().allocated,
            alloc_before,
            "repeat pass must not allocate"
        );
        assert_eq!(
            sim.refblocks, refblocks_before,
            "repeat pass must leave refcounts unchanged"
        );
    };
    assert_no_churn(&mut sim, &mut st, &mut model, 42);
    let new = model.materialise();
    run_flush_ok(&mut sim, &mut st);
    epoch_models.push((old, new));
    let rc_after_epoch0 = full_consistency_walk(&sim.disks[DEV_IN0], initial_disk.len());

    // Epoch 1: overwrite the flushed range again; the flush of a
    // pure-overwrite epoch is a single Durability barrier and
    // the on-disk refcounts stay identical.
    let old = model.materialise();
    assert_no_churn(&mut sim, &mut st, &mut model, 43);
    let new = model.materialise();
    let flush_steps = run_flush_ok(&mut sim, &mut st);
    epoch_models.push((old, new));
    assert_eq!(
        flush_steps.iter().map(|s| s.kind).collect::<Vec<_>>(),
        vec![StepKind::Barrier {
            class: BarrierClass::Durability
        }],
        "a pure-overwrite epoch flushes as one barrier"
    );
    let rc_after_epoch1 = full_consistency_walk(&sim.disks[DEV_IN0], initial_disk.len());
    assert_eq!(
        rc_after_epoch0, rc_after_epoch1,
        "on-disk refcounts unchanged across a pure-overwrite epoch"
    );

    assert_virtual_content_matches_model(&sim.disks[DEV_IN0], &model);
    crash_consistency_scan(&sim, &initial_disk, &epoch_models)
}

// ---------------------------------------------------------------------------
// Grid tests: {512, 4096, 65536, 2 MiB} x 2 image sizes x pattern
// ---------------------------------------------------------------------------

#[test]
fn sim_sequential_c512() {
    run_pattern_grid(9, pattern_sequential, "sequential");
}

#[test]
fn sim_sequential_c4k() {
    run_pattern_grid(12, pattern_sequential, "sequential");
}

#[test]
fn sim_sequential_c64k() {
    run_pattern_grid(16, pattern_sequential, "sequential");
}

#[test]
fn sim_sequential_c2m() {
    run_pattern_grid(21, pattern_sequential, "sequential");
}

#[test]
fn sim_sparse_c512() {
    run_pattern_grid(9, pattern_sparse, "sparse");
}

#[test]
fn sim_sparse_c4k() {
    run_pattern_grid(12, pattern_sparse, "sparse");
}

#[test]
fn sim_sparse_c64k() {
    run_pattern_grid(16, pattern_sparse, "sparse");
}

#[test]
fn sim_sparse_c2m() {
    run_pattern_grid(21, pattern_sparse, "sparse");
}

#[test]
fn sim_straddling_c512() {
    run_pattern_grid(9, pattern_straddling, "straddling");
}

#[test]
fn sim_straddling_c4k() {
    run_pattern_grid(12, pattern_straddling, "straddling");
}

#[test]
fn sim_straddling_c64k() {
    run_pattern_grid(16, pattern_straddling, "straddling");
}

#[test]
fn sim_straddling_c2m() {
    run_pattern_grid(21, pattern_straddling, "straddling");
}

#[test]
fn sim_subcluster_c512() {
    run_pattern_grid(9, pattern_subcluster, "subcluster");
}

#[test]
fn sim_subcluster_c4k() {
    run_pattern_grid(12, pattern_subcluster, "subcluster");
}

#[test]
fn sim_subcluster_c64k() {
    run_pattern_grid(16, pattern_subcluster, "subcluster");
}

#[test]
fn sim_subcluster_c2m() {
    run_pattern_grid(21, pattern_subcluster, "subcluster");
}

#[test]
fn sim_repeated_overwrite_c512() {
    for vsize in grid_sizes(9) {
        let barriers = run_repeated_overwrite(9, vsize);
        eprintln!("repeated-overwrite cs=512 vsize={vsize}: {barriers} barrier truncation points");
    }
}

#[test]
fn sim_repeated_overwrite_c4k() {
    for vsize in grid_sizes(12) {
        let barriers = run_repeated_overwrite(12, vsize);
        eprintln!("repeated-overwrite cs=4096 vsize={vsize}: {barriers} barrier truncation points");
    }
}

#[test]
fn sim_repeated_overwrite_c64k() {
    for vsize in grid_sizes(16) {
        let barriers = run_repeated_overwrite(16, vsize);
        eprintln!("repeated-overwrite cs=64K vsize={vsize}: {barriers} barrier truncation points");
    }
}

#[test]
fn sim_repeated_overwrite_c2m() {
    for vsize in grid_sizes(21) {
        let barriers = run_repeated_overwrite(21, vsize);
        eprintln!("repeated-overwrite cs=2M vsize={vsize}: {barriers} barrier truncation points");
    }
}

/// Two flush epochs with mixed work: an allocation epoch, then
/// an epoch mixing owned overwrites with new allocations across
/// an L2-table boundary — the richest multi-epoch crash surface
/// in the suite (~8 barriers).
#[test]
fn sim_multi_epoch_mixed_c4k() {
    let cs = 1u64 << 12;
    let l2_cov = (cs / 8) * cs;
    let vsize = 4u64 << 20; // two L2 tables
    let epochs = vec![
        vec![
            Wr {
                voff: 0,
                len: 2 * cs,
                src: Src::Data(51),
            },
            Wr {
                voff: 5 * cs + 9,
                len: 100,
                src: Src::Data(52),
            },
        ],
        vec![
            Wr {
                voff: cs,
                len: cs,
                src: Src::Data(53), // owned overwrite of epoch 0's cluster
            },
            Wr {
                voff: l2_cov - cs / 2,
                len: cs, // fresh allocations straddling the L2 boundary
                src: Src::Data(54),
            },
        ],
    ];
    let barriers = run_scenario(12, vsize, &epochs);
    eprintln!("multi-epoch cs=4096 vsize={vsize}: {barriers} barrier truncation points");
    assert!(
        barriers >= 5,
        "two flushes with metadata churn barrier-separate"
    );
}

/// Unaligned virtual size (the phase-4 plan's amended decision
/// 7 / D9), backing-less: the EOV-tail write — from the tail
/// cluster's base up to exactly `virtual_size` — allocates the
/// full cluster with a beyond-EOV zero-fill. The reference model
/// treats beyond-EOV bytes as outside virtual content (all
/// content comparisons run over `virtual_size` bytes), the
/// consistency walk still sees the full allocated tail cluster,
/// and the per-barrier crash pass runs unchanged over the new
/// shape.
#[test]
fn sim_unaligned_virtual_size_eov_tail() {
    for (cluster_bits, base) in [(9u32, 32u64 << 10), (12, 1u64 << 20)] {
        let cs = 1u64 << cluster_bits;
        let vsize = base + cs / 2 + 24; // unaligned tail cluster
        let tail_base = (vsize / cs) * cs;
        let tail_len = vsize - tail_base;
        let epochs = vec![vec![
            Wr {
                voff: 0,
                len: cs,
                src: Src::Data(71),
            },
            Wr {
                voff: 5,
                len: 9,
                src: Src::Data(72), // owned sub-range overwrite
            },
            Wr {
                voff: 2 * cs + 7,
                len: 11,
                src: Src::Data(73), // fresh sub-cluster RMW below EOV
            },
            Wr {
                voff: tail_base,
                len: tail_len,
                src: Src::Data(74), // the EOV-tail shape
            },
        ]];
        let barriers = run_scenario(cluster_bits, vsize, &epochs);
        eprintln!("unaligned-eov cs={cs} vsize={vsize}: {barriers} barrier truncation points");
        assert!(barriers >= 1, "the flush must contribute a barrier");
    }
}

/// Unaligned virtual size on a BACKED image: the EOV-tail write
/// is full coverage (amended decision 7 — bytes beyond EOV are
/// not virtual content, so the zero-fill is the correct
/// pre-image), while every genuinely partial write below EOV
/// keeps the NeedsBackingFill refusal; the mutated image stays
/// consistent through flush and the crash pass.
#[test]
fn sim_backed_unaligned_eov_tail() {
    let cs = 1u64 << 12;
    let tail_base = 1u64 << 20;
    let vsize = tail_base + cs / 2 + 24;
    let tail_len = vsize - tail_base;
    let (initial_disk, hdr) = build_image(12, vsize, Some(b"base.qcow2"));
    let mut sim = Sim::new(&hdr, initial_disk.clone());
    let mut st = new_state(&hdr, &staging_config()).expect("backed image passes the envelope");
    let mut model = RefModel::new(vsize);
    let mut epoch_models: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();

    // Genuinely partial below-EOV tail writes refuse: coverage
    // ending below EOV, and a head gap below EOV.
    sim.set_caller(&vec![7u8; tail_len as usize]);
    let (err, _) = run_write(
        &mut sim,
        &mut st,
        tail_base,
        tail_len - 1,
        DataSource::CallerData { offset: 0 },
    )
    .expect_err("coverage below EOV on a backed image must refuse");
    assert_eq!(err, WriteError::NeedsBackingFill);
    let (err, _) = run_write(
        &mut sim,
        &mut st,
        tail_base + 4,
        tail_len - 4,
        DataSource::CallerData { offset: 0 },
    )
    .expect_err("head gap below EOV on a backed image must refuse");
    assert_eq!(err, WriteError::NeedsBackingFill);

    // The EOV-tail write and a full-cluster allocating write
    // both succeed.
    let old = model.materialise();
    apply_write(
        &mut sim,
        &mut st,
        &mut model,
        &Wr {
            voff: cs,
            len: cs,
            src: Src::Data(81),
        },
    );
    apply_write(
        &mut sim,
        &mut st,
        &mut model,
        &Wr {
            voff: tail_base,
            len: tail_len,
            src: Src::Data(82),
        },
    );
    let new = model.materialise();
    run_flush_ok(&mut sim, &mut st);
    epoch_models.push((old, new));

    // Note read_virtual is overlay-local; with only full-coverage
    // allocated content the model comparison stays exact.
    assert_virtual_content_matches_model(&sim.disks[DEV_IN0], &model);
    full_consistency_walk(&sim.disks[DEV_IN0], initial_disk.len());
    let barriers = crash_consistency_scan(&sim, &initial_disk, &epoch_models);
    assert!(barriers >= 1, "the flush must contribute a barrier");
}

/// The documented backed-image refusal: partial allocating
/// writes on an image with a backing file refuse as
/// NeedsBackingFill (v1's zero-fill would mask backing content);
/// a full-cluster allocating write on the same image is fine.
#[test]
fn sim_backed_image_partial_allocating_write_refuses() {
    let cs = 1u64 << 12;
    let vsize = 1u64 << 20;
    let (initial_disk, hdr) = build_image(12, vsize, Some(b"base.qcow2"));
    let mut sim = Sim::new(&hdr, initial_disk.clone());
    let mut st = new_state(&hdr, &staging_config()).expect("backed image passes the envelope");
    let mut model = RefModel::new(vsize);

    sim.set_caller(&[7u8; 50]);
    let (err, _) = run_write(
        &mut sim,
        &mut st,
        100,
        50,
        DataSource::CallerData { offset: 0 },
    )
    .expect_err("partial allocating write on a backed image must refuse");
    assert_eq!(err, WriteError::NeedsBackingFill);

    // Full-cluster allocating write: allowed (the backing
    // pre-image is fully overwritten), and the image stays
    // consistent through flush.
    apply_write(
        &mut sim,
        &mut st,
        &mut model,
        &Wr {
            voff: cs,
            len: cs,
            src: Src::Data(61),
        },
    );
    run_flush_ok(&mut sim, &mut st);
    // Note read_virtual is overlay-local; with only full-cluster
    // allocated content the model comparison stays exact.
    assert_virtual_content_matches_model(&sim.disks[DEV_IN0], &model);
    full_consistency_walk(&sim.disks[DEV_IN0], initial_disk.len());
}
