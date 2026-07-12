//! Step 3c: the decision-7 crash-ordering contract as tests.
//!
//! A property-style integration suite (public API only) that runs
//! deterministic pseudo-random write sets through `plan_write` /
//! `plan_flush`, collects the FULL emitted program across every
//! window, and asserts the settled ordering invariants of
//! `docs/plans/PLAN-qcow2-write-infrastructure-phase-03-crate.md`
//! decision 7 mechanically:
//!
//! - 7(a) [`assert_write_covers_cluster_before_l2_patch`]: for
//!   every `PatchEntryU64` making a data cluster reachable, data
//!   writes (`WriteRange`/`ZeroRange`/`FillRange`) covering the
//!   whole cluster precede it in the program.
//! - 7(b) [`assert_fresh_l2_init_precedes_l1_patch`] (in-stream)
//!   and [`assert_l2_writeback_precedes_l1_table_write`] (flush
//!   order): a fresh L2's `ZeroRegion` init precedes the L1 patch
//!   referencing it, and the table's disk writeback precedes the
//!   L1 table's disk write, with a barrier between.
//! - 7(c) [`assert_refblock_writebacks_flush_only_and_last`]:
//!   refcount writebacks appear only in `plan_flush` output,
//!   after every pointer patch of the epoch, in ascending
//!   refblock order.
//! - 7(d) [`assert_flush_barrier_skeleton`]: Durability barriers
//!   sit exactly at the flush contract points
//!   (`[B] L2-writebacks [B] L1 [B] refblocks [B]`), empty groups
//!   vanish and adjacent barriers collapse.
//!
//! Plus: every step's region/disk references are in bounds for
//! the `StagedRegions` sizes and `StagingConfig`
//! ([`assert_step_bounds`]); gated images can never yield a
//! `WriteState`, so no write step can exist for them; refusals
//! emit no steps beyond already-planned clusters; and the emitted
//! program is byte-identical regardless of the step-buffer size
//! (window-invariance — the property the whole windowed design
//! rests on), including byte-identical final disk and staging
//! content.
//!
//! "Randomized-but-seedless": an inline xorshift64* generator
//! with hardcoded seeds; no std RNG, no clocks — every run is
//! identical.
//!
//! The assertion helpers are deliberately reusable (they consume
//! only the tagged step program plus a small context struct);
//! phase 7 extends them for COW.

use qcow2::{
    QcowHeader, L1_OFFSET_MASK, L2_OFFSET_MASK, OFLAG_COMPRESSED, OFLAG_COPIED, QCOW2_MAGIC,
};
use qcow2_write::{
    new_state, plan_flush, plan_write, BarrierClass, DataSource, Gate, RegionId, StagedRegions,
    StagingConfig, Step, StepBuf, StepKind, TargetDevice, WriteError, WriteState, MAX_L2_SLOTS,
};

// ---------------------------------------------------------------------------
// Deterministic PRNG (fixed seeds, no std RNG, no time)
// ---------------------------------------------------------------------------

/// xorshift64* with a hardcoded seed: deterministic across runs
/// and platforms by construction.
struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Rng {
        Rng(seed.max(1))
    }

    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
}

// ---------------------------------------------------------------------------
// Minimal in-memory qcow2 image + literal step executor
// ---------------------------------------------------------------------------

/// L1 tables every synthetic image carries (virtual size is
/// exactly this many L2 tables of coverage).
const L1_TABLES: u32 = 4;

/// Minimal valid v3 header bytes. Host layout convention:
/// cluster 0 header, cluster 1 refcount table, cluster 2
/// refblock 0, cluster 3 L1 table, clusters 4.. additional
/// refblocks, then free space.
fn header_bytes(cluster_bits: u32, virtual_size: u64, l1_size: u32, backing: bool) -> [u8; 4096] {
    let cs = 1u64 << cluster_bits;
    let mut h = [0u8; 4096];
    h[0..4].copy_from_slice(&QCOW2_MAGIC.to_be_bytes());
    h[4..8].copy_from_slice(&3u32.to_be_bytes());
    if backing {
        h[8..16].copy_from_slice(&200u64.to_be_bytes());
        h[16..20].copy_from_slice(&4u32.to_be_bytes());
    }
    h[20..24].copy_from_slice(&cluster_bits.to_be_bytes());
    h[24..32].copy_from_slice(&virtual_size.to_be_bytes());
    h[36..40].copy_from_slice(&l1_size.to_be_bytes());
    h[40..48].copy_from_slice(&(3 * cs).to_be_bytes()); // L1 offset
    h[48..56].copy_from_slice(&cs.to_be_bytes()); // refcount table offset
    h[56..60].copy_from_slice(&1u32.to_be_bytes()); // refcount table clusters
    h[96..100].copy_from_slice(&4u32.to_be_bytes()); // refcount_order = 4
    h[100..104].copy_from_slice(&104u32.to_be_bytes()); // header_length
    h
}

fn parse(h: &[u8]) -> QcowHeader {
    QcowHeader::parse(h).expect("synthetic header must parse")
}

/// The executor-side stand-in: Vec-backed staged buffers plus a
/// Vec-backed disk. Sentinel fill (0xEE) makes missed zero-fills
/// and stale reads observable; the disk grows on demand.
struct SimImage {
    cs: usize,
    disk: Vec<u8>,
    l1: Vec<u8>,
    l2win: Vec<u8>,
    rt: Vec<u8>,
    refblocks: Vec<u8>,
    caller: Vec<u8>,
    barrier_count: usize,
}

fn set_rc(img: &mut SimImage, cluster: u64, value: u64) {
    snapshot::qcow2::set_refcount_in_block(&mut img.refblocks, cluster, 16, value).unwrap();
}

/// Set an L1 entry in the staged copy AND on disk.
fn set_l1(img: &mut SimImage, idx: usize, value: u64) {
    img.l1[idx * 8..idx * 8 + 8].copy_from_slice(&value.to_be_bytes());
    let off = 3 * img.cs + idx * 8;
    img.disk[off..off + 8].copy_from_slice(&value.to_be_bytes());
}

fn put_disk_u64(img: &mut SimImage, off: usize, value: u64) {
    img.disk[off..off + 8].copy_from_slice(&value.to_be_bytes());
}

/// Build a clean image (virtual size = `L1_TABLES` L2 tables of
/// coverage) and its gated state. `rb_count` staged refblocks
/// are placed per the layout convention with refcount 1.
fn mk_image(
    cluster_bits: u32,
    l2_slots: usize,
    rb_count: usize,
    backing: bool,
    device: TargetDevice,
) -> (SimImage, WriteState) {
    let cs = 1usize << cluster_bits;
    let l2_coverage = (cs as u64 / 8) * cs as u64;
    mk_image_vs(
        cluster_bits,
        l2_slots,
        rb_count,
        backing,
        device,
        L1_TABLES as u64 * l2_coverage,
    )
}

/// [`mk_image`] with an explicit `virtual_size` (still
/// `L1_TABLES` L1 entries): the EOV-tail scenarios need unaligned
/// sizes (the phase-4 plan's amended decision 7).
fn mk_image_vs(
    cluster_bits: u32,
    l2_slots: usize,
    rb_count: usize,
    backing: bool,
    device: TargetDevice,
    virtual_size: u64,
) -> (SimImage, WriteState) {
    let cs = 1usize << cluster_bits;
    let hdr = parse(&header_bytes(
        cluster_bits,
        virtual_size,
        L1_TABLES,
        backing,
    ));
    let mut img = SimImage {
        cs,
        disk: vec![0xee; 16 * cs],
        l1: vec![0u8; L1_TABLES as usize * 8],
        l2win: vec![0xee; l2_slots * cs],
        rt: vec![0u8; rb_count * 8],
        refblocks: vec![0u8; rb_count * cs],
        caller: (0..8 * cs)
            .map(|i| (i.wrapping_mul(131).wrapping_add(7) % 256) as u8)
            .collect(),
        barrier_count: 0,
    };
    img.rt[0..8].copy_from_slice(&(2 * cs as u64).to_be_bytes());
    for j in 1..rb_count {
        let host = (3 + j) as u64 * cs as u64;
        img.rt[j * 8..j * 8 + 8].copy_from_slice(&host.to_be_bytes());
    }
    // Metadata refcounts: header, refcount table, refblock 0, L1
    // (clusters 0..=3) plus the extra refblocks at 4..
    for c in 0..(3 + rb_count as u64) {
        set_rc(&mut img, c, 1);
    }
    let cfg = StagingConfig {
        l2_slots,
        max_refblocks: rb_count.max(32),
        device,
    };
    let st = new_state(&hdr, &cfg).expect("clean image must pass the gates");
    (img, st)
}

/// Persist pre-existing allocated mappings (one on-disk L2 table
/// per distinct `l1_idx`, one owned data cluster per pair, all
/// refcount 1) so scenarios exercise the LoadCluster staging path
/// and owned overwrites of on-disk data.
fn prepopulate(img: &mut SimImage, rb_count: usize, mappings: &[(usize, usize)]) {
    let cs = img.cs;
    let mut next = 3 + rb_count as u64; // first cluster past the metadata
    let mut l2_host = [0u64; L1_TABLES as usize];
    for &(l1_idx, l2_idx) in mappings {
        if l2_host[l1_idx] == 0 {
            let host = next * cs as u64;
            next += 1;
            img.disk[host as usize..host as usize + cs].fill(0);
            set_l1(img, l1_idx, host | OFLAG_COPIED);
            set_rc(img, host / cs as u64, 1);
            l2_host[l1_idx] = host;
        }
        let data = next * cs as u64;
        next += 1;
        for (i, b) in img.disk[data as usize..data as usize + cs]
            .iter_mut()
            .enumerate()
        {
            *b = (i % 253) as u8;
        }
        put_disk_u64(
            img,
            l2_host[l1_idx] as usize + l2_idx * 8,
            data | OFLAG_COPIED,
        );
        set_rc(img, data / cs as u64, 1);
    }
}

fn filler_step() -> Step {
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

fn region_base(img: &mut SimImage, region: RegionId) -> (&mut Vec<u8>, usize) {
    let cs = img.cs;
    match region {
        RegionId::L1 => (&mut img.l1, 0),
        RegionId::L2Slot(v) => (&mut img.l2win, v as usize * cs),
        RegionId::RefcountTable => (&mut img.rt, 0),
        RegionId::Refblocks => (&mut img.refblocks, 0),
        RegionId::CallerData => (&mut img.caller, 0),
        RegionId::Bounce => panic!("Bounce carries no bytes in v1 programs"),
    }
}

fn region_bytes(img: &mut SimImage, region: RegionId, off: usize, len: usize) -> Vec<u8> {
    let (buf, base) = region_base(img, region);
    buf[base + off..base + off + len].to_vec()
}

/// Apply one emitted window literally (the executor role of the
/// decision-1 loop). Semantics mirror what the phase 4-6 guest
/// ops will do with the program.
fn exec_steps(img: &mut SimImage, steps: &[Step]) {
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
            img.disk.resize(dof + len, 0xee);
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
                let (buf, base) = region_base(img, s.region);
                let off = base + s.region_offset as usize;
                buf[off..off + 8].copy_from_slice(&value.to_be_bytes());
            }
            StepKind::LoadCluster => {
                let src = img.disk[dof..dof + cs].to_vec();
                let (buf, base) = region_base(img, s.region);
                let off = base + s.region_offset as usize;
                buf[off..off + cs].copy_from_slice(&src);
            }
            StepKind::WritebackCluster => {
                let src = region_bytes(img, s.region, s.region_offset as usize, cs);
                img.disk[dof..dof + cs].copy_from_slice(&src);
            }
            StepKind::ZeroRegion => {
                let (buf, base) = region_base(img, s.region);
                let off = base + s.region_offset as usize;
                buf[off..off + len].fill(0);
            }
            StepKind::Barrier { .. } => img.barrier_count += 1,
            StepKind::ReadCluster => panic!("v1 planner must not emit ReadCluster"),
        }
    }
}

// ---------------------------------------------------------------------------
// Harness: the decision-1 plan/execute/reset loop with program
// collection and provenance tags
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    Write,
    Flush,
}

/// One emitted step plus provenance: which planner emitted it and
/// in which epoch (epochs are delimited by completed flushes).
#[derive(Debug, Clone, Copy)]
struct Tagged {
    step: Step,
    phase: Phase,
    epoch: usize,
}

struct Harness {
    img: SimImage,
    st: WriteState,
    cap: usize,
    program: Vec<Tagged>,
    /// (start, end) index ranges of each plan_flush call's steps
    /// within `program` (recorded even when empty, for the 7(d)
    /// skeleton check).
    flush_bounds: Vec<(usize, usize)>,
    epoch: usize,
}

impl Harness {
    fn new(img: SimImage, st: WriteState, cap: usize) -> Harness {
        Harness {
            img,
            st,
            cap,
            program: Vec::new(),
            flush_bounds: Vec::new(),
            epoch: 0,
        }
    }

    /// Plan/execute/reset until `Ok` or a real error, honouring
    /// the hard contract that every emitted window is executed
    /// before the next planner call. Steps emitted before a
    /// refusal stay in the program (they were executed).
    fn drive(&mut self, req: Option<(u64, u64, DataSource)>) -> Result<(), WriteError> {
        let phase = if req.is_some() {
            Phase::Write
        } else {
            Phase::Flush
        };
        let mut storage = vec![filler_step(); self.cap];
        for _ in 0..1_000_000usize {
            let mut buf = StepBuf::new(&mut storage);
            let r = {
                let mut sv = StagedRegions {
                    l1: &self.img.l1,
                    l2_window: &self.img.l2win,
                    refcount_table: &self.img.rt,
                    refblocks: &mut self.img.refblocks,
                };
                match req {
                    Some((voff, len, data)) => {
                        plan_write(&mut self.st, &mut sv, voff, len, data, &mut buf)
                    }
                    None => plan_flush(&mut self.st, &mut sv, &mut buf),
                }
            };
            let emitted = buf.steps().to_vec();
            exec_steps(&mut self.img, &emitted);
            for step in emitted {
                self.program.push(Tagged {
                    step,
                    phase,
                    epoch: self.epoch,
                });
            }
            match r {
                Ok(_) => return Ok(()),
                Err(WriteError::BufFull) => continue,
                Err(e) => return Err(e),
            }
        }
        panic!("planner failed to converge at cap {}", self.cap);
    }

    fn write(&mut self, voff: u64, len: u64, data: DataSource) -> Result<(), WriteError> {
        self.drive(Some((voff, len, data)))
    }

    fn flush(&mut self) -> Result<(), WriteError> {
        let start = self.program.len();
        let r = self.drive(None);
        self.flush_bounds.push((start, self.program.len()));
        if r.is_ok() {
            self.epoch += 1;
        }
        r
    }

    fn steps(&self) -> Vec<Step> {
        self.program.iter().map(|t| t.step).collect()
    }

    fn kinds(&self) -> Vec<StepKind> {
        self.program.iter().map(|t| t.step.kind).collect()
    }
}

/// Snapshot of every mutable byte the executor owns, for the
/// window-invariance final-content comparison.
#[derive(PartialEq, Eq)]
struct FinalContent {
    disk: Vec<u8>,
    l1: Vec<u8>,
    l2win: Vec<u8>,
    rt: Vec<u8>,
    refblocks: Vec<u8>,
    caller: Vec<u8>,
    barrier_count: usize,
}

fn final_content(img: &SimImage) -> FinalContent {
    FinalContent {
        disk: img.disk.clone(),
        l1: img.l1.clone(),
        l2win: img.l2win.clone(),
        rt: img.rt.clone(),
        refblocks: img.refblocks.clone(),
        caller: img.caller.clone(),
        barrier_count: img.barrier_count,
    }
}

// ---------------------------------------------------------------------------
// Invariant assertion helpers (reusable; phase 7 extends for COW)
// ---------------------------------------------------------------------------

/// Everything the mechanical checks need to know about the run:
/// geometry plus the actual staged-buffer sizes the executor
/// mapped the RegionIds onto.
struct ProgramCtx {
    cs: u64,
    l2_slots: usize,
    l1_len: usize,
    rt_len: usize,
    refblocks_len: usize,
    caller_len: usize,
    device: TargetDevice,
}

fn ctx_of(h: &Harness) -> ProgramCtx {
    ProgramCtx {
        cs: h.img.cs as u64,
        l2_slots: h.st.config().l2_slots,
        l1_len: h.img.l1.len(),
        rt_len: h.img.rt.len(),
        refblocks_len: h.img.refblocks.len(),
        caller_len: h.img.caller.len(),
        device: h.st.config().device,
    }
}

impl ProgramCtx {
    /// Byte length of the region a step offset must stay within
    /// (per-slot for the L2 window: step offsets are slot-local).
    fn region_len(&self, region: RegionId) -> u64 {
        match region {
            RegionId::L1 => self.l1_len as u64,
            RegionId::L2Slot(v) => {
                assert!(
                    (v as usize) < self.l2_slots,
                    "L2 slot {v} outside the configured window of {}",
                    self.l2_slots
                );
                self.cs
            }
            RegionId::RefcountTable => self.rt_len as u64,
            RegionId::Refblocks => self.refblocks_len as u64,
            RegionId::CallerData => self.caller_len as u64,
            RegionId::Bounce => 0,
        }
    }

    /// Highest host byte the staged refblocks cover: every disk
    /// reference the planner emits must stay below this (its
    /// refcount could not otherwise have been checked/claimed).
    fn host_ceiling(&self) -> u64 {
        (self.refblocks_len as u64 / self.cs) * (self.cs * 8 / 16) * self.cs
    }
}

/// Union of half-open byte intervals with a full-coverage query.
#[derive(Default)]
struct IntervalSet {
    spans: Vec<(u64, u64)>,
}

impl IntervalSet {
    fn add(&mut self, start: u64, end: u64) {
        if start < end {
            self.spans.push((start, end));
        }
    }

    /// Whether `[start, end)` is fully covered by the union.
    fn covers(&self, start: u64, end: u64) -> bool {
        let mut spans = self.spans.clone();
        spans.sort_unstable();
        let mut cursor = start;
        for (s, e) in spans {
            if cursor >= end {
                break;
            }
            if e <= cursor {
                continue;
            }
            if s > cursor {
                return false;
            }
            cursor = e;
        }
        cursor >= end
    }
}

/// Every step's references are in bounds for the staged-region
/// sizes and the StagingConfig, every step targets the configured
/// device, unused fields carry the documented fillers, and every
/// barrier is Durability class.
fn assert_step_bounds(prog: &[Tagged], ctx: &ProgramCtx) {
    let ceiling = ctx.host_ceiling();
    for (i, t) in prog.iter().enumerate() {
        let s = &t.step;
        assert_eq!(
            s.device, ctx.device,
            "step {i}: every step must carry the configured device"
        );
        match s.kind {
            StepKind::WriteRange => {
                assert!(
                    matches!(
                        s.region,
                        RegionId::CallerData | RegionId::L1 | RegionId::Refblocks
                    ),
                    "step {i}: unexpected WriteRange source region {:?}",
                    s.region
                );
                assert!(s.len > 0, "step {i}: zero-length WriteRange");
                assert!(
                    s.region_offset + s.len <= ctx.region_len(s.region),
                    "step {i}: WriteRange overruns region {:?}",
                    s.region
                );
                assert!(
                    s.disk_offset + s.len <= ceiling,
                    "step {i}: disk write beyond staged refcount coverage"
                );
            }
            StepKind::ZeroRange | StepKind::FillRange => {
                assert_eq!(
                    s.region,
                    RegionId::Bounce,
                    "step {i}: unused region must be the Bounce filler"
                );
                assert!(s.len > 0, "step {i}: zero-length range write");
                assert!(
                    s.disk_offset + s.len <= ceiling,
                    "step {i}: disk write beyond staged refcount coverage"
                );
                if s.kind == StepKind::ZeroRange {
                    assert_eq!(s.value, 0, "step {i}: ZeroRange value filler must be 0");
                } else {
                    assert!(s.value <= 0xff, "step {i}: FillRange value must be a byte");
                }
            }
            StepKind::PatchEntryU64 => {
                assert!(
                    matches!(s.region, RegionId::L1 | RegionId::L2Slot(_)),
                    "step {i}: patches target L1 or an L2 slot, got {:?}",
                    s.region
                );
                assert!(
                    s.region_offset.is_multiple_of(8),
                    "step {i}: misaligned entry patch offset"
                );
                assert!(
                    s.region_offset + 8 <= ctx.region_len(s.region),
                    "step {i}: entry patch overruns region {:?}",
                    s.region
                );
                assert_eq!(
                    s.value & !(OFLAG_COPIED | L2_OFFSET_MASK),
                    0,
                    "step {i}: unknown bits in patched entry {:#x}",
                    s.value
                );
                assert_ne!(
                    s.value & OFLAG_COPIED,
                    0,
                    "step {i}: v1 patches always set COPIED"
                );
                let host = s.value & L2_OFFSET_MASK;
                assert!(
                    host > 0 && host.is_multiple_of(ctx.cs),
                    "step {i}: misaligned patched host offset {host:#x}"
                );
                assert!(
                    host + ctx.cs <= ceiling,
                    "step {i}: patched entry references host {host:#x} beyond refcount coverage"
                );
            }
            StepKind::LoadCluster | StepKind::WritebackCluster => {
                assert!(
                    matches!(s.region, RegionId::L2Slot(_)),
                    "step {i}: cluster load/writeback must target an L2 slot"
                );
                let slot_len = ctx.region_len(s.region);
                assert_eq!(s.region_offset, 0, "step {i}: slot transfers start at 0");
                assert_eq!(s.len, slot_len, "step {i}: slot transfers are one cluster");
                assert!(
                    s.disk_offset.is_multiple_of(ctx.cs),
                    "step {i}: misaligned cluster transfer"
                );
                assert!(
                    s.disk_offset + ctx.cs <= ceiling,
                    "step {i}: cluster transfer beyond refcount coverage"
                );
            }
            StepKind::ZeroRegion => {
                assert!(
                    matches!(s.region, RegionId::L2Slot(_)),
                    "step {i}: v1 ZeroRegion only initialises L2 slots"
                );
                let slot_len = ctx.region_len(s.region);
                assert!(
                    s.region_offset + s.len <= slot_len,
                    "step {i}: ZeroRegion overruns its slot"
                );
                assert_eq!(s.len, ctx.cs, "step {i}: fresh L2 init zeroes a full slot");
            }
            StepKind::Barrier { class } => {
                assert_eq!(
                    class,
                    BarrierClass::Durability,
                    "step {i}: v1 emits Durability barriers only"
                );
                assert_eq!(
                    s.region,
                    RegionId::Bounce,
                    "step {i}: barrier region filler"
                );
                assert_eq!(
                    (s.region_offset, s.disk_offset, s.len, s.value),
                    (0, 0, 0, 0),
                    "step {i}: barrier numeric fillers must be zero"
                );
            }
            StepKind::ReadCluster => panic!("step {i}: v1 planner must not emit ReadCluster"),
        }
    }
}

/// Invariant 7(a): for every `PatchEntryU64` into an L2 slot
/// (making a data cluster reachable), the union of preceding
/// data writes (`WriteRange` from caller data, `ZeroRange`,
/// `FillRange`) covers the ENTIRE referenced cluster.
fn assert_write_covers_cluster_before_l2_patch(prog: &[Tagged], ctx: &ProgramCtx) {
    let mut cov = IntervalSet::default();
    for (i, t) in prog.iter().enumerate() {
        let s = &t.step;
        match s.kind {
            StepKind::WriteRange if s.region == RegionId::CallerData => {
                cov.add(s.disk_offset, s.disk_offset + s.len);
            }
            StepKind::ZeroRange | StepKind::FillRange => {
                cov.add(s.disk_offset, s.disk_offset + s.len);
            }
            StepKind::PatchEntryU64 if matches!(s.region, RegionId::L2Slot(_)) => {
                let host = s.value & L2_OFFSET_MASK;
                assert!(
                    cov.covers(host, host + ctx.cs),
                    "step {i}: 7(a) violated — L2 patch makes cluster at {host:#x} \
                     reachable before data writes cover it"
                );
            }
            _ => {}
        }
    }
}

/// What an L2 window slot currently stages, for the 7(b) replay.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SlotBind {
    Empty,
    /// A ZeroRegion init not yet referenced by an L1 patch.
    FreshZeroed {
        zero_idx: usize,
    },
    /// Stages the L2 table at this host offset.
    Bound {
        host: u64,
    },
}

/// Invariant 7(b), in-stream half: every L1 patch is preceded by
/// exactly one un-consumed fresh-L2 `ZeroRegion` init, and every
/// later `WritebackCluster` of that slot targets the host offset
/// the L1 patch bound (or, for loaded slots, the load origin).
fn assert_fresh_l2_init_precedes_l1_patch(prog: &[Tagged], ctx: &ProgramCtx) {
    let mut slots = vec![SlotBind::Empty; ctx.l2_slots];
    for (i, t) in prog.iter().enumerate() {
        let s = &t.step;
        match (s.kind, s.region) {
            (StepKind::ZeroRegion, RegionId::L2Slot(v)) => {
                slots[v as usize] = SlotBind::FreshZeroed { zero_idx: i };
            }
            (StepKind::LoadCluster, RegionId::L2Slot(v)) => {
                slots[v as usize] = SlotBind::Bound {
                    host: s.disk_offset,
                };
            }
            (StepKind::PatchEntryU64, RegionId::L1) => {
                let host = s.value & L1_OFFSET_MASK;
                let pending: Vec<usize> = slots
                    .iter()
                    .enumerate()
                    .filter(|(_, b)| matches!(b, SlotBind::FreshZeroed { .. }))
                    .map(|(v, _)| v)
                    .collect();
                assert_eq!(
                    pending.len(),
                    1,
                    "step {i}: 7(b) violated — an L1 patch must follow exactly one \
                     un-consumed fresh-L2 ZeroRegion init (found {})",
                    pending.len()
                );
                let v = pending[0];
                if let SlotBind::FreshZeroed { zero_idx } = slots[v] {
                    assert!(zero_idx < i, "step {i}: init must precede the L1 patch");
                }
                slots[v] = SlotBind::Bound { host };
            }
            (StepKind::WritebackCluster, RegionId::L2Slot(v)) => {
                assert_eq!(
                    slots[v as usize],
                    SlotBind::Bound {
                        host: s.disk_offset
                    },
                    "step {i}: writeback of slot {v} must target the host its \
                     load / L1 patch bound"
                );
            }
            _ => {}
        }
    }
    assert!(
        !slots
            .iter()
            .any(|b| matches!(b, SlotBind::FreshZeroed { .. })),
        "program ends with a fresh L2 init never referenced by an L1 patch"
    );
}

/// Invariant 7(b), flush-order half: for every L1 patch
/// referencing a fresh L2 at host H, the first disk writeback of
/// H precedes the first L1 table write that flushes the patch,
/// with a barrier between them.
fn assert_l2_writeback_precedes_l1_table_write(prog: &[Tagged], _ctx: &ProgramCtx) {
    for (i, t) in prog.iter().enumerate() {
        let s = &t.step;
        if s.kind != StepKind::PatchEntryU64 || s.region != RegionId::L1 {
            continue;
        }
        let host = s.value & L1_OFFSET_MASK;
        let wb = prog
            .iter()
            .position(|u| u.step.kind == StepKind::WritebackCluster && u.step.disk_offset == host)
            .unwrap_or_else(|| {
                panic!("step {i}: fresh L2 at {host:#x} referenced by L1 but never written back")
            });
        let l1w = (i + 1..prog.len())
            .find(|&k| {
                let u = &prog[k].step;
                u.kind == StepKind::WriteRange
                    && u.region == RegionId::L1
                    && u.region_offset <= s.region_offset
                    && s.region_offset + 8 <= u.region_offset + u.len
            })
            .unwrap_or_else(|| panic!("step {i}: L1 patch never flushed by an L1 WriteRange"));
        assert!(
            wb < l1w,
            "7(b) flush order violated: L1 table write at {l1w} precedes the fresh \
             L2 writeback at {wb}"
        );
        assert!(
            prog[wb + 1..l1w]
                .iter()
                .any(|u| matches!(u.step.kind, StepKind::Barrier { .. })),
            "7(b)/(d): no barrier between the fresh L2 writeback ({wb}) and the L1 write ({l1w})"
        );
    }
}

/// Invariant 7(c): refcount writebacks (`WriteRange` from the
/// Refblocks region) appear only in `plan_flush` output, after
/// EVERY pointer patch of their epoch, in ascending refblock
/// order; pointer patches appear only in `plan_write` output.
fn assert_refblock_writebacks_flush_only_and_last(prog: &[Tagged]) {
    for (i, t) in prog.iter().enumerate() {
        let s = &t.step;
        if s.kind == StepKind::PatchEntryU64 {
            assert_eq!(
                t.phase,
                Phase::Write,
                "step {i}: pointer patches belong to plan_write windows"
            );
        }
        if s.kind == StepKind::WriteRange && s.region == RegionId::Refblocks {
            assert_eq!(
                t.phase,
                Phase::Flush,
                "step {i}: 7(c) violated — refcount writeback outside plan_flush"
            );
        }
    }
    let Some(max_epoch) = prog.iter().map(|t| t.epoch).max() else {
        return;
    };
    for e in 0..=max_epoch {
        let last_patch = prog
            .iter()
            .rposition(|t| t.epoch == e && t.step.kind == StepKind::PatchEntryU64);
        let first_rb = prog.iter().position(|t| {
            t.epoch == e
                && t.step.kind == StepKind::WriteRange
                && t.step.region == RegionId::Refblocks
        });
        if let (Some(lp), Some(fr)) = (last_patch, first_rb) {
            assert!(
                lp < fr,
                "epoch {e}: 7(c) violated — refcount writeback at {fr} precedes \
                 pointer patch at {lp}"
            );
        }
        let offs: Vec<u64> = prog
            .iter()
            .filter(|t| {
                t.epoch == e
                    && t.step.kind == StepKind::WriteRange
                    && t.step.region == RegionId::Refblocks
            })
            .map(|t| t.step.region_offset)
            .collect();
        assert!(
            offs.windows(2).all(|w| w[0] < w[1]),
            "epoch {e}: refblock writebacks not in ascending refblock order: {offs:?}"
        );
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FlushClass {
    Barrier,
    L2Writeback,
    L1Write,
    RefblockWrite,
}

fn classify_flush_step(step: &Step, flush_idx: usize) -> FlushClass {
    match step.kind {
        StepKind::Barrier { .. } => FlushClass::Barrier,
        StepKind::WritebackCluster => FlushClass::L2Writeback,
        StepKind::WriteRange if step.region == RegionId::L1 => FlushClass::L1Write,
        StepKind::WriteRange if step.region == RegionId::Refblocks => FlushClass::RefblockWrite,
        other => panic!("flush {flush_idx}: unexpected step kind {other:?} in flush output"),
    }
}

/// Invariant 7(d): each flush's emission matches the contract
/// skeleton `[B] L2-writebacks [B] L1 [B] refblocks [B]` exactly,
/// with empty groups vanishing and adjacent barriers collapsing.
/// The expected sequence is rebuilt from the observed group
/// contents plus the collapse rules and compared positionally, so
/// barrier PLACEMENT is pinned, not just presence.
fn assert_flush_barrier_skeleton(prog: &[Tagged], flush_bounds: &[(usize, usize)]) {
    for (fi, &(start, end)) in flush_bounds.iter().enumerate() {
        // Un-barriered non-barrier steps pending before this flush
        // (the planner's steps_since_barrier, reconstructed from
        // the program alone).
        let mut pending = false;
        for t in &prog[..start] {
            pending = !matches!(t.step.kind, StepKind::Barrier { .. });
        }
        let actual: Vec<FlushClass> = prog[start..end]
            .iter()
            .map(|t| classify_flush_step(&t.step, fi))
            .collect();
        let n_wb = actual
            .iter()
            .filter(|c| **c == FlushClass::L2Writeback)
            .count();
        let n_l1 = actual.iter().filter(|c| **c == FlushClass::L1Write).count();
        let n_rb = actual
            .iter()
            .filter(|c| **c == FlushClass::RefblockWrite)
            .count();
        assert!(n_l1 <= 1, "flush {fi}: more than one L1 write");
        let mut expected = Vec::new();
        let mut since = pending;
        if since {
            expected.push(FlushClass::Barrier);
            since = false;
        }
        for _ in 0..n_wb {
            expected.push(FlushClass::L2Writeback);
            since = true;
        }
        if n_l1 == 1 {
            if since {
                expected.push(FlushClass::Barrier);
            }
            expected.push(FlushClass::L1Write);
            since = true;
        }
        if n_rb > 0 {
            if since {
                expected.push(FlushClass::Barrier);
            }
            for _ in 0..n_rb {
                expected.push(FlushClass::RefblockWrite);
            }
            since = true;
        }
        if since {
            expected.push(FlushClass::Barrier);
        }
        assert_eq!(
            actual, expected,
            "flush {fi}: 7(d) violated — barrier skeleton mismatch"
        );
    }
}

/// Barriers are a flush-only emission in v1 (`plan_write` never
/// emits one; 7(d)'s contract points all live in the flush).
fn assert_no_barriers_in_write_phase(prog: &[Tagged]) {
    for (i, t) in prog.iter().enumerate() {
        if matches!(t.step.kind, StepKind::Barrier { .. }) {
            assert_eq!(
                t.phase,
                Phase::Flush,
                "step {i}: barrier emitted by plan_write"
            );
        }
    }
}

/// The full decision-7 ordering contract plus bounds, over the
/// complete concatenated program of a harness run.
fn assert_ordering_contract(h: &Harness) {
    let ctx = ctx_of(h);
    assert_step_bounds(&h.program, &ctx);
    assert_write_covers_cluster_before_l2_patch(&h.program, &ctx);
    assert_fresh_l2_init_precedes_l1_patch(&h.program, &ctx);
    assert_l2_writeback_precedes_l1_table_write(&h.program, &ctx);
    assert_refblock_writebacks_flush_only_and_last(&h.program);
    assert_flush_barrier_skeleton(&h.program, &h.flush_bounds);
    assert_no_barriers_in_write_phase(&h.program);
}

// ---------------------------------------------------------------------------
// Scenario generation (deterministic pseudo-random write sets)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy)]
struct Scenario {
    cluster_bits: u32,
    l2_slots: usize,
    seed: u64,
    prepopulate: bool,
    device: TargetDevice,
}

/// Deterministic write set mixing the required shapes:
/// sequential runs, sparse full-cluster writes, cluster- and
/// L1-boundary straddles, sub-cluster writes and owned
/// overwrites (request repeats), with both caller-data and fill
/// sources. Independent of the step-buffer size by construction.
fn scenario_requests(sc: &Scenario) -> Vec<(u64, u64, DataSource)> {
    let cs = 1u64 << sc.cluster_bits;
    let entries_per_l2 = cs / 8;
    let l2_cov = entries_per_l2 * cs;
    let virtual_size = L1_TABLES as u64 * l2_cov;
    let total_clusters = virtual_size / cs;
    let mut rng = Rng::new(sc.seed);
    let mut reqs: Vec<(u64, u64, DataSource)> = Vec::new();
    // Fixed shapes every scenario contains: an L1-boundary
    // straddle and a sub-cluster write.
    reqs.push((l2_cov - cs / 2, cs, DataSource::CallerData { offset: 0 }));
    reqs.push((cs / 4 + 1, cs / 2 - 1, DataSource::Fill { byte: 0x5a }));
    let mut cursor = 0u64;
    for _ in 0..9 {
        let (voff, len) = match rng.below(5) {
            0 => {
                // Sequential run of 1-3 clusters.
                let len = (1 + rng.below(3)) * cs;
                if cursor + len > virtual_size {
                    cursor = 0;
                }
                let v = cursor;
                cursor += len;
                (v, len)
            }
            1 => {
                // Sparse full-cluster write.
                (rng.below(total_clusters) * cs, cs)
            }
            2 => {
                // Straddle a cluster boundary (sometimes an L1
                // boundary, when the boundary index is a multiple
                // of entries_per_l2).
                let boundary = (1 + rng.below(total_clusters - 1)) * cs;
                let head = 1 + rng.below(cs - 1);
                let tail = 1 + rng.below(cs - 1);
                let voff = boundary - head;
                (voff, (head + tail).min(virtual_size - voff))
            }
            3 => {
                // Sub-cluster write.
                let c = rng.below(total_clusters);
                let off = rng.below(cs - 1);
                (c * cs + off, 1 + rng.below(cs - off))
            }
            _ => {
                // Owned overwrite: repeat an earlier request's
                // range (a fresh data source below).
                let k = rng.below(reqs.len() as u64) as usize;
                (reqs[k].0, reqs[k].1)
            }
        };
        let data = if rng.below(2) == 0 {
            DataSource::CallerData {
                offset: rng.below(cs),
            }
        } else {
            DataSource::Fill {
                byte: rng.below(256) as u8,
            }
        };
        reqs.push((voff, len, data));
    }
    // Guaranteed owned overwrite of the first request's range.
    reqs.push((reqs[0].0, reqs[0].1, DataSource::Fill { byte: 0xa7 }));
    reqs
}

/// Run one scenario to completion at the given step-buffer
/// capacity: two epochs (a mid-scenario flush and a final flush),
/// optional prepopulated on-disk mappings.
fn run_scenario(sc: &Scenario, cap: usize) -> (Harness, FinalContent) {
    let (mut img, st) = mk_image(sc.cluster_bits, sc.l2_slots, 1, false, sc.device);
    if sc.prepopulate {
        prepopulate(&mut img, 1, &[(0, 1), (0, 3), (2, 0)]);
    }
    let mut h = Harness::new(img, st, cap);
    let reqs = scenario_requests(sc);
    for (i, &(voff, len, data)) in reqs.iter().enumerate() {
        h.write(voff, len, data)
            .unwrap_or_else(|e| panic!("grid write {i} must plan cleanly, got {e:?} ({sc:?})"));
        if i + 1 == reqs.len() / 2 {
            h.flush().expect("mid-scenario flush must plan cleanly");
        }
    }
    h.flush().expect("final flush must plan cleanly");
    let fc = final_content(&h.img);
    (h, fc)
}

/// Step-buffer capacities the window-invariance sweep compares
/// against the effectively-unbounded reference (1024), down to
/// the pathological 1-step buffer that splits every emission
/// group at every possible point.
const INVARIANCE_CAPS: [usize; 7] = [1, 2, 3, 4, 5, 7, 16];

/// The grid body: for each (slot count, seed) combination at one
/// cluster size, pin the full ordering contract on the reference
/// program, then assert window-invariance (identical step
/// sequence AND identical final bytes) at every capacity.
fn grid_for(cluster_bits: u32) {
    for &l2_slots in &[1usize, 2, 3, MAX_L2_SLOTS] {
        for &seed in &[0x3c0d_e5ee_d001u64, 0x3c0d_e5ee_d002] {
            let sc = Scenario {
                cluster_bits,
                l2_slots,
                seed,
                // One prepopulated (LoadCluster + on-disk owned
                // overwrite) and one fully-fresh run per slot count.
                prepopulate: seed.is_multiple_of(2),
                // Exercise the device dimension on one column.
                device: if l2_slots == 2 {
                    TargetDevice::Output
                } else {
                    TargetDevice::Input0
                },
            };
            let (h_ref, fc_ref) = run_scenario(&sc, 1024);
            assert!(
                !h_ref.program.is_empty(),
                "grid scenario emitted nothing ({sc:?})"
            );
            assert_ordering_contract(&h_ref);
            for &cap in &INVARIANCE_CAPS {
                let (h, fc) = run_scenario(&sc, cap);
                assert_eq!(
                    h.steps(),
                    h_ref.steps(),
                    "window invariance violated at cap {cap} ({sc:?})"
                );
                assert_eq!(
                    h.flush_bounds, h_ref.flush_bounds,
                    "flush boundaries shifted at cap {cap} ({sc:?})"
                );
                assert!(
                    fc == fc_ref,
                    "final disk/staging content diverged at cap {cap} ({sc:?})"
                );
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn ordering_grid_512_byte_clusters() {
    grid_for(9);
}

#[test]
fn ordering_grid_4k_clusters() {
    grid_for(12);
}

#[test]
fn ordering_grid_64k_clusters() {
    grid_for(16);
}

#[test]
fn multi_refblock_flush_is_refcounts_last_in_ascending_order() {
    // 512-byte clusters: one refblock covers 256 clusters, so
    // writing the whole 256-cluster virtual disk (4 fresh L2
    // tables + 256 data clusters + metadata) forces allocations
    // into staged refblock 1 and the flush must write BOTH
    // refblocks back, ascending, after all patches.
    let cs = 512u64;
    let virtual_size = L1_TABLES as u64 * (cs / 8) * cs;
    let run = |cap: usize| {
        let (img, st) = mk_image(9, 2, 2, false, TargetDevice::Input0);
        let mut h = Harness::new(img, st, cap);
        let mut v = 0;
        while v < virtual_size {
            let len = (8 * cs).min(virtual_size - v);
            h.write(v, len, DataSource::CallerData { offset: 0 })
                .expect("full-disk write must plan cleanly");
            v += len;
        }
        h.flush().expect("flush must plan cleanly");
        h
    };
    let h = run(1024);
    assert_ordering_contract(&h);
    let rb_writes: Vec<&Tagged> = h
        .program
        .iter()
        .filter(|t| t.step.kind == StepKind::WriteRange && t.step.region == RegionId::Refblocks)
        .collect();
    assert_eq!(rb_writes.len(), 2, "both staged refblocks must flush");
    assert_eq!(rb_writes[0].step.region_offset, 0);
    assert_eq!(rb_writes[0].step.disk_offset, 2 * cs);
    assert_eq!(rb_writes[1].step.region_offset, cs);
    assert_eq!(rb_writes[1].step.disk_offset, 4 * cs);
    // Window-invariance holds for the multi-refblock epoch too.
    for cap in [1usize, 3] {
        let h_small = run(cap);
        assert_eq!(h_small.steps(), h.steps(), "cap {cap}");
        assert!(
            final_content(&h_small.img) == final_content(&h.img),
            "cap {cap}"
        );
    }
}

#[test]
fn flush_skeleton_exact_shapes() {
    let cs = 1u64 << 12;

    // (a) No activity: the flush emits nothing at all (every
    // group empty, all barriers collapse away).
    let (img, st) = mk_image(12, 2, 1, false, TargetDevice::Input0);
    let mut h = Harness::new(img, st, 8);
    h.flush().expect("empty flush");
    assert!(h.program.is_empty(), "an idle epoch flushes to nothing");
    assert_ordering_contract(&h);

    // (b) Owned-overwrite-only epoch: exactly one barrier pinning
    // the data write; no metadata groups exist.
    let (mut img, st) = mk_image(12, 2, 1, false, TargetDevice::Input0);
    prepopulate(&mut img, 1, &[(0, 0)]);
    let mut h = Harness::new(img, st, 8);
    h.write(0, 8, DataSource::Fill { byte: 1 })
        .expect("owned overwrite");
    h.flush().expect("flush");
    assert_eq!(
        h.kinds(),
        vec![
            StepKind::LoadCluster,
            StepKind::FillRange,
            StepKind::Barrier {
                class: BarrierClass::Durability
            },
        ]
    );
    assert_ordering_contract(&h);
    // A second flush right away emits nothing further.
    let before = h.program.len();
    h.flush().expect("second flush");
    assert_eq!(
        h.program.len(),
        before,
        "a clean epoch re-flushes to nothing"
    );
    assert_ordering_contract(&h);

    // (c) Allocating epoch: the full skeleton, every group
    // populated: [B] writeback [B] L1 [B] refblock [B].
    let (img, st) = mk_image(12, 2, 1, false, TargetDevice::Input0);
    let mut h = Harness::new(img, st, 64);
    h.write(0, cs, DataSource::CallerData { offset: 0 })
        .expect("allocating write");
    h.flush().expect("flush");
    let durability = StepKind::Barrier {
        class: BarrierClass::Durability,
    };
    assert_eq!(
        h.kinds(),
        vec![
            StepKind::ZeroRegion,
            StepKind::PatchEntryU64, // L1 -> fresh L2
            StepKind::WriteRange,    // data
            StepKind::PatchEntryU64, // L2 entry -> data cluster
            durability,
            StepKind::WritebackCluster, // fresh L2 table
            durability,
            StepKind::WriteRange, // L1
            durability,
            StepKind::WriteRange, // refblock 0 (refcounts last)
            durability,
        ]
    );
    let flush_steps = &h.program[4..];
    assert_eq!(flush_steps[3].step.region, RegionId::L1);
    assert_eq!(flush_steps[5].step.region, RegionId::Refblocks);
    assert_ordering_contract(&h);
}

#[test]
fn gated_images_never_yield_a_write_state() {
    // Decision 8 as the 3c "no write step exists for a gated
    // image" property: `plan_write` needs a `WriteState`, and a
    // gated header cannot produce one, so no program can exist.
    let cs = 4096u64;
    let virtual_size = L1_TABLES as u64 * (cs / 8) * cs;
    let cfg = StagingConfig {
        l2_slots: 2,
        max_refblocks: 32,
        device: TargetDevice::Input0,
    };
    let base = header_bytes(12, virtual_size, L1_TABLES, false);
    assert!(
        new_state(&parse(&base), &cfg).is_ok(),
        "the base header must pass"
    );

    let mut cases: Vec<([u8; 4096], Gate)> = Vec::new();
    let mut with = |edit: &dyn Fn(&mut [u8; 4096]), gate: Gate| {
        let mut h = base;
        edit(&mut h);
        cases.push((h, gate));
    };
    with(
        &|h| h[96..100].copy_from_slice(&5u32.to_be_bytes()),
        Gate::RefcountWidth,
    );
    with(
        &|h| h[72..80].copy_from_slice(&qcow2::INCOMPAT_COMPRESSION.to_be_bytes()),
        Gate::UnknownIncompatible,
    );
    with(
        &|h| h[72..80].copy_from_slice(&(1u64 << 60).to_be_bytes()),
        Gate::UnknownIncompatible,
    );
    with(
        &|h| h[72..80].copy_from_slice(&qcow2::INCOMPAT_EXTENDED_L2.to_be_bytes()),
        Gate::ExtendedL2,
    );
    with(
        &|h| h[72..80].copy_from_slice(&qcow2::INCOMPAT_EXTERNAL_DATA.to_be_bytes()),
        Gate::ExternalDataFile,
    );
    with(
        &|h| h[32..36].copy_from_slice(&1u32.to_be_bytes()),
        Gate::Encryption,
    );
    with(
        &|h| h[32..36].copy_from_slice(&2u32.to_be_bytes()),
        Gate::Encryption,
    );
    with(
        &|h| h[72..80].copy_from_slice(&qcow2::INCOMPAT_DIRTY.to_be_bytes()),
        Gate::DirtyCorrupt,
    );
    with(
        &|h| h[72..80].copy_from_slice(&qcow2::INCOMPAT_CORRUPT.to_be_bytes()),
        Gate::DirtyCorrupt,
    );
    with(
        &|h| h[60..64].copy_from_slice(&1u32.to_be_bytes()),
        Gate::HasSnapshots,
    );
    for (bytes, gate) in cases {
        assert_eq!(
            new_state(&parse(&bytes), &cfg).err(),
            Some(gate),
            "gated header must refuse before any step can exist"
        );
    }

    // Unsupported version (parse cannot produce it; defend the
    // direct-construction path).
    let mut hdr = parse(&base);
    hdr.version = 1;
    assert_eq!(new_state(&hdr, &cfg).err(), Some(Gate::UnsupportedVersion));

    // Out-of-range staging config refuses too: still no state.
    let bad = StagingConfig {
        l2_slots: 0,
        max_refblocks: 32,
        device: TargetDevice::Input0,
    };
    assert_eq!(
        new_state(&parse(&base), &bad).err(),
        Some(Gate::InvalidStagingConfig)
    );
}

/// Negative controls: each mechanical checker must actually
/// reject a program violating its invariant (guards against the
/// helpers passing vacuously, now and when phase 7 extends them).
#[test]
fn invariant_helpers_reject_violations() {
    fn panics(f: impl FnOnce()) -> bool {
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)).is_err()
    }
    fn tag(
        kind: StepKind,
        region: RegionId,
        disk_offset: u64,
        len: u64,
        value: u64,
        phase: Phase,
    ) -> Tagged {
        Tagged {
            step: Step {
                kind,
                device: TargetDevice::Input0,
                region,
                region_offset: 0,
                disk_offset,
                len,
                value,
            },
            phase,
            epoch: 0,
        }
    }
    let cs = 4096u64;
    let ctx = ProgramCtx {
        cs,
        l2_slots: 2,
        l1_len: 32,
        rt_len: 8,
        refblocks_len: cs as usize,
        caller_len: 8 * cs as usize,
        device: TargetDevice::Input0,
    };

    // Bounds: an L2 slot index outside the configured window.
    let prog = vec![tag(
        StepKind::LoadCluster,
        RegionId::L2Slot(5),
        4 * cs,
        cs,
        0,
        Phase::Write,
    )];
    assert!(panics(|| assert_step_bounds(&prog, &ctx)));

    // 7(a): an L2 patch with no preceding data write covering the
    // referenced cluster.
    let prog = vec![tag(
        StepKind::PatchEntryU64,
        RegionId::L2Slot(0),
        0,
        0,
        5 * cs | OFLAG_COPIED,
        Phase::Write,
    )];
    assert!(panics(|| assert_write_covers_cluster_before_l2_patch(
        &prog, &ctx
    )));

    // 7(b) in-stream: an L1 patch with no pending fresh-L2 init.
    let prog = vec![tag(
        StepKind::PatchEntryU64,
        RegionId::L1,
        0,
        0,
        4 * cs | OFLAG_COPIED,
        Phase::Write,
    )];
    assert!(panics(|| assert_fresh_l2_init_precedes_l1_patch(
        &prog, &ctx
    )));

    // 7(b) flush order: an L1 patch whose fresh L2 is never
    // written back before (or at all for) the L1 table write.
    let prog = vec![
        tag(
            StepKind::ZeroRegion,
            RegionId::L2Slot(0),
            0,
            cs,
            0,
            Phase::Write,
        ),
        tag(
            StepKind::PatchEntryU64,
            RegionId::L1,
            0,
            0,
            4 * cs | OFLAG_COPIED,
            Phase::Write,
        ),
        tag(
            StepKind::WriteRange,
            RegionId::L1,
            3 * cs,
            32,
            0,
            Phase::Flush,
        ),
    ];
    assert!(panics(|| assert_l2_writeback_precedes_l1_table_write(
        &prog, &ctx
    )));

    // 7(c): a refcount writeback emitted by plan_write.
    let prog = vec![tag(
        StepKind::WriteRange,
        RegionId::Refblocks,
        2 * cs,
        cs,
        0,
        Phase::Write,
    )];
    assert!(panics(|| assert_refblock_writebacks_flush_only_and_last(
        &prog
    )));

    // 7(d): a flush whose emission lacks the closing barrier.
    let prog = vec![tag(
        StepKind::WritebackCluster,
        RegionId::L2Slot(0),
        4 * cs,
        cs,
        0,
        Phase::Flush,
    )];
    assert!(panics(|| assert_flush_barrier_skeleton(&prog, &[(0, 1)])));
}

/// The amended-decision-7 EOV-tail shape (phase-4 plan / D9): on
/// an unaligned virtual size, a tail write covering
/// [cluster base, virtual_size) is a full-coverage allocating
/// write on backed and backing-less images alike. The invariant
/// helpers must hold over programs containing the shape — 7(a)'s
/// coverage check in particular must see the body write plus the
/// beyond-EOV ZeroRange as together covering the whole physical
/// cluster — and window-invariance must keep holding (the new
/// path is a classification outcome, not a window boundary).
#[test]
fn ordering_eov_tail_unaligned_virtual_size() {
    let cluster_bits = 12u32;
    let cs = 1u64 << cluster_bits;
    let l2_cov = (cs / 8) * cs;
    let tail_len = cs / 2 + 36;
    let vs = l2_cov + 2 * cs + tail_len; // tail cluster lives in L1 table 1
    let tail_base = vs - tail_len;
    for backing in [false, true] {
        let run = |cap: usize| {
            let (img, st) = mk_image_vs(cluster_bits, 2, 1, backing, TargetDevice::Input0, vs);
            let mut h = Harness::new(img, st, cap);
            // Full-cluster allocating writes (safe on backed
            // images) either side of the L1 boundary...
            h.write(0, cs, DataSource::CallerData { offset: 0 })
                .expect("full-cluster allocating write");
            h.write(l2_cov, cs, DataSource::Fill { byte: 0x2c })
                .expect("full-cluster allocating write, table 1");
            // ...the EOV-tail write itself...
            h.write(tail_base, tail_len, DataSource::CallerData { offset: 3 })
                .expect("EOV-tail write must classify as full coverage");
            // ...and an owned partial overwrite of the tail
            // cluster afterwards (allowed on backed images too).
            h.write(tail_base + 5, 9, DataSource::Fill { byte: 0x77 })
                .expect("owned tail overwrite");
            h.flush().expect("flush");
            let fc = final_content(&h.img);
            (h, fc)
        };
        let (h_ref, fc_ref) = run(1024);
        assert_ordering_contract(&h_ref);
        // The program contains the EOV-tail shape: a ZeroRange
        // from the EOV offset to the physical cluster end.
        assert!(
            h_ref
                .program
                .iter()
                .any(|t| t.step.kind == StepKind::ZeroRange
                    && t.step.len == cs - tail_len
                    && t.step.disk_offset % cs == tail_len),
            "beyond-EOV ZeroRange missing (backing {backing})"
        );
        for &cap in &INVARIANCE_CAPS {
            let (h, fc) = run(cap);
            assert_eq!(
                h.steps(),
                h_ref.steps(),
                "window invariance violated at cap {cap} (backing {backing})"
            );
            assert!(
                fc == fc_ref,
                "final disk/staging content diverged at cap {cap} (backing {backing})"
            );
        }
    }
    // Genuinely partial below-EOV tail writes on a BACKED image
    // still refuse, emitting nothing for the refused cluster
    // beyond the fresh-L2 scaffolding group.
    let (img, st) = mk_image_vs(cluster_bits, 2, 1, true, TargetDevice::Input0, vs);
    let mut h = Harness::new(img, st, 1024);
    let err = h
        .write(
            tail_base,
            tail_len - 1,
            DataSource::CallerData { offset: 0 },
        )
        .expect_err("coverage below EOV must refuse");
    assert_eq!(err, WriteError::NeedsBackingFill);
    let err = h
        .write(
            tail_base + 4,
            tail_len - 4,
            DataSource::CallerData { offset: 0 },
        )
        .expect_err("head gap below EOV must refuse");
    assert_eq!(err, WriteError::NeedsBackingFill);
}

#[test]
fn refusals_emit_no_steps_beyond_planned_clusters() {
    let cs = 4096u64;

    // Case 1: a straddling partial-allocating write on a BACKED
    // image refuses (NeedsBackingFill) at the partial cluster.
    // The emitted prefix is exactly the fully-planned first
    // cluster's group; the refused cluster leaves nothing behind.
    let run = |cap: usize| {
        let (img, st) = mk_image(12, 2, 1, true, TargetDevice::Input0);
        let mut h = Harness::new(img, st, cap);
        let err = h
            .write(0, cs + 100, DataSource::CallerData { offset: 0 })
            .expect_err("partial allocating write on a backed image must refuse");
        assert_eq!(err, WriteError::NeedsBackingFill);
        h
    };
    let mut h = run(1024);
    assert_eq!(
        h.kinds(),
        vec![
            StepKind::ZeroRegion,    // fresh L2 init
            StepKind::PatchEntryU64, // L1 -> fresh L2
            StepKind::WriteRange,    // cluster 0's data (full cluster)
            StepKind::PatchEntryU64, // L2 entry -> cluster 0's data
        ],
        "refusal emits nothing beyond the already-planned cluster"
    );
    assert_eq!(
        h.st.alloc_cursor().allocated,
        2,
        "nothing was allocated for the refused cluster"
    );
    // Refusal windows are window-invariant too.
    for cap in [1usize, 3, 7] {
        let h_small = run(cap);
        assert_eq!(h_small.steps(), h.steps(), "cap {cap}");
    }
    // The refusal abandoned the request (state back to idle): a
    // full-cluster write and a flush proceed, and the whole
    // program — refused window included — satisfies the contract,
    // which is what makes the emitted prefix safe to execute.
    h.write(cs, cs, DataSource::Fill { byte: 3 })
        .expect("full-cluster write after refusal");
    h.flush().expect("flush after refusal");
    assert_ordering_contract(&h);

    // Case 2: a classification refusal mid-request (compressed
    // cluster) after a fully-planned cluster: same shape — the
    // planned prefix stands, the refused cluster emits nothing.
    let (mut img, st) = mk_image(12, 2, 1, false, TargetDevice::Input0);
    set_l1(&mut img, 0, 4 * cs | OFLAG_COPIED);
    img.disk[4 * cs as usize..5 * cs as usize].fill(0);
    put_disk_u64(&mut img, 4 * cs as usize + 8, 6 * cs | OFLAG_COMPRESSED);
    set_rc(&mut img, 4, 1);
    let mut h = Harness::new(img, st, 1024);
    let err = h
        .write(0, 2 * cs, DataSource::CallerData { offset: 0 })
        .expect_err("write reaching a compressed cluster must refuse");
    assert_eq!(err, WriteError::CompressedCluster);
    assert_eq!(
        h.kinds(),
        vec![
            StepKind::LoadCluster,   // stage the existing L2 (window boundary)
            StepKind::WriteRange,    // cluster 0's data
            StepKind::PatchEntryU64, // L2 entry -> cluster 0's data
        ],
        "classification refusal emits nothing for the refused cluster"
    );
    h.flush().expect("flush after classification refusal");
    assert_ordering_contract(&h);
}
