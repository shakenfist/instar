//! Pure windowed step-program planner for writes into existing
//! qcow2 images.
//!
//! This crate is the centrepiece of
//! `docs/plans/PLAN-qcow2-write-infrastructure.md`: a `no_std`,
//! I/O-free planner that turns "write N bytes at virtual offset
//! X into an existing qcow2" into a typed step program the guest
//! ops (commit, rebase, bench — phases 4-6) execute. Every shape
//! here implements a numbered settled decision from
//! `docs/plans/PLAN-qcow2-write-infrastructure-phase-03-crate.md`
//! ("Settled design decisions", pinned empirically by the master
//! plan's "Findings: phase 1 semantics pin" Q4 subsection):
//!
//! - Decision 1 — *windowed step-program*: [`plan_write`] /
//!   [`plan_flush`] emit into a caller-provided [`StepBuf`]; a
//!   full-image program is never materialised (commit's envelope
//!   reaches ~2M clusters). [`WriteError::BufFull`] is the
//!   resume signal, not a failure.
//! - Decision 2 — *steps are plain Rust data*: [`Step`] is a
//!   `#[repr(C)]` struct with a [`StepKind`] tag, const-asserted
//!   at ≤ 48 bytes so a 64 KiB buffer holds 1300+ steps.
//! - Decision 3 — *address-free planner*: steps name staged
//!   buffers by [`RegionId`] + offset and devices by
//!   [`TargetDevice`]; the executor owns the region-id → slice
//!   mapping. No guest address ever enters this crate.
//! - Decision 4 — *barrier semantics*: [`BarrierClass`] encodes
//!   the fsync asymmetry (the call table exposes only
//!   `fsync_input`, `src/shared/src/lib.rs`; executors degrade
//!   Durability to Ordering where no fsync primitive exists).
//! - Decision 5 — *fixed-slot L2 window* with planner-emitted
//!   load/writeback and deterministic LRU (access counter in
//!   [`WriteState`], no clocks).
//! - Decision 6 — *single staged refblock copy, mutated in
//!   place* (bench's model), dirty bitset in [`WriteState`].
//! - Decision 7 — *crash-ordering contract in emission order*
//!   (pinned mechanically by the step-3c suite).
//! - Decision 8 — *unified envelope gates* in
//!   [`check_envelope`], run by [`new_state`] before any step
//!   can exist.
//! - Decision 9 — capacity refusals are clean but not
//!   byte-idempotent in v1 (see [`WriteError`]).
//! - Decision 10 — dependencies are `shared`, `qcow2` (parsing,
//!   geometry) and `snapshot` (allocator + refcount RMW
//!   primitives, e.g. [`snapshot::qcow2::AllocCursor`]).
//!
//! Phase 3a shipped the type vocabulary, the envelope gates and
//! a gated [`WriteState`] constructor. Phase 3b fills in
//! [`plan_write`] and [`plan_flush`], with three documented
//! refinements the phase plan anticipated:
//!
//! - [`StagedRegions`]: the planning calls take a view of the
//!   executor-staged buffers (the API sketch anticipated a
//!   `staged` parameter). Classification reads L2 entries and
//!   refcounts through it; the allocator mutates the staged
//!   refblocks through it in place (decision 6).
//! - [`StepKind::FillRange`] and [`StepKind::ZeroRegion`] join
//!   the step vocabulary (the sketch's trailing `...`): the
//!   former lowers [`DataSource::Fill`], the latter initialises
//!   a fresh L2 window slot to zeros.
//! - The decision-5 window protocol: when the planner emits a
//!   [`StepKind::LoadCluster`] it returns
//!   [`WriteError::BufFull`] immediately, because the slot's
//!   bytes exist only after the executor runs the load. BufFull
//!   is therefore a *window boundary* signal, not strictly a
//!   capacity signal; the caller's loop is identical either way.

#![no_std]

use qcow2::{QcowHeader, L1_OFFSET_MASK, L2_OFFSET_MASK, OFLAG_COMPRESSED, OFLAG_COPIED};
use snapshot::qcow2::{alloc_cluster_in_refblocks, read_refcount_in_block, AllocCursor};
use snapshot::SnapshotError;

// ---------------------------------------------------------------------------
// Capacity constants
// ---------------------------------------------------------------------------

/// Upper bound on [`StagingConfig::l2_slots`].
///
/// Matches the stage-everything caps of the ops this crate
/// absorbs (`MAX_STAGED_L2 == 256` in both
/// `src/operations/commit/src/main.rs` and
/// `src/operations/rebase/src/main.rs`), so decision 5's
/// degenerate large-window case covers commit's current
/// behaviour without growing [`WriteState`].
pub const MAX_L2_SLOTS: usize = 256;

/// Upper bound on [`StagingConfig::max_refblocks`].
///
/// The master plan's Q4 findings call out the cap asymmetry to
/// unify: commit caps at 32 staged refblocks while rebase and
/// bench cap at 2048 (`WRITE_MAX_REFBLOCKS`,
/// `src/operations/bench/src/main.rs`). The unified crate takes
/// the larger figure; the dirty bitset this sizes costs
/// `2048 / 8 == 256` bytes of state.
pub const MAX_REFBLOCKS: usize = 2048;

/// Decision 2's size budget for [`Step`], asserted below.
pub const STEP_SIZE_LIMIT: usize = 48;

// ---------------------------------------------------------------------------
// Geometry
// ---------------------------------------------------------------------------

/// Image geometry derived from a parsed [`QcowHeader`]
/// (decision 10: `qcow2` owns parsing; this crate derives what
/// planning needs and nothing else).
///
/// All derived quantities assume the envelope gates have passed:
/// `entries_per_l2` assumes standard 8-byte L2 entries
/// (extended-L2 is gated, [`Gate::ExtendedL2`]) and
/// `entries_per_refblock` assumes 16-bit refcounts
/// ([`Gate::RefcountWidth`]). [`new_state`] enforces this by
/// running [`check_envelope`] before deriving a `Geometry`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Geometry {
    /// `cluster_bits` from the header (9..=21 by parse).
    pub cluster_bits: u32,
    /// `1 << cluster_bits`, in bytes.
    pub cluster_size: u64,
    /// Virtual disk size in bytes.
    pub virtual_size: u64,
    /// Host byte offset of the active L1 table.
    pub l1_table_offset: u64,
    /// Active L1 table size in entries.
    pub l1_size: u32,
    /// Host byte offset of the refcount table.
    pub refcount_table_offset: u64,
    /// Refcount table size in clusters.
    pub refcount_table_clusters: u32,
    /// Refcount entry width in bits (16 post-gate; kept
    /// explicitly because the `snapshot` primitives take it as
    /// a parameter, e.g.
    /// `snapshot::qcow2::alloc_contiguous_clusters_in_refblocks`).
    pub refcount_bits: u32,
    /// L2 entries per L2 table: `cluster_size / 8` (standard
    /// entries only; extended-L2 is gated).
    pub entries_per_l2: u64,
    /// Virtual bytes covered by one L2 table:
    /// `cluster_size * entries_per_l2`.
    pub l2_coverage: u64,
    /// Refcount entries per refblock:
    /// `cluster_size * 8 / refcount_bits`.
    pub entries_per_refblock: u64,
}

impl Geometry {
    /// Derive planner geometry from a parsed header.
    ///
    /// Pure derivation with no gating — callers that need the
    /// derived quantities to be meaningful must run
    /// [`check_envelope`] first, as [`new_state`] does. At the
    /// parse-enforced maximum `cluster_bits == 21` the largest
    /// product here is `l2_coverage == 2^39`, so no arithmetic
    /// can overflow.
    pub fn from_header(hdr: &QcowHeader) -> Geometry {
        let entries_per_l2 = hdr.cluster_size / 8;
        Geometry {
            cluster_bits: hdr.cluster_bits,
            cluster_size: hdr.cluster_size,
            virtual_size: hdr.virtual_size,
            l1_table_offset: hdr.l1_table_offset,
            l1_size: hdr.l1_size,
            refcount_table_offset: hdr.refcount_table_offset,
            refcount_table_clusters: hdr.refcount_table_clusters,
            refcount_bits: hdr.refcount_bits,
            entries_per_l2,
            l2_coverage: hdr.cluster_size * entries_per_l2,
            entries_per_refblock: hdr.cluster_size * 8 / hdr.refcount_bits as u64,
        }
    }
}

// ---------------------------------------------------------------------------
// Staging configuration
// ---------------------------------------------------------------------------

/// Caller-chosen staging shape (decisions 5 and 6).
///
/// The caller (executor) carves the actual staging buffers out
/// of its scratch region — the master plan's Q4 findings pin
/// staging to scratch-address-carved slices, never `static`
/// (the `.bss`/HEADER_MISMATCH hazard class). The planner only
/// needs the *shape*: how many L2 window slots exist (decision
/// 5) and how many staged refblocks the dirty bitset must cover
/// (decision 6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StagingConfig {
    /// Number of L2 window slots the executor stages
    /// (`1..=MAX_L2_SLOTS`). Stage-everything (commit today) is
    /// the degenerate case of a large window; bench's
    /// zero-staging RMW maps onto a small one.
    pub l2_slots: usize,
    /// Number of staged refblocks the dirty bitset covers
    /// (`1..=MAX_REFBLOCKS`).
    pub max_refblocks: usize,
    /// The device the written image lives on (decision 3 — the
    /// dimension exists because commit writes the *backing* via
    /// the output device while bench writes its image via input
    /// slot 0). Every step [`plan_write`] / [`plan_flush`] emit
    /// targets this device; a 3b field the phase plan's
    /// `StagingConfig` sketch anticipated with its trailing
    /// `...`.
    pub device: TargetDevice,
}

// ---------------------------------------------------------------------------
// Step vocabulary (decisions 2, 3, 4)
// ---------------------------------------------------------------------------

/// Staged-buffer regions a [`Step`] may reference (decision 3).
///
/// The planner is address-free: it names buffers symbolically
/// and the executor owns the region-id → slice mapping. This is
/// what keeps the crate pure and host-unit-testable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum RegionId {
    /// The staged copy of the active L1 table.
    L1,
    /// One slot of the fixed-slot staged-L2 window (decision
    /// 5); the index is `< StagingConfig::l2_slots`.
    L2Slot(u16),
    /// The staged copy of the refcount table.
    RefcountTable,
    /// The staged refblock array (single copy, mutated in
    /// place — decision 6, bench's model).
    Refblocks,
    /// The cluster-sized bounce buffer for sub-cluster RMW.
    Bounce,
    /// The caller's data buffer for [`DataSource::CallerData`].
    CallerData,
}

/// Devices a [`Step`] may target (decision 3).
///
/// The device dimension exists from day one because commit is
/// two-device: it writes the backing via the output device and
/// clears the overlay via input slot 0.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum TargetDevice {
    /// Input device slot 0 (RW where the op opens it RW;
    /// commit's overlay, bench's image).
    Input0,
    /// The output device (commit's backing, rebase's overlay).
    Output,
}

/// Barrier strength (decision 4 — the fsync asymmetry, decided).
///
/// The contract: no step after a barrier may be issued before
/// every step preceding it has been issued (`Ordering`) / made
/// durable (`Durability`). Executors map `Durability` to
/// `fsync_input(0)` where the target is the RW input device and
/// degrade it to `Ordering` where no fsync primitive exists —
/// the call table exposes only `fsync_input`
/// (`src/shared/src/lib.rs`), and commit/rebase write via the
/// output device with zero fsyncs today. Adding `fsync_output`
/// is recorded future work that phases 4-5 must NOT take
/// implicitly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum BarrierClass {
    /// Issue-order barrier only.
    Ordering,
    /// Durability barrier; degrades to [`Self::Ordering`] on
    /// devices without an fsync primitive.
    Durability,
}

/// Discriminant of a [`Step`] (decision 2).
///
/// Which `Step` fields each kind consumes is documented per
/// variant; unused numeric fields are zero, an unused `region`
/// is [`RegionId::Bounce`] and an unused `device` carries the
/// configured [`StagingConfig::device`] — fixed fillers so
/// emitted programs are bit-deterministic (the step-3c
/// window-invariance property compares whole `Step` values).
/// Executors stay dumb: even the refblock flush is a planner
/// emission pattern (per-dirty-refblock [`StepKind::WriteRange`]
/// steps from [`plan_flush`]), not a magic composite step
/// (decision 6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum StepKind {
    /// Read `len` bytes from `device` at `disk_offset` into
    /// `region` at `region_offset` (COW/RMW source reads into
    /// [`RegionId::Bounce`]).
    ReadCluster,
    /// Write `len` bytes from `region` at `region_offset` to
    /// `device` at `disk_offset`.
    WriteRange,
    /// Write `len` zero bytes to `device` at `disk_offset` (no
    /// region; sub-cluster zero-fill around freshly allocated
    /// data clusters).
    ZeroRange,
    /// Write `len` bytes of the fill byte (the low 8 bits of
    /// `value`) to `device` at `disk_offset` (no region). Lowers
    /// [`DataSource::Fill`] so bench-style patterned writes
    /// never bounce through a staged buffer; a 3b extension of
    /// the decision-2 vocabulary (the phase plan's `StepKind`
    /// sketch ends in `...`).
    FillRange,
    /// Store `value` as a big-endian u64 at `region_offset`
    /// within `region` (L1/L2 pointer patches; reaches disk via
    /// a later [`Self::WriteRange`] / [`Self::WritebackCluster`]
    /// per decision 7's ordering).
    PatchEntryU64,
    /// Load one cluster (`len == cluster_size`) from `device`
    /// at `disk_offset` into the L2 window slot `region`
    /// (decision 5, emitted on window miss).
    LoadCluster,
    /// Write one cluster (`len == cluster_size`) from the L2
    /// window slot `region` back to `device` at `disk_offset`
    /// (decision 5, emitted before eviction or at flush).
    WritebackCluster,
    /// Zero `len` bytes within `region` at `region_offset` (no
    /// device I/O). Initialises a freshly allocated L2 table's
    /// window slot to all-zero before entries are patched into
    /// it; the slot reaches disk via a later
    /// [`Self::WritebackCluster`], which decision 7(b) orders
    /// before the L1 patch's disk write. A 3b extension of the
    /// decision-2 vocabulary.
    ZeroRegion,
    /// Barrier of the given class separating emission groups
    /// (decision 4); consumes no other fields.
    Barrier {
        /// Barrier strength.
        class: BarrierClass,
    },
}

/// One planned step (decision 2: plain Rust data, not a packed
/// byte encoding — planner and executor share a binary, so no
/// serialization boundary exists).
///
/// Fixed-size `#[repr(C)]` struct, const-asserted at ≤
/// [`STEP_SIZE_LIMIT`] bytes so a 64 KiB buffer holds 1300+
/// steps (≈ 100+ worst-case allocating clusters per refill at
/// ~11 steps each — master plan Q4). Field applicability per
/// kind is documented on [`StepKind`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct Step {
    /// What the executor must do; selects which fields apply.
    pub kind: StepKind,
    /// Device side of the transfer (decision 3).
    pub device: TargetDevice,
    /// Staged-buffer side of the transfer (decision 3).
    pub region: RegionId,
    /// Byte offset within `region`.
    pub region_offset: u64,
    /// Host byte offset on `device`.
    pub disk_offset: u64,
    /// Transfer length in bytes.
    pub len: u64,
    /// Payload for [`StepKind::PatchEntryU64`].
    pub value: u64,
}

const _: () = assert!(core::mem::size_of::<Step>() <= STEP_SIZE_LIMIT);

// ---------------------------------------------------------------------------
// Step buffer
// ---------------------------------------------------------------------------

/// Signal that a [`StepBuf`] has no room for another step.
///
/// Converted to [`WriteError::BufFull`] at the planner boundary;
/// per decision 1 this is the normal windowing resume signal,
/// not a failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BufFull;

/// Caller-provided step window (decision 1).
///
/// Wraps a caller-owned `&mut [Step]` — the buffer length (and
/// therefore the window size) is caller-chosen — with an
/// emitted-count cursor. The executor loop is: plan into the
/// buffer until `Ok` or [`WriteError::BufFull`], execute
/// [`Self::steps`], [`Self::reset`], resume.
pub struct StepBuf<'a> {
    buf: &'a mut [Step],
    emitted: usize,
}

impl<'a> StepBuf<'a> {
    /// Wrap a caller-provided buffer; the cursor starts at zero.
    pub fn new(buf: &'a mut [Step]) -> StepBuf<'a> {
        StepBuf { buf, emitted: 0 }
    }

    /// Append one step, or signal [`BufFull`] with the buffer
    /// unchanged (the planner records its resume point in
    /// [`WriteState`] and surfaces [`WriteError::BufFull`]).
    pub fn push(&mut self, step: Step) -> Result<(), BufFull> {
        if self.emitted == self.buf.len() {
            return Err(BufFull);
        }
        self.buf[self.emitted] = step;
        self.emitted += 1;
        Ok(())
    }

    /// Steps emitted since construction or the last
    /// [`Self::reset`].
    pub fn emitted(&self) -> usize {
        self.emitted
    }

    /// Total capacity of the underlying buffer.
    pub fn capacity(&self) -> usize {
        self.buf.len()
    }

    /// Slots still free in this window.
    pub fn remaining(&self) -> usize {
        self.buf.len() - self.emitted
    }

    /// The emitted prefix, in emission order (the program the
    /// executor runs for this window).
    pub fn steps(&self) -> &[Step] {
        &self.buf[..self.emitted]
    }

    /// Rewind the cursor so the buffer can take the next
    /// window. Does not clear the underlying storage.
    pub fn reset(&mut self) {
        self.emitted = 0;
    }
}

// ---------------------------------------------------------------------------
// Staged-region view (decisions 3, 5, 6 — 3b refinement)
// ---------------------------------------------------------------------------

/// The planner's view of the executor-staged buffers, passed to
/// every planning call.
///
/// A 3b refinement the phase plan anticipated (its API sketch
/// carried a `staged: ...` parameter): the planner is pure — no
/// I/O, no guest addresses — but classification must read L2
/// entries and refcounts *somewhere*, and the settled model is
/// that the caller lends the planner a view of the same staged
/// buffers its executor maps the [`RegionId`]s onto. The view is
/// passed per call rather than stored in [`WriteState`] so the
/// state type stays lifetime-free for the ops' scratch-carved
/// staging.
///
/// Field-by-field contract (each slice is the exact buffer the
/// executor uses for the corresponding [`RegionId`]):
///
/// - `l1` ([`RegionId::L1`]): the staged active L1, at least
///   `l1_size * 8` bytes. Read-only to the planner — L1
///   mutations are emitted as [`StepKind::PatchEntryU64`] steps
///   so the crash-ordering suite can check them as data
///   (decision 7).
/// - `l2_window` ([`RegionId::L2Slot`]): the staged-L2 window,
///   [`StagingConfig::l2_slots`] contiguous cluster-sized slots.
///   Read-only to the planner (same reason).
/// - `refcount_table` ([`RegionId::RefcountTable`]): the staged
///   refcount table; maps staged refblock index to host offset
///   for [`plan_flush`]'s refcounts-last write-backs. At least
///   8 bytes per staged refblock. Read-only (v1 never grows the
///   refcount table — decision 9).
/// - `refblocks` ([`RegionId::Refblocks`]): the staged refblocks
///   as a dense prefix — staged refblock `j` occupies bytes
///   `[j * cluster_size, (j + 1) * cluster_size)` and covers
///   host cluster indices `[j * entries_per_refblock, ...)` from
///   host offset zero (bench's contiguous-from-index-0 staging
///   model). **Mutable**: decision 6 pins bench's single staged
///   copy mutated in place, so the `snapshot` crate's allocator
///   updates refcounts here directly at plan time and
///   [`plan_flush`] emits only the write-backs.
///
/// The planner assumes the staged regions reflect every step
/// emitted by *previous* planning calls: the decision-1 executor
/// loop (plan a window, execute it, reset the buffer, plan on)
/// is a hard contract, because classification reads through this
/// view would otherwise see stale bytes.
pub struct StagedRegions<'a> {
    /// Staged active L1 table bytes ([`RegionId::L1`]).
    pub l1: &'a [u8],
    /// Staged-L2 window slots, concatenated in slot order
    /// ([`RegionId::L2Slot`]).
    pub l2_window: &'a [u8],
    /// Staged refcount table bytes ([`RegionId::RefcountTable`]).
    pub refcount_table: &'a [u8],
    /// Staged refblock bytes, a dense prefix covering host
    /// clusters from zero ([`RegionId::Refblocks`]); mutated in
    /// place by the planner's allocator (decision 6).
    pub refblocks: &'a mut [u8],
}

// ---------------------------------------------------------------------------
// Envelope gates (decision 8)
// ---------------------------------------------------------------------------

/// A typed envelope refusal (decision 8: gates are unified and
/// checked before any write step exists — [`new_state`] runs
/// them, so a gated image can never produce a [`WriteState`],
/// honouring the phase-2 "no mutation before envelope checks"
/// deferral by construction).
///
/// Every variant is a pure header check — the gates take a
/// parsed [`QcowHeader`] and perform no I/O. One condition from
/// decision 8 is deliberately NOT here: *compressed clusters*
/// cannot be gated from the header alone (zlib images carry
/// compressed L2 entries without any header bit), so the write
/// path's classification refuses them on encounter at plan time
/// (step 3b). What CAN be seen in the header — the
/// `INCOMPAT_COMPRESSION` (zstd) bit, or any unknown
/// incompatible bit — refuses as [`Self::UnknownIncompatible`],
/// matching bench's proven gate
/// (`src/operations/bench/src/main.rs`).
///
/// The `u32` codes ([`Self::code`]) are stable for host
/// rendering. Codes 1-7 deliberately equal bench's `wgate`
/// constants so the phase-6 migration maps them one-to-one;
/// codes 8+ are new to this crate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Gate {
    /// `refcount_bits != 16`. The v1 write envelope, like the
    /// `snapshot` crate's allocator, supports 16-bit refcounts
    /// only. Code 1.
    RefcountWidth,
    /// The `INCOMPAT_COMPRESSION` (zstd) bit or any incompatible
    /// feature bit this crate does not know is set. The qcow2
    /// spec requires refusing unknown incompatible bits; writing
    /// through unknown semantics could corrupt the image. Code 2
    /// (bench renders this as its compression gate).
    UnknownIncompatible,
    /// The extended-L2 bit is set; the planner assumes standard
    /// 8-byte L2 entries. Code 3.
    ExtendedL2,
    /// The external-data-file bit is set; data clusters would
    /// live outside the addressed device. Code 4.
    ExternalDataFile,
    /// `crypt_method != 0` (AES or LUKS); plaintext writes into
    /// an encrypted payload would corrupt it. Code 5.
    Encryption,
    /// The dirty or corrupt incompatible bit is set; metadata
    /// cannot be trusted as a planning substrate. Code 6.
    DirtyCorrupt,
    /// `nb_snapshots != 0`. v1 refuses snapshot-bearing images
    /// outright: in-place writes corrupt snapshot-shared
    /// clusters (GitHub issues #420/#423, found by phases 1-2).
    /// Phase 7's COW support lifts this gate. Code 7.
    HasSnapshots,
    /// `version` is not 2 or 3. [`QcowHeader::parse`] cannot
    /// produce such a header; this defends direct struct
    /// construction. Code 8.
    UnsupportedVersion,
    /// [`StagingConfig`] out of range (zero, or above
    /// [`MAX_L2_SLOTS`] / [`MAX_REFBLOCKS`]). A caller-config
    /// refusal from [`new_state`] rather than an image gate;
    /// grouped here because `new_state`'s refusal channel is
    /// `Gate`. Code 9.
    InvalidStagingConfig,
}

impl Gate {
    /// Stable code for host rendering (see the type docs for
    /// the bench `wgate` correspondence).
    pub const fn code(self) -> u32 {
        match self {
            Gate::RefcountWidth => 1,
            Gate::UnknownIncompatible => 2,
            Gate::ExtendedL2 => 3,
            Gate::ExternalDataFile => 4,
            Gate::Encryption => 5,
            Gate::DirtyCorrupt => 6,
            Gate::HasSnapshots => 7,
            Gate::UnsupportedVersion => 8,
            Gate::InvalidStagingConfig => 9,
        }
    }
}

impl From<Gate> for u32 {
    fn from(gate: Gate) -> u32 {
        gate.code()
    }
}

/// Check the decision-8 write envelope against a parsed header.
///
/// Pure header predicate, no I/O. Returns the first tripped
/// [`Gate`] in a fixed check order (version, refcount width,
/// unknown incompatible bits, extended-L2, external data,
/// encryption, dirty/corrupt, snapshots — bench's order with
/// the defensive version check first). [`new_state`] calls this
/// before building any state; ops may also call it directly for
/// early refusal.
pub fn check_envelope(hdr: &QcowHeader) -> Result<(), Gate> {
    if hdr.version != 2 && hdr.version != 3 {
        return Err(Gate::UnsupportedVersion);
    }
    if hdr.refcount_bits != 16 {
        return Err(Gate::RefcountWidth);
    }
    const KNOWN_INCOMPAT: u64 = qcow2::INCOMPAT_DIRTY
        | qcow2::INCOMPAT_CORRUPT
        | qcow2::INCOMPAT_EXTERNAL_DATA
        | qcow2::INCOMPAT_EXTENDED_L2;
    if hdr.incompatible_features & qcow2::INCOMPAT_COMPRESSION != 0
        || hdr.incompatible_features & !KNOWN_INCOMPAT != 0
    {
        return Err(Gate::UnknownIncompatible);
    }
    if hdr.extended_l2 {
        return Err(Gate::ExtendedL2);
    }
    if hdr.has_external_data {
        return Err(Gate::ExternalDataFile);
    }
    if hdr.crypt_method != 0 {
        return Err(Gate::Encryption);
    }
    if hdr.dirty || hdr.corrupt {
        return Err(Gate::DirtyCorrupt);
    }
    if hdr.nb_snapshots > 0 {
        return Err(Gate::HasSnapshots);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Planner errors and results
// ---------------------------------------------------------------------------

/// Errors from the planning functions.
///
/// Decision 9 (capacity semantics): capacity and classification
/// refusals are clean but not byte-idempotent in v1.
/// [`Self::RefcountExhausted`] — and any classification refusal
/// below — can surface mid-plan after earlier windows executed;
/// the image is left with the same semantics as today's ops:
/// unreferenced scaffolding clusters may exist (their staged
/// refcounts claimed but never flushed), no metadata was
/// flushed, and the image is check-clean. Full byte-idempotence
/// needs a worst-case pre-pass whose bound machinery arrives
/// with phase 6's refcount-growth planner, so it is deferred
/// there. After a refusal the in-flight request is abandoned
/// ([`WriteState`] returns to idle); the steps already emitted
/// into the window are safe to execute or to discard.
///
/// The `u32` codes ([`Self::code`]) are stable for host
/// rendering, in the same style as [`Gate::code`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WriteError {
    /// The current window is complete — either the step buffer
    /// filled, or the planner emitted a
    /// [`StepKind::LoadCluster`] whose bytes it needs (the
    /// decision-5 protocol). NOT a failure: per decision 1 this
    /// is the windowing resume signal — execute the emitted
    /// steps, [`StepBuf::reset`], and call the planner again
    /// with the same arguments; [`WriteState`] holds the resume
    /// point, and the concatenated windows are identical to what
    /// one unbounded buffer would have produced. Code 1.
    BufFull,
    /// Every staged refblock is full; v1 does not grow the
    /// refcount table (decision 9 above; phase 6 moves bench's
    /// growth planner in). Code 2.
    RefcountExhausted,
    /// Retained from the phase-3a stubs for API stability; no
    /// planning function returns it since 3b. Code 3.
    NotImplemented,
    /// The request runs past the virtual disk size (or past the
    /// active L1's coverage on a header whose L1 is too small
    /// for its own virtual size), or an offset computation
    /// overflowed. Refused before any step or state change.
    /// Code 4.
    OutOfBounds,
    /// Planner-protocol misuse: a resumed call's arguments do
    /// not match the in-flight request recorded in
    /// [`WriteState`] (decision 1 requires resuming with the
    /// SAME arguments), or [`plan_write`] / [`plan_flush`] was
    /// called while the *other* planner holds the resume point.
    /// The in-flight request is preserved so a correct resume
    /// still succeeds. Code 5.
    ResumeMismatch,
    /// The [`StagedRegions`] slices do not match the geometry
    /// and [`StagingConfig`] (too short, refblocks not a whole
    /// number of clusters, more refblocks than the dirty bitset
    /// covers, a dirty refblock whose refcount-table entry is
    /// empty or misaligned), or the step buffer has zero
    /// capacity, or a `snapshot`-primitive precondition failed.
    /// Caller/staging bug, not an image classification. Code 6.
    StagedRegionsMismatch,
    /// Classification refusal: the write touches a compressed
    /// cluster (decision 8 — per-cluster zlib compression
    /// carries no header bit, so this is detected at plan time,
    /// on encounter). Code 7.
    CompressedCluster,
    /// Classification refusal: the target data cluster is
    /// snapshot-shared — `OFLAG_COPIED` clear on an allocated L2
    /// entry, or a staged refcount above 1. Overwriting it in
    /// place is the #420 corruption; phase 7's copy-on-write
    /// lifts this. Unreachable through [`new_state`]'s
    /// `nb_snapshots == 0` gate on consistent images, kept as
    /// defence in depth (bench's posture). Code 8.
    SnapshotShared,
    /// Classification refusal: the L2 *table* itself is
    /// snapshot-shared (`OFLAG_COPIED` clear on the allocated L1
    /// entry, or the L2 cluster's staged refcount above 1).
    /// Patching it in place is the #421 corruption; phase 7
    /// lifts this. Code 9.
    SnapshotSharedL2Table,
    /// Classification refusal: an L1 entry carries bits outside
    /// `OFLAG_COPIED` and the L2-offset mask, or a misaligned or
    /// missing L2 offset with other bits set. Writing through
    /// unknown semantics could corrupt the image. Code 10.
    UnknownL1Entry,
    /// Classification refusal: an L2 entry carries an unknown
    /// bit pattern — the v3 all-zeroes flag (bit 0), reserved
    /// bits, a flags-only entry with no offset, or a misaligned
    /// offset. Code 11.
    UnknownL2Entry,
    /// Classification refusal: an allocated entry whose target
    /// cluster has staged refcount zero — the image's refcounts
    /// are inconsistent and cannot anchor a safe write. Code 12.
    RefcountInconsistent,
    /// Classification refusal: the cluster's refcount lives
    /// outside the staged refblock set, so the decision-6 owned
    /// check cannot run. The executor stages every populated
    /// refblock (bench's model); hitting this means the staging
    /// was partial. Code 13.
    RefcountCoverage,
    /// Classification refusal: a sub-cluster write would
    /// allocate a fresh cluster in an image with a backing file,
    /// where the uncovered remainder's virtual content comes
    /// from the backing chain — a chain read the pure planner
    /// cannot perform. v1 fills uncovered remainders with zeros,
    /// which is only correct without a backing file; callers
    /// with backing chains pass full clusters (phase 6) until
    /// phase 7's COW machinery absorbs the fill.
    ///
    /// Coverage is judged against the EFFECTIVE cluster end,
    /// `min(cluster_size, virtual_size - cluster_virtual_base)`:
    /// on the final (tail) cluster of an unaligned virtual size,
    /// a write starting at the cluster base whose coverage
    /// reaches `virtual_size` is full coverage — bytes beyond
    /// EOV are not virtual content, so the crate's beyond-EOV
    /// zero-fill is the correct pre-image regardless of backing
    /// (`PLAN-qcow2-write-infrastructure-phase-04-commit.md`,
    /// amended decision 7 / divergence D9). Every genuinely
    /// partial write below EOV — including a head gap below EOV
    /// on the tail cluster — keeps this refusal. Code 14.
    NeedsBackingFill,
}

impl WriteError {
    /// Stable code for host rendering (see the variant docs).
    pub const fn code(self) -> u32 {
        match self {
            WriteError::BufFull => 1,
            WriteError::RefcountExhausted => 2,
            WriteError::NotImplemented => 3,
            WriteError::OutOfBounds => 4,
            WriteError::ResumeMismatch => 5,
            WriteError::StagedRegionsMismatch => 6,
            WriteError::CompressedCluster => 7,
            WriteError::SnapshotShared => 8,
            WriteError::SnapshotSharedL2Table => 9,
            WriteError::UnknownL1Entry => 10,
            WriteError::UnknownL2Entry => 11,
            WriteError::RefcountInconsistent => 12,
            WriteError::RefcountCoverage => 13,
            WriteError::NeedsBackingFill => 14,
        }
    }
}

impl From<BufFull> for WriteError {
    fn from(_: BufFull) -> WriteError {
        WriteError::BufFull
    }
}

/// Result of a completed planning call (decision 1).
///
/// Returned when the *request* completed within the current
/// window; a window that fills mid-request ends with
/// [`WriteError::BufFull`] instead, with the resume point held
/// in [`WriteState`] and the partial emission readable via
/// [`StepBuf::emitted`]. Step 3b may extend this with resume
/// diagnostics; 3a keeps the settled minimum.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Window {
    /// Steps emitted into the [`StepBuf`] by this call.
    pub emitted: usize,
}

/// Where the bytes of a [`plan_write`] come from.
///
/// Abstracts "caller data region at offset" vs "fill pattern"
/// (bench's patterned writes) so the phase 4-6 migrations don't
/// bounce data twice (phase-3 plan, API sketch).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DataSource {
    /// Bytes live in [`RegionId::CallerData`] starting at this
    /// byte offset.
    CallerData {
        /// Byte offset within the caller-data region.
        offset: u64,
    },
    /// Every byte of the write is this fill value.
    Fill {
        /// The fill byte.
        byte: u8,
    },
}

// ---------------------------------------------------------------------------
// Write state (decisions 5, 6)
// ---------------------------------------------------------------------------

/// Bookkeeping for one slot of the staged-L2 window
/// (decision 5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct L2Slot {
    /// Whether the slot holds a staged L2 table.
    pub valid: bool,
    /// Whether the staged copy diverges from disk (writeback
    /// needed before eviction or at flush).
    pub dirty: bool,
    /// L1 index of the staged L2 table.
    pub l1_idx: u32,
    /// Host byte offset of the L2 table on disk (zero for a
    /// freshly allocated, not-yet-written L2).
    pub host_offset: u64,
    /// Value of the state's access counter at last touch;
    /// eviction is deterministic LRU over this (decision 5 —
    /// no clocks).
    pub last_access: u64,
}

impl L2Slot {
    const EMPTY: L2Slot = L2Slot {
        valid: false,
        dirty: false,
        l1_idx: 0,
        host_offset: 0,
        last_access: 0,
    };
}

/// Planner state threaded through [`plan_write`] /
/// [`plan_flush`] calls (decision 1's resume point lives here).
///
/// Constructed only by [`new_state`], which runs the decision-8
/// gates first — holding a `WriteState` is proof the image
/// passed the envelope. Holds the derived [`Geometry`], the
/// caller's [`StagingConfig`], the L2 window map (decision 5),
/// the refblock dirty bitset (decision 6), the deterministic
/// LRU access counter and the `snapshot` crate's allocator
/// cursor (decision 10).
pub struct WriteState {
    geometry: Geometry,
    config: StagingConfig,
    l2_slots: [L2Slot; MAX_L2_SLOTS],
    refblock_dirty: [u64; MAX_REFBLOCKS / 64],
    access_counter: u64,
    alloc_cursor: AllocCursor,
    /// Whether the gated header carries a backing file
    /// reference (drives [`WriteError::NeedsBackingFill`]).
    has_backing: bool,
    /// Whether the staged L1 diverges from disk (an L1 patch was
    /// emitted); cleared by [`plan_flush`]'s L1 write-back.
    l1_dirty: bool,
    /// Non-barrier steps emitted since the last barrier, across
    /// windows. [`plan_flush`] emits a barrier at a decision-7
    /// contract point only when this is non-zero, so adjacent
    /// barriers collapse deterministically (a stream-position
    /// property, independent of the step-buffer size — the
    /// window-invariance requirement).
    steps_since_barrier: u64,
    /// Per-slot "a ZeroRegion for this slot was emitted in the
    /// CURRENT window and is not yet executed" bits: the slot's
    /// staged bytes are garbage until the executor runs the
    /// step, but their logical content is known-zero, so
    /// classification substitutes 0 instead of reading them.
    /// Cleared at every planner-call entry (the decision-1 loop
    /// guarantees the previous window was executed by then).
    slot_pending_zero: [u64; MAX_L2_SLOTS / 64],
    /// Decision-1 resume point.
    pending: Pending,
}

impl WriteState {
    /// The geometry derived from the gated header.
    pub fn geometry(&self) -> &Geometry {
        &self.geometry
    }

    /// The staging shape this state was built for.
    pub fn config(&self) -> &StagingConfig {
        &self.config
    }

    /// L2 window slot bookkeeping; `None` above
    /// [`StagingConfig::l2_slots`].
    pub fn l2_slot(&self, idx: usize) -> Option<&L2Slot> {
        if idx < self.config.l2_slots {
            self.l2_slots.get(idx)
        } else {
            None
        }
    }

    /// Whether staged refblock `idx` diverges from disk
    /// (decision 6; flushed by [`plan_flush`]). `false` above
    /// [`StagingConfig::max_refblocks`].
    pub fn refblock_dirty(&self, idx: usize) -> bool {
        if idx >= self.config.max_refblocks {
            return false;
        }
        (self.refblock_dirty[idx / 64] >> (idx % 64)) & 1 != 0
    }

    /// Monotonic access counter driving deterministic LRU
    /// eviction (decision 5).
    pub fn access_counter(&self) -> u64 {
        self.access_counter
    }

    /// The `snapshot` crate's allocator cursor (decision 10).
    pub fn alloc_cursor(&self) -> &AllocCursor {
        &self.alloc_cursor
    }

    /// Whether the staged L1 diverges from disk (flushed by
    /// [`plan_flush`]).
    pub fn l1_dirty(&self) -> bool {
        self.l1_dirty
    }

    // ----- internal window bookkeeping (decision 5) -----

    /// Window slot currently staging the L2 table for `l1_idx`.
    fn find_slot(&self, l1_idx: u32) -> Option<usize> {
        (0..self.config.l2_slots)
            .find(|&i| self.l2_slots[i].valid && self.l2_slots[i].l1_idx == l1_idx)
    }

    /// Deterministic eviction choice (decision 5): the first
    /// invalid slot, else the least-recently-used valid slot
    /// (ties broken toward the lowest index). Pure over state,
    /// so a resumed call recomputes the same victim.
    fn pick_victim(&self) -> usize {
        let mut best = 0usize;
        let mut best_access = u64::MAX;
        for i in 0..self.config.l2_slots {
            if !self.l2_slots[i].valid {
                return i;
            }
            if self.l2_slots[i].last_access < best_access {
                best = i;
                best_access = self.l2_slots[i].last_access;
            }
        }
        best
    }

    /// Bump the deterministic LRU clock for `idx` (decision 5 —
    /// an access counter, no wall clocks). Called exactly once
    /// per cluster group, when the group's slot becomes ready.
    fn touch(&mut self, idx: usize) {
        self.access_counter += 1;
        self.l2_slots[idx].last_access = self.access_counter;
    }

    fn pending_zero_set(&mut self, idx: usize) {
        self.slot_pending_zero[idx / 64] |= 1u64 << (idx % 64);
    }

    fn pending_zero_get(&self, idx: usize) -> bool {
        (self.slot_pending_zero[idx / 64] >> (idx % 64)) & 1 != 0
    }

    fn pending_zero_clear_all(&mut self) {
        self.slot_pending_zero = [0u64; MAX_L2_SLOTS / 64];
    }

    fn refblock_dirty_set(&mut self, idx: usize) {
        self.refblock_dirty[idx / 64] |= 1u64 << (idx % 64);
    }

    fn refblock_dirty_clear(&mut self, idx: usize) {
        self.refblock_dirty[idx / 64] &= !(1u64 << (idx % 64));
    }

    /// First dirty, valid L2 window slot at or after `from`
    /// (ascending slot order — the deterministic flush order).
    fn next_dirty_slot(&self, from: usize) -> Option<usize> {
        (from..self.config.l2_slots).find(|&i| self.l2_slots[i].valid && self.l2_slots[i].dirty)
    }

    /// First dirty staged refblock at or after `from`.
    fn next_dirty_refblock(&self, from: usize) -> Option<usize> {
        (from..self.config.max_refblocks).find(|&i| self.refblock_dirty(i))
    }
}

/// Build a [`WriteState`] for an image, running the decision-8
/// envelope gates first.
///
/// A gated image yields a typed refusal before any step can be
/// emitted ("no mutation before envelope checks" — the phase-2
/// deferral, honoured by construction). An out-of-range
/// [`StagingConfig`] refuses as [`Gate::InvalidStagingConfig`].
/// On success all bookkeeping is zeroed: every L2 slot invalid,
/// no refblock dirty, access counter zero and a default
/// [`AllocCursor`].
pub fn new_state(hdr: &QcowHeader, cfg: &StagingConfig) -> Result<WriteState, Gate> {
    check_envelope(hdr)?;
    if cfg.l2_slots == 0
        || cfg.l2_slots > MAX_L2_SLOTS
        || cfg.max_refblocks == 0
        || cfg.max_refblocks > MAX_REFBLOCKS
    {
        return Err(Gate::InvalidStagingConfig);
    }
    Ok(WriteState {
        geometry: Geometry::from_header(hdr),
        config: *cfg,
        l2_slots: [L2Slot::EMPTY; MAX_L2_SLOTS],
        refblock_dirty: [0u64; MAX_REFBLOCKS / 64],
        access_counter: 0,
        alloc_cursor: AllocCursor::default(),
        has_backing: hdr.backing_file_offset != 0,
        l1_dirty: false,
        steps_since_barrier: 0,
        slot_pending_zero: [0u64; MAX_L2_SLOTS / 64],
        pending: Pending::Idle,
    })
}

// ---------------------------------------------------------------------------
// Planner internals (decision 1 resume machinery)
// ---------------------------------------------------------------------------

/// Micro-stage within the current cluster's emission group.
///
/// Decision 1's window-invariance rests on this: every state
/// mutation (allocator claim, slot assignment, LRU touch, dirty
/// bit) is tied to exactly one stage transition, and a stage
/// advances only after its step (if any) was pushed. A
/// [`WriteError::BufFull`] mid-group therefore resumes at the
/// exact step that failed to fit, with all earlier mutations
/// performed exactly once — the concatenated windows are
/// byte-identical to a single unbounded emission.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ClusterStage {
    /// Nothing done for this cluster yet.
    Enter,
    /// The chosen window slot is free (any dirty victim's
    /// writeback was emitted); the L1 entry decides load vs
    /// fresh.
    SlotFree,
    /// A fresh L2 cluster was allocated (`l2_host`); the slot's
    /// ZeroRegion init is next.
    FreshAlloc,
    /// The fresh slot's ZeroRegion was emitted; the L1 patch is
    /// next (decision 7(b): init before the referencing patch).
    FreshZeroed,
    /// The slot stages the right L2 table; classification runs.
    SlotReady,
    /// A fresh data cluster was allocated (`data_host`); the
    /// head zero-fill is next.
    DataAlloc,
    /// Head zero-fill emitted (or not needed); the body write is
    /// next.
    HeadDone,
    /// Body write emitted; the tail zero-fill is next.
    BodyDone,
    /// Tail zero-fill emitted (or not needed); the L2 patch that
    /// makes the cluster reachable is next (decision 7(a): data
    /// before the patch).
    TailDone,
}

/// Resume point for an in-flight [`plan_write`] request.
#[derive(Debug, Clone, Copy)]
struct WriteProgress {
    /// Request identity — a resumed call must repeat these.
    voff: u64,
    len: u64,
    data: DataSource,
    /// Bytes of the request fully planned so far.
    consumed: u64,
    /// Micro-stage within the current cluster's group.
    stage: ClusterStage,
    /// Window slot serving the current cluster.
    slot: u16,
    /// Fresh L2 host offset (valid from [`ClusterStage::FreshAlloc`]).
    l2_host: u64,
    /// Fresh data-cluster host offset (valid from
    /// [`ClusterStage::DataAlloc`]).
    data_host: u64,
}

/// Flush emission stage (decision 7(c)-(d) skeleton).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FlushStage {
    /// Barrier pinning the epoch's data writes (if any steps are
    /// un-barriered).
    PreBarrier,
    /// Dirty L2 slot write-backs, ascending slot order.
    L2Writebacks,
    /// Barrier before the L1 write (7(b) at flush granularity).
    L1Barrier,
    /// Staged-L1 write-back.
    L1Write,
    /// Barrier before the refcount write-backs (7(c):
    /// refcounts last).
    RbBarrier,
    /// Dirty refblock write-backs, ascending refblock order.
    RbWritebacks,
    /// Epoch-closing barrier.
    EndBarrier,
}

/// Resume point for an in-flight [`plan_flush`].
#[derive(Debug, Clone, Copy)]
struct FlushProgress {
    stage: FlushStage,
    /// Scan cursor for the write-back stages.
    next_idx: u32,
}

/// Which planner (if any) holds the decision-1 resume point.
#[derive(Debug, Clone, Copy)]
enum Pending {
    Idle,
    Write(WriteProgress),
    Flush(FlushProgress),
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

/// Push one step, maintaining the barrier-collapse counter (see
/// [`WriteState::steps_since_barrier`]).
fn push_step(
    state: &mut WriteState,
    steps: &mut StepBuf<'_>,
    step: Step,
) -> Result<(), WriteError> {
    steps.push(step)?;
    if matches!(step.kind, StepKind::Barrier { .. }) {
        state.steps_since_barrier = 0;
    } else {
        state.steps_since_barrier += 1;
    }
    Ok(())
}

/// Emit a Durability barrier at a decision-7 contract point,
/// unless no step was emitted since the last barrier (adjacent
/// barriers collapse; empty groups emit nothing).
fn barrier_if_needed(state: &mut WriteState, steps: &mut StepBuf<'_>) -> Result<(), WriteError> {
    if state.steps_since_barrier == 0 {
        return Ok(());
    }
    let dev = state.config.device;
    push_step(
        state,
        steps,
        Step {
            kind: StepKind::Barrier {
                class: BarrierClass::Durability,
            },
            device: dev,
            region: RegionId::Bounce,
            region_offset: 0,
            disk_offset: 0,
            len: 0,
            value: 0,
        },
    )
}

fn load_step(slot: u16, l2_host: u64, cs: u64, dev: TargetDevice) -> Step {
    Step {
        kind: StepKind::LoadCluster,
        device: dev,
        region: RegionId::L2Slot(slot),
        region_offset: 0,
        disk_offset: l2_host,
        len: cs,
        value: 0,
    }
}

fn writeback_step(slot: u16, l2_host: u64, cs: u64, dev: TargetDevice) -> Step {
    Step {
        kind: StepKind::WritebackCluster,
        device: dev,
        region: RegionId::L2Slot(slot),
        region_offset: 0,
        disk_offset: l2_host,
        len: cs,
        value: 0,
    }
}

fn zero_region_step(slot: u16, cs: u64, dev: TargetDevice) -> Step {
    Step {
        kind: StepKind::ZeroRegion,
        device: dev,
        region: RegionId::L2Slot(slot),
        region_offset: 0,
        disk_offset: 0,
        len: cs,
        value: 0,
    }
}

fn patch_step(region: RegionId, region_offset: u64, value: u64, dev: TargetDevice) -> Step {
    Step {
        kind: StepKind::PatchEntryU64,
        device: dev,
        region,
        region_offset,
        disk_offset: 0,
        len: 0,
        value,
    }
}

fn zero_range_step(disk_offset: u64, len: u64, dev: TargetDevice) -> Step {
    Step {
        kind: StepKind::ZeroRange,
        device: dev,
        region: RegionId::Bounce,
        region_offset: 0,
        disk_offset,
        len,
        value: 0,
    }
}

/// The body write for the caller's [`DataSource`]: a
/// [`StepKind::WriteRange`] from the caller-data region (offset
/// advanced by the request bytes already consumed) or a
/// [`StepKind::FillRange`].
fn body_step(
    data: DataSource,
    consumed: u64,
    disk_offset: u64,
    len: u64,
    dev: TargetDevice,
) -> Step {
    match data {
        DataSource::CallerData { offset } => Step {
            kind: StepKind::WriteRange,
            device: dev,
            region: RegionId::CallerData,
            region_offset: offset + consumed,
            disk_offset,
            len,
            value: 0,
        },
        DataSource::Fill { byte } => Step {
            kind: StepKind::FillRange,
            device: dev,
            region: RegionId::Bounce,
            region_offset: 0,
            disk_offset,
            len,
            value: byte as u64,
        },
    }
}

/// Validate the [`StagedRegions`] slices against the geometry
/// and [`StagingConfig`] (and refuse a zero-capacity step
/// buffer, which could never make progress).
fn validate_staged(
    state: &WriteState,
    staged: &StagedRegions<'_>,
    steps: &StepBuf<'_>,
) -> Result<(), WriteError> {
    let geo = &state.geometry;
    let cs = geo.cluster_size as usize;
    if steps.capacity() == 0 {
        return Err(WriteError::StagedRegionsMismatch);
    }
    if staged.l1.len() < geo.l1_size as usize * 8 {
        return Err(WriteError::StagedRegionsMismatch);
    }
    if staged.l2_window.len() < state.config.l2_slots * cs {
        return Err(WriteError::StagedRegionsMismatch);
    }
    if !staged.refblocks.len().is_multiple_of(cs) {
        return Err(WriteError::StagedRegionsMismatch);
    }
    let rb_count = staged.refblocks.len() / cs;
    if rb_count > state.config.max_refblocks {
        return Err(WriteError::StagedRegionsMismatch);
    }
    if staged.refcount_table.len() < rb_count * 8 {
        return Err(WriteError::StagedRegionsMismatch);
    }
    Ok(())
}

/// Read the refcount of the cluster at host offset `host` from
/// the staged refblocks (decision 6; `host` must be
/// cluster-aligned — callers validate).
fn read_staged_refcount(
    state: &WriteState,
    staged: &StagedRegions<'_>,
    host: u64,
) -> Result<u64, WriteError> {
    let geo = &state.geometry;
    let cs = geo.cluster_size;
    let cluster_index = host / cs;
    let rb_idx = (cluster_index / geo.entries_per_refblock) as usize;
    let rb_count = staged.refblocks.len() / cs as usize;
    if rb_idx >= rb_count {
        return Err(WriteError::RefcountCoverage);
    }
    let start = rb_idx * cs as usize;
    read_refcount_in_block(
        &staged.refblocks[start..start + cs as usize],
        cluster_index % geo.entries_per_refblock,
        geo.refcount_bits,
    )
    .map_err(|_| WriteError::StagedRegionsMismatch)
}

/// Allocate one fresh cluster from the staged refblocks via the
/// `snapshot` crate's allocator (decision 10), which sets the
/// claimed refcount to 1 in place (decision 6), and mark the
/// covering refblock dirty for the refcounts-last flush.
fn alloc_cluster(
    state: &mut WriteState,
    staged: &mut StagedRegions<'_>,
) -> Result<u64, WriteError> {
    let geo = state.geometry;
    let rb_count = (staged.refblocks.len() as u64) / geo.cluster_size;
    match alloc_cluster_in_refblocks(
        staged.refblocks,
        geo.cluster_size,
        geo.refcount_bits,
        rb_count,
        0,
        &mut state.alloc_cursor,
    ) {
        Ok(host) => {
            let rb_idx = ((host / geo.cluster_size) / geo.entries_per_refblock) as usize;
            state.refblock_dirty_set(rb_idx);
            Ok(host)
        }
        Err(SnapshotError::RefcountExhausted) => Err(WriteError::RefcountExhausted),
        Err(_) => Err(WriteError::StagedRegionsMismatch),
    }
}

/// Classification verdict for one L2 entry (see the table on
/// [`plan_write`]).
enum Classified {
    /// No mapping: allocate a fresh data cluster.
    Unallocated,
    /// Owned, exclusively referenced data cluster at this host
    /// offset: overwrite in place.
    Owned(u64),
}

/// Classify one L2 entry (decision 8's plan-time refusals plus
/// the owned check from the phase-3b brief: COPIED *and* staged
/// refcount 1).
fn classify_l2_entry(
    state: &WriteState,
    staged: &StagedRegions<'_>,
    entry: u64,
) -> Result<Classified, WriteError> {
    if entry == 0 {
        return Ok(Classified::Unallocated);
    }
    if entry & OFLAG_COMPRESSED != 0 {
        return Err(WriteError::CompressedCluster);
    }
    if entry & !(OFLAG_COPIED | L2_OFFSET_MASK) != 0 {
        // Covers the v3 all-zeroes flag (bit 0) and every
        // reserved bit.
        return Err(WriteError::UnknownL2Entry);
    }
    let host = entry & L2_OFFSET_MASK;
    if host == 0 || !host.is_multiple_of(state.geometry.cluster_size) {
        return Err(WriteError::UnknownL2Entry);
    }
    if entry & OFLAG_COPIED == 0 {
        return Err(WriteError::SnapshotShared);
    }
    let rc = read_staged_refcount(state, staged, host)?;
    if rc == 0 {
        return Err(WriteError::RefcountInconsistent);
    }
    if rc > 1 {
        return Err(WriteError::SnapshotShared);
    }
    Ok(Classified::Owned(host))
}

/// Validate an allocated L1 entry and return the L2 table's host
/// offset (the L2-table analogue of [`classify_l2_entry`]; the
/// COPIED + refcount check here is what makes the #421-style
/// shared-L2 in-place patch unreachable).
fn validate_l1_entry(
    state: &WriteState,
    staged: &StagedRegions<'_>,
    raw: u64,
) -> Result<u64, WriteError> {
    if raw & !(OFLAG_COPIED | L1_OFFSET_MASK) != 0 {
        return Err(WriteError::UnknownL1Entry);
    }
    let host = raw & L1_OFFSET_MASK;
    if host == 0 || !host.is_multiple_of(state.geometry.cluster_size) {
        return Err(WriteError::UnknownL1Entry);
    }
    if raw & OFLAG_COPIED == 0 {
        return Err(WriteError::SnapshotSharedL2Table);
    }
    let rc = read_staged_refcount(state, staged, host)?;
    if rc == 0 {
        return Err(WriteError::RefcountInconsistent);
    }
    if rc > 1 {
        return Err(WriteError::SnapshotSharedL2Table);
    }
    Ok(host)
}

/// The L2 entry for `l2_idx` as staged in `slot` — substituting
/// logical zero while the slot's ZeroRegion init is pending in
/// the current window (see
/// [`WriteState::slot_pending_zero`]).
fn read_staged_l2_entry(
    state: &WriteState,
    staged: &StagedRegions<'_>,
    slot: u16,
    l2_idx: u64,
) -> u64 {
    if state.pending_zero_get(slot as usize) {
        return 0;
    }
    let cs = state.geometry.cluster_size as usize;
    read_u64_be(staged.l2_window, slot as usize * cs + l2_idx as usize * 8)
}

/// The per-cluster emission loop behind [`plan_write`]. Returns
/// `Ok(())` when the whole request is planned;
/// [`WriteError::BufFull`] leaves the resume point in `prog`.
fn drive_write(
    state: &mut WriteState,
    staged: &mut StagedRegions<'_>,
    prog: &mut WriteProgress,
    steps: &mut StepBuf<'_>,
) -> Result<(), WriteError> {
    let geo = state.geometry;
    let cs = geo.cluster_size;
    let dev = state.config.device;
    while prog.consumed < prog.len {
        let cur = prog.voff + prog.consumed;
        let l1_idx = (cur / geo.l2_coverage) as u32;
        let l2_idx = (cur / cs) % geo.entries_per_l2;
        let in_off = cur % cs;
        let win_len = (cs - in_off).min(prog.len - prog.consumed);

        'cluster: loop {
            match prog.stage {
                ClusterStage::Enter => {
                    if let Some(hit) = state.find_slot(l1_idx) {
                        prog.slot = hit as u16;
                        state.touch(hit);
                        prog.stage = ClusterStage::SlotReady;
                    } else {
                        let victim = state.pick_victim();
                        prog.slot = victim as u16;
                        let sl = state.l2_slots[victim];
                        if sl.valid && sl.dirty {
                            push_step(
                                state,
                                steps,
                                writeback_step(victim as u16, sl.host_offset, cs, dev),
                            )?;
                            state.l2_slots[victim].valid = false;
                            state.l2_slots[victim].dirty = false;
                        }
                        prog.stage = ClusterStage::SlotFree;
                    }
                }
                ClusterStage::SlotFree => {
                    let raw = read_u64_be(staged.l1, l1_idx as usize * 8);
                    if raw == 0 {
                        // Empty L1 slot: allocate a fresh L2
                        // table (phase-3b brief).
                        prog.l2_host = alloc_cluster(state, staged)?;
                        prog.stage = ClusterStage::FreshAlloc;
                    } else {
                        let l2_host = validate_l1_entry(state, staged, raw)?;
                        push_step(state, steps, load_step(prog.slot, l2_host, cs, dev))?;
                        let v = prog.slot as usize;
                        let last = state.l2_slots[v].last_access;
                        state.l2_slots[v] = L2Slot {
                            valid: true,
                            dirty: false,
                            l1_idx,
                            host_offset: l2_host,
                            last_access: last,
                        };
                        prog.stage = ClusterStage::Enter;
                        // Decision-5 window protocol: the slot's
                        // bytes exist only after the executor
                        // runs the LoadCluster, so close the
                        // window here; the resumed call re-enters
                        // via the window-hit path and classifies
                        // real bytes.
                        return Err(WriteError::BufFull);
                    }
                }
                ClusterStage::FreshAlloc => {
                    push_step(state, steps, zero_region_step(prog.slot, cs, dev))?;
                    let v = prog.slot as usize;
                    let last = state.l2_slots[v].last_access;
                    state.l2_slots[v] = L2Slot {
                        valid: true,
                        dirty: true,
                        l1_idx,
                        host_offset: prog.l2_host,
                        last_access: last,
                    };
                    state.pending_zero_set(v);
                    prog.stage = ClusterStage::FreshZeroed;
                }
                ClusterStage::FreshZeroed => {
                    // Decision 7(b): the ZeroRegion init precedes
                    // this L1 patch in the stream; on disk the
                    // ordering holds because plan_flush writes
                    // the L2 slots back before the L1.
                    push_step(
                        state,
                        steps,
                        patch_step(
                            RegionId::L1,
                            l1_idx as u64 * 8,
                            prog.l2_host | OFLAG_COPIED,
                            dev,
                        ),
                    )?;
                    state.l1_dirty = true;
                    state.touch(prog.slot as usize);
                    prog.stage = ClusterStage::SlotReady;
                }
                ClusterStage::SlotReady => {
                    let entry = read_staged_l2_entry(state, staged, prog.slot, l2_idx);
                    match classify_l2_entry(state, staged, entry)? {
                        Classified::Owned(host) => {
                            // Owned overwrite: a bare in-place
                            // range write, no metadata changes
                            // (bench's fast path).
                            push_step(
                                state,
                                steps,
                                body_step(prog.data, prog.consumed, host + in_off, win_len, dev),
                            )?;
                            prog.consumed += win_len;
                            prog.stage = ClusterStage::Enter;
                            break 'cluster;
                        }
                        Classified::Unallocated => {
                            // Effective cluster end for coverage
                            // classification: the physical cluster
                            // end, clamped to `virtual_size` on
                            // the final (tail) cluster of an
                            // unaligned image. A write from
                            // in_off == 0 whose coverage reaches
                            // it is FULL coverage — bytes beyond
                            // EOV are not virtual content, so the
                            // beyond-EOV zero-fill is the correct
                            // pre-image regardless of backing
                            // (phase-4 plan, amended decision 7 /
                            // divergence D9). A head gap below
                            // EOV on a backed image still
                            // refuses: its pre-image is backing
                            // content.
                            let eff_end = cs.min(geo.virtual_size - (cur - in_off));
                            if state.has_backing && (in_off != 0 || in_off + win_len < eff_end) {
                                // v1 fills uncovered below-EOV
                                // remainders with zeros — only
                                // correct without a backing chain
                                // (see
                                // WriteError::NeedsBackingFill).
                                return Err(WriteError::NeedsBackingFill);
                            }
                            prog.data_host = alloc_cluster(state, staged)?;
                            prog.stage = ClusterStage::DataAlloc;
                        }
                    }
                }
                ClusterStage::DataAlloc => {
                    if in_off > 0 {
                        push_step(state, steps, zero_range_step(prog.data_host, in_off, dev))?;
                    }
                    prog.stage = ClusterStage::HeadDone;
                }
                ClusterStage::HeadDone => {
                    push_step(
                        state,
                        steps,
                        body_step(
                            prog.data,
                            prog.consumed,
                            prog.data_host + in_off,
                            win_len,
                            dev,
                        ),
                    )?;
                    prog.stage = ClusterStage::BodyDone;
                }
                ClusterStage::BodyDone => {
                    let tail_off = in_off + win_len;
                    if tail_off < cs {
                        push_step(
                            state,
                            steps,
                            zero_range_step(prog.data_host + tail_off, cs - tail_off, dev),
                        )?;
                    }
                    prog.stage = ClusterStage::TailDone;
                }
                ClusterStage::TailDone => {
                    // Decision 7(a): every write covering the
                    // fresh cluster precedes this patch in the
                    // stream.
                    push_step(
                        state,
                        steps,
                        patch_step(
                            RegionId::L2Slot(prog.slot),
                            l2_idx * 8,
                            prog.data_host | OFLAG_COPIED,
                            dev,
                        ),
                    )?;
                    state.l2_slots[prog.slot as usize].dirty = true;
                    prog.consumed += win_len;
                    prog.stage = ClusterStage::Enter;
                    break 'cluster;
                }
            }
        }
    }
    Ok(())
}

/// The flush emission loop behind [`plan_flush`].
fn drive_flush(
    state: &mut WriteState,
    staged: &mut StagedRegions<'_>,
    prog: &mut FlushProgress,
    steps: &mut StepBuf<'_>,
) -> Result<(), WriteError> {
    let geo = state.geometry;
    let cs = geo.cluster_size;
    let dev = state.config.device;
    let rb_count = staged.refblocks.len() / cs as usize;
    loop {
        match prog.stage {
            FlushStage::PreBarrier => {
                barrier_if_needed(state, steps)?;
                prog.stage = FlushStage::L2Writebacks;
                prog.next_idx = 0;
            }
            FlushStage::L2Writebacks => match state.next_dirty_slot(prog.next_idx as usize) {
                Some(idx) => {
                    let host = state.l2_slots[idx].host_offset;
                    push_step(state, steps, writeback_step(idx as u16, host, cs, dev))?;
                    state.l2_slots[idx].dirty = false;
                    prog.next_idx = idx as u32 + 1;
                }
                None => {
                    prog.stage = FlushStage::L1Barrier;
                }
            },
            FlushStage::L1Barrier => {
                if state.l1_dirty {
                    barrier_if_needed(state, steps)?;
                    prog.stage = FlushStage::L1Write;
                } else {
                    prog.stage = FlushStage::RbBarrier;
                }
            }
            FlushStage::L1Write => {
                push_step(
                    state,
                    steps,
                    Step {
                        kind: StepKind::WriteRange,
                        device: dev,
                        region: RegionId::L1,
                        region_offset: 0,
                        disk_offset: geo.l1_table_offset,
                        len: geo.l1_size as u64 * 8,
                        value: 0,
                    },
                )?;
                state.l1_dirty = false;
                prog.stage = FlushStage::RbBarrier;
            }
            FlushStage::RbBarrier => {
                if state.next_dirty_refblock(0).is_some() {
                    barrier_if_needed(state, steps)?;
                    prog.stage = FlushStage::RbWritebacks;
                    prog.next_idx = 0;
                } else {
                    prog.stage = FlushStage::EndBarrier;
                }
            }
            FlushStage::RbWritebacks => match state.next_dirty_refblock(prog.next_idx as usize) {
                Some(idx) => {
                    if idx >= rb_count {
                        return Err(WriteError::StagedRegionsMismatch);
                    }
                    let rt_entry = read_u64_be(staged.refcount_table, idx * 8);
                    let host = rt_entry & L1_OFFSET_MASK;
                    if host == 0 || !host.is_multiple_of(cs) || rt_entry & 0x1ff != 0 {
                        return Err(WriteError::StagedRegionsMismatch);
                    }
                    push_step(
                        state,
                        steps,
                        Step {
                            kind: StepKind::WriteRange,
                            device: dev,
                            region: RegionId::Refblocks,
                            region_offset: idx as u64 * cs,
                            disk_offset: host,
                            len: cs,
                            value: 0,
                        },
                    )?;
                    state.refblock_dirty_clear(idx);
                    prog.next_idx = idx as u32 + 1;
                }
                None => {
                    prog.stage = FlushStage::EndBarrier;
                }
            },
            FlushStage::EndBarrier => {
                barrier_if_needed(state, steps)?;
                return Ok(());
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Planners (decisions 1-7)
// ---------------------------------------------------------------------------

/// Plan "write `len` bytes of `data` at virtual offset `voff`"
/// into the caller's step window (decisions 1-3, 5-7).
///
/// Per-cluster classification (input L2 entry state → action):
///
/// | L2 entry state | verdict |
/// |----------------|---------|
/// | zero | allocate a data cluster (fresh L2 first when the L1 slot is empty); zero-fill the uncovered head/tail; write the data; patch the entry `host \| COPIED` |
/// | zero, backing file present, coverage partial below the effective cluster end | [`WriteError::NeedsBackingFill`] |
/// | `OFLAG_COMPRESSED` set | [`WriteError::CompressedCluster`] |
/// | v3 zero flag / reserved bits / flags-only / misaligned | [`WriteError::UnknownL2Entry`] |
/// | allocated, `OFLAG_COPIED` clear | [`WriteError::SnapshotShared`] |
/// | allocated, staged refcount 0 | [`WriteError::RefcountInconsistent`] |
/// | allocated, staged refcount > 1 | [`WriteError::SnapshotShared`] |
/// | allocated, refcount not staged | [`WriteError::RefcountCoverage`] |
/// | allocated, COPIED, refcount 1 | owned: overwrite in place, no metadata change |
///
/// The allocated L1 entry feeding the lookup passes the
/// analogous checks first ([`WriteError::UnknownL1Entry`] /
/// [`WriteError::SnapshotSharedL2Table`]).
///
/// Emission per allocating cluster follows decision 7: uncovered
/// head zero-fill, body, uncovered tail zero-fill — all covering
/// the fresh cluster — then the L2 patch (7(a)); a fresh L2's
/// [`StepKind::ZeroRegion`] init precedes the L1 patch (7(b));
/// no refcount write-back is emitted here (7(c) — the staged
/// refblocks are mutated in place per decision 6 and flushed by
/// [`plan_flush`]). The v1 fill for uncovered ranges is zeros,
/// the virtual pre-image of an unallocated cluster in a
/// backing-less image; images WITH a backing file refuse partial
/// allocating writes as [`WriteError::NeedsBackingFill`] rather
/// than corrupt the read-through content. The refusal condition
/// is: backing file present AND (the write does not start at the
/// cluster base OR its coverage ends below the EFFECTIVE cluster
/// end `min(cluster_size, virtual_size - cluster_virtual_base)`).
/// Full-cluster writes are therefore unaffected (the pre-image is
/// fully overwritten), and on the final (tail) cluster of an
/// unaligned virtual size a write from the cluster base covering
/// up to `virtual_size` classifies as full coverage too — bytes
/// beyond EOV are not virtual content, so the emitted beyond-EOV
/// [`StepKind::ZeroRange`] is the correct pre-image regardless of
/// backing (`PLAN-qcow2-write-infrastructure-phase-04-commit.md`,
/// amended decision 7 / divergence D9).
///
/// Windowing (decision 1): on [`WriteError::BufFull`] — which
/// also signals the decision-5 load boundary, see
/// [`StagedRegions`] — the caller executes the emitted window,
/// resets the buffer, and calls again with the SAME arguments;
/// `state` holds the resume point and the concatenation across
/// windows is invariant over the buffer size. The caller MUST
/// execute each emitted window before the next planner call (the
/// classification reads assume it).
pub fn plan_write(
    state: &mut WriteState,
    staged: &mut StagedRegions<'_>,
    voff: u64,
    len: u64,
    data: DataSource,
    steps: &mut StepBuf<'_>,
) -> Result<Window, WriteError> {
    let start_emitted = steps.emitted();
    // Protocol misuse checks first, touching no state, so an
    // interrupted request survives a bad interleaved call.
    match state.pending {
        Pending::Flush(_) => return Err(WriteError::ResumeMismatch),
        Pending::Write(p) => {
            if p.voff != voff || p.len != len || p.data != data {
                return Err(WriteError::ResumeMismatch);
            }
        }
        Pending::Idle => {}
    }
    validate_staged(state, staged, steps)?;
    let mut prog = match state.pending {
        Pending::Write(p) => p,
        _ => {
            // Request admission: bounds-check before any step or
            // state change (the phase-2 "no mutation before the
            // checks" posture, applied to the request).
            let end = voff.checked_add(len).ok_or(WriteError::OutOfBounds)?;
            if end > state.geometry.virtual_size {
                return Err(WriteError::OutOfBounds);
            }
            if let DataSource::CallerData { offset } = data {
                offset.checked_add(len).ok_or(WriteError::OutOfBounds)?;
            }
            if len == 0 {
                return Ok(Window { emitted: 0 });
            }
            if (end - 1) / state.geometry.l2_coverage >= state.geometry.l1_size as u64 {
                return Err(WriteError::OutOfBounds);
            }
            WriteProgress {
                voff,
                len,
                data,
                consumed: 0,
                stage: ClusterStage::Enter,
                slot: 0,
                l2_host: 0,
                data_host: 0,
            }
        }
    };
    // A planner call means the previous window was executed
    // (decision-1 contract): pending slot inits are now real.
    state.pending = Pending::Idle;
    state.pending_zero_clear_all();
    match drive_write(state, staged, &mut prog, steps) {
        Ok(()) => Ok(Window {
            emitted: steps.emitted() - start_emitted,
        }),
        Err(WriteError::BufFull) => {
            state.pending = Pending::Write(prog);
            Err(WriteError::BufFull)
        }
        Err(e) => Err(e),
    }
}

/// Plan the end-of-epoch flush: write-backs for dirty L2 window
/// slots (ascending slot order), the staged L1 if dirty, then
/// the dirty refblocks (ascending, refcounts last — decision
/// 7(c)), with Durability barriers at the decision-4/7(d)
/// contract points.
///
/// Emission skeleton (empty groups vanish, adjacent barriers
/// collapse — both deterministic over the dirty state, never
/// over the buffer size):
///
/// ```text
/// [Barrier] WritebackCluster*  — pin data writes; dirty L2s
/// [Barrier] WriteRange(L1)     — 7(b): L2 init durable first
/// [Barrier] WriteRange(Refblocks)*  — 7(c): refcounts last
/// [Barrier]                    — close the epoch
/// ```
///
/// All barriers are [`BarrierClass::Durability`]; executors on
/// devices without an fsync primitive degrade them to Ordering
/// (decision 4), which matches commit/rebase's current
/// no-fsync reality. [`WriteError::BufFull`] resumes exactly
/// like [`plan_write`].
pub fn plan_flush(
    state: &mut WriteState,
    staged: &mut StagedRegions<'_>,
    steps: &mut StepBuf<'_>,
) -> Result<Window, WriteError> {
    let start_emitted = steps.emitted();
    let mut prog = match state.pending {
        Pending::Write(_) => return Err(WriteError::ResumeMismatch),
        Pending::Flush(p) => p,
        Pending::Idle => FlushProgress {
            stage: FlushStage::PreBarrier,
            next_idx: 0,
        },
    };
    validate_staged(state, staged, steps)?;
    state.pending = Pending::Idle;
    state.pending_zero_clear_all();
    match drive_flush(state, staged, &mut prog, steps) {
        Ok(()) => Ok(Window {
            emitted: steps.emitted() - start_emitted,
        }),
        Err(WriteError::BufFull) => {
            state.pending = Pending::Flush(prog);
            Err(WriteError::BufFull)
        }
        Err(e) => Err(e),
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
extern crate std;

#[cfg(test)]
mod tests {
    use super::*;
    use std::vec;
    use std::vec::Vec;

    /// Build minimal valid v2/v3 qcow2 header bytes for the
    /// parse path (the pattern of `crates/commit`'s
    /// `make_header`): 64 KiB clusters, 16-bit refcounts, 1 MiB
    /// virtual size.
    fn header_bytes(version: u32) -> [u8; 4096] {
        let mut h = [0u8; 4096];
        h[0..4].copy_from_slice(&qcow2::QCOW2_MAGIC.to_be_bytes());
        h[4..8].copy_from_slice(&version.to_be_bytes());
        h[20..24].copy_from_slice(&16u32.to_be_bytes()); // cluster_bits
        h[24..32].copy_from_slice(&(1u64 << 20).to_be_bytes()); // virtual size
        h[36..40].copy_from_slice(&1u32.to_be_bytes()); // l1_size
        h[40..48].copy_from_slice(&(2u64 * 65536).to_be_bytes()); // l1_table_offset
        h[48..56].copy_from_slice(&65536u64.to_be_bytes()); // refcount_table_offset
        h[56..60].copy_from_slice(&1u32.to_be_bytes()); // refcount_table_clusters
        if version >= 3 {
            h[96..100].copy_from_slice(&4u32.to_be_bytes()); // refcount_order = 4
            h[100..104].copy_from_slice(&104u32.to_be_bytes()); // header_length
        }
        h
    }

    fn parse(h: &[u8]) -> QcowHeader {
        QcowHeader::parse(h).expect("synthetic header must parse")
    }

    fn clean_header() -> QcowHeader {
        parse(&header_bytes(3))
    }

    fn valid_config() -> StagingConfig {
        StagingConfig {
            l2_slots: 4,
            max_refblocks: 32,
            device: TargetDevice::Input0,
        }
    }

    fn step(kind: StepKind) -> Step {
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

    // ---------------- Step / StepBuf ----------------

    #[test]
    fn step_size_within_48_byte_budget() {
        // Decision 2: fixed size, ≤ 48 bytes (also enforced at
        // compile time by the `const` assertion above).
        assert!(core::mem::size_of::<Step>() <= STEP_SIZE_LIMIT);
    }

    #[test]
    fn step_buf_cursor_and_buf_full() {
        let mut storage = [step(StepKind::ZeroRange); 3];
        let mut buf = StepBuf::new(&mut storage);
        assert_eq!(buf.emitted(), 0);
        assert_eq!(buf.capacity(), 3);
        assert_eq!(buf.remaining(), 3);
        assert!(buf.steps().is_empty());

        buf.push(step(StepKind::WriteRange)).unwrap();
        buf.push(step(StepKind::PatchEntryU64)).unwrap();
        assert_eq!(buf.emitted(), 2);
        assert_eq!(buf.remaining(), 1);
        assert_eq!(buf.steps()[0].kind, StepKind::WriteRange);
        assert_eq!(buf.steps()[1].kind, StepKind::PatchEntryU64);

        buf.push(step(StepKind::Barrier {
            class: BarrierClass::Durability,
        }))
        .unwrap();
        assert_eq!(buf.remaining(), 0);

        // Full: push refuses and leaves the emitted prefix
        // intact (decision 1's resume protocol).
        assert_eq!(buf.push(step(StepKind::ReadCluster)), Err(BufFull));
        assert_eq!(buf.emitted(), 3);
        assert_eq!(
            buf.steps()[2].kind,
            StepKind::Barrier {
                class: BarrierClass::Durability
            }
        );
    }

    #[test]
    fn step_buf_reset_rewinds_cursor() {
        let mut storage = [step(StepKind::ZeroRange); 2];
        let mut buf = StepBuf::new(&mut storage);
        buf.push(step(StepKind::LoadCluster)).unwrap();
        buf.push(step(StepKind::WritebackCluster)).unwrap();
        assert_eq!(buf.push(step(StepKind::ZeroRange)), Err(BufFull));
        buf.reset();
        assert_eq!(buf.emitted(), 0);
        assert_eq!(buf.remaining(), 2);
        buf.push(step(StepKind::ReadCluster)).unwrap();
        assert_eq!(buf.steps().len(), 1);
        assert_eq!(buf.steps()[0].kind, StepKind::ReadCluster);
    }

    #[test]
    fn buf_full_converts_to_write_error() {
        assert_eq!(WriteError::from(BufFull), WriteError::BufFull);
    }

    // ---------------- Gate codes ----------------

    #[test]
    fn gate_codes_distinct_and_stable() {
        // The commit_result_error_codes_distinct pattern: every
        // code distinct, and pinned to its documented number so
        // host renderers can't be broken by a reorder. 1-7
        // deliberately match bench's wgate constants.
        let codes = [
            (Gate::RefcountWidth, 1),
            (Gate::UnknownIncompatible, 2),
            (Gate::ExtendedL2, 3),
            (Gate::ExternalDataFile, 4),
            (Gate::Encryption, 5),
            (Gate::DirtyCorrupt, 6),
            (Gate::HasSnapshots, 7),
            (Gate::UnsupportedVersion, 8),
            (Gate::InvalidStagingConfig, 9),
        ];
        for (gate, expected) in codes {
            assert_eq!(gate.code(), expected, "{gate:?} code drifted");
            assert_eq!(u32::from(gate), expected);
        }
        for i in 0..codes.len() {
            for j in (i + 1)..codes.len() {
                assert_ne!(codes[i].1, codes[j].1, "codes {i} and {j} alias");
            }
        }
    }

    // ---------------- Envelope gates ----------------

    #[test]
    fn envelope_accepts_clean_v3_and_v2() {
        assert_eq!(check_envelope(&clean_header()), Ok(()));
        // v2: no refcount_order field; parse defaults to 16-bit
        // refcounts and zero feature bits — inside the envelope.
        assert_eq!(check_envelope(&parse(&header_bytes(2))), Ok(()));
    }

    #[test]
    fn envelope_refuses_unsupported_version() {
        // QcowHeader::parse cannot emit versions outside 2/3,
        // so exercise the defensive gate by direct field edit.
        let mut hdr = clean_header();
        assert_eq!(check_envelope(&hdr), Ok(()));
        hdr.version = 1;
        assert_eq!(check_envelope(&hdr), Err(Gate::UnsupportedVersion));
        hdr.version = 4;
        assert_eq!(check_envelope(&hdr), Err(Gate::UnsupportedVersion));
    }

    #[test]
    fn envelope_refcount_width_gate() {
        // Accept: refcount_order 4 (16-bit) via the clean header.
        assert_eq!(check_envelope(&clean_header()), Ok(()));
        // Refuse: order 5 (32-bit) and order 0 (1-bit).
        for order in [5u32, 0u32] {
            let mut h = header_bytes(3);
            h[96..100].copy_from_slice(&order.to_be_bytes());
            assert_eq!(
                check_envelope(&parse(&h)),
                Err(Gate::RefcountWidth),
                "order {order} must refuse"
            );
        }
    }

    #[test]
    fn envelope_unknown_incompatible_gate() {
        // Accept: no incompatible bits via the clean header.
        assert_eq!(check_envelope(&clean_header()), Ok(()));
        // Refuse: the zstd compression-type bit and an unknown
        // future bit (per-cluster zlib compression carries no
        // header bit — that refusal is classification-time, 3b).
        for bits in [qcow2::INCOMPAT_COMPRESSION, 1u64 << 60] {
            let mut h = header_bytes(3);
            h[72..80].copy_from_slice(&bits.to_be_bytes());
            assert_eq!(
                check_envelope(&parse(&h)),
                Err(Gate::UnknownIncompatible),
                "incompatible bits {bits:#x} must refuse"
            );
        }
    }

    #[test]
    fn envelope_extended_l2_gate() {
        assert_eq!(check_envelope(&clean_header()), Ok(()));
        let mut h = header_bytes(3);
        h[72..80].copy_from_slice(&qcow2::INCOMPAT_EXTENDED_L2.to_be_bytes());
        assert_eq!(check_envelope(&parse(&h)), Err(Gate::ExtendedL2));
    }

    #[test]
    fn envelope_external_data_gate() {
        assert_eq!(check_envelope(&clean_header()), Ok(()));
        let mut h = header_bytes(3);
        h[72..80].copy_from_slice(&qcow2::INCOMPAT_EXTERNAL_DATA.to_be_bytes());
        assert_eq!(check_envelope(&parse(&h)), Err(Gate::ExternalDataFile));
    }

    #[test]
    fn envelope_encryption_gate() {
        assert_eq!(check_envelope(&clean_header()), Ok(()));
        // 1 = legacy AES, 2 = LUKS; both refuse.
        for method in [1u32, 2u32] {
            let mut h = header_bytes(3);
            h[32..36].copy_from_slice(&method.to_be_bytes());
            assert_eq!(
                check_envelope(&parse(&h)),
                Err(Gate::Encryption),
                "crypt_method {method} must refuse"
            );
        }
    }

    #[test]
    fn envelope_dirty_corrupt_gate() {
        assert_eq!(check_envelope(&clean_header()), Ok(()));
        for bits in [qcow2::INCOMPAT_DIRTY, qcow2::INCOMPAT_CORRUPT] {
            let mut h = header_bytes(3);
            h[72..80].copy_from_slice(&bits.to_be_bytes());
            assert_eq!(
                check_envelope(&parse(&h)),
                Err(Gate::DirtyCorrupt),
                "incompatible bits {bits:#x} must refuse"
            );
        }
    }

    #[test]
    fn envelope_snapshots_gate() {
        // Accept: nb_snapshots == 0 via the clean header.
        assert_eq!(check_envelope(&clean_header()), Ok(()));
        // Refuse: v1 has no COW; phase 7 lifts this (issues
        // #420/#423 are what the gate prevents).
        let mut h = header_bytes(3);
        h[60..64].copy_from_slice(&1u32.to_be_bytes());
        assert_eq!(check_envelope(&parse(&h)), Err(Gate::HasSnapshots));
    }

    // ---------------- Geometry ----------------

    #[test]
    fn geometry_from_header_derivations() {
        let geo = Geometry::from_header(&clean_header());
        assert_eq!(geo.cluster_bits, 16);
        assert_eq!(geo.cluster_size, 65536);
        assert_eq!(geo.virtual_size, 1 << 20);
        assert_eq!(geo.l1_size, 1);
        assert_eq!(geo.l1_table_offset, 2 * 65536);
        assert_eq!(geo.refcount_table_offset, 65536);
        assert_eq!(geo.refcount_table_clusters, 1);
        assert_eq!(geo.refcount_bits, 16);
        assert_eq!(geo.entries_per_l2, 8192);
        assert_eq!(geo.l2_coverage, 65536 * 8192);
        assert_eq!(geo.entries_per_refblock, 65536 * 8 / 16);

        // 512-byte clusters (the envelope's small end).
        let mut h = header_bytes(3);
        h[20..24].copy_from_slice(&9u32.to_be_bytes());
        let geo = Geometry::from_header(&parse(&h));
        assert_eq!(geo.cluster_size, 512);
        assert_eq!(geo.entries_per_l2, 64);
        assert_eq!(geo.l2_coverage, 512 * 64);
        assert_eq!(geo.entries_per_refblock, 256);
    }

    // ---------------- new_state ----------------

    #[test]
    fn new_state_builds_zeroed_bookkeeping() {
        let hdr = clean_header();
        let st = new_state(&hdr, &valid_config()).expect("clean image must build");
        assert_eq!(*st.geometry(), Geometry::from_header(&hdr));
        assert_eq!(*st.config(), valid_config());
        assert_eq!(st.access_counter(), 0);
        assert_eq!(*st.alloc_cursor(), AllocCursor::default());
        for idx in 0..valid_config().l2_slots {
            let slot = st.l2_slot(idx).expect("slot within config");
            assert!(!slot.valid);
            assert!(!slot.dirty);
            assert_eq!(slot.last_access, 0);
        }
        // Slots beyond the configured window are not visible.
        assert!(st.l2_slot(valid_config().l2_slots).is_none());
        for idx in 0..MAX_REFBLOCKS {
            assert!(!st.refblock_dirty(idx));
        }
    }

    #[test]
    fn new_state_refuses_gated_image() {
        // Gates run before any state exists (decision 8; the
        // phase-2 "no mutation before envelope checks" deferral
        // honoured by construction).
        let mut h = header_bytes(3);
        h[60..64].copy_from_slice(&1u32.to_be_bytes()); // nb_snapshots = 1
        assert_eq!(
            new_state(&parse(&h), &valid_config()).err(),
            Some(Gate::HasSnapshots)
        );
    }

    #[test]
    fn new_state_validates_staging_config() {
        let hdr = clean_header();
        for cfg in [
            StagingConfig {
                l2_slots: 0,
                max_refblocks: 32,
                device: TargetDevice::Input0,
            },
            StagingConfig {
                l2_slots: MAX_L2_SLOTS + 1,
                max_refblocks: 32,
                device: TargetDevice::Input0,
            },
            StagingConfig {
                l2_slots: 4,
                max_refblocks: 0,
                device: TargetDevice::Output,
            },
            StagingConfig {
                l2_slots: 4,
                max_refblocks: MAX_REFBLOCKS + 1,
                device: TargetDevice::Output,
            },
        ] {
            assert_eq!(
                new_state(&hdr, &cfg).err(),
                Some(Gate::InvalidStagingConfig),
                "{cfg:?} must refuse"
            );
        }
        // The boundary values themselves are accepted.
        assert!(new_state(
            &hdr,
            &StagingConfig {
                l2_slots: MAX_L2_SLOTS,
                max_refblocks: MAX_REFBLOCKS,
                device: TargetDevice::Output,
            }
        )
        .is_ok());
        assert!(new_state(
            &hdr,
            &StagingConfig {
                l2_slots: 1,
                max_refblocks: 1,
                device: TargetDevice::Input0,
            }
        )
        .is_ok());
    }

    // =====================================================================
    // 3b planner harness: a minimal executor over Vec-backed
    // staging + disk, mirroring what the phase 4-6 guest ops do
    // with the emitted programs.
    // =====================================================================

    /// Parameterised v3 header for the planner tests (the 3a
    /// `header_bytes` keeps its fixed shape for the gate tests).
    /// Layout convention: cluster 0 header, cluster 1 refcount
    /// table, cluster 2 refblock 0, cluster 3 L1, clusters 4+
    /// free.
    fn build_header(
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

    /// Executor-side stand-in: the staged buffers an op carves
    /// from scratch, plus a Vec-backed disk. Sentinel fills
    /// (0xEE) make zero-fills and stale reads observable; the
    /// disk grows on demand so far-flung allocations stay in
    /// range.
    struct TestImg {
        hdr: QcowHeader,
        cs: usize,
        disk: Vec<u8>,
        l1: Vec<u8>,
        l2win: Vec<u8>,
        rt: Vec<u8>,
        refblocks: Vec<u8>,
        caller: Vec<u8>,
        barriers: Vec<BarrierClass>,
    }

    /// Build a clean image (no backing) plus its gated state:
    /// `virtual_size` = 4 L2 tables of coverage, `l1_size` = 4.
    fn mk(cluster_bits: u32, l2_slots: usize, backing: bool) -> (TestImg, WriteState) {
        let cs = 1usize << cluster_bits;
        let l2_coverage = (cs as u64 / 8) * cs as u64;
        mk_vs(cluster_bits, l2_slots, backing, 4 * l2_coverage)
    }

    /// [`mk`] with an explicit `virtual_size` (still `l1_size` =
    /// 4): the EOV-tail tests need unaligned sizes (the phase-4
    /// plan's amended decision 7).
    fn mk_vs(
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
    fn set_l1(img: &mut TestImg, idx: usize, value: u64) {
        img.l1[idx * 8..idx * 8 + 8].copy_from_slice(&value.to_be_bytes());
        let off = 3 * img.cs + idx * 8;
        img.disk[off..off + 8].copy_from_slice(&value.to_be_bytes());
    }

    fn put_disk_u64(img: &mut TestImg, off: usize, value: u64) {
        img.disk[off..off + 8].copy_from_slice(&value.to_be_bytes());
    }

    fn set_rc(img: &mut TestImg, cluster: u64, value: u64) {
        snapshot::qcow2::set_refcount_in_block(&mut img.refblocks, cluster, 16, value).unwrap();
    }

    fn rc_of(img: &TestImg, cluster: u64) -> u64 {
        snapshot::qcow2::read_refcount_in_block(&img.refblocks, cluster, 16).unwrap()
    }

    /// Persist an allocated mapping: L2 table at cluster 4
    /// (zeroed on disk), data cluster 5 mapped at `l2_idx` of L1
    /// slot 0, refcounts 1.
    fn add_allocated_cluster(img: &mut TestImg, l2_idx: usize, l1_flags: u64, l2_flags: u64) {
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
            RegionId::Bounce => panic!("Bounce is filler-only in v1 programs"),
        }
    }

    fn region_bytes(img: &mut TestImg, region: RegionId, off: usize, len: usize) -> Vec<u8> {
        let (buf, base) = region_mut(img, region);
        buf[base + off..base + off + len].to_vec()
    }

    /// Apply an emitted window literally (the executor role).
    fn exec(img: &mut TestImg, steps: &[Step]) {
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
                StepKind::ReadCluster => panic!("v1 planner must not emit ReadCluster"),
            }
        }
    }

    /// The decision-1 executor loop for one write request:
    /// plan / execute / reset until `Ok` or a real error.
    /// Returns the concatenated program (all windows in order).
    fn run_write(
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

    fn run_write_ok(
        img: &mut TestImg,
        st: &mut WriteState,
        voff: u64,
        len: u64,
        data: DataSource,
        cap: usize,
    ) -> Vec<Step> {
        run_write(img, st, voff, len, data, cap).expect("write must plan cleanly")
    }

    fn run_write_err(
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
    fn run_flush(
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

    fn run_flush_ok(img: &mut TestImg, st: &mut WriteState, cap: usize) -> Vec<Step> {
        run_flush(img, st, cap).expect("flush must plan cleanly")
    }

    fn kinds(steps: &[Step]) -> Vec<StepKind> {
        steps.iter().map(|s| s.kind).collect()
    }

    fn caller_data() -> DataSource {
        DataSource::CallerData { offset: 0 }
    }

    // ---------------- plan_write: classification ----------------

    #[test]
    fn alloc_write_full_cluster_emission_shape() {
        // Empty image, one full-cluster write: fresh L2 (cluster
        // 4) + fresh data cluster (5), emission order per
        // decision 7 (a)-(b).
        let (mut img, mut st) = mk(12, 2, false);
        let cs = img.cs as u64;
        let steps = run_write_ok(&mut img, &mut st, 0, cs, caller_data(), 64);
        assert_eq!(
            kinds(&steps),
            vec![
                StepKind::ZeroRegion,
                StepKind::PatchEntryU64,
                StepKind::WriteRange,
                StepKind::PatchEntryU64,
            ]
        );
        // Fresh L2 slot init.
        assert_eq!(steps[0].region, RegionId::L2Slot(0));
        assert_eq!(steps[0].len, cs);
        // 7(b): L2 init precedes the L1 patch referencing it.
        assert_eq!(steps[1].region, RegionId::L1);
        assert_eq!(steps[1].region_offset, 0);
        assert_eq!(steps[1].value, 4 * cs | OFLAG_COPIED);
        // Data write, then 7(a): the L2 patch last.
        assert_eq!(steps[2].region, RegionId::CallerData);
        assert_eq!(steps[2].region_offset, 0);
        assert_eq!(steps[2].disk_offset, 5 * cs);
        assert_eq!(steps[2].len, cs);
        assert_eq!(steps[3].region, RegionId::L2Slot(0));
        assert_eq!(steps[3].region_offset, 0);
        assert_eq!(steps[3].value, 5 * cs | OFLAG_COPIED);
        // Refcounts mutated in place (decision 6), dirty bits set.
        assert_eq!(rc_of(&img, 4), 1);
        assert_eq!(rc_of(&img, 5), 1);
        assert_eq!(rc_of(&img, 6), 0);
        assert_eq!(st.alloc_cursor().allocated, 2);
        assert!(st.refblock_dirty(0));
        assert!(st.l1_dirty());
        let slot = st.l2_slot(0).unwrap();
        assert!(slot.valid && slot.dirty);
        assert_eq!(slot.l1_idx, 0);
        assert_eq!(slot.host_offset, 4 * cs);
        // Executor state: staged L1/L2 patched, data on disk.
        assert_eq!(read_u64_be(&img.l1, 0), 4 * cs | OFLAG_COPIED);
        assert_eq!(read_u64_be(&img.l2win, 0), 5 * cs | OFLAG_COPIED);
        let d = 5 * img.cs;
        assert_eq!(&img.disk[d..d + img.cs], &img.caller[..img.cs]);
    }

    #[test]
    fn owned_overwrite_load_boundary_then_in_place_write() {
        // Allocated + owned (COPIED, refcount 1): the decision-5
        // protocol loads the L2 through a forced window
        // boundary, then overwrites in place with no metadata
        // change.
        let (mut img, mut st) = mk(12, 2, false);
        let cs = img.cs as u64;
        add_allocated_cluster(&mut img, 3, OFLAG_COPIED, OFLAG_COPIED);
        let steps = run_write_ok(&mut img, &mut st, 3 * cs + 100, 200, caller_data(), 64);
        assert_eq!(
            kinds(&steps),
            vec![StepKind::LoadCluster, StepKind::WriteRange]
        );
        assert_eq!(steps[0].disk_offset, 4 * cs);
        assert_eq!(steps[1].disk_offset, 5 * cs + 100);
        assert_eq!(steps[1].len, 200);
        // No allocation, no dirty metadata.
        assert_eq!(st.alloc_cursor().allocated, 0);
        assert!(!st.refblock_dirty(0));
        assert!(!st.l1_dirty());
        assert!(!st.l2_slot(0).unwrap().dirty);
        let d = 5 * img.cs + 100;
        assert_eq!(&img.disk[d..d + 200], &img.caller[..200]);
        // Flush after a pure overwrite epoch: one Durability
        // barrier pinning the data writes, nothing else.
        let flush = run_flush_ok(&mut img, &mut st, 64);
        assert_eq!(
            kinds(&flush),
            vec![StepKind::Barrier {
                class: BarrierClass::Durability
            }]
        );
    }

    #[test]
    fn classification_l2_refusal_table() {
        // Each row: (entry value, refcount for cluster 5,
        // expected refusal).
        let cs = 1u64 << 12;
        let rows: [(u64, u64, WriteError); 8] = [
            (5 * cs | OFLAG_COMPRESSED, 1, WriteError::CompressedCluster),
            (5 * cs, 1, WriteError::SnapshotShared), // COPIED clear
            (5 * cs | OFLAG_COPIED, 2, WriteError::SnapshotShared),
            (5 * cs | OFLAG_COPIED, 0, WriteError::RefcountInconsistent),
            (1, 1, WriteError::UnknownL2Entry), // v3 zero flag
            (
                5 * cs | OFLAG_COPIED | (1 << 56),
                1,
                WriteError::UnknownL2Entry,
            ),
            (OFLAG_COPIED, 1, WriteError::UnknownL2Entry), // flags-only
            ((5 * cs + 512) | OFLAG_COPIED, 1, WriteError::UnknownL2Entry),
        ];
        for (entry, rc, expected) in rows {
            let (mut img, mut st) = mk(12, 2, false);
            add_allocated_cluster(&mut img, 0, OFLAG_COPIED, OFLAG_COPIED);
            let l2_disk = 4 * img.cs;
            put_disk_u64(&mut img, l2_disk, entry);
            set_rc(&mut img, 5, rc);
            assert_eq!(
                run_write_err(&mut img, &mut st, 0, 8, caller_data()),
                expected,
                "entry {entry:#x} rc {rc}"
            );
        }
        // Refcount outside the staged refblock set.
        let (mut img, mut st) = mk(12, 2, false);
        add_allocated_cluster(&mut img, 0, OFLAG_COPIED, OFLAG_COPIED);
        let far = 2048 * cs; // first cluster of refblock 1 (unstaged)
        let l2_disk = 4 * img.cs;
        put_disk_u64(&mut img, l2_disk, far | OFLAG_COPIED);
        assert_eq!(
            run_write_err(&mut img, &mut st, 0, 8, caller_data()),
            WriteError::RefcountCoverage
        );
    }

    #[test]
    fn classification_l1_refusal_table() {
        // Each row: (L1 entry value, refcount for cluster 4,
        // expected refusal). All refuse before any step is
        // emitted (the L1 check precedes the load).
        let cs = 1u64 << 12;
        let rows: [(u64, u64, WriteError); 7] = [
            (4 * cs, 1, WriteError::SnapshotSharedL2Table), // COPIED clear
            (
                4 * cs | OFLAG_COPIED | (1 << 57),
                1,
                WriteError::UnknownL1Entry,
            ),
            (OFLAG_COPIED, 1, WriteError::UnknownL1Entry), // flags-only
            ((4 * cs + 512) | OFLAG_COPIED, 1, WriteError::UnknownL1Entry),
            (4 * cs | OFLAG_COPIED, 2, WriteError::SnapshotSharedL2Table),
            (4 * cs | OFLAG_COPIED, 0, WriteError::RefcountInconsistent),
            ((2048 * cs) | OFLAG_COPIED, 1, WriteError::RefcountCoverage),
        ];
        for (entry, rc, expected) in rows {
            let (mut img, mut st) = mk(12, 2, false);
            set_l1(&mut img, 0, entry);
            set_rc(&mut img, 4, rc);
            let (err, steps) = run_write(&mut img, &mut st, 0, 8, caller_data(), 128)
                .expect_err("L1 shape must refuse");
            assert_eq!(err, expected, "entry {entry:#x} rc {rc}");
            assert!(steps.is_empty(), "L1 refusals precede any emission");
        }
    }

    #[test]
    fn needs_backing_fill_refusal_and_allowances() {
        let cs = 1u64 << 12;
        // Partial write into an unallocated cluster of a BACKED
        // image: the zero-fill would mask backing content.
        let (mut img, mut st) = mk(12, 2, true);
        add_allocated_cluster(&mut img, 0, OFLAG_COPIED, OFLAG_COPIED);
        let (err, steps) = run_write(&mut img, &mut st, cs + 100, 50, caller_data(), 128)
            .expect_err("partial allocating write on backed image must refuse");
        assert_eq!(err, WriteError::NeedsBackingFill);
        // Only the L2 load ran; nothing was allocated.
        assert_eq!(kinds(&steps), vec![StepKind::LoadCluster]);
        assert_eq!(st.alloc_cursor().allocated, 0);
        // Full-cluster allocating write on the same image: fine
        // (the pre-image is fully overwritten).
        let steps = run_write_ok(&mut img, &mut st, cs, cs, caller_data(), 128);
        assert_eq!(
            kinds(&steps),
            vec![StepKind::WriteRange, StepKind::PatchEntryU64]
        );
        // Partial write into an OWNED cluster: fine (no fill).
        let steps = run_write_ok(&mut img, &mut st, 100, 50, caller_data(), 128);
        assert_eq!(kinds(&steps), vec![StepKind::WriteRange]);
    }

    // ---------------- EOV tail cluster (amended decision 7 / D9) ----------------

    #[test]
    fn eov_tail_write_classifies_full_coverage() {
        // Phase-4 plan, amended decision 7: on the final (tail)
        // cluster of an unaligned virtual size, a partial
        // allocating write from the cluster base whose coverage
        // reaches virtual_size classifies as FULL coverage on
        // backed and backing-less images alike, and the crate
        // zero-fills the beyond-EOV remainder to the physical
        // cluster end.
        for backed in [false, true] {
            for cluster_bits in [9u32, 16] {
                let cs = 1u64 << cluster_bits;
                let tail_len = cs / 2 + 24; // unaligned EOV inside the tail cluster
                let vs = 3 * cs + tail_len;
                let (mut img, mut st) = mk_vs(cluster_bits, 2, backed, vs);
                let steps = run_write_ok(&mut img, &mut st, 3 * cs, tail_len, caller_data(), 64);
                assert_eq!(
                    kinds(&steps),
                    vec![
                        StepKind::ZeroRegion,
                        StepKind::PatchEntryU64, // L1 -> fresh L2 (cluster 4)
                        StepKind::WriteRange,    // body [0, tail_len)
                        StepKind::ZeroRange,     // beyond-EOV remainder
                        StepKind::PatchEntryU64, // L2 entry -> cluster 5
                    ],
                    "backed {backed} cb {cluster_bits}"
                );
                assert_eq!(steps[2].disk_offset, 5 * cs);
                assert_eq!(steps[2].len, tail_len);
                assert_eq!(steps[3].disk_offset, 5 * cs + tail_len);
                assert_eq!(steps[3].len, cs - tail_len);
                assert_eq!(steps[4].region_offset, 3 * 8); // l2_idx 3
                assert_eq!(steps[4].value, 5 * cs | OFLAG_COPIED);
                // Executed content: data, then zeros to the
                // physical cluster end (sentinel disproves a
                // missed beyond-EOV fill).
                let d = 5 * img.cs;
                let t = tail_len as usize;
                assert_eq!(&img.disk[d..d + t], &img.caller[..t]);
                assert!(
                    img.disk[d + t..d + img.cs].iter().all(|&b| b == 0),
                    "backed {backed} cb {cluster_bits}: beyond-EOV tail must be zero-filled"
                );
            }
        }
    }

    #[test]
    fn eov_tail_refusal_boundaries_on_backed_image() {
        // The amended-decision-7 rule only exempts the beyond-EOV
        // remainder: every genuinely partial write below EOV on a
        // backed image keeps the NeedsBackingFill refusal.
        for cluster_bits in [9u32, 16] {
            let cs = 1u64 << cluster_bits;
            let tail_len = cs / 2 + 24;
            let vs = 3 * cs + tail_len;
            let (mut img, mut st) = mk_vs(cluster_bits, 2, true, vs);
            add_allocated_cluster(&mut img, 0, OFLAG_COPIED, OFLAG_COPIED);
            // (a) in_off > 0 with coverage to EOV: the head
            // [0, in_off) is below-EOV backing content — refuse.
            assert_eq!(
                run_write_err(&mut img, &mut st, 3 * cs + 8, tail_len - 8, caller_data()),
                WriteError::NeedsBackingFill,
                "cb {cluster_bits}: head gap below EOV must refuse"
            );
            // (b) in_off == 0 but coverage ends one byte below
            // EOV: genuinely partial — refuse.
            assert_eq!(
                run_write_err(&mut img, &mut st, 3 * cs, tail_len - 1, caller_data()),
                WriteError::NeedsBackingFill,
                "cb {cluster_bits}: coverage below EOV must refuse"
            );
            // (c) genuinely partial below-EOV write on a
            // non-tail cluster: unchanged refusal.
            assert_eq!(
                run_write_err(&mut img, &mut st, cs, 8, caller_data()),
                WriteError::NeedsBackingFill,
                "cb {cluster_bits}: mid-image partial must refuse"
            );
            // (d) full-cluster allocating write on a non-tail
            // cluster of the same image: fine.
            let steps = run_write_ok(&mut img, &mut st, cs, cs, caller_data(), 64);
            assert_eq!(
                kinds(&steps),
                vec![StepKind::WriteRange, StepKind::PatchEntryU64],
                "cb {cluster_bits}"
            );
        }
    }

    #[test]
    fn eov_tail_aligned_virtual_size_keeps_full_cluster_rule() {
        // On a cluster-aligned virtual size the effective cluster
        // end equals the physical end everywhere: the final
        // cluster gets no exemption.
        let (mut img, mut st) = mk(16, 2, true);
        let cs = img.cs as u64;
        let vs = st.geometry().virtual_size;
        assert!(vs.is_multiple_of(cs));
        // One byte short of the aligned EOV: still partial.
        assert_eq!(
            run_write_err(&mut img, &mut st, vs - cs, cs - 1, caller_data()),
            WriteError::NeedsBackingFill
        );
        // The full final cluster: fine.
        run_write_ok(&mut img, &mut st, vs - cs, cs, caller_data(), 64);
    }

    #[test]
    fn eov_tail_backing_less_head_gap_zero_fills() {
        // Backing-less images are untouched by the amendment:
        // a tail-cluster write with a head gap still succeeds
        // with head + beyond-EOV zero-fills.
        let cs = 512u64;
        let (mut img, mut st) = mk_vs(9, 2, false, 3 * cs + 200);
        let steps = run_write_ok(&mut img, &mut st, 3 * cs + 40, 160, caller_data(), 64);
        assert_eq!(
            kinds(&steps),
            vec![
                StepKind::ZeroRegion,
                StepKind::PatchEntryU64, // L1 -> fresh L2
                StepKind::ZeroRange,     // head [0, 40)
                StepKind::WriteRange,    // body [40, 200)
                StepKind::ZeroRange,     // tail [200, 512) — beyond EOV
                StepKind::PatchEntryU64, // L2 entry
            ]
        );
        assert_eq!(steps[2].len, 40);
        assert_eq!(steps[3].len, 160);
        assert_eq!(steps[4].disk_offset, 5 * cs + 200);
        assert_eq!(steps[4].len, cs - 200);
    }

    #[test]
    fn out_of_bounds_still_fires_past_unaligned_eov() {
        // The tail rule reinterprets coverage WITHIN the final
        // cluster; it admits nothing past virtual_size.
        for backed in [false, true] {
            let cs = 1u64 << 12;
            let tail_len = 100u64;
            let vs = 3 * cs + tail_len;
            let (mut img, mut st) = mk_vs(12, 2, backed, vs);
            for (voff, len) in [(vs, 1u64), (3 * cs, tail_len + 1), (vs - 1, 2)] {
                assert_eq!(
                    run_write_err(&mut img, &mut st, voff, len, caller_data()),
                    WriteError::OutOfBounds,
                    "backed {backed} voff {voff} len {len}"
                );
            }
            // The exact EOV end is admitted (and, from the
            // cluster base, plans cleanly on both).
            run_write_ok(&mut img, &mut st, 3 * cs, tail_len, caller_data(), 64);
        }
    }

    #[test]
    fn fill_data_source_lowers_to_fill_range() {
        let (mut img, mut st) = mk(12, 2, false);
        let cs = img.cs as u64;
        add_allocated_cluster(&mut img, 3, OFLAG_COPIED, OFLAG_COPIED);
        let steps = run_write_ok(
            &mut img,
            &mut st,
            3 * cs + 10,
            20,
            DataSource::Fill { byte: 0xa5 },
            64,
        );
        assert_eq!(
            kinds(&steps),
            vec![StepKind::LoadCluster, StepKind::FillRange]
        );
        assert_eq!(steps[1].value, 0xa5);
        assert_eq!(steps[1].disk_offset, 5 * cs + 10);
        assert_eq!(steps[1].len, 20);
        let d = 5 * img.cs;
        assert_eq!(img.disk[d + 9], 0xEE, "byte before the fill untouched");
        assert!(img.disk[d + 10..d + 30].iter().all(|&b| b == 0xa5));
        assert_eq!(img.disk[d + 30], 0xEE, "byte after the fill untouched");
    }

    // ---------------- plan_write: sub-cluster + straddling ----------------

    #[test]
    fn sub_cluster_fresh_cluster_zero_fills_head_and_tail() {
        let (mut img, mut st) = mk(12, 2, false);
        let cs = img.cs as u64;
        let steps = run_write_ok(&mut img, &mut st, 100, 300, caller_data(), 64);
        assert_eq!(
            kinds(&steps),
            vec![
                StepKind::ZeroRegion,
                StepKind::PatchEntryU64, // L1 -> fresh L2 (cluster 4)
                StepKind::ZeroRange,     // head [0, 100)
                StepKind::WriteRange,    // body [100, 400)
                StepKind::ZeroRange,     // tail [400, cs)
                StepKind::PatchEntryU64, // L2 entry -> cluster 5
            ]
        );
        assert_eq!(steps[2].disk_offset, 5 * cs);
        assert_eq!(steps[2].len, 100);
        assert_eq!(steps[3].disk_offset, 5 * cs + 100);
        assert_eq!(steps[3].len, 300);
        assert_eq!(steps[4].disk_offset, 5 * cs + 400);
        assert_eq!(steps[4].len, cs - 400);
        // Executed content: zeros + data + zeros over the whole
        // cluster (sentinel disproves missed fills).
        let d = 5 * img.cs;
        assert!(img.disk[d..d + 100].iter().all(|&b| b == 0));
        assert_eq!(&img.disk[d + 100..d + 400], &img.caller[..300]);
        assert!(img.disk[d + 400..d + img.cs].iter().all(|&b| b == 0));
    }

    #[test]
    fn straddling_write_splits_at_cluster_boundary() {
        let (mut img, mut st) = mk(12, 2, false);
        let cs = img.cs as u64;
        let steps = run_write_ok(&mut img, &mut st, cs - 100, 200, caller_data(), 64);
        // Cluster 0 (tail 100 bytes): fresh L2 + data cluster 5,
        // head zero only. Cluster 1 (head 100 bytes): window
        // hit, data cluster 6, tail zero only.
        assert_eq!(
            kinds(&steps),
            vec![
                StepKind::ZeroRegion,
                StepKind::PatchEntryU64,
                StepKind::ZeroRange,  // head of cluster 0's window
                StepKind::WriteRange, // 100 bytes at end of cluster 5
                StepKind::PatchEntryU64,
                StepKind::WriteRange, // 100 bytes at start of cluster 6
                StepKind::ZeroRange,  // tail of cluster 6
                StepKind::PatchEntryU64,
            ]
        );
        // Caller-data continuity across the split (decision 1's
        // consumed-offset bookkeeping).
        assert_eq!(steps[3].region_offset, 0);
        assert_eq!(steps[3].disk_offset, 5 * cs + (cs - 100));
        assert_eq!(steps[3].len, 100);
        assert_eq!(steps[5].region_offset, 100);
        assert_eq!(steps[5].disk_offset, 6 * cs);
        assert_eq!(steps[5].len, 100);
        // Virtual content round-trips.
        assert_eq!(&img.disk[6 * img.cs - 100..6 * img.cs], &img.caller[..100]);
        assert_eq!(
            &img.disk[6 * img.cs..6 * img.cs + 100],
            &img.caller[100..200]
        );
    }

    #[test]
    fn l1_boundary_straddle_stages_both_tables() {
        let (mut img, mut st) = mk(12, 2, false);
        let cs = img.cs as u64;
        let l2_cov = st.geometry().l2_coverage;
        let steps = run_write_ok(&mut img, &mut st, l2_cov - cs, 2 * cs, caller_data(), 64);
        // Two fresh L2 tables (clusters 4 and 6), two data
        // clusters (5 and 7), no eviction with 2 slots.
        assert!(!kinds(&steps).contains(&StepKind::WritebackCluster));
        assert_eq!(read_u64_be(&img.l1, 0), 4 * cs | OFLAG_COPIED);
        assert_eq!(read_u64_be(&img.l1, 8), 6 * cs | OFLAG_COPIED);
        assert_eq!(st.l2_slot(0).unwrap().l1_idx, 0);
        assert_eq!(st.l2_slot(1).unwrap().l1_idx, 1);
        // Last entry of table 0 -> cluster 5; first of table 1
        // -> cluster 7.
        let last = img.cs - 8;
        assert_eq!(read_u64_be(&img.l2win, last), 5 * cs | OFLAG_COPIED);
        assert_eq!(read_u64_be(&img.l2win, img.cs), 7 * cs | OFLAG_COPIED);
    }

    // ---------------- plan_write: L2 window / LRU ----------------

    #[test]
    fn single_slot_evicts_dirty_table_with_writeback() {
        let (mut img, mut st) = mk(12, 1, false);
        let cs = img.cs as u64;
        let l2_cov = st.geometry().l2_coverage;
        let steps = run_write_ok(&mut img, &mut st, l2_cov - cs, 2 * cs, caller_data(), 64);
        // Moving from table 0 to table 1 with one slot: the
        // dirty fresh table 0 is written back before reuse.
        let wb: Vec<&Step> = steps
            .iter()
            .filter(|s| s.kind == StepKind::WritebackCluster)
            .collect();
        assert_eq!(wb.len(), 1);
        assert_eq!(wb[0].disk_offset, 4 * cs);
        assert_eq!(wb[0].region, RegionId::L2Slot(0));
        assert_eq!(st.l2_slot(0).unwrap().l1_idx, 1, "slot recycled to table 1");
        // The evicted table's content reached disk: its last
        // entry maps cluster 5.
        assert_eq!(
            read_u64_be(&img.disk, 4 * img.cs + img.cs - 8),
            5 * cs | OFLAG_COPIED
        );
        // Flush writes back only the live slot (table 1).
        let flush = run_flush_ok(&mut img, &mut st, 64);
        let fwb: Vec<&Step> = flush
            .iter()
            .filter(|s| s.kind == StepKind::WritebackCluster)
            .collect();
        assert_eq!(fwb.len(), 1);
        assert_eq!(fwb[0].disk_offset, 6 * cs);
    }

    #[test]
    fn lru_eviction_order_is_least_recently_used() {
        let (mut img, mut st) = mk(12, 2, false);
        let cs = img.cs as u64;
        let l2_cov = st.geometry().l2_coverage;
        // Touch tables 0, 1, 2, 0 with 2 slots. Table 2 must
        // evict table 0 (LRU), and revisiting table 0 must evict
        // table 1.
        run_write_ok(&mut img, &mut st, 0, cs, caller_data(), 64); // table 0: L2=4, data=5
        run_write_ok(&mut img, &mut st, l2_cov, cs, caller_data(), 64); // table 1: L2=6, data=7
        let s3 = run_write_ok(&mut img, &mut st, 2 * l2_cov, cs, caller_data(), 64); // table 2: L2=8, data=9
        let wb3: Vec<&Step> = s3
            .iter()
            .filter(|s| s.kind == StepKind::WritebackCluster)
            .collect();
        assert_eq!(wb3.len(), 1);
        assert_eq!(wb3[0].disk_offset, 4 * cs, "table 0 (LRU) evicted first");
        assert_eq!(wb3[0].region, RegionId::L2Slot(0));
        let s4 = run_write_ok(&mut img, &mut st, 0, cs, caller_data(), 64); // table 0 again
        let wb4: Vec<&Step> = s4
            .iter()
            .filter(|s| s.kind == StepKind::WritebackCluster)
            .collect();
        assert_eq!(wb4.len(), 1);
        assert_eq!(wb4[0].disk_offset, 6 * cs, "then table 1");
        assert_eq!(wb4[0].region, RegionId::L2Slot(1));
        // The reloaded table 0 classifies its cluster as owned
        // now: the 4th write is load + in-place overwrite.
        assert_eq!(
            kinds(&s4),
            vec![
                StepKind::WritebackCluster,
                StepKind::LoadCluster,
                StepKind::WriteRange,
            ]
        );
        assert_eq!(
            st.alloc_cursor().allocated,
            6,
            "no re-allocation on revisit"
        );
    }

    #[test]
    fn clean_slot_eviction_emits_no_writeback() {
        let (mut img, mut st) = mk(12, 1, false);
        let cs = img.cs as u64;
        let l2_cov = st.geometry().l2_coverage;
        // Two tables allocated on disk; overwrites only, so the
        // slot never dirties and eviction is silent.
        set_l1(&mut img, 0, 4 * cs | OFLAG_COPIED);
        set_l1(&mut img, 1, 6 * cs | OFLAG_COPIED);
        for c in [4usize, 6] {
            for b in &mut img.disk[c * img.cs..(c + 1) * img.cs] {
                *b = 0;
            }
        }
        let t0_disk = 4 * img.cs;
        let t1_disk = 6 * img.cs;
        put_disk_u64(&mut img, t0_disk, 5 * cs | OFLAG_COPIED);
        put_disk_u64(&mut img, t1_disk, 7 * cs | OFLAG_COPIED);
        for c in 4..8 {
            set_rc(&mut img, c, 1);
        }
        let s1 = run_write_ok(&mut img, &mut st, 0, 8, caller_data(), 64);
        let s2 = run_write_ok(&mut img, &mut st, l2_cov, 8, caller_data(), 64);
        assert_eq!(
            kinds(&s1),
            vec![StepKind::LoadCluster, StepKind::WriteRange]
        );
        assert_eq!(
            kinds(&s2),
            vec![StepKind::LoadCluster, StepKind::WriteRange],
            "clean eviction must not write back"
        );
    }

    // ---------------- plan_write: windowing / resume ----------------

    /// One eventful scenario: owned overwrite, fresh L2s, a
    /// straddling sub-cluster write, an L1-boundary crossing and
    /// an eviction (1 slot), then a flush.
    fn invariance_scenario(cap: usize) -> (Vec<Step>, Vec<Step>) {
        let (mut img, mut st) = mk(12, 1, false);
        let cs = img.cs as u64;
        let l2_cov = 512 * cs;
        add_allocated_cluster(&mut img, 0, OFLAG_COPIED, OFLAG_COPIED);
        let mut program = Vec::new();
        program.extend(run_write_ok(&mut img, &mut st, 50, 100, caller_data(), cap));
        program.extend(run_write_ok(
            &mut img,
            &mut st,
            2 * cs - 100,
            cs,
            caller_data(),
            cap,
        ));
        program.extend(run_write_ok(
            &mut img,
            &mut st,
            l2_cov - 100,
            300,
            DataSource::Fill { byte: 0x5a },
            cap,
        ));
        let flush = run_flush_ok(&mut img, &mut st, cap);
        (program, flush)
    }

    #[test]
    fn window_invariance_across_buffer_sizes() {
        // Decision 1: the concatenated emission is identical for
        // every step-buffer size, including a pathological
        // 1-step buffer that splits every cluster group at every
        // possible point (step 3c pins this property over a much
        // larger grid; this is the 3b anchor).
        let reference = invariance_scenario(128);
        for cap in [1usize, 2, 3, 5, 7] {
            let got = invariance_scenario(cap);
            assert_eq!(got.0, reference.0, "write program at cap {cap}");
            assert_eq!(got.1, reference.1, "flush program at cap {cap}");
        }
    }

    #[test]
    fn buf_full_resume_requires_same_arguments() {
        let (mut img, mut st) = mk(12, 2, false);
        let cs = img.cs as u64;
        let mut storage = [step(StepKind::ZeroRange); 1];
        let mut buf = StepBuf::new(&mut storage);
        let r = {
            let mut sv = StagedRegions {
                l1: &img.l1,
                l2_window: &img.l2win,
                refcount_table: &img.rt,
                refblocks: &mut img.refblocks,
            };
            plan_write(&mut st, &mut sv, 0, cs, caller_data(), &mut buf)
        };
        assert_eq!(r, Err(WriteError::BufFull));
        assert_eq!(buf.emitted(), 1);
        let window1 = buf.steps().to_vec();
        exec(&mut img, &window1);
        buf.reset();
        // Different arguments: protocol misuse, in-flight
        // request preserved.
        {
            let mut sv = StagedRegions {
                l1: &img.l1,
                l2_window: &img.l2win,
                refcount_table: &img.rt,
                refblocks: &mut img.refblocks,
            };
            assert_eq!(
                plan_write(&mut st, &mut sv, 8, cs, caller_data(), &mut buf),
                Err(WriteError::ResumeMismatch)
            );
            assert_eq!(
                plan_write(
                    &mut st,
                    &mut sv,
                    0,
                    cs,
                    DataSource::Fill { byte: 0 },
                    &mut buf
                ),
                Err(WriteError::ResumeMismatch)
            );
            // A flush during a pending write is also misuse.
            assert_eq!(
                plan_flush(&mut st, &mut sv, &mut buf),
                Err(WriteError::ResumeMismatch)
            );
        }
        assert_eq!(buf.emitted(), 0, "misuse emits nothing");
        // The correct resume still completes.
        let rest = run_write_ok(&mut img, &mut st, 0, cs, caller_data(), 1);
        let mut full = window1;
        full.extend(rest);
        assert_eq!(
            kinds(&full),
            vec![
                StepKind::ZeroRegion,
                StepKind::PatchEntryU64,
                StepKind::WriteRange,
                StepKind::PatchEntryU64,
            ]
        );
    }

    #[test]
    fn write_during_pending_flush_is_misuse() {
        let (mut img, mut st) = mk(12, 2, false);
        let cs = img.cs as u64;
        run_write_ok(&mut img, &mut st, 0, cs, caller_data(), 64);
        let mut storage = [step(StepKind::ZeroRange); 1];
        let mut buf = StepBuf::new(&mut storage);
        let r = {
            let mut sv = StagedRegions {
                l1: &img.l1,
                l2_window: &img.l2win,
                refcount_table: &img.rt,
                refblocks: &mut img.refblocks,
            };
            plan_flush(&mut st, &mut sv, &mut buf)
        };
        assert_eq!(r, Err(WriteError::BufFull));
        exec(&mut img, buf.steps());
        buf.reset();
        {
            let mut sv = StagedRegions {
                l1: &img.l1,
                l2_window: &img.l2win,
                refcount_table: &img.rt,
                refblocks: &mut img.refblocks,
            };
            assert_eq!(
                plan_write(&mut st, &mut sv, 0, 8, caller_data(), &mut buf),
                Err(WriteError::ResumeMismatch)
            );
        }
        // The flush resumes and completes.
        run_flush_ok(&mut img, &mut st, 1);
    }

    #[test]
    fn window_emitted_counts_per_call() {
        let (mut img, mut st) = mk(12, 2, false);
        let cs = img.cs as u64;
        let mut storage = [step(StepKind::ZeroRange); 3];
        let mut buf = StepBuf::new(&mut storage);
        let r = {
            let mut sv = StagedRegions {
                l1: &img.l1,
                l2_window: &img.l2win,
                refcount_table: &img.rt,
                refblocks: &mut img.refblocks,
            };
            plan_write(&mut st, &mut sv, 0, cs, caller_data(), &mut buf)
        };
        assert_eq!(r, Err(WriteError::BufFull));
        assert_eq!(buf.emitted(), 3);
        exec(&mut img, buf.steps());
        buf.reset();
        let r = {
            let mut sv = StagedRegions {
                l1: &img.l1,
                l2_window: &img.l2win,
                refcount_table: &img.rt,
                refblocks: &mut img.refblocks,
            };
            plan_write(&mut st, &mut sv, 0, cs, caller_data(), &mut buf)
        };
        assert_eq!(
            r,
            Ok(Window { emitted: 1 }),
            "resumed call emits the remainder"
        );
    }

    // ---------------- refcount arithmetic ----------------

    #[test]
    fn refcount_arithmetic_hand_computed_across_cluster_sizes() {
        // The phase-3b brief's matrix: 512 B, 4 KiB, 64 KiB and
        // 2 MiB clusters. A 3-cluster write on an empty image
        // claims cluster 4 (fresh L2) and clusters 5-7 (data);
        // every refcount expectation below is hand-computed
        // against the 16-bit big-endian refblock layout.
        for cluster_bits in [9u32, 12, 16, 21] {
            let (mut img, mut st) = mk(cluster_bits, 1, false);
            let cs = img.cs as u64;
            let steps = run_write_ok(&mut img, &mut st, 0, 3 * cs, caller_data(), 64);
            // Allocation order: L2 table first, then the three
            // data clusters, all from the first-fit scan.
            let patches: Vec<&Step> = steps
                .iter()
                .filter(|s| s.kind == StepKind::PatchEntryU64)
                .collect();
            assert_eq!(patches.len(), 4, "cb {cluster_bits}");
            assert_eq!(patches[0].value, 4 * cs | OFLAG_COPIED); // L1 -> L2
            for (i, p) in patches[1..].iter().enumerate() {
                assert_eq!(p.value, (5 + i as u64) * cs | OFLAG_COPIED);
                assert_eq!(p.region_offset, i as u64 * 8);
            }
            // Staged refblock: entries 0-7 == 1, entry 8 == 0,
            // checked through the primitive AND as raw bytes.
            for c in 0..8u64 {
                assert_eq!(rc_of(&img, c), 1, "cb {cluster_bits} cluster {c}");
                assert_eq!(
                    &img.refblocks[c as usize * 2..c as usize * 2 + 2],
                    &[0u8, 1],
                    "cb {cluster_bits} cluster {c} raw bytes"
                );
            }
            assert_eq!(rc_of(&img, 8), 0);
            assert_eq!(st.alloc_cursor().allocated, 4);
            assert!(st.refblock_dirty(0));
            // Flush and verify everything landed at the
            // hand-computed disk offsets.
            run_flush_ok(&mut img, &mut st, 64);
            assert_eq!(&img.disk[2 * img.cs..3 * img.cs], &img.refblocks[..]);
            assert_eq!(&img.disk[3 * img.cs..3 * img.cs + 32], &img.l1[..]);
            for i in 0..3usize {
                assert_eq!(
                    read_u64_be(&img.disk, 4 * img.cs + i * 8),
                    (5 + i as u64) * cs | OFLAG_COPIED
                );
                let d = (5 + i) * img.cs;
                assert_eq!(
                    &img.disk[d..d + img.cs],
                    &img.caller[i * img.cs..(i + 1) * img.cs],
                    "cb {cluster_bits} data cluster {i}"
                );
            }
        }
    }

    #[test]
    fn refcount_exhausted_when_staged_refblocks_full() {
        let (mut img, mut st) = mk(12, 1, false);
        let cs = img.cs as u64;
        // Fill every entry of the (single) staged refblock.
        for c in 0..(img.cs as u64 * 8 / 16) {
            set_rc(&mut img, c, 1);
        }
        let (err, steps) = run_write(&mut img, &mut st, 0, cs, caller_data(), 128)
            .expect_err("full refblocks must refuse");
        assert_eq!(err, WriteError::RefcountExhausted);
        assert!(steps.is_empty(), "no allocation possible, nothing emitted");
        // Decision-9 shape: with exactly ONE free entry the
        // fresh L2 claims it and the data allocation fails,
        // leaving claimed-but-unflushed scaffolding.
        let (mut img, mut st) = mk(12, 1, false);
        for c in 0..(img.cs as u64 * 8 / 16) {
            set_rc(&mut img, c, 1);
        }
        set_rc(&mut img, 4, 0);
        let (err, steps) = run_write(&mut img, &mut st, 0, cs, caller_data(), 128)
            .expect_err("data allocation must still refuse");
        assert_eq!(err, WriteError::RefcountExhausted);
        assert_eq!(
            kinds(&steps),
            vec![StepKind::ZeroRegion, StepKind::PatchEntryU64]
        );
        assert_eq!(
            rc_of(&img, 4),
            1,
            "scaffolding L2 stays claimed (decision 9)"
        );
    }

    // ---------------- plan_flush ----------------

    #[test]
    fn flush_emission_order_refcounts_last_with_barriers() {
        let (mut img, mut st) = mk(12, 2, false);
        let cs = img.cs as u64;
        let l2_cov = st.geometry().l2_coverage;
        run_write_ok(&mut img, &mut st, 0, cs, caller_data(), 64);
        run_write_ok(&mut img, &mut st, l2_cov, cs, caller_data(), 64);
        let flush = run_flush_ok(&mut img, &mut st, 64);
        let durability = StepKind::Barrier {
            class: BarrierClass::Durability,
        };
        assert_eq!(
            kinds(&flush),
            vec![
                durability,
                StepKind::WritebackCluster, // slot 0 (table 0, L2 at 4)
                StepKind::WritebackCluster, // slot 1 (table 1, L2 at 6)
                durability,
                StepKind::WriteRange, // L1
                durability,
                StepKind::WriteRange, // refblock 0 (refcounts last, 7(c))
                durability,
            ]
        );
        assert_eq!(flush[1].disk_offset, 4 * cs);
        assert_eq!(flush[2].disk_offset, 6 * cs);
        assert_eq!(flush[4].region, RegionId::L1);
        assert_eq!(flush[4].disk_offset, 3 * cs);
        assert_eq!(flush[4].len, 32);
        assert_eq!(flush[6].region, RegionId::Refblocks);
        assert_eq!(flush[6].region_offset, 0);
        assert_eq!(flush[6].disk_offset, 2 * cs);
        assert_eq!(flush[6].len, cs);
        // The executor observed all four Durability barriers.
        assert_eq!(img.barriers.len(), 4);
        assert!(img.barriers.iter().all(|c| *c == BarrierClass::Durability));
        // Dirty state fully retired; a second flush is empty.
        assert!(!st.l1_dirty());
        assert!(!st.refblock_dirty(0));
        assert!(!st.l2_slot(0).unwrap().dirty);
        assert!(!st.l2_slot(1).unwrap().dirty);
        let again = run_flush_ok(&mut img, &mut st, 64);
        assert!(again.is_empty());
    }

    #[test]
    fn flush_skips_l1_group_when_l1_clean() {
        // A second epoch that only adds a data cluster through
        // an existing L2: the flush carries the slot write-back
        // and the refblock, but no L1 group.
        let (mut img, mut st) = mk(12, 1, false);
        let cs = img.cs as u64;
        run_write_ok(&mut img, &mut st, 0, cs, caller_data(), 64);
        run_flush_ok(&mut img, &mut st, 64);
        let steps = run_write_ok(&mut img, &mut st, cs, cs, caller_data(), 64);
        // Slot still valid from the last epoch: no reload.
        assert!(!kinds(&steps).contains(&StepKind::LoadCluster));
        let flush = run_flush_ok(&mut img, &mut st, 64);
        let durability = StepKind::Barrier {
            class: BarrierClass::Durability,
        };
        assert_eq!(
            kinds(&flush),
            vec![
                durability,
                StepKind::WritebackCluster,
                durability,
                StepKind::WriteRange, // refblock only, no L1 write
                durability,
            ]
        );
        assert_eq!(flush[3].region, RegionId::Refblocks);
    }

    #[test]
    fn flush_with_no_activity_emits_nothing() {
        let (mut img, mut st) = mk(12, 2, false);
        let flush = run_flush_ok(&mut img, &mut st, 64);
        assert!(flush.is_empty());
    }

    #[test]
    fn flush_refuses_dirty_refblock_without_table_entry() {
        // Two staged refblocks but the refcount table maps only
        // the first: an allocation landing in refblock 1 flushes
        // into a hole -> staging mismatch.
        let (mut img, mut st) = mk(9, 1, false);
        let cs = img.cs;
        img.refblocks = vec![0u8; 2 * cs];
        for c in 0..(cs as u64 * 8 / 16) {
            set_rc(&mut img, c, 1); // refblock 0 exhausted
        }
        img.rt = vec![0u8; 16];
        img.rt[..8].copy_from_slice(&(2 * cs as u64).to_be_bytes()); // entry 1 stays 0
        let steps = run_write_ok(&mut img, &mut st, 0, cs as u64, caller_data(), 128);
        assert!(!steps.is_empty());
        assert!(st.refblock_dirty(1));
        let (err, _) = run_flush(&mut img, &mut st, 128).expect_err("hole must refuse");
        assert_eq!(err, WriteError::StagedRegionsMismatch);
    }

    // ---------------- validation ----------------

    #[test]
    fn staged_region_mismatch_variants() {
        let (mut img, mut st) = mk(12, 2, false);
        let cs = img.cs;
        let mut storage = [step(StepKind::ZeroRange); 8];

        // l1 too short for l1_size.
        let mut buf = StepBuf::new(&mut storage);
        let mut sv = StagedRegions {
            l1: &img.l1[..24],
            l2_window: &img.l2win,
            refcount_table: &img.rt,
            refblocks: &mut img.refblocks,
        };
        assert_eq!(
            plan_write(&mut st, &mut sv, 0, 8, caller_data(), &mut buf),
            Err(WriteError::StagedRegionsMismatch)
        );

        // l2 window smaller than the configured slots.
        let mut buf = StepBuf::new(&mut storage);
        let mut sv = StagedRegions {
            l1: &img.l1,
            l2_window: &img.l2win[..cs],
            refcount_table: &img.rt,
            refblocks: &mut img.refblocks,
        };
        assert_eq!(
            plan_write(&mut st, &mut sv, 0, 8, caller_data(), &mut buf),
            Err(WriteError::StagedRegionsMismatch)
        );

        // Refblocks not a whole number of clusters.
        let mut short_rb = vec![0u8; cs - 1];
        let mut buf = StepBuf::new(&mut storage);
        let mut sv = StagedRegions {
            l1: &img.l1,
            l2_window: &img.l2win,
            refcount_table: &img.rt,
            refblocks: &mut short_rb,
        };
        assert_eq!(
            plan_flush(&mut st, &mut sv, &mut buf),
            Err(WriteError::StagedRegionsMismatch)
        );

        // More staged refblocks than the dirty bitset covers.
        let cfg = StagingConfig {
            l2_slots: 1,
            max_refblocks: 1,
            device: TargetDevice::Input0,
        };
        let mut small = new_state(&img.hdr, &cfg).unwrap();
        let mut two_rb = vec![0u8; 2 * cs];
        let mut rt16 = vec![0u8; 16];
        rt16[..8].copy_from_slice(&(2 * cs as u64).to_be_bytes());
        let mut buf = StepBuf::new(&mut storage);
        let mut sv = StagedRegions {
            l1: &img.l1,
            l2_window: &img.l2win,
            refcount_table: &rt16,
            refblocks: &mut two_rb,
        };
        assert_eq!(
            plan_write(&mut small, &mut sv, 0, 8, caller_data(), &mut buf),
            Err(WriteError::StagedRegionsMismatch)
        );

        // Refcount table shorter than 8 bytes per staged
        // refblock.
        let mut two_rb = vec![0u8; 2 * cs];
        let mut buf = StepBuf::new(&mut storage);
        let mut sv = StagedRegions {
            l1: &img.l1,
            l2_window: &img.l2win,
            refcount_table: &img.rt, // 8 bytes, needs 16
            refblocks: &mut two_rb,
        };
        assert_eq!(
            plan_write(&mut st, &mut sv, 0, 8, caller_data(), &mut buf),
            Err(WriteError::StagedRegionsMismatch)
        );

        // A zero-capacity step buffer can never make progress.
        let mut empty: [Step; 0] = [];
        let mut buf = StepBuf::new(&mut empty);
        let mut sv = StagedRegions {
            l1: &img.l1,
            l2_window: &img.l2win,
            refcount_table: &img.rt,
            refblocks: &mut img.refblocks,
        };
        assert_eq!(
            plan_write(&mut st, &mut sv, 0, 8, caller_data(), &mut buf),
            Err(WriteError::StagedRegionsMismatch)
        );
    }

    #[test]
    fn out_of_bounds_requests_refuse_before_emission() {
        let (mut img, mut st) = mk(12, 2, false);
        let vs = st.geometry().virtual_size;
        let mut storage = [step(StepKind::ZeroRange); 8];
        let mut buf = StepBuf::new(&mut storage);
        let mut sv = StagedRegions {
            l1: &img.l1,
            l2_window: &img.l2win,
            refcount_table: &img.rt,
            refblocks: &mut img.refblocks,
        };
        // Past the virtual size.
        assert_eq!(
            plan_write(&mut st, &mut sv, vs, 1, caller_data(), &mut buf),
            Err(WriteError::OutOfBounds)
        );
        assert_eq!(
            plan_write(&mut st, &mut sv, vs - 1, 2, caller_data(), &mut buf),
            Err(WriteError::OutOfBounds)
        );
        // Arithmetic overflow.
        assert_eq!(
            plan_write(&mut st, &mut sv, u64::MAX, 2, caller_data(), &mut buf),
            Err(WriteError::OutOfBounds)
        );
        // Caller-data offset overflow.
        assert_eq!(
            plan_write(
                &mut st,
                &mut sv,
                0,
                8,
                DataSource::CallerData { offset: u64::MAX },
                &mut buf
            ),
            Err(WriteError::OutOfBounds)
        );
        // The exact end of the disk is fine; len == 0 is a
        // no-op.
        assert_eq!(
            plan_write(&mut st, &mut sv, vs, 0, caller_data(), &mut buf),
            Ok(Window { emitted: 0 })
        );
        assert_eq!(buf.emitted(), 0);
    }

    #[test]
    fn out_of_bounds_when_header_l1_undersized() {
        // A header whose virtual size exceeds its own L1
        // coverage: writes beyond the L1 refuse (defensive; a
        // well-formed image cannot hit it).
        let cs = 1usize << 12;
        let l2_cov = (cs as u64 / 8) * cs as u64;
        let hdr = parse(&build_header(12, 4 * l2_cov, 1, 0));
        let cfg = StagingConfig {
            l2_slots: 1,
            max_refblocks: 32,
            device: TargetDevice::Input0,
        };
        let mut st = new_state(&hdr, &cfg).unwrap();
        let l1 = vec![0u8; 8];
        let l2win = vec![0u8; cs];
        let rt = (2 * cs as u64).to_be_bytes().to_vec();
        let mut refblocks = vec![0u8; cs];
        let mut storage = [step(StepKind::ZeroRange); 8];
        let mut buf = StepBuf::new(&mut storage);
        let mut sv = StagedRegions {
            l1: &l1,
            l2_window: &l2win,
            refcount_table: &rt,
            refblocks: &mut refblocks,
        };
        assert_eq!(
            plan_write(&mut st, &mut sv, l2_cov, 8, caller_data(), &mut buf),
            Err(WriteError::OutOfBounds)
        );
    }

    #[test]
    fn write_error_codes_distinct_and_stable() {
        let codes = [
            (WriteError::BufFull, 1),
            (WriteError::RefcountExhausted, 2),
            (WriteError::NotImplemented, 3),
            (WriteError::OutOfBounds, 4),
            (WriteError::ResumeMismatch, 5),
            (WriteError::StagedRegionsMismatch, 6),
            (WriteError::CompressedCluster, 7),
            (WriteError::SnapshotShared, 8),
            (WriteError::SnapshotSharedL2Table, 9),
            (WriteError::UnknownL1Entry, 10),
            (WriteError::UnknownL2Entry, 11),
            (WriteError::RefcountInconsistent, 12),
            (WriteError::RefcountCoverage, 13),
            (WriteError::NeedsBackingFill, 14),
        ];
        for (err, expected) in codes {
            assert_eq!(err.code(), expected, "{err:?} code drifted");
        }
        for i in 0..codes.len() {
            for j in (i + 1)..codes.len() {
                assert_ne!(codes[i].1, codes[j].1, "codes {i} and {j} alias");
            }
        }
    }

    #[test]
    fn second_cluster_in_pending_fresh_l2_classifies_as_zero() {
        // Two clusters through one freshly allocated L2 in ONE
        // window: the second classification runs while the
        // slot's ZeroRegion is still pending, so it must see
        // logical zeros (the window buffer holds 0xEE sentinel
        // until execution — a raw read would refuse as
        // UnknownL2Entry).
        let (mut img, mut st) = mk(12, 1, false);
        let cs = img.cs as u64;
        let mut storage = [step(StepKind::ZeroRange); 64];
        let mut buf = StepBuf::new(&mut storage);
        let r = {
            let mut sv = StagedRegions {
                l1: &img.l1,
                l2_window: &img.l2win,
                refcount_table: &img.rt,
                refblocks: &mut img.refblocks,
            };
            plan_write(&mut st, &mut sv, 0, 2 * cs, caller_data(), &mut buf)
        };
        assert_eq!(
            r,
            Ok(Window { emitted: 6 }),
            "both clusters plan in one window despite the pending slot init"
        );
        exec(&mut img, buf.steps());
        assert_eq!(read_u64_be(&img.l2win, 0), 5 * cs | OFLAG_COPIED);
        assert_eq!(read_u64_be(&img.l2win, 8), 6 * cs | OFLAG_COPIED);
    }
}
