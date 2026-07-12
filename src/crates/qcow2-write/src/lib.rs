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
//! Phase 3a ships the type vocabulary, the envelope gates and a
//! gated [`WriteState`] constructor; [`plan_write`] and
//! [`plan_flush`] are typed stubs returning
//! [`WriteError::NotImplemented`] until step 3b fills them in.

#![no_std]

use qcow2::QcowHeader;
use snapshot::qcow2::AllocCursor;

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
/// variant; unused fields are zero. Executors stay dumb: even
/// the refblock flush is a planner emission pattern
/// (per-dirty-refblock [`StepKind::WriteRange`] steps from
/// [`plan_flush`]), not a magic composite step (decision 6).
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
    /// region; fresh-L2 init and zero-fill).
    ZeroRange,
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
/// Decision 9 (capacity semantics): capacity refusals are clean
/// but not byte-idempotent in v1. [`Self::RefcountExhausted`]
/// can surface mid-plan after earlier windows executed; the
/// image is left with the same semantics as today's ops —
/// unreferenced scaffolding clusters may exist, no metadata was
/// flushed, and the image is check-clean. Full byte-idempotence
/// needs a worst-case pre-pass whose bound machinery arrives
/// with phase 6's refcount-growth planner, so it is deferred
/// there.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WriteError {
    /// The step buffer filled mid-plan. NOT a failure: per
    /// decision 1 this is the windowing resume signal — execute
    /// the emitted steps, [`StepBuf::reset`], and call the
    /// planner again; [`WriteState`] holds the resume point.
    BufFull,
    /// Every staged refblock is full; v1 does not grow the
    /// refcount table (decision 9 above; phase 6 moves bench's
    /// growth planner in).
    RefcountExhausted,
    /// The requested planner is not implemented yet (phase 3a
    /// stubs; step 3b replaces every occurrence).
    NotImplemented,
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
    })
}

// ---------------------------------------------------------------------------
// Planners (stubs — step 3b)
// ---------------------------------------------------------------------------

/// Plan "write `len` bytes of `data` at virtual offset `voff`"
/// into the caller's step window (decisions 1-3, 5-7).
///
/// Step 3b implements per-cluster classification, allocation,
/// sub-cluster RMW and the L2 window; until then every call
/// returns [`WriteError::NotImplemented`]. The signature is the
/// settled one from the phase-3 plan's API sketch: on
/// [`WriteError::BufFull`] the caller executes the emitted
/// window, resets the buffer and calls again — `state` holds
/// the resume point.
pub fn plan_write(
    state: &mut WriteState,
    voff: u64,
    len: u64,
    data: DataSource,
    steps: &mut StepBuf<'_>,
) -> Result<Window, WriteError> {
    let _ = (state, voff, len, data, steps);
    Err(WriteError::NotImplemented)
}

/// Plan the end-of-epoch flush: writebacks for dirty L2 slots
/// and dirty refblocks, refcounts last, with decision-4
/// barriers at the decision-7 contract points.
///
/// Step 3b implements the emission; until then every call
/// returns [`WriteError::NotImplemented`].
pub fn plan_flush(state: &mut WriteState, steps: &mut StepBuf<'_>) -> Result<Window, WriteError> {
    let _ = (state, steps);
    Err(WriteError::NotImplemented)
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

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
            },
            StagingConfig {
                l2_slots: MAX_L2_SLOTS + 1,
                max_refblocks: 32,
            },
            StagingConfig {
                l2_slots: 4,
                max_refblocks: 0,
            },
            StagingConfig {
                l2_slots: 4,
                max_refblocks: MAX_REFBLOCKS + 1,
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
            }
        )
        .is_ok());
        assert!(new_state(
            &hdr,
            &StagingConfig {
                l2_slots: 1,
                max_refblocks: 1,
            }
        )
        .is_ok());
    }

    // ---------------- Planner stubs ----------------

    #[test]
    fn plan_write_and_flush_not_implemented() {
        let hdr = clean_header();
        let mut st = new_state(&hdr, &valid_config()).unwrap();
        let mut storage = [step(StepKind::ZeroRange); 8];
        let mut buf = StepBuf::new(&mut storage);
        assert_eq!(
            plan_write(&mut st, 0, 512, DataSource::Fill { byte: 0xa5 }, &mut buf),
            Err(WriteError::NotImplemented)
        );
        assert_eq!(
            plan_write(
                &mut st,
                4096,
                65536,
                DataSource::CallerData { offset: 0 },
                &mut buf
            ),
            Err(WriteError::NotImplemented)
        );
        assert_eq!(
            plan_flush(&mut st, &mut buf),
            Err(WriteError::NotImplemented)
        );
        // Stubs must not emit anything.
        assert_eq!(buf.emitted(), 0);
    }
}
