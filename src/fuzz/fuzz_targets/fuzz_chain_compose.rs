//! Coverage-guided fuzzing of the backing-chain compose path: a child
//! image read through a device behind it.
//!
//! The first target to reach `read_chain_virtual_cluster` at all. Every
//! other CallTable target serves one input device, so the chain walk —
//! the loop over devices, the descent into a device behind the one that
//! does not hold a cluster, and the zero-fill at the bottom — was
//! unreachable by construction, not merely unexplored. That is why this
//! one opts the harness into multi-device mode
//! (`instar_fuzz::set_fuzz_devices`) rather than sharing the single
//! buffer the rest use.
//!
//! The chain config is built here as a Rust struct rather than decoded
//! from bytes. `init_chain_states` and `read_chain_virtual_cluster` both
//! take `&ChainConfig` directly, so the serialised form the host writes
//! to guest memory — and the `get_chain_config` call that reads it back
//! — is not on the path under test, and synthesising it would only add a
//! second thing for the fuzzer to get right before a single cluster is
//! looked up.
//!
//! Invariants asserted below, not merely the absence of a panic. A
//! chain reader that crashes is the least of its failure modes; the ones
//! worth catching all look like success from the outside:
//!
//! 1. A read that reports success filled the whole buffer it was given.
//!    A span the reader leaves untouched hands the caller whatever was
//!    in the buffer before — stale data, or the zeros of a fresh
//!    allocation — under a `true` return.
//! 2. A device that failed to initialise is not read through. The
//!    reader has no state for such a device and cannot look a cluster up
//!    in it; serving the device's own zeros instead is a wrong answer
//!    reported as a right one. Checked at every depth the target
//!    builds, not only at the top of the chain: a stateless device
//!    *behind* the child is the shape a read reaches only by
//!    descending, and so the one a top-of-chain check cannot see.
//! 3. A refusal does not look like a successful read of zeros. This is
//!    the shape of issue #547, where a differencing child whose parent
//!    was never resolved composed against nothing and wrote the child's
//!    own zeros wherever the parent's data belonged, exiting 0. The
//!    buffer is prefilled with a sentinel and the return value checked
//!    before the contents, so "refused" and "read a hole" cannot be
//!    confused here the way they were there.
//! 4. A device behind the child never overrides a byte the child holds.
//!    Reading the same offset twice — once as the whole chain, once as
//!    the child alone — must agree wherever the child alone produced
//!    non-zero bytes, because those are bytes the child owns and the
//!    chain length has no business changing them.

#![no_main]

use libfuzzer_sys::fuzz_target;
use qcow2::{init_chain_states, read_chain_virtual_cluster, ChainStates};
use shared::{
    ChainConfig, ChainSegment, ImageFormat, COMPRESSED_BUF_SIZE, MAX_CLUSTER_SIZE, MAX_SECTOR_SIZE,
};
use std::cell::RefCell;

/// Devices in the chain: a child and one device behind it. Two is what
/// makes a compose a compose; a third would cost input bytes the
/// fuzzer currently spends on the two images' contents.
const DEVICE_COUNT: usize = 2;

/// Device (and mock) sector size.
const SECTOR_SIZE: usize = 512;

/// Upper bound on the chunk a single read is asked for.
///
/// `MAX_SECTOR_SIZE`, not an arbitrary number: `read_raw_sectors`
/// documents that its caller's buffer is always at least that large,
/// and reads a whole sector into it even for a shorter chunk. A
/// smaller read buffer here would be a harness bug reported as a
/// crash in the code under test.
const MAX_CHUNK: usize = MAX_SECTOR_SIZE;

/// Prefilled into a read buffer before each read, so a byte the reader
/// did not write is visible as one it did not write. Two distinct
/// values are needed: see `read_twice`.
const SENTINEL_A: u8 = 0xA5;
const SENTINEL_B: u8 = 0x5A;

/// The buffers the reader's safety contract fixes the size of, plus the
/// per-device cache region `init_chain_states` carves up.
///
/// Held for the life of the process rather than allocated per
/// iteration. Together these are over four megabytes; zeroing them for
/// every execution would cost far more than the reads being fuzzed, and
/// would put the harness rather than the parser at the top of the
/// profile.
struct Scratch {
    /// Scratch for decompressing a compressed cluster.
    compressed: Vec<u8>,
    /// Staging for a cluster larger than the requested chunk.
    staging: Vec<u8>,
    /// `2 * MAX_SECTOR_SIZE` of L1/L2 cache per device, which is the
    /// layout `shared::l1_cache_addr`/`l2_cache_addr` impose on the
    /// region handed to `init_chain_states`.
    caches: Vec<u8>,
    /// Two read buffers for the same span, prefilled differently.
    read_a: Vec<u8>,
    read_b: Vec<u8>,
    /// A third, for the same span read as the child alone.
    child_only: Vec<u8>,
}

impl Scratch {
    fn new() -> Self {
        Self {
            compressed: vec![0u8; COMPRESSED_BUF_SIZE],
            staging: vec![0u8; MAX_CLUSTER_SIZE],
            caches: vec![0u8; 2 * MAX_SECTOR_SIZE * DEVICE_COUNT],
            read_a: vec![0u8; MAX_CHUNK],
            read_b: vec![0u8; MAX_CHUNK],
            child_only: vec![0u8; MAX_CHUNK],
        }
    }
}

thread_local! {
    static SCRATCH: RefCell<Scratch> = RefCell::new(Scratch::new());
}

/// How the config describes the two devices' chain membership.
#[derive(Clone, Copy)]
enum Segmentation {
    /// One chain of two devices: the compose shape.
    OneChain,
    /// Two chains of one device each, which is what an operation
    /// reading two unrelated images packs into the one array. A legal
    /// tiling that declares no composition, so the reader is driven
    /// over device 0 alone.
    TwoChains,
    /// A segmentation that does not tile `[0, device_count)`.
    /// `init_chain_states` refuses this by design — there is no
    /// encoding for "the host did not say" — and the refusal is what
    /// invariants 2 and 3 are asserted against.
    Unstated,
}

/// The formats this target reasons about.
///
/// Deliberately only the two arms of `read_chain_virtual_cluster` that
/// are compiled unconditionally. Every other input format is behind a
/// cargo feature the fuzz crate does not enable, so naming one would
/// land in the catch-all raw arm instead — spending fuzzer bytes on a
/// format code that reaches nothing, and making the "needs per-device
/// state" judgement below depend on which features happened to be on.
const FORMATS: [[ImageFormat; DEVICE_COUNT]; 4] = [
    [ImageFormat::Qcow2, ImageFormat::Qcow2],
    [ImageFormat::Qcow2, ImageFormat::Qcow2],
    [ImageFormat::Qcow2, ImageFormat::Raw],
    [ImageFormat::Raw, ImageFormat::Qcow2],
];

/// Whether the chain reader needs per-device state to look a cluster up
/// in this format, and so cannot read a device it failed to initialise.
///
/// Only QCOW2, for the reason `FORMATS` gives: it is the one stateful
/// arm this build compiles. A raw device needs no state and reads its
/// own sectors whatever init did.
fn needs_state(format: ImageFormat) -> bool {
    matches!(format, ImageFormat::Qcow2)
}

fuzz_target!(|data: &[u8]| {
    // One control byte plus a byte for each image is the least that can
    // describe a two-device chain.
    if data.len() < 3 {
        return;
    }
    let control = data[0];
    let body = &data[1..];

    let formats = FORMATS[(control & 0x03) as usize];
    let segmentation = match (control >> 2) & 0x03 {
        // Weighted towards the chain that composes: the other two
        // shapes are each a single decision in `init_chain_states`,
        // while this one is the whole walk.
        0 | 1 => Segmentation::OneChain,
        2 => Segmentation::TwoChains,
        _ => Segmentation::Unstated,
    };

    // Where the child ends and the device behind it begins. Weighted
    // towards an even split, which is the only arm that can give the
    // two devices genuinely different contents; the others keep a
    // whole-input child (the easiest shape for the fuzzer to make a
    // valid image out of) and a short one in play.
    let split = match control >> 6 {
        0 | 1 => body.len() / 2,
        2 => body.len(),
        _ => body.len() / 4,
    }
    .clamp(1, body.len());
    let (child, tail) = body.split_at(split);
    let parent: &[u8] = match (control >> 4) & 0x03 {
        // Most of the corpus: the device behind the child is the
        // child's own bytes. A chain of two identical images is a
        // legal chain, and it is the only arm that reaches a two-device
        // chain of two *valid* images without the fuzzer having to
        // discover a header twice over inside one input — a second
        // precondition on top of the first, which is how a path ends up
        // fuzzed in name only.
        0 | 1 => child,
        2 => tail,
        // A device with no bytes at all: every read of it fails, which
        // is how a descent into an unreadable parent gets exercised.
        _ => &[],
    };
    instar_fuzz::set_fuzz_devices(&[child, parent]);

    let config = build_config(formats, segmentation);
    let call_table = instar_fuzz::build_call_table();
    let mut states = ChainStates::default();
    let mut bytes_read = 0u64;

    SCRATCH.with(|cell| {
        let mut guard = cell.borrow_mut();
        let scratch = &mut *guard;

        let init_ok = unsafe {
            init_chain_states(
                &call_table,
                &config,
                &mut states,
                DEVICE_COUNT,
                SECTOR_SIZE,
                scratch.caches.as_mut_ptr() as usize,
                // No DMG scratch region: `FORMATS` never names DMG, so
                // the arm that would carve a slot out of one cannot
                // run, and reserving its ~3.25 MiB per device for an
                // unreachable arm would be the largest allocation here.
                0,
                0,
                &mut bytes_read,
            )
        };

        check_init_agrees_with_states(init_ok, formats, &states);

        // What a read is asked for, and at which offsets. Both follow
        // from the cluster sizes the chain actually ended up with, so
        // they are only knowable after init.
        let plan = ReadPlan::for_chain(formats, &states);

        // The chain the reader is driven over. `TwoChains` declares no
        // composition, so a faithful caller walks device 0 alone;
        // `Unstated` was refused, and driving the full chain anyway is
        // exactly the caller that ignores a refusal — the one invariant
        // 3 exists for.
        let chain_len = match segmentation {
            Segmentation::TwoChains => 1,
            Segmentation::OneChain | Segmentation::Unstated => DEVICE_COUNT,
        };

        // Invariants 2 and 3. A device the reader needs state for and
        // has none for is the top of this chain, so the reader reaches
        // it on the first iteration of its own loop and cannot answer
        // from anywhere else. The judgement is about the chain, not
        // about an offset, so it is made once.
        let refusal_required = needs_state(formats[0]) && states.qcow2_states[0].is_none();

        // Invariant 2 at depth. `refusal_required` covers the top of
        // the chain, where the reader meets a stateless device on its
        // first iteration and has nowhere else to answer from. A
        // stateless device *behind* the child is the harder shape, and
        // the one closest to #547: the child answers every byte it
        // holds, and only a descent reaches the device that never
        // resolved. The reader refuses when it descends into one, so a
        // composed read that reports success cannot have descended --
        // and must therefore agree with the child alone over every
        // byte, not merely over the non-zero ones invariant 4 checks.
        let stateless_behind = (1..DEVICE_COUNT)
            .any(|dev| needs_state(formats[dev]) && states.qcow2_states[dev].is_none());

        for offset in plan.offsets(body) {
            let composed = unsafe {
                read_twice(
                    &call_table,
                    &config,
                    &mut states,
                    scratch,
                    chain_len,
                    offset,
                    plan.chunk,
                    plan.full_fill_owed,
                    &mut bytes_read,
                )
            };

            if refusal_required {
                assert!(
                    !composed,
                    "a read through device 0, which has no state, reported success \
                     at virtual offset {offset}: a refusal that fills the buffer is \
                     indistinguishable from a successful read of a hole"
                );
                // Nothing below is meaningful once the read refused.
                continue;
            }

            // Invariant 4. The child alone, over the same offset. A
            // fresh staging key, because the staging buffer is keyed by
            // virtual cluster base and not by device: carrying the
            // previous read's key over would let the child-only read be
            // answered out of a cluster the *parent* decompressed, and
            // the disagreement would be the harness's, not the
            // reader's.
            // Only when both reads are owed every byte. Without that
            // guarantee a byte the composed read wrote and the
            // child-only read did not would read as a sentinel against
            // real data, and the disagreement would be about which read
            // was complete rather than about which device owns the
            // byte.
            if chain_len > 1 && plan.full_fill_owed {
                let mut staging_key = u64::MAX;
                scratch.child_only[..plan.chunk as usize].fill(SENTINEL_A);
                let child_ok = unsafe {
                    read_chain_virtual_cluster(
                        &call_table,
                        0,
                        1,
                        offset,
                        scratch.child_only.as_mut_ptr(),
                        plan.chunk,
                        SECTOR_SIZE,
                        &config,
                        &mut states,
                        scratch.compressed.as_mut_ptr(),
                        scratch.staging.as_mut_ptr(),
                        &mut staging_key,
                        None,
                        None,
                        SECTOR_SIZE as u64,
                        &mut bytes_read,
                    )
                };
                if composed && child_ok {
                    if stateless_behind {
                        check_no_descent(
                            &scratch.read_a[..plan.chunk as usize],
                            &scratch.child_only[..plan.chunk as usize],
                            offset,
                        );
                    }
                    check_child_bytes_survive(
                        &scratch.read_a[..plan.chunk as usize],
                        &scratch.child_only[..plan.chunk as usize],
                        offset,
                    );
                }
            }
        }
    });
});

/// A chain config describing the two devices and how they are grouped.
///
/// Only `format` is set per device. The chain reader consults
/// `detected_format()` and `data_device_idx`; the remaining fields
/// describe an image to the operation that reports on it, not to the
/// cluster reader, and `data_device_idx` is deliberately left at zero —
/// a non-zero one redirects cluster reads to another device, which
/// would make "the child's own bytes" a question about two devices and
/// invariant 4 unprovable.
fn build_config(formats: [ImageFormat; DEVICE_COUNT], segmentation: Segmentation) -> ChainConfig {
    let mut config = ChainConfig::new();
    config.device_count = DEVICE_COUNT as u32;
    for (slot, format) in config.devices.iter_mut().zip(formats.iter()) {
        slot.format = *format as u32;
    }
    match segmentation {
        Segmentation::OneChain => {
            config.segment_count = 1;
            config.segments[0] = ChainSegment {
                first: 0,
                count: DEVICE_COUNT as u32,
            };
        }
        Segmentation::TwoChains => {
            config.segment_count = DEVICE_COUNT as u32;
            for (i, slot) in config.segments.iter_mut().take(DEVICE_COUNT).enumerate() {
                *slot = ChainSegment {
                    first: i as u32,
                    count: 1,
                };
            }
        }
        Segmentation::Unstated => {
            // One segment covering only the child: a tiling of
            // `[0, 1)`, not of `[0, 2)`.
            config.segment_count = 1;
            config.segments[0] = ChainSegment { first: 0, count: 1 };
        }
    }
    config
}

/// The chunk size and offsets one iteration reads at, and whether a
/// successful read of that chunk owes the caller every byte of it.
struct ReadPlan {
    chunk: u64,
    full_fill_owed: bool,
}

impl ReadPlan {
    /// Derive the read plan from the cluster sizes the chain actually
    /// has.
    ///
    /// `read_chain_virtual_cluster` fills `min(chunk_size, cluster
    /// size)` bytes, where the cluster size is that of whichever device
    /// *serves* the span — the child for a cluster it holds, a device
    /// behind it for one it does not. So the chunk is taken as the
    /// smallest cluster size in the chain, which is the only choice
    /// under which every device that could answer owes the whole
    /// buffer. A raw device places no bound: it fills any chunk.
    ///
    /// The one remaining way a successful read can legitimately leave
    /// the buffer short is an extended-L2 device, whose arm walks
    /// subclusters of `cluster / 32` and covers `chunk / subcluster` of
    /// them — none at all for a chunk smaller than one subcluster. That
    /// cannot be arranged away here, because it is a property of a
    /// device the fuzzer built, so it is detected instead and the
    /// fill check is skipped for that chain. Dropping the whole
    /// iteration would be worse: the other three invariants still hold
    /// and these are exactly the chains with the most interesting
    /// bitmaps.
    fn for_chain(formats: [ImageFormat; DEVICE_COUNT], states: &ChainStates) -> Self {
        let mut smallest_cluster: Option<u64> = None;
        let mut largest_extended = 0u64;
        for dev in 0..DEVICE_COUNT {
            if !needs_state(formats[dev]) {
                continue;
            }
            if let Some(state) = states.qcow2_states[dev].as_ref() {
                let cluster = state.cluster_size;
                smallest_cluster = Some(smallest_cluster.map_or(cluster, |c| c.min(cluster)));
                if state.extended_l2 {
                    largest_extended = largest_extended.max(cluster);
                }
            }
        }
        // `Qcow2State::init` accepts cluster_bits 9..=21, so a cluster
        // is a power of two of at least one sector, and so is
        // `MAX_CHUNK`. The chunk is therefore a power of two dividing
        // every cluster in the chain, which is what makes a
        // chunk-aligned offset cluster-aligned enough for the
        // subcluster walk to stay inside its 32-bit bitmap.
        //
        // No initialised cluster size at all means nothing in the chain
        // reads in clusters, and one sector is the chunk to ask for.
        // Most of a random corpus lands here, and asking those chains
        // for 64 KiB would spend 128 mock sector reads per call
        // reaching the same two branches a single sector reaches.
        let chunk = smallest_cluster
            .map_or(SECTOR_SIZE as u64, |cluster| cluster.min(MAX_CHUNK as u64))
            .max(SECTOR_SIZE as u64);
        Self {
            chunk,
            full_fill_owed: largest_extended <= chunk * 32,
        }
    }

    /// Offsets to read at: the start of the image, two fixed offsets
    /// deeper into it, and one the fuzzer chooses, all rounded down to
    /// a whole chunk.
    ///
    /// Chunk-aligned because that is how the reader is reached in
    /// practice — `read_chain_virtual_range` steps in whole chunks —
    /// and because an offset part way into a cluster shifts the
    /// subcluster walk's starting index, which is what makes the
    /// 32-subcluster bitmap the bound the walk has to respect rather
    /// than one it trivially does.
    fn offsets(&self, body: &[u8]) -> [u64; 4] {
        let align = |offset: u64| offset & !(self.chunk - 1);
        let dynamic = instar_fuzz::extract_fuzz_offset(body).unwrap_or(0);
        [
            0,
            align(self.chunk * 3),
            align(1 << 20),
            // Masked, not truncated: a wild offset is a cheap `None`
            // from `cluster_lookup` and explores nothing, whereas one
            // inside a plausible 4 GiB image reaches the L1/L2 walk.
            align(dynamic & 0xFFFF_FFFF),
        ]
    }
}

/// Invariant 2, at init time: a success that left a device the reader
/// needs state for without any is a device that silently failed, and
/// every read descending into it would refuse.
fn check_init_agrees_with_states(
    init_ok: bool,
    formats: [ImageFormat; DEVICE_COUNT],
    states: &ChainStates,
) {
    if !init_ok {
        return;
    }
    for dev in 0..DEVICE_COUNT {
        if needs_state(formats[dev]) {
            assert!(
                states.qcow2_states[dev].is_some(),
                "init_chain_states reported success with device {dev} uninitialised"
            );
        }
    }
}

/// Read the same span twice, from two different prefills, and check
/// invariant 1.
///
/// Two prefills rather than one, because a target cannot know what the
/// right bytes are: any single sentinel is a byte value the image could
/// legitimately contain, so a surviving sentinel proves nothing. A byte
/// the reader never wrote keeps whichever sentinel it started from, so
/// it is the one thing that differs between the two buffers — and a
/// byte it did write is identical in both unless the reader is not a
/// function of its inputs. The same `chain_states` and staging key are
/// carried across the pair deliberately: the second read runs against
/// the caches the first one warmed, which is how a cache that answers
/// for the wrong cluster would show up.
#[allow(clippy::too_many_arguments)]
unsafe fn read_twice(
    call_table: &shared::CallTable,
    config: &ChainConfig,
    states: &mut ChainStates,
    scratch: &mut Scratch,
    chain_len: usize,
    offset: u64,
    chunk: u64,
    full_fill_owed: bool,
    bytes_read: &mut u64,
) -> bool {
    let len = chunk as usize;
    let mut staging_key = u64::MAX;

    scratch.read_a[..len].fill(SENTINEL_A);
    let first = read_once(
        call_table,
        config,
        states,
        scratch.read_a.as_mut_ptr(),
        scratch.compressed.as_mut_ptr(),
        scratch.staging.as_mut_ptr(),
        &mut staging_key,
        chain_len,
        offset,
        chunk,
        bytes_read,
    );

    scratch.read_b[..len].fill(SENTINEL_B);
    let second = read_once(
        call_table,
        config,
        states,
        scratch.read_b.as_mut_ptr(),
        scratch.compressed.as_mut_ptr(),
        scratch.staging.as_mut_ptr(),
        &mut staging_key,
        chain_len,
        offset,
        chunk,
        bytes_read,
    );

    assert_eq!(
        first, second,
        "a read of {chunk} bytes at virtual offset {offset} succeeded and then \
         failed over the same chain"
    );
    if !first || !full_fill_owed {
        return first;
    }

    for i in 0..len {
        let (a, b) = (scratch.read_a[i], scratch.read_b[i]);
        assert_eq!(
            a, b,
            "a successful read of {chunk} bytes at virtual offset {offset} left \
             byte {i} unwritten: it kept whichever sentinel the buffer was \
             prefilled with ({a:#04x} / {b:#04x}), so a caller would be handed \
             whatever its buffer already contained"
        );
    }
    true
}

/// One call into the chain reader, with the arguments this target holds
/// fixed.
///
/// No AES or LUKS key: both features are off in this build, so passing
/// a key would exercise nothing, and passing `None` is what every
/// unencrypted read does anyway.
#[allow(clippy::too_many_arguments)]
unsafe fn read_once(
    call_table: &shared::CallTable,
    config: &ChainConfig,
    states: &mut ChainStates,
    buf: *mut u8,
    compressed: *mut u8,
    staging: *mut u8,
    staging_key: &mut u64,
    chain_len: usize,
    offset: u64,
    chunk: u64,
    bytes_read: &mut u64,
) -> bool {
    read_chain_virtual_cluster(
        call_table,
        0,
        chain_len,
        offset,
        buf,
        chunk,
        SECTOR_SIZE,
        config,
        states,
        compressed,
        staging,
        staging_key,
        None,
        None,
        SECTOR_SIZE as u64,
        bytes_read,
    )
}

/// Invariant 2, at a device behind the child: a composed read that
/// succeeded while a device behind the child has no state never
/// descended, so it produced exactly what the child alone produced.
///
/// Stronger than [`check_child_bytes_survive`], which permits the
/// chain to supply a byte the child alone read as zero -- the very
/// thing a descent into a stateless device would have to do. It is
/// sound only because both buffers are owed every byte, which is why
/// the caller checks `full_fill_owed` first.
fn check_no_descent(composed: &[u8], child_only: &[u8], offset: u64) {
    if let Some((i, (&c, &own))) = composed
        .iter()
        .zip(child_only.iter())
        .enumerate()
        .find(|(_, (&c, &own))| c != own)
    {
        panic!(
            "byte {i} of the span at virtual offset {offset} reads as {own:#04x} \
             from the child alone but {c:#04x} through the chain, while a device \
             behind the child has no state: the read either descended into a \
             device it cannot look a cluster up in, or reported success for a \
             span it did not serve"
        );
    }
}

/// Invariant 4: a device behind the child never overrides a byte the
/// child holds.
///
/// Only the non-zero bytes of the child-only read are checked, and that
/// is the whole of what is provable from the outside: a zero there is
/// either data the child holds or the zero-fill the reader writes at the
/// bottom of a chain, and the two are indistinguishable by design — a
/// hole is defined to read as zeros. Every non-zero byte, though, came
/// from a cluster the child itself holds, and the composed read serves
/// those from the child whatever is behind it. A disagreement means the
/// chain walk descended for a span the child had already answered for,
/// which is a parent's data presented as the child's.
fn check_child_bytes_survive(composed: &[u8], child_only: &[u8], offset: u64) {
    for (i, (&c, &own)) in composed.iter().zip(child_only.iter()).enumerate() {
        if own != 0 {
            assert_eq!(
                c, own,
                "byte {i} of the span at virtual offset {offset} reads as \
                 {own:#04x} from the child alone but {c:#04x} through the \
                 chain: a device behind the child overrode a byte the child \
                 holds"
            );
        }
    }
}
