//! Coverage-guided fuzzing for the dd read primitives
//! `qcow2::read_raw_sectors` and `qcow2::read_cluster_sectors`.
//!
//! Both walk a (possibly sub-sector / past-capacity) byte window over
//! a device, reading whole sectors through a `CallTable` and copying
//! only the requested bytes. The phase-3 bugs were partial-tail drops
//! and multi-sector mis-offsets, and the risk surface is OOB writes
//! past the requested range. This target drives both primitives with
//! a fuzzer-chosen `(virtual_offset, length, sector_size, capacity)`
//! against a deterministic position-dependent device and checks every
//! returned byte.
//!
//! The device pattern is `byte(o) = (o % 251) as u8` (251 is prime
//! and < 256, so the period is coprime with any power-of-two sector
//! size — a misaligned copy cannot accidentally match). The mock
//! `read_input_sector` is an `extern "C" fn` and can only close over
//! `'static` state, so the per-iteration capacity lives in a global
//! guarded by a mutex (mirrors the phase-5 `READ_TEST_*` fixture and
//! the qcow2 streaming fixture).
//!
//! Invariants asserted (libFuzzer's oracle is panic):
//!
//!   read_raw_sectors (zero-fills past capacity):
//!     1. Returns true (the mock always serves in-capacity sectors).
//!     2. In-range bytes equal the pattern; bytes at/after capacity
//!        are zero.
//!     3. The sentinel bytes past `length` are untouched (no OOB
//!        write past the requested range).
//!     4. `bytes_read` advanced by a whole number of sectors.
//!
//!   read_cluster_sectors (has NO capacity arg — returns false the
//!   moment it touches a past-capacity sector, never zero-fills):
//!     5. When the whole cluster window lies within capacity, returns
//!        true and every byte equals the pattern, with the sentinel
//!        tail untouched and `bytes_read` a sector multiple.
//!
//! Buffers are bounded (length <= 1 MiB, sector_size <= 65536) so the
//! fuzzer cannot OOM.

#![no_main]
use libfuzzer_sys::fuzz_target;

use std::sync::Mutex;

/// Largest read window the harness will request, in bytes. Keeps the
/// per-iteration buffer bounded so libFuzzer can't drive an OOM.
const MAX_LEN: u64 = 1 << 20; // 1 MiB

/// Sentinel the output buffer is pre-filled with; any sentinel byte
/// found inside the requested range, or any non-sentinel byte past
/// it, is a bug.
const SENTINEL: u8 = 0xAA;

/// Deterministic position-dependent device byte. Must match
/// `pattern_sector` below and the phase-5 `read_test_pattern_byte`.
fn pattern_byte(o: u64) -> u8 {
    (o % 251) as u8
}

/// Device capacity in sectors served by the mock callback, set per
/// iteration under `CAP_LOCK`. The callback is `extern "C"` and cannot
/// capture, hence the `'static` global + lock.
static mut CAP_SECTORS: u64 = 0;
static CAP_LOCK: Mutex<()> = Mutex::new(());

/// Mock `read_input_sector`: fills `out_buf` with the device pattern
/// for the requested sector, or returns false at/past capacity (so a
/// caller that reads past the end without zero-filling itself surfaces
/// as a failure rather than fabricated bytes).
unsafe extern "C" fn pattern_sector(
    _device_idx: u32,
    sector: u64,
    out_buf: *mut u8,
    sector_size: usize,
) -> bool {
    if sector >= CAP_SECTORS {
        return false;
    }
    let base = sector.wrapping_mul(sector_size as u64);
    for i in 0..sector_size {
        *out_buf.add(i) = pattern_byte(base.wrapping_add(i as u64));
    }
    true
}

/// Reference bytes a correct read of `[offset, offset+len)` must
/// produce: the pattern within capacity, zero past the device end.
fn expected(offset: u64, len: usize, capacity_bytes: u64) -> Vec<u8> {
    (0..len as u64)
        .map(|i| {
            let abs = offset.wrapping_add(i);
            if abs < capacity_bytes {
                pattern_byte(abs)
            } else {
                0
            }
        })
        .collect()
}

fuzz_target!(|data: &[u8]| {
    // 8 (offset) + 8 (length) + 1 (sector-size selector) + 8 (capacity).
    if data.len() < 25 {
        return;
    }

    let raw_offset = u64::from_le_bytes(data[0..8].try_into().unwrap());
    let raw_length = u64::from_le_bytes(data[8..16].try_into().unwrap());
    let sector_size: usize = if data[16] & 1 != 0 { 4096 } else { 512 };
    let ssz = sector_size as u64;

    // Bound the window so the buffer stays small. Floor at 1 byte:
    // a zero-length read is outside the primitives' usage domain (the
    // convert/dd loop never issues an empty read), and the
    // read_raw_sectors fast path deliberately reads one whole sector
    // to guarantee progress when `0 < chunk_size < sector_size`, which
    // for chunk_size==0 would (legitimately, per that contract) write
    // a full sector into a buffer whose requested range is empty —
    // tripping the past-range sentinel check on an input that can
    // never occur in practice. Excluding it keeps the past-range
    // invariant strict for every real (>=1 byte) read rather than
    // weakening it.
    let length = std::cmp::max(1, raw_length % (MAX_LEN + 1));
    // Bound the offset to a few device-lengths so reads land both
    // inside and past capacity. MAX_LEN * 4 keeps abs offsets well
    // within u64 with no overflow concerns.
    let virtual_offset = raw_offset % (MAX_LEN * 4);

    // Capacity in sectors, bounded so capacity_bytes stays small.
    let max_cap_sectors = (MAX_LEN * 4) / ssz + 2;
    let raw_cap = u64::from_le_bytes(data[17..25].try_into().unwrap());
    let capacity_sectors = raw_cap % (max_cap_sectors + 1);
    let capacity_bytes = capacity_sectors.saturating_mul(ssz);

    // Buffer: per the safety contract, at least max(length, ssz) bytes.
    // Pad with 64 sentinel bytes to catch writes past the requested range.
    let buf_len = std::cmp::max(length as usize, sector_size) + 64;

    let _guard = CAP_LOCK.lock().unwrap();
    unsafe {
        CAP_SECTORS = capacity_sectors;
    }

    // Base the table on the shared fuzz mock and swap in the pattern
    // reader (every other callback is an inert stub).
    let mut call_table = instar_fuzz::build_call_table();
    call_table.read_input_sector = pattern_sector;

    // ---- read_raw_sectors: sub-sector + past-capacity, zero-fills ----
    {
        let mut buf = vec![SENTINEL; buf_len];
        let mut bytes_read: u64 = 0;
        let ok = unsafe {
            qcow2::read_raw_sectors(
                &call_table,
                0,
                virtual_offset,
                buf.as_mut_ptr(),
                length,
                sector_size,
                capacity_sectors,
                &mut bytes_read,
            )
        };
        // The mock serves every sector below capacity, and the primitive
        // zero-fills the rest, so it must succeed.
        assert!(ok, "read_raw_sectors returned false (offset={virtual_offset} len={length})");

        let want = expected(virtual_offset, length as usize, capacity_bytes);
        assert_eq!(
            &buf[..length as usize],
            &want[..],
            "read_raw_sectors bytes mismatch at offset={virtual_offset} len={length} \
             ssz={sector_size} cap_sectors={capacity_sectors}"
        );
        assert!(
            buf[length as usize..].iter().all(|&b| b == SENTINEL),
            "read_raw_sectors wrote past the requested range \
             (offset={virtual_offset} len={length})"
        );
        assert!(
            bytes_read.is_multiple_of(ssz),
            "read_raw_sectors bytes_read {bytes_read} not a sector multiple (ssz={ssz})"
        );
    }

    // ---- read_cluster_sectors: no capacity arg, must stay in-range ----
    // It returns false the instant it touches a past-capacity sector
    // and never zero-fills, so only drive it over a window the device
    // fully covers. Derive a cluster window clamped to capacity.
    if capacity_bytes >= ssz {
        // cluster_size: a fuzzer-derived length in [1, MAX_LEN], also
        // clamped so the window ends within capacity.
        let cluster_size = std::cmp::max(1, length).min(MAX_LEN);
        // host_offset clamped so host_offset + cluster_size <= capacity_bytes.
        let max_host_offset = capacity_bytes - cluster_size.min(capacity_bytes);
        let host_offset = if max_host_offset == 0 {
            0
        } else {
            virtual_offset % (max_host_offset + 1)
        };
        // Only proceed when the whole window is genuinely in-range.
        if host_offset.saturating_add(cluster_size) <= capacity_bytes {
            let cbuf_len = std::cmp::max(cluster_size as usize, sector_size) + 64;
            let mut buf = vec![SENTINEL; cbuf_len];
            let mut bytes_read: u64 = 0;
            let ok = unsafe {
                qcow2::read_cluster_sectors(
                    &call_table,
                    0,
                    host_offset,
                    buf.as_mut_ptr(),
                    cluster_size,
                    sector_size,
                    &mut bytes_read,
                )
            };
            assert!(
                ok,
                "read_cluster_sectors returned false on in-range window \
                 (host_offset={host_offset} cluster_size={cluster_size} \
                 cap_bytes={capacity_bytes})"
            );
            let want = expected(host_offset, cluster_size as usize, capacity_bytes);
            assert_eq!(
                &buf[..cluster_size as usize],
                &want[..],
                "read_cluster_sectors bytes mismatch at host_offset={host_offset} \
                 cluster_size={cluster_size} ssz={sector_size}"
            );
            assert!(
                buf[cluster_size as usize..].iter().all(|&b| b == SENTINEL),
                "read_cluster_sectors wrote past the requested range \
                 (host_offset={host_offset} cluster_size={cluster_size})"
            );
            assert!(
                bytes_read.is_multiple_of(ssz),
                "read_cluster_sectors bytes_read {bytes_read} not a sector multiple"
            );
        }
    }
});
