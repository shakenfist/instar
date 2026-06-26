//! Compute the `dd` input byte-window and output virtual size.
//!
//! Given the `dd` operands (`bs`, `count`, `skip`) and the input
//! image's virtual size, [`compute_dd_window`] returns a
//! [`DdWindow`] describing the absolute input byte-window
//! (`start`/`end`) and the resulting output virtual size
//! (`out_vsize`).
//!
//! This crate is `no_std` and performs no I/O — it is plain `u64`
//! arithmetic. It owns the exact upstream `qemu-img dd` window
//! semantics (count clamps DOWN only, skip past EOF yields empty
//! output, never an error) so the math can be unit-tested and
//! fuzzed independently of the vmm binary.

#![no_std]

/// The input byte-window and output virtual size derived from the `dd`
/// operands and the input's virtual size.
pub struct DdWindow {
    /// Absolute window start byte offset (`window_start`).
    pub start: u64,
    /// Absolute window end byte offset (`window_end`).
    pub end: u64,
    /// Output virtual size (`out_vsize`), `end - start` saturating.
    pub out_vsize: u64,
}

/// Compute the `dd` input window and output size.
///
/// Exact upstream semantics — there is NO bounds rejection: out-of-range
/// windows yield empty output, never an error.
///
/// - `copy_len = count.map(|c| c*bs).min(virtual_size)` (count clamps DOWN
///   only; overflow saturates then clamps); `None` ⇒ virtual_size.
/// - `start = skip*bs` (saturating).
/// - `end = copy_len`; `out_vsize = end - start` (saturating).
///
/// So skip past EOF ⇒ start>=end ⇒ out_vsize 0; count=0 ⇒ out_vsize 0.
pub fn compute_dd_window(virtual_size: u64, bs: u64, count: Option<u64>, skip: u64) -> DdWindow {
    let copy_len = match count {
        Some(c) => c.saturating_mul(bs).min(virtual_size),
        None => virtual_size,
    };
    let start = skip.saturating_mul(bs);
    let end = copy_len;
    let out_vsize = end.saturating_sub(start);
    DdWindow {
        start,
        end,
        out_vsize,
    }
}

#[cfg(test)]
mod tests {
    //! Unit tests for `compute_dd_window`.
    //!
    //! Pure `u64` arithmetic — host-only, no KVM or testdata required.
    use super::*;

    #[test]
    fn whole_image_window() {
        let w = compute_dd_window(4 * 1024 * 1024, 512, None, 0);
        assert_eq!(w.start, 0);
        assert_eq!(w.end, 4 * 1024 * 1024);
        assert_eq!(w.out_vsize, 4 * 1024 * 1024);
    }

    #[test]
    fn count_clamps_down_to_virtual_size() {
        // count * bs > virtual_size ⇒ end = virtual_size.
        let vsize = 4 * 1024 * 1024;
        let w = compute_dd_window(vsize, 1024 * 1024, Some(100), 0);
        assert_eq!(w.end, vsize);
        assert_eq!(w.out_vsize, vsize);
    }

    #[test]
    fn count_smaller_than_image() {
        // count * bs < virtual_size ⇒ end = count * bs.
        let vsize = 4 * 1024 * 1024;
        let w = compute_dd_window(vsize, 1024 * 1024, Some(2), 0);
        assert_eq!(w.start, 0);
        assert_eq!(w.end, 2 * 1024 * 1024);
        assert_eq!(w.out_vsize, 2 * 1024 * 1024);
    }

    #[test]
    fn count_zero_yields_empty() {
        let w = compute_dd_window(4 * 1024 * 1024, 512, Some(0), 0);
        assert_eq!(w.end, 0);
        assert_eq!(w.out_vsize, 0);
    }

    #[test]
    fn skip_within_image() {
        let vsize = 4 * 1024 * 1024;
        let w = compute_dd_window(vsize, 1024 * 1024, None, 1);
        assert_eq!(w.start, 1024 * 1024);
        assert_eq!(w.end, vsize);
        assert_eq!(w.out_vsize, vsize - 1024 * 1024);
    }

    #[test]
    fn skip_past_eof_yields_empty() {
        let vsize = 4 * 1024 * 1024;
        // skip beyond the image ⇒ start >= end ⇒ out_vsize 0 (no error).
        let w = compute_dd_window(vsize, 1024 * 1024, None, 100);
        assert!(w.start >= w.end);
        assert_eq!(w.out_vsize, 0);
    }

    #[test]
    fn count_overflow_saturates() {
        // Huge count * bs must saturate, then clamp to virtual_size.
        let vsize = 1024;
        let w = compute_dd_window(vsize, u64::MAX, Some(u64::MAX), 0);
        assert_eq!(w.end, vsize);
        assert_eq!(w.out_vsize, vsize);
    }

    #[test]
    fn skip_overflow_saturates() {
        // Huge skip * bs must saturate without panicking; out_vsize 0.
        let w = compute_dd_window(1024, u64::MAX, None, u64::MAX);
        assert_eq!(w.start, u64::MAX);
        assert_eq!(w.out_vsize, 0);
    }
}
