//! Overlap-detection bitmap for structural validation.
//!
//! Provides a 1-bit-per-item bitmap backed by guest scratch memory,
//! used by the check operation to detect overlapping clusters (QCOW2)
//! or grains (VMDK). Each bit tracks whether a host allocation unit
//! has already been referenced; setting an already-set bit indicates
//! an overlap error.

use crate::{SCRATCH_MEM_BASE, SCRATCH_MEM_SIZE};

/// Result of a [`BitmapContext::set`] operation.
pub enum BitmapSetResult {
    /// Bit was not previously set (no overlap).
    NewBit,
    /// Bit was already set — overlap detected.
    AlreadySet,
    /// Index exceeds bitmap capacity; overlap status unknown.
    BeyondCapacity,
}

/// A 1-bit-per-item bitmap backed by scratch memory.
///
/// Bundles the bitmap pointer, allocated size, and tracking capability
/// so callers don't need to thread three separate values through every
/// call site.
pub struct BitmapContext {
    pub ptr: *mut u8,
    pub size: usize,
    pub can_track: bool,
}

impl BitmapContext {
    /// Allocate and zero a bitmap in scratch memory for `total_items`.
    ///
    /// Each item gets one bit. The bitmap is capped at `SCRATCH_MEM_SIZE`
    /// bytes; if `total_items` exceeds what fits, `can_track` is `false`
    /// and overlap detection is best-effort (items beyond the bitmap
    /// capacity return `BeyondCapacity`).
    ///
    /// # Safety
    ///
    /// Scratch memory at `SCRATCH_MEM_BASE` must be valid and not in
    /// use by other code for the lifetime of this `BitmapContext`.
    pub unsafe fn init_in_scratch(total_items: u64) -> Self {
        let ptr = SCRATCH_MEM_BASE as *mut u8;
        let needed_bytes = ((total_items + 7) / 8) as usize;
        let size = core::cmp::min(needed_bytes, SCRATCH_MEM_SIZE);
        core::ptr::write_bytes(ptr, 0, size);
        let max_trackable = (size as u64) * 8;
        let can_track = total_items <= max_trackable;
        Self {
            ptr,
            size,
            can_track,
        }
    }

    /// Set a bit in the bitmap, returning whether it was already set.
    ///
    /// # Safety
    ///
    /// The bitmap pointer must be valid for `self.size` bytes.
    pub unsafe fn set(&self, idx: u64) -> BitmapSetResult {
        let byte_idx = (idx / 8) as usize;
        let bit_mask = 1u8 << (idx % 8) as u8;
        if byte_idx >= self.size {
            return BitmapSetResult::BeyondCapacity;
        }
        let byte_ptr = self.ptr.add(byte_idx);
        let was_set = (*byte_ptr & bit_mask) != 0;
        *byte_ptr |= bit_mask;
        if was_set {
            BitmapSetResult::AlreadySet
        } else {
            BitmapSetResult::NewBit
        }
    }

    /// Test whether a bit is set in the bitmap.
    ///
    /// Returns `false` for indices beyond bitmap capacity.
    ///
    /// # Safety
    ///
    /// The bitmap pointer must be valid for `self.size` bytes.
    pub unsafe fn test(&self, idx: u64) -> bool {
        let byte_idx = (idx / 8) as usize;
        let bit_mask = 1u8 << (idx % 8) as u8;
        if byte_idx >= self.size {
            return false;
        }
        (*self.ptr.add(byte_idx) & bit_mask) != 0
    }
}
