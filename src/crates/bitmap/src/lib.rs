//! Pure planner crate for qcow2 persistent dirty bitmap mutators.
//!
//! This crate is the correctness core of the `bitmap` subcommand
//! (master plan phase 3). It computes qcow2 persistent dirty bitmap
//! mutations as pure functions over caller-staged big-endian byte
//! slices (directory bytes, refcount-block bytes) plus scalar
//! geometry, mirroring the in-place slice-mutator convention of
//! `snapshot` and `check`. It performs no I/O and owns no
//! allocator: the Phase 4 guest op stages on-disk structures into
//! scratch, calls these functions to mutate the buffers, and writes
//! them back.
//!
//! The crate reuses `snapshot::qcow2` for cluster allocation and
//! refcount arithmetic (16-bit refcount width only, no refcount-
//! table growth), and the Phase 1 `qcow2::bitmap` primitives for
//! directory-entry and bitmap-table codecs.
//!
//! - [`directory`] — directory-level byte helpers (find, build,
//!   replace, extension-body serialization).
//! - [`action`] — per-action validate-then-mutate functions.
//!
//! The crate is `no_std` and panic-free.

#![no_std]

#[cfg(test)]
extern crate std;

pub mod action;
pub mod directory;

use shared::BitmapResult;

/// Errors returned by the bitmap mutator primitives.
///
/// Each variant maps to a [`BitmapResult::ERROR_*`] wire code via
/// the [`From<BitmapError> for u32`] impl below, mirroring
/// `snapshot::SnapshotError`. The phase 2 ABI froze codes 0..=17;
/// phase 3 appended [`BitmapResult::ERROR_UNSUPPORTED_REFCOUNT_WIDTH`]
/// (18) for the 16-bit-only allocator constraint inherited from
/// `snapshot::qcow2`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BitmapError {
    /// Input is not qcow2 (v1 is qcow2-only). Maps to
    /// [`BitmapResult::ERROR_UNSUPPORTED_FORMAT`] (1).
    UnsupportedFormat,
    /// qcow2 v2 cannot store dirty bitmaps. Maps to
    /// [`BitmapResult::ERROR_UNSUPPORTED_VERSION`] (2).
    UnsupportedVersion,
    /// A format-specific parser failed. Maps to
    /// [`BitmapResult::ERROR_PARSE_FAILED`] (3).
    ParseFailed,
    /// The host-probed cross-check disagreed with the guest's
    /// re-read of the header. Maps to
    /// [`BitmapResult::ERROR_HEADER_MISMATCH`] (4).
    HeaderMismatch,
    /// A remove/clear/enable/disable/merge named a bitmap that
    /// does not exist. Maps to
    /// [`BitmapResult::ERROR_BITMAP_NOT_FOUND`] (5).
    BitmapNotFound,
    /// `--add` with an already-existing name. Maps to
    /// [`BitmapResult::ERROR_BITMAP_EXISTS`] (6).
    BitmapExists,
    /// An `in_use`/inconsistent bitmap was targeted by an action
    /// other than `--remove`. Maps to
    /// [`BitmapResult::ERROR_BITMAP_IN_USE`] (7).
    BitmapInUse,
    /// Name longer than 1023 bytes. Maps to
    /// [`BitmapResult::ERROR_NAME_TOO_LONG`] (8).
    NameTooLong,
    /// Granularity bits outside `9..=31`. Maps to
    /// [`BitmapResult::ERROR_GRANULARITY_RANGE`] (9).
    GranularityRange,
    /// Would exceed 65535 bitmaps. Maps to
    /// [`BitmapResult::ERROR_TOO_MANY_BITMAPS`] (10).
    TooManyBitmaps,
    /// Cluster allocation failed / bitmap too large for the
    /// granularity (also `RefcountExhausted`, since v1 does not
    /// grow the refcount table). Maps to
    /// [`BitmapResult::ERROR_NO_SPACE`] (11).
    NoSpace,
    /// A device write back to the image failed. Maps to
    /// [`BitmapResult::ERROR_WRITE_FAILED`] (12).
    WriteFailed,
    /// A device read from the image failed. Maps to
    /// [`BitmapResult::ERROR_READ_FAILED`] (13).
    ReadFailed,
    /// Guest scratch buffer was too small for the requested
    /// layout. Maps to
    /// [`BitmapResult::ERROR_SCRATCH_TOO_SMALL`] (14).
    ScratchTooSmall,
    /// Internal size or offset computation overflowed. Maps to
    /// [`BitmapResult::ERROR_INTERNAL_OVERFLOW`] (15).
    InternalOverflow,
    /// A `--merge` source bitmap does not exist. Maps to
    /// [`BitmapResult::ERROR_MERGE_SOURCE_NOT_FOUND`] (16).
    MergeSourceNotFound,
    /// A deferred / unimplemented action path (e.g. cross-file
    /// `--merge -b`). Maps to
    /// [`BitmapResult::ERROR_UNSUPPORTED_ACTION`] (17).
    UnsupportedAction,
    /// qcow2 refcount width != 16; v1 reuses the 16-bit-only
    /// allocator and refuses other widths. Maps to
    /// [`BitmapResult::ERROR_UNSUPPORTED_REFCOUNT_WIDTH`] (18).
    UnsupportedRefcountWidth,
}

impl From<BitmapError> for u32 {
    fn from(err: BitmapError) -> u32 {
        match err {
            BitmapError::UnsupportedFormat => BitmapResult::ERROR_UNSUPPORTED_FORMAT,
            BitmapError::UnsupportedVersion => BitmapResult::ERROR_UNSUPPORTED_VERSION,
            BitmapError::ParseFailed => BitmapResult::ERROR_PARSE_FAILED,
            BitmapError::HeaderMismatch => BitmapResult::ERROR_HEADER_MISMATCH,
            BitmapError::BitmapNotFound => BitmapResult::ERROR_BITMAP_NOT_FOUND,
            BitmapError::BitmapExists => BitmapResult::ERROR_BITMAP_EXISTS,
            BitmapError::BitmapInUse => BitmapResult::ERROR_BITMAP_IN_USE,
            BitmapError::NameTooLong => BitmapResult::ERROR_NAME_TOO_LONG,
            BitmapError::GranularityRange => BitmapResult::ERROR_GRANULARITY_RANGE,
            BitmapError::TooManyBitmaps => BitmapResult::ERROR_TOO_MANY_BITMAPS,
            BitmapError::NoSpace => BitmapResult::ERROR_NO_SPACE,
            BitmapError::WriteFailed => BitmapResult::ERROR_WRITE_FAILED,
            BitmapError::ReadFailed => BitmapResult::ERROR_READ_FAILED,
            BitmapError::ScratchTooSmall => BitmapResult::ERROR_SCRATCH_TOO_SMALL,
            BitmapError::InternalOverflow => BitmapResult::ERROR_INTERNAL_OVERFLOW,
            BitmapError::MergeSourceNotFound => BitmapResult::ERROR_MERGE_SOURCE_NOT_FOUND,
            BitmapError::UnsupportedAction => BitmapResult::ERROR_UNSUPPORTED_ACTION,
            BitmapError::UnsupportedRefcountWidth => BitmapResult::ERROR_UNSUPPORTED_REFCOUNT_WIDTH,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_to_wire_code_mapping() {
        // Each variant maps to its exact intended ERROR_* constant.
        assert_eq!(
            u32::from(BitmapError::UnsupportedFormat),
            BitmapResult::ERROR_UNSUPPORTED_FORMAT
        );
        assert_eq!(
            u32::from(BitmapError::UnsupportedVersion),
            BitmapResult::ERROR_UNSUPPORTED_VERSION
        );
        assert_eq!(
            u32::from(BitmapError::ParseFailed),
            BitmapResult::ERROR_PARSE_FAILED
        );
        assert_eq!(
            u32::from(BitmapError::HeaderMismatch),
            BitmapResult::ERROR_HEADER_MISMATCH
        );
        assert_eq!(
            u32::from(BitmapError::BitmapNotFound),
            BitmapResult::ERROR_BITMAP_NOT_FOUND
        );
        assert_eq!(
            u32::from(BitmapError::BitmapExists),
            BitmapResult::ERROR_BITMAP_EXISTS
        );
        assert_eq!(
            u32::from(BitmapError::BitmapInUse),
            BitmapResult::ERROR_BITMAP_IN_USE
        );
        assert_eq!(
            u32::from(BitmapError::NameTooLong),
            BitmapResult::ERROR_NAME_TOO_LONG
        );
        assert_eq!(
            u32::from(BitmapError::GranularityRange),
            BitmapResult::ERROR_GRANULARITY_RANGE
        );
        assert_eq!(
            u32::from(BitmapError::TooManyBitmaps),
            BitmapResult::ERROR_TOO_MANY_BITMAPS
        );
        assert_eq!(
            u32::from(BitmapError::NoSpace),
            BitmapResult::ERROR_NO_SPACE
        );
        assert_eq!(
            u32::from(BitmapError::WriteFailed),
            BitmapResult::ERROR_WRITE_FAILED
        );
        assert_eq!(
            u32::from(BitmapError::ReadFailed),
            BitmapResult::ERROR_READ_FAILED
        );
        assert_eq!(
            u32::from(BitmapError::ScratchTooSmall),
            BitmapResult::ERROR_SCRATCH_TOO_SMALL
        );
        assert_eq!(
            u32::from(BitmapError::InternalOverflow),
            BitmapResult::ERROR_INTERNAL_OVERFLOW
        );
        assert_eq!(
            u32::from(BitmapError::MergeSourceNotFound),
            BitmapResult::ERROR_MERGE_SOURCE_NOT_FOUND
        );
        assert_eq!(
            u32::from(BitmapError::UnsupportedAction),
            BitmapResult::ERROR_UNSUPPORTED_ACTION
        );
        assert_eq!(
            u32::from(BitmapError::UnsupportedRefcountWidth),
            BitmapResult::ERROR_UNSUPPORTED_REFCOUNT_WIDTH
        );
    }

    #[test]
    fn error_to_wire_code_distinct() {
        // Every BitmapError variant maps to a distinct wire code.
        let codes = [
            u32::from(BitmapError::UnsupportedFormat),
            u32::from(BitmapError::UnsupportedVersion),
            u32::from(BitmapError::ParseFailed),
            u32::from(BitmapError::HeaderMismatch),
            u32::from(BitmapError::BitmapNotFound),
            u32::from(BitmapError::BitmapExists),
            u32::from(BitmapError::BitmapInUse),
            u32::from(BitmapError::NameTooLong),
            u32::from(BitmapError::GranularityRange),
            u32::from(BitmapError::TooManyBitmaps),
            u32::from(BitmapError::NoSpace),
            u32::from(BitmapError::WriteFailed),
            u32::from(BitmapError::ReadFailed),
            u32::from(BitmapError::ScratchTooSmall),
            u32::from(BitmapError::InternalOverflow),
            u32::from(BitmapError::MergeSourceNotFound),
            u32::from(BitmapError::UnsupportedAction),
            u32::from(BitmapError::UnsupportedRefcountWidth),
        ];
        for i in 0..codes.len() {
            for j in (i + 1)..codes.len() {
                assert_ne!(codes[i], codes[j], "codes {i} and {j} alias");
            }
        }
    }
}
