//! Directory-level byte helpers for the qcow2 bitmaps directory.
//!
//! Templated on `snapshot::table`, these functions locate, build,
//! and rewrite bitmap directory entries and serialize the bitmaps
//! extension body, reusing the Phase 1 entry codec in
//! [`qcow2::bitmap`]. They are `no_std`, panic-free, and
//! bounds-checked. Implemented in phase 3b.
