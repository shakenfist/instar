//! Per-action logic for the bitmap subcommand.
//!
//! Each action (`add`, `remove`, `clear`, `enable`, `disable`, and
//! same-image `merge`) is a pure validate-then-mutate function over
//! caller-staged slices (directory bytes, refcount-block bytes) plus
//! scalar geometry, reusing `snapshot::qcow2` for allocation and
//! refcount arithmetic. They are `no_std` and perform no I/O.
//! Implemented in phases 3c / 3d.
