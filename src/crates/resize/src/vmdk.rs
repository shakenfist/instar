//! VMDK-specific resize planning.
//!
//! Phase 6 of `PLAN-resize.md`. The public entry point
//! [`plan_resize_vmdk`](super::plan_resize_vmdk) in the crate
//! root dispatches into [`plan_grow`] here, which classifies the
//! request and emits the patch list. Phase 6 supports
//! `MonolithicSparse` only; other subformats are rejected with
//! [`ResizeError::UnsupportedSubformat`].
//!
//! Step 6a ships the module skeleton with `plan_grow` returning
//! `UnsupportedFormat`; step 6b lands the real planner.

use crate::{ResizeError, ResizePlan, VmdkResizeOpts};

pub(crate) fn plan_grow<'a>(
    _opts: &VmdkResizeOpts<'_>,
    _scratch: &'a mut [u8],
) -> Result<ResizePlan<'a>, ResizeError> {
    Err(ResizeError::UnsupportedFormat)
}
