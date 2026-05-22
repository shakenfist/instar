//! VHDX-specific resize planning.
//!
//! Phase 5 of `PLAN-resize.md`. The public entry point
//! [`plan_resize_vhdx`](super::plan_resize_vhdx) in the crate
//! root dispatches into [`plan_grow`] here, which classifies the
//! request and emits the patch list in the documented
//! crash-safety order (prepare → inactive-header-commit →
//! active-header-redundancy).
//!
//! Step 5a ships the module skeleton with `plan_grow` returning
//! `UnsupportedFormat`; step 5b lands the real planner.

use crate::{ResizeError, ResizePlan, VhdxResizeOpts};

pub(crate) fn plan_grow<'a>(
    _opts: &VhdxResizeOpts<'_>,
    _scratch: &'a mut [u8],
) -> Result<ResizePlan<'a>, ResizeError> {
    Err(ResizeError::UnsupportedFormat)
}
