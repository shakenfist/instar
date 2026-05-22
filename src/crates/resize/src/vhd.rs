//! VHD-specific resize planning.
//!
//! Phase 4 of `PLAN-resize.md`. The public entry point
//! [`plan_resize_vhd`](super::plan_resize_vhd) in the crate root
//! dispatches into [`plan_grow`] here, which classifies the
//! request into a [`VhdGrowAction`] and emits the patch list in
//! the documented crash-safety order.
//!
//! Step 4a ships the module skeleton with `plan_grow` returning
//! `UnsupportedFormat`; step 4b lands the real planner.

use crate::{ResizeError, ResizePlan, VhdResizeOpts};

pub(crate) fn plan_grow<'a>(
    _opts: &VhdResizeOpts<'_>,
    _scratch: &'a mut [u8],
) -> Result<ResizePlan<'a>, ResizeError> {
    Err(ResizeError::UnsupportedFormat)
}
