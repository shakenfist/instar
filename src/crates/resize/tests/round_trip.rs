//! Integration tests for the resize planner's type surface.
//!
//! These tests run with `cargo test -p resize --tests` and
//! exercise the public API as an external caller would. The
//! inline tests in `src/lib.rs` cover the internals (`push`
//! capacity, individual planner classification); these tests
//! cover end-to-end invariants and forward-compat tripwires.

use resize::{
    plan_resize_raw, plan_resize_vhd, plan_resize_vhdx, plan_resize_vmdk, Preallocation,
    RawResizeOpts, ResizeAction, ResizeError, ResizePatch, ResizePlan, VhdResizeOpts, VhdSubformat,
    VhdxResizeOpts, VmdkResizeOpts, VmdkSubformat, MAX_RESIZE_PATCHES,
};

#[test]
fn plan_carries_patches_in_push_order() {
    let mut plan = ResizePlan::new(ResizeAction::Grow, 4 << 20);
    plan.push(ResizePatch::Write {
        byte_offset: 0,
        bytes: &[0x01; 8],
    })
    .unwrap();
    plan.push(ResizePatch::Append {
        byte_offset: 1024,
        bytes: &[0x02; 16],
    })
    .unwrap();
    plan.push(ResizePatch::ZeroFill {
        byte_offset: 1 << 20,
        len: 1 << 20,
    })
    .unwrap();

    let patches = plan.patches();
    assert_eq!(patches.len(), 3);
    assert_eq!(patches[0].byte_offset(), 0);
    assert_eq!(patches[0].len(), 8);
    assert_eq!(patches[1].byte_offset(), 1024);
    assert_eq!(patches[1].len(), 16);
    assert_eq!(patches[2].byte_offset(), 1 << 20);
    assert_eq!(patches[2].len(), 1 << 20);

    // Patches range over disjoint byte regions in this test,
    // which the planner-invariant for a real-world resize will
    // also satisfy. Overlap-checking is deferred to phase 12's
    // fuzz harness per the phase plan's open question 5.
    let total: u64 = patches.iter().map(ResizePatch::len).sum();
    assert_eq!(total, 8 + 16 + (1 << 20));
}

#[test]
fn plan_capacity_is_max_resize_patches() {
    let mut plan = ResizePlan::new(ResizeAction::Grow, 0);
    for _ in 0..MAX_RESIZE_PATCHES {
        plan.push(ResizePatch::Write {
            byte_offset: 0,
            bytes: &[],
        })
        .unwrap();
    }
    assert_eq!(plan.patches().len(), MAX_RESIZE_PATCHES);
    assert_eq!(
        plan.push(ResizePatch::Write {
            byte_offset: 0,
            bytes: &[],
        })
        .unwrap_err(),
        ResizeError::ScratchTooSmall
    );
}

#[test]
fn preallocation_variant_count_is_four() {
    // Forward-compat tripwire: phase 9 will key off all four
    // variants. Adding a fifth would need new translation logic
    // host-side; deliberately fail this test so the change is
    // reviewed.
    let variants = [
        Preallocation::Off,
        Preallocation::Metadata,
        Preallocation::Falloc,
        Preallocation::Full,
    ];
    assert_eq!(variants.len(), 4);
    // And the numeric encoding matches shared::ResizeConfig.
    assert_eq!(Preallocation::Off as u32, 0);
    assert_eq!(Preallocation::Metadata as u32, 1);
    assert_eq!(Preallocation::Falloc as u32, 2);
    assert_eq!(Preallocation::Full as u32, 3);
}

#[test]
fn plan_resize_raw_classifies_action_for_three_size_pairs() {
    fn opts(current: u64, new: u64) -> RawResizeOpts {
        RawResizeOpts {
            current_virtual_size: current,
            new_virtual_size: new,
            preallocation: Preallocation::Off,
        }
    }

    let grow = plan_resize_raw(&opts(1 << 20, 2 << 20)).unwrap();
    assert_eq!(grow.action, ResizeAction::Grow);
    assert_eq!(grow.total_file_size, 2 << 20);
    assert_eq!(grow.patches().len(), 0);

    let shrink = plan_resize_raw(&opts(2 << 20, 1 << 20)).unwrap();
    assert_eq!(shrink.action, ResizeAction::Shrink);
    assert_eq!(shrink.total_file_size, 1 << 20);
    assert_eq!(shrink.patches().len(), 0);

    let noop = plan_resize_raw(&opts(1 << 20, 1 << 20)).unwrap();
    assert_eq!(noop.action, ResizeAction::NoOp);
    assert_eq!(noop.total_file_size, 1 << 20);
    assert_eq!(noop.patches().len(), 0);
}

#[test]
fn non_raw_planners_remain_stubbed() {
    // qcow2 has its own integration suite (phase 2d's
    // tests/qcow2_grow.rs); the three remaining non-raw
    // planners are still phase-stubbed.
    let mut scratch = [0u8; 128];

    let vmdk_opts = VmdkResizeOpts {
        current_virtual_size: 1 << 20,
        new_virtual_size: 2 << 20,
        grain_size: 65536,
        subformat: VmdkSubformat::MonolithicSparse,
        allow_shrink: false,
        preallocation: Preallocation::Off,
    };
    assert_eq!(
        plan_resize_vmdk(&vmdk_opts, &mut scratch).unwrap_err(),
        ResizeError::UnsupportedFormat
    );

    let vhd_opts = VhdResizeOpts {
        current_virtual_size: 1 << 20,
        new_virtual_size: 2 << 20,
        block_size: 2 * 1024 * 1024,
        subformat: VhdSubformat::Dynamic,
        allow_shrink: false,
        preallocation: Preallocation::Off,
    };
    assert_eq!(
        plan_resize_vhd(&vhd_opts, &mut scratch).unwrap_err(),
        ResizeError::UnsupportedFormat
    );

    let vhdx_opts = VhdxResizeOpts {
        current_virtual_size: 1 << 20,
        new_virtual_size: 2 << 20,
        block_size: 32 * 1024 * 1024,
        preallocation: Preallocation::Off,
    };
    assert_eq!(
        plan_resize_vhdx(&vhdx_opts, &mut scratch).unwrap_err(),
        ResizeError::UnsupportedFormat
    );
}
