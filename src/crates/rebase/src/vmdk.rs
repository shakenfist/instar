//! vmdk monolithicSparse rebase planner.
//!
//! Step 2d ships the unsafe-mode planner and a descriptor
//! rewriter. The descriptor rewriter copies the existing
//! descriptor lines into scratch, substituting `parentCID=`
//! and `parentFileNameHint=` lines with new values, preserving
//! every other line (so the createType, CID, extent line, and
//! ddb lines survive untouched).
//!
//! Step 2e (safe-mode planner + grain allocator) is deferred
//! pending demand — vmdk backing-chain rebase has a smaller
//! user base than qcow2.

use crate::{RebaseError, RebaseMode, RebasePatch, RebasePlan};

/// Maximum bytes the descriptor rewriter will emit. Keeps the
/// scratch carve-out bounded and matches the typical 10 KiB
/// descriptor slot vmdk monolithicSparse uses.
pub const MAX_DESCRIPTOR_REWRITE_LEN: usize = 64 * 1024;

/// Options for [`plan_rebase_vmdk`].
#[derive(Debug, Clone, Copy)]
pub struct VmdkRebaseOpts<'a> {
    /// Rebase mode.
    pub mode: RebaseMode,
    /// Overlay's virtual size in bytes.
    pub overlay_virtual_size: u64,
    /// Overlay's existing descriptor bytes (the planner
    /// rewrites this slot).
    pub overlay_descriptor: &'a [u8],
    /// Overlay's existing descriptor slot size in bytes.
    pub overlay_descriptor_size: u32,
    /// Byte offset of the descriptor within the overlay file.
    pub overlay_descriptor_offset: u64,
    /// New backing's virtual size. Used for compatibility
    /// checking.
    pub new_backing_virtual_size: u64,
    /// New backing path string. Written into the rewritten
    /// descriptor's `parentFileNameHint=` line.
    pub new_backing_path: &'a [u8],
    /// New parent CID. The host reads this from the new
    /// backing's own descriptor before populating the opts.
    /// Ignored when `detach` is set.
    pub new_parent_cid: u32,
    /// Detach flag: emit `parentCID=ffffffff` and an empty
    /// `parentFileNameHint=` line, matching qemu-img's detach
    /// convention.
    pub detach: bool,
}

/// Output of [`plan_rebase_vmdk`].
///
/// Not `Copy` — the safe-mode context (defined in step 2e)
/// will carry `&mut` borrows. The unsafe-mode variant carries
/// only a [`RebasePlan`], which itself is `Copy`.
#[allow(clippy::large_enum_variant)]
#[derive(Debug)]
pub enum VmdkRebaseOutput<'a> {
    /// Unsafe-mode (`-u`) output.
    Unsafe { plan: RebasePlan<'a> },
    /// Safe-mode output. Deferred to step 2e.
    Safe {
        context: RebaseVmdkSafeContext<'a>,
        deferred_metadata: RebasePlan<'a>,
    },
}

/// Context carried by the guest across safe-mode rebase's
/// per-grain comparison loop. Placeholder — step 2e fills in
/// the field set.
#[derive(Debug)]
pub struct RebaseVmdkSafeContext<'a> {
    /// Overlay grain size in sectors.
    pub overlay_grain_size_sectors: u32,
    /// Total guest grains the comparison loop iterates over.
    pub overlay_grain_count: u64,
    /// Reserved for step 2e: staged grain-directory bytes.
    pub grain_directory: &'a mut [u8],
}

/// Allocator state for safe-mode vmdk rebase (step 2e).
#[derive(Debug, Clone, Copy, Default)]
pub struct GrainAllocationState {
    pub next_gde_index: u32,
    pub next_gte_index: u32,
    pub allocated: u64,
}

/// Plan a vmdk monolithicSparse rebase.
pub fn plan_rebase_vmdk<'a>(
    opts: &VmdkRebaseOpts<'_>,
    scratch: &'a mut [u8],
) -> Result<VmdkRebaseOutput<'a>, RebaseError> {
    if opts.detach && !opts.new_backing_path.is_empty() {
        return Err(RebaseError::HeaderMismatch);
    }
    if opts.new_backing_path.len() > MAX_DESCRIPTOR_REWRITE_LEN {
        return Err(RebaseError::BackingPathTooLong);
    }
    if !opts.detach && opts.new_backing_virtual_size < opts.overlay_virtual_size {
        return Err(RebaseError::NewBackingIncompatible);
    }

    match opts.mode {
        RebaseMode::Unsafe => plan_vmdk_unsafe(opts, scratch),
        RebaseMode::Safe => {
            // Step 2e fills this in.
            Err(RebaseError::UnsupportedFormat)
        }
    }
}

fn plan_vmdk_unsafe<'a>(
    opts: &VmdkRebaseOpts<'_>,
    scratch: &'a mut [u8],
) -> Result<VmdkRebaseOutput<'a>, RebaseError> {
    let slot_size = opts.overlay_descriptor_size as usize;
    if scratch.len() < slot_size {
        return Err(RebaseError::ScratchTooSmall);
    }

    let written = rewrite_descriptor(
        opts.overlay_descriptor,
        opts.new_backing_path,
        opts.new_parent_cid,
        opts.detach,
        &mut scratch[..slot_size],
    )?;
    // Zero-pad the rest of the slot so the patch covers the
    // full descriptor region (qemu-img's parsers stop at the
    // first NUL, so this matches its in-memory model).
    for b in scratch[written..slot_size].iter_mut() {
        *b = 0;
    }

    let patch_bytes: &'a [u8] = &scratch[..slot_size];
    let mut plan = RebasePlan::new(0);
    plan.push(RebasePatch::Write {
        byte_offset: opts.overlay_descriptor_offset,
        bytes: patch_bytes,
    })?;

    Ok(VmdkRebaseOutput::Unsafe { plan })
}

/// Rewrite a vmdk descriptor with new `parentCID=` and
/// `parentFileNameHint=` values.
///
/// Walks the source descriptor line-by-line. Lines starting
/// with `parentCID=` and `parentFileNameHint=` are replaced;
/// other lines are copied verbatim. If neither line was
/// present in the source, the replacements are appended after
/// the `CID=` line (or at the top if even that's missing).
///
/// Returns the number of bytes written to `dest`, or
/// [`RebaseError::DescriptorTooLarge`] if the rewrite would
/// exceed the destination slot.
fn rewrite_descriptor(
    source: &[u8],
    new_path: &[u8],
    new_parent_cid: u32,
    detach: bool,
    dest: &mut [u8],
) -> Result<usize, RebaseError> {
    // Trim source at first NUL to match the parser's
    // conventions.
    let source_end = source.iter().position(|&b| b == 0).unwrap_or(source.len());
    let source = &source[..source_end];

    let mut pos = 0usize;
    let mut saw_parent_cid = false;
    let mut saw_parent_hint = false;

    let cid_value = if detach { 0xffff_ffff } else { new_parent_cid };

    let mut line_start = 0usize;
    while line_start < source.len() {
        let line_end = source[line_start..]
            .iter()
            .position(|&b| b == b'\n')
            .map(|p| line_start + p)
            .unwrap_or(source.len());
        let line = &source[line_start..line_end];

        if line.starts_with(b"parentCID=") {
            pos = write_parent_cid_line(dest, pos, cid_value)?;
            saw_parent_cid = true;
        } else if line.starts_with(b"parentFileNameHint=") {
            pos = write_parent_hint_line(dest, pos, new_path, detach)?;
            saw_parent_hint = true;
        } else {
            pos = copy_line(dest, pos, line)?;
        }

        if line_end < source.len() {
            // Preserve the newline.
            pos = put_byte(dest, pos, b'\n')?;
        }

        // Insert missing parent lines right after the first
        // `CID=` line, matching the descriptor layout
        // create::build_vmdk_descriptor_with_backing emits.
        if line.starts_with(b"CID=") {
            if !saw_parent_cid {
                pos = write_parent_cid_line(dest, pos, cid_value)?;
                pos = put_byte(dest, pos, b'\n')?;
                saw_parent_cid = true;
            }
        }

        line_start = line_end + 1;
    }

    // If the source had no CID line at all, the parent lines
    // weren't inserted above; append them at the end so the
    // descriptor still parses.
    if !saw_parent_cid {
        pos = write_parent_cid_line(dest, pos, cid_value)?;
        pos = put_byte(dest, pos, b'\n')?;
    }
    if !saw_parent_hint {
        pos = write_parent_hint_line(dest, pos, new_path, detach)?;
        pos = put_byte(dest, pos, b'\n')?;
    }

    Ok(pos)
}

fn put_byte(dest: &mut [u8], pos: usize, b: u8) -> Result<usize, RebaseError> {
    if pos >= dest.len() {
        return Err(RebaseError::DescriptorTooLarge);
    }
    dest[pos] = b;
    Ok(pos + 1)
}

fn copy_line(dest: &mut [u8], pos: usize, line: &[u8]) -> Result<usize, RebaseError> {
    let end = pos.checked_add(line.len()).ok_or(RebaseError::Overflow)?;
    if end > dest.len() {
        return Err(RebaseError::DescriptorTooLarge);
    }
    dest[pos..end].copy_from_slice(line);
    Ok(end)
}

fn write_parent_cid_line(
    dest: &mut [u8],
    pos: usize,
    parent_cid: u32,
) -> Result<usize, RebaseError> {
    let mut pos = copy_line(dest, pos, b"parentCID=")?;
    let mut buf = [0u8; 8];
    let hex = format_u32_hex8(parent_cid, &mut buf);
    pos = copy_line(dest, pos, hex)?;
    Ok(pos)
}

fn write_parent_hint_line(
    dest: &mut [u8],
    pos: usize,
    path: &[u8],
    detach: bool,
) -> Result<usize, RebaseError> {
    let mut pos = copy_line(dest, pos, b"parentFileNameHint=\"")?;
    if !detach {
        pos = copy_line(dest, pos, path)?;
    }
    pos = copy_line(dest, pos, b"\"")?;
    Ok(pos)
}

/// Format a u32 as a fixed-width 8-character lowercase hex
/// string (matches qemu-img's parentCID format).
fn format_u32_hex8(val: u32, buf: &mut [u8; 8]) -> &[u8] {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for (i, slot) in buf.iter_mut().enumerate() {
        let nibble = (val >> ((7 - i) * 4)) & 0xf;
        *slot = HEX[nibble as usize];
    }
    &buf[..]
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_DESCRIPTOR: &[u8] = b"# Disk DescriptorFile\n\
        version=1\n\
        CID=fffffffe\n\
        parentCID=ffffffff\n\
        createType=\"monolithicSparse\"\n\
        parentFileNameHint=\"old.vmdk\"\n\
        \n\
        # Extent description\n\
        RW 2097152 SPARSE \"output.vmdk\"\n\
        \n\
        # The Disk Data Base\n\
        #DDB\n";

    #[test]
    fn rewrites_parent_cid_and_hint() {
        let mut dest = [0u8; 4096];
        let n = rewrite_descriptor(
            SAMPLE_DESCRIPTOR,
            b"new.vmdk",
            0x1234_5678,
            false,
            &mut dest,
        )
        .unwrap();
        let out = core::str::from_utf8(&dest[..n]).unwrap();
        assert!(out.contains("parentCID=12345678"));
        assert!(out.contains("parentFileNameHint=\"new.vmdk\""));
        // Other lines preserved.
        assert!(out.contains("CID=fffffffe"));
        assert!(out.contains("createType=\"monolithicSparse\""));
        assert!(out.contains("RW 2097152 SPARSE \"output.vmdk\""));
        // No leftover old path.
        assert!(!out.contains("old.vmdk"));
    }

    #[test]
    fn detach_uses_sentinel_and_empty_path() {
        let mut dest = [0u8; 4096];
        let n = rewrite_descriptor(SAMPLE_DESCRIPTOR, b"", 0, true, &mut dest).unwrap();
        let out = core::str::from_utf8(&dest[..n]).unwrap();
        assert!(out.contains("parentCID=ffffffff"));
        assert!(out.contains("parentFileNameHint=\"\""));
    }

    #[test]
    fn inserts_missing_lines_after_cid() {
        // Descriptor without parentCID or parentFileNameHint;
        // rewriter should insert them after CID=.
        let src = b"# Disk DescriptorFile\nversion=1\nCID=fffffffe\ncreateType=\"monolithicSparse\"\n";
        let mut dest = [0u8; 4096];
        let n = rewrite_descriptor(src, b"new.vmdk", 0xabcd_1234, false, &mut dest).unwrap();
        let out = core::str::from_utf8(&dest[..n]).unwrap();
        assert!(out.contains("CID=fffffffe"));
        assert!(out.contains("parentCID=abcd1234"));
        assert!(out.contains("parentFileNameHint=\"new.vmdk\""));
    }

    #[test]
    fn rejects_when_dest_too_small() {
        let mut tiny = [0u8; 32];
        let r = rewrite_descriptor(
            SAMPLE_DESCRIPTOR,
            b"new.vmdk",
            0,
            false,
            &mut tiny,
        );
        assert_eq!(r.err(), Some(RebaseError::DescriptorTooLarge));
    }

    #[test]
    fn unsafe_mode_plan_emits_descriptor_rewrite() {
        let mut scratch = [0u8; 4096];
        let opts = VmdkRebaseOpts {
            mode: RebaseMode::Unsafe,
            overlay_virtual_size: 1024 * 1024 * 1024,
            overlay_descriptor: SAMPLE_DESCRIPTOR,
            overlay_descriptor_size: 1024,
            overlay_descriptor_offset: 512,
            new_backing_virtual_size: 1024 * 1024 * 1024,
            new_backing_path: b"new.vmdk",
            new_parent_cid: 0xc0de_f00d,
            detach: false,
        };
        let out = plan_rebase_vmdk(&opts, &mut scratch).unwrap();
        match out {
            VmdkRebaseOutput::Unsafe { plan } => {
                let patches = plan.patches();
                assert_eq!(patches.len(), 1);
                match patches[0] {
                    RebasePatch::Write { byte_offset, bytes } => {
                        assert_eq!(byte_offset, 512);
                        assert_eq!(bytes.len(), 1024);
                        // Decode the rewritten descriptor.
                        let text = core::str::from_utf8(bytes).unwrap();
                        assert!(text.contains("parentCID=c0def00d"));
                        assert!(text.contains("parentFileNameHint=\"new.vmdk\""));
                    }
                    _ => panic!("expected Write"),
                }
            }
            _ => panic!("expected Unsafe variant"),
        }
    }

    #[test]
    fn rejects_smaller_new_backing() {
        let mut scratch = [0u8; 4096];
        let opts = VmdkRebaseOpts {
            mode: RebaseMode::Unsafe,
            overlay_virtual_size: 4 * 1024 * 1024,
            overlay_descriptor: SAMPLE_DESCRIPTOR,
            overlay_descriptor_size: 1024,
            overlay_descriptor_offset: 512,
            new_backing_virtual_size: 1024 * 1024, // smaller
            new_backing_path: b"new.vmdk",
            new_parent_cid: 0,
            detach: false,
        };
        let r = plan_rebase_vmdk(&opts, &mut scratch);
        assert_eq!(r.err(), Some(RebaseError::NewBackingIncompatible));
    }

    #[test]
    fn safe_mode_returns_unsupported_for_now() {
        let mut scratch = [0u8; 4096];
        let opts = VmdkRebaseOpts {
            mode: RebaseMode::Safe,
            overlay_virtual_size: 4 * 1024 * 1024,
            overlay_descriptor: SAMPLE_DESCRIPTOR,
            overlay_descriptor_size: 1024,
            overlay_descriptor_offset: 512,
            new_backing_virtual_size: 4 * 1024 * 1024,
            new_backing_path: b"new.vmdk",
            new_parent_cid: 0,
            detach: false,
        };
        let r = plan_rebase_vmdk(&opts, &mut scratch);
        assert_eq!(r.err(), Some(RebaseError::UnsupportedFormat));
    }
}
