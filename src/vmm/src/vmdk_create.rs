//! Creating flat VMDK images: `monolithicFlat` and `twoGbMaxExtentFlat`.
//!
//! The descriptor and its extents are host files the guest never sees, so
//! the whole create happens here on the host: naming the extents beside the
//! descriptor, writing them and the descriptor, and undoing a create that
//! fails part-way. `run_create` dispatches here for either subformat.

use std::path::Path;

use crate::escape::terminal_safe_path;
use crate::{parse_memory_size, render_create_success, CreateArgs};

/// How a VMDK names the extent files that sit beside its descriptor,
/// and how many of them there are.
///
/// Every flat subformat puts its extents in the output's own directory
/// and derives each name from the output's own stem, so one derivation
/// serves them all and only the suffix and the count differ. A second
/// derivation would be a second name-safety predicate to keep in step
/// with this one, which is how the two descriptor builders came to
/// disagree about their `ddb.*` lines.
#[derive(Debug, Clone, Copy)]
enum VmdkExtentNaming {
    /// `monolithicFlat`: one extent, named `<prefix>-flat<postfix>`.
    MonolithicFlat,
    /// A split subformat: one extent per `layout.extent_count`, named
    /// `<prefix>-f<NNN><postfix>` for a flat layout and
    /// `<prefix>-s<NNN><postfix>` for a sparse one, where `NNN` is the
    /// one-based extent number zero-padded to at least three digits.
    /// `vmdk::build_split_descriptor` writes those same names from the
    /// same stem, which is why the stem is returned alongside them.
    Split(vmdk::SplitLayout),
}

impl VmdkExtentNaming {
    /// The subformat's name, for a refusal that has to say which
    /// create path refused.
    fn subformat(&self) -> &'static str {
        match self {
            Self::MonolithicFlat => "monolithicFlat",
            Self::Split(layout) => match layout.kind {
                vmdk::SplitKind::Flat => "twoGbMaxExtentFlat",
                vmdk::SplitKind::Sparse => "twoGbMaxExtentSparse",
            },
        }
    }

    /// How many extent files this naming yields.
    fn extent_count(&self) -> u64 {
        match self {
            Self::MonolithicFlat => 1,
            Self::Split(layout) => layout.extent_count,
        }
    }

    /// What goes between the stem's prefix and its extension for
    /// extent `index`, counted from zero.
    fn suffix(&self, index: u64) -> Vec<u8> {
        match self {
            Self::MonolithicFlat => b"-flat".to_vec(),
            Self::Split(layout) => {
                let tag = match layout.kind {
                    vmdk::SplitKind::Flat => 'f',
                    vmdk::SplitKind::Sparse => 's',
                };
                format!("-{tag}{:03}", index.saturating_add(1)).into_bytes()
            }
        }
    }
}

/// The extent file names a VMDK create derives from its output path.
///
/// `prefix` and `postfix` are the decomposed stem, which is what
/// `vmdk::build_split_descriptor` names its extents from; the split
/// writer passes them straight through to it.
#[derive(Debug)]
struct VmdkExtentPaths {
    /// The output's base name up to its last `.`, without the
    /// directory.
    prefix: Vec<u8>,
    /// The output's extension including its dot, or empty when the
    /// base name holds no dot.
    postfix: Vec<u8>,
    /// One entry per extent in extent order: the path to write, and
    /// the name the descriptor records for it.
    extents: Vec<(std::path::PathBuf, String)>,
}

/// Name the extent files of a flat VMDK the way qemu does.
///
/// qemu (`filename_decompose`, `block/vmdk.c:2279-2316`, and the `"%s-flat%s"`
/// format in `vmdk_co_do_create`, `:2599`, qemu 7.0.0) takes the basename
/// after the last `/`, splits it at its last `.`, and writes
/// `<prefix><suffix><postfix>` in the output's directory. The output's own
/// extension is kept, a name with no dot gets a bare suffix, and a
/// leading dot is the split point (`.hid` with monolithicFlat's `-flat`
/// gives `-flat.hid`). qemu also looks for `\` and then `:` when there is
/// no `/`; neither is a path separator on the hosts instar runs on, so
/// they are not split on. The split subformats number their extents from
/// the same decomposition, so the same split point serves every
/// subformat.
///
/// The descriptor records each name as a quoted string on a line of UTF-8
/// text, so a name that is not UTF-8, or that holds a `"`, CR or LF, is
/// refused rather than written: it would name a file other than the
/// extent, or end the quoted string and add descriptor lines of its own.
/// qemu writes such names verbatim. `op` prefixes the refusal, which
/// names the subformat that refused.
///
/// Nothing here bounds the extent count, and the work is one allocation
/// per extent: a caller deriving the count from a virtual size must
/// bound the size before it asks.
fn vmdk_extent_paths(
    output: &Path,
    naming: VmdkExtentNaming,
    op: &str,
) -> Result<VmdkExtentPaths, String> {
    use std::os::unix::ffi::{OsStrExt, OsStringExt};

    let bytes = output.as_os_str().as_bytes();
    let base_start = bytes.iter().rposition(|&b| b == b'/').map_or(0, |i| i + 1);
    let (dir, base) = bytes.split_at(base_start);
    let (prefix, postfix) = match base.iter().rposition(|&b| b == b'.') {
        Some(i) => base.split_at(i),
        None => (base, &base[base.len()..]),
    };

    let count = naming.extent_count();
    // The capacity hint is clamped so that an unbounded count cannot
    // ask for an unbounded allocation up front; the loop still derives
    // every name it was asked for.
    let hint = count.min(vmdk::MAX_EXTENTS as u64) as usize;
    let mut extents = Vec::with_capacity(hint);
    for index in 0..count {
        let suffix = naming.suffix(index);
        let mut name = Vec::with_capacity(base.len() + suffix.len());
        name.extend_from_slice(prefix);
        name.extend_from_slice(&suffix);
        name.extend_from_slice(postfix);
        let recordable = std::str::from_utf8(&name)
            .ok()
            .filter(|n| !n.contains(['"', '\r', '\n']));
        let Some(recorded) = recordable else {
            return Err(format!(
                "{}: vmdk {} cannot record the extent name {:?} in its descriptor \
                 (it must be UTF-8 without '\"', CR or LF)",
                op,
                naming.subformat(),
                String::from_utf8_lossy(&name)
            ));
        };
        let recorded = recorded.to_string();
        let mut path = dir.to_vec();
        path.extend_from_slice(&name);
        extents.push((
            std::path::PathBuf::from(std::ffi::OsString::from_vec(path)),
            recorded,
        ));
    }

    Ok(VmdkExtentPaths {
        prefix: prefix.to_vec(),
        postfix: postfix.to_vec(),
        extents,
    })
}

/// Name the one extent file of a monolithicFlat VMDK, for create and
/// convert, which both have exactly one.
///
/// Returns the extent's path and the name the descriptor records for
/// it. `vmdk_extent_paths` does the deriving and the refusing.
pub(super) fn vmdk_flat_extent_path(
    output: &Path,
    op: &str,
) -> Result<(std::path::PathBuf, String), String> {
    let derived = vmdk_extent_paths(output, VmdkExtentNaming::MonolithicFlat, op)?;
    derived
        .extents
        .into_iter()
        .next()
        .ok_or_else(|| format!("internal error: {op}: monolithicFlat derived no extent name"))
}

/// Refuse what a split VMDK create cannot write, and derive what it
/// will write, before anything is opened.
///
/// Returns the extent layout the descriptor and the extent lengths come
/// from, and the derived names. Three things are refused here rather
/// than part-way through a write that has already made files:
///
/// A size needing more extents than the guest's extent table holds.
/// That table is a fixed array of `vmdk::MAX_EXTENTS` entries, so an
/// image with more extents is one instar's own reader declines; writing
/// it would produce output no part of instar can read back, and would
/// leave the differential fuzzer blind above the cap. The limit is
/// instar's own: qemu-img has none, and writes a split image of any
/// size it can express.
///
/// A zero virtual size, which lays out zero extents and would emit a
/// descriptor with no extent lines at all. The reader refuses that too.
///
/// A derived extent path that already exists. The descriptor is the
/// path the user named and create has always overwritten it, but
/// `<stem>-f001<ext>` and its siblings are instar's invention, and
/// truncating a file nobody named is not something to do on instar's
/// word alone. qemu-img truncates them in place, so this is a
/// deliberate divergence, and the cost is that re-running a failed
/// create means removing the extents by hand.
///
/// The existence test is advisory against anyone else who can write to
/// the output's directory, as the cleanup helpers' test is: between the
/// stat and the create they could put a file at the path. The output
/// path and its directory are the invoking user's choice, which puts
/// that party outside the untrusted-image threat model this project
/// defends. A dangling symlink counts as present, because creating
/// through one writes to a file the user never named.
fn vmdk_split_create_plan(
    output: &Path,
    virtual_size: u64,
    kind: vmdk::SplitKind,
    op: &str,
) -> Result<(vmdk::SplitLayout, VmdkExtentPaths), String> {
    let layout = vmdk::split_layout(virtual_size, kind);
    let naming = VmdkExtentNaming::Split(layout);
    let subformat = naming.subformat();

    if layout.extent_count == 0 {
        return Err(format!(
            "{op}: a vmdk {subformat} image of {virtual_size} bytes has no extents, and a \
             descriptor with no extent lines is one instar cannot read; refusing to write \
             an image with nothing in it"
        ));
    }
    if layout.extent_count > vmdk::MAX_EXTENTS as u64 {
        return Err(format!(
            "{op}: a vmdk {subformat} image of {virtual_size} bytes needs {} extents, more \
             than the {} the guest's extent table holds; the table is a fixed array, so \
             instar could not read such an image back and refuses to write one (the limit \
             is instar's own, not qemu's)",
            layout.extent_count,
            vmdk::MAX_EXTENTS
        ));
    }

    let paths = vmdk_extent_paths(output, naming, op)?;
    for (path, _) in &paths.extents {
        if std::fs::symlink_metadata(path).is_ok() {
            return Err(format!(
                "{op}: the vmdk {subformat} extent '{}' already exists; instar derived that \
                 path rather than being given it and will not overwrite it, so nothing has \
                 been written",
                terminal_safe_path(path)
            ));
        }
    }

    Ok((layout, paths))
}

/// The monolithicFlat descriptor naming `extent_name`, for create and
/// convert. The builder reports the length it needs whatever the buffer, so
/// it is measured first and the buffer sized to fit.
pub(super) fn vmdk_flat_descriptor(capacity_sectors: u64, extent_name: &str) -> Vec<u8> {
    let needed = vmdk::build_flat_descriptor(&mut [], 0, capacity_sectors, extent_name.as_bytes());
    let mut text = vec![0u8; needed];
    let written =
        vmdk::build_flat_descriptor(&mut text, 0, capacity_sectors, extent_name.as_bytes());
    debug_assert_eq!(written, needed);
    text
}

/// The split descriptor naming the extents derived from `prefix` and
/// `postfix`, for create. As with the monolithicFlat descriptor, the
/// builder reports the length it needs whatever the buffer, so it is
/// measured first and the buffer sized to fit.
///
/// Both passes cost one iteration per extent, so the caller must have
/// bounded `layout.extent_count` before it measures.
fn vmdk_split_descriptor(layout: &vmdk::SplitLayout, prefix: &[u8], postfix: &[u8]) -> Vec<u8> {
    let needed = vmdk::build_split_descriptor(&mut [], 0, layout, prefix, postfix);
    let mut text = vec![0u8; needed];
    let written = vmdk::build_split_descriptor(&mut text, 0, layout, prefix, postfix);
    debug_assert_eq!(written, needed);
    text
}

/// Whether `args` (with `-o` applied) asks for a monolithicFlat VMDK.
pub(super) fn is_vmdk_flat_create(args: &CreateArgs) -> bool {
    args.target_format == "vmdk" && args.subformat == "monolithicFlat"
}

/// Whether `args` (with `-o` applied) asks for a twoGbMaxExtentFlat VMDK.
pub(super) fn is_vmdk_split_flat_create(args: &CreateArgs) -> bool {
    args.target_format == "vmdk" && args.subformat == "twoGbMaxExtentFlat"
}

/// The options a flat VMDK, single extent or split, cannot take.
///
/// qemu refuses a backing file ("Flat image can't have backing file") and
/// `zeroed_grain=on` ("Flat image can't enable zeroed grain"), at
/// `block/vmdk.c:2428-2437` in qemu 7.0.0. A grain size means nothing for
/// a flat extent, so it is refused rather than ignored. Without a backing
/// file the size must be given. `preallocation=metadata` is refused by the
/// common preallocation check.
pub(super) fn validate_vmdk_flat_create_args(
    args: &CreateArgs,
) -> Result<(), Box<dyn std::error::Error>> {
    let name = args.subformat.as_str();
    if args.backing.is_some() {
        return Err(format!("create: vmdk {name} cannot have a backing file").into());
    }
    if args.size.is_none() {
        return Err(format!("create: vmdk {name} requires SIZE").into());
    }
    if args.zeroed_grain {
        return Err(format!("create: vmdk {name} cannot enable zeroed_grain").into());
    }
    if args.grain_size != 0 {
        return Err(format!(
            "create: vmdk {name} has no grains, so it takes no grain size (got {})",
            args.grain_size
        )
        .into());
    }
    Ok(())
}

/// The files a flat VMDK create has opened, and which of them it
/// brought into existence.
///
/// Opening the output truncates it, so a create that fails part-way
/// through has to undo what it did. Removing everything it opened is
/// the wrong undo: the descriptor is a path the user named, and create
/// overwrites a file the user named by design, so a failed create
/// would delete a file the user had before it ran. Removing only the
/// files that were not there when this run opened them leaves such a
/// file where it was found -- empty, because the open truncated it,
/// which is also what qemu-img leaves behind when its own create
/// fails. The guarantee is that create does not delete a file it did
/// not make; keeping the contents of one it truncated would mean
/// copying the file aside before opening it, which is a different and
/// much larger promise, and not one qemu-img makes either.
///
/// Both flat create paths open every file through here, so there is
/// one answer for the descriptor and for every extent.
#[derive(Debug, Default)]
struct VmdkCreatedFiles {
    /// One entry per file opened, in the order it was opened: the path,
    /// and whether this run is what created it.
    opened: Vec<(std::path::PathBuf, bool)>,
}

impl VmdkCreatedFiles {
    /// Open `path` the way create opens its output -- created if it is
    /// absent, truncated if it is not, mode 0644 -- and record whether
    /// this run created it.
    ///
    /// A file is this run's if it was not there when this run went to
    /// open it, tested immediately before the open with
    /// `symlink_metadata`, which is the test the derived-extent
    /// refusal uses. The test is not atomic and is not claimed to be:
    /// between the stat and the open, anyone who can write to the
    /// output's directory could put a file at the path, and a later
    /// failure would then remove a file this run did not create. The
    /// output path and its directory are the invoking user's own
    /// choice, which puts that party outside the untrusted-image
    /// threat model this project defends. A dangling symlink counts as
    /// the path being taken, so neither the link nor the file the open
    /// creates through it is removed.
    ///
    /// `render` formats the path for the failure message, because the
    /// two writers quote their paths differently: the split writer's
    /// derived names are refused for `"`, CR and LF but not for other
    /// control characters, so it escapes them before they reach a
    /// terminal.
    fn open(
        &mut self,
        path: &Path,
        render: impl Fn(&Path) -> String,
    ) -> Result<std::fs::File, String> {
        use std::os::unix::fs::OpenOptionsExt;

        let existed = std::fs::symlink_metadata(path).is_ok();
        let file = std::fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .mode(0o644)
            .open(path)
            .map_err(|e| format!("create: open '{}' failed: {}", render(path), e))?;
        self.opened.push((path.to_path_buf(), !existed));
        Ok(file)
    }

    /// Remove the files this run created, for a create that failed
    /// after making some of them. Anything that was already there is
    /// left exactly as the open found it.
    fn remove_created(&self) {
        for (path, created) in &self.opened {
            if *created {
                let _ = std::fs::remove_file(path);
            }
        }
    }
}

/// Host-side monolithicFlat VMDK creation: a sparse raw extent and the
/// text descriptor that names it.
///
/// The extent is the requested size rounded up to a whole sector, as qemu
/// writes it (a 1000-byte request gives a 1024-byte extent and `RW 2
/// FLAT`). qemu only truncates the extent, under every preallocation mode,
/// so `falloc` and `full` allocate nothing here either; that is why
/// `create_raw_finalize` is not used. The extent is named by
/// `vmdk_flat_extent_path`, as convert names it, and the descriptor is the
/// one convert writes.
///
/// The arguments were validated before this runs, so nothing is opened
/// for a refused command. Once a file has been opened (and so
/// truncated), any failure removes the files this call created, and
/// leaves the ones that were already there -- see `VmdkCreatedFiles`.
/// A symlink is followed when opened, and counts as the path being
/// taken, so the link stays and the file it points at is left
/// truncated.
pub(super) fn run_create_vmdk_flat(args: &CreateArgs) -> Result<(), Box<dyn std::error::Error>> {
    let size_str = args
        .size
        .as_ref()
        .ok_or("create: vmdk monolithicFlat requires SIZE")?;
    let virtual_size = parse_memory_size(size_str)?
        .checked_next_multiple_of(512)
        .ok_or("create: SIZE is too large")?;

    let descriptor_path = Path::new(&args.filename);
    let (extent_path, extent_name) = vmdk_flat_extent_path(descriptor_path, "create")?;
    let mut opened = VmdkCreatedFiles::default();
    let result = write_vmdk_flat(
        descriptor_path,
        &extent_path,
        &extent_name,
        virtual_size,
        &mut opened,
    );
    let descriptor_len = match result {
        Ok(n) => n,
        Err(e) => {
            opened.remove_created();
            return Err(e);
        }
    };

    render_create_success(args, virtual_size, descriptor_len, descriptor_len, 0);
    Ok(())
}

/// Write a monolithicFlat VMDK for `run_create_vmdk_flat`, returning the
/// descriptor's length. Every file is opened through `opened`, which
/// records which of them this run created so the caller can remove
/// exactly those on failure.
fn write_vmdk_flat(
    descriptor_path: &Path,
    extent_path: &Path,
    extent_name: &str,
    virtual_size: u64,
    opened: &mut VmdkCreatedFiles,
) -> Result<u64, Box<dyn std::error::Error>> {
    use std::io::Write;

    let render = |path: &Path| path.display().to_string();
    let mut descriptor = opened.open(descriptor_path, render)?;
    let extent = opened.open(extent_path, render)?;

    extent.set_len(virtual_size).map_err(|e| {
        format!(
            "create: ftruncate '{}' failed: {}",
            extent_path.display(),
            e
        )
    })?;

    let text = vmdk_flat_descriptor(virtual_size / 512, extent_name);
    descriptor.write_all(&text).map_err(|e| {
        format!(
            "create: write '{}' failed: {}",
            descriptor_path.display(),
            e
        )
    })?;

    extent
        .sync_all()
        .map_err(|e| format!("create: sync '{}' failed: {}", extent_path.display(), e))?;
    descriptor
        .sync_all()
        .map_err(|e| format!("create: sync '{}' failed: {}", descriptor_path.display(), e))?;
    Ok(text.len() as u64)
}

/// Host-side twoGbMaxExtentFlat VMDK creation: one sparse raw extent per
/// extent the layout calls for, and the text descriptor that names them
/// all.
///
/// Every extent is the length `SplitLayout` gives it -- a full 2 GiB for
/// all but the last -- and nothing is written into any of them, so the
/// image costs its descriptor and a set of holes, exactly as the
/// single-extent subformat does for its one extent. qemu only truncates
/// a flat extent under every preallocation mode, so `falloc` and `full`
/// allocate nothing here either.
///
/// `vmdk_split_create_plan` does all the refusing, before a file is
/// opened, so nothing is created for a command that will be refused.
/// Once a file has been opened (and so truncated), any failure removes
/// the files this call created, and leaves the ones that were already
/// there -- see `VmdkCreatedFiles`. The plan has already refused a
/// pre-existing extent, so the descriptor is the only file a split
/// create can find in place.
pub(super) fn run_create_vmdk_split_flat(
    args: &CreateArgs,
) -> Result<(), Box<dyn std::error::Error>> {
    let size_str = args
        .size
        .as_ref()
        .ok_or("create: vmdk twoGbMaxExtentFlat requires SIZE")?;
    let requested = parse_memory_size(size_str)?;

    let descriptor_path = Path::new(&args.filename);
    let (layout, paths) =
        vmdk_split_create_plan(descriptor_path, requested, vmdk::SplitKind::Flat, "create")?;
    // The size the image describes, which is the request rounded up to a
    // whole sector as the single-extent path rounds it. The plan bounds
    // the extent count, so this is at most 128 GiB and cannot overflow.
    let virtual_size = layout.total_sectors * 512;

    let mut opened = VmdkCreatedFiles::default();
    let result = write_vmdk_split_flat(descriptor_path, &layout, &paths, &mut opened);
    let descriptor_len = match result {
        Ok(n) => n,
        Err(e) => {
            opened.remove_created();
            return Err(e);
        }
    };

    render_create_success(args, virtual_size, descriptor_len, descriptor_len, 0);
    Ok(())
}

/// Write a twoGbMaxExtentFlat VMDK for `run_create_vmdk_split_flat`,
/// returning the descriptor's length. Every file is opened through
/// `opened`, which records which of them this run created so the caller
/// can remove exactly those on failure.
///
/// Every extent is written and `fsync`ed before the descriptor is
/// created, which is the reverse of the single-extent order and is
/// deliberate. The descriptor is the only part of a split image that
/// says what the other parts are, so one that exists should never name
/// a set of extents that is not on disk. Ordering it last leaves extent
/// files with no descriptor as the only half-state a failure can
/// produce, and nothing reads those.
///
/// That holds for a create that fails, which is what the ordering is
/// for. It does not extend to a host crash: the containing directory is
/// never `fsync`ed, so the descriptor's directory entry and the
/// extents' can reach stable storage in either order, and a power loss
/// can leave a descriptor naming extents whose names are not there yet.
/// The single-extent writer has the same gap, and qemu-img promises no
/// more.
fn write_vmdk_split_flat(
    descriptor_path: &Path,
    layout: &vmdk::SplitLayout,
    paths: &VmdkExtentPaths,
    opened: &mut VmdkCreatedFiles,
) -> Result<u64, Box<dyn std::error::Error>> {
    use std::io::Write;

    for (index, (extent_path, _)) in paths.extents.iter().enumerate() {
        let extent = opened.open(extent_path, terminal_safe_path)?;
        // The extent is a hole of this length, not this many bytes
        // written. The plan bounds the count at 64 extents of 2 GiB, so
        // the multiplication cannot overflow.
        let length = layout.sectors_of_extent(index as u64) * 512;
        extent.set_len(length).map_err(|e| {
            format!(
                "create: ftruncate '{}' failed: {}",
                terminal_safe_path(extent_path),
                e
            )
        })?;
        extent.sync_all().map_err(|e| {
            format!(
                "create: sync '{}' failed: {}",
                terminal_safe_path(extent_path),
                e
            )
        })?;
    }

    let text = vmdk_split_descriptor(layout, &paths.prefix, &paths.postfix);
    let mut descriptor = opened.open(descriptor_path, terminal_safe_path)?;
    descriptor.write_all(&text).map_err(|e| {
        format!(
            "create: write '{}' failed: {}",
            terminal_safe_path(descriptor_path),
            e
        )
    })?;
    descriptor.sync_all().map_err(|e| {
        format!(
            "create: sync '{}' failed: {}",
            terminal_safe_path(descriptor_path),
            e
        )
    })?;
    Ok(text.len() as u64)
}

#[cfg(test)]
mod vmdk_flat_extent_path_tests {
    //! Unit tests for `vmdk_flat_extent_path`. Integration coverage against
    //! the host qemu-img lives in `tests/test_convert.py`.
    use super::*;
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt;
    use std::path::PathBuf;

    /// Assert `output` gives the extent path `extent`, and that the descriptor
    /// records the final component of `extent`.
    fn check(output: &str, extent: &str) {
        let (path, name) = vmdk_flat_extent_path(Path::new(output), "test").unwrap();
        assert_eq!(path, PathBuf::from(extent));
        assert_eq!(name, extent.rsplit('/').next().unwrap());
    }

    #[test]
    fn vmdk_extension_is_kept() {
        check("out.vmdk", "out-flat.vmdk");
    }

    #[test]
    fn other_extension_is_kept() {
        check("out.img", "out-flat.img");
    }

    #[test]
    fn no_extension_gets_a_bare_suffix() {
        check("out", "out-flat");
    }

    #[test]
    fn leading_dot_is_the_split_point() {
        check(".hid", "-flat.hid");
    }

    #[test]
    fn split_is_at_the_last_dot() {
        check("a.b.c", "a.b-flat.c");
    }

    #[test]
    fn trailing_dot_is_kept() {
        check("x.", "x-flat.");
    }

    #[test]
    fn extent_stays_in_the_outputs_directory() {
        check("dir/sub/x.y", "dir/sub/x-flat.y");
        check("/abs/noext", "/abs/noext-flat");
    }

    #[test]
    fn dots_in_directories_are_ignored() {
        check("d.ir/out", "d.ir/out-flat");
    }

    #[test]
    fn backslash_and_colon_are_not_separators() {
        check("a\\b.vmdk", "a\\b-flat.vmdk");
        check("a:b.vmdk", "a:b-flat.vmdk");
    }

    /// Assert `output` is refused, naming `op` and the offending name.
    fn refused(output: &[u8], shown: &str) {
        let err = vmdk_flat_extent_path(Path::new(OsStr::from_bytes(output)), "op").unwrap_err();
        assert!(err.starts_with("op: "), "{err}");
        assert!(err.contains(shown), "{err} should show {shown}");
    }

    #[test]
    fn non_utf8_basename_is_refused() {
        refused(b"d/\xff\xfe.img", "\"\u{fffd}\u{fffd}-flat.img\"");
    }

    #[test]
    fn descriptor_breaking_characters_are_refused() {
        refused(b"a\"b.vmdk", r#""a\"b-flat.vmdk""#);
        refused(b"a\nb.vmdk", r#""a\nb-flat.vmdk""#);
        refused(b"a\rb.vmdk", r#""a\rb-flat.vmdk""#);
    }

    #[test]
    fn non_utf8_and_quotes_in_directories_are_allowed() {
        // Only the basename is recorded; the directory never reaches the
        // descriptor.
        let out = Path::new(OsStr::from_bytes(b"\xff\"/out.vmdk"));
        let (path, name) = vmdk_flat_extent_path(out, "op").unwrap();
        assert_eq!(path.as_os_str().as_bytes(), b"\xff\"/out-flat.vmdk");
        assert_eq!(name, "out-flat.vmdk");
    }
}

#[cfg(test)]
mod vmdk_split_extent_paths_tests {
    //! Unit tests for the split half of `vmdk_extent_paths`, and for the
    //! three things `vmdk_split_create_plan` refuses before a file can be
    //! opened. End-to-end coverage against qemu's pinned descriptors
    //! lives in the Python suite.
    use super::*;
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt;
    use std::path::PathBuf;
    use tempfile::TempDir;

    /// Bytes in every extent but the last.
    const EXTENT_BYTES: u64 = vmdk::SPLIT_EXTENT_SECTORS * 512;
    /// The largest image the guest's extent table can describe: 128 GiB.
    const MAX_BYTES: u64 = vmdk::MAX_EXTENTS as u64 * EXTENT_BYTES;

    /// Derive the flat split names for `output` at `bytes`. No bound is
    /// applied: the deriver has none, which is why the plan has them.
    fn derived(output: &str, bytes: u64) -> VmdkExtentPaths {
        let layout = vmdk::split_layout(bytes, vmdk::SplitKind::Flat);
        vmdk_extent_paths(Path::new(output), VmdkExtentNaming::Split(layout), "test").unwrap()
    }

    /// The names the descriptor would record, in extent order.
    fn names(paths: &VmdkExtentPaths) -> Vec<&str> {
        paths.extents.iter().map(|(_, n)| n.as_str()).collect()
    }

    #[test]
    fn the_stem_is_the_decomposition_the_emitter_takes() {
        let paths = derived("dir/out.vmdk", EXTENT_BYTES);
        assert_eq!(paths.prefix, b"out");
        assert_eq!(paths.postfix, b".vmdk");

        let bare = derived("dir/out", EXTENT_BYTES);
        assert_eq!(bare.prefix, b"out");
        assert_eq!(bare.postfix, b"");
    }

    #[test]
    fn one_extent_is_numbered_from_one() {
        let paths = derived("dir/out.vmdk", EXTENT_BYTES);
        assert_eq!(names(&paths), ["out-f001.vmdk"]);
        assert_eq!(paths.extents[0].0, PathBuf::from("dir/out-f001.vmdk"));
    }

    #[test]
    fn two_extents_are_numbered_in_order() {
        let paths = derived("out.vmdk", EXTENT_BYTES + 1);
        assert_eq!(names(&paths), ["out-f001.vmdk", "out-f002.vmdk"]);
    }

    #[test]
    fn the_tables_worth_of_extents_derives_every_name() {
        let paths = derived("out.vmdk", MAX_BYTES);
        assert_eq!(paths.extents.len(), 64);
        assert_eq!(names(&paths)[0], "out-f001.vmdk");
        assert_eq!(names(&paths)[63], "out-f064.vmdk");
    }

    /// The deriver does not enforce the extent ceiling, so that there is
    /// one place that does and one message to read.
    #[test]
    fn one_extent_past_the_table_still_derives() {
        let paths = derived("out.vmdk", MAX_BYTES + 1);
        assert_eq!(paths.extents.len(), 65);
        assert_eq!(names(&paths)[64], "out-f065.vmdk");
    }

    #[test]
    fn a_sparse_layout_is_tagged_s() {
        let layout = vmdk::split_layout(EXTENT_BYTES, vmdk::SplitKind::Sparse);
        let paths = vmdk_extent_paths(
            Path::new("out.vmdk"),
            VmdkExtentNaming::Split(layout),
            "test",
        )
        .unwrap();
        assert_eq!(names(&paths), ["out-s001.vmdk"]);
    }

    #[test]
    fn extents_stay_in_the_outputs_directory() {
        let paths = derived("/abs/d.ir/out", EXTENT_BYTES + 1);
        assert_eq!(paths.extents[0].0, PathBuf::from("/abs/d.ir/out-f001"));
        assert_eq!(paths.extents[1].0, PathBuf::from("/abs/d.ir/out-f002"));
        assert_eq!(names(&paths), ["out-f001", "out-f002"]);
    }

    /// The same predicate monolithicFlat uses, naming the subformat that
    /// refused rather than monolithicFlat's name.
    #[test]
    fn a_name_the_descriptor_cannot_quote_is_refused() {
        let layout = vmdk::split_layout(EXTENT_BYTES, vmdk::SplitKind::Flat);
        let outputs: [&[u8]; 4] = [b"a\"b.vmdk", b"a\nb.vmdk", b"a\rb.vmdk", b"\xff\xfe.img"];
        for output in outputs {
            let err = vmdk_extent_paths(
                Path::new(OsStr::from_bytes(output)),
                VmdkExtentNaming::Split(layout),
                "op",
            )
            .unwrap_err();
            assert!(err.starts_with("op: vmdk twoGbMaxExtentFlat "), "{err}");
            assert!(err.contains("UTF-8 without"), "{err}");
        }
    }

    /// Plan a flat split create of `bytes` into `dir`.
    fn plan(dir: &Path, bytes: u64) -> Result<(vmdk::SplitLayout, VmdkExtentPaths), String> {
        vmdk_split_create_plan(
            &dir.join("out.vmdk"),
            bytes,
            vmdk::SplitKind::Flat,
            "create",
        )
    }

    #[test]
    fn exactly_the_table_s_worth_is_accepted() {
        let dir = TempDir::new().unwrap();
        let (layout, paths) = plan(dir.path(), MAX_BYTES).expect("128 GiB is 64 extents");
        assert_eq!(layout.extent_count, 64);
        assert_eq!(paths.extents.len(), 64);
    }

    #[test]
    fn one_byte_past_the_table_is_refused() {
        let dir = TempDir::new().unwrap();
        let err = plan(dir.path(), MAX_BYTES + 1).unwrap_err();
        assert!(err.starts_with("create: "), "{err}");
        assert!(err.contains("needs 65 extents"), "{err}");
        assert!(
            err.contains("the 64 the guest's extent table holds"),
            "{err}"
        );
        assert!(err.contains(&format!("{} bytes", MAX_BYTES + 1)), "{err}");
        assert!(err.contains("fixed array"), "{err}");
        assert!(err.contains("not qemu's"), "{err}");
        assert!(
            !dir.path().join("out.vmdk").exists(),
            "the refusal opened the descriptor"
        );
        assert!(
            !dir.path().join("out-f001.vmdk").exists(),
            "the refusal opened an extent"
        );
    }

    #[test]
    fn a_zero_size_is_refused_with_its_own_message() {
        let dir = TempDir::new().unwrap();
        let err = plan(dir.path(), 0).unwrap_err();
        assert!(err.starts_with("create: "), "{err}");
        assert!(err.contains("has no extents"), "{err}");
        assert!(err.contains("no extent lines"), "{err}");
        assert!(!err.contains("extent table holds"), "{err}");
        assert!(
            !dir.path().join("out.vmdk").exists(),
            "the refusal created the descriptor"
        );
    }

    #[test]
    fn a_derived_extent_that_exists_is_refused_by_name() {
        let dir = TempDir::new().unwrap();
        let clash = dir.path().join("out-f002.vmdk");
        std::fs::write(&clash, b"mine").unwrap();
        let later = dir.path().join("out-f003.vmdk");
        std::fs::write(&later, b"also mine").unwrap();

        let err = plan(dir.path(), 5 * EXTENT_BYTES).unwrap_err();
        assert!(err.starts_with("create: "), "{err}");
        assert!(err.contains("out-f002.vmdk"), "{err}");
        assert!(
            !err.contains("out-f003.vmdk"),
            "only the first is named: {err}"
        );
        assert!(err.contains("already exists"), "{err}");
        assert!(err.contains("nothing has been written"), "{err}");

        assert_eq!(std::fs::read(&clash).unwrap(), b"mine");
        assert!(
            !dir.path().join("out.vmdk").exists(),
            "the refusal created the descriptor"
        );
        assert!(
            !dir.path().join("out-f001.vmdk").exists(),
            "the refusal created an extent"
        );
    }

    /// Creating through a dangling symlink would write a file the user
    /// never named, so a link counts as the path being taken.
    #[test]
    fn a_dangling_symlink_at_a_derived_path_is_refused() {
        let dir = TempDir::new().unwrap();
        let link = dir.path().join("out-f001.vmdk");
        std::os::unix::fs::symlink(dir.path().join("gone"), &link).unwrap();
        let err = plan(dir.path(), EXTENT_BYTES).unwrap_err();
        assert!(err.contains("out-f001.vmdk"), "{err}");
        assert!(err.contains("already exists"), "{err}");
    }

    /// The asymmetry is deliberate: the descriptor is the path the user
    /// typed, and create's help text has always promised to overwrite it.
    #[test]
    fn a_pre_existing_descriptor_is_not_refused() {
        let dir = TempDir::new().unwrap();
        std::fs::write(dir.path().join("out.vmdk"), b"old").unwrap();
        plan(dir.path(), EXTENT_BYTES).expect("the named descriptor is the user's to lose");
    }
}

#[cfg(test)]
mod vmdk_split_flat_writer_tests {
    //! Unit tests for the host-side twoGbMaxExtentFlat writer: the length
    //! it gives each extent, the descriptor bytes it writes, and that no
    //! descriptor exists until every extent does.
    //!
    //! The extents are holes, so every length here is an apparent length.
    //! An allocated length or a disk-usage figure would be a property of
    //! the filesystem the test happens to run on, not of the writer.
    //! Comparison against qemu's own descriptors lives in the Python
    //! suite, which has the pinned cases.
    use super::*;
    use std::path::PathBuf;
    use tempfile::TempDir;

    /// Bytes in every extent but the last.
    const EXTENT_BYTES: u64 = vmdk::SPLIT_EXTENT_SECTORS * 512;
    /// The largest image the guest's extent table can describe: 128 GiB.
    const MAX_BYTES: u64 = vmdk::MAX_EXTENTS as u64 * EXTENT_BYTES;
    const GIB: u64 = 1024 * 1024 * 1024;

    /// Plan a flat split create of `bytes` into `dir`, for a writer test
    /// that is not about the refusals.
    fn plan(dir: &Path, bytes: u64) -> (vmdk::SplitLayout, VmdkExtentPaths) {
        vmdk_split_create_plan(
            &dir.join("out.vmdk"),
            bytes,
            vmdk::SplitKind::Flat,
            "create",
        )
        .expect("the plan accepts this size")
    }

    /// The length the file claims, which for a hole-bearing extent is
    /// the only length that is the writer's business.
    fn apparent_len(path: &Path) -> u64 {
        std::fs::metadata(path)
            .unwrap_or_else(|e| panic!("{}: {e}", path.display()))
            .len()
    }

    #[test]
    fn each_extent_is_as_long_as_the_layout_says() {
        let dir = TempDir::new().unwrap();
        let descriptor = dir.path().join("out.vmdk");
        let (layout, paths) = plan(dir.path(), 5 * GIB);
        let mut opened = VmdkCreatedFiles::default();
        write_vmdk_split_flat(&descriptor, &layout, &paths, &mut opened).unwrap();

        let lengths: Vec<u64> = paths.extents.iter().map(|(p, _)| apparent_len(p)).collect();
        assert_eq!(lengths, [2 * GIB, 2 * GIB, GIB]);
        for (index, length) in lengths.iter().enumerate() {
            assert_eq!(*length, layout.sectors_of_extent(index as u64) * 512);
        }
    }

    #[test]
    fn the_descriptor_is_the_emitters_bytes() {
        let dir = TempDir::new().unwrap();
        let descriptor = dir.path().join("out.vmdk");
        let (layout, paths) = plan(dir.path(), 5 * GIB);
        let mut opened = VmdkCreatedFiles::default();
        let reported = write_vmdk_split_flat(&descriptor, &layout, &paths, &mut opened).unwrap();

        let needed = vmdk::build_split_descriptor(&mut [], 0, &layout, b"out", b".vmdk");
        let mut expected = vec![0u8; needed];
        vmdk::build_split_descriptor(&mut expected, 0, &layout, b"out", b".vmdk");

        let on_disk = std::fs::read(&descriptor).unwrap();
        assert_eq!(on_disk, expected);
        assert_eq!(reported, expected.len() as u64);
        // Measuring first sized the buffer exactly: a buffer sized by
        // guess would leave trailing zeros or a truncated last line.
        assert!(
            on_disk.ends_with(b"ddb.toolsVersion = \"2147483647\"\n"),
            "{}",
            String::from_utf8_lossy(&on_disk)
        );
    }

    /// Sixty-four extents is the most the guest's extent table holds, and
    /// all of them are holes: this writes no bytes at all.
    #[test]
    fn a_tables_worth_of_extents_is_all_written() {
        let dir = TempDir::new().unwrap();
        let descriptor = dir.path().join("out.vmdk");
        let (layout, paths) = plan(dir.path(), MAX_BYTES);
        let mut opened = VmdkCreatedFiles::default();
        write_vmdk_split_flat(&descriptor, &layout, &paths, &mut opened).unwrap();

        assert_eq!(paths.extents.len(), vmdk::MAX_EXTENTS);
        for (path, _) in &paths.extents {
            assert_eq!(apparent_len(path), EXTENT_BYTES);
        }
        assert!(apparent_len(&descriptor) > 0);
        // Every extent, then the descriptor: the order the files were
        // opened in, which is the order they were created in.
        assert_eq!(opened.opened.len(), vmdk::MAX_EXTENTS + 1);
        assert_eq!(opened.opened[vmdk::MAX_EXTENTS].0, descriptor);
    }

    /// The descriptor is the only part of a split image that says what
    /// the other parts are, so it must not exist until they do. A
    /// directory in the way of the second extent fails the write
    /// part-way through, which is the half-state the ordering is for.
    #[test]
    fn no_descriptor_is_created_until_every_extent_is() {
        let dir = TempDir::new().unwrap();
        let descriptor = dir.path().join("out.vmdk");
        let (layout, paths) = plan(dir.path(), 3 * EXTENT_BYTES);
        std::fs::create_dir(&paths.extents[1].0).unwrap();

        let mut opened = VmdkCreatedFiles::default();
        let err = write_vmdk_split_flat(&descriptor, &layout, &paths, &mut opened)
            .unwrap_err()
            .to_string();
        assert!(err.starts_with("create: open "), "{err}");
        assert!(err.contains("out-f002.vmdk"), "{err}");
        assert!(
            !descriptor.exists(),
            "the descriptor outlived a write that never finished its extents"
        );
        assert!(!paths.extents[2].0.exists(), "a later extent was opened");
        assert_eq!(
            opened.opened,
            vec![(PathBuf::from(&paths.extents[0].0), true)]
        );
        assert_eq!(apparent_len(&paths.extents[0].0), EXTENT_BYTES);
    }
}

#[cfg(test)]
mod vmdk_created_files_tests {
    //! Unit tests for `VmdkCreatedFiles`, the bookkeeping both flat
    //! create writers open their files through.
    //!
    //! The two halves of its guarantee are tested apart: a file this
    //! run created is removed when the create fails, and a file that
    //! was already there is not. End-to-end coverage of both writers'
    //! failure paths lives with the create tests; these cover what a
    //! portable failure injection cannot reach through them. A
    //! directory in the way is the only failure either writer can be
    //! made to take without permission games or a full filesystem, and
    //! it fires at an open -- so a monolithicFlat extent and a split
    //! descriptor, both of which are opened after that point, are
    //! never truncated-then-kept there.
    use super::*;
    use tempfile::TempDir;

    /// Half one: a file that was already there survives the cleanup.
    #[test]
    fn a_file_that_was_already_there_is_kept() {
        let dir = TempDir::new().unwrap();
        let existing = dir.path().join("extent");
        std::fs::write(&existing, b"bytes this run did not write").unwrap();

        let mut opened = VmdkCreatedFiles::default();
        opened
            .open(&existing, |path| path.display().to_string())
            .expect("the open truncates what it finds");
        opened.remove_created();

        assert!(
            existing.exists(),
            "the cleanup deleted a file this run did not create"
        );
        // Empty, because the open truncated it. Not deleted is the
        // promise; unchanged would mean copying the file aside first.
        assert_eq!(std::fs::metadata(&existing).unwrap().len(), 0);
    }

    /// Half two: a file this run created is removed, told apart from
    /// one that was already there in the same set of open files.
    #[test]
    fn a_file_this_run_created_is_removed() {
        let dir = TempDir::new().unwrap();
        let existing = dir.path().join("descriptor");
        let fresh = dir.path().join("extent");
        std::fs::write(&existing, b"old").unwrap();

        let mut opened = VmdkCreatedFiles::default();
        for path in [&existing, &fresh] {
            opened
                .open(path, |path| path.display().to_string())
                .expect("both opens succeed");
        }
        assert_eq!(
            opened.opened,
            vec![(existing.clone(), false), (fresh.clone(), true)]
        );
        opened.remove_created();

        assert!(!fresh.exists(), "the cleanup left a file this run made");
        assert!(existing.exists());
    }
}
