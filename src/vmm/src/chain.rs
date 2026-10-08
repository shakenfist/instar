//! Backing chain discovery and validation.
//!
//! This module handles discovery of backing file chains for qcow2 images by
//! iteratively running the sandboxed info operation. All format parsing happens
//! inside the KVM guest - this module only coordinates the discovery process
//! and validates backing file paths against a security allowlist.
//!
//! # Security
//!
//! Backing file paths are **untrusted data** read from image headers by the
//! sandboxed guest operation. This module:
//! - Checks each path against an allowlist of directories from its
//!   lexically normalised spelling before touching the filesystem, so
//!   `../` traversal is refused without probing where it leads
//! - Resolves symlinks and `..` one component at a time, as the kernel
//!   would, never looking at an image-chosen path outside the
//!   allowlist, so a refusal never depends on (or prints) what lies
//!   outside it
//! - Enforces a maximum chain depth to prevent infinite loops
//! - Does NOT parse image formats on the host

use std::path::{Component, Path, PathBuf};

use crate::config::{get_backing_allowlist, get_max_chain_depth, SecurityConfig};
use shared::format_detection::VMDK_DESCRIPTOR_MAGIC;

/// Image format detected by the sandboxed info operation
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImageFormat {
    /// Raw disk image (no container format)
    Raw,
    /// QCOW2 format (versions 2 and 3)
    Qcow2,
    /// QCOW1 format
    Qcow1,
    /// VMDK version 4
    Vmdk4,
    /// VMDK version 3
    Vmdk3,
    /// VHD format
    Vhd,
    /// VHDX format
    Vhdx,
    /// VDI format (VirtualBox Disk Image)
    Vdi,
    /// Parallels disk image (WithoutFreeSpace / WithouFreSpacExt magics)
    Parallels,
    /// LUKS encrypted container
    Luks,
    /// VMDK monolithicFlat descriptor file (text, points to a
    /// separate flat extent file that holds the actual content).
    VmdkDescriptor,
    /// DMG (Apple UDIF) disk image
    Dmg,
    /// Unknown or unsupported format
    Unknown,
}

impl ImageFormat {
    /// Parse format from string (as returned by info operation)
    pub fn from_str(s: &str) -> Self {
        match s {
            "raw" => ImageFormat::Raw,
            "qcow2" => ImageFormat::Qcow2,
            // The info op emits "qcow" (qemu-img / oslo spelling); "qcow1"
            // is kept as an accepted input alias.
            "qcow" | "qcow1" => ImageFormat::Qcow1,
            "vmdk" => ImageFormat::Vmdk4,
            "vmdk3" => ImageFormat::Vmdk3,
            "vpc" => ImageFormat::Vhd,
            "vhdx" => ImageFormat::Vhdx,
            "vdi" => ImageFormat::Vdi,
            "parallels" => ImageFormat::Parallels,
            "luks" => ImageFormat::Luks,
            "dmg" => ImageFormat::Dmg,
            _ => ImageFormat::Unknown,
        }
    }

    /// Check if this format can have a backing file
    #[allow(dead_code)]
    pub fn supports_backing(&self) -> bool {
        matches!(self, ImageFormat::Qcow2 | ImageFormat::Qcow1)
    }

    /// Convert to shared crate's ImageFormat u32 value.
    ///
    /// These values must match `shared::ImageFormat` enum values defined in
    /// `src/shared/src/lib.rs` (which uses `#[repr(u32)]`).
    pub fn to_shared_format_u32(self) -> u32 {
        match self {
            ImageFormat::Unknown => 0,
            ImageFormat::Raw => 1,
            ImageFormat::Qcow2 => 2,
            ImageFormat::Vmdk4 => 3,
            ImageFormat::Vmdk3 => 4,
            ImageFormat::Vhd => 5,
            ImageFormat::Vhdx => 6,
            ImageFormat::Qcow1 => 7,
            ImageFormat::Vdi => 8,
            ImageFormat::Parallels => 13,
            ImageFormat::Luks => 11,
            ImageFormat::VmdkDescriptor => 12,
            ImageFormat::Dmg => 16,
        }
    }
}

impl std::fmt::Display for ImageFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ImageFormat::Raw => write!(f, "raw"),
            ImageFormat::Qcow2 => write!(f, "qcow2"),
            // qemu-img / oslo call the v1 format "qcow" (not "qcow1").
            ImageFormat::Qcow1 => write!(f, "qcow"),
            ImageFormat::Vmdk4 => write!(f, "vmdk"),
            ImageFormat::Vmdk3 => write!(f, "vmdk3"),
            ImageFormat::Vhd => write!(f, "vpc"),
            ImageFormat::Vhdx => write!(f, "vhdx"),
            ImageFormat::Vdi => write!(f, "vdi"),
            ImageFormat::Parallels => write!(f, "parallels"),
            ImageFormat::Luks => write!(f, "luks"),
            // Reports as "vmdk" to match qemu-img info output for
            // monolithicFlat — matches the `name()` method on
            // `shared::ImageFormat::VmdkDescriptor`.
            ImageFormat::VmdkDescriptor => write!(f, "vmdk"),
            ImageFormat::Dmg => write!(f, "dmg"),
            ImageFormat::Unknown => write!(f, "unknown"),
        }
    }
}

/// A single external data file (flat extent or QCOW2 external data
/// file) to be opened as a separate virtio-block device.
#[derive(Debug, Clone)]
pub struct ExternalDataFile {
    /// Absolute, validated path to the file.
    pub path: PathBuf,
    /// Size of this file's virtual address space contribution in
    /// bytes. For QCOW2 external data files this equals the file
    /// size; for VMDK flat extents it equals the extent size from
    /// the descriptor.
    pub extent_size: u64,
}

/// Information about a single image in the backing chain.
///
/// This information comes from the sandboxed info operation.
#[derive(Debug, Clone)]
pub struct ChainImage {
    /// Absolute path to this image
    pub path: PathBuf,
    /// Detected format
    pub format: ImageFormat,
    /// Virtual size of the image in bytes
    pub virtual_size: u64,
    /// Actual/disk size of the image in bytes
    pub actual_size: u64,
    /// Cluster size (0 for raw images)
    pub cluster_size: u32,
    /// Raw backing file path from header (for display purposes)
    pub backing_file_raw: Option<String>,
    /// Feature flags from the info operation
    #[allow(dead_code)]
    pub flags: u32,
    /// External data files for this image (QCOW2 v3 external data
    /// file or VMDK flat extent files). Inserted as separate
    /// virtio-block devices immediately after this image's device.
    pub external_data_files: Vec<ExternalDataFile>,
}

/// Complete backing chain for an image.
///
/// The chain is ordered from top (index 0) to base (last index).
/// The top image is the one originally specified by the user.
/// The base image is the one with no backing file.
#[derive(Debug, Clone)]
pub struct BackingChain {
    /// Images in the chain, from top (index 0) to base (last index)
    pub images: Vec<ChainImage>,
}

impl BackingChain {
    /// Create a new empty backing chain
    pub fn new() -> Self {
        Self { images: Vec::new() }
    }

    /// Get the number of images in the chain
    pub fn len(&self) -> usize {
        self.images.len()
    }

    /// Total number of virtio-block devices needed for this chain.
    /// Includes external data file devices for each image.
    pub fn total_devices(&self) -> usize {
        self.images
            .iter()
            .map(|img| 1 + img.external_data_files.len())
            .sum()
    }

    /// Check if the chain is empty
    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.images.is_empty()
    }

    /// Get the top image (the one originally specified)
    #[allow(dead_code)]
    pub fn top(&self) -> Option<&ChainImage> {
        self.images.first()
    }

    /// Get the base image (the one with no backing file)
    #[allow(dead_code)]
    pub fn base(&self) -> Option<&ChainImage> {
        self.images.last()
    }

    /// Add an image to the chain
    pub fn push(&mut self, image: ChainImage) {
        self.images.push(image);
    }

    /// Get all images as a slice
    pub fn images(&self) -> &[ChainImage] {
        &self.images
    }
}

impl Default for BackingChain {
    fn default() -> Self {
        Self::new()
    }
}

/// Errors that can occur during chain discovery
#[derive(Debug)]
pub enum ChainError {
    /// Failed to run the info operation
    InfoOperationFailed(String),
    /// Backing file path is outside allowed directories
    BackingFileNotAllowed {
        path: PathBuf,
        allowed: Vec<PathBuf>,
    },
    /// Backing file does not exist
    BackingFileNotFound(PathBuf),
    /// Chain depth exceeds maximum
    ChainTooDeep { depth: u32, max: u32 },
    /// Circular reference detected in backing chain
    CircularReference(PathBuf),
    /// Failed to resolve backing file path
    PathResolutionError(String),
    /// Input format is detected (and describable by the `info` op) but has
    /// no read path, so treating it as raw would silently misrepresent its
    /// contents. Carries the detected format string reported by info.
    UnsupportedInputFormat(String),
    /// I/O error
    IoError(std::io::Error),
}

impl std::fmt::Display for ChainError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ChainError::InfoOperationFailed(msg) => {
                write!(f, "Info operation failed: {msg}")
            }
            ChainError::BackingFileNotAllowed { path, allowed } => {
                write!(
                    f,
                    "Backing file '{}' is outside allowed paths: {:?}",
                    path.display(),
                    allowed
                )
            }
            ChainError::BackingFileNotFound(path) => {
                write!(f, "Backing file not found: {}", path.display())
            }
            ChainError::ChainTooDeep { depth, max } => {
                write!(f, "Backing chain depth {depth} exceeds maximum of {max}")
            }
            ChainError::CircularReference(path) => {
                write!(f, "Circular reference detected: {}", path.display())
            }
            ChainError::PathResolutionError(msg) => {
                write!(f, "Path resolution error: {msg}")
            }
            ChainError::UnsupportedInputFormat(fmt) => {
                write!(
                    f,
                    "input format '{fmt}' is detected but not supported for reading \
                     (detection and info only)"
                )
            }
            ChainError::IoError(e) => write!(f, "I/O error: {e}"),
        }
    }
}

impl std::error::Error for ChainError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ChainError::IoError(e) => Some(e),
            _ => None,
        }
    }
}

impl From<std::io::Error> for ChainError {
    fn from(e: std::io::Error) -> Self {
        ChainError::IoError(e)
    }
}

/// Result of running the info operation on a single image.
///
/// This is an intermediate type used during chain discovery.
#[derive(Debug, Clone)]
pub struct InfoOperationResult {
    /// The format string from the info operation
    pub format: String,
    /// Virtual size in bytes
    pub virtual_size: u64,
    /// Actual/disk size in bytes
    pub actual_size: u64,
    /// Cluster size in bytes (0 for raw)
    pub cluster_size: u32,
    /// Feature flags
    pub flags: u32,
    /// Backing file path (if any)
    pub backing_file: Option<String>,
    /// External data file path (if any, QCOW2 v3)
    pub external_data_file: Option<String>,
}

/// The most symbolic links one resolution follows. It matches Linux's
/// own limit (`MAXSYMLINKS`), past which the kernel answers `ELOOP`.
const MAX_SYMLINK_HOPS: u32 = 40;

/// Normalise a path without touching the filesystem.
///
/// `.` components are dropped and `..` removes the component before
/// it. At the root `..` is clamped, as the kernel does, so `/..` is
/// `/`. A relative path keeps any leading `..` it cannot resolve.
///
/// This is not the kernel's answer when the component before a `..`
/// is a symlink, so the result only ever decides things that must be
/// settled before the filesystem is looked at: whether a backing
/// reference is worth walking at all, and what an error names. Where
/// a reference actually leads is decided by `walk_within_allowlist`,
/// which resolves `..` physically, after the symlinks before it.
fn normalize_lexically(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Prefix(_) | Component::RootDir => out.push(component.as_os_str()),
            Component::CurDir => {}
            Component::ParentDir => match out.components().next_back() {
                Some(Component::Normal(_)) => {
                    out.pop();
                }
                Some(Component::RootDir) | Some(Component::Prefix(_)) => {}
                _ => out.push(".."),
            },
            Component::Normal(name) => out.push(name),
        }
    }
    out
}

/// The path a backing reference names, built without touching the
/// filesystem: the reference itself when it is absolute, otherwise
/// the reference joined to `parent_dir`, normalised either way.
/// `parent_dir` must already be absolute.
///
/// This is the spelling the allowlist pre-check judges and errors
/// print. It is never itself walked; see `normalize_lexically`.
fn lexical_backing_candidate(parent_dir: &Path, reference: &str) -> PathBuf {
    // `join` replaces the base outright when the reference is absolute.
    normalize_lexically(&parent_dir.join(reference))
}

/// The backing-file allowlist, with every entry in both of its
/// spellings.
///
/// Entries are operator configuration rather than image data, so
/// canonicalising them answers nothing an image could ask. The
/// canonical spelling is what the physical path a resolution ends at
/// is compared with, and is the final word.
///
/// The lexical spelling is kept for one case: an operator-configured
/// entry spelled through a symlink, such as `/srv/images` where `/srv`
/// links elsewhere. Images built there carry absolute references in
/// that same spelling, and without it they would be judged outside
/// the allowlist and sent to the file-name fallback, which only finds
/// a base sitting directly beside the image. The same goes for the
/// operator's spelling of the image's directory, which
/// `validate_backing_path` adds beside the canonical `$IMAGE_DIR`.
/// Relative references never need it, since they are joined to the
/// canonical directory.
///
/// A lexical spelling is only kept when it names the same place as
/// the entry. Without `..` it does: symlinks along it are resolved
/// wherever they lead. A `..` after a symlink is where the two part,
/// because the kernel applies it to the symlink's target, so
/// `/e/link/../b` with `link -> /e/x/y` is `/e/x/b`, while its lexical
/// form `/e/b` is some other directory, one the walk would then treat
/// as allowlisted. An entry spelled with `..` is matched in its
/// canonical form alone.
struct AllowlistForms {
    lexical: Vec<PathBuf>,
    canonical: Vec<PathBuf>,
}

impl AllowlistForms {
    fn new(allowlist: &[PathBuf]) -> Self {
        let lexical = allowlist
            .iter()
            .filter_map(|entry| std::path::absolute(entry).ok())
            .filter(|entry| {
                !entry
                    .components()
                    .any(|component| component == Component::ParentDir)
            })
            .map(|entry| normalize_lexically(&entry))
            .collect();
        let canonical = allowlist
            .iter()
            .filter_map(|entry| entry.canonicalize().ok())
            .collect();
        AllowlistForms { lexical, canonical }
    }

    fn entries(&self) -> impl Iterator<Item = &PathBuf> {
        self.lexical.iter().chain(self.canonical.iter())
    }

    /// Whether `path` is under an entry, judged from its spelling alone.
    ///
    /// The path is normalised here rather than trusted to arrive
    /// normalised: `Path::starts_with` compares components without
    /// resolving `..`, so `/imgs/../etc/x` "starts with" `/imgs`. A
    /// relative path is never allowed, because what it names depends on
    /// the working directory.
    fn lexically_allows(&self, path: &Path) -> bool {
        if !path.is_absolute() {
            return false;
        }
        let path = normalize_lexically(path);
        self.entries().any(|entry| path.starts_with(entry))
    }

    /// Whether a resolution may look at the path `path`, which is a
    /// symlink-free directory with one more name added: it is under an
    /// entry, or it is one of the directories leading to an entry,
    /// which are operator configuration too.
    ///
    /// Being under a lexical spelling is as good as being under the
    /// canonical one here. If `path` is under a lexical entry and is not
    /// the entry itself, the entry is a prefix of the symlink-free
    /// directory, so it has no symlinks and, having no `..` either, is
    /// its own canonical form.
    fn may_probe(&self, path: &Path) -> bool {
        self.entries()
            .any(|entry| path.starts_with(entry) || entry.starts_with(path))
    }

    /// Whether a symlink-free physical path is under an entry's
    /// canonical form, which is the final word on where a file is.
    fn physically_allows(&self, path: &Path) -> bool {
        self.canonical.iter().any(|entry| path.starts_with(entry))
    }
}

/// One component still to be walked by `walk_within_allowlist`.
enum WalkStep {
    Into(std::ffi::OsString),
    Up,
}

/// Push `path`'s components onto `pending` so that the first of them
/// is popped first.
fn push_walk_steps(pending: &mut Vec<WalkStep>, path: &Path) {
    for component in path.components().rev() {
        match component {
            Component::Normal(name) => pending.push(WalkStep::Into(name.to_os_string())),
            Component::ParentDir => pending.push(WalkStep::Up),
            Component::CurDir | Component::RootDir | Component::Prefix(_) => {}
        }
    }
}

/// How a walk of a path whose spelling passed the lexical check ended.
#[derive(Debug, PartialEq)]
enum Walk {
    /// The physical path: absolute, symlink-free and allowlisted.
    Found(PathBuf),
    /// A component inside the allowlist is missing or unreadable.
    Missing,
    /// The path leads out of the allowlist, by a symlink or a `..`.
    Escapes,
    /// More than `MAX_SYMLINK_HOPS` symlinks were followed. They were
    /// all inside the allowlist or on the operator-configured
    /// directories leading to an entry, never an image-chosen path
    /// outside it.
    Loop,
}

/// Resolve the absolute path `path` to a physical path as
/// `canonicalize` would, but one component at a time, and never look
/// at an image-chosen path outside the allowlist.
///
/// `canonicalize` follows a symlink wherever it points, so whether it
/// succeeds can depend on a path outside the allowlist. With a link to
/// `/etc` inside the image directory, `link/shadow` would canonicalise
/// and `link/nosuch` would not, and a link to a missing directory
/// outside would turn into one that resolves when that directory
/// appears. Walking by hand lets each name be checked before it is
/// looked at: a name that would leave the allowlist, reached through a
/// symlink's target or a `..`, ends the walk as `Escapes`, unprobed, so
/// the result depends only on what is inside the allowlist. The only
/// paths outside it that are looked at are the directories leading to
/// each entry, which the operator chose, not the image. Every failure
/// to read a component -- missing, permission denied, not a directory
/// -- is `Missing`, so no error kind becomes a third answer either.
///
/// `..` is applied to the physical directory reached so far, after any
/// symlinks before it have been followed, as the kernel applies it. So
/// `path` is walked as spelled, not lexically normalised first:
/// normalising would turn `link/../x` into `x` beside `link`, where the
/// kernel, and qemu-img, open `x` beside the link's target.
fn walk_within_allowlist(path: &Path, forms: &AllowlistForms) -> Walk {
    debug_assert!(path.is_absolute(), "{}", path.display());
    let mut pending = Vec::new();
    push_walk_steps(&mut pending, path);
    let mut physical = PathBuf::from("/");
    let mut hops = 0;

    while let Some(step) = pending.pop() {
        let name = match step {
            WalkStep::Into(name) => name,
            WalkStep::Up => {
                // `physical` contains no symlinks, so dropping its last
                // component is exactly what the kernel does with `..`.
                physical.pop();
                continue;
            }
        };
        let next = physical.join(name);
        if !forms.may_probe(&next) {
            return Walk::Escapes;
        }
        let is_symlink = match std::fs::symlink_metadata(&next) {
            Ok(meta) => meta.file_type().is_symlink(),
            Err(_) => return Walk::Missing,
        };
        if !is_symlink {
            physical = next;
            continue;
        }

        hops += 1;
        if hops > MAX_SYMLINK_HOPS {
            return Walk::Loop;
        }
        let target = match std::fs::read_link(&next) {
            Ok(target) => target,
            Err(_) => return Walk::Missing,
        };
        // A relative target continues from the link's own directory,
        // which is where `physical` still points.
        if target.is_absolute() {
            physical = PathBuf::from("/");
        }
        push_walk_steps(&mut pending, &target);
    }

    if forms.physically_allows(&physical) {
        Walk::Found(physical)
    } else {
        Walk::Escapes
    }
}

/// Resolve a backing reference read from `parent_image` and check it
/// against `allowlist`.
///
/// The reference is image data. If resolving it answered differently
/// depending on whether some host path outside the allowlist exists,
/// an image could ask about any path on the host and read the answer
/// from the refusal -- which `info --chain` prints while still exiting
/// zero. So the result, the path returned or the error and what it
/// prints, depends only on the filesystem inside the allowlist:
///
/// 1. The candidate path is built and checked against the allowlist
///    from its lexically normalised spelling alone, before anything is
///    looked at. A relative reference outside is refused there.
/// 2. An absolute reference outside is never probed. It goes straight
///    to the reference's file name beside `parent_image`, which keeps
///    images built on another host working; that path faces the same
///    checks, and using it is announced on stderr.
/// 3. A candidate inside is walked component by component, in its
///    spelling as written so that `..` follows the symlinks before it as
///    the kernel's does, refusing any step that leads out. An absolute
///    reference that is inside but missing falls back to its file name
///    in the same way.
///
/// Errors carry the lexical candidate rather than any physical path,
/// so a symlink's target is never printed.
///
/// `parent_image` must be absolute, and its directory symlink-free, so
/// that the lexical candidate built on it means what it says.
///
/// Walking the spelling as written rather than the candidate that
/// passed step 1 cannot make the walk probe an image-chosen name
/// outside the allowlist, because the pre-check is not what keeps the
/// walk in. Every filesystem access the walk makes is to a path that
/// `AllowlistForms::may_probe` admitted first, and a `..` only pops a
/// component off the physical path, looking at nothing. So whichever
/// way the spelling's `..` and symlinks land, each probe is under an
/// entry or is one of the operator's directories leading to one, and
/// the end of the walk must still pass `physically_allows`. The
/// pre-check only decides whether a walk is worth starting and whether
/// an absolute reference goes to the fallback, from nothing but the
/// reference's spelling, so it cannot add an answer either. A reference
/// that passes it can still be refused by the walk: with `up -> ..` in
/// the image directory, `up/sibling` is lexically inside, but its walk
/// reaches the parent of the image directory and is refused there
/// before `sibling` is looked at.
///
/// `extra_spellings` are further operator-given spellings of entries
/// already in `allowlist`. They take part in the checks but are not
/// printed, since `allowlist` already names the same directories.
fn resolve_backing_path(
    parent_image: &Path,
    backing_path: &str,
    allowlist: &[PathBuf],
    extra_spellings: &[PathBuf],
) -> Result<PathBuf, ChainError> {
    let entries: Vec<PathBuf> = allowlist.iter().chain(extra_spellings).cloned().collect();
    let forms = AllowlistForms::new(&entries);
    let parent_dir = parent_image
        .parent()
        .ok_or_else(|| ChainError::PathResolutionError("no parent directory".to_string()))?;
    let candidate = lexical_backing_candidate(parent_dir, backing_path);
    // `join` replaces the base outright when the reference is absolute.
    let as_written = parent_dir.join(backing_path);
    let not_allowed = |path: PathBuf| ChainError::BackingFileNotAllowed {
        path,
        allowed: allowlist.to_vec(),
    };

    let inside = forms.lexically_allows(&candidate);
    if inside {
        match walk_within_allowlist(&as_written, &forms) {
            Walk::Found(resolved) => return Ok(resolved),
            Walk::Escapes => return Err(not_allowed(candidate)),
            Walk::Loop => {
                return Err(ChainError::PathResolutionError(format!(
                    "{}: too many levels of symbolic links",
                    candidate.display()
                )))
            }
            Walk::Missing => {}
        }
    }

    let reference = Path::new(backing_path);
    if !reference.is_absolute() {
        return Err(if inside {
            ChainError::BackingFileNotFound(candidate)
        } else {
            not_allowed(candidate)
        });
    }

    // An absolute reference that is missing, or that was never looked
    // at because it is outside the allowlist: try its file name beside
    // the image, for images built on a host with another layout. Any
    // failure here reports the reference itself, so whether a file of
    // that name sits beside the image is not a separate answer.
    if let Some(name) = reference.file_name() {
        // A file name has no `..` or `/`, so this spelling is already
        // normal.
        let fallback = parent_dir.join(name);
        if forms.lexically_allows(&fallback) {
            if let Walk::Found(resolved) = walk_within_allowlist(&fallback, &forms) {
                eprintln!(
                    "instar: using '{}' beside the image in place of '{}'",
                    name.to_string_lossy(),
                    backing_path
                );
                return Ok(resolved);
            }
        }
    }

    Err(if inside {
        ChainError::BackingFileNotFound(candidate)
    } else {
        not_allowed(candidate)
    })
}

/// Validate a backing file reference read from `parent_image`, and
/// return the physical path of the file it names if that is allowed.
///
/// `backing_path` is untrusted image data. See `resolve_backing_path`
/// for the order checks run in and why it matters. `parent_image` is
/// trusted: the operator's input, or a path this function returned.
/// Its directory is canonicalised before use, and a failure to do so
/// is a `PathResolutionError`. `$IMAGE_DIR` is that canonical
/// directory, and is also matched as the caller spelled it, unless
/// that spelling contains `..`.
pub fn validate_backing_path(
    parent_image: &Path,
    backing_path: &str,
    security_config: &SecurityConfig,
) -> Result<PathBuf, ChainError> {
    // The image's directory is canonicalised, so that both `$IMAGE_DIR`
    // and the base relative references are joined to are physical paths
    // whose lexical form means what it says. As spelled, a `..` after a
    // symlink (`a/link/../b`) names one directory to the kernel and
    // another to a lexical comparison, and the walk would then probe
    // image-chosen names under the wrong one. Probing this directory is
    // safe: `parent_image` is the operator's input, or a path an earlier
    // resolution already validated, never a name the image chose.
    //
    // Only the directory is canonicalised, not the image's own file
    // name. A top image that is itself a symlink keeps the directory it
    // was named in, so relative references are found beside the link,
    // as qemu-img finds them.
    let resolution_error = |e: std::io::Error| {
        ChainError::PathResolutionError(format!("{}: {}", parent_image.display(), e))
    };
    let spelled_parent = std::path::absolute(parent_image).map_err(resolution_error)?;
    let canonical_parent = match (spelled_parent.parent(), spelled_parent.file_name()) {
        (Some(dir), Some(name)) => dir.canonicalize().map_err(resolution_error)?.join(name),
        _ => {
            return Err(resolution_error(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "not a path to a file",
            )))
        }
    };
    let allowlist = get_backing_allowlist(security_config, &canonical_parent);

    // `$IMAGE_DIR` is also matched in the operator's own spelling of the
    // image's directory, when that differs from the canonical one and
    // has no `..`. An image built in a directory reached through a
    // symlink carries absolute references in that spelling, including
    // ones into its subdirectories, which the file-name fallback cannot
    // find. A spelling without `..` names the same directory as the
    // canonical form, so it admits nothing the canonical form does not;
    // one with `..` might not, and is left out.
    let spelled_allowlist = get_backing_allowlist(security_config, &spelled_parent);
    let extra_spellings: Vec<PathBuf> = spelled_allowlist
        .into_iter()
        .zip(&allowlist)
        .filter(|(spelled, canonical)| spelled != *canonical)
        .map(|(spelled, _)| spelled)
        .filter(|spelled| {
            !spelled
                .components()
                .any(|component| component == Component::ParentDir)
        })
        .collect();

    resolve_backing_path(
        &canonical_parent,
        backing_path,
        &allowlist,
        &extra_spellings,
    )
}

/// Maximum bytes of descriptor text the VMM will read from disk
/// when resolving a VMDK monolithicFlat descriptor. qemu-img emits
/// descriptors well under 4 KB; capping small keeps the host-side
/// parse cheap and bounds the memory taken by an untrusted file.
pub const MAX_DESCRIPTOR_BYTES: usize = 8192;

/// A single resolved flat extent within a VMDK descriptor.
#[derive(Debug, Clone)]
pub struct ResolvedVmdkExtent {
    /// Absolute, allowlist-validated path to the flat extent file.
    pub flat_path: PathBuf,
    /// Size of this extent in bytes (extent `size_sectors` × 512).
    pub extent_size: u64,
}

/// Result of resolving a VMDK flat descriptor on the host.
#[derive(Debug, Clone)]
pub struct ResolvedVmdkDescriptor {
    /// Ordered flat extent files. For monolithicFlat, length 1;
    /// for twoGbMaxExtentFlat, length N.
    pub flat_extents: Vec<ResolvedVmdkExtent>,
    /// Total virtual size across all extents in bytes.
    pub virtual_size: u64,
    /// Parent filename hint from descriptor, if present.
    /// Analogous to QCOW2 backing-filename.
    pub parent_hint: Option<String>,
}

/// Read a VMDK flat descriptor, validate it, and resolve its flat
/// extent file(s) against the backing-file allowlist.
///
/// Supports both monolithicFlat (single extent) and
/// twoGbMaxExtentFlat (multiple extents). All extents must be of
/// kind `FLAT` with `offset_sectors == 0`.
///
/// If the descriptor contains a `parentFileNameHint=` line, the
/// hint is returned in `parent_hint` so the caller can continue
/// chain discovery.
///
/// Each extent filename is resolved relative to the descriptor's
/// directory and validated against the security allowlist.
pub fn resolve_vmdk_flat_descriptor(
    descriptor_path: &Path,
    security_config: &SecurityConfig,
) -> Result<ResolvedVmdkDescriptor, ChainError> {
    use std::io::Read;

    let mut file = std::fs::File::open(descriptor_path)?;
    let mut buf = [0u8; MAX_DESCRIPTOR_BYTES];
    let n = file.read(&mut buf)?;
    let text = core::str::from_utf8(&buf[..n]).map_err(|e| {
        ChainError::PathResolutionError(format!(
            "VMDK descriptor '{}' is not valid UTF-8: {}",
            descriptor_path.display(),
            e
        ))
    })?;

    // Extract parentFileNameHint if present.
    let mut parent_hint: Option<String> = None;
    for line in text.lines() {
        let trimmed = line.trim_start();
        if let Some(rest) = trimmed.strip_prefix("parentFileNameHint=") {
            let hint = rest.trim_matches('"').trim();
            if !hint.is_empty() {
                parent_hint = Some(hint.to_string());
            }
        }
    }

    let extents = vmdk::parse_descriptor_extents(text).map_err(|e| {
        ChainError::PathResolutionError(format!(
            "VMDK descriptor '{}' has malformed extent lines: {:?}",
            descriptor_path.display(),
            e
        ))
    })?;

    let mut flat_extents = Vec::with_capacity(extents.len());
    let mut virtual_size: u64 = 0;

    for i in 0..extents.len() {
        let extent = extents.get(i).expect("index < len");

        if extent.kind != vmdk::ExtentKind::Flat {
            return Err(ChainError::PathResolutionError(format!(
                "VMDK descriptor '{}' extent {} has kind {:?}; \
                 only FLAT extents are supported",
                descriptor_path.display(),
                i,
                extent.kind
            )));
        }

        if extent.offset_sectors != 0 {
            return Err(ChainError::PathResolutionError(format!(
                "VMDK descriptor '{}' extent {} has non-zero \
                 offset ({} sectors); only offset-0 extents \
                 are supported",
                descriptor_path.display(),
                i,
                extent.offset_sectors
            )));
        }

        if extent.filename.is_empty() {
            return Err(ChainError::PathResolutionError(format!(
                "VMDK descriptor '{}' extent {} has no filename",
                descriptor_path.display(),
                i,
            )));
        }

        let flat_path = validate_backing_path(descriptor_path, extent.filename, security_config)?;

        let extent_size = extent.size_sectors.checked_mul(512).ok_or_else(|| {
            ChainError::PathResolutionError(format!(
                "VMDK descriptor '{}' extent {} size overflows u64",
                descriptor_path.display(),
                i,
            ))
        })?;

        virtual_size = virtual_size.checked_add(extent_size).ok_or_else(|| {
            ChainError::PathResolutionError(format!(
                "VMDK descriptor '{}' total virtual size overflows u64",
                descriptor_path.display()
            ))
        })?;

        flat_extents.push(ResolvedVmdkExtent {
            flat_path,
            extent_size,
        });
    }

    Ok(ResolvedVmdkDescriptor {
        flat_extents,
        virtual_size,
        parent_hint,
    })
}

/// Peek at `path` and return true if its first bytes match a VMDK
/// descriptor prefix. Returns Ok(false) on short files or files the
/// VMM can't open; callers should treat that as "not a descriptor"
/// and proceed to existing format detection.
pub fn peek_is_vmdk_descriptor(path: &Path) -> std::io::Result<bool> {
    use std::io::Read;

    let mut file = std::fs::File::open(path)?;
    let mut buf = [0u8; 64];
    let n = file.read(&mut buf)?;
    Ok(n >= VMDK_DESCRIPTOR_MAGIC.len()
        && &buf[..VMDK_DESCRIPTOR_MAGIC.len()] == VMDK_DESCRIPTOR_MAGIC)
}

/// Peek at `path` and return true if it is a qcow2 v3 image
/// (magic = "QFI\xfb", version = 3). Used host-side to decide
/// whether `measure -O qcow2` should emit the `bitmaps` field —
/// qemu-img only emits it for qcow2 v3 sources because persistent
/// bitmaps are a v3 feature. Returns false on short files, files
/// we can't open, non-qcow2 files, or qcow2 v2 files.
pub fn peek_is_qcow2_v3(path: &str) -> bool {
    use std::io::Read;

    let mut file = match std::fs::File::open(path) {
        Ok(f) => f,
        Err(_) => return false,
    };
    // Header layout: magic[4] | version[4] (big-endian u32).
    let mut buf = [0u8; 8];
    if file.read(&mut buf).unwrap_or(0) < 8 {
        return false;
    }
    // QCOW2 magic: "QFI\xfb" = 0x51_46_49_FB.
    if buf[..4] != [0x51, 0x46, 0x49, 0xfb] {
        return false;
    }
    let version = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
    version == 3
}

/// Check chain depth and return error if exceeded.
pub fn check_chain_depth(
    current_depth: usize,
    security_config: &SecurityConfig,
) -> Result<(), ChainError> {
    let max_depth = get_max_chain_depth(security_config);
    if current_depth >= max_depth as usize {
        return Err(ChainError::ChainTooDeep {
            depth: current_depth as u32 + 1,
            max: max_depth,
        });
    }
    Ok(())
}

/// Check for circular references in the chain.
pub fn check_circular_reference(path: &Path, seen_paths: &[PathBuf]) -> Result<(), ChainError> {
    let canonical = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
    if seen_paths.contains(&canonical) {
        return Err(ChainError::CircularReference(canonical));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_image_format_from_str() {
        assert_eq!(ImageFormat::from_str("raw"), ImageFormat::Raw);
        assert_eq!(ImageFormat::from_str("qcow2"), ImageFormat::Qcow2);
        assert_eq!(ImageFormat::from_str("vpc"), ImageFormat::Vhd);
        assert_eq!(
            ImageFormat::from_str("unknown_format"),
            ImageFormat::Unknown
        );
    }

    #[test]
    fn test_format_supports_backing() {
        assert!(ImageFormat::Qcow2.supports_backing());
        assert!(ImageFormat::Qcow1.supports_backing());
        assert!(!ImageFormat::Raw.supports_backing());
        assert!(!ImageFormat::Vhd.supports_backing());
    }

    #[test]
    fn test_backing_chain_operations() {
        let mut chain = BackingChain::new();
        assert!(chain.is_empty());
        assert_eq!(chain.len(), 0);

        chain.push(ChainImage {
            path: PathBuf::from("/test/top.qcow2"),
            format: ImageFormat::Qcow2,
            virtual_size: 1024 * 1024 * 1024,
            actual_size: 512 * 1024,
            cluster_size: 65536,
            backing_file_raw: Some("base.qcow2".to_string()),
            flags: 0,
            external_data_files: Vec::new(),
        });

        chain.push(ChainImage {
            path: PathBuf::from("/test/base.qcow2"),
            format: ImageFormat::Qcow2,
            virtual_size: 1024 * 1024 * 1024,
            actual_size: 100 * 1024 * 1024,
            cluster_size: 65536,
            backing_file_raw: None,
            flags: 0,
            external_data_files: Vec::new(),
        });

        assert!(!chain.is_empty());
        assert_eq!(chain.len(), 2);
        assert!(chain.top().unwrap().path.ends_with("top.qcow2"));
        assert!(chain.base().unwrap().path.ends_with("base.qcow2"));
    }

    #[test]
    fn test_resolve_relative_backing_path() {
        let tmp = TempDir::new().unwrap();
        let parent = tmp.path().join("images/top.qcow2");
        std::fs::create_dir_all(parent.parent().unwrap()).unwrap();
        std::fs::write(&parent, b"").unwrap();

        // Create the backing file
        let backing = tmp.path().join("images/base.qcow2");
        std::fs::write(&backing, b"").unwrap();

        let resolved =
            validate_backing_path(&parent, "base.qcow2", &default_security_config()).unwrap();
        assert_eq!(resolved, backing.canonicalize().unwrap());
    }

    #[test]
    fn test_resolve_absolute_backing_path() {
        // The reference is spelled physically: one spelled through a
        // symlinked temporary directory is outside the allowlist as
        // written, since the image's directory is canonicalised.
        let tmp = TempDir::new().unwrap();
        let root = tmp.path().canonicalize().unwrap();
        let parent = root.join("top.qcow2");
        std::fs::write(&parent, b"").unwrap();

        let backing = root.join("other/base.qcow2");
        std::fs::create_dir_all(backing.parent().unwrap()).unwrap();
        std::fs::write(&backing, b"").unwrap();

        let resolved = validate_backing_path(
            &parent,
            backing.to_str().unwrap(),
            &default_security_config(),
        )
        .unwrap();
        assert_eq!(resolved, backing.canonicalize().unwrap());
    }

    #[test]
    fn test_backing_file_not_found() {
        let tmp = TempDir::new().unwrap();
        let parent = tmp.path().join("top.qcow2");
        std::fs::write(&parent, b"").unwrap();

        let result =
            validate_backing_path(&parent, "nonexistent.qcow2", &default_security_config());
        assert!(matches!(result, Err(ChainError::BackingFileNotFound(_))));
    }

    #[test]
    fn test_absolute_path_fallback_to_filename() {
        // Simulate an image created on a different machine with an absolute path
        // that doesn't exist on this machine. The fallback should find the file
        // by its filename in the parent image's directory.
        let tmp = TempDir::new().unwrap();
        let images_dir = tmp.path().join("images");
        std::fs::create_dir_all(&images_dir).unwrap();

        let parent = images_dir.join("top.qcow2");
        std::fs::write(&parent, b"").unwrap();

        // Create the backing file in the same directory as the parent
        let backing = images_dir.join("base.qcow2");
        std::fs::write(&backing, b"").unwrap();

        // Use a non-existent absolute path that has the same filename
        let nonexistent_absolute = "/some/other/machine/path/base.qcow2";
        let resolved =
            validate_backing_path(&parent, nonexistent_absolute, &default_security_config())
                .unwrap();

        // Should fall back to finding base.qcow2 in the parent's directory
        assert_eq!(resolved, backing.canonicalize().unwrap());
    }

    #[test]
    fn test_absolute_path_inside_allowlist_used_when_exists() {
        // An absolute reference inside the allowlist is used as named,
        // even with a file of the same name beside the image.
        let tmp = TempDir::new().unwrap();
        let root = tmp.path().canonicalize().unwrap();

        // Create parent image
        let parent = root.join("top.qcow2");
        std::fs::write(&parent, b"").unwrap();

        // Create backing file at an absolute path under the image dir
        let other_dir = root.join("other");
        std::fs::create_dir_all(&other_dir).unwrap();
        let backing_absolute = other_dir.join("base.qcow2");
        std::fs::write(&backing_absolute, b"absolute").unwrap();

        // Also create a file with same name in parent's directory
        let backing_local = root.join("base.qcow2");
        std::fs::write(&backing_local, b"local").unwrap();

        // Should use the absolute path, not the local file
        let resolved = validate_backing_path(
            &parent,
            backing_absolute.to_str().unwrap(),
            &default_security_config(),
        )
        .unwrap();
        assert_eq!(resolved, backing_absolute.canonicalize().unwrap());
    }

    #[test]
    fn test_absolute_path_outside_allowlist_uses_local_file() {
        // An absolute reference outside the allowlist is never looked
        // at, even when it exists: the file of the same name beside the
        // image is used instead.
        let tmp = TempDir::new().unwrap();
        let images = tmp.path().join("images");
        let outside = tmp.path().join("outside");
        std::fs::create_dir_all(&images).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        let parent = images.join("top.qcow2");
        std::fs::write(&parent, b"").unwrap();
        let backing_local = images.join("base.qcow2");
        std::fs::write(&backing_local, b"local").unwrap();
        let backing_outside = outside.join("base.qcow2");
        std::fs::write(&backing_outside, b"outside").unwrap();

        let resolved = validate_backing_path(
            &parent,
            backing_outside.to_str().unwrap(),
            &default_security_config(),
        )
        .unwrap();
        assert_eq!(resolved, backing_local.canonicalize().unwrap());
    }

    #[test]
    fn test_absolute_path_inside_allowlist_missing_falls_back() {
        let tmp = TempDir::new().unwrap();
        let parent = tmp.path().join("top.qcow2");
        std::fs::write(&parent, b"").unwrap();
        let backing_local = tmp.path().join("base.qcow2");
        std::fs::write(&backing_local, b"").unwrap();
        let missing = tmp.path().join("moved/base.qcow2");

        let resolved = validate_backing_path(
            &parent,
            missing.to_str().unwrap(),
            &default_security_config(),
        )
        .unwrap();
        assert_eq!(resolved, backing_local.canonicalize().unwrap());
    }

    #[test]
    fn test_absolute_path_fallback_not_found() {
        // An absolute reference outside the allowlist with no file of
        // its name beside the image is refused as outside the
        // allowlist. It used to answer "not found", but that was only
        // true when the path happened not to exist on this host.
        let tmp = TempDir::new().unwrap();
        let parent = tmp.path().join("top.qcow2");
        std::fs::write(&parent, b"").unwrap();

        let result = validate_backing_path(
            &parent,
            "/nonexistent/path/base.qcow2",
            &default_security_config(),
        );
        match result {
            Err(ChainError::BackingFileNotAllowed { path, .. }) => {
                assert_eq!(path, PathBuf::from("/nonexistent/path/base.qcow2"))
            }
            other => panic!("expected BackingFileNotAllowed, got {other:?}"),
        }
    }

    // ====================================================================
    // Backing resolution never depends on what is outside the allowlist
    // ====================================================================

    /// The observable outcome of a resolution: the path, or the error
    /// variant and exactly what it prints.
    fn outcome(result: &Result<PathBuf, ChainError>) -> String {
        match result {
            Ok(path) => format!("Ok({})", path.display()),
            Err(e) => format!("Err({:?}: {e})", std::mem::discriminant(e)),
        }
    }

    /// An image directory and a sibling directory outside the default
    /// `$IMAGE_DIR` allowlist.
    struct Layout {
        _tmp: TempDir,
        images: PathBuf,
        outside: PathBuf,
        parent: PathBuf,
    }

    fn layout() -> Layout {
        let tmp = TempDir::new().unwrap();
        let images = tmp.path().join("images");
        let outside = tmp.path().join("outside");
        std::fs::create_dir_all(&images).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        let parent = images.join("top.qcow2");
        std::fs::write(&parent, b"").unwrap();
        Layout {
            _tmp: tmp,
            images,
            outside,
            parent,
        }
    }

    /// Resolve `reference` with `target` absent, then present, and
    /// return both outcomes.
    fn resolve_absent_then_present(
        parent: &Path,
        reference: &str,
        target: &Path,
    ) -> (String, String) {
        let cfg = default_security_config();
        assert!(!target.exists());
        let absent = outcome(&validate_backing_path(parent, reference, &cfg));
        std::fs::write(target, b"secret").unwrap();
        let present = outcome(&validate_backing_path(parent, reference, &cfg));
        (absent, present)
    }

    #[test]
    fn invariant_absolute_reference_outside() {
        let l = layout();
        let target = l.outside.join("secret.qcow2");
        let (absent, present) =
            resolve_absent_then_present(&l.parent, target.to_str().unwrap(), &target);
        assert_eq!(absent, present);
        assert!(absent.contains("is outside allowed paths"), "{absent}");
    }

    #[test]
    fn invariant_relative_dotdot_escape() {
        let l = layout();
        let target = l.outside.join("secret.qcow2");
        let (absent, present) =
            resolve_absent_then_present(&l.parent, "../outside/secret.qcow2", &target);
        assert_eq!(absent, present);
        assert!(absent.contains("is outside allowed paths"), "{absent}");
    }

    #[test]
    fn invariant_symlink_inside_allowlist_escape() {
        let l = layout();
        std::os::unix::fs::symlink(&l.outside, l.images.join("link")).unwrap();
        let target = l.outside.join("secret.qcow2");
        let (absent, present) =
            resolve_absent_then_present(&l.parent, "link/secret.qcow2", &target);
        assert_eq!(absent, present);
        assert!(absent.contains("is outside allowed paths"), "{absent}");
        // The error names the reference, never where the link points.
        assert!(!absent.contains("outside/secret"), "{absent}");
    }

    #[test]
    fn invariant_symlink_to_missing_directory_outside() {
        // A link whose target directory is absent does not resolve, and
        // `canonicalize` would then report the reference missing; once
        // the directory appears it would report it outside. The answer
        // must not change when the outside directory appears.
        let l = layout();
        let target_dir = l.outside.join("dir");
        std::os::unix::fs::symlink(&target_dir, l.images.join("link")).unwrap();
        let cfg = default_security_config();
        let absent = outcome(&validate_backing_path(&l.parent, "link/secret.qcow2", &cfg));
        std::fs::create_dir_all(&target_dir).unwrap();
        let present = outcome(&validate_backing_path(&l.parent, "link/secret.qcow2", &cfg));
        assert_eq!(absent, present);
        assert!(absent.contains("is outside allowed paths"), "{absent}");
        assert!(!absent.contains("outside/dir"), "{absent}");
    }

    #[test]
    fn invariant_absolute_reference_with_basename_fallback() {
        let l = layout();
        let local = l.images.join("secret.qcow2");
        std::fs::write(&local, b"local").unwrap();
        let target = l.outside.join("secret.qcow2");
        let (absent, present) =
            resolve_absent_then_present(&l.parent, target.to_str().unwrap(), &target);
        assert_eq!(absent, present);
        assert_eq!(
            absent,
            format!("Ok({})", local.canonicalize().unwrap().display())
        );
    }

    #[test]
    fn symlink_loop_inside_allowlist_is_an_error() {
        let l = layout();
        std::os::unix::fs::symlink("loop", l.images.join("loop")).unwrap();
        let result = validate_backing_path(&l.parent, "loop", &default_security_config());
        assert!(
            matches!(result, Err(ChainError::PathResolutionError(_))),
            "{result:?}"
        );
    }

    #[test]
    fn symlink_inside_allowlist_to_inside_resolves() {
        let l = layout();
        let base = l.images.join("base.qcow2");
        std::fs::write(&base, b"").unwrap();
        std::fs::create_dir_all(l.images.join("sub")).unwrap();
        std::os::unix::fs::symlink("../base.qcow2", l.images.join("sub/link")).unwrap();

        let resolved =
            validate_backing_path(&l.parent, "sub/link", &default_security_config()).unwrap();
        assert_eq!(resolved, base.canonicalize().unwrap());
    }

    #[test]
    fn symlinked_image_dir_resolves_its_own_children() {
        // The image is named through a symlinked directory. Relative
        // references and absolute references in either spelling must
        // all still resolve.
        let tmp = TempDir::new().unwrap();
        let real = tmp.path().join("real");
        std::fs::create_dir_all(&real).unwrap();
        let via = tmp.path().join("via");
        std::os::unix::fs::symlink(&real, &via).unwrap();
        std::fs::write(real.join("top.qcow2"), b"").unwrap();
        let base = real.join("base.qcow2");
        std::fs::write(&base, b"").unwrap();
        let parent = via.join("top.qcow2");
        let cfg = default_security_config();
        let expected = base.canonicalize().unwrap();

        for reference in [
            "base.qcow2".to_string(),
            via.join("base.qcow2").display().to_string(),
            real.join("base.qcow2").display().to_string(),
        ] {
            let resolved = validate_backing_path(&parent, &reference, &cfg).unwrap();
            assert_eq!(resolved, expected, "reference {reference}");
        }
    }

    #[test]
    fn symlinked_image_dir_resolves_absolute_reference_into_subdirectory() {
        // An image built in a directory reached through a symlink names
        // its base by an absolute path in that spelling, here in a
        // subdirectory. It resolves as named, not through the file-name
        // fallback: a file of the same name beside the image, which the
        // fallback would pick, is not chosen.
        let tmp = TempDir::new().unwrap();
        let real = tmp.path().canonicalize().unwrap().join("real");
        std::fs::create_dir_all(real.join("sub")).unwrap();
        let via = tmp.path().canonicalize().unwrap().join("via");
        std::os::unix::fs::symlink(&real, &via).unwrap();
        std::fs::write(real.join("top.qcow2"), b"").unwrap();
        std::fs::write(real.join("base.qcow2"), b"beside").unwrap();
        let base = real.join("sub/base.qcow2");
        std::fs::write(&base, b"sub").unwrap();

        let reference = via.join("sub/base.qcow2").display().to_string();
        let resolved = validate_backing_path(
            &via.join("top.qcow2"),
            &reference,
            &default_security_config(),
        )
        .unwrap();
        assert_eq!(resolved, base);

        // Only the operator's spelling is added. With the image named
        // through the real directory, nobody spelled `via`, so the same
        // reference is outside the allowlist as written and takes the
        // fallback to the file beside the image.
        let resolved = validate_backing_path(
            &real.join("top.qcow2"),
            &reference,
            &default_security_config(),
        )
        .unwrap();
        assert_eq!(resolved, real.join("base.qcow2"));
    }

    // ====================================================================
    // `..` after a symlink
    // ====================================================================

    /// A tree where `a/link -> x/y`, so `a/link/../b` is `x/b` to the
    /// kernel but `a/b` lexically. Both `a/b` and `x/b` exist.
    struct DotDotLayout {
        _tmp: TempDir,
        root: PathBuf,
        /// `root/a/link/../b`, spelled through the link.
        via_link: PathBuf,
        /// `root/x/b`: where `via_link` really is.
        real: PathBuf,
        /// `root/a/b`: where `via_link` is lexically.
        lexical: PathBuf,
    }

    fn dotdot_layout() -> DotDotLayout {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path().canonicalize().unwrap();
        std::fs::create_dir_all(root.join("x/y")).unwrap();
        std::fs::create_dir_all(root.join("x/b")).unwrap();
        std::fs::create_dir_all(root.join("a/b")).unwrap();
        std::os::unix::fs::symlink(root.join("x/y"), root.join("a/link")).unwrap();
        DotDotLayout {
            via_link: root.join("a/link/../b"),
            real: root.join("x/b"),
            lexical: root.join("a/b"),
            root,
            _tmp: tmp,
        }
    }

    #[test]
    fn allowlist_entry_with_dotdot_keeps_only_its_canonical_form() {
        let l = dotdot_layout();
        let forms = AllowlistForms::new(std::slice::from_ref(&l.via_link));
        assert!(forms.lexical.is_empty(), "{:?}", forms.lexical);
        assert!(forms.lexically_allows(&l.real.join("f")));
        assert!(!forms.lexically_allows(&l.lexical.join("f")));
        assert!(!forms.may_probe(&l.lexical.join("f")));
    }

    #[test]
    fn allowlist_entry_with_dotdot_after_symlink_is_not_an_oracle() {
        // An operator entry spelled `a/link/../b` must not make the
        // lexical directory `a/b` allowlisted, or names under it could
        // be probed and a refusal would differ from a "not found".
        let l = dotdot_layout();
        let parent = l.real.join("top.qcow2");
        std::fs::write(&parent, b"").unwrap();
        let cfg = SecurityConfig {
            backing_path_allowlist: Some(vec![l.via_link.display().to_string()]),
            ..Default::default()
        };
        let target = l.lexical.join("probe");
        for reference in [target.display().to_string(), "../../a/b/probe".to_string()] {
            let absent = outcome(&validate_backing_path(&parent, &reference, &cfg));
            std::fs::write(&target, b"secret").unwrap();
            let present = outcome(&validate_backing_path(&parent, &reference, &cfg));
            std::fs::remove_file(&target).unwrap();
            assert_eq!(absent, present, "reference {reference}");
            assert!(absent.contains("is outside allowed paths"), "{absent}");
        }
    }

    #[test]
    fn image_path_with_dotdot_after_symlink_resolves_where_the_kernel_does() {
        // The image is named `a/link/../b/top.qcow2`, which the kernel
        // opens as `x/b/top.qcow2`. Its relative references belong
        // beside that, and `a/b` is not its directory.
        let l = dotdot_layout();
        std::fs::write(l.real.join("top.qcow2"), b"").unwrap();
        let base = l.real.join("base.qcow2");
        std::fs::write(&base, b"").unwrap();
        let parent = l.via_link.join("top.qcow2");
        let cfg = default_security_config();

        let resolved = validate_backing_path(&parent, "base.qcow2", &cfg).unwrap();
        assert_eq!(resolved, base);

        // Nor can names under the lexical directory be probed.
        let target = l.lexical.join("probe");
        let reference = target.display().to_string();
        let (absent, present) = resolve_absent_then_present(&parent, &reference, &target);
        assert_eq!(absent, present);
        assert!(absent.contains("is outside allowed paths"), "{absent}");
    }

    #[test]
    fn descriptor_named_with_dotdot_after_symlink_finds_its_extent() {
        let l = dotdot_layout();
        let flat = l.real.join("foo-flat.vmdk");
        std::fs::write(
            l.real.join("foo.vmdk"),
            make_flat_descriptor("foo-flat.vmdk", 1),
        )
        .unwrap();
        std::fs::write(&flat, vec![0u8; 512]).unwrap();

        let resolved =
            resolve_vmdk_flat_descriptor(&l.via_link.join("foo.vmdk"), &default_security_config())
                .unwrap();
        assert_eq!(resolved.flat_extents[0].flat_path, flat);
    }

    #[test]
    fn dotdot_after_symlink_in_reference_follows_the_kernel() {
        // `sub/link -> deep/dir`, so `sub/link/../x.raw` is `deep/x.raw`
        // to the kernel and to qemu-img. A file of that name in `sub`
        // must not be chosen instead.
        let l = layout();
        std::fs::create_dir_all(l.images.join("deep/dir")).unwrap();
        std::fs::create_dir_all(l.images.join("sub")).unwrap();
        std::os::unix::fs::symlink("../deep/dir", l.images.join("sub/link")).unwrap();
        std::fs::write(l.images.join("deep/x.raw"), b"deep").unwrap();
        std::fs::write(l.images.join("sub/x.raw"), b"sub").unwrap();
        let reference = "sub/link/../x.raw";
        let kernel = l.images.join(reference).canonicalize().unwrap();
        assert!(kernel.ends_with("deep/x.raw"));

        let resolved =
            validate_backing_path(&l.parent, reference, &default_security_config()).unwrap();
        assert_eq!(resolved, kernel);
    }

    #[test]
    fn dotdot_after_symlink_missing_reports_the_reference() {
        // When the kernel's answer is missing, the error names the
        // reference's lexical spelling, not the physical path.
        let l = layout();
        std::fs::create_dir_all(l.images.join("deep/dir")).unwrap();
        std::fs::create_dir_all(l.images.join("sub")).unwrap();
        std::os::unix::fs::symlink("../deep/dir", l.images.join("sub/link")).unwrap();
        std::fs::write(l.images.join("sub/x.raw"), b"sub").unwrap();

        let result =
            validate_backing_path(&l.parent, "sub/link/../x.raw", &default_security_config());
        match result {
            Err(ChainError::BackingFileNotFound(path)) => {
                assert_eq!(path, l.images.canonicalize().unwrap().join("sub/x.raw"))
            }
            other => panic!("expected BackingFileNotFound, got {other:?}"),
        }
    }

    #[test]
    fn symlink_to_parent_of_image_dir_is_not_an_oracle() {
        // `up -> ..` leads from the image directory to its parent, so
        // `up/<name>` is lexically inside the allowlist but physically
        // a sibling of the image directory. The walk must stop at the
        // sibling without looking at it.
        let l = layout();
        std::os::unix::fs::symlink("..", l.images.join("up")).unwrap();
        let sibling = l.outside.parent().unwrap().join("sibling.qcow2");
        let secret = l.outside.join("secret.qcow2");
        for (reference, target) in [
            ("up/sibling.qcow2", &sibling),
            ("up/outside/secret.qcow2", &secret),
        ] {
            let (absent, present) = resolve_absent_then_present(&l.parent, reference, target);
            assert_eq!(absent, present, "reference {reference}");
            assert!(absent.contains("is outside allowed paths"), "{absent}");
            assert!(absent.contains(&format!("images/{reference}")), "{absent}");
        }
    }

    // ====================================================================
    // Lexical normalisation and the lexical allowlist check
    // ====================================================================

    #[test]
    fn normalize_lexically_cases() {
        let cases = [
            ("/..", "/"),
            ("/../../etc/x", "/etc/x"),
            ("/a/./b/.", "/a/b"),
            ("/a/b/", "/a/b"),
            ("/a/b/../../..", "/"),
            ("a/b/../../..", ".."),
            ("a/./b/../c", "a/c"),
            ("/imgs/../etc/x", "/etc/x"),
        ];
        for (input, expected) in cases {
            assert_eq!(
                normalize_lexically(Path::new(input)),
                PathBuf::from(expected),
                "{input}"
            );
        }
    }

    #[test]
    fn lexical_backing_candidate_cases() {
        let dir = Path::new("/imgs/sub");
        assert_eq!(
            lexical_backing_candidate(dir, "base"),
            PathBuf::from("/imgs/sub/base")
        );
        assert_eq!(
            lexical_backing_candidate(dir, "../base"),
            PathBuf::from("/imgs/base")
        );
        assert_eq!(
            lexical_backing_candidate(dir, "../../../etc/x"),
            PathBuf::from("/etc/x")
        );
        assert_eq!(
            lexical_backing_candidate(dir, "/abs/./x"),
            PathBuf::from("/abs/x")
        );
    }

    #[test]
    fn lexically_allows_resolves_dotdot_before_comparing() {
        // `/imgs` need not exist: only the spelling is compared.
        let forms = AllowlistForms::new(&[PathBuf::from("/imgs")]);
        assert!(!forms.lexically_allows(Path::new("/imgs/../etc/x")));
        assert!(forms.lexically_allows(Path::new("/imgs/a/../b")));
        assert!(forms.lexically_allows(Path::new("/imgs")));
        assert!(!forms.lexically_allows(Path::new("/imgsx/a")));
        assert!(!forms.lexically_allows(Path::new("imgs/a")));
    }

    #[test]
    fn lexically_allows_matches_both_spellings_of_an_entry() {
        let tmp = TempDir::new().unwrap();
        let real = tmp.path().join("real");
        std::fs::create_dir_all(&real).unwrap();
        let via = tmp.path().join("via");
        std::os::unix::fs::symlink(&real, &via).unwrap();

        let forms = AllowlistForms::new(&[via.clone()]);
        assert!(forms.lexically_allows(&via.join("x")));
        assert!(forms.lexically_allows(&real.canonicalize().unwrap().join("x")));
        assert!(!forms.lexically_allows(&tmp.path().join("other/x")));
    }

    #[test]
    fn test_chain_depth_check() {
        let config = SecurityConfig::default(); // max_chain_depth defaults to 16

        // Should pass at depth 15
        assert!(check_chain_depth(15, &config).is_ok());

        // Should fail at depth 16
        assert!(matches!(
            check_chain_depth(16, &config),
            Err(ChainError::ChainTooDeep { .. })
        ));
    }

    #[test]
    fn test_circular_reference_check() {
        let path1 = PathBuf::from("/test/a.qcow2");
        let path2 = PathBuf::from("/test/b.qcow2");

        let seen = vec![path1.clone()];

        // New path should pass
        assert!(check_circular_reference(&path2, &seen).is_ok());

        // Already seen path should fail
        assert!(matches!(
            check_circular_reference(&path1, &seen),
            Err(ChainError::CircularReference(_))
        ));
    }

    // ====================================================================
    // VMDK monolithicFlat descriptor resolution tests
    // ====================================================================

    fn make_flat_descriptor(filename: &str, size_sectors: u64) -> String {
        format!(
            "# Disk DescriptorFile\n\
             version=1\n\
             CID=abcdef01\n\
             parentCID=ffffffff\n\
             createType=\"monolithicFlat\"\n\
             \n\
             # Extent description\n\
             RW {size_sectors} FLAT \"{filename}\" 0\n\
             \n\
             # Disk Data Base\n\
             ddb.adapterType = \"ide\"\n"
        )
    }

    /// Returns a SecurityConfig that treats the image's own directory
    /// as the only allowed backing location. This matches the
    /// default $IMAGE_DIR allowlist and keeps tests self-contained.
    fn default_security_config() -> SecurityConfig {
        SecurityConfig::default()
    }

    #[test]
    fn peek_is_vmdk_descriptor_detects_descriptor() {
        let tmp = TempDir::new().unwrap();
        let desc = tmp.path().join("foo.vmdk");
        std::fs::write(&desc, make_flat_descriptor("foo-flat.vmdk", 1024)).unwrap();

        assert!(peek_is_vmdk_descriptor(&desc).unwrap());
    }

    #[test]
    fn peek_is_vmdk_descriptor_rejects_random_file() {
        let tmp = TempDir::new().unwrap();
        let raw = tmp.path().join("foo.raw");
        std::fs::write(&raw, b"random binary content goes here").unwrap();

        assert!(!peek_is_vmdk_descriptor(&raw).unwrap());
    }

    /// Build the first 8 bytes of a qcow2 header (magic + u32 BE version).
    fn qcow2_magic_bytes(version: u32) -> [u8; 8] {
        let mut buf = [0u8; 8];
        buf[0..4].copy_from_slice(&[0x51, 0x46, 0x49, 0xfb]); // "QFI\xfb"
        buf[4..8].copy_from_slice(&version.to_be_bytes());
        buf
    }

    #[test]
    fn peek_is_qcow2_v3_accepts_v3() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("v3.qcow2");
        std::fs::write(&path, qcow2_magic_bytes(3)).unwrap();
        assert!(peek_is_qcow2_v3(path.to_str().unwrap()));
    }

    #[test]
    fn peek_is_qcow2_v3_rejects_v2() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("v2.qcow2");
        std::fs::write(&path, qcow2_magic_bytes(2)).unwrap();
        assert!(!peek_is_qcow2_v3(path.to_str().unwrap()));
    }

    #[test]
    fn peek_is_qcow2_v3_rejects_non_qcow2_magic() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("notqcow.bin");
        // Use a magic that is decidedly not "QFI\xfb".
        std::fs::write(&path, b"NOPE\x00\x00\x00\x03").unwrap();
        assert!(!peek_is_qcow2_v3(path.to_str().unwrap()));
    }

    #[test]
    fn peek_is_qcow2_v3_rejects_short_file() {
        // Files shorter than 8 bytes cannot encode the magic + version
        // pair and must be rejected.
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("tiny.bin");
        std::fs::write(&path, b"QFI\xfb").unwrap(); // 4 bytes only
        assert!(!peek_is_qcow2_v3(path.to_str().unwrap()));
    }

    #[test]
    fn peek_is_qcow2_v3_rejects_missing_file() {
        // A path that doesn't exist returns false rather than
        // panicking — same defensive contract as peek_is_vmdk_descriptor.
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("does-not-exist.qcow2");
        assert!(!peek_is_qcow2_v3(path.to_str().unwrap()));
    }

    #[test]
    fn resolve_descriptor_happy_path() {
        let tmp = TempDir::new().unwrap();
        let desc = tmp.path().join("foo.vmdk");
        let flat = tmp.path().join("foo-flat.vmdk");
        std::fs::write(&desc, make_flat_descriptor("foo-flat.vmdk", 20971520)).unwrap();
        std::fs::write(&flat, vec![0u8; 512]).unwrap();

        let cfg = default_security_config();
        let resolved = resolve_vmdk_flat_descriptor(&desc, &cfg).unwrap();

        assert_eq!(resolved.virtual_size, 20971520 * 512);
        assert_eq!(resolved.flat_extents.len(), 1);
        assert_eq!(
            resolved.flat_extents[0].flat_path,
            flat.canonicalize().unwrap()
        );
        assert_eq!(resolved.flat_extents[0].extent_size, 20971520 * 512);
        assert!(resolved.parent_hint.is_none());
    }

    #[test]
    fn resolve_descriptor_returns_parent_hint() {
        let tmp = TempDir::new().unwrap();
        let desc = tmp.path().join("foo.vmdk");
        let flat = tmp.path().join("foo-flat.vmdk");
        let text = "# Disk DescriptorFile\n\
             version=1\n\
             CID=1\n\
             parentCID=2\n\
             createType=\"monolithicFlat\"\n\
             parentFileNameHint=\"parent.vmdk\"\n\
             RW 1024 FLAT \"foo-flat.vmdk\" 0\n"
            .to_string();
        std::fs::write(&desc, text).unwrap();
        std::fs::write(&flat, vec![0u8; 512]).unwrap();

        let cfg = default_security_config();
        let resolved = resolve_vmdk_flat_descriptor(&desc, &cfg).unwrap();
        assert_eq!(resolved.parent_hint.as_deref(), Some("parent.vmdk"));
        assert_eq!(resolved.flat_extents.len(), 1);
    }

    #[test]
    fn resolve_descriptor_multi_extent() {
        let tmp = TempDir::new().unwrap();
        let desc = tmp.path().join("foo.vmdk");
        let flat1 = tmp.path().join("foo-f001.vmdk");
        let flat2 = tmp.path().join("foo-f002.vmdk");
        let text = "# Disk DescriptorFile\n\
                    version=1\n\
                    CID=1\n\
                    parentCID=ffffffff\n\
                    createType=\"twoGbMaxExtentFlat\"\n\
                    RW 4194304 FLAT \"foo-f001.vmdk\" 0\n\
                    RW 4194304 FLAT \"foo-f002.vmdk\" 0\n";
        std::fs::write(&desc, text).unwrap();
        std::fs::write(&flat1, vec![0u8; 512]).unwrap();
        std::fs::write(&flat2, vec![0u8; 512]).unwrap();

        let cfg = default_security_config();
        let resolved = resolve_vmdk_flat_descriptor(&desc, &cfg).unwrap();
        assert_eq!(resolved.flat_extents.len(), 2);
        assert_eq!(
            resolved.flat_extents[0].flat_path,
            flat1.canonicalize().unwrap()
        );
        assert_eq!(
            resolved.flat_extents[1].flat_path,
            flat2.canonicalize().unwrap()
        );
        assert_eq!(resolved.flat_extents[0].extent_size, 4194304 * 512);
        assert_eq!(resolved.flat_extents[1].extent_size, 4194304 * 512);
        assert_eq!(resolved.virtual_size, 2 * 4194304 * 512);
        assert!(resolved.parent_hint.is_none());
    }

    #[test]
    fn resolve_descriptor_rejects_non_flat_kind() {
        let tmp = TempDir::new().unwrap();
        let desc = tmp.path().join("foo.vmdk");
        let sparse = tmp.path().join("foo-sparse.vmdk");
        let text = "# Disk DescriptorFile\n\
                    version=1\n\
                    CID=1\n\
                    createType=\"monolithicSparse\"\n\
                    RW 1024 SPARSE \"foo-sparse.vmdk\"\n";
        std::fs::write(&desc, text).unwrap();
        std::fs::write(&sparse, vec![0u8; 512]).unwrap();

        let cfg = default_security_config();
        let err = resolve_vmdk_flat_descriptor(&desc, &cfg).unwrap_err();
        match err {
            ChainError::PathResolutionError(msg) => {
                assert!(
                    msg.contains("FLAT"),
                    "expected error about FLAT kind, got: {msg}"
                );
            }
            _ => panic!("expected PathResolutionError, got {err:?}"),
        }
    }

    #[test]
    fn resolve_descriptor_rejects_nonzero_offset() {
        let tmp = TempDir::new().unwrap();
        let desc = tmp.path().join("foo.vmdk");
        let flat = tmp.path().join("foo-flat.vmdk");
        let text = "# Disk DescriptorFile\n\
                    version=1\n\
                    CID=1\n\
                    createType=\"monolithicFlat\"\n\
                    RW 1024 FLAT \"foo-flat.vmdk\" 100\n";
        std::fs::write(&desc, text).unwrap();
        std::fs::write(&flat, vec![0u8; 512]).unwrap();

        let cfg = default_security_config();
        let err = resolve_vmdk_flat_descriptor(&desc, &cfg).unwrap_err();
        match err {
            ChainError::PathResolutionError(msg) => {
                assert!(msg.contains("non-zero") || msg.contains("offset"));
            }
            _ => panic!("expected PathResolutionError, got {err:?}"),
        }
    }

    #[test]
    fn resolve_descriptor_rejects_flat_outside_allowlist() {
        let tmp = TempDir::new().unwrap();
        let allowed = tmp.path().join("allowed");
        let forbidden = tmp.path().join("forbidden");
        std::fs::create_dir_all(&allowed).unwrap();
        std::fs::create_dir_all(&forbidden).unwrap();

        let desc = allowed.join("foo.vmdk");
        let flat = forbidden.join("foo-flat.vmdk");
        // Relative path would resolve to allowed/foo-flat.vmdk,
        // so use an absolute path that points outside.
        let text = format!(
            "# Disk DescriptorFile\n\
             version=1\n\
             CID=1\n\
             createType=\"monolithicFlat\"\n\
             RW 1024 FLAT \"{}\" 0\n",
            flat.display()
        );
        std::fs::write(&desc, text).unwrap();
        std::fs::write(&flat, vec![0u8; 512]).unwrap();

        let cfg = default_security_config();
        let err = resolve_vmdk_flat_descriptor(&desc, &cfg).unwrap_err();
        assert!(matches!(err, ChainError::BackingFileNotAllowed { .. }));
    }

    // Tests for shared::ChainConfig and shared::ChainDeviceInfo structures
    mod chain_config_tests {
        use shared::{
            ChainConfig, ChainDeviceInfo, ChainSegment, ImageFormat as SharedImageFormat,
            InfoResult, CALL_TABLE_ADDR, CHAIN_CONFIG_ADDR, MAX_CHAIN_DEVICES,
            OPERATION_CONFIG_ADDR, OPERATION_LOAD_ADDR, VMM_PARAMS_ADDR, VQ_BASE_START,
        };

        #[test]
        fn test_chain_device_info_new() {
            let info = ChainDeviceInfo::new();
            assert_eq!(info.format, 0);
            assert_eq!(info.flags, 0);
            assert_eq!(info.virtual_size, 0);
            assert_eq!(info.actual_size, 0);
            assert_eq!(info.cluster_size, 0);
        }

        #[test]
        fn test_chain_device_info_detected_format() {
            let mut info = ChainDeviceInfo::new();
            info.format = SharedImageFormat::Qcow2 as u32;
            assert_eq!(info.detected_format(), SharedImageFormat::Qcow2);

            info.format = SharedImageFormat::Raw as u32;
            assert_eq!(info.detected_format(), SharedImageFormat::Raw);
        }

        #[test]
        fn test_chain_device_info_flags() {
            let mut info = ChainDeviceInfo::new();

            // No flags set
            assert!(!info.has_backing_file());
            assert!(!info.is_encrypted());
            assert!(!info.is_compressed());

            // Set backing file flag
            info.flags = InfoResult::FLAG_HAS_BACKING_FILE;
            assert!(info.has_backing_file());
            assert!(!info.is_encrypted());

            // Set encrypted flag
            info.flags = InfoResult::FLAG_ENCRYPTED;
            assert!(!info.has_backing_file());
            assert!(info.is_encrypted());

            // Set compressed flag
            info.flags = InfoResult::FLAG_COMPRESSED;
            assert!(info.is_compressed());

            // Multiple flags
            info.flags = InfoResult::FLAG_HAS_BACKING_FILE | InfoResult::FLAG_ENCRYPTED;
            assert!(info.has_backing_file());
            assert!(info.is_encrypted());
        }

        #[test]
        fn test_chain_config_new() {
            let config = ChainConfig::new();
            assert_eq!(config.magic, ChainConfig::MAGIC);
            assert_eq!(config.device_count, 0);
            assert!(config.is_empty());
            assert!(!config.is_valid()); // device_count must be > 0 for valid
        }

        #[test]
        fn test_chain_config_with_devices() {
            let mut config = ChainConfig::new();
            config.device_count = 2;

            // Set up first device (top image - qcow2)
            config.devices[0].format = SharedImageFormat::Qcow2 as u32;
            config.devices[0].virtual_size = 10 * 1024 * 1024 * 1024; // 10 GiB
            config.devices[0].actual_size = 500 * 1024 * 1024; // 500 MiB
            config.devices[0].cluster_size = 65536;
            config.devices[0].flags = InfoResult::FLAG_HAS_BACKING_FILE;

            // Set up second device (base image - raw)
            config.devices[1].format = SharedImageFormat::Raw as u32;
            config.devices[1].virtual_size = 10 * 1024 * 1024 * 1024;
            config.devices[1].actual_size = 10 * 1024 * 1024 * 1024;
            config.devices[1].cluster_size = 0;
            config.devices[1].flags = 0;

            assert!(config.is_valid());
            assert_eq!(config.len(), 2);
            assert!(!config.is_empty());
            assert!(!config.is_single_image());

            // Test top()
            let top = config.top().unwrap();
            assert_eq!(top.detected_format(), SharedImageFormat::Qcow2);
            assert!(top.has_backing_file());

            // Test base()
            let base = config.base().unwrap();
            assert_eq!(base.detected_format(), SharedImageFormat::Raw);
            assert!(!base.has_backing_file());

            // Test get()
            assert!(config.get(0).is_some());
            assert!(config.get(1).is_some());
            assert!(config.get(2).is_none()); // Out of bounds
        }

        #[test]
        fn test_chain_config_single_image() {
            let mut config = ChainConfig::new();
            config.device_count = 1;
            config.devices[0].format = SharedImageFormat::Raw as u32;
            config.devices[0].virtual_size = 1024 * 1024 * 1024;

            assert!(config.is_valid());
            assert!(config.is_single_image());
            // top() and base() should return the same device
            assert!(config.top().is_some());
            assert!(config.base().is_some());
        }

        #[test]
        fn test_chain_config_max_devices() {
            let mut config = ChainConfig::new();
            config.device_count = MAX_CHAIN_DEVICES as u32;

            // Should be able to access all 16 devices
            for i in 0..MAX_CHAIN_DEVICES {
                assert!(config.get(i).is_some());
            }
            assert!(config.get(MAX_CHAIN_DEVICES).is_none());
        }

        #[test]
        fn test_chain_config_struct_size() {
            // Verify the struct sizes are what we expect for FFI
            // ChainDeviceInfo: 4 + 4 + 8 + 8 + 4 + 4 = 32 bytes
            assert_eq!(core::mem::size_of::<ChainDeviceInfo>(), 32);

            // ChainSegment: 4 + 4 = 8 bytes
            assert_eq!(core::mem::size_of::<ChainSegment>(), 8);

            // ChainConfig: 16 header + (16 * 32) devices
            // + (16 * 8) segments + 64 reserved = 720 bytes
            assert_eq!(core::mem::size_of::<ChainConfig>(), 720);
        }

        #[test]
        fn test_chain_config_memory_address() {
            // Verify the memory addresses don't overlap
            // Memory layout:
            //   0x010000: core.bin (up to 128KB)
            //   0x030000 (OPERATION_LOAD_ADDR): operation binary (up to 768KB)
            //   0x0F0000 (CALL_TABLE_ADDR): call table
            //   0x0F1000 (OPERATION_CONFIG_ADDR): operation config (4KB)
            //   0x0F2000 (CHAIN_CONFIG_ADDR): chain config (1KB)
            //   0x0F3000 (VMM_PARAMS_ADDR): VMM params (4KB)
            //   [0x0F4000, 0x100000): 48KB guard gap below the virtqueue region
            //   0x100000 (VQ_BASE_START): virtqueue memory (16 devices * 64KB = 1MB)
            //   0x200000 (DMA_POOL_BASE): DMA pool (64KB)
            //   0x300000 (SCRATCH_MEM_BASE): scratch memory (~12.9MB)
            //   0xFF0000 (SCRATCH_MEM_END): end of scratch + 64KB guard gap
            //  0x1000000 (STACK_BASE): stack (4MB)
            //  0x2000000: end of guest memory (GUEST_MEM_SIZE)
            //
            // The operation binary area (0x30000-0xF0000 = 768KB) must be large
            // enough for all operations (info.bin, copy.bin, check.bin). Binary
            // sizes are validated at build time in the Makefile.

            // Configs are ordered correctly (chain after operation config)
            assert!(CHAIN_CONFIG_ADDR > OPERATION_CONFIG_ADDR);
            // Operation config is after call table
            assert!(OPERATION_CONFIG_ADDR > CALL_TABLE_ADDR);
            // Call table is above operation binary area (0xF0000 > 0x30000)
            assert!(CALL_TABLE_ADDR > OPERATION_LOAD_ADDR);
            // The data pages sit below the virtqueue region with headroom.
            assert!(VMM_PARAMS_ADDR + 0x1000 <= VQ_BASE_START);
        }
    }
}
