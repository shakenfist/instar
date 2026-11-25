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
use crate::escape::terminal_safe;
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

    /// The format the guest should read this image's bytes as.
    ///
    /// `Unknown` is the name the secure-mode `info` operation gives a
    /// file whose header matches no magic and which carries no
    /// partition table, and the name discovery keeps for an ISO. It is
    /// a statement about identification, not about layout: the bytes
    /// are at the guest-virtual offset, which is exactly what raw
    /// means, and the guest's chain reader has always read such a
    /// member through its raw arm by falling through its format
    /// dispatch.
    ///
    /// Reporting and reading want different answers here, so they ask
    /// different questions. `info --chain` prints [`Self::format`]'s
    /// own name, so an unidentifiable backing file is still listed as
    /// `unknown` and the listing agrees with `instar info` run on that
    /// file alone. The guest is told `raw`, because an operation that
    /// allowlists the formats it can read must see the format it will
    /// actually use -- `Unknown` failed those allowlists, which refused
    /// chains the same build reads correctly through `convert`.
    pub fn read_format(self) -> Self {
        match self {
            ImageFormat::Unknown => ImageFormat::Raw,
            other => other,
        }
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

/// A single file holding an image's content outside the image itself:
/// a QCOW2 external data file, or one extent of a VMDK descriptor.
///
/// The two reach the guest differently. A QCOW2 external data file is
/// its own virtio-block device in the slot after its owner. A VMDK
/// descriptor's extents share the descriptor's one device, laid end to
/// end, and the guest finds each of them through the chain config's
/// extent table -- so however many extents a descriptor has, it costs
/// one device slot.
#[derive(Debug, Clone)]
pub struct ExternalDataFile {
    /// Absolute, validated path to the file.
    pub path: PathBuf,
    /// Size of this file's virtual address space contribution in
    /// bytes. For QCOW2 external data files this equals the file
    /// size; for VMDK extents it equals the span the descriptor
    /// declares, which for a sparse extent is neither the file's
    /// length nor derivable from it.
    pub extent_size: u64,
    /// Which kind the descriptor's extent line called this file, for a
    /// VMDK descriptor's extent, and `None` for a QCOW2 external data
    /// file. The guest's extent table has no entry that leaves the
    /// kind unsaid, so a VMDK extent reaching the host with `None`
    /// here is a bug rather than a default.
    pub vmdk_extent_kind: Option<VmdkExtentKind>,
    /// The file's length when the chain was discovered, or the error
    /// that measuring it gave.
    ///
    /// A VMDK descriptor's extents are laid out into one device twice
    /// over -- once to tell the guest where each file begins in it, and
    /// once to open the files as that device -- and the two have to
    /// describe the same bytes. Measuring the file in each pass does
    /// not give that: a file that grows between them moves every later
    /// extent's base in one pass and not the other, and the guest then
    /// reads one extent's offset inside another extent's bytes and is
    /// told it succeeded. So the length is taken once, here, and both
    /// passes lay the device out from this number. A file that changes
    /// afterwards is harmless: the device still says what the guest was
    /// told it says, and a member shorter than its declared length
    /// reads as zeros past its end (`BackingStore::open_concatenated`).
    ///
    /// For a QCOW2 external data file this is the file size, the same
    /// figure as `extent_size`; nothing lays that device out, because it
    /// is a device of its own.
    pub file_length: Result<u64, String>,
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
    /// Files holding this image's content outside the image itself: a
    /// QCOW2 v3 external data file, or a VMDK descriptor's extents.
    /// A QCOW2 data file becomes a virtio-block device of its own
    /// immediately after this image's; a descriptor's extents are laid
    /// end to end inside this image's own device and named by the chain
    /// config's extent table. [`Self::data_device_count`] is which.
    pub external_data_files: Vec<ExternalDataFile>,
}

impl ChainImage {
    /// Whether this image is a VMDK descriptor, whose content is the
    /// extents in `external_data_files` and whose own bytes are text.
    pub fn is_vmdk_descriptor(&self) -> bool {
        self.format == ImageFormat::VmdkDescriptor
    }

    /// The external data files that become virtio-block devices of
    /// their own, in the slots immediately after this image's.
    ///
    /// Empty for a VMDK descriptor: the host lays its extent files end
    /// to end as the descriptor's own device and the guest reaches each
    /// of them at an offset inside it, so an extent costs an entry in
    /// the chain config's extent table rather than a device slot. That
    /// is what keeps a 26-extent image inside the sixteen slots the
    /// guest's virtqueue region holds, and it is why nothing can hand
    /// an extent to `DeviceSet::add_device`: every device the VMM
    /// attaches for a chain is an image or one of these, and a
    /// descriptor's extents are neither. A QCOW2 external data file is
    /// still a device of its own.
    pub fn data_devices(&self) -> &[ExternalDataFile] {
        if self.is_vmdk_descriptor() {
            &[]
        } else {
            &self.external_data_files
        }
    }

    /// How many devices [`Self::data_devices`] asks for.
    pub fn data_device_count(&self) -> usize {
        self.data_devices().len()
    }
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

    /// Total number of virtio-block devices needed for this chain:
    /// one per image, plus one per external data file that is a device
    /// of its own.
    ///
    /// A VMDK descriptor's extents are not, so a descriptor counts one
    /// however many extents it has -- see
    /// [`ChainImage::data_device_count`]. Every caller bounding a chain
    /// against the sixteen device slots counts through here, so the
    /// extents stopped consuming slots in one place rather than in each
    /// of the guards.
    pub fn total_devices(&self) -> usize {
        self.images
            .iter()
            .map(|img| 1 + img.data_device_count())
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
    /// A backing image (not the top of the chain) records a qcow2
    /// external data file. Only the top image's data file is attached
    /// to the guest, so a read through this image would find no device
    /// behind its data and fail with no explanation (issue #806).
    /// Carries the backing image's path and the data file reference as
    /// its header records it, which is untrusted text.
    BackingDataFileUnsupported { image: PathBuf, data_file: String },
    /// A reference read from an image's header or descriptor is in
    /// Windows convention (`C:\images\base.qcow2`, `\\server\share`).
    /// No file on this host is named by it, and the same spelling is
    /// also a legal POSIX file name, so joining it onto the image's
    /// directory would open whatever happened to sit there under that
    /// name (issue #899). Carries the image that records it and the
    /// reference as recorded, which is untrusted text.
    WindowsAbsoluteReference { image: PathBuf, reference: String },
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
            ChainError::BackingDataFileUnsupported { image, data_file } => {
                write!(
                    f,
                    "backing image {} has an external data file ({}), and external data \
                     files are only supported on the top image of a chain",
                    terminal_safe(&image.to_string_lossy()),
                    terminal_safe(data_file)
                )
            }
            ChainError::WindowsAbsoluteReference { image, reference } => {
                write!(
                    f,
                    "{} records a backing reference in Windows convention ({}), which \
                     names no file on this host; qemu-img refuses it as an unknown \
                     protocol and instar will not open a POSIX file of that literal \
                     name instead",
                    terminal_safe(&image.to_string_lossy()),
                    terminal_safe(reference)
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

/// Whether `reference`, read from `parent_image`, names `path`, judged
/// from the two spellings alone.
///
/// Nothing is looked at, so the answer is the same whatever is on the
/// host, and no allowlist is needed to keep it from being an oracle.
/// It is yes only when neither spelling contains `..`. Without one, a
/// spelling names the file at that path whatever symlinks lie along
/// it, so two equal spellings name the same file; with one, a symlink
/// before the `..` can send a spelling somewhere its text does not
/// say. A no means only that the spellings alone cannot tell.
pub fn reference_spells_path(parent_image: &Path, reference: &str, path: &Path) -> bool {
    let (Ok(parent_image), Ok(path)) =
        (std::path::absolute(parent_image), std::path::absolute(path))
    else {
        return false;
    };
    let Some(parent_dir) = parent_image.parent() else {
        return false;
    };
    // `join` replaces the base outright when the reference is absolute.
    let named = parent_dir.join(reference);
    let has_parent_dir = |p: &Path| p.components().any(|c| c == Component::ParentDir);
    !has_parent_dir(&named) && !has_parent_dir(&path) && named == path
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

/// Whether an absolute reference that cannot be used as written may be
/// replaced by its file name beside the image.
///
/// The substitute keeps images built on another host working for
/// anything that only reads them. A write target must be refused
/// instead: the substitute is any file that happens to share the
/// reference's name, and writing into it would let an image choose an
/// unrelated file to change.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FileNameFallback {
    Allowed,
    Refused,
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
///    checks, and using it is announced on stderr. With
///    `FileNameFallback::Refused` it is refused instead.
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
    fallback: FileNameFallback,
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
    if !reference.is_absolute() || fallback == FileNameFallback::Refused {
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
                    terminal_safe(&name.to_string_lossy()),
                    terminal_safe(backing_path)
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
///
/// An absolute reference that cannot be used as written may resolve to
/// its file name beside the image; see `FileNameFallback`. A file the
/// caller will write into goes through `validate_backing_write_target`
/// instead.
pub fn validate_backing_path(
    parent_image: &Path,
    backing_path: &str,
    security_config: &SecurityConfig,
) -> Result<PathBuf, ChainError> {
    validate_reference(
        parent_image,
        backing_path,
        security_config,
        FileNameFallback::Allowed,
    )
}

/// Validate a reference read from `parent_image` that names a file the
/// caller will write into, as `validate_backing_path` does, but never
/// substitute the reference's file name beside the image: a reference
/// that cannot be used as written is refused.
pub fn validate_backing_write_target(
    parent_image: &Path,
    backing_path: &str,
    security_config: &SecurityConfig,
) -> Result<PathBuf, ChainError> {
    validate_reference(
        parent_image,
        backing_path,
        security_config,
        FileNameFallback::Refused,
    )
}

/// Is this reference a Windows absolute path?
///
/// True for a drive-letter path (`C:\images\parent.vhdx`, the VHDX
/// `absolute_win32_path` locator key) and for anything rooted at `\\`
/// (`\\?\Volume{GUID}\...`, the `volume_path` key, and plain UNC
/// shares). Both keys reach the host verbatim, in Windows convention,
/// because that is what the image says and `info` prints what the
/// image says.
///
/// This is a *classification*, never a conversion. No caller builds a
/// host path from the value: a reporting walk uses the answer to stop,
/// and [`validate_reference`] uses it to refuse. The VHDX
/// `relative_path` key does not arrive in Windows convention at all --
/// the guest renders it into POSIX before reporting it -- so a
/// `.\parent.vhdx` locator reaches the host as `parent.vhdx` and
/// resolves like any other relative name.
pub fn is_windows_absolute_reference(reference: &str) -> bool {
    if reference.starts_with(r"\\") {
        return true;
    }
    let bytes = reference.as_bytes();
    bytes.len() >= 3 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' && bytes[2] == b'\\'
}

fn validate_reference(
    parent_image: &Path,
    backing_path: &str,
    security_config: &SecurityConfig,
    fallback: FileNameFallback,
) -> Result<PathBuf, ChainError> {
    // A reference in Windows convention names no file on this host, so
    // nothing is opened for it. It is refused here rather than joined
    // onto the image's directory, which is what used to happen: a
    // drive-letter or UNC reference is also a legal POSIX file name, so
    // `C:\images\base.qcow2` beside the image was opened as the
    // backing file while `info` -- which classifies the same string as
    // absolute, and so prints it with no resolved path -- reported
    // nothing of the kind. Whoever could write the image's directory
    // chose what the reading operations opened, and the audit step did
    // not show it (issue #899).
    //
    // qemu-img refuses the same reference, for its own reason: it reads
    // everything before the first colon as a protocol name and reports
    // "Unknown protocol 'C'". So this is parity as well as the stricter
    // of the two available answers, and it leaves `info` and the
    // reading operations agreeing about what a chain holds.
    if is_windows_absolute_reference(backing_path) {
        return Err(ChainError::WindowsAbsoluteReference {
            image: parent_image.to_path_buf(),
            reference: backing_path.to_string(),
        });
    }

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
        fallback,
    )
}

/// Maximum bytes of descriptor text the VMM will read from disk
/// when resolving a VMDK monolithicFlat descriptor. qemu-img emits
/// descriptors well under 4 KB; capping small keeps the host-side
/// parse cheap and bounds the memory taken by an untrusted file.
pub const MAX_DESCRIPTOR_BYTES: usize = 8192;

/// How an extent file holds the span its descriptor line declares for
/// it.
///
/// The line is the authority, and nothing here looks at the file: qemu
/// reads a file as whatever kind its line says, so a host that decided
/// from the bytes could mean a different disk by the same image. A line
/// naming any other kind is refused rather than mapped to the closer of
/// these two.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VmdkExtentKind {
    /// Raw sectors, byte for byte from the start of the file.
    Flat,
    /// A sparse VMDK image in its own right, with its own header, grain
    /// directory and grain tables, covering only this extent's span.
    Sparse,
}

/// A single resolved extent within a VMDK descriptor.
#[derive(Debug, Clone)]
pub struct ResolvedVmdkExtent {
    /// Absolute, allowlist-validated path to the extent file.
    pub path: PathBuf,
    /// Span of the virtual disk this extent covers, in bytes (extent
    /// `size_sectors` × 512). Not the length of the file: a sparse
    /// extent's file is shorter than its span until every grain is
    /// allocated, and longer once its metadata is counted.
    pub extent_size: u64,
    /// Which kind the descriptor's extent line called this file.
    pub kind: VmdkExtentKind,
    /// The grain size this extent's own binary header declares, in
    /// bytes, and `None` for a flat extent or a sparse one whose header
    /// could not be read. This is what `info` reports as the extent's
    /// cluster size, so it is read here, where the path has just been
    /// validated and the line's kind is known.
    pub cluster_size: Option<u64>,
}

/// Result of resolving a VMDK descriptor's extents on the host.
#[derive(Debug, Clone)]
pub struct ResolvedVmdkDescriptor {
    /// Ordered extent files. For monolithicFlat, length 1; for the
    /// `twoGbMaxExtent*` subformats, length N.
    pub extents: Vec<ResolvedVmdkExtent>,
    /// Total virtual size across all extents in bytes.
    pub virtual_size: u64,
    /// Parent filename hint from descriptor, if present.
    /// Analogous to QCOW2 backing-filename.
    pub parent_hint: Option<String>,
}

impl ResolvedVmdkDescriptor {
    /// The cluster size the image reports as a whole, and `None` when
    /// it reports none.
    ///
    /// A descriptor is text and names no grain size of its own, so the
    /// figure comes from the extents. Measured against qemu-img 10.2.0:
    /// it is printed only when every extent is sparse and every one of
    /// them declares the same grain size. A descriptor mixing flat and
    /// sparse extents prints none, and neither does one whose sparse
    /// extents disagree -- in both cases each extent still reports its
    /// own, so the image-wide figure is the only thing withheld. An
    /// all-flat descriptor has no grain size to report at all.
    pub fn cluster_size(&self) -> Option<u64> {
        common_cluster_size(self.extents.iter().map(|extent| extent.cluster_size))
    }
}

/// The one cluster size a set of extents agrees on, or `None` if any of
/// them has none or they disagree. The rule `ResolvedVmdkDescriptor::
/// cluster_size` documents, kept in one place because the chain printer
/// applies it to extents it has only the paths and kinds of.
fn common_cluster_size(sizes: impl IntoIterator<Item = Option<u64>>) -> Option<u64> {
    let mut sizes = sizes.into_iter();
    let first = sizes.next()??;
    sizes.all(|size| size == Some(first)).then_some(first)
}

/// The cluster size reported for a descriptor whose extents are known
/// only as paths and kinds, reading each sparse extent's header to get
/// it. `ResolvedVmdkDescriptor::cluster_size` is the same rule over
/// extents already resolved.
pub fn descriptor_cluster_size<'a>(
    extents: impl IntoIterator<Item = (&'a Path, VmdkExtentKind)>,
) -> Option<u64> {
    common_cluster_size(
        extents
            .into_iter()
            .map(|(path, kind)| extent_cluster_size(path, kind)),
    )
}

/// The grain size a sparse extent's own binary header declares, in
/// bytes. `None` for a flat extent, which has no grain size, and for a
/// sparse extent whose header cannot be read, does not carry the VMDK4
/// magic, or declares a zero grain size.
///
/// qemu-img refuses to open an image whose sparse extent is any of
/// those three, so there is no output to be unlike; reporting no
/// cluster size is as close as an `info` that still describes the
/// descriptor can come, and the guest's reader refuses the same extent
/// when something tries to read it.
///
/// Only a regular file is opened. The path is one the descriptor named,
/// and the allowlist constrains where it may point but not what it may
/// point at: a FIFO beside the image would block the host inside
/// `open` until something wrote to it, with no timeout, hanging a
/// command as ordinary as `instar info` on an image someone uploaded.
/// `O_NONBLOCK` closes the window between the check and the open, where
/// the regular file could be replaced by a FIFO; on a regular file it
/// does nothing.
fn extent_cluster_size(path: &Path, kind: VmdkExtentKind) -> Option<u64> {
    use std::io::Read;
    use std::os::unix::fs::OpenOptionsExt;

    if kind != VmdkExtentKind::Sparse {
        return None;
    }
    if !std::fs::metadata(path)
        .map(|m| m.is_file())
        .unwrap_or(false)
    {
        return None;
    }
    let mut header = [0u8; vmdk::HEADER_FULL_SIZE];
    std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK)
        .open(path)
        .and_then(|mut file| file.read_exact(&mut header))
        .ok()?;
    let magic = u32::from_le_bytes(
        header[vmdk::MAGIC_OFFSET..vmdk::MAGIC_OFFSET + 4]
            .try_into()
            .expect("four bytes"),
    );
    if magic != vmdk::VMDK4_MAGIC {
        return None;
    }
    let grain_size = vmdk::Vmdk4HeaderFull::parse(&header)?.grain_size_bytes;
    (grain_size > 0).then_some(grain_size)
}

/// Read a VMDK descriptor, validate it, and resolve its extent file(s)
/// against the backing-file allowlist.
///
/// Supports monolithicFlat and monolithicSparse (single extent) and the
/// `twoGbMaxExtentFlat` / `twoGbMaxExtentSparse` subformats (multiple
/// extents). Every extent must be `FLAT` or `SPARSE` with
/// `offset_sectors == 0`.
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
        // The parser refuses a descriptor with more extents than the
        // chain config's extent table holds, because `MAX_EXTENTS` is
        // that table's size, so this is the first and usually the only
        // place an over-long descriptor is stopped. The table's own
        // check still runs, for a chain or a comparison whose images
        // each fit but whose extents together do not.
        if e == vmdk::ExtentParseError::TooManyExtents {
            return ChainError::PathResolutionError(format!(
                "VMDK descriptor '{}' declares more than the {} extents \
                 a descriptor may have",
                descriptor_path.display(),
                vmdk::MAX_EXTENTS
            ));
        }
        ChainError::PathResolutionError(format!(
            "VMDK descriptor '{}' has malformed extent lines: {:?}",
            descriptor_path.display(),
            e
        ))
    })?;

    let mut resolved_extents = Vec::with_capacity(extents.len());
    let mut virtual_size: u64 = 0;

    for i in 0..extents.len() {
        let extent = extents.get(i).expect("index < len");

        // FLAT and SPARSE are the kinds the guest's extent table can
        // describe. ZERO has no file to attach, and the two VMFS kinds
        // name a layout on a VMware filesystem that is not a file at
        // all here, so each is refused rather than read as the nearest
        // of the two.
        let kind = match extent.kind {
            vmdk::ExtentKind::Flat => VmdkExtentKind::Flat,
            vmdk::ExtentKind::Sparse => VmdkExtentKind::Sparse,
            _ => {
                return Err(ChainError::PathResolutionError(format!(
                    "VMDK descriptor '{}' extent {} has kind {:?}; \
                     only FLAT and SPARSE extents are supported",
                    descriptor_path.display(),
                    i,
                    extent.kind
                )));
            }
        };

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

        let path = validate_backing_path(descriptor_path, extent.filename, security_config)?;

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

        let cluster_size = extent_cluster_size(&path, kind);

        resolved_extents.push(ResolvedVmdkExtent {
            path,
            extent_size,
            kind,
            cluster_size,
        });
    }

    Ok(ResolvedVmdkDescriptor {
        extents: resolved_extents,
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
    fn backing_data_file_refusal_names_both_files_and_escapes_them() {
        // The data file reference comes out of the image's header, so a
        // control character in it must not reach the terminal raw.
        let err = ChainError::BackingDataFileUnsupported {
            image: PathBuf::from("/images/mid.qcow2"),
            data_file: "mid\x1b[2J.data".to_string(),
        };
        let message = err.to_string();
        assert!(message.contains("/images/mid.qcow2"), "{message}");
        assert!(
            message.contains("only supported on the top image of a chain"),
            "{message}"
        );
        assert!(!message.contains('\x1b'), "{message:?}");
    }

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
    fn unknown_is_read_as_raw_and_nothing_else_moves() {
        // The one remapping: a member the info gate could not identify
        // is read as raw, which is how the guest's chain reader has
        // always served it.
        assert_eq!(ImageFormat::Unknown.read_format(), ImageFormat::Raw);
        assert_eq!(
            ImageFormat::Unknown.read_format().to_shared_format_u32(),
            ImageFormat::Raw.to_shared_format_u32()
        );
        // Every other format reads as itself. A format that gained a
        // remapping here would be read through the wrong arm of the
        // chain reader, which is a wrong-bytes bug under exit 0, so
        // this is asserted over the whole enum rather than a sample.
        for format in [
            ImageFormat::Raw,
            ImageFormat::Qcow2,
            ImageFormat::Qcow1,
            ImageFormat::Vmdk4,
            ImageFormat::Vmdk3,
            ImageFormat::Vhd,
            ImageFormat::Vhdx,
            ImageFormat::Vdi,
            ImageFormat::Parallels,
            ImageFormat::Luks,
            ImageFormat::VmdkDescriptor,
            ImageFormat::Dmg,
        ] {
            assert_eq!(format.read_format(), format, "{format:?}");
        }
    }

    #[test]
    fn reporting_keeps_the_name_the_info_gate_gave() {
        // `info --chain` prints `format`, not `read_format`, so an
        // unidentifiable backing file is still listed as `unknown` and
        // the listing agrees with `instar info` on that file alone.
        assert_eq!(ImageFormat::Unknown.to_string(), "unknown");
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

    #[test]
    fn write_target_never_falls_back_to_file_name() {
        // A write target is refused where a read would take the file of
        // the same name beside the image, both for a reference outside
        // the allowlist and for one inside it that is missing, and the
        // refusal is the one a read gives with no such file there.
        let l = layout();
        let decoy = l.images.join("base.qcow2");
        std::fs::write(&decoy, b"").unwrap();
        let cfg = default_security_config();

        let outside = l.outside.join("base.qcow2");
        let outside = outside.to_str().unwrap();
        assert_eq!(
            validate_backing_path(&l.parent, outside, &cfg).unwrap(),
            decoy.canonicalize().unwrap()
        );
        match validate_backing_write_target(&l.parent, outside, &cfg) {
            Err(ChainError::BackingFileNotAllowed { path, .. }) => {
                assert_eq!(path, PathBuf::from(outside))
            }
            other => panic!("expected BackingFileNotAllowed, got {other:?}"),
        }

        let missing = l.images.join("sub").join("base.qcow2");
        let missing = missing.to_str().unwrap();
        assert_eq!(
            validate_backing_path(&l.parent, missing, &cfg).unwrap(),
            decoy.canonicalize().unwrap()
        );
        match validate_backing_write_target(&l.parent, missing, &cfg) {
            Err(ChainError::BackingFileNotFound(path)) => {
                assert_eq!(path, PathBuf::from(missing))
            }
            other => panic!("expected BackingFileNotFound, got {other:?}"),
        }
    }

    #[test]
    fn write_target_resolves_references_usable_as_written() {
        let l = layout();
        let base = l.images.join("base.qcow2");
        std::fs::write(&base, b"").unwrap();
        let cfg = default_security_config();
        for reference in ["base.qcow2", base.to_str().unwrap()] {
            assert_eq!(
                validate_backing_write_target(&l.parent, reference, &cfg).unwrap(),
                base.canonicalize().unwrap(),
                "{reference}"
            );
        }
    }

    #[test]
    fn reference_spells_path_cases() {
        let parent = Path::new("/vms/overlays/top.qcow2");
        let base = Path::new("/vms/bases/base.qcow2");
        assert!(reference_spells_path(parent, "/vms/bases/base.qcow2", base));
        assert!(reference_spells_path(
            parent,
            "/vms/./bases//base.qcow2",
            base
        ));
        assert!(reference_spells_path(
            parent,
            "base.qcow2",
            Path::new("/vms/overlays/base.qcow2")
        ));
        assert!(!reference_spells_path(
            parent,
            "/vms/bases/other.qcow2",
            base
        ));
        // A `..` in either spelling could follow a symlink, so the
        // spellings alone cannot tell.
        assert!(!reference_spells_path(parent, "../bases/base.qcow2", base));
        assert!(!reference_spells_path(
            parent,
            "/vms/bases/base.qcow2",
            Path::new("/vms/overlays/../bases/base.qcow2")
        ));
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
        assert_eq!(resolved.extents[0].path, flat);
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
        assert_eq!(resolved.extents.len(), 1);
        assert_eq!(resolved.extents[0].path, flat.canonicalize().unwrap());
        assert_eq!(resolved.extents[0].extent_size, 20971520 * 512);
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
        assert_eq!(resolved.extents.len(), 1);
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
        assert_eq!(resolved.extents.len(), 2);
        assert_eq!(resolved.extents[0].path, flat1.canonicalize().unwrap());
        assert_eq!(resolved.extents[1].path, flat2.canonicalize().unwrap());
        assert_eq!(resolved.extents[0].extent_size, 4194304 * 512);
        assert_eq!(resolved.extents[1].extent_size, 4194304 * 512);
        assert_eq!(resolved.virtual_size, 2 * 4194304 * 512);
        assert!(resolved.parent_hint.is_none());
    }

    #[test]
    fn resolve_descriptor_carries_each_extents_kind() {
        // The kinds a descriptor may mix, each reported as the line
        // declared it. The only thing read from an extent file here is
        // a sparse one's grain size, and these two carry no header, so
        // neither reports a cluster size.
        let tmp = TempDir::new().unwrap();
        let desc = tmp.path().join("foo.vmdk");
        let first = tmp.path().join("foo-s001.vmdk");
        let second = tmp.path().join("foo-s002.vmdk");
        let text = "# Disk DescriptorFile\n\
                    version=1\n\
                    CID=1\n\
                    createType=\"twoGbMaxExtentSparse\"\n\
                    RW 1024 SPARSE \"foo-s001.vmdk\"\n\
                    RW 2048 FLAT \"foo-s002.vmdk\"\n";
        std::fs::write(&desc, text).unwrap();
        std::fs::write(&first, vec![0u8; 512]).unwrap();
        std::fs::write(&second, vec![0u8; 512]).unwrap();

        let cfg = default_security_config();
        let resolved = resolve_vmdk_flat_descriptor(&desc, &cfg).unwrap();
        assert_eq!(resolved.extents.len(), 2);
        assert_eq!(resolved.extents[0].kind, VmdkExtentKind::Sparse);
        assert_eq!(resolved.extents[0].extent_size, 1024 * 512);
        assert_eq!(resolved.extents[1].kind, VmdkExtentKind::Flat);
        assert_eq!(resolved.extents[1].extent_size, 2048 * 512);
        assert_eq!(resolved.virtual_size, (1024 + 2048) * 512);
        assert_eq!(resolved.extents[0].cluster_size, None);
        assert_eq!(resolved.extents[1].cluster_size, None);
    }

    /// Write a sparse extent file whose header declares
    /// `grain_size_sectors`. The grain size is all the host reads from
    /// a sparse extent, so nothing else in the header is filled in.
    fn write_sparse_extent(path: &Path, grain_size_sectors: u64) {
        let mut header = vec![0u8; 512];
        header[vmdk::MAGIC_OFFSET..vmdk::MAGIC_OFFSET + 4]
            .copy_from_slice(&vmdk::VMDK4_MAGIC.to_le_bytes());
        header[vmdk::GRAIN_SIZE_OFFSET..vmdk::GRAIN_SIZE_OFFSET + 8]
            .copy_from_slice(&grain_size_sectors.to_le_bytes());
        std::fs::write(path, header).unwrap();
    }

    /// Resolve a two-extent descriptor whose lines declare `kinds`,
    /// over extent files written by `write_extents`.
    fn resolve_two_extent_descriptor(
        tmp: &TempDir,
        kinds: [&str; 2],
        write_extents: impl Fn(&Path, &Path),
    ) -> ResolvedVmdkDescriptor {
        let desc = tmp.path().join("foo.vmdk");
        let first = tmp.path().join("foo-s001.vmdk");
        let second = tmp.path().join("foo-s002.vmdk");
        let text = format!(
            "# Disk DescriptorFile\n\
             version=1\n\
             CID=1\n\
             createType=\"twoGbMaxExtentSparse\"\n\
             RW 1024 {} \"foo-s001.vmdk\" 0\n\
             RW 1024 {} \"foo-s002.vmdk\" 0\n",
            kinds[0], kinds[1]
        );
        std::fs::write(&desc, text).unwrap();
        write_extents(&first, &second);
        resolve_vmdk_flat_descriptor(&desc, &default_security_config()).unwrap()
    }

    #[test]
    fn resolve_descriptor_reads_each_sparse_extents_grain_size() {
        // A descriptor states no grain size of its own: it is in each
        // sparse extent's binary header, and the span its line declares
        // is nothing like it.
        let tmp = TempDir::new().unwrap();
        let resolved = resolve_two_extent_descriptor(&tmp, ["SPARSE", "SPARSE"], |a, b| {
            write_sparse_extent(a, 128);
            write_sparse_extent(b, 128);
        });
        assert_eq!(resolved.extents[0].cluster_size, Some(65536));
        assert_eq!(resolved.extents[1].cluster_size, Some(65536));
        assert_eq!(resolved.cluster_size(), Some(65536));
    }

    #[test]
    fn a_flat_extent_reports_no_cluster_size_whatever_its_bytes_hold() {
        // The extent line is the authority on an extent's kind, so a
        // flat extent whose file happens to begin with a sparse header
        // still has no grain size -- and a descriptor mixing the kinds
        // reports none for the image, which is what qemu-img does.
        let tmp = TempDir::new().unwrap();
        let resolved = resolve_two_extent_descriptor(&tmp, ["SPARSE", "FLAT"], |a, b| {
            write_sparse_extent(a, 128);
            write_sparse_extent(b, 128);
        });
        assert_eq!(resolved.extents[0].cluster_size, Some(65536));
        assert_eq!(resolved.extents[1].cluster_size, None);
        assert_eq!(resolved.cluster_size(), None);
    }

    #[test]
    fn a_descriptor_whose_sparse_extents_disagree_reports_no_cluster_size() {
        // Each extent still reports its own: only the image-wide figure
        // is withheld, and qemu-img withholds it the same way.
        let tmp = TempDir::new().unwrap();
        let resolved = resolve_two_extent_descriptor(&tmp, ["SPARSE", "SPARSE"], |a, b| {
            write_sparse_extent(a, 128);
            write_sparse_extent(b, 256);
        });
        assert_eq!(resolved.extents[0].cluster_size, Some(65536));
        assert_eq!(resolved.extents[1].cluster_size, Some(131072));
        assert_eq!(resolved.cluster_size(), None);
    }

    #[test]
    fn a_sparse_extent_header_that_says_nothing_reports_no_cluster_size() {
        // Three files qemu-img refuses to open at all: one carrying a
        // grain size where a header would have one but no VMDK4 magic,
        // one declaring a zero grain size, and one too short to hold a
        // header. An `info` that still describes the descriptor reports
        // no cluster size for them rather than a figure read out of
        // whatever bytes are there.
        for prepare in [
            (|path: &Path| {
                let mut bytes = vec![0u8; 512];
                bytes[vmdk::GRAIN_SIZE_OFFSET..vmdk::GRAIN_SIZE_OFFSET + 8]
                    .copy_from_slice(&128u64.to_le_bytes());
                std::fs::write(path, bytes).unwrap();
            }) as fn(&Path),
            |path: &Path| write_sparse_extent(path, 0),
            |path: &Path| {
                // Shorter than a whole header, so there is nothing to
                // parse however good the first bytes look.
                let mut header = vec![0u8; vmdk::HEADER_FULL_SIZE - 1];
                header[vmdk::MAGIC_OFFSET..vmdk::MAGIC_OFFSET + 4]
                    .copy_from_slice(&vmdk::VMDK4_MAGIC.to_le_bytes());
                std::fs::write(path, header).unwrap();
            },
        ] {
            let tmp = TempDir::new().unwrap();
            let resolved = resolve_two_extent_descriptor(&tmp, ["SPARSE", "SPARSE"], |a, b| {
                write_sparse_extent(a, 128);
                prepare(b);
            });
            assert_eq!(resolved.extents[1].cluster_size, None);
            assert_eq!(resolved.cluster_size(), None);
        }
    }

    // The allowlist says where an extent path may point, not what it
    // may point at, so a descriptor can name a FIFO beside itself.
    // Opening one blocks until something writes to it, with no timeout:
    // a command as ordinary as `instar info` on an uploaded image would
    // hang rather than fail. The work runs on a thread and the answer
    // is waited for, so a regression fails this test instead of
    // stopping the suite (issue #936).
    #[test]
    fn a_fifo_extent_reports_no_cluster_size_without_blocking() {
        use std::ffi::CString;
        use std::sync::mpsc;
        use std::time::Duration;

        let tmp = TempDir::new().unwrap();
        let fifo = tmp.path().join("s001.vmdk");
        let as_c = CString::new(fifo.as_os_str().as_encoded_bytes()).unwrap();
        // SAFETY: a call with a NUL-terminated path and a mode, whose
        // only effect is to create the node; the return value is checked.
        let made = unsafe { libc::mkfifo(as_c.as_ptr(), 0o600) };
        assert_eq!(made, 0, "mkfifo: {}", std::io::Error::last_os_error());
        assert!(!std::fs::metadata(&fifo).unwrap().is_file());

        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let answer = descriptor_cluster_size([(fifo.as_path(), VmdkExtentKind::Sparse)]);
            let _ = tx.send(answer);
        });
        match rx.recv_timeout(Duration::from_secs(20)) {
            Ok(answer) => assert_eq!(answer, None, "a FIFO declares no grain size"),
            Err(mpsc::RecvTimeoutError::Timeout) => {
                panic!("reading a FIFO extent's cluster size blocked")
            }
            Err(other) => panic!("{other}"),
        }
    }

    #[test]
    fn descriptor_cluster_size_reads_the_extents_it_is_given() {
        // The same rule over extents known only as paths and kinds,
        // which is how the chain printer sees a descriptor's.
        let tmp = TempDir::new().unwrap();
        let sparse = tmp.path().join("s001.vmdk");
        let flat = tmp.path().join("f001.vmdk");
        write_sparse_extent(&sparse, 128);
        write_sparse_extent(&flat, 128);
        assert_eq!(
            descriptor_cluster_size([(sparse.as_path(), VmdkExtentKind::Sparse)]),
            Some(65536)
        );
        assert_eq!(
            descriptor_cluster_size([
                (sparse.as_path(), VmdkExtentKind::Sparse),
                (flat.as_path(), VmdkExtentKind::Flat),
            ]),
            None
        );
        assert_eq!(
            descriptor_cluster_size([(flat.as_path(), VmdkExtentKind::Flat)]),
            None
        );
        let no_extents: [(&Path, VmdkExtentKind); 0] = [];
        assert_eq!(descriptor_cluster_size(no_extents), None);
    }

    #[test]
    fn resolve_descriptor_rejects_a_kind_the_extent_table_cannot_describe() {
        // ZERO has no file to lay in the device, and the VMFS kinds
        // name a layout on a VMware filesystem rather than a file.
        for kind in ["ZERO", "VMFS", "VMFSSPARSE"] {
            let tmp = TempDir::new().unwrap();
            let desc = tmp.path().join("foo.vmdk");
            let extent = tmp.path().join("foo-extent.vmdk");
            let text = format!(
                "# Disk DescriptorFile\n\
                 version=1\n\
                 CID=1\n\
                 createType=\"monolithicFlat\"\n\
                 RW 1024 {kind} \"foo-extent.vmdk\"\n"
            );
            std::fs::write(&desc, text).unwrap();
            std::fs::write(&extent, vec![0u8; 512]).unwrap();

            let cfg = default_security_config();
            let err = resolve_vmdk_flat_descriptor(&desc, &cfg).unwrap_err();
            match err {
                ChainError::PathResolutionError(msg) => {
                    assert!(
                        msg.contains("only FLAT and SPARSE extents are supported"),
                        "expected error about the supported kinds for {kind}, got: {msg}"
                    );
                }
                _ => panic!("expected PathResolutionError for {kind}, got {err:?}"),
            }
        }
    }

    #[test]
    fn resolve_descriptor_names_the_extent_bound_that_applied() {
        // The parser's bound is the extent table's size, so the two
        // cannot disagree about how many extents an image may have and
        // the message names a number the user can act on. They are
        // asserted equal here rather than only defined that way,
        // because a later edit to either is what this test exists to
        // catch: a parser that accepted more than the table holds would
        // refuse the image later, from the host, naming a different
        // bound.
        assert_eq!(
            vmdk::MAX_EXTENTS,
            shared::MAX_CHAIN_EXTENTS,
            "the parser's extent bound is the extent table's size"
        );
        let tmp = TempDir::new().unwrap();
        let desc = tmp.path().join("foo.vmdk");
        let mut text = String::from(
            "# Disk DescriptorFile\n\
             version=1\n\
             CID=1\n\
             createType=\"twoGbMaxExtentFlat\"\n",
        );
        for i in 0..=vmdk::MAX_EXTENTS {
            text.push_str(&format!("RW 1024 FLAT \"foo-s{i:03}.vmdk\"\n"));
        }
        std::fs::write(&desc, &text).unwrap();

        let cfg = default_security_config();
        let err = resolve_vmdk_flat_descriptor(&desc, &cfg).unwrap_err();
        match err {
            ChainError::PathResolutionError(msg) => {
                assert!(
                    msg.contains(&format!("more than the {} extents", vmdk::MAX_EXTENTS)),
                    "expected the parser's bound to be named, got: {msg}"
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
            ChainConfig, ChainDeviceInfo, ChainExtent, ChainSegment,
            ImageFormat as SharedImageFormat, InfoResult, CALL_TABLE_ADDR, CHAIN_CONFIG_ADDR,
            MAX_CHAIN_DEVICES, OPERATION_CONFIG_ADDR, OPERATION_LOAD_ADDR, VMM_PARAMS_ADDR,
            VQ_BASE_START,
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
            // ChainDeviceInfo: 4 + 4 + 8 + 8 + 4 + 4 + 4 + 4 = 40 bytes
            assert_eq!(core::mem::size_of::<ChainDeviceInfo>(), 40);

            // ChainSegment: 4 + 4 = 8 bytes
            assert_eq!(core::mem::size_of::<ChainSegment>(), 8);

            // ChainExtent: 8 + 8 + 8 + 4 + 4 = 32 bytes
            assert_eq!(core::mem::size_of::<ChainExtent>(), 32);

            // ChainConfig: 16 header + (16 * 40) devices
            // + (16 * 8) segments + 4 extent count + 4 padding
            // + (64 * 32) extents + 64 reserved = 2904 bytes
            assert_eq!(core::mem::size_of::<ChainConfig>(), 2904);
        }

        #[test]
        fn test_chain_config_memory_address() {
            // Verify the memory addresses don't overlap
            // Memory layout:
            //   0x010000: core.bin (up to 128KB)
            //   0x030000 (OPERATION_LOAD_ADDR): operation binary (up to 768KB)
            //   0x0F0000 (CALL_TABLE_ADDR): call table
            //   0x0F1000 (OPERATION_CONFIG_ADDR): operation config (4KB)
            //   0x0F2000 (CHAIN_CONFIG_ADDR): chain config (4KB)
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
