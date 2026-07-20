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
//! - Canonicalizes all paths to prevent `../` traversal attacks
//! - Validates paths against an allowlist of directories
//! - Enforces a maximum chain depth to prevent infinite loops
//! - Does NOT parse image formats on the host

use std::path::{Path, PathBuf};

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

/// Resolve a backing file path relative to the parent image.
///
/// Backing file paths can be:
/// - Absolute paths (start with `/`)
/// - Relative paths (resolved relative to the parent image's directory)
///
/// For portability, when an absolute path doesn't exist, we fall back to
/// resolving just the filename relative to the parent image's directory.
/// This handles images created on different machines where the absolute
/// path may not match the current filesystem layout.
///
/// # Resolution strategy
///
/// 1. If relative: resolve relative to parent image's directory
/// 2. If absolute and exists: use the absolute path
/// 3. If absolute and doesn't exist: fall back to filename-only resolution
///    relative to parent image's directory (for portability)
/// 4. Canonicalize the result to prevent traversal attacks
///
/// # Security
///
/// This function only resolves paths - security allowlist validation happens
/// in `validate_backing_path()` which calls this function. The allowlist is
/// always checked regardless of which resolution strategy succeeded.
pub fn resolve_backing_path(
    parent_image: &Path,
    backing_path: &str,
) -> Result<PathBuf, ChainError> {
    let backing = Path::new(backing_path);
    let parent_dir = parent_image
        .parent()
        .ok_or_else(|| ChainError::PathResolutionError("no parent directory".to_string()))?;

    let resolved = if backing.is_absolute() {
        // For absolute paths: try the path directly first, then fall back
        // to filename-only resolution for portability
        if backing.exists() {
            backing.to_path_buf()
        } else {
            // Absolute path doesn't exist - try filename only, relative to
            // parent image's directory. This handles images created on other
            // machines with different filesystem layouts.
            if let Some(filename) = backing.file_name() {
                let fallback = parent_dir.join(filename);
                if fallback.exists() {
                    fallback
                } else {
                    // Neither the absolute path nor the filename fallback exist
                    return Err(ChainError::BackingFileNotFound(backing.to_path_buf()));
                }
            } else {
                return Err(ChainError::BackingFileNotFound(backing.to_path_buf()));
            }
        }
    } else {
        // Relative path: resolve relative to parent image's directory
        parent_dir.join(backing)
    };

    // Canonicalize to resolve symlinks and `..` components
    resolved.canonicalize().map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            ChainError::BackingFileNotFound(resolved)
        } else {
            ChainError::PathResolutionError(format!("{}: {}", resolved.display(), e))
        }
    })
}

/// Check if a path is within the allowlist.
pub fn is_path_allowed(path: &Path, allowlist: &[PathBuf]) -> bool {
    // Try to canonicalize for comparison
    let canonical = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());

    allowlist.iter().any(|allowed| {
        let allowed_canonical = allowed.canonicalize().unwrap_or_else(|_| allowed.clone());
        canonical.starts_with(&allowed_canonical)
    })
}

/// Validate a backing file path and return the validated path if allowed.
///
/// This function:
/// 1. Resolves the path relative to the parent image
/// 2. Canonicalizes it to prevent traversal attacks
/// 3. Checks it against the security allowlist
/// 4. Verifies the file exists
pub fn validate_backing_path(
    parent_image: &Path,
    backing_path: &str,
    security_config: &SecurityConfig,
) -> Result<PathBuf, ChainError> {
    let allowlist = get_backing_allowlist(security_config, parent_image);

    // Resolve and canonicalize the path
    let resolved = resolve_backing_path(parent_image, backing_path)?;

    // Check against allowlist
    if !is_path_allowed(&resolved, &allowlist) {
        return Err(ChainError::BackingFileNotAllowed {
            path: resolved,
            allowed: allowlist,
        });
    }

    // Verify the file exists (canonicalize already does this, but be explicit)
    if !resolved.exists() {
        return Err(ChainError::BackingFileNotFound(resolved));
    }

    Ok(resolved)
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

        let resolved = resolve_backing_path(&parent, "base.qcow2").unwrap();
        assert_eq!(resolved, backing.canonicalize().unwrap());
    }

    #[test]
    fn test_resolve_absolute_backing_path() {
        let tmp = TempDir::new().unwrap();
        let parent = tmp.path().join("top.qcow2");
        std::fs::write(&parent, b"").unwrap();

        let backing = tmp.path().join("other/base.qcow2");
        std::fs::create_dir_all(backing.parent().unwrap()).unwrap();
        std::fs::write(&backing, b"").unwrap();

        let resolved = resolve_backing_path(&parent, backing.to_str().unwrap()).unwrap();
        assert_eq!(resolved, backing.canonicalize().unwrap());
    }

    #[test]
    fn test_backing_file_not_found() {
        let tmp = TempDir::new().unwrap();
        let parent = tmp.path().join("top.qcow2");
        std::fs::write(&parent, b"").unwrap();

        let result = resolve_backing_path(&parent, "nonexistent.qcow2");
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
        let resolved = resolve_backing_path(&parent, nonexistent_absolute).unwrap();

        // Should fall back to finding base.qcow2 in the parent's directory
        assert_eq!(resolved, backing.canonicalize().unwrap());
    }

    #[test]
    fn test_absolute_path_no_fallback_when_exists() {
        // When the absolute path exists, it should be used directly
        // (no fallback to filename)
        let tmp = TempDir::new().unwrap();

        // Create parent image
        let parent = tmp.path().join("top.qcow2");
        std::fs::write(&parent, b"").unwrap();

        // Create backing file at absolute path
        let other_dir = tmp.path().join("other");
        std::fs::create_dir_all(&other_dir).unwrap();
        let backing_absolute = other_dir.join("base.qcow2");
        std::fs::write(&backing_absolute, b"absolute").unwrap();

        // Also create a file with same name in parent's directory
        let backing_local = tmp.path().join("base.qcow2");
        std::fs::write(&backing_local, b"local").unwrap();

        // Should use the absolute path, not the local file
        let resolved = resolve_backing_path(&parent, backing_absolute.to_str().unwrap()).unwrap();
        assert_eq!(resolved, backing_absolute.canonicalize().unwrap());
    }

    #[test]
    fn test_absolute_path_fallback_not_found() {
        // When absolute path doesn't exist and filename fallback also doesn't
        // exist, should return BackingFileNotFound
        let tmp = TempDir::new().unwrap();
        let parent = tmp.path().join("top.qcow2");
        std::fs::write(&parent, b"").unwrap();

        let result = resolve_backing_path(&parent, "/nonexistent/path/base.qcow2");
        assert!(matches!(result, Err(ChainError::BackingFileNotFound(_))));
    }

    #[test]
    fn test_is_path_allowed() {
        let tmp = TempDir::new().unwrap();
        let allowed = vec![tmp.path().to_path_buf()];

        let inside = tmp.path().join("test.qcow2");
        std::fs::write(&inside, b"").unwrap();
        assert!(is_path_allowed(&inside, &allowed));

        // Path outside allowed directory
        let outside = PathBuf::from("/etc/passwd");
        assert!(!is_path_allowed(&outside, &allowed));
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
            ChainConfig, ChainDeviceInfo, ImageFormat as SharedImageFormat, InfoResult,
            CALL_TABLE_ADDR, CHAIN_CONFIG_ADDR, MAX_CHAIN_DEVICES, OPERATION_CONFIG_ADDR,
            OPERATION_LOAD_ADDR, VMM_PARAMS_ADDR, VQ_BASE_START,
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

            // ChainConfig: 4 + 4 + 8 + (16 * 32) = 528 bytes
            assert_eq!(core::mem::size_of::<ChainConfig>(), 528);
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
