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
    /// Unknown or unsupported format
    Unknown,
}

impl ImageFormat {
    /// Parse format from string (as returned by info operation)
    pub fn from_str(s: &str) -> Self {
        match s {
            "raw" => ImageFormat::Raw,
            "qcow2" => ImageFormat::Qcow2,
            "qcow1" => ImageFormat::Qcow1,
            "vmdk" => ImageFormat::Vmdk4,
            "vmdk3" => ImageFormat::Vmdk3,
            "vpc" => ImageFormat::Vhd,
            "vhdx" => ImageFormat::Vhdx,
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
        }
    }
}

impl std::fmt::Display for ImageFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ImageFormat::Raw => write!(f, "raw"),
            ImageFormat::Qcow2 => write!(f, "qcow2"),
            ImageFormat::Qcow1 => write!(f, "qcow1"),
            ImageFormat::Vmdk4 => write!(f, "vmdk"),
            ImageFormat::Vmdk3 => write!(f, "vmdk3"),
            ImageFormat::Vhd => write!(f, "vpc"),
            ImageFormat::Vhdx => write!(f, "vhdx"),
            ImageFormat::Unknown => write!(f, "unknown"),
        }
    }
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
    /// I/O error
    IoError(std::io::Error),
}

impl std::fmt::Display for ChainError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ChainError::InfoOperationFailed(msg) => {
                write!(f, "Info operation failed: {}", msg)
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
                write!(
                    f,
                    "Backing chain depth {} exceeds maximum of {}",
                    depth, max
                )
            }
            ChainError::CircularReference(path) => {
                write!(f, "Circular reference detected: {}", path.display())
            }
            ChainError::PathResolutionError(msg) => {
                write!(f, "Path resolution error: {}", msg)
            }
            ChainError::IoError(e) => write!(f, "I/O error: {}", e),
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
        });

        chain.push(ChainImage {
            path: PathBuf::from("/test/base.qcow2"),
            format: ImageFormat::Qcow2,
            virtual_size: 1024 * 1024 * 1024,
            actual_size: 100 * 1024 * 1024,
            cluster_size: 65536,
            backing_file_raw: None,
            flags: 0,
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

    // Tests for shared::ChainConfig and shared::ChainDeviceInfo structures
    mod chain_config_tests {
        use shared::{
            ChainConfig, ChainDeviceInfo, ImageFormat as SharedImageFormat, InfoResult,
            CHAIN_CONFIG_ADDR, CHAIN_CONFIG_MAX_SIZE, MAX_CHAIN_DEVICES, OPERATION_CONFIG_ADDR,
            OPERATION_LOAD_ADDR,
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
            assert!(CHAIN_CONFIG_ADDR > OPERATION_CONFIG_ADDR);
            assert!(CHAIN_CONFIG_ADDR + CHAIN_CONFIG_MAX_SIZE <= OPERATION_LOAD_ADDR);
        }
    }
}
