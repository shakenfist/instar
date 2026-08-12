//! qemu-img version detection and output profile management.
//!
//! Different qemu-img versions produce different output formats:
//! - qemu-img 6.0 - 7.2.x (Debian 12 bookworm): No "Child node '/file'" section
//! - qemu-img 8.0+ (Debian 13 trixie): Includes "Child node '/file'" section
//!
//! This module provides runtime version detection and profile selection to
//! ensure instar's output matches the installed qemu-img version.

use std::process::Command;
use std::sync::OnceLock;

static VERSION_PROFILE: OnceLock<OutputProfile> = OnceLock::new();

/// Parsed qemu-img version (major.minor).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Version {
    pub major: u32,
    pub minor: u32,
}

impl Version {
    pub fn new(major: u32, minor: u32) -> Self {
        Self { major, minor }
    }

    /// Parse a version string like "7.2", "10.0", or "10.2.0".
    /// Accepts 1-3 parts (major, major.minor, major.minor.patch).
    /// Rejects 4+ parts (e.g., "1.2.3.4") and non-numeric parts.
    pub fn parse(s: &str) -> Option<Self> {
        let parts: Vec<&str> = s.split('.').collect();
        match parts.len() {
            2 | 3 => {
                let major = parts[0].parse().ok()?;
                let minor = parts[1].parse().ok()?;
                // Validate patch part is numeric if present
                if parts.len() == 3 {
                    let _patch: u32 = parts[2].parse().ok()?;
                }
                Some(Self { major, minor })
            }
            1 => {
                // Allow just major version (e.g., "8" means "8.0")
                let major = parts[0].parse().ok()?;
                Some(Self { major, minor: 0 })
            }
            _ => None,
        }
    }
}

impl std::fmt::Display for Version {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{}", self.major, self.minor)
    }
}

/// Output profile controlling version-specific formatting.
///
/// Maps qemu-img versions to feature sets rather than maintaining
/// version-specific code paths. Based on analysis of 80+ qemu-img versions
/// (6.0.0 through 10.2.0), there are exactly two output profiles:
///
/// - **profile-6-0-0** (qemu-img 6.0.0 - 7.2.x): No "Child node '/file'" section
/// - **profile-8-0-0** (qemu-img 8.0.0+): Includes "Child node '/file'" section
#[derive(Debug, Clone)]
pub struct OutputProfile {
    /// The detected or specified version (None if qemu-img not found).
    pub version: Option<Version>,

    /// Include "Child node '/file'" section in human output and
    /// "children" array in JSON output. Added in qemu-img 8.0.
    pub include_child_node: bool,

    /// Include dirty flag in output. When true, shows "cleanly shut down: no"
    /// in human output and "dirty-flag": true in JSON output for dirty images.
    /// Added in qemu-img 6.1. Before 6.1, dirty images were detected but the
    /// flag was not exposed in the output.
    pub include_dirty_flag: bool,

    /// Include the "present" key in `map --output=json` extents.
    /// Added in qemu-img 6.1.0 (measured: absent at 6.0.1, present at
    /// 6.1.0), the same release that exposed the dirty flag. No distro
    /// in the CI matrix ships anything this old — the oldest is Ubuntu
    /// 22.04 at 6.2.0 — so only the cross-profile baseline tests
    /// exercise this boundary.
    pub include_map_present: bool,

    /// Include the "compressed" key in `map --output=json` extents.
    /// Added in qemu-img 8.2.0: measured absent at 8.1.5 and present at
    /// 8.2.0 against instar-testdata's static per-version qemu-img
    /// builds, and confirmed live by Ubuntu 24.04 (8.2.2), which shows
    /// no map divergence while every pre-8.2 distro does.
    pub include_map_compressed: bool,

    /// Use the qemu-img 9.0+ `snapshot -l` column layout: `VM_SIZE` /
    /// `VM_CLOCK` titles, space-separated widths 7/16/8/19/15/10, and a
    /// 4-digit-hour clock. Before 9.0 the titles are `VM SIZE` /
    /// `VM CLOCK`, the fields are concatenated with no separators at
    /// widths 10/16/9/20/13/11, and hours are 2-digit. The boundary is
    /// exactly 9.0.0, measured across 6.0.0-10.2.0.
    ///
    /// The 16/9 split is load-bearing and was got wrong once: 10/18/7
    /// renders identically for any tag that fits its field (16 + 9 ==
    /// 18 + 7) and only diverges on overflow. See
    /// `snapshot_human_overflowing_tag_pins_the_column_widths`, which
    /// is the test that actually distinguishes them.
    pub snapshot_underscored_columns: bool,
}

impl OutputProfile {
    /// Create a profile for a specific version.
    ///
    /// The profile features are determined by version thresholds:
    /// - `include_dirty_flag`: true for version >= 6.1
    /// - `include_child_node`: true for major >= 8
    /// - `include_map_present`: true for version >= 6.1
    /// - `include_map_compressed`: true for version >= 8.2
    /// - `snapshot_underscored_columns`: true for major >= 9
    pub fn for_version(v: Version) -> Self {
        Self {
            version: Some(v),
            include_child_node: v.major >= 8,
            // Dirty flag output was added in qemu-img 6.1
            include_dirty_flag: v.major > 6 || (v.major == 6 && v.minor >= 1),
            // map --output=json gained "present" in qemu-img 6.1
            include_map_present: v.major > 6 || (v.major == 6 && v.minor >= 1),
            // map --output=json gained "compressed" in qemu-img 8.2
            include_map_compressed: v.major > 8 || (v.major == 8 && v.minor >= 2),
            // snapshot -l switched to the underscored layout in qemu-img 9.0
            snapshot_underscored_columns: v.major >= 9,
        }
    }

    /// Create a profile for the newest known qemu-img format.
    /// Used as fallback when qemu-img is not installed.
    pub fn newest() -> Self {
        Self::for_version(Version::new(10, 0))
    }

    /// Create a profile matching qemu-img 6.0-7.2 (profile-6-0-0).
    /// No Child node section. Used by Debian 12 bookworm.
    #[allow(dead_code)]
    pub fn profile_6_0_0() -> Self {
        Self::for_version(Version::new(6, 0))
    }

    /// Create a profile matching qemu-img 8.0+ (profile-8-0-0).
    /// Includes Child node section. Used by Debian 13 trixie.
    #[allow(dead_code)]
    pub fn profile_8_0_0() -> Self {
        Self::for_version(Version::new(8, 0))
    }
}

impl Default for OutputProfile {
    fn default() -> Self {
        Self::newest()
    }
}

/// Detect the installed qemu-img version by running `qemu-img --version`.
///
/// Returns None if qemu-img is not installed or version cannot be parsed.
pub fn detect_qemu_version() -> Option<Version> {
    let output = Command::new("qemu-img").arg("--version").output().ok()?;

    if !output.status.success() {
        return None;
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    parse_qemu_version_output(&stdout)
}

/// Parse a `qemu-img --version` banner into a [`Version`].
///
/// The version token is the whitespace-delimited word immediately after
/// `qemu-img version `; the trailing distro parenthetical is ignored,
/// including the Debian epoch form (`1:7.2+dfsg`) whose embedded version
/// must not be matched. Examples:
/// - `qemu-img version 7.2.22 (Debian 1:7.2+dfsg-7+deb12u18+b3)` -> 7.2
/// - `qemu-img version 10.2.2 (qemu-10.2.2-1.fc44)`              -> 10.2
/// - `qemu-img version 10.1.0 (qemu-kvm-10.1.0-17.el9_8.5)`      -> 10.1
fn parse_qemu_version_output(stdout: &str) -> Option<Version> {
    for line in stdout.lines() {
        if let Some(rest) = line.strip_prefix("qemu-img version ") {
            // Take characters until space or end
            let version_str: String = rest.chars().take_while(|c| !c.is_whitespace()).collect();
            return Version::parse(&version_str);
        }
    }

    None
}

/// Get the output profile for the current environment.
///
/// This function caches the result for the process lifetime.
/// On first call, it detects the qemu-img version (if installed)
/// and creates an appropriate profile.
pub fn get_profile() -> &'static OutputProfile {
    VERSION_PROFILE.get_or_init(|| {
        detect_qemu_version()
            .map(OutputProfile::for_version)
            .unwrap_or_else(OutputProfile::newest)
    })
}

/// Get an output profile for a specific version string.
///
/// Used when the user specifies `--qemu-version` to override detection.
pub fn profile_for_version_str(version_str: &str) -> Option<OutputProfile> {
    Version::parse(version_str).map(OutputProfile::for_version)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version_parse() {
        assert_eq!(Version::parse("7.2"), Some(Version::new(7, 2)));
        assert_eq!(Version::parse("8.0"), Some(Version::new(8, 0)));
        assert_eq!(Version::parse("10.2.0"), Some(Version::new(10, 2)));
        assert_eq!(Version::parse("8"), Some(Version::new(8, 0)));
        assert_eq!(Version::parse(""), None);
        assert_eq!(Version::parse("abc"), None);
        assert_eq!(Version::parse("1.2.3.4"), None);
        assert_eq!(Version::parse("not.a.version"), None);
    }

    #[test]
    fn test_profile_child_node() {
        // profile-6-0-0: versions 6.0 - 7.x should not include child node
        assert!(!OutputProfile::for_version(Version::new(6, 0)).include_child_node);
        assert!(!OutputProfile::for_version(Version::new(6, 2)).include_child_node);
        assert!(!OutputProfile::for_version(Version::new(7, 0)).include_child_node);
        assert!(!OutputProfile::for_version(Version::new(7, 2)).include_child_node);

        // profile-8-0-0: versions 8.0+ should include child node
        assert!(OutputProfile::for_version(Version::new(8, 0)).include_child_node);
        assert!(OutputProfile::for_version(Version::new(8, 2)).include_child_node);
        assert!(OutputProfile::for_version(Version::new(9, 0)).include_child_node);
        assert!(OutputProfile::for_version(Version::new(10, 2)).include_child_node);
    }

    #[test]
    fn test_profile_dirty_flag() {
        // qemu-img 6.0 did not expose dirty flag in output
        assert!(!OutputProfile::for_version(Version::new(6, 0)).include_dirty_flag);

        // qemu-img 6.1+ exposes dirty flag in output
        assert!(OutputProfile::for_version(Version::new(6, 1)).include_dirty_flag);
        assert!(OutputProfile::for_version(Version::new(6, 2)).include_dirty_flag);
        assert!(OutputProfile::for_version(Version::new(7, 0)).include_dirty_flag);
        assert!(OutputProfile::for_version(Version::new(7, 2)).include_dirty_flag);
        assert!(OutputProfile::for_version(Version::new(8, 0)).include_dirty_flag);
        assert!(OutputProfile::for_version(Version::new(10, 0)).include_dirty_flag);
    }

    #[test]
    fn test_profile_map_compressed() {
        // qemu-img map --output=json gained the "compressed" key in
        // 8.2.0. Measured directly: absent at 8.1.5, present at 8.2.0
        // (instar-testdata qemu-img-binaries/x86_64), and confirmed
        // live by Ubuntu 24.04 (8.2.2) showing no map divergence.
        for (major, minor) in [(6, 0), (6, 2), (7, 2), (8, 0), (8, 1)] {
            assert!(
                !OutputProfile::for_version(Version::new(major, minor)).include_map_compressed,
                "{major}.{minor} predates the compressed field"
            );
        }
        for (major, minor) in [(8, 2), (9, 0), (10, 0), (10, 2)] {
            assert!(
                OutputProfile::for_version(Version::new(major, minor)).include_map_compressed,
                "{major}.{minor} emits the compressed field"
            );
        }
    }

    #[test]
    fn test_profile_map_present() {
        // "present" arrived in 6.1.0 alongside the dirty flag.
        // Measured: absent at 6.0.0 and 6.0.1, present from 6.1.0.
        assert!(!OutputProfile::for_version(Version::new(6, 0)).include_map_present);
        for (major, minor) in [(6, 1), (6, 2), (7, 2), (8, 2), (10, 2)] {
            assert!(
                OutputProfile::for_version(Version::new(major, minor)).include_map_present,
                "{major}.{minor} emits the present field"
            );
        }
    }

    #[test]
    fn test_profile_snapshot_columns() {
        // qemu-img snapshot -l switched from `VM SIZE`/`VM CLOCK` to
        // `VM_SIZE`/`VM_CLOCK` (and 2- to 4-digit hours) at exactly
        // 9.0.0; 8.2.2 still emits the old layout. Measured across
        // 6.0.0 through 10.2.0.
        for (major, minor) in [(6, 0), (7, 2), (8, 0), (8, 2)] {
            assert!(
                !OutputProfile::for_version(Version::new(major, minor))
                    .snapshot_underscored_columns,
                "{major}.{minor} uses the pre-9.0 snapshot layout"
            );
        }
        for (major, minor) in [(9, 0), (9, 2), (10, 0), (10, 2)] {
            assert!(
                OutputProfile::for_version(Version::new(major, minor)).snapshot_underscored_columns,
                "{major}.{minor} uses the 9.0+ snapshot layout"
            );
        }
    }

    #[test]
    fn test_parse_qemu_version_output_real_distro_strings() {
        // The exact `qemu-img --version` banners the CI matrix distros
        // ship (tools/probe-qemu-versions.sh, phase-2 step 2a). A parse
        // failure here would silently fall back to newest() (10.0) and
        // emit wrong output on an older-qemu distro.
        let cases = [
            (
                "qemu-img version 7.2.22 (Debian 1:7.2+dfsg-7+deb12u18+b3)",
                Version::new(7, 2),
            ),
            (
                "qemu-img version 10.0.11 (Debian 1:10.0.11+ds-0+deb13u1)",
                Version::new(10, 0),
            ),
            (
                "qemu-img version 6.2.0 (Debian 1:6.2+dfsg-2ubuntu6.31)",
                Version::new(6, 2),
            ),
            (
                "qemu-img version 8.2.2 (Debian 1:8.2.2+ds-0ubuntu1.18)",
                Version::new(8, 2),
            ),
            (
                "qemu-img version 10.2.2 (qemu-10.2.2-1.fc44)",
                Version::new(10, 2),
            ),
            (
                "qemu-img version 10.1.0 (qemu-kvm-10.1.0-17.el9_8.5)",
                Version::new(10, 1),
            ),
            (
                "qemu-img version 10.1.0 (qemu-kvm-10.1.0-16.el10_2.2)",
                Version::new(10, 1),
            ),
        ];
        for (banner, expected) in cases {
            assert_eq!(
                parse_qemu_version_output(banner),
                Some(expected),
                "failed to parse: {banner}"
            );
        }
    }

    #[test]
    fn test_parse_qemu_version_output_ignores_epoch_and_junk() {
        // The epoch '1:7.2' in the parenthetical must not win over the
        // leading 7.2.22 token.
        assert_eq!(
            parse_qemu_version_output("qemu-img version 7.2.22 (Debian 1:7.2+dfsg-7+deb12u18+b3)"),
            Some(Version::new(7, 2))
        );
        // No banner line -> None (caller falls back to newest()).
        assert_eq!(parse_qemu_version_output("qemu-img: not found"), None);
        assert_eq!(parse_qemu_version_output(""), None);
    }

    #[test]
    fn test_version_display() {
        assert_eq!(format!("{}", Version::new(7, 2)), "7.2");
        assert_eq!(format!("{}", Version::new(10, 0)), "10.0");
    }

    #[test]
    fn test_profile_helpers() {
        let p6 = OutputProfile::profile_6_0_0();
        assert!(!p6.include_child_node);
        assert!(!p6.include_dirty_flag); // 6.0 didn't expose dirty flag
        assert_eq!(p6.version, Some(Version::new(6, 0)));

        let p8 = OutputProfile::profile_8_0_0();
        assert!(p8.include_child_node);
        assert!(p8.include_dirty_flag); // 8.0 exposes dirty flag
        assert_eq!(p8.version, Some(Version::new(8, 0)));
    }
}
