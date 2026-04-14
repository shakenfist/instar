//! Configuration file support for instar.
//!
//! Configuration files are read in order, with later values overriding earlier:
//! 1. /etc/instar/config - System-wide defaults
//! 2. ~/.config/instar/config - User defaults
//! 3. Command-line arguments - Per-invocation overrides
//!
//! Config files use TOML format.

// Many items are defined for future phases (backing chain support, CLI integration)
#![allow(dead_code)]

use serde::Deserialize;
use std::path::{Path, PathBuf};

/// System-wide config file path
pub const SYSTEM_CONFIG_PATH: &str = "/etc/instar/config";

/// User config file path relative to home directory
pub const USER_CONFIG_RELATIVE: &str = ".config/instar/config";

/// Special marker for the directory containing the input image
pub const MARKER_IMAGE_DIR: &str = "$IMAGE_DIR";

/// Special marker for the current working directory
pub const MARKER_CWD: &str = "$CWD";

/// Root configuration structure
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct InstarConfig {
    /// Global settings
    pub global: GlobalConfig,
    /// Security settings
    pub security: SecurityConfig,
    /// Convert operation settings
    pub convert: ConvertConfig,
    /// Copy operation settings
    pub copy: CopyConfig,
}

/// Global settings applicable to all operations
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, rename_all = "kebab-case")]
pub struct GlobalConfig {
    /// Default output format for convert (e.g., "raw", "qcow2")
    pub output_format: Option<String>,
    /// Ignore quirks mode for format detection
    pub ignore_quirks: Option<bool>,
    /// QEMU version compatibility for info output
    pub qemu_version: Option<String>,
    /// Default output mode ("human" or "json")
    pub output: Option<String>,
    /// Enable verbose logging
    pub verbose: Option<bool>,
}

/// Security settings
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, rename_all = "kebab-case")]
pub struct SecurityConfig {
    /// Directories allowed for backing file resolution.
    /// Special markers: $IMAGE_DIR, $CWD
    /// Default if not specified: ["$IMAGE_DIR"]
    pub backing_path_allowlist: Option<Vec<String>>,
    /// Maximum backing chain depth (default: 16)
    pub max_chain_depth: Option<u32>,
}

/// Convert operation settings
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, rename_all = "kebab-case")]
pub struct ConvertConfig {
    /// Enable sparse output by default
    pub sparse: Option<bool>,
    /// Show progress during conversion
    pub progress: Option<bool>,
}

/// Copy operation settings
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, rename_all = "kebab-case")]
pub struct CopyConfig {
    /// Skip zero sectors by default
    pub skip_zeros: Option<bool>,
    /// Verify data after copy
    pub verify: Option<bool>,
}

/// Tracks the source of each configuration value
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum ConfigSource {
    /// Built-in default value
    #[default]
    Default,
    /// From system config file (/etc/instar/config)
    System,
    /// From user config file (~/.config/instar/config)
    User,
    /// From command-line argument
    CommandLine,
}

impl std::fmt::Display for ConfigSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConfigSource::Default => write!(f, "(default)"),
            ConfigSource::System => write!(f, "/etc/instar/config"),
            ConfigSource::User => write!(f, "~/.config/instar/config"),
            ConfigSource::CommandLine => write!(f, "(command line)"),
        }
    }
}

/// Configuration with source tracking for introspection
#[derive(Debug, Clone, Default)]
pub struct TrackedConfig {
    pub config: InstarConfig,
    pub sources: ConfigSources,
}

/// Tracks which file each config value came from
#[derive(Debug, Clone, Default)]
pub struct ConfigSources {
    pub global_output_format: ConfigSource,
    pub global_ignore_quirks: ConfigSource,
    pub global_qemu_version: ConfigSource,
    pub global_output: ConfigSource,
    pub global_verbose: ConfigSource,
    pub security_backing_path_allowlist: ConfigSource,
    pub security_max_chain_depth: ConfigSource,
    pub convert_sparse: ConfigSource,
    pub convert_progress: ConfigSource,
    pub copy_skip_zeros: ConfigSource,
    pub copy_verify: ConfigSource,
}

/// Load configuration from all sources, merging them in order.
/// Returns the merged config with source tracking.
pub fn load_config() -> TrackedConfig {
    let mut tracked = TrackedConfig::default();

    // Layer 1: System config
    if let Some(sys_config) = load_config_file(Path::new(SYSTEM_CONFIG_PATH)) {
        merge_config(&mut tracked, sys_config, ConfigSource::System);
    }

    // Layer 2: User config
    if let Some(home) = dirs::home_dir() {
        let user_path = home.join(USER_CONFIG_RELATIVE);
        if let Some(user_config) = load_config_file(&user_path) {
            merge_config(&mut tracked, user_config, ConfigSource::User);
        }
    }

    tracked
}

/// Load and parse a single config file
fn load_config_file(path: &Path) -> Option<InstarConfig> {
    let content = std::fs::read_to_string(path).ok()?;
    toml::from_str(&content).ok()
}

/// Merge a loaded config into the tracked config, updating sources
fn merge_config(tracked: &mut TrackedConfig, loaded: InstarConfig, source: ConfigSource) {
    // Global settings
    if loaded.global.output_format.is_some() {
        tracked.config.global.output_format = loaded.global.output_format;
        tracked.sources.global_output_format = source.clone();
    }
    if loaded.global.ignore_quirks.is_some() {
        tracked.config.global.ignore_quirks = loaded.global.ignore_quirks;
        tracked.sources.global_ignore_quirks = source.clone();
    }
    if loaded.global.qemu_version.is_some() {
        tracked.config.global.qemu_version = loaded.global.qemu_version;
        tracked.sources.global_qemu_version = source.clone();
    }
    if loaded.global.output.is_some() {
        tracked.config.global.output = loaded.global.output;
        tracked.sources.global_output = source.clone();
    }
    if loaded.global.verbose.is_some() {
        tracked.config.global.verbose = loaded.global.verbose;
        tracked.sources.global_verbose = source.clone();
    }

    // Security settings
    if loaded.security.backing_path_allowlist.is_some() {
        tracked.config.security.backing_path_allowlist = loaded.security.backing_path_allowlist;
        tracked.sources.security_backing_path_allowlist = source.clone();
    }
    if loaded.security.max_chain_depth.is_some() {
        tracked.config.security.max_chain_depth = loaded.security.max_chain_depth;
        tracked.sources.security_max_chain_depth = source.clone();
    }

    // Convert settings
    if loaded.convert.sparse.is_some() {
        tracked.config.convert.sparse = loaded.convert.sparse;
        tracked.sources.convert_sparse = source.clone();
    }
    if loaded.convert.progress.is_some() {
        tracked.config.convert.progress = loaded.convert.progress;
        tracked.sources.convert_progress = source.clone();
    }

    // Copy settings
    if loaded.copy.skip_zeros.is_some() {
        tracked.config.copy.skip_zeros = loaded.copy.skip_zeros;
        tracked.sources.copy_skip_zeros = source.clone();
    }
    if loaded.copy.verify.is_some() {
        tracked.config.copy.verify = loaded.copy.verify;
        tracked.sources.copy_verify = source;
    }
}

/// Expand marker values in the backing path allowlist
pub fn expand_backing_allowlist(allowlist: &[String], image_path: &Path) -> Vec<PathBuf> {
    let cwd = std::env::current_dir().unwrap_or_default();
    let image_dir = image_path
        .parent()
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| cwd.clone());

    allowlist
        .iter()
        .map(|entry| match entry.as_str() {
            MARKER_IMAGE_DIR => image_dir.clone(),
            MARKER_CWD => cwd.clone(),
            path => PathBuf::from(path),
        })
        .collect()
}

/// Get the effective backing path allowlist, with defaults applied
pub fn get_backing_allowlist(config: &SecurityConfig, image_path: &Path) -> Vec<PathBuf> {
    let default_list = vec![MARKER_IMAGE_DIR.to_string()];
    let allowlist = config
        .backing_path_allowlist
        .as_ref()
        .unwrap_or(&default_list);

    expand_backing_allowlist(allowlist, image_path)
}

/// Get the effective max chain depth, with default applied
pub fn get_max_chain_depth(config: &SecurityConfig) -> u32 {
    config.max_chain_depth.unwrap_or(16)
}

/// Validate all config files and return any errors found
pub fn validate_config_files() -> Vec<(PathBuf, String)> {
    let mut errors = Vec::new();

    // Check system config
    let system_path = Path::new(SYSTEM_CONFIG_PATH);
    if system_path.exists() {
        if let Err(e) = validate_config_file(system_path) {
            errors.push((system_path.to_path_buf(), e));
        }
    }

    // Check user config
    if let Some(home) = dirs::home_dir() {
        let user_path = home.join(USER_CONFIG_RELATIVE);
        if user_path.exists() {
            if let Err(e) = validate_config_file(&user_path) {
                errors.push((user_path, e));
            }
        }
    }

    errors
}

/// Validate a single config file
fn validate_config_file(path: &Path) -> Result<(), String> {
    let content =
        std::fs::read_to_string(path).map_err(|e| format!("Failed to read file: {}", e))?;

    let _: InstarConfig = toml::from_str(&content).map_err(|e| format!("Invalid TOML: {}", e))?;

    Ok(())
}

/// Format the configuration for display
pub fn format_config(tracked: &TrackedConfig, show_sources: bool) -> String {
    let mut output = String::new();

    output.push_str("[global]\n");
    format_option(
        &mut output,
        "output-format",
        &tracked.config.global.output_format,
        &tracked.sources.global_output_format,
        show_sources,
    );
    format_option(
        &mut output,
        "ignore-quirks",
        &tracked.config.global.ignore_quirks,
        &tracked.sources.global_ignore_quirks,
        show_sources,
    );
    format_option(
        &mut output,
        "qemu-version",
        &tracked.config.global.qemu_version,
        &tracked.sources.global_qemu_version,
        show_sources,
    );
    format_option(
        &mut output,
        "output",
        &tracked.config.global.output,
        &tracked.sources.global_output,
        show_sources,
    );
    format_option(
        &mut output,
        "verbose",
        &tracked.config.global.verbose,
        &tracked.sources.global_verbose,
        show_sources,
    );

    output.push_str("\n[security]\n");
    format_list_option(
        &mut output,
        "backing-path-allowlist",
        &tracked.config.security.backing_path_allowlist,
        &tracked.sources.security_backing_path_allowlist,
        show_sources,
    );
    format_option(
        &mut output,
        "max-chain-depth",
        &tracked.config.security.max_chain_depth,
        &tracked.sources.security_max_chain_depth,
        show_sources,
    );

    output.push_str("\n[convert]\n");
    format_option(
        &mut output,
        "sparse",
        &tracked.config.convert.sparse,
        &tracked.sources.convert_sparse,
        show_sources,
    );
    format_option(
        &mut output,
        "progress",
        &tracked.config.convert.progress,
        &tracked.sources.convert_progress,
        show_sources,
    );

    output.push_str("\n[copy]\n");
    format_option(
        &mut output,
        "skip-zeros",
        &tracked.config.copy.skip_zeros,
        &tracked.sources.copy_skip_zeros,
        show_sources,
    );
    format_option(
        &mut output,
        "verify",
        &tracked.config.copy.verify,
        &tracked.sources.copy_verify,
        show_sources,
    );

    output
}

fn format_option<T: std::fmt::Display>(
    output: &mut String,
    name: &str,
    value: &Option<T>,
    source: &ConfigSource,
    show_sources: bool,
) {
    let value_str = match value {
        Some(v) => format!("{}", v),
        None => "(not set)".to_string(),
    };

    if show_sources {
        output.push_str(&format!("{} = {}  # from: {}\n", name, value_str, source));
    } else {
        output.push_str(&format!("{} = {}\n", name, value_str));
    }
}

fn format_list_option(
    output: &mut String,
    name: &str,
    value: &Option<Vec<String>>,
    source: &ConfigSource,
    show_sources: bool,
) {
    match value {
        Some(list) => {
            if show_sources {
                output.push_str(&format!("{} = [  # from: {}\n", name, source));
            } else {
                output.push_str(&format!("{} = [\n", name));
            }
            for item in list {
                output.push_str(&format!("    \"{}\",\n", item));
            }
            output.push_str("]\n");
        }
        None => {
            if show_sources {
                output.push_str(&format!("{} = (not set)  # from: {}\n", name, source));
            } else {
                output.push_str(&format!("{} = (not set)\n", name));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_expand_image_dir_marker() {
        let allowlist = vec![MARKER_IMAGE_DIR.to_string()];
        let image_path = Path::new("/home/user/images/test.qcow2");
        let expanded = expand_backing_allowlist(&allowlist, image_path);
        assert_eq!(expanded, vec![PathBuf::from("/home/user/images")]);
    }

    #[test]
    fn test_expand_mixed_paths() {
        let allowlist = vec![
            MARKER_IMAGE_DIR.to_string(),
            "/var/lib/libvirt/images".to_string(),
        ];
        let image_path = Path::new("/home/user/test.qcow2");
        let expanded = expand_backing_allowlist(&allowlist, image_path);
        assert_eq!(expanded.len(), 2);
        assert_eq!(expanded[0], PathBuf::from("/home/user"));
        assert_eq!(expanded[1], PathBuf::from("/var/lib/libvirt/images"));
    }

    #[test]
    fn test_default_max_chain_depth() {
        let config = SecurityConfig::default();
        assert_eq!(get_max_chain_depth(&config), 16);
    }

    #[test]
    fn test_custom_max_chain_depth() {
        let config = SecurityConfig {
            max_chain_depth: Some(8),
            ..Default::default()
        };
        assert_eq!(get_max_chain_depth(&config), 8);
    }
}
