//! Escaping for text that came out of an image.
//!
//! Every string the guest reports -- a backing file name, a VMDK create
//! type, a snapshot tag, even the detected format name -- is image data
//! or was produced by code parsing image data inside the sandbox, so the
//! host treats it as attacker controlled wherever it is printed. A
//! crafted name carrying ESC can drive the user's terminal, one carrying
//! a newline can forge whole output lines, and one carrying a bidi
//! override can make the text on screen read differently from the bytes
//! in the image.
//!
//! There are exactly two renderings, and every printer picks one of them
//! rather than escaping by hand:
//!
//! * [`terminal_safe`] for human output on stdout and stderr.
//! * [`json_escape`] for the contents of a JSON string literal.
//!
//! Log records are the exception to picking: `--verbose` installs
//! [`EscapingLogger`], which passes every record through
//! [`terminal_safe`] on its way out, so a `debug!` call never needs to
//! escape its own arguments.

use std::borrow::Cow;
use std::fmt::Write;
use std::path::Path;

/// Whether `c` must not reach a terminal or a JSON document unescaped.
///
/// That is every Unicode control character (the C0 range, DEL and the C1
/// range, which includes the single-byte CSI 0x9B) and the Unicode
/// bidirectional formatting characters, which reorder the text a
/// terminal displays without being visible themselves.
fn is_unsafe_char(c: char) -> bool {
    c.is_control()
        || matches!(
            c,
            '\u{061C}' | '\u{200E}' | '\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}'
        )
}

/// Render an image-derived string for human output.
///
/// Unsafe characters (see [`is_unsafe_char`]) are written the way Rust's
/// `escape_debug` writes them: `\n`, `\r` and `\t`, and `\u{1b}` for the
/// rest. Backslashes and quotes are deliberately left alone, so a Windows
/// or UNC parent path prints exactly as qemu-img and the image record it;
/// the cost is that a name containing the literal text `\u{1b}` reads the
/// same as one containing ESC, which is harmless because neither reaches
/// the terminal as a control character.
///
/// Borrows the input unchanged in the common case of a name with nothing
/// to escape.
pub fn terminal_safe(s: &str) -> Cow<'_, str> {
    if !s.chars().any(is_unsafe_char) {
        return Cow::Borrowed(s);
    }
    let mut out = String::with_capacity(s.len() + 8);
    for c in s.chars() {
        match c {
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if is_unsafe_char(c) => {
                let _ = write!(out, "\\u{{{:x}}}", c as u32);
            }
            c => out.push(c),
        }
    }
    Cow::Owned(out)
}

/// [`terminal_safe`] for a path, which may itself have been resolved from
/// an image-derived reference. Non-UTF-8 bytes are replaced as
/// `Path::display` would replace them.
pub fn terminal_safe_path(path: &Path) -> String {
    terminal_safe(&path.to_string_lossy()).into_owned()
}

/// Escape a string for use as the contents of a JSON string literal.
///
/// Escapes `"` and `\`, writes the short forms JSON defines for `\n`,
/// `\r`, `\t`, backspace and form feed, and writes every other unsafe
/// character (see [`is_unsafe_char`]) as `\uXXXX`. JSON itself only
/// requires the C0 range to be escaped; DEL, the C1 range and the bidi
/// controls are escaped as well so that JSON output read on a terminal
/// is as safe as the human form. Every unsafe character is in the Basic
/// Multilingual Plane, so four hex digits always suffice.
pub fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\x08' => out.push_str("\\b"),
            '\x0C' => out.push_str("\\f"),
            c if is_unsafe_char(c) => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out
}

/// A logger that escapes every record before the inner logger formats it.
///
/// `debug!` lines interpolate image-derived values -- recorded parent
/// names, data file references, paths resolved from them, and every
/// line the guest prints -- and there are too many of them to trust each
/// call site to escape its own arguments. Escaping the finished message
/// here covers all of them, including ones not written yet.
pub struct EscapingLogger<L: log::Log> {
    inner: L,
}

impl<L: log::Log> EscapingLogger<L> {
    pub fn new(inner: L) -> Self {
        Self { inner }
    }
}

impl<L: log::Log> log::Log for EscapingLogger<L> {
    fn enabled(&self, metadata: &log::Metadata<'_>) -> bool {
        self.inner.enabled(metadata)
    }

    fn log(&self, record: &log::Record<'_>) {
        if !self.inner.enabled(record.metadata()) {
            return;
        }
        let message = record.args().to_string();
        let safe = terminal_safe(&message);
        self.inner.log(
            &log::Record::builder()
                .args(format_args!("{safe}"))
                .metadata(record.metadata().clone())
                .module_path(record.module_path())
                .file(record.file())
                .line(record.line())
                .build(),
        );
    }

    fn flush(&self) {
        self.inner.flush();
    }
}

/// Install the `--verbose` logger: env_logger at debug level, with every
/// record escaped by [`EscapingLogger`].
pub fn init_verbose_logger() {
    let inner = env_logger::Builder::new()
        .filter_level(log::LevelFilter::Debug)
        .format_target(false)
        .format_timestamp(None)
        .build();
    let max_level = inner.filter();
    if log::set_boxed_logger(Box::new(EscapingLogger::new(inner))).is_ok() {
        log::set_max_level(max_level);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    #[test]
    fn terminal_safe_borrows_plain_text() {
        assert!(matches!(
            terminal_safe("base.qcow2"),
            Cow::Borrowed("base.qcow2")
        ));
        assert!(matches!(terminal_safe("caf\u{e9}.vhd"), Cow::Borrowed(_)));
    }

    #[test]
    fn terminal_safe_escapes_escape_sequences_and_newlines() {
        assert_eq!(
            terminal_safe("a\x1b[2Jb\nNo errors were found."),
            "a\\u{1b}[2Jb\\nNo errors were found."
        );
        assert_eq!(terminal_safe("\r\t\x07\x7f"), "\\r\\t\\u{7}\\u{7f}");
    }

    #[test]
    fn terminal_safe_escapes_c1_and_bidi_controls() {
        assert_eq!(terminal_safe("x\u{9b}31m"), "x\\u{9b}31m");
        assert_eq!(terminal_safe("evil\u{202e}gpj.vhd"), "evil\\u{202e}gpj.vhd");
        assert_eq!(
            terminal_safe("\u{2066}\u{2069}\u{200f}"),
            "\\u{2066}\\u{2069}\\u{200f}"
        );
    }

    #[test]
    fn terminal_safe_keeps_backslashes_and_quotes() {
        let unc = "\\\\server\\share\\\"parent\".vhd";
        assert!(matches!(terminal_safe(unc), Cow::Borrowed(_)));
    }

    #[test]
    fn terminal_safe_path_escapes() {
        assert_eq!(
            terminal_safe_path(Path::new("/tmp/a\x1bb")),
            "/tmp/a\\u{1b}b"
        );
    }

    struct CapturingLogger(Mutex<Vec<String>>);

    impl log::Log for CapturingLogger {
        fn enabled(&self, metadata: &log::Metadata<'_>) -> bool {
            metadata.level() <= log::Level::Debug
        }
        fn log(&self, record: &log::Record<'_>) {
            self.0.lock().unwrap().push(record.args().to_string());
        }
        fn flush(&self) {}
    }

    fn log_through_escaping_logger(level: log::Level, message: &str) -> Vec<String> {
        use log::Log;
        let logger = EscapingLogger::new(CapturingLogger(Mutex::new(Vec::new())));
        logger.log(
            &log::Record::builder()
                .args(format_args!("parent: {message}"))
                .level(level)
                .build(),
        );
        logger.inner.0.into_inner().unwrap()
    }

    #[test]
    fn escaping_logger_escapes_interpolated_arguments() {
        assert_eq!(
            log_through_escaping_logger(log::Level::Debug, "p\x1b[2J\nforged"),
            vec!["parent: p\\u{1b}[2J\\nforged".to_string()]
        );
    }

    #[test]
    fn escaping_logger_respects_inner_filter() {
        assert!(log_through_escaping_logger(log::Level::Trace, "x").is_empty());
    }

    #[test]
    fn json_escape_basic() {
        assert_eq!(json_escape("snap1"), "snap1");
        assert_eq!(json_escape("a\"b\\c"), "a\\\"b\\\\c");
        assert_eq!(json_escape("\n\r\t\x08\x0c"), "\\n\\r\\t\\b\\f");
    }

    #[test]
    fn json_escape_control_and_bidi() {
        assert_eq!(json_escape("\x00\x1b\x1f"), "\\u0000\\u001b\\u001f");
        assert_eq!(json_escape("\x7f\u{85}\u{9b}"), "\\u007f\\u0085\\u009b");
        assert_eq!(json_escape("\u{202e}"), "\\u202e");
        assert_eq!(json_escape("caf\u{e9}"), "caf\u{e9}");
    }

    /// Decode the contents of a JSON string literal, per RFC 8259
    /// section 7, panicking on anything a JSON parser would reject.
    fn json_unescape(s: &str) -> String {
        let mut out = String::new();
        let mut chars = s.chars();
        while let Some(c) = chars.next() {
            assert!(
                c != '"' && (c as u32) >= 0x20,
                "raw {c:?} is not valid JSON"
            );
            if c != '\\' {
                out.push(c);
                continue;
            }
            match chars.next().expect("dangling backslash") {
                '"' => out.push('"'),
                '\\' => out.push('\\'),
                '/' => out.push('/'),
                'b' => out.push('\x08'),
                'f' => out.push('\x0C'),
                'n' => out.push('\n'),
                'r' => out.push('\r'),
                't' => out.push('\t'),
                'u' => {
                    let hex: String = chars.by_ref().take(4).collect();
                    let code = u32::from_str_radix(&hex, 16).expect("four hex digits");
                    out.push(char::from_u32(code).expect("BMP scalar"));
                }
                other => panic!("invalid escape \\{other}"),
            }
        }
        out
    }

    #[test]
    fn json_escape_output_is_valid_json() {
        // Every scalar value below 0xA0 plus the bidi controls must
        // survive a strict JSON decode unchanged.
        let mut input: String = (0u32..0xA0).filter_map(char::from_u32).collect();
        input.push_str("\u{061c}\u{200e}\u{200f}\u{202a}\u{202e}\u{2066}\u{2069}");
        assert_eq!(json_unescape(&json_escape(&input)), input);
    }
}
