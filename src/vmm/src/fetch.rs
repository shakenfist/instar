//! Telling a URL from a path on an instar input.
//!
//! An input argument is either a filesystem path, exactly as it has always
//! been, or a URL that names where the bytes live. Deciding which has to happen
//! before anything is opened, because the wrong guess produces the wrong error:
//! `instar info https://example.com/disk.qcow2` would otherwise fail with "No
//! such file or directory", telling the user their file is missing rather than
//! that the feature is not built.
//!
//! The rule is deliberately mechanical. An argument that starts with a scheme
//! (a letter, then letters, digits, `+`, `-` or `.`) followed by `://` is a
//! URL. Anything else is a path, so a file called `weird:name` or `c:foo`
//! still opens, because without the `//` there is no URL here.
//!
//! The parse is by hand rather than through a URL or regex crate: instar's
//! dependency tree is part of its attack surface, and the only URL form
//! accepted today is a narrow `file://`, for which percent-decoding and the
//! rest of RFC 3986 would be machinery nothing uses. A real parser belongs
//! with the first protocol that needs one.
//!
//! Nothing here opens a file or starts a process; it only classifies a string.

use std::path::PathBuf;

/// What an input argument turned out to be.
// Exercised by its tests before any operation calls it, so the binary's
// dead-code lint would otherwise reject the whole module.
#[allow(dead_code)]
#[derive(Debug, PartialEq, Eq)]
pub enum InputSource {
    /// An ordinary filesystem path, to be opened as instar always has.
    Path(PathBuf),
    /// A `file://` URL, reduced to the absolute path it names. The path is
    /// not percent-decoded: a `%` anywhere in the URL is refused instead, so
    /// the text the user typed and the path that is opened cannot differ.
    FileUrl(PathBuf),
}

/// The sentence shown for each scheme that is recognised but not served,
/// keyed by lowercase scheme. This is the one place that says which schemes
/// exist, so enabling one, or wording it differently per operation, is an edit
/// to this table and nowhere else.
const REFUSED_SCHEMES: &[(&str, &str)] = &[
    (
        "https",
        "instar does not accept https:// inputs yet; pass a local path",
    ),
    (
        "http",
        "instar does not accept http:// inputs yet; pass a local path",
    ),
    (
        "s3",
        "instar does not accept s3:// inputs yet; pass a local path",
    ),
    (
        "nbd",
        "instar does not accept nbd:// inputs yet; pass a local path",
    ),
];

/// Returns the length of the scheme if `arg` begins with `scheme://`, where a
/// scheme is `[A-Za-z][A-Za-z0-9+.-]*`.
fn url_scheme_len(arg: &str) -> Option<usize> {
    let bytes = arg.as_bytes();
    if !bytes.first()?.is_ascii_alphabetic() {
        return None;
    }
    let len = bytes
        .iter()
        .position(|b| !(b.is_ascii_alphanumeric() || matches!(b, b'+' | b'-' | b'.')))
        .unwrap_or(bytes.len());
    if arg[len..].starts_with("://") {
        Some(len)
    } else {
        None
    }
}

/// Parses the part of a `file://` URL after the scheme: an empty authority or
/// `localhost`, then an absolute path. A query, a fragment, a percent escape,
/// a NUL, or any other authority is refused, because each would make the path
/// that is opened differ from the one the user wrote or reach a different host.
fn parse_file_url(rest: &str) -> Result<PathBuf, String> {
    let refuse = |why: &str| {
        Err(format!(
            "instar cannot use the input file://{}: {}",
            rest, why
        ))
    };
    if rest.contains('?') {
        return refuse("a query string is not supported");
    }
    if rest.contains('#') {
        return refuse("a fragment is not supported");
    }
    if rest.contains('%') {
        return refuse("percent escapes are not supported");
    }
    if rest.contains('\0') {
        return refuse("a NUL byte is not allowed");
    }
    let path = match rest.find("/") {
        Some(slash) => {
            let authority = &rest[..slash];
            if !authority.is_empty() && !authority.eq_ignore_ascii_case("localhost") {
                return refuse("only an empty or localhost host is supported");
            }
            &rest[slash..]
        }
        // No slash at all: either `file://localhost` with no path, or a bare
        // word that is a relative path or a host. Neither is absolute.
        None => {
            return refuse(
                if rest.is_empty() || rest.eq_ignore_ascii_case("localhost") {
                    "no path was given"
                } else {
                    "the path must be absolute"
                },
            );
        }
    };
    Ok(PathBuf::from(path))
}

/// Classifies an input argument as a plain path or a `file://` URL, or refuses
/// it with a sentence fit to show the user.
///
/// The scheme is compared case-insensitively, as RFC 3986 says to. Every URL
/// scheme other than `file` is refused by name, using the sentence in
/// [`REFUSED_SCHEMES`] or a generic one for a scheme not in it.
#[allow(dead_code)] // Called by operations as they learn to read through a URL.
pub fn classify_input(arg: &str) -> Result<InputSource, String> {
    let Some(len) = url_scheme_len(arg) else {
        return Ok(InputSource::Path(PathBuf::from(arg)));
    };
    let scheme = arg[..len].to_ascii_lowercase();
    if scheme == "file" {
        return parse_file_url(&arg[len + 3..]).map(InputSource::FileUrl);
    }
    match REFUSED_SCHEMES.iter().find(|(name, _)| *name == scheme) {
        Some((_, sentence)) => Err((*sentence).to_string()),
        None => Err(format!(
            "instar does not accept {}:// inputs; pass a local path",
            scheme
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn file_url(arg: &str) -> PathBuf {
        match classify_input(arg) {
            Ok(InputSource::FileUrl(p)) => p,
            other => panic!("{} did not classify as a file URL: {:?}", arg, other),
        }
    }

    fn refusal(arg: &str) -> String {
        match classify_input(arg) {
            Err(e) => e,
            other => panic!("{} was not refused: {:?}", arg, other),
        }
    }

    fn path(arg: &str) {
        assert_eq!(
            classify_input(arg),
            Ok(InputSource::Path(PathBuf::from(arg)))
        );
    }

    #[test]
    fn empty_authority_absolute_path() {
        assert_eq!(file_url("file:///tmp/x"), PathBuf::from("/tmp/x"));
    }

    #[test]
    fn localhost_authority_absolute_path() {
        assert_eq!(file_url("file://localhost/tmp/x"), PathBuf::from("/tmp/x"));
    }

    #[test]
    fn scheme_and_localhost_are_case_insensitive() {
        assert_eq!(file_url("FILE://LocalHost/tmp/x"), PathBuf::from("/tmp/x"));
    }

    #[test]
    fn foreign_authority_refused() {
        assert!(refusal("file://evil.example/tmp/x").contains("host"));
    }

    #[test]
    fn relative_path_refused() {
        assert!(refusal("file://relative").contains("absolute"));
    }

    #[test]
    fn no_path_after_localhost_refused() {
        assert!(refusal("file://localhost").contains("no path"));
    }

    #[test]
    fn nothing_after_scheme_refused() {
        assert!(refusal("file://").contains("no path"));
    }

    #[test]
    fn query_refused() {
        assert!(refusal("file:///x?y").contains("query"));
    }

    #[test]
    fn fragment_refused() {
        assert!(refusal("file:///x#y").contains("fragment"));
    }

    #[test]
    fn percent_escape_refused() {
        assert!(refusal("file:///%2e%2e/x").contains("percent"));
    }

    #[test]
    fn nul_byte_refused() {
        assert!(refusal("file:///tm\0p/x").contains("NUL"));
    }

    #[test]
    fn https_refused_by_name() {
        assert_eq!(
            refusal("https://example.com/x"),
            "instar does not accept https:// inputs yet; pass a local path"
        );
    }

    #[test]
    fn scheme_case_is_folded_for_refusal() {
        assert!(refusal("HTTPS://example.com/x").contains("https://"));
    }

    #[test]
    fn unknown_scheme_refused_by_name() {
        assert!(refusal("gopher://example.com/x").contains("gopher://"));
    }

    #[test]
    fn plain_absolute_path() {
        path("/plain/path");
    }

    #[test]
    fn dot_relative_path() {
        path("./rel");
    }

    #[test]
    fn colon_without_slashes_is_a_path() {
        path("weird:name");
    }

    #[test]
    fn single_slash_after_colon_is_a_path() {
        path("file:/tmp/x");
    }

    #[test]
    fn digit_leading_scheme_is_a_path() {
        path("1http://x");
    }

    #[test]
    fn empty_argument_is_a_path() {
        path("");
    }
}
