//! Mapping scanner-reported values back to UTF-8 byte ranges.
//!
//! Ports the legacy `locate` family (`scanners/index.mjs:62-252`) exactly:
//! a finding is located by byte-searching the reported value in the fixture,
//! filtered by the reported 1-based line; repeated identical
//! `(path, value, line)` reports within one scan claim ascending unclaimed
//! occurrences; zero or several candidates fail closed. Scanner columns are
//! never consulted, and no expected range is ever consulted.
//!
//! Every error message is fixed and never contains the value being located.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fmt;
use std::path::{Component, Path, PathBuf};
use std::sync::LazyLock;

use regex::Regex;
use serde_json::Value;

/// A failure to map scanner output onto fixture bytes. The message is a fixed,
/// sanitized string (it is safe to log and to publish as a status reason).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MapError(pub &'static str);

impl fmt::Display for MapError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0)
    }
}

impl std::error::Error for MapError {}

/// A located byte range on one fixture.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Located {
    /// Fixture path (relative, `/`-separated).
    pub path: String,
    /// Inclusive start byte.
    pub start: usize,
    /// Exclusive end byte.
    pub end: usize,
}

/// The fixtures a scan ran over: materialization root plus exact contents.
#[derive(Debug, Clone)]
pub struct Fixtures<'a> {
    root: PathBuf,
    by_path: BTreeMap<&'a str, &'a str>,
}

impl<'a> Fixtures<'a> {
    /// Fixtures materialized under `root` (which should be canonical, as the
    /// scanner sees it).
    pub fn new(
        root: impl Into<PathBuf>,
        files: impl IntoIterator<Item = (&'a str, &'a str)>,
    ) -> Self {
        Self {
            root: root.into(),
            by_path: files.into_iter().collect(),
        }
    }

    /// The materialization root.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Content of a fixture by relative path.
    pub fn content(&self, path: &str) -> Option<&'a str> {
        self.by_path.get(path).copied()
    }

    /// Resolve a scanner-reported file to a known fixture: legacy
    /// `path.isAbsolute(file) ? path.relative(root, file) : file.replace(/^\.\//, "")`
    /// followed by `fixtures.find(f => f.path === relative)`.
    pub fn resolve(&self, file: &str) -> Result<(&'a str, &'a str), MapError> {
        let relative = if file.starts_with('/') {
            relative_to(&self.root, Path::new(file))
        } else {
            Some(file.strip_prefix("./").unwrap_or(file).to_owned())
        };
        relative
            .and_then(|rel| {
                self.by_path
                    .get_key_value(rel.as_str())
                    .map(|(k, v)| (*k, *v))
            })
            .ok_or(MapError("Unknown scanner path"))
    }
}

/// Lexical `path.relative(root, file)` for a file under `root`; `None` when
/// the file lies outside the root.
fn relative_to(root: &Path, file: &Path) -> Option<String> {
    let normalize = |p: &Path| {
        let mut parts: Vec<String> = Vec::new();
        for component in p.components() {
            match component {
                Component::Normal(part) => parts.push(part.to_string_lossy().into_owned()),
                Component::ParentDir => {
                    parts.pop();
                }
                Component::CurDir | Component::RootDir | Component::Prefix(_) => {}
            }
        }
        parts
    };
    let root = normalize(root);
    let file = normalize(file);
    if file.len() <= root.len() || file[..root.len()] != root[..] {
        return None;
    }
    Some(file[root.len()..].join("/"))
}

/// Line filter of a scanner report. JavaScript `line == null` disables the
/// filter; any other value must strictly equal the computed 1-based line.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Line {
    /// `undefined`: no filter.
    Undefined,
    /// `null`: no filter.
    Null,
    /// A number: the line must equal it.
    Number(f64),
    /// Any other JSON value: never equal to a line number.
    Other,
}

impl Line {
    /// Read a line field from a JSON report.
    pub fn from_json(value: Option<&Value>) -> Self {
        match value {
            None => Self::Undefined,
            Some(Value::Null) => Self::Null,
            Some(Value::Number(n)) => n.as_f64().map_or(Self::Other, Self::Number),
            Some(_) => Self::Other,
        }
    }

    fn accepts(self, line: usize) -> bool {
        match self {
            Self::Undefined | Self::Null => true,
            #[allow(clippy::cast_precision_loss)]
            Self::Number(n) => n == line as f64,
            Self::Other => false,
        }
    }

    fn key(self) -> String {
        match self {
            Self::Undefined => "undefined".into(),
            Self::Null => "null".into(),
            Self::Number(n) => format!("{n}"),
            Self::Other => "other".into(),
        }
    }
}

/// Claimed occurrences shared by every locate call in one scan (legacy `claim`).
#[derive(Debug, Default)]
pub struct Claims(HashMap<(String, String, String), BTreeSet<usize>>);

impl Claims {
    /// Pick the first unclaimed candidate when there are several; legacy
    /// `index.mjs:93-102`.
    fn resolve(&mut self, key: (String, String, String), matches: &[usize]) -> Vec<usize> {
        if matches.len() <= 1 {
            return matches.to_vec();
        }
        let used = self.0.entry(key).or_default();
        match matches.iter().find(|at| !used.contains(at)) {
            Some(&first) => {
                used.insert(first);
                vec![first]
            }
            None => matches.to_vec(),
        }
    }
}

/// 1-based line of byte offset `at` (count of `\n` before it, plus one).
pub fn line_of(content: &str, at: usize) -> usize {
    content.as_bytes()[..at]
        .iter()
        .filter(|b| **b == b'\n')
        .count()
        + 1
}

/// Legacy `locate(fixtures, root, file, raw, line, claim)`.
pub fn locate(
    fixtures: &Fixtures<'_>,
    file: Option<&str>,
    raw: Option<&str>,
    line: Line,
    claims: &mut Claims,
) -> Result<Located, MapError> {
    let (Some(file), Some(raw)) = (file, raw) else {
        return Err(MapError("Unmappable scanner finding"));
    };
    if raw.is_empty() {
        return Err(MapError("Unmappable scanner finding"));
    }
    let (path, content) = fixtures.resolve(file)?;
    let haystack = content.as_bytes();
    let needle = raw.as_bytes();
    let mut matches = Vec::new();
    let mut from = 0;
    while let Some(offset) = find_bytes(&haystack[from..], needle) {
        let at = from + offset;
        if line.accepts(line_of(content, at)) {
            matches.push(at);
        }
        from = at + 1;
    }
    let key = (path.to_owned(), raw.to_owned(), line.key());
    let candidates = claims.resolve(key, &matches);
    match candidates.as_slice() {
        [at] => Ok(Located {
            path: path.to_owned(),
            start: *at,
            end: at + needle.len(),
        }),
        _ => Err(MapError("Ambiguous or unmappable scanner finding")),
    }
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.len() > haystack.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// Legacy `locatePercentEncoded` (`index.mjs:206-241`): each `%XX` escape of
/// a printable ASCII byte matches either the escape (hex digits in any case)
/// or the literal byte, on the reported line only.
pub fn locate_percent_encoded(
    fixtures: &Fixtures<'_>,
    file: Option<&str>,
    raw: Option<&str>,
    line: Line,
    claims: &mut Claims,
) -> Result<Located, MapError> {
    let (Some(file), Some(raw)) = (file, raw) else {
        return Err(MapError("Unmappable scanner finding"));
    };
    if raw.is_empty() {
        return Err(MapError("Unmappable scanner finding"));
    }
    let (path, content) = fixtures.resolve(file)?;
    let pattern = percent_pattern(raw);
    let regex = Regex::new(&pattern).map_err(|_| MapError("Unmappable scanner finding"))?;
    let mut matches: Vec<(usize, usize)> = Vec::new();
    for m in regex.find_iter(content) {
        if line.accepts(line_of(content, m.start())) {
            matches.push((m.start(), m.end()));
        }
    }
    let starts: Vec<usize> = matches.iter().map(|m| m.0).collect();
    // Legacy keys percent claims with NUL separators, distinct from `locate`'s.
    let key = (format!("%{path}"), raw.to_owned(), line.key());
    let candidates = claims.resolve(key, &starts);
    match candidates.as_slice() {
        [at] => {
            let end = matches.iter().find(|m| m.0 == *at).map_or(*at, |m| m.1);
            Ok(Located {
                path: path.to_owned(),
                start: *at,
                end,
            })
        }
        _ => Err(MapError("Ambiguous or unmappable percent-encoded finding")),
    }
}

static ESCAPE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new("%[0-9A-Fa-f]{2}").expect("static regex"));

fn percent_pattern(raw: &str) -> String {
    let mut pattern = String::new();
    let mut last = 0;
    for m in ESCAPE.find_iter(raw) {
        pattern.push_str(&regex::escape(&raw[last..m.start()]));
        let token = m.as_str();
        let byte = u8::from_str_radix(&token[1..], 16).expect("two hex digits");
        let mut any_case = String::from("%");
        for d in token[1..].chars() {
            if d.is_ascii_alphabetic() {
                any_case.push('[');
                any_case.push(d.to_ascii_lowercase());
                any_case.push(d.to_ascii_uppercase());
                any_case.push(']');
            } else {
                any_case.push(d);
            }
        }
        if (0x20..0x7f).contains(&byte) {
            let literal = regex::escape(&char::from(byte).to_string());
            pattern.push_str(&format!("(?:{any_case}|{literal})"));
        } else {
            pattern.push_str(&any_case);
        }
        last = m.end();
    }
    pattern.push_str(&regex::escape(&raw[last..]));
    pattern
}

/// Whether `raw` carries a `%XX` escape (legacy `PERCENT`).
pub fn has_percent_escape(raw: &str) -> bool {
    ESCAPE.is_match(raw)
}

/// Byte length of the UTF-8 encoding of the first `n` UTF-16 code units of
/// `units`, exactly as `Buffer.byteLength(text.slice(0, n))` computes it (a
/// lone surrogate encodes as three bytes of U+FFFD).
pub fn utf16_prefix_bytes(units: &[u16], n: usize) -> usize {
    let n = n.min(units.len());
    let mut bytes = 0;
    let mut i = 0;
    while i < n {
        let unit = units[i];
        if (0xD800..0xDC00).contains(&unit) && i + 1 < n && (0xDC00..0xE000).contains(&units[i + 1])
        {
            bytes += 4;
            i += 2;
        } else {
            bytes += match unit {
                0..=0x7F => 1,
                0x80..=0x7FF => 2,
                _ => 3,
            };
            i += 1;
        }
    }
    bytes
}

/// Converts UTF-16 code-unit offsets reported by JavaScript scanners into
/// UTF-8 byte offsets for one text (legacy `Buffer.byteLength(text.slice(0, i))`).
#[derive(Debug)]
pub struct Utf16Offsets {
    /// `byte[i]` = byte offset of UTF-16 index `i`, or `None` inside a pair.
    bytes: Vec<Option<usize>>,
}

impl Utf16Offsets {
    /// Build the table for `text`.
    pub fn new(text: &str) -> Self {
        let mut bytes = Vec::with_capacity(text.len() + 1);
        let mut offset = 0;
        for c in text.chars() {
            bytes.push(Some(offset));
            if c.len_utf16() == 2 {
                bytes.push(None);
            }
            offset += c.len_utf8();
        }
        bytes.push(Some(offset));
        Self { bytes }
    }

    /// Byte offset of UTF-16 index `index`, clamped to the text length as
    /// `String.prototype.slice` clamps. `None` when the index splits a
    /// surrogate pair (legacy would produce a non-boundary offset that its
    /// range validation rejects; here it fails closed immediately).
    pub fn byte(&self, index: u64) -> Option<usize> {
        let last = self.bytes.len() - 1;
        let index = usize::try_from(index).unwrap_or(usize::MAX).min(last);
        self.bytes[index]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fx<'a>(files: &[(&'a str, &'a str)]) -> Fixtures<'a> {
        Fixtures::new("/scan/root", files.iter().copied())
    }

    #[test]
    fn resolves_absolute_relative_and_unknown_paths() {
        let fixtures = fx(&[("a/b.txt", "x")]);
        assert_eq!(fixtures.resolve("/scan/root/a/b.txt").unwrap().0, "a/b.txt");
        assert_eq!(fixtures.resolve("./a/b.txt").unwrap().0, "a/b.txt");
        assert_eq!(fixtures.resolve("a/b.txt").unwrap().0, "a/b.txt");
        assert_eq!(
            fixtures.resolve("/scan/root/a/../a/b.txt").unwrap().0,
            "a/b.txt"
        );
        assert!(fixtures.resolve("/elsewhere/a/b.txt").is_err());
        assert!(fixtures.resolve("/scan/root").is_err());
    }

    #[test]
    fn locates_utf8_bytes_with_line_filter() {
        let content = "é=TOKEN1\nTOKEN1\n";
        let fixtures = fx(&[("f", content)]);
        let mut claims = Claims::default();
        let hit = locate(
            &fixtures,
            Some("f"),
            Some("TOKEN1"),
            Line::Number(1.0),
            &mut claims,
        )
        .unwrap();
        assert_eq!((hit.start, hit.end), (3, 9));
        let hit = locate(
            &fixtures,
            Some("f"),
            Some("TOKEN1"),
            Line::Number(2.0),
            &mut claims,
        )
        .unwrap();
        assert_eq!((hit.start, hit.end), (10, 16));
        // Without a line, repeated reports claim occurrences in ascending order
        // until none is left, then fail closed.
        let mut fresh = Claims::default();
        let first = locate(
            &fixtures,
            Some("f"),
            Some("TOKEN1"),
            Line::Undefined,
            &mut fresh,
        )
        .unwrap();
        let second = locate(&fixtures, Some("f"), Some("TOKEN1"), Line::Null, &mut fresh).unwrap();
        assert_eq!(
            (first.start, second.start),
            (3, 3),
            "undefined and null lines are distinct claim keys"
        );
        locate(
            &fixtures,
            Some("f"),
            Some("TOKEN1"),
            Line::Undefined,
            &mut fresh,
        )
        .unwrap();
        let err = locate(
            &fixtures,
            Some("f"),
            Some("TOKEN1"),
            Line::Undefined,
            &mut fresh,
        );
        assert_eq!(
            err.unwrap_err().0,
            "Ambiguous or unmappable scanner finding"
        );
        // Not on the reported line.
        assert!(
            locate(
                &fixtures,
                Some("f"),
                Some("TOKEN1"),
                Line::Number(3.0),
                &mut claims
            )
            .is_err()
        );
        // A string line never equals a number.
        assert!(
            locate(
                &fixtures,
                Some("f"),
                Some("TOKEN1"),
                Line::Other,
                &mut claims
            )
            .is_err()
        );
        assert!(locate(&fixtures, Some("f"), Some(""), Line::Undefined, &mut claims).is_err());
        assert!(locate(&fixtures, None, Some("x"), Line::Undefined, &mut claims).is_err());
    }

    #[test]
    fn claims_resolve_repeats_in_ascending_order_then_fail() {
        let fixtures = fx(&[("f", "k=AAAA k=AAAA\n")]);
        let mut claims = Claims::default();
        let a = locate(
            &fixtures,
            Some("f"),
            Some("AAAA"),
            Line::Number(1.0),
            &mut claims,
        )
        .unwrap();
        let b = locate(
            &fixtures,
            Some("f"),
            Some("AAAA"),
            Line::Number(1.0),
            &mut claims,
        )
        .unwrap();
        assert_eq!((a.start, b.start), (2, 9));
        assert!(
            locate(
                &fixtures,
                Some("f"),
                Some("AAAA"),
                Line::Number(1.0),
                &mut claims
            )
            .is_err()
        );
    }

    #[test]
    fn overlapping_occurrences_are_candidates() {
        let fixtures = fx(&[("f", "aaa")]);
        let mut claims = Claims::default();
        let a = locate(
            &fixtures,
            Some("f"),
            Some("aa"),
            Line::Number(1.0),
            &mut claims,
        )
        .unwrap();
        let b = locate(
            &fixtures,
            Some("f"),
            Some("aa"),
            Line::Number(1.0),
            &mut claims,
        )
        .unwrap();
        assert_eq!((a.start, b.start), (0, 1));
    }

    #[test]
    fn percent_encoded_matches_literal_or_escape() {
        let content = "uri=scheme://user:p!ss@host\n";
        let fixtures = fx(&[("f", content)]);
        let mut claims = Claims::default();
        let hit = locate_percent_encoded(
            &fixtures,
            Some("f"),
            Some("scheme://user:p%21ss@host"),
            Line::Number(1.0),
            &mut claims,
        )
        .unwrap();
        assert_eq!(&content[hit.start..hit.end], "scheme://user:p!ss@host");
        let content = "x=a%2fb\n";
        let fixtures = fx(&[("f", content)]);
        let hit = locate_percent_encoded(
            &fixtures,
            Some("f"),
            Some("a%2Fb"),
            Line::Undefined,
            &mut claims,
        )
        .unwrap();
        assert_eq!((hit.start, hit.end), (2, 7));
        assert!(has_percent_escape("a%2Fb"));
        assert!(!has_percent_escape("a%zz"));
    }

    #[test]
    fn utf16_conversion_matches_buffer_bytelength() {
        let text = "a😀é";
        let units: Vec<u16> = text.encode_utf16().collect();
        assert_eq!(utf16_prefix_bytes(&units, 1), 1);
        assert_eq!(utf16_prefix_bytes(&units, 2), 4); // lone high surrogate
        assert_eq!(utf16_prefix_bytes(&units, 3), 5);
        assert_eq!(utf16_prefix_bytes(&units, 4), 7);
        let offsets = Utf16Offsets::new(text);
        assert_eq!(offsets.byte(0), Some(0));
        assert_eq!(offsets.byte(1), Some(1));
        assert_eq!(offsets.byte(2), None);
        assert_eq!(offsets.byte(3), Some(5));
        assert_eq!(offsets.byte(4), Some(7));
        assert_eq!(offsets.byte(99), Some(7));
    }
}
