//! The one range convention of the protocol.
//!
//! A range is a **half-open interval `[start, end)` of UTF-8 byte offsets**
//! into the exact case content bytes. Both endpoints must fall on a code point
//! boundary, `start < end` (ranges are never empty) and `end <= content length`.
//! This is the legacy convention (`benchmarks/types.ts:1`,
//! `benchmarks/lib/scoring.ts:34-35`). Adapters convert scanner-native offsets
//! (lines/columns, UTF-16 units, characters) to this form at the adapter
//! boundary; the kernel never sees any other convention.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Half-open UTF-8 byte range `[start, end)`.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(deny_unknown_fields)]
pub struct ByteRange {
    /// Inclusive start byte offset.
    pub start: u64,
    /// Exclusive end byte offset.
    pub end: u64,
}

impl ByteRange {
    /// Construct without validation.
    pub const fn new(start: u64, end: u64) -> Self {
        Self { start, end }
    }

    /// Length in bytes (saturating; a valid range is never empty).
    pub const fn len(&self) -> u64 {
        self.end.saturating_sub(self.start)
    }

    /// True when the range covers no bytes (never valid in the protocol).
    pub const fn is_empty(&self) -> bool {
        self.end <= self.start
    }

    /// Whether this is a valid protocol range over `content`: non-empty,
    /// in bounds, and both endpoints on UTF-8 code point boundaries.
    pub fn is_valid_in(&self, content: &str) -> bool {
        let (Ok(start), Ok(end)) = (usize::try_from(self.start), usize::try_from(self.end)) else {
            return false;
        };
        start < end
            && end <= content.len()
            && content.is_char_boundary(start)
            && content.is_char_boundary(end)
    }
}

/// An authored acceptable envelope around a span: a wider range a finding may
/// cover without being `OVERBROAD`. The reason is authored evidence.
#[derive(
    Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(deny_unknown_fields)]
pub struct Envelope {
    /// Inclusive start byte offset (`<=` the span start).
    pub start: u64,
    /// Exclusive end byte offset (`>=` the span end).
    pub end: u64,
    /// Why the wider range is acceptable. Must be non-blank.
    pub reason: String,
}

impl Envelope {
    /// The envelope as a plain range.
    pub const fn range(&self) -> ByteRange {
        ByteRange::new(self.start, self.end)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn utf8_boundaries() {
        // "é" is two bytes; offset 2 is inside it.
        let content = "aé=x";
        assert!(ByteRange::new(0, 1).is_valid_in(content));
        assert!(ByteRange::new(1, 3).is_valid_in(content));
        assert!(!ByteRange::new(1, 2).is_valid_in(content));
        assert!(!ByteRange::new(3, 3).is_valid_in(content));
        assert!(!ByteRange::new(0, 6).is_valid_in(content));
        assert!(ByteRange::new(0, 5).is_valid_in(content));
    }
}
