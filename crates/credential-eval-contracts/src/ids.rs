//! Stable, URL-safe identifiers and digests.
//!
//! Every identifier is validated on deserialization (`try_from = "String"`),
//! so an invalid document fails closed at the boundary. The JSON Schema for
//! each type carries the same grammar as a `pattern`.

use std::borrow::Cow;
use std::fmt;

use schemars::{JsonSchema, Schema, SchemaGenerator, json_schema};
use serde::{Deserialize, Serialize};

use crate::ContractError;

macro_rules! validated_string {
    (
        $(#[$meta:meta])*
        $name:ident, kind = $kind:literal, pattern = $pattern:literal, max = $max:literal, check = $check:expr
    ) => {
        $(#[$meta])*
        #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
        #[serde(try_from = "String", into = "String")]
        pub struct $name(String);

        impl $name {
            /// JSON Schema / ECMA-262 pattern for this identifier.
            pub const PATTERN: &'static str = $pattern;
            /// Maximum length in bytes.
            pub const MAX_LEN: usize = $max;

            /// Validate and wrap `value`.
            pub fn new(value: impl Into<String>) -> Result<Self, ContractError> {
                let value = value.into();
                let check: fn(&str) -> bool = $check;
                if value.is_empty() || value.len() > Self::MAX_LEN || !check(&value) {
                    return Err(ContractError::InvalidId { kind: $kind, value });
                }
                Ok(Self(value))
            }

            /// Borrow the identifier.
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl TryFrom<String> for $name {
            type Error = ContractError;
            fn try_from(value: String) -> Result<Self, Self::Error> {
                Self::new(value)
            }
        }

        impl From<$name> for String {
            fn from(value: $name) -> String {
                value.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }

        impl AsRef<str> for $name {
            fn as_ref(&self) -> &str {
                &self.0
            }
        }

        impl JsonSchema for $name {
            fn schema_name() -> Cow<'static, str> {
                Cow::Borrowed(stringify!($name))
            }
            fn json_schema(_: &mut SchemaGenerator) -> Schema {
                json_schema!({
                    "type": "string",
                    "pattern": $pattern,
                    "minLength": 1,
                    "maxLength": $max,
                })
            }
        }
    };
}

fn slug(value: &str) -> bool {
    let bytes = value.as_bytes();
    (bytes[0].is_ascii_lowercase() || bytes[0].is_ascii_digit())
        && bytes
            .iter()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'-')
}

fn dotted_slug(value: &str) -> bool {
    let bytes = value.as_bytes();
    (bytes[0].is_ascii_lowercase() || bytes[0].is_ascii_digit())
        && bytes
            .iter()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'-' || *b == b'.')
}

fn fixture_path(value: &str) -> bool {
    value
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'/' | b'-'))
        && !value.starts_with('/')
        && value
            .split('/')
            .all(|segment| !segment.is_empty() && segment != "." && segment != "..")
}

fn release_tag(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes[0].is_ascii_alphanumeric()
        && bytes
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

fn git_revision(value: &str) -> bool {
    value.len() == 40
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn sha256(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(|hex| {
        hex.len() == 64
            && hex
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    })
}

validated_string!(
    /// Case (fixture) identifier, unique within a corpus snapshot.
    /// Grammar inherited from the legacy corpus: lowercase slug.
    CaseId, kind = "case", pattern = "^[a-z0-9][a-z0-9-]*$", max = 256, check = slug
);

validated_string!(
    /// Scanner identifier (e.g. `gitleaks`). Unique within a run.
    ScannerId, kind = "scanner", pattern = "^[a-z0-9][a-z0-9-]*$", max = 64, check = slug
);

validated_string!(
    /// Adapter, method or operator identifier (e.g. `lexical.length-plus-one`).
    ComponentId, kind = "component", pattern = "^[a-z0-9][a-z0-9.-]*$", max = 128, check = dotted_slug
);

validated_string!(
    /// Relative fixture path used for materialization. ASCII `[A-Za-z0-9_./-]`,
    /// never absolute, no empty, `.` or `..` segments (checked in code as well
    /// as by the schema pattern).
    FixturePath, kind = "fixture path", pattern = "^(?!/)(?!.*/$)(?!.*//)(?!(.*/)?\\.{1,2}(/|$))[A-Za-z0-9_./-]+$", max = 512, check = fixture_path
);

validated_string!(
    /// A SHA-256 digest rendered as `sha256:<64 lowercase hex>`.
    Sha256Digest, kind = "digest", pattern = "^sha256:[0-9a-f]{64}$", max = 71, check = sha256
);

validated_string!(
    /// A release tag of an evidence source (e.g. `snapshot-2026.10.01`):
    /// ASCII letters, digits, `.`, `_` and `-`, starting with a letter or digit.
    ReleaseTag, kind = "release tag", pattern = "^[A-Za-z0-9][A-Za-z0-9._-]*$", max = 128, check = release_tag
);

validated_string!(
    /// A full Git commit id: 40 lowercase hex digits.
    GitRevision, kind = "git revision", pattern = "^[0-9a-f]{40}$", max = 40, check = git_revision
);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn case_ids() {
        assert!(CaseId::new("generic-api-key-01").is_ok());
        assert!(CaseId::new("").is_err());
        assert!(CaseId::new("Upper").is_err());
        assert!(CaseId::new("-lead").is_err());
        assert!(CaseId::new("a.b").is_err());
    }

    #[test]
    fn paths() {
        assert!(FixturePath::new("smoke/positive-01.txt").is_ok());
        for bad in ["/abs", "a//b", "a/../b", "./a", "a/.", "a b", "a/"] {
            assert!(FixturePath::new(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn release_tags() {
        assert!(ReleaseTag::new("snapshot-2026.10.01").is_ok());
        assert!(ReleaseTag::new("v1.2.3_rc1").is_ok());
        for bad in ["", "-x", ".x", "a b", "a/b", "tag:1"] {
            assert!(ReleaseTag::new(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn git_revisions() {
        assert!(GitRevision::new("ad877c036825a926f93478c2104e675d9c301326").is_ok());
        for bad in [
            "",
            "ad877c0",
            "AD877C036825A926F93478C2104E675D9C301326",
            "g".repeat(40).as_str(),
        ] {
            assert!(GitRevision::new(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn digests() {
        let ok = format!("sha256:{}", "0".repeat(64));
        assert!(Sha256Digest::new(ok).is_ok());
        assert!(Sha256Digest::new(format!("sha256:{}", "A".repeat(64))).is_err());
        assert!(Sha256Digest::new("md5:00").is_err());
    }
}
