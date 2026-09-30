//! Canonical JSON and digests.
//!
//! Canonical JSON is compact JSON with object keys sorted by byte order at
//! every depth, no insignificant whitespace, strings escaped by `serde_json`,
//! and numbers rendered by `serde_json` (integers verbatim, floats in shortest
//! round-trip form). It is independent of struct field declaration order and
//! of `serde_json`'s `preserve_order` feature, so digests stay stable under
//! refactors that reorder fields.

use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::ids::Sha256Digest;

/// Serialize `value` to canonical JSON bytes.
///
/// # Panics
/// Only if `value`'s `Serialize` implementation fails, which cannot happen for
/// the contract types (no non-string map keys, no non-finite floats).
pub fn to_canonical_json<T: Serialize + ?Sized>(value: &T) -> Vec<u8> {
    let value = serde_json::to_value(value).expect("contract types serialize to JSON");
    let mut out = Vec::new();
    write_value(&value, &mut out);
    out
}

fn write_value(value: &Value, out: &mut Vec<u8>) {
    match value {
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            out.push(b'{');
            for (i, key) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                write_value(&Value::String((*key).clone()), out);
                out.push(b':');
                write_value(&map[key.as_str()], out);
            }
            out.push(b'}');
        }
        Value::Array(items) => {
            out.push(b'[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                write_value(item, out);
            }
            out.push(b']');
        }
        scalar => out.extend(serde_json::to_vec(scalar).expect("scalar JSON")),
    }
}

/// SHA-256 of raw bytes, rendered as `sha256:<hex>`.
pub fn sha256_bytes(bytes: &[u8]) -> Sha256Digest {
    let digest = Sha256::digest(bytes);
    let mut hex = String::with_capacity(7 + 64);
    hex.push_str("sha256:");
    for byte in digest {
        hex.push(char::from(b"0123456789abcdef"[usize::from(byte >> 4)]));
        hex.push(char::from(b"0123456789abcdef"[usize::from(byte & 0xf)]));
    }
    Sha256Digest::new(hex).expect("well-formed digest")
}

/// SHA-256 of the canonical JSON of `value`.
pub fn sha256_canonical<T: Serialize + ?Sized>(value: &T) -> Sha256Digest {
    sha256_bytes(&to_canonical_json(value))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn sorts_keys_at_every_depth() {
        let value = json!({"b": 1, "a": {"z": [3, {"y": true, "x": null}], "c": "é"}});
        assert_eq!(
            String::from_utf8(to_canonical_json(&value)).unwrap(),
            r#"{"a":{"c":"é","z":[3,{"x":null,"y":true}]},"b":1}"#
        );
    }

    #[test]
    fn digest_of_empty_string() {
        assert_eq!(
            sha256_bytes(b"").as_str(),
            "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }
}
