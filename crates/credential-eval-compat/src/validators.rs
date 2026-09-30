//! Value validators of the legacy format-contract table.
//!
//! Legacy contracts may carry a `validate(value)` function beside their
//! `pattern` (`benchmarks/types.ts:94`); lexical mutation operators call
//! `pattern.test(value) && validate(value)` to decide whether an edited value
//! still satisfies the contract (`operators/lexical.ts:20-21`,
//! `assessment.ts:416`). Validators are code, so a migration evidence file
//! names them (`legacy:<name>`) and the CLI resolves the name here
//! (kernel-deltas N5). At the pinned commit four families have one:
//!
//! | name | family | legacy source |
//! |---|---|---|
//! | `legacy:discord-bot-token` | `discord-bot-token` | `assessment.ts:280` |
//! | `legacy:confluent-cloud-api-secret` | `confluent-cloud-api-secret` | `assessment.ts:33, 324` |
//! | `legacy:gitlab-routable-optional` | `gitlab-runner-authentication-token` | `lib/beta8/212.ts:36-43` |
//! | `legacy:gitlab-routable-required` | `gitlab-routable-personal-access-token` | `lib/beta8/1012c.ts:36-42` |
//!
//! JavaScript strings are UTF-16; each validator only ever sees values that
//! already matched an ASCII-only contract pattern (the kernel checks the
//! pattern first), and is written over UTF-16 code units where the legacy
//! arithmetic depends on them.

use std::sync::{Arc, LazyLock};

use credential_eval_kernel::evaluation::evidence::ValueValidator;
use regex::Regex;

/// Every validator name this module provides.
pub const NAMES: [&str; 4] = [
    "legacy:discord-bot-token",
    "legacy:confluent-cloud-api-secret",
    "legacy:gitlab-routable-optional",
    "legacy:gitlab-routable-required",
];

/// Resolve a validator name.
pub fn named(name: &str) -> Option<ValueValidator> {
    let f: fn(&str) -> bool = match name {
        "legacy:discord-bot-token" => discord_bot_token,
        "legacy:confluent-cloud-api-secret" => confluent_cloud_api_secret,
        "legacy:gitlab-routable-optional" => gitlab_routable_optional,
        "legacy:gitlab-routable-required" => gitlab_routable_required,
        _ => return None,
    };
    Some(Arc::new(f))
}

/// IEEE CRC-32 of `text` read as Latin-1: each UTF-16 code unit contributes
/// its low byte (`lib/crc32.ts` `crc32Latin1`).
pub fn crc32_latin1(text: &str) -> u32 {
    let mut c: u32 = 0xFFFF_FFFF;
    for unit in text.encode_utf16() {
        let byte = (unit & 0xFF) as u32;
        c ^= byte;
        for _ in 0..8 {
            c = if c & 1 == 1 {
                0xEDB8_8320 ^ (c >> 1)
            } else {
                c >> 1
            };
        }
    }
    c ^ 0xFFFF_FFFF
}

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn base64_standard(bytes: &[u8]) -> String {
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let b = [
            chunk[0],
            chunk.get(1).copied().unwrap_or(0),
            chunk.get(2).copied().unwrap_or(0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(B64[((n >> (18 - 6 * i)) & 63) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

/// WHATWG forgiving-base64 decode, as `atob`. `None` where `atob` throws.
fn atob(input: &str) -> Option<Vec<u8>> {
    let mut data: Vec<u8> = input
        .bytes()
        .filter(|b| !matches!(b, b' ' | b'\t' | b'\n' | b'\x0c' | b'\r'))
        .collect();
    if !input.is_ascii() {
        return None;
    }
    if data.len() % 4 == 0 {
        for _ in 0..2 {
            if data.last() == Some(&b'=') {
                data.pop();
            }
        }
    }
    if data.len() % 4 == 1 {
        return None;
    }
    let mut out = Vec::new();
    let (mut buffer, mut bits) = (0u32, 0u32);
    for b in data {
        let v = B64.iter().position(|c| *c == b)? as u32;
        buffer = (buffer << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(((buffer >> bits) & 0xFF) as u8);
        }
    }
    Some(out)
}

/// `discord-bot-token`: the first segment, read as base64url, decodes to a
/// numeric (snowflake) id. `atob` throwing makes the legacy validator throw;
/// that cannot happen for a value matching the contract pattern (24 or 26
/// alphabet characters), and it is reported as `false` here.
pub fn discord_bot_token(value: &str) -> bool {
    let first = value.split('.').next().unwrap_or("");
    let mapped: String = first
        .chars()
        .map(|c| match c {
            '-' => '+',
            '_' => '/',
            c => c,
        })
        .collect();
    atob(&mapped).is_some_and(|bytes| !bytes.is_empty() && bytes.iter().all(u8::is_ascii_digit))
}

fn utf16_slice(units: &[u16], start: usize, end: usize) -> String {
    let start = start.min(units.len());
    let end = end.clamp(start, units.len());
    String::from_utf16_lossy(&units[start..end])
}

/// `confluent-cloud-api-secret`: the last six characters are the first six
/// of standard Base64 over the little-endian CRC-32 of the 54 characters after
/// `cflt` (`value.slice(58) === confluentChecksum(value.slice(4, 58))`).
pub fn confluent_cloud_api_secret(value: &str) -> bool {
    let units: Vec<u16> = value.encode_utf16().collect();
    let body = utf16_slice(&units, 4, 58);
    let tail = utf16_slice(&units, 58, units.len());
    let checksum = base64_standard(&crc32_latin1(&body).to_le_bytes());
    tail == checksum[..6]
}

fn base36(mut n: u32) -> String {
    const DIGITS: &[u8; 36] = b"0123456789abcdefghijklmnopqrstuvwxyz";
    if n == 0 {
        return "0".into();
    }
    let mut out = Vec::new();
    while n > 0 {
        out.push(DIGITS[(n % 36) as usize]);
        n /= 36;
    }
    out.reverse();
    String::from_utf8(out).expect("ascii")
}

/// Width of the base36 CRC suffix (`GITLAB_ROUTABLE_CRC_WIDTH`).
const CRC_WIDTH: usize = 7;

fn base36_crc(text: &str) -> String {
    format!("{:0>width$}", base36(crc32_latin1(text)), width = CRC_WIDTH)
}

fn routable(payload: &str, length: &str, crc: &str, value: &str) -> bool {
    let declared = u32::from_str_radix(length, 36).ok();
    let units: Vec<u16> = value.encode_utf16().collect();
    let prefix = utf16_slice(&units, 0, units.len().saturating_sub(CRC_WIDTH));
    declared == u32::try_from(payload.encode_utf16().count()).ok() && base36_crc(&prefix) == crc
}

static RUNNER: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^(glrt-)([A-Za-z0-9_-]+)\.([0-9a-z]{2})\.([0-9a-z]{2})([0-9a-z]{7})$")
        .expect("valid regex")
});
static PAT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^glpat-([A-Za-z0-9_-]+)\.[0-9a-z]{2}\.([0-9a-z]{2})([0-9a-z]{7})$")
        .expect("valid regex")
});

/// `gitlab-runner-authentication-token` (`gitlabRoutableValid`): a value in
/// the routable `glrt-` shape must carry a consistent payload length and
/// base36 CRC; any other value is left to the pattern alone.
pub fn gitlab_routable_optional(value: &str) -> bool {
    match RUNNER.captures(value) {
        None => true,
        Some(m) => routable(&m[2], &m[4], &m[5], value),
    }
}

/// `gitlab-routable-personal-access-token` (`gitlabRoutablePatValid`): the
/// value must be in the routable `glpat-` shape with a consistent payload
/// length and base36 CRC.
pub fn gitlab_routable_required(value: &str) -> bool {
    match PAT.captures(value) {
        None => false,
        Some(m) => routable(&m[1], &m[2], &m[3], value),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Synthetic values only; none is a real credential.

    #[test]
    fn crc32_matches_the_ieee_check_value() {
        assert_eq!(crc32_latin1("123456789"), 0xCBF4_3926);
        assert_eq!(crc32_latin1(""), 0);
    }

    #[test]
    fn base64_matches_btoa() {
        assert_eq!(base64_standard(&[0xde, 0xad, 0xbe, 0xef]), "3q2+7w==");
        assert_eq!(base64_standard(b"abc"), "YWJj");
        assert_eq!(atob("3q2+7w=="), Some(vec![0xde, 0xad, 0xbe, 0xef]));
        assert_eq!(atob("YWJ"), Some(b"ab".to_vec()));
        assert_eq!(atob("Y"), None);
        assert_eq!(atob("Y!=="), None);
    }

    #[test]
    fn discord_segment_must_decode_to_digits() {
        // base64("123456789012345678") = "MTIzNDU2Nzg5MDEyMzQ1Njc4" (24 chars).
        assert!(discord_bot_token(
            "MTIzNDU2Nzg5MDEyMzQ1Njc4.AAAAAA.zzzzzzzzzzzzzzzzzzzzzzzzzzz"
        ));
        assert!(!discord_bot_token(
            "QTIzNDU2Nzg5MDEyMzQ1Njc4.AAAAAA.zzzzzzzzzzzzzzzzzzzzzzzzzzz"
        ));
    }

    fn confluent(body: &str) -> String {
        let sum = base64_standard(&crc32_latin1(body).to_le_bytes());
        format!("cflt{body}{}", &sum[..6])
    }

    #[test]
    fn confluent_checksum_round_trips() {
        let body = "A".repeat(54);
        let value = confluent(&body);
        assert_eq!(value.len(), 64);
        assert!(confluent_cloud_api_secret(&value));
        let mut broken = value.clone();
        broken.replace_range(10..11, "B");
        assert!(!confluent_cloud_api_secret(&broken));
    }

    fn routable_value(prefix: &str, payload: &str, middle: &str) -> String {
        let length = format!("{:0>2}", base36(payload.len() as u32));
        let head = format!("{prefix}{payload}.{middle}.{length}");
        format!("{head}{}", base36_crc(&head))
    }

    #[test]
    fn routable_tokens_need_length_and_crc() {
        let pat = routable_value("glpat-", "syntheticpayloadxyz", "01");
        assert!(gitlab_routable_required(&pat));
        assert!(!gitlab_routable_required(
            &pat.replace("synthetic", "Synthetic")
        ));
        assert!(!gitlab_routable_required("glpat-notroutable"));
        let runner = routable_value("glrt-", "syntheticrunner", "0a");
        assert!(gitlab_routable_optional(&runner));
        assert!(!gitlab_routable_optional(
            &runner.replace("runner", "Runner")
        ));
        assert!(gitlab_routable_optional("glrt-legacy-shape"));
    }

    #[test]
    fn every_name_resolves() {
        for name in NAMES {
            assert!(named(name).is_some(), "{name}");
        }
        assert!(named("legacy:unknown").is_none());
    }
}
