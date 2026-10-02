//! Deterministic synthetic workloads.
//!
//! Every workload is generated from fixed seeds and fixed templates, so a
//! given `(id, units)` always yields the same bytes
//! ([`WORKLOAD_CONTRACT_VERSION`]). Values are shaped like credentials but are
//! random synthetic strings: no real or documented-public credential is used,
//! and no generated text is ever written to an artifact (only its size and
//! digest).
//!
//! Generation is bounded: it stops, and reports [`TooLarge`], as soon as the
//! output would exceed the caller's byte limit, so a large `units` cannot
//! exhaust memory.
//!
//! The `assignments-*` and `otp-*` generators reproduce, byte for byte, the
//! fixtures of the Redact Secret allocation harness of issue #1121 (seeds 1,
//! 7, 11 and 13), so allocation counts stay comparable with that baseline.

use credential_eval_contracts::ids::Sha256Digest;
use credential_eval_contracts::performance::WorkloadId;
use sha2::{Digest, Sha256};

/// The generated input would exceed the byte limit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TooLarge {
    /// The limit that was exceeded.
    pub max_bytes: usize,
}

impl std::fmt::Display for TooLarge {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "workload exceeds {} bytes", self.max_bytes)
    }
}

impl std::error::Error for TooLarge {}

/// Output buffer with a hard limit.
struct Out {
    buf: String,
    max: usize,
    over: bool,
}

impl Out {
    fn new(max: usize) -> Self {
        Self {
            buf: String::new(),
            max,
            over: false,
        }
    }

    fn push(&mut self, piece: &str) {
        if self.over {
            return;
        }
        if self.buf.len() + piece.len() > self.max {
            self.over = true;
            return;
        }
        self.buf.push_str(piece);
    }

    fn done(&self) -> bool {
        self.over
    }

    fn finish(self) -> Result<String, TooLarge> {
        if self.over {
            Err(TooLarge {
                max_bytes: self.max,
            })
        } else {
            Ok(self.buf)
        }
    }
}

/// Linear congruential generator (the harness's own constants).
struct Lcg(u64);

impl Lcg {
    fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        self.0 >> 33
    }

    fn pick<'a>(&mut self, items: &'a [&'a str]) -> &'a str {
        items[usize::try_from(self.next()).unwrap_or(0) % items.len()]
    }

    fn string(&mut self, alphabet: &[u8], len: usize) -> String {
        (0..len)
            .map(|_| alphabet[usize::try_from(self.next()).unwrap_or(0) % alphabet.len()] as char)
            .collect()
    }
}

const B62: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
const HEX: &[u8] = b"0123456789abcdef";
const B64: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const KEYS: &[&str] = &[
    "api_key",
    "secret",
    "password",
    "auth_token",
    "client_secret",
];

/// The synthetic storage account key of the Azure workloads (base64 of a
/// sentence that says it is not a credential).
const AZURE_KEY: &str = "U1lOVEhFVElDX1JFVk9LRURfQUNDT1VOVF9LRVlfT05MWV9OT1RfUkVBTF9DUkVERU5USUFM";

const ORDINARY_LINE: &str = "ordinary request processed successfully\n";
const PADDING_LINE: &str =
    "The quick brown fox, request id 12345, status ok; path /var/log/app.log\n";

/// Generate workload `id` with `units` units, at most `max_bytes` long.
///
/// A unit is one line (or record) of the workload; the catalogue entry of
/// each id in [`WorkloadId`] says what it is.
pub fn generate(id: WorkloadId, units: u32, max_bytes: usize) -> Result<String, TooLarge> {
    let units = units as usize;
    let mut out = Out::new(max_bytes);
    match id {
        WorkloadId::SparseUnicode => {
            repeat(&mut out, units, ORDINARY_LINE);
            out.push("한글🙂");
        }
        WorkloadId::DenseUnicode => repeat(&mut out, units, "한글 문장과🙂이모지 테스트\n"),
        WorkloadId::SparseInvisible => {
            repeat(&mut out, units, "ordinary request\n");
            out.push("\u{200b}");
            repeat(&mut out, units, "completed successfully\n");
        }
        WorkloadId::DenseInvisible => repeat(&mut out, units, "a\u{200b}b\u{200c}가🙂\n"),
        WorkloadId::OverlapClusters => overlap_clusters(&mut out, units),
        WorkloadId::SeamHeavy => seam_heavy(&mut out, units),
        WorkloadId::RepeatedShortLogLines => repeat(&mut out, units, "GET /health 200 3ms\n"),
        WorkloadId::LongSingleLineAssignments => long_assignments(&mut out, units),
        WorkloadId::DenseEarlyExhaustion => early_exhaustion(&mut out, units),
        WorkloadId::AssignmentsOrdinary => ordinary(&mut out, units),
        WorkloadId::AssignmentsDiverse => diverse(&mut out, units),
        WorkloadId::AssignmentsReferences => references(&mut out, units),
        WorkloadId::OtpDense => otp_dense(&mut out, units),
        WorkloadId::OtpSparse => {
            repeat(&mut out, units, PADDING_LINE);
            out.push(
                "otpauth://totp/Example:alice@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Example\n",
            );
        }
        WorkloadId::AzureSingle => out.push(&azure_record()),
        WorkloadId::AzureRepeatedRecords => {
            let record = format!("{}\n", azure_record());
            repeat(&mut out, units, &record);
        }
        WorkloadId::AzureDuplicateKeys => {
            out.push(&azure_record());
            let field = format!(";AccountKey={AZURE_KEY}");
            repeat(&mut out, units.saturating_sub(1), &field);
        }
        WorkloadId::AzureBenign => repeat(&mut out, units, ORDINARY_LINE),
        WorkloadId::OverlapDisjoint => overlap(&mut out, units, OverlapShape::Disjoint),
        WorkloadId::OverlapSparse => overlap(&mut out, units, OverlapShape::Sparse),
        WorkloadId::OverlapPairs => overlap(&mut out, units, OverlapShape::Pairs),
        WorkloadId::OverlapDense => overlap(&mut out, units, OverlapShape::Dense),
    }
    out.finish()
}

/// SHA-256 of generated bytes, as a contract digest.
pub fn digest(bytes: &[u8]) -> Sha256Digest {
    let hash = Sha256::digest(bytes);
    let mut hex = String::with_capacity(71);
    hex.push_str("sha256:");
    for byte in hash {
        hex.push_str(&format!("{byte:02x}"));
    }
    Sha256Digest::new(hex).expect("a SHA-256 renders as a valid digest")
}

/// Split `input` at line boundaries into chunks of at most `chunk_bytes`.
/// A single line longer than `chunk_bytes` is its own chunk: lines are never
/// cut, so a secret is never split by the chunker.
pub fn chunks(input: &str, chunk_bytes: usize) -> Vec<&str> {
    let mut out = Vec::new();
    let mut start = 0;
    let mut end = 0;
    for line in input.split_inclusive('\n') {
        if end > start && end - start + line.len() > chunk_bytes {
            out.push(&input[start..end]);
            start = end;
        }
        end += line.len();
    }
    if end > start {
        out.push(&input[start..end]);
    }
    out
}

fn repeat(out: &mut Out, units: usize, piece: &str) {
    for _ in 0..units {
        if out.done() {
            return;
        }
        out.push(piece);
    }
}

fn azure_record() -> String {
    format!(
        "DefaultEndpointsProtocol=https;AccountName=synthetic;EndpointSuffix=core.windows.net;AccountKey={AZURE_KEY}"
    )
}

fn ordinary(out: &mut Out, n: usize) {
    let mut r = Lcg(1);
    for _ in 0..n {
        if out.done() {
            return;
        }
        let v = r.string(B62, 32);
        out.push(&format!("api_key = \"{v}\"\n"));
    }
}

fn diverse(out: &mut Out, n: usize) {
    let mut r = Lcg(7);
    for i in 0..n {
        if out.done() {
            return;
        }
        let key = r.pick(KEYS);
        let v = match i % 5 {
            0 => {
                let len = 20 + usize::try_from(r.next() % 30).unwrap_or(0);
                r.string(B62, len)
            }
            1 => r.string(HEX, 40),
            2 => format!("{}-{}", r.string(B62, 8), r.string(B62, 24)),
            3 => r.string(B64, 44),
            _ => format!("{}_{}", r.string(b"abcdefghijklmnop", 6), r.string(B62, 28)),
        };
        out.push(&format!("{key}: \"{v}\"\n"));
    }
}

fn references(out: &mut Out, n: usize) {
    let mut r = Lcg(11);
    for i in 0..n {
        if out.done() {
            return;
        }
        let a = r.string(b"abcdefghij", 8);
        let b = r.string(b"klmnopqrst", 9);
        let v = match i % 9 {
            0 => format!("projects/{a}-proj/secrets/{b}/versions/3"),
            1 => format!("arn:aws:secretsmanager:us-east-1:123456789012:secret:{a}/{b}-AbCdEf"),
            2 => format!("https://{a}.vault.azure.net/secrets/{b}"),
            3 => format!("ref+vault://secret/data/{a}#/{b}"),
            4 => format!("vault:secret/data/{a}#{b}"),
            5 => format!("{a}-key:your-{b}-key"),
            6 => format!("prod:{a}|super-secret-key"),
            7 => "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx-us1".to_string(),
            _ => format!("projects/{a}/locations/x/secrets/{b}"),
        };
        out.push(&format!("api_key = \"{v}\"\n"));
    }
}

fn otp_dense(out: &mut Out, n: usize) {
    let mut r = Lcg(13);
    for i in 0..n {
        if out.done() {
            return;
        }
        let kind = if i % 2 == 0 { "totp" } else { "hotp" };
        let secret = r.string(b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567", 24);
        out.push(&format!(
            "otpauth://{kind}/Example:user{i}@example.com?secret={secret}&issuer=Example\n"
        ));
    }
}

/// A GitHub-shaped personal access token made of random base-62 characters.
fn token(r: &mut Lcg) -> String {
    format!("ghp_{}", r.string(B62, 36))
}

fn overlap_clusters(out: &mut Out, n: usize) {
    let mut r = Lcg(17);
    for i in 0..n {
        if out.done() {
            return;
        }
        let t = token(&mut r);
        if i % 3 == 2 {
            out.push(&format!("{t}\n"));
        } else {
            out.push(&format!("api_key = \"{t}\"\n"));
        }
    }
}

fn seam_heavy(out: &mut Out, n: usize) {
    let mut r = Lcg(19);
    for _ in 0..n {
        if out.done() {
            return;
        }
        let head = r.string(B62, 20);
        let tail = r.string(B62, 20);
        out.push(&format!(
            "api_key = \"{head}\u{200b}{tail}\"\nab\u{200b}cdEFGH\n"
        ));
    }
}

fn long_assignments(out: &mut Out, n: usize) {
    let mut r = Lcg(23);
    for _ in 0..n {
        if out.done() {
            return;
        }
        let v = r.string(B62, 8192);
        out.push(&format!("password = \"{v}\"\n"));
    }
}

fn early_exhaustion(out: &mut Out, n: usize) {
    let mut r = Lcg(29);
    for i in 0..n {
        if out.done() {
            return;
        }
        let key = r.pick(KEYS);
        let v = r.string(B62, 32);
        out.push(&format!("{key} = \"{v}\"\n"));
        if i + 1 == n {
            repeat(out, n.saturating_mul(10), ORDINARY_LINE);
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum OverlapShape {
    Disjoint,
    Sparse,
    Pairs,
    Dense,
}

/// End-to-end overlap proxies. The core's overlap resolution is crate-private
/// (ADR 0002, lost path `overlap-probe`), so these workloads create competing
/// candidates through the public API: a bare token is claimed by one
/// detector, a token inside an assignment is claimed by that detector and by
/// the generic assignment detector.
fn overlap(out: &mut Out, n: usize, shape: OverlapShape) {
    let mut r = Lcg(31);
    for i in 0..n {
        if out.done() {
            return;
        }
        let t = token(&mut r);
        let overlapping = match shape {
            OverlapShape::Disjoint => false,
            OverlapShape::Sparse => i == n / 2,
            OverlapShape::Pairs | OverlapShape::Dense => true,
        };
        let line = match (overlapping, shape) {
            (false, _) => format!("{t}\n"),
            (true, OverlapShape::Dense) => {
                let u = token(&mut r);
                let v = token(&mut r);
                format!("api_key = \"{t}:{u}:{v}\"\n")
            }
            (true, _) => format!("api_key = \"{t}\"\n"),
        };
        out.push(&line);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const LIMIT: usize = 1 << 22;

    #[test]
    fn every_workload_is_deterministic_and_non_empty() {
        for id in WorkloadId::ALL {
            let a = generate(id, 20, LIMIT).unwrap();
            let b = generate(id, 20, LIMIT).unwrap();
            assert_eq!(a, b, "{id:?}");
            assert!(!a.is_empty(), "{id:?}");
            assert_eq!(digest(a.as_bytes()), digest(b.as_bytes()));
        }
    }

    #[test]
    fn workloads_are_distinct() {
        let mut digests: Vec<_> = WorkloadId::ALL
            .iter()
            .map(|id| digest(generate(*id, 20, LIMIT).unwrap().as_bytes()))
            .collect();
        digests.sort();
        digests.dedup();
        assert_eq!(digests.len(), WorkloadId::ALL.len());
    }

    #[test]
    fn generation_is_bounded() {
        // `azure-single` ignores `units`: it is one fixed record.
        for id in WorkloadId::ALL
            .into_iter()
            .filter(|id| *id != WorkloadId::AzureSingle)
        {
            // The limit is checked before each piece is appended, so even a
            // huge unit count stops at the limit.
            let result = generate(id, u32::MAX, 4096);
            assert_eq!(result, Err(TooLarge { max_bytes: 4096 }), "{id:?}");
        }
    }

    #[test]
    fn card_fixtures_match_the_1121_harness_shape() {
        let ordinary = generate(WorkloadId::AssignmentsOrdinary, 1000, LIMIT).unwrap();
        assert_eq!(ordinary.lines().count(), 1000);
        // `api_key = "<32>"\n` is 11 + 32 + 2 = 45 bytes: 1000 lines.
        assert_eq!(ordinary.len(), 1000 * 45);
        let diverse = generate(WorkloadId::AssignmentsDiverse, 1000, LIMIT).unwrap();
        assert_eq!(diverse.lines().count(), 1000);
        let references = generate(WorkloadId::AssignmentsReferences, 1000, LIMIT).unwrap();
        assert_eq!(references.lines().count(), 1000);
    }

    #[test]
    fn azure_workloads_follow_the_cards() {
        let single = generate(WorkloadId::AzureSingle, 1, LIMIT).unwrap();
        assert!(single.starts_with("DefaultEndpointsProtocol=https;"));
        assert_eq!(single.matches("AccountKey=").count(), 1);
        let duplicate = generate(WorkloadId::AzureDuplicateKeys, 100, LIMIT).unwrap();
        assert_eq!(duplicate.matches("AccountKey=").count(), 100);
        assert!(!duplicate.contains('\n'));
        let repeated = generate(WorkloadId::AzureRepeatedRecords, 100, LIMIT).unwrap();
        assert_eq!(repeated.lines().count(), 100);
    }

    #[test]
    fn chunks_cover_the_input_without_cutting_lines() {
        let input = generate(WorkloadId::RepeatedShortLogLines, 500, LIMIT).unwrap();
        let parts = chunks(&input, 1000);
        assert_eq!(parts.concat(), input);
        assert!(parts.iter().all(|p| p.ends_with('\n') && p.len() <= 1000));
        // A line longer than the chunk size is its own chunk.
        let long = generate(WorkloadId::LongSingleLineAssignments, 3, LIMIT).unwrap();
        let parts = chunks(&long, 1024);
        assert_eq!(parts.len(), 3);
        assert_eq!(parts.concat(), long);
        assert!(chunks("", 1024).is_empty());
    }

    #[test]
    fn no_workload_contains_a_known_public_credential() {
        // Generated values are random; the only fixed secret-shaped strings are
        // the synthetic Azure key and the RFC 6238 style sample OTP seed.
        for id in WorkloadId::ALL {
            let text = generate(id, 5, LIMIT).unwrap();
            assert!(!text.contains("AKIA"), "{id:?}");
            assert!(!text.contains("BEGIN PRIVATE KEY"), "{id:?}");
        }
    }
}
