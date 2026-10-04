//! Mapping a decoded finding back to original-input bytes ([ADR 0005]).
//!
//! Some scanners decode part of the input (base64, hex) and report a finding
//! in the *decoded* text: the reported value is absent from the file, so the
//! locate rules of [`crate::locate`] cannot place it. This module places such a
//! finding **only when the placement can be re-derived from the original
//! bytes**, and the result is a bound, never a claim about the finding's own
//! bytes.
//!
//! # Rule
//!
//! For a finding with a decoded value `secret`, a set of codecs and a decode
//! depth (or a range of depths), a *source segment* is a maximal run of
//! encoded text in the original content, on the reported line, that decodes
//! through a chain of that many layers to text containing `secret`:
//!
//! * layer one decodes the whole segment, strictly: the declared alphabet,
//!   padding and letter case, canonical form, valid UTF-8 ([`strict`]);
//! * each later layer decodes every run of its codec inside the previous
//!   layer's text that decodes strictly, and leaves the rest as it is (the
//!   same expansion the scanners apply);
//! * every chain of the codec set at that depth is tried, in a fixed order.
//!
//! The finding maps to a segment only when **exactly one** segment satisfies
//! this, or when several identical ones do and the report is claiming them in
//! ascending order (the repeated-report rule of [`crate::locate`]; the reported
//! line, when there is one, narrows the candidates first). Zero segments, no
//! unclaimed segment left, an unsupported
//! codec, a depth beyond [`MAX_DEPTH`] or more than [`MAX_CANDIDATES`]
//! candidate runs are an error with a fixed message, so the case stays
//! unmeasured when per-case handling was chosen: never a zero detection, never
//! a guessed range. The mapped range is the whole segment
//! ([`MappingBound::SourceSegment`]): the finding lies somewhere inside its
//! decoded text, and nothing narrower is claimed.
//!
//! Every error message is fixed and never contains the value being located.
//!
//! [ADR 0005]: ../../../docs/decisions/0005-representation-contract.md

use std::collections::BTreeSet;
use std::sync::LazyLock;

use credential_eval_contracts::representation::{
    Alphabet, Codec, FindingMapping, HexCase, MappingBound, Padding, base64_decode_strict,
    hex_decode_strict,
};
use regex::Regex;

use crate::locate::{Claims, Fixtures, Line, Located, MapError};

/// Optional configuration key choosing whether a decoded finding is placed on
/// the original bytes. Absent or `"off"`: only the locate rules that predate
/// the representation contract apply (the default; output is byte for byte
/// what it was). The value [`SOURCE_SEGMENT`]: the rule of this module runs
/// first for every finding the scanner reports as decoded.
pub const DECODED_MAPPING_KEY: &str = "decoded_mapping";
/// The opt-in value of [`DECODED_MAPPING_KEY`].
pub const SOURCE_SEGMENT: &str = "source-segment";

/// Read [`DECODED_MAPPING_KEY`] from a scanner configuration: `false` when
/// absent or `"off"`, `true` for [`SOURCE_SEGMENT`], and an `error`
/// observation (a configuration mistake, never a measurement) otherwise.
pub(crate) fn decoded_policy(
    spec: &credential_eval_contracts::config::ScannerSpec,
    prepared: &crate::Prepared,
) -> Result<bool, Box<crate::PrepareFailure>> {
    use serde_json::Value;
    match spec.configuration.get(DECODED_MAPPING_KEY) {
        None => Ok(false),
        Some(Value::String(v)) if v == "off" => Ok(false),
        Some(Value::String(v)) if v == SOURCE_SEGMENT => Ok(true),
        Some(_) => Err(Box::new(crate::PrepareFailure {
            result: credential_eval_contracts::observation::ObservationResult::Error {
                reason: format!("invalid scanner configuration: {DECODED_MAPPING_KEY}"),
            },
            version: prepared.version.clone(),
            provenance: prepared.provenance.clone(),
            processes: prepared.processes,
            process_time: prepared.process_time,
        })),
    }
}

/// Most decode layers the rule follows.
pub const MAX_DEPTH: u8 = 4;
/// Most candidate runs one finding examines.
pub const MAX_CANDIDATES: usize = 4096;
/// Shortest base64 run examined.
const MIN_BASE64_RUN: usize = 8;
/// Shortest hex run examined (sixteen digits, eight bytes).
const MIN_HEX_RUN: usize = 16;

const UNSUPPORTED: MapError = MapError("Unsupported decoded finding");
const UNMAPPABLE: MapError = MapError("Unmappable decoded finding");
const AMBIGUOUS: MapError = MapError("Ambiguous or unmappable decoded finding");

/// A decoded finding placed on the original bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mapped {
    /// The source segment.
    pub located: Located,
    /// How it was placed.
    pub mapping: FindingMapping,
}

/// How many layers separate the original bytes from the finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Depth {
    /// Exactly this many layers (Gitleaks reports it).
    Exactly(u8),
    /// One to this many layers (TruffleHog does not report it).
    UpTo(u8),
}

static BASE64_RUN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(&format!(r"[A-Za-z0-9+/_-]{{{MIN_BASE64_RUN},}}={{0,2}}")).expect("static regex")
});
static HEX_RUN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(&format!(r"[0-9A-Fa-f]{{{MIN_HEX_RUN},}}")).expect("static regex"));

fn runs(codec: Codec) -> &'static Regex {
    match codec {
        Codec::Base64 => &BASE64_RUN,
        Codec::Hex => &HEX_RUN,
    }
}

/// Strict decoders over a run of encoded text.
pub mod strict {
    use super::{Alphabet, Codec, HexCase, Padding, base64_decode_strict, hex_decode_strict};

    /// Decode `run` with `codec`, strictly. The alphabet, padding and letter
    /// case are read off the run itself, then checked by the contract's strict
    /// decoder; the result must be valid UTF-8.
    pub fn decode_run(run: &str, codec: Codec) -> Option<String> {
        let bytes = run.as_bytes();
        let decoded = match codec {
            Codec::Base64 => {
                let url = bytes.iter().any(|b| matches!(b, b'-' | b'_'));
                let std = bytes.iter().any(|b| matches!(b, b'+' | b'/'));
                if url && std {
                    return None;
                }
                let alphabet = if url {
                    Alphabet::UrlSafe
                } else {
                    Alphabet::Standard
                };
                let padding = if bytes.ends_with(b"=") {
                    Padding::Padded
                } else {
                    Padding::Unpadded
                };
                base64_decode_strict(bytes, alphabet, padding)?
            }
            Codec::Hex => {
                let lower = bytes.iter().any(|b| (b'a'..=b'f').contains(b));
                let upper = bytes.iter().any(|b| (b'A'..=b'F').contains(b));
                let hex_case = match (lower, upper) {
                    (true, true) => HexCase::Mixed,
                    (false, true) => HexCase::Upper,
                    _ => HexCase::Lower,
                };
                hex_decode_strict(bytes, hex_case)?
            }
        };
        String::from_utf8(decoded).ok()
    }
}

/// One layer after the first: replace every run of `codec` in `text` that
/// decodes strictly. `None` when no run decoded (the layer does not exist).
fn expand(text: &str, codec: Codec) -> Option<String> {
    let mut out = String::with_capacity(text.len());
    let (mut last, mut replaced) = (0, false);
    for m in runs(codec).find_iter(text) {
        if let Some(decoded) = strict::decode_run(m.as_str(), codec) {
            out.push_str(&text[last..m.start()]);
            out.push_str(&decoded);
            last = m.end();
            replaced = true;
        }
    }
    out.push_str(&text[last..]);
    replaced.then_some(out)
}

/// Every codec sequence of exactly `depth` layers over `codecs`, in a fixed
/// (lexicographic) order.
fn chains(codecs: &[Codec], depth: u8) -> Vec<Vec<Codec>> {
    let mut all = vec![Vec::new()];
    for _ in 0..depth {
        all = all
            .into_iter()
            .flat_map(|prefix| {
                codecs.iter().map(move |c| {
                    let mut next = prefix.clone();
                    next.push(*c);
                    next
                })
            })
            .collect();
    }
    all
}

/// The decoded text of `segment` through `chain`, when every layer exists.
fn decode_chain(segment: &str, chain: &[Codec]) -> Option<String> {
    let (first, rest) = chain.split_first()?;
    let mut text = strict::decode_run(segment, *first)?;
    for codec in rest {
        text = expand(&text, *codec)?;
    }
    Some(text)
}

/// Place a decoded finding on the original bytes of `file`, or explain
/// (with a fixed message) why it cannot be placed. See the module rule.
pub fn map_decoded(
    fixtures: &Fixtures<'_>,
    file: &str,
    secret: &str,
    line: Line,
    codecs: &BTreeSet<Codec>,
    depth: Depth,
    claims: &mut Claims,
) -> Result<Mapped, MapError> {
    let (lo, hi) = match depth {
        Depth::Exactly(d) => (d, d),
        Depth::UpTo(d) => (1, d),
    };
    if codecs.is_empty() || lo == 0 || hi > MAX_DEPTH || lo > hi {
        return Err(UNSUPPORTED);
    }
    let (path, content) = fixtures.resolve(file).map_err(|_| UNMAPPABLE)?;
    if secret.is_empty() {
        return Err(UNMAPPABLE);
    }
    let codecs: Vec<Codec> = codecs.iter().copied().collect();
    let candidates = candidate_runs(content, &codecs, line)?;
    let all_chains: Vec<Vec<Codec>> = (lo..=hi).flat_map(|d| chains(&codecs, d)).collect();
    // The first chain that decodes a segment to text containing the secret.
    let mut hits: Vec<((usize, usize), &Vec<Codec>)> = Vec::new();
    for (start, end) in candidates {
        let segment = &content[start..end];
        let chain = all_chains
            .iter()
            .find(|chain| decode_chain(segment, chain).is_some_and(|t| t.contains(secret)));
        if let Some(chain) = chain {
            hits.push(((start, end), chain));
        }
    }
    let starts: Vec<usize> = hits.iter().map(|((s, _), _)| *s).collect();
    let key = (format!("decoded:{path}"), secret.to_owned(), line.key());
    let resolved = claims.resolve(key, &starts);
    let [at] = resolved.as_slice() else {
        return Err(if starts.is_empty() {
            UNMAPPABLE
        } else {
            AMBIGUOUS
        });
    };
    let ((start, end), chain) = hits
        .iter()
        .find(|((s, _), _)| s == at)
        .map(|(range, chain)| (*range, *chain))
        .ok_or(AMBIGUOUS)?;
    let used: BTreeSet<Codec> = chain.iter().copied().collect();
    Ok(Mapped {
        located: Located {
            path: path.to_owned(),
            start,
            end,
        },
        mapping: FindingMapping {
            bound: MappingBound::SourceSegment,
            layers: u8::try_from(chain.len()).unwrap_or(MAX_DEPTH),
            codecs: used.into_iter().collect(),
        },
    })
}

/// Candidate first-layer runs of every codec, on the accepted line, sorted and
/// unique. Lines are counted incrementally, so the cost is one pass per codec.
fn candidate_runs(
    content: &str,
    codecs: &[Codec],
    line: Line,
) -> Result<Vec<(usize, usize)>, MapError> {
    let mut found: BTreeSet<(usize, usize)> = BTreeSet::new();
    for codec in codecs {
        let (mut counted_to, mut line_no) = (0usize, 1usize);
        for m in runs(*codec).find_iter(content) {
            line_no += content.as_bytes()[counted_to..m.start()]
                .iter()
                .filter(|b| **b == b'\n')
                .count();
            counted_to = m.start();
            if line.accepts(line_no) {
                found.insert((m.start(), m.end()));
                if found.len() > MAX_CANDIDATES {
                    return Err(UNMAPPABLE);
                }
            }
        }
    }
    Ok(found.into_iter().collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use credential_eval_contracts::representation::{Alphabet, Padding, base64_decode_strict};

    const ROOT: &str = "/tmp/root";

    fn fx<'a>(files: &[(&'a str, &'a str)]) -> Fixtures<'a> {
        Fixtures::new(ROOT, files.iter().copied())
    }

    fn b64(text: &str) -> String {
        crate::gitleaks::base64_encode(text.as_bytes())
    }

    fn hex(text: &str) -> String {
        text.bytes().map(|b| format!("{b:02x}")).collect()
    }

    fn set(codecs: &[Codec]) -> BTreeSet<Codec> {
        codecs.iter().copied().collect()
    }

    fn map(
        content: &str,
        secret: &str,
        codecs: &[Codec],
        depth: Depth,
        line: Line,
    ) -> Result<Mapped, MapError> {
        let fixtures = fx(&[("f.txt", content)]);
        map_decoded(
            &fixtures,
            "f.txt",
            secret,
            line,
            &set(codecs),
            depth,
            &mut Claims::default(),
        )
    }

    const SECRET: &str = "SG.SYNTHETICNEVERISSUED00.EXAMPLEONLY_NEVER-ISSUED";

    #[test]
    fn nested_base64_maps_to_the_outer_segment() {
        let once = b64(SECRET);
        let twice = b64(&once);
        let thrice = b64(&twice);
        let content = format!("K=é{thrice}\n");
        let mapped = map(
            &content,
            SECRET,
            &[Codec::Base64],
            Depth::Exactly(3),
            Line::Number(1.0),
        )
        .unwrap();
        let start = content.find(&thrice).unwrap();
        assert_eq!(
            (mapped.located.start, mapped.located.end),
            (start, start + thrice.len())
        );
        assert_eq!(mapped.mapping.layers, 3);
        assert_eq!(mapped.mapping.codecs, vec![Codec::Base64]);
        assert_eq!(mapped.mapping.bound, MappingBound::SourceSegment);
        // A wrong depth does not map: the rule re-derives it.
        let wrong = map(
            &content,
            SECRET,
            &[Codec::Base64],
            Depth::Exactly(2),
            Line::Undefined,
        );
        assert_eq!(wrong.unwrap_err().0, "Unmappable decoded finding");
        // A range of depths (TruffleHog) finds it.
        assert!(
            map(
                &content,
                SECRET,
                &[Codec::Base64],
                Depth::UpTo(4),
                Line::Undefined
            )
            .is_ok()
        );
    }

    #[test]
    fn hex_and_mixed_chains_map_in_any_declared_order() {
        let content = format!("DATA={}\n", hex(&b64(&hex(SECRET))));
        let mapped = map(
            &content,
            SECRET,
            &[Codec::Base64, Codec::Hex],
            Depth::Exactly(3),
            Line::Number(1.0),
        )
        .unwrap();
        assert_eq!(mapped.mapping.layers, 3);
        assert_eq!(mapped.mapping.codecs, vec![Codec::Base64, Codec::Hex]);
        assert_eq!(mapped.located.start, 5);
        assert_eq!(mapped.located.end, content.len() - 1);
        // Hex alone, upper case.
        let upper = format!("DATA={}\n", hex(SECRET).to_uppercase());
        assert!(
            map(
                &upper,
                SECRET,
                &[Codec::Hex],
                Depth::Exactly(1),
                Line::Undefined
            )
            .is_ok()
        );
    }

    #[test]
    fn url_safe_unpadded_and_json_carriers_map() {
        // A value whose standard base64 has `+`/`/` and padding.
        let value = "SG.??>>~~~~EXAMPLE";
        let url = b64(value)
            .trim_end_matches('=')
            .replace('+', "-")
            .replace('/', "_");
        let content = format!("{{\"k\": \"{url}\"}}\n");
        let mapped = map(
            &content,
            value,
            &[Codec::Base64],
            Depth::Exactly(1),
            Line::Number(1.0),
        )
        .unwrap();
        assert_eq!(&content[mapped.located.start..mapped.located.end], url);
    }

    #[test]
    fn the_reported_line_selects_between_equal_segments() {
        let run = b64(SECRET);
        let content = format!("a={run}\nb={run}\n");
        let second = map(
            &content,
            SECRET,
            &[Codec::Base64],
            Depth::Exactly(1),
            Line::Number(2.0),
        )
        .unwrap();
        assert_eq!(second.located.start, content.rfind(&run).unwrap());
        // Without a line both segments qualify, and one report claims the
        // first, as the locate rules do for a value that occurs twice.
        let both = map(
            &content,
            SECRET,
            &[Codec::Base64],
            Depth::Exactly(1),
            Line::Undefined,
        )
        .unwrap();
        assert_eq!(both.located.start, content.find(&run).unwrap());
    }

    #[test]
    fn repeated_identical_reports_claim_segments_in_order() {
        let run = b64(SECRET);
        let content = format!("a={run} b={run}\n");
        let fixtures = fx(&[("f.txt", content.as_str())]);
        let mut claims = Claims::default();
        let place = |claims: &mut Claims| {
            map_decoded(
                &fixtures,
                "f.txt",
                SECRET,
                Line::Number(1.0),
                &set(&[Codec::Base64]),
                Depth::Exactly(1),
                claims,
            )
        };
        let first = place(&mut claims).unwrap();
        let second = place(&mut claims).unwrap();
        assert!(first.located.start < second.located.start);
        // A third report has no segment left and is not guessed.
        assert!(place(&mut claims).is_err());
    }

    #[test]
    fn unsupported_and_unprovable_findings_fail_closed() {
        let content = format!("a={}\n", b64(SECRET));
        let run = |secret: &str, codecs: &[Codec], depth| {
            map(&content, secret, codecs, depth, Line::Undefined)
        };
        // Depth beyond the bound, zero depth, no codec.
        assert_eq!(
            run(SECRET, &[Codec::Base64], Depth::Exactly(5))
                .unwrap_err()
                .0,
            "Unsupported decoded finding"
        );
        assert!(run(SECRET, &[Codec::Base64], Depth::Exactly(0)).is_err());
        assert!(run(SECRET, &[], Depth::Exactly(1)).is_err());
        // A secret the segment does not decode to.
        assert_eq!(
            run("SOMETHINGELSE", &[Codec::Base64], Depth::Exactly(1))
                .unwrap_err()
                .0,
            "Unmappable decoded finding"
        );
        // An empty secret and an unknown file.
        assert!(run("", &[Codec::Base64], Depth::Exactly(1)).is_err());
        let fixtures = fx(&[("f.txt", content.as_str())]);
        assert!(
            map_decoded(
                &fixtures,
                "other.txt",
                SECRET,
                Line::Undefined,
                &set(&[Codec::Base64]),
                Depth::Exactly(1),
                &mut Claims::default()
            )
            .is_err()
        );
        // Text that is not strictly the declared encoding is not a segment:
        // non-canonical trailing bits, mixed alphabets, odd hex.
        let canonical = b64("0123456789");
        assert!(canonical.ends_with("=="));
        let noncanonical = format!("{}B==", &canonical[..canonical.len() - 3]);
        let bad = format!("a={noncanonical}\n");
        assert!(
            map(
                &format!("a={canonical}\n"),
                "0123456789",
                &[Codec::Base64],
                Depth::Exactly(1),
                Line::Undefined
            )
            .is_ok()
        );
        assert!(
            map(
                &bad,
                "0123456789",
                &[Codec::Base64],
                Depth::Exactly(1),
                Line::Undefined
            )
            .is_err()
        );
        let odd = format!("a={}0\n", hex(SECRET));
        assert!(
            map(
                &odd,
                SECRET,
                &[Codec::Hex],
                Depth::Exactly(1),
                Line::Undefined
            )
            .is_err()
        );
    }

    #[test]
    fn a_secret_that_crosses_the_segment_is_not_mapped() {
        // The secret the scanner reports spans the decoded text and the text
        // after it: the segment alone does not decode to it.
        let run = b64("SG.PART");
        let content = format!("k={run}.tail\n");
        let r = map(
            &content,
            "SG.PART.tail",
            &[Codec::Base64],
            Depth::Exactly(1),
            Line::Undefined,
        );
        assert!(r.is_err());
    }

    #[test]
    fn too_many_candidates_is_unmappable() {
        let word = "ABCDEFGHIJ";
        let content = (0..MAX_CANDIDATES + 10)
            .map(|_| word)
            .collect::<Vec<_>>()
            .join(" ");
        let r = map(
            &content,
            "x",
            &[Codec::Base64],
            Depth::Exactly(1),
            Line::Undefined,
        );
        assert_eq!(r.unwrap_err().0, "Unmappable decoded finding");
    }

    #[test]
    fn strict_runs_reject_what_the_contract_rejects() {
        let std = Alphabet::Standard;
        assert!(base64_decode_strict(b"YQ==", std, Padding::Padded).is_some());
        assert_eq!(
            strict::decode_run("YQ==", Codec::Base64).as_deref(),
            Some("a")
        );
        assert_eq!(
            strict::decode_run("6162", Codec::Hex).as_deref(),
            Some("ab")
        );
        // Not UTF-8 after decoding.
        assert_eq!(strict::decode_run("/w==", Codec::Base64), None);
        // Both alphabets at once.
        assert_eq!(strict::decode_run("+_+_+_+_", Codec::Base64), None);
    }
}
