//! Variant operators (legacy `evaluation/domains/credential/operators/*`).
//!
//! String edits reproduce JavaScript semantics exactly: lexical edits work on
//! UTF-16 code units (`String.prototype.slice`), and a lone surrogate left by
//! an edit becomes U+FFFD, which is what `Buffer` writes for it. Offsets stay
//! UTF-8 bytes. Every choice is seeded ([`seeded_choice`]); nothing is random.

use std::collections::BTreeMap;
use std::fmt;
use std::str::FromStr;

use credential_eval_contracts::artifact::{Relation, VariantStrategy};
use credential_eval_contracts::corpus::{Case, EvidenceTier, ExpectedSpan};
use credential_eval_contracts::ids::ComponentId;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::Value;

use super::evidence::EvaluationEvidence;
use super::model::{EvaluationCase, ExpectationEffect, Integrity, secrets, seeded_choice};

/// A registered operator (legacy `createOperators`, `operators/index.ts:8-12`,
/// in registration order).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum OperatorId {
    /// `authored.twin`
    AuthoredTwin,
    /// `context.unicode-prefix`
    UnicodePrefix,
    /// `context.indent`
    Indent,
    /// `encoding.crlf`
    Crlf,
    /// `context.json`
    Json,
    /// `context.quote`
    Quote,
    /// `context.single-quote`
    SingleQuote,
    /// `context.yaml`
    Yaml,
    /// `context.markdown`
    Markdown,
    /// `lexical.length-minus-one`
    LengthMinusOne,
    /// `lexical.length-plus-one`
    LengthPlusOne,
    /// `lexical.replace-last`
    ReplaceLast,
    /// `lexical.invalid-alphabet`
    InvalidAlphabet,
    /// `lexical.prefix-change`
    PrefixChange,
    /// `boundary.remove-delimiter`
    RemoveDelimiter,
    /// `structural.remove-segment`
    RemoveSegment,
}

impl OperatorId {
    /// Every operator, in registration order.
    pub const ALL: [Self; 16] = [
        Self::AuthoredTwin,
        Self::UnicodePrefix,
        Self::Indent,
        Self::Crlf,
        Self::Json,
        Self::Quote,
        Self::SingleQuote,
        Self::Yaml,
        Self::Markdown,
        Self::LengthMinusOne,
        Self::LengthPlusOne,
        Self::ReplaceLast,
        Self::InvalidAlphabet,
        Self::PrefixChange,
        Self::RemoveDelimiter,
        Self::RemoveSegment,
    ];

    /// Wire id.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AuthoredTwin => "authored.twin",
            Self::UnicodePrefix => "context.unicode-prefix",
            Self::Indent => "context.indent",
            Self::Crlf => "encoding.crlf",
            Self::Json => "context.json",
            Self::Quote => "context.quote",
            Self::SingleQuote => "context.single-quote",
            Self::Yaml => "context.yaml",
            Self::Markdown => "context.markdown",
            Self::LengthMinusOne => "lexical.length-minus-one",
            Self::LengthPlusOne => "lexical.length-plus-one",
            Self::ReplaceLast => "lexical.replace-last",
            Self::InvalidAlphabet => "lexical.invalid-alphabet",
            Self::PrefixChange => "lexical.prefix-change",
            Self::RemoveDelimiter => "boundary.remove-delimiter",
            Self::RemoveSegment => "structural.remove-segment",
        }
    }

    /// Operator version (all operators are version 1).
    pub const fn version(self) -> u32 {
        1
    }

    /// As a contract component id.
    pub fn component(self) -> ComponentId {
        ComponentId::new(self.as_str()).expect("operator ids are component ids")
    }

    /// Context and encoding operators (the metamorphic set, `cases.ts:92`).
    pub const fn is_context(self) -> bool {
        matches!(
            self,
            Self::UnicodePrefix
                | Self::Indent
                | Self::Crlf
                | Self::Json
                | Self::Quote
                | Self::SingleQuote
                | Self::Yaml
                | Self::Markdown
        )
    }

    /// Lexical, boundary and structural operators (the mutation set, `cases.ts:96-97`).
    pub const fn is_lexical(self) -> bool {
        matches!(
            self,
            Self::LengthMinusOne
                | Self::LengthPlusOne
                | Self::ReplaceLast
                | Self::InvalidAlphabet
                | Self::PrefixChange
                | Self::RemoveDelimiter
                | Self::RemoveSegment
        )
    }
}

impl fmt::Display for OperatorId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for OperatorId {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::ALL
            .into_iter()
            .find(|o| o.as_str() == s)
            .ok_or_else(|| format!("unknown operator: {s}"))
    }
}

impl Serialize for OperatorId {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for OperatorId {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

/// A suppressed generation failure: the attempt records a fixed reason and
/// never the underlying cause (which could echo fixture bytes).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GenerationFailed;

impl fmt::Display for GenerationFailed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("transformation generation or validation failed")
    }
}

impl std::error::Error for GenerationFailed {}

/// What an operator produced (legacy `Operator.generate` result).
#[derive(Debug, Clone, PartialEq)]
pub struct OperatorOutput {
    /// Transformed fixture.
    pub fixture: Case,
    /// Expectation strategy.
    pub strategy: VariantStrategy,
    /// Property changed.
    pub property: Option<String>,
    /// Relation to the canonical variant.
    pub relation: Option<Relation>,
    /// Integrity claim.
    pub integrity: Option<Integrity>,
    /// Lexical contract match.
    pub contract_match: Option<bool>,
    /// Resolved parameters (when the operator resolves a seeded choice).
    pub parameters: Option<BTreeMap<String, Value>>,
    /// Explicit expectation effect.
    pub expectation_effect: Option<ExpectationEffect>,
}

impl OperatorOutput {
    fn new(fixture: Case, strategy: VariantStrategy, property: &str) -> Self {
        Self {
            fixture,
            strategy,
            property: Some(property.to_owned()),
            relation: None,
            integrity: None,
            contract_match: None,
            parameters: None,
            expectation_effect: None,
        }
    }
}

// ---------------------------------------------------------------------------
// JavaScript string helpers.

fn utf16(s: &str) -> Vec<u16> {
    s.encode_utf16().collect()
}

fn from_utf16(units: &[u16]) -> String {
    String::from_utf16_lossy(units)
}

/// JavaScript `WhiteSpace` and `LineTerminator` (`String.prototype.trimEnd`).
fn is_js_space(c: char) -> bool {
    matches!(
        c,
        '\t' | '\n' | '\u{b}' | '\u{c}' | '\r' | ' ' | '\u{a0}' | '\u{1680}' | '\u{2000}'
            ..='\u{200a}'
                | '\u{2028}'
                | '\u{2029}'
                | '\u{202f}'
                | '\u{205f}'
                | '\u{3000}'
                | '\u{feff}'
    )
}

fn js_trim_end(s: &str) -> &str {
    s.trim_end_matches(is_js_space)
}

fn slice(case: &Case, span: &ExpectedSpan) -> String {
    case.content[span.start as usize..span.end as usize].to_owned()
}

fn find_bytes(haystack: &[u8], needle: &[u8], from: usize) -> Option<usize> {
    if needle.is_empty() {
        return Some(from.min(haystack.len()));
    }
    haystack
        .get(from..)?
        .windows(needle.len())
        .position(|w| w == needle)
        .map(|p| p + from)
}

// ---------------------------------------------------------------------------
// authored.twin (operators/authored-twin.ts:6-44)

fn authored_twin(c: &EvaluationCase) -> Result<OperatorOutput, GenerationFailed> {
    let twin = c.twin.as_ref().ok_or(GenerationFailed)?;
    let seed = &c.seed;
    super::model::validate_fixture(seed).map_err(|_| GenerationFailed)?;
    super::model::validate_fixture(twin).map_err(|_| GenerationFailed)?;
    let lineage = twin.twin.as_ref().ok_or(GenerationFailed)?;
    if lineage.twin_of != seed.id
        || twin.content == seed.content
        || twin.grouping.family != seed.grouping.family
        || seed.id == twin.id
        || seed.path == twin.path
        || lineage.mutation.trim().is_empty()
        || !secrets(twin).is_empty()
    {
        return Err(GenerationFailed);
    }
    let spans = secrets(seed);
    if spans.len() != 1 {
        return Err(GenerationFailed);
    }
    let span = spans[0];
    let source = seed.content.as_bytes();
    let (start, end) = (span.start as usize, span.end as usize);
    let integrity = |property: &str| {
        Some(Integrity {
            kind: "authored-single-property".to_owned(),
            property: Some(property.to_owned()),
        })
    };
    if lineage.mutation_kind == "context" {
        let target = twin.content.as_bytes();
        let value = &source[start..end];
        let mut head = 0;
        while head < source.len() && head < target.len() && source[head] == target[head] {
            head += 1;
        }
        let mut tail = 0;
        while tail < source.len() - head
            && tail < target.len() - head
            && source[source.len() - 1 - tail] == target[target.len() - 1 - tail]
        {
            tail += 1;
        }
        let first = find_bytes(target, value, 0).ok_or(GenerationFailed)?;
        if find_bytes(target, value, first + 1).is_some() {
            return Err(GenerationFailed);
        }
        if !(source.len() - tail <= start || head >= end) {
            return Err(GenerationFailed);
        }
        let mut out = OperatorOutput::new(twin.clone(), VariantStrategy::Authored, "context");
        out.relation = Some(Relation::MustFlip);
        out.integrity = integrity("context");
        return Ok(out);
    }
    let prefix = &seed.content[..start];
    let suffix = js_trim_end(&seed.content[end..]);
    let candidate = js_trim_end(&twin.content);
    let len16 = |s: &str| s.encode_utf16().count();
    if !candidate.starts_with(prefix)
        || !candidate.ends_with(suffix)
        || len16(candidate) <= len16(prefix) + len16(suffix)
    {
        return Err(GenerationFailed);
    }
    let kind = lineage.mutation_kind.clone();
    let mut out = OperatorOutput::new(twin.clone(), VariantStrategy::Authored, &kind);
    out.relation = Some(Relation::MustFlip);
    out.integrity = integrity(&kind);
    Ok(out)
}

// ---------------------------------------------------------------------------
// Context operators (operators/context.ts)

/// Map every byte boundary through a per-character transformation, remapping
/// every span and envelope without searching for values
/// (`operators/context.ts:5-19`).
pub fn map_fixture(
    seed: &Case,
    transform: impl Fn(char, usize) -> String,
    prefix: &str,
    suffix: &str,
) -> Case {
    let mut content = String::from(prefix);
    let mut offsets: BTreeMap<usize, usize> = BTreeMap::new();
    offsets.insert(0, prefix.len());
    let mut old = 0;
    for c in seed.content.chars() {
        content.push_str(&transform(c, old));
        old += c.len_utf8();
        offsets.insert(old, content.len());
    }
    content.push_str(suffix);
    let map = |o: u64| offsets[&(o as usize)] as u64;
    let mut out = seed.clone();
    out.content = content;
    for span in &mut out.expected {
        span.start = map(span.start);
        span.end = map(span.end);
        if let Some(envelope) = &mut span.envelope {
            envelope.start = map(envelope.start);
            envelope.end = map(envelope.end);
        }
    }
    out
}

fn has_any(content: &str, pred: impl Fn(char) -> bool) -> bool {
    content.chars().any(pred)
}

fn is_control(c: char) -> bool {
    (c as u32) < 0x20
}

fn context_supported(op: OperatorId, content: &str) -> bool {
    match op {
        OperatorId::UnicodePrefix | OperatorId::Indent => true,
        // /(^|[^\r])\n/
        OperatorId::Crlf => {
            let bytes = content.as_bytes();
            bytes
                .iter()
                .enumerate()
                .any(|(i, b)| *b == b'\n' && (i == 0 || bytes[i - 1] != b'\r'))
        }
        OperatorId::Json | OperatorId::Quote => {
            !has_any(content, |c| c == '"' || c == '\\' || is_control(c))
        }
        OperatorId::SingleQuote => !has_any(content, |c| c == '\'' || c == '\\' || is_control(c)),
        OperatorId::Yaml => !has_any(content, |c| c == '\'' || is_control(c)),
        OperatorId::Markdown => !has_any(content, |c| c == '`' || c == '\r' || c == '\n'),
        _ => false,
    }
}

fn context_apply(op: OperatorId, seed: &Case) -> Case {
    let same = |c: char, _: usize| c.to_string();
    match op {
        OperatorId::UnicodePrefix => {
            map_fixture(seed, same, "# \u{1f511} \u{5bc6}\u{94a5} caf\u{e9}\n", "")
        }
        OperatorId::Indent => map_fixture(seed, same, "    ", ""),
        OperatorId::Crlf => {
            let input = seed.content.as_bytes();
            map_fixture(
                seed,
                |c, offset| {
                    if c == '\n' && (offset == 0 || input[offset - 1] != b'\r') {
                        "\r\n".to_owned()
                    } else {
                        c.to_string()
                    }
                },
                "",
                "",
            )
        }
        OperatorId::Json => map_fixture(seed, same, "{\"value\":\"", "\"}"),
        OperatorId::Quote => map_fixture(seed, same, "\"", "\""),
        OperatorId::SingleQuote => map_fixture(seed, same, "'", "'"),
        OperatorId::Yaml => map_fixture(seed, same, "value: '", "'\n"),
        OperatorId::Markdown => map_fixture(seed, same, "`", "`"),
        _ => seed.clone(),
    }
}

// ---------------------------------------------------------------------------
// Lexical, boundary and structural operators (operators/lexical.ts, structural.ts)

/// `supportsLexical` (`operators/lexical.ts:6-8`): exactly one secret, tier
/// T1/T2, and a family with a pattern.
fn supports_lexical(c: &EvaluationCase, evidence: &EvaluationEvidence) -> bool {
    secrets(&c.seed).len() == 1
        && matches!(c.seed.grouping.tier, EvidenceTier::T1 | EvidenceTier::T2)
        && c.seed
            .grouping
            .family
            .as_deref()
            .is_some_and(|f| evidence.contracts.has_pattern(f))
}

/// Replace the single secret's bytes and shift every range that starts or
/// ends at or after the span end (`operators/lexical.ts:10-26`).
fn mutate(
    c: &EvaluationCase,
    evidence: &EvaluationEvidence,
    change: impl Fn(&[u16]) -> Vec<u16>,
    property: &str,
) -> OperatorOutput {
    let seed = &c.seed;
    let span = secrets(seed)[0].clone();
    let original = utf16(&slice(seed, &span));
    let replacement = from_utf16(&change(&original));
    let width = span.end - span.start;
    let delta = replacement.len() as i128 - i128::from(width);
    let shift = |o: u64| {
        if o >= span.end {
            (i128::from(o) + delta) as u64
        } else {
            o
        }
    };
    let mut fixture = seed.clone();
    fixture.content = format!(
        "{}{}{}",
        &seed.content[..span.start as usize],
        replacement,
        &seed.content[span.end as usize..]
    );
    for r in &mut fixture.expected {
        r.start = shift(r.start);
        r.end = shift(r.end);
        if let Some(envelope) = &mut r.envelope {
            envelope.start = shift(envelope.start);
            envelope.end = shift(envelope.end);
        }
    }
    let family = seed.grouping.family.as_deref().unwrap_or("");
    let valid = evidence.contracts.is_valid(family, &replacement);
    let mut out = OperatorOutput::new(
        fixture,
        if valid {
            VariantStrategy::Derived
        } else {
            VariantStrategy::ReviewRequired
        },
        property,
    );
    out.expectation_effect = Some(if valid {
        ExpectationEffect::Preserve
    } else {
        ExpectationEffect::Defer
    });
    out.contract_match = Some(valid);
    out.relation = valid.then_some(Relation::SameDetection);
    out
}

fn secret_value(c: &EvaluationCase) -> String {
    slice(&c.seed, secrets(&c.seed)[0])
}

/// UTF-16 indices of `[._-]` in the secret value (`structural.ts:6`).
fn separators(value: &[u16]) -> Vec<u64> {
    value
        .iter()
        .enumerate()
        .filter(|(_, u)| matches!(**u, 0x2e | 0x5f | 0x2d))
        .map(|(i, _)| i as u64)
        .collect()
}

/// `validIndex` (`structural.ts:7-8`): only an `index` key, and when present
/// a number in `allowed`.
fn valid_index(p: &BTreeMap<String, Value>, allowed: &[u64]) -> bool {
    p.keys().all(|k| k == "index")
        && p.get("index").is_none_or(|v| {
            v.as_f64()
                .is_some_and(|n| allowed.iter().any(|a| *a as f64 == n))
        })
}

fn index_param(p: &BTreeMap<String, Value>) -> Option<u64> {
    p.get("index").and_then(Value::as_f64).map(|n| n as u64)
}

fn lexical_change(op: OperatorId, s: &[u16]) -> Vec<u16> {
    let drop_last = &s[..s.len().saturating_sub(1)];
    let mut out = drop_last.to_vec();
    match op {
        OperatorId::LengthMinusOne => {}
        OperatorId::LengthPlusOne => {
            out = s.to_vec();
            out.push(u16::from(b'A'));
        }
        OperatorId::ReplaceLast => {
            let ends_with_a = s.last() == Some(&u16::from(b'A'));
            out.push(u16::from(if ends_with_a { b'B' } else { b'A' }));
        }
        OperatorId::InvalidAlphabet => out.push(u16::from(b'!')),
        _ => out = s.to_vec(),
    }
    out
}

impl OperatorId {
    /// Whether the operator applies to `c` with `parameters` (legacy `supports`).
    pub fn supports(
        self,
        c: &EvaluationCase,
        parameters: &BTreeMap<String, Value>,
        evidence: &EvaluationEvidence,
    ) -> bool {
        match self {
            Self::AuthoredTwin => c.twin.is_some(),
            op if op.is_context() => {
                parameters.is_empty() && context_supported(op, &c.seed.content)
            }
            Self::LengthMinusOne
            | Self::LengthPlusOne
            | Self::ReplaceLast
            | Self::InvalidAlphabet => parameters.is_empty() && supports_lexical(c, evidence),
            Self::PrefixChange => {
                supports_lexical(c, evidence)
                    && parameters.keys().all(|k| k == "choice")
                    && parameters.get("choice").is_none_or(|v| {
                        v.as_f64()
                            .is_some_and(|n| n.fract() == 0.0 && (0.0..25.0).contains(&n))
                    })
            }
            Self::RemoveDelimiter => {
                if !supports_lexical(c, evidence) {
                    return false;
                }
                let positions = separators(&utf16(&secret_value(c)));
                !positions.is_empty() && valid_index(parameters, &positions)
            }
            Self::RemoveSegment => {
                if !supports_lexical(c, evidence) {
                    return false;
                }
                let rule = c
                    .seed
                    .grouping
                    .family
                    .as_deref()
                    .and_then(|f| evidence.contracts.get(f))
                    .and_then(|contract| contract.segments.as_ref());
                rule.is_some_and(|rule| valid_index(parameters, &rule.removable))
            }
            _ => false,
        }
    }

    /// Generate the transformed fixture. An error is a suppressed generation
    /// error (the attempt records a fixed reason).
    pub fn generate(
        self,
        c: &EvaluationCase,
        parameters: &BTreeMap<String, Value>,
        evidence: &EvaluationEvidence,
    ) -> Result<OperatorOutput, GenerationFailed> {
        match self {
            Self::AuthoredTwin => authored_twin(c),
            op if op.is_context() => {
                let mut out = OperatorOutput::new(
                    context_apply(op, &c.seed),
                    VariantStrategy::Derived,
                    "context",
                );
                out.relation = Some(Relation::SameDetection);
                Ok(out)
            }
            Self::LengthMinusOne | Self::LengthPlusOne => {
                Ok(mutate(c, evidence, |s| lexical_change(self, s), "length"))
            }
            Self::ReplaceLast | Self::InvalidAlphabet => {
                Ok(mutate(c, evidence, |s| lexical_change(self, s), "alphabet"))
            }
            Self::PrefixChange => {
                let value = secret_value(c);
                let first = value.chars().next().ok_or(GenerationFailed)?;
                let upper: String = first.to_uppercase().collect();
                let alphabet: Vec<u8> = (b'A'..=b'Z')
                    .filter(|ch| upper != char::from(*ch).to_string())
                    .collect();
                let choice = match parameters.get("choice") {
                    Some(v) => v.as_f64().ok_or(GenerationFailed)? as u64,
                    None => seeded_choice(&c.seed_key, self.as_str(), 25),
                };
                let letter = u16::from(*alphabet.get(choice as usize).ok_or(GenerationFailed)?);
                let mut out = mutate(
                    c,
                    evidence,
                    |s| {
                        let mut v = vec![letter];
                        v.extend_from_slice(s.get(1..).unwrap_or(&[]));
                        v
                    },
                    "prefix",
                );
                out.parameters = Some(BTreeMap::from([("choice".to_owned(), Value::from(choice))]));
                Ok(out)
            }
            Self::RemoveDelimiter => {
                let value = utf16(&secret_value(c));
                let positions = separators(&value);
                if positions.is_empty() {
                    return Err(GenerationFailed);
                }
                let index = match index_param(parameters) {
                    Some(i) => i,
                    None => {
                        positions[seeded_choice(&c.seed_key, self.as_str(), positions.len() as u64)
                            as usize]
                    }
                } as usize;
                let mut out = mutate(
                    c,
                    evidence,
                    |s| {
                        let mut v = s[..index.min(s.len())].to_vec();
                        v.extend_from_slice(s.get(index + 1..).unwrap_or(&[]));
                        v
                    },
                    "boundary",
                );
                out.parameters = Some(BTreeMap::from([("index".to_owned(), Value::from(index))]));
                Ok(out)
            }
            Self::RemoveSegment => {
                let family = c.seed.grouping.family.as_deref().ok_or(GenerationFailed)?;
                let rule = evidence
                    .contracts
                    .get(family)
                    .and_then(|contract| contract.segments.clone())
                    .ok_or(GenerationFailed)?;
                let value = secret_value(c);
                let parts = value.split(rule.delimiter.as_str()).count() as u64;
                if parts < 2 {
                    // Legacy computes `seededChoice(..) % 0` (NaN) here; refuse instead.
                    return Err(GenerationFailed);
                }
                let index = match index_param(parameters) {
                    Some(i) => i,
                    None => 1 + seeded_choice(&c.seed_key, self.as_str(), parts - 1),
                };
                let delimiter = rule.delimiter.clone();
                let mut out = mutate(
                    c,
                    evidence,
                    |s| {
                        let text = from_utf16(s);
                        let kept: Vec<&str> = text
                            .split(delimiter.as_str())
                            .enumerate()
                            .filter(|(i, _)| *i as u64 != index)
                            .map(|(_, p)| p)
                            .collect();
                        utf16(&kept.join(delimiter.as_str()))
                    },
                    "structural",
                );
                out.parameters = Some(BTreeMap::from([("index".to_owned(), Value::from(index))]));
                Ok(out)
            }
            _ => Err(GenerationFailed),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn js_trim_end_matches_javascript_whitespace() {
        assert_eq!(js_trim_end("a \t\r\n\u{feff}"), "a");
        // NEL is not JavaScript whitespace.
        assert_eq!(js_trim_end("a\u{85}"), "a\u{85}");
    }

    #[test]
    fn lexical_edits_are_utf16() {
        let s = utf16("AB");
        assert_eq!(
            from_utf16(&lexical_change(OperatorId::ReplaceLast, &s)),
            "AA"
        );
        let s = utf16("BA");
        assert_eq!(
            from_utf16(&lexical_change(OperatorId::ReplaceLast, &s)),
            "BB"
        );
        // Dropping the low half of a surrogate pair leaves U+FFFD, as Buffer writes.
        let s = utf16("x\u{1f511}");
        assert_eq!(
            from_utf16(&lexical_change(OperatorId::LengthMinusOne, &s)),
            "x\u{fffd}"
        );
    }

    #[test]
    fn operator_ids_round_trip() {
        for op in OperatorId::ALL {
            assert_eq!(op.as_str().parse::<OperatorId>().unwrap(), op);
        }
    }
}
