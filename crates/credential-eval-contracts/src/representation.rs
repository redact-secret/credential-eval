//! Representation contract (revision v1.3, [ADR 0005]).
//!
//! The closed v1 corpus snapshot has one range per expected span and one
//! `content` string. This module adds the optional facts a consumer needs to
//! state what a transformed or fragmented input *is*, without changing what any
//! earlier document means:
//!
//! * on a [`Case`](crate::corpus::Case): [`Representation`] with the input's
//!   validity, its derivation, the transformation lineage that produced it and
//!   its chunking;
//! * on an [`ExpectedSpan`](crate::corpus::ExpectedSpan): `base`, `fragments`
//!   (the secret bytes inside a range that is not contiguous) and `decoded`
//!   (how the source bytes decode to the credential value).
//!
//! Every fact is optional and absent from a document that does not use it.
//! A snapshot that carries any of them declares
//! [`REPRESENTATION_CONTRACT`] in `identity.representation`. Facts never
//! assert an outcome and never carry a decoded value: only its length and
//! digest. Ranges stay half-open UTF-8 byte offsets into the original
//! `content` ([`crate::range`]).
//!
//! [ADR 0005]: ../../../docs/decisions/0005-representation-contract.md

use std::collections::BTreeSet;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::ContractError;
use crate::canonical::{sha256_bytes, sha256_canonical};
use crate::corpus::{Case, CorpusSnapshot, EvidenceTier, ExpectedSpan, SpanRole};
use crate::ids::{CaseId, CodePoint, Sha256Digest, Slug};
use crate::range::ByteRange;
use crate::schema::RepresentationContract;

/// Version of the representation facts, as declared by a snapshot and reported
/// by a run artifact.
pub const REPRESENTATION_CONTRACT: &str = RepresentationContract::VALUE;

/// Revision of the v1 schemas this build writes (the last row of the
/// "Revisions" table in `docs/contracts/README.md`).
pub const CONTRACT_REVISION: &str = "1.3";

/// Most decode steps a span may declare.
pub const MAX_DECODE_STEPS: usize = 8;
/// Most transformation steps a case may declare.
pub const MAX_TRANSFORM_STEPS: usize = 16;
/// Most fragments one span may declare.
pub const MAX_FRAGMENTS: usize = 4096;
/// Most chunk boundaries a case may declare.
pub const MAX_CHUNK_BOUNDARIES: usize = 4096;
/// Most code points one step may list.
pub const MAX_CODE_POINTS: usize = 16;
/// Most bases a projection may name.
pub const MAX_BASES: usize = 64;

/// Whether an input is a valid string for the interface that receives it.
#[derive(
    Debug,
    Clone,
    Copy,
    Default,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Serialize,
    Deserialize,
    JsonSchema,
)]
#[serde(rename_all = "kebab-case")]
pub enum InputValidity {
    /// A valid input (the default; never written).
    #[default]
    Valid,
    /// The bytes are not valid UTF-8. A snapshot case holds its input as a
    /// JSON string, so it cannot carry these bytes: the value is part of the
    /// vocabulary, and a snapshot that uses it is refused.
    InvalidUtf8,
    /// A UTF-16 chunk boundary falls between the two halves of a surrogate
    /// pair, so that chunk is not a valid string. The content itself is valid.
    UnpairedSurrogateSplit,
}

impl InputValidity {
    /// Whether this is the default, valid reading.
    pub const fn is_valid(&self) -> bool {
        matches!(self, Self::Valid)
    }
}

/// Facts about a case's input as a whole. Present only when it carries at
/// least one fact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Representation {
    /// Input validity. Any value but `valid` makes the case an *expected
    /// rejection*: it has no spans and is tier `T0`, so it is never a true
    /// positive, a false negative or a false alarm.
    #[serde(default, skip_serializing_if = "InputValidity::is_valid")]
    pub input_validity: InputValidity,
    /// Whether the input is an authored base or derives from authored bases.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub derivation: Option<Derivation>,
    /// The input-level steps from the base to this content, in forward order.
    /// Descriptive: the evaluator checks the shape of each step, not that the
    /// content was produced by it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transformation: Option<Transformation>,
    /// Chunk boundaries the input is delivered in.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chunking: Option<Chunking>,
}

/// How an input relates to the authored bases.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Derivation {
    /// `authored-base` or `projection`.
    pub kind: DerivationKind,
    /// The authored base fixtures a projection derives from (evidence ids,
    /// which need not be cases of this snapshot). Empty for an authored base.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub bases: Vec<CaseId>,
}

/// Kind of a [`Derivation`].
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "kebab-case")]
pub enum DerivationKind {
    /// A hand-written base value.
    AuthoredBase,
    /// An input derived from one or more authored bases.
    Projection,
}

/// Input-level transformation lineage.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Transformation {
    /// Steps in forward order (base to input), at most [`MAX_TRANSFORM_STEPS`].
    pub steps: Vec<TransformStep>,
}

/// One input-level transformation step.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "op", rename_all = "kebab-case", deny_unknown_fields)]
pub enum TransformStep {
    /// Encode the value. `base64` needs `alphabet` and `padding`; `hex` needs
    /// `case`; the other fields are refused.
    Encode {
        /// The codec.
        codec: Codec,
        /// Base64 alphabet.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        alphabet: Option<Alphabet>,
        /// Base64 padding.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        padding: Option<Padding>,
        /// Hex letter case.
        #[serde(default, rename = "case", skip_serializing_if = "Option::is_none")]
        hex_case: Option<HexCase>,
    },
    /// Insert code points (zero-width characters, no-break spaces, a BOM).
    InsertCodepoints {
        /// The inserted code points.
        code_points: Vec<CodePoint>,
        /// Where they were inserted.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        positions: Option<Positions>,
    },
    /// Unicode normalization.
    Normalize {
        /// The normalization form.
        form: NormalizationForm,
    },
    /// Split the value across the input.
    Fragment {
        /// Short label of the mechanism (`shell-line-continuation`).
        mechanism: Slug,
        /// The line break the fragmentation used.
        line_break: LineBreak,
        /// Column width of a wrap, when it is one.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        width: Option<u32>,
        /// Whether the surrounding language rebuilds the value.
        reconstruction: Reconstruction,
    },
    /// Place the value in a carrier.
    Embed {
        /// Whole value or embedded in other text.
        mode: EmbedMode,
        /// Short label of the carrier (`json`, `url-query`).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        carrier: Option<Slug>,
    },
    /// Escape the value.
    Escape {
        /// Short label of the escape style.
        style: Slug,
    },
    /// Place the value in filler text.
    Place {
        /// Head, middle or tail.
        placement: Placement,
        /// Filler size in bytes.
        filler_bytes: u64,
    },
    /// Repeat the value.
    Repeat {
        /// Occurrence count (at least one).
        count: u64,
    },
}

/// A decoding or encoding codec of the bounded vocabulary.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "kebab-case")]
pub enum Codec {
    /// Base64 (standard or URL-safe alphabet).
    Base64,
    /// Hexadecimal.
    Hex,
}

/// Base64 alphabet.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "kebab-case")]
pub enum Alphabet {
    /// `A-Za-z0-9+/`.
    Standard,
    /// `A-Za-z0-9-_`.
    UrlSafe,
}

/// Base64 padding.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "kebab-case")]
pub enum Padding {
    /// Padded with `=` to a multiple of four.
    Padded,
    /// No `=`.
    Unpadded,
}

/// Hex letter case.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "kebab-case")]
pub enum HexCase {
    /// Only lower-case letters.
    Lower,
    /// Only upper-case letters.
    Upper,
    /// Both cases occur.
    Mixed,
}

/// Unicode normalization form.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "kebab-case")]
pub enum NormalizationForm {
    /// NFC.
    Nfc,
    /// NFD.
    Nfd,
    /// NFKC.
    Nfkc,
    /// NFKD.
    Nfkd,
}

/// Where code points were inserted.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "kebab-case")]
pub enum Positions {
    /// At the start.
    Start,
    /// Inside the value.
    Inside,
    /// At the end.
    End,
    /// Between every character.
    BetweenEveryCharacter,
}

/// Line break used by a fragmentation.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "kebab-case")]
pub enum LineBreak {
    /// `\n`.
    Lf,
    /// `\r\n`.
    Crlf,
    /// `\r`.
    Cr,
    /// None.
    None,
}

/// What a fragmentation means to the surrounding language. A fact about the
/// input, never a claim about a scanner or a product.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "kebab-case")]
pub enum Reconstruction {
    /// The language or serialization rebuilds the original value.
    ReconstructsOriginal,
    /// Separator text was inserted into a different value.
    InsertsSeparator,
    /// The reading depends on the consumer.
    Unresolved,
}

/// Whole-value or embedded.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "kebab-case")]
pub enum EmbedMode {
    /// The whole input is the value.
    WholeValue,
    /// The value is embedded in other text.
    Embedded,
}

/// Placement in filler text.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "kebab-case")]
pub enum Placement {
    /// At the head.
    Head,
    /// In the middle.
    Middle,
    /// At the tail.
    Tail,
}

/// Chunk boundaries of an input.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Chunking {
    /// What the boundaries count.
    pub unit: ChunkUnit,
    /// Boundary offsets: strictly increasing and inside the content.
    pub boundaries: Vec<u64>,
}

/// Unit of chunk boundaries.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "kebab-case")]
pub enum ChunkUnit {
    /// UTF-8 bytes. A boundary may fall inside a multibyte sequence and the
    /// input is still valid for a byte stream.
    Utf8Byte,
    /// UTF-16 code units. A boundary between the halves of a surrogate pair
    /// makes that chunk an invalid string.
    Utf16CodeUnit,
}

/// How the source bytes of a span decode to the credential value. The value is
/// never repeated: only its length and digest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DecodedFact {
    /// Decode steps in decode order, from the source bytes (the fragments
    /// concatenated, else `[start, end)`) to the value. At most
    /// [`MAX_DECODE_STEPS`].
    pub via: Vec<DecodeStep>,
    /// Digest of the decoded value.
    pub sha256: Sha256Digest,
    /// Length of the decoded value in bytes (non-zero).
    pub bytes: u64,
}

/// One decode step.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "codec", rename_all = "kebab-case", deny_unknown_fields)]
pub enum DecodeStep {
    /// Decode base64.
    Base64 {
        /// Alphabet.
        alphabet: Alphabet,
        /// Padding.
        padding: Padding,
    },
    /// Decode hexadecimal.
    Hex {
        /// Letter case of the encoded text.
        #[serde(rename = "case")]
        hex_case: HexCase,
    },
    /// Remove every occurrence of these code points.
    StripCodepoints {
        /// The code points removed.
        code_points: Vec<CodePoint>,
    },
    /// Unicode normalization (declared; this build does not verify it).
    Normalize {
        /// The form.
        form: NormalizationForm,
    },
}

/// What this build did with a span's `decoded` fact.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecodedCheck {
    /// Every step was re-derived from the content bytes and the length and
    /// digest matched.
    Verified,
    /// A step (`normalize`) cannot be re-derived here: the fact is carried and
    /// its shape was checked, but its length and digest were not.
    Unverified,
}

/// Per-snapshot account of the representation facts received. Written to the
/// run manifest only when the snapshot declares the contract.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RepresentationReport {
    /// The contract version the snapshot declared.
    pub contract: RepresentationContract,
    /// Digest of every representation fact received, canonical and sorted by
    /// case id. An exporter computes the same digest from what it wrote, so a
    /// consumer can prove which facts reached the engine.
    pub facts_digest: Sha256Digest,
    /// Cases carrying any representation fact (case-level or span-level).
    pub cases: u64,
    /// Cases with a `transformation`.
    pub transformed_cases: u64,
    /// Cases with `chunking`.
    pub chunked_cases: u64,
    /// Expected rejections: cases whose `input_validity` is not `valid`.
    /// Non-asserting; in no TP/FN denominator.
    pub expected_rejections: u64,
    /// Spans with `fragments`.
    pub fragmented_spans: u64,
    /// Fragments over all such spans.
    pub fragments: u64,
    /// Spans with `decoded`.
    pub decoded_spans: u64,
    /// Of those, spans whose decode was re-derived and matched.
    pub decoded_verified: u64,
    /// Of those, spans carried but not re-derivable here (`normalize`).
    pub decoded_unverified: u64,
}

/// What one case's facts amount to.
#[derive(Debug, Default, Clone, Copy)]
pub(crate) struct CaseSummary {
    pub has_facts: bool,
    pub transformed: bool,
    pub chunked: bool,
    pub rejection: bool,
    pub fragmented_spans: u64,
    pub fragments: u64,
    pub decoded_spans: u64,
    pub decoded_verified: u64,
}

fn invalid(case: &Case, reason: &'static str) -> ContractError {
    ContractError::InvalidRepresentation {
        case: case.id.to_string(),
        reason,
    }
}

/// Whether the case carries any representation fact.
pub fn case_has_facts(case: &Case) -> bool {
    case.representation.is_some()
        || case
            .expected
            .iter()
            .any(|s| s.base.is_some() || s.fragments.is_some() || s.decoded.is_some())
}

/// Validate every representation fact of `case` and summarize it. Fails closed
/// on the first violation; messages name the case, never its content.
pub(crate) fn check_case(case: &Case) -> Result<CaseSummary, ContractError> {
    let mut summary = CaseSummary {
        has_facts: case_has_facts(case),
        ..CaseSummary::default()
    };
    if !summary.has_facts {
        return Ok(summary);
    }
    if let Some(rep) = &case.representation {
        check_representation(case, rep)?;
        summary.transformed = rep.transformation.is_some();
        summary.chunked = rep.chunking.is_some();
        summary.rejection = !rep.input_validity.is_valid();
    }
    for span in &case.expected {
        check_span(case, span, &mut summary)?;
    }
    Ok(summary)
}

fn check_representation(case: &Case, rep: &Representation) -> Result<(), ContractError> {
    if rep.input_validity.is_valid()
        && rep.derivation.is_none()
        && rep.transformation.is_none()
        && rep.chunking.is_none()
    {
        return Err(invalid(case, "representation carries no fact"));
    }
    let splits = match &rep.chunking {
        Some(chunking) => check_chunking(case, chunking)?,
        None => false,
    };
    match rep.input_validity {
        InputValidity::Valid => {
            if splits {
                return Err(invalid(
                    case,
                    "a chunk boundary splits a surrogate pair but the input is declared valid",
                ));
            }
        }
        InputValidity::InvalidUtf8 => {
            return Err(invalid(
                case,
                "invalid-utf8 input cannot be carried by a snapshot case",
            ));
        }
        InputValidity::UnpairedSurrogateSplit => {
            if !splits {
                return Err(invalid(
                    case,
                    "unpaired-surrogate-split needs a utf16 chunk boundary inside a surrogate pair",
                ));
            }
        }
    }
    if !rep.input_validity.is_valid() {
        if !case.expected.is_empty() {
            return Err(invalid(case, "an expected rejection carries no spans"));
        }
        if case.grouping.tier != EvidenceTier::T0 {
            return Err(invalid(case, "an expected rejection is tier T0"));
        }
    }
    if let Some(derivation) = &rep.derivation {
        check_derivation(case, derivation)?;
    }
    if let Some(transformation) = &rep.transformation {
        if transformation.steps.is_empty() || transformation.steps.len() > MAX_TRANSFORM_STEPS {
            return Err(invalid(case, "transformation step count out of bounds"));
        }
        for step in &transformation.steps {
            check_transform_step(case, step)?;
        }
    }
    Ok(())
}

fn check_derivation(case: &Case, derivation: &Derivation) -> Result<(), ContractError> {
    match derivation.kind {
        DerivationKind::AuthoredBase if !derivation.bases.is_empty() => {
            Err(invalid(case, "an authored base names no bases"))
        }
        DerivationKind::Projection
            if derivation.bases.is_empty() || derivation.bases.len() > MAX_BASES =>
        {
            Err(invalid(case, "a projection names one to 64 bases"))
        }
        _ => {
            let unique: BTreeSet<&CaseId> = derivation.bases.iter().collect();
            if unique.len() == derivation.bases.len() {
                Ok(())
            } else {
                Err(invalid(case, "duplicate base"))
            }
        }
    }
}

/// Validate chunk boundaries; returns whether a utf16 boundary splits a
/// surrogate pair of the content.
fn check_chunking(case: &Case, chunking: &Chunking) -> Result<bool, ContractError> {
    let boundaries = &chunking.boundaries;
    if boundaries.is_empty() || boundaries.len() > MAX_CHUNK_BOUNDARIES {
        return Err(invalid(case, "chunk boundary count out of bounds"));
    }
    if boundaries.windows(2).any(|w| w[0] >= w[1]) {
        return Err(invalid(
            case,
            "chunk boundaries are not strictly increasing",
        ));
    }
    match chunking.unit {
        ChunkUnit::Utf8Byte => {
            let len = case.content.len() as u64;
            if boundaries.iter().any(|b| *b == 0 || *b >= len) {
                return Err(invalid(case, "chunk boundary outside the content"));
            }
            Ok(false)
        }
        ChunkUnit::Utf16CodeUnit => {
            let units: Vec<u16> = case.content.encode_utf16().collect();
            let len = units.len() as u64;
            if boundaries.iter().any(|b| *b == 0 || *b >= len) {
                return Err(invalid(case, "chunk boundary outside the content"));
            }
            Ok(boundaries.iter().any(|b| {
                let at = *b as usize;
                (0xD800..0xDC00).contains(&units[at - 1]) && (0xDC00..0xE000).contains(&units[at])
            }))
        }
    }
}

fn check_code_points(case: &Case, points: &[CodePoint]) -> Result<(), ContractError> {
    let unique: BTreeSet<&CodePoint> = points.iter().collect();
    if points.is_empty() || points.len() > MAX_CODE_POINTS || unique.len() != points.len() {
        return Err(invalid(case, "code point list out of bounds or duplicated"));
    }
    Ok(())
}

fn check_transform_step(case: &Case, step: &TransformStep) -> Result<(), ContractError> {
    match step {
        TransformStep::Encode {
            codec,
            alphabet,
            padding,
            hex_case,
        } => {
            let shape = match codec {
                Codec::Base64 => alphabet.is_some() && padding.is_some() && hex_case.is_none(),
                Codec::Hex => alphabet.is_none() && padding.is_none() && hex_case.is_some(),
            };
            if shape {
                Ok(())
            } else {
                Err(invalid(case, "encode step fields do not fit its codec"))
            }
        }
        TransformStep::InsertCodepoints { code_points, .. } => check_code_points(case, code_points),
        TransformStep::Fragment { width, .. } if *width == Some(0) => {
            Err(invalid(case, "fragment width is zero"))
        }
        TransformStep::Repeat { count } if *count == 0 => {
            Err(invalid(case, "repeat count is zero"))
        }
        _ => Ok(()),
    }
}

fn check_span(
    case: &Case,
    span: &ExpectedSpan,
    summary: &mut CaseSummary,
) -> Result<(), ContractError> {
    if span.base.is_none() && span.fragments.is_none() && span.decoded.is_none() {
        return Ok(());
    }
    if span.role != SpanRole::Secret {
        return Err(invalid(case, "span facts belong to a secret span"));
    }
    let content = case.content.as_str();
    if let Some(fragments) = &span.fragments {
        if fragments.len() < 2 || fragments.len() > MAX_FRAGMENTS {
            return Err(invalid(case, "a fragmented span has two or more fragments"));
        }
        let mut previous_end: Option<u64> = None;
        for fragment in fragments {
            if !fragment.is_valid_in(content) {
                return Err(invalid(case, "fragment is not a valid UTF-8 range"));
            }
            if previous_end.is_some_and(|end| fragment.start <= end) {
                return Err(invalid(
                    case,
                    "fragments are not sorted, disjoint and separated",
                ));
            }
            previous_end = Some(fragment.end);
        }
        let (first, last) = (fragments[0], fragments[fragments.len() - 1]);
        if first.start != span.start || last.end != span.end {
            return Err(invalid(
                case,
                "fragments must start at the span start and end at the span end",
            ));
        }
        summary.fragmented_spans += 1;
        summary.fragments += fragments.len() as u64;
    }
    if let Some(decoded) = &span.decoded {
        summary.decoded_spans += 1;
        if check_decoded(case, span, decoded)? == DecodedCheck::Verified {
            summary.decoded_verified += 1;
        }
    }
    Ok(())
}

/// The bytes a span's `decoded.via` starts from: the fragments concatenated,
/// else `[start, end)`.
fn source_bytes(case: &Case, span: &ExpectedSpan) -> Vec<u8> {
    let bytes = case.content.as_bytes();
    let slice = |r: ByteRange| &bytes[r.start as usize..r.end as usize];
    match &span.fragments {
        Some(fragments) => fragments.iter().flat_map(|r| slice(*r)).copied().collect(),
        None => slice(span.range()).to_vec(),
    }
}

fn check_decoded(
    case: &Case,
    span: &ExpectedSpan,
    decoded: &DecodedFact,
) -> Result<DecodedCheck, ContractError> {
    if decoded.via.is_empty() || decoded.via.len() > MAX_DECODE_STEPS {
        return Err(invalid(case, "decode step count out of bounds"));
    }
    if decoded.bytes == 0 {
        return Err(invalid(case, "decoded length is zero"));
    }
    for step in &decoded.via {
        if let DecodeStep::StripCodepoints { code_points } = step {
            check_code_points(case, code_points)?;
        }
    }
    if decoded
        .via
        .iter()
        .any(|s| matches!(s, DecodeStep::Normalize { .. }))
    {
        return Ok(DecodedCheck::Unverified);
    }
    let mut value = source_bytes(case, span);
    for step in &decoded.via {
        value = apply_decode(&value, step)
            .ok_or_else(|| invalid(case, "a decode step does not re-derive from the source"))?;
    }
    if value.len() as u64 != decoded.bytes || sha256_bytes(&value) != decoded.sha256 {
        return Err(invalid(
            case,
            "decoded length or digest does not match the re-derived value",
        ));
    }
    Ok(DecodedCheck::Verified)
}

/// Apply one decode step strictly: any deviation from the declared alphabet,
/// padding, case or canonical form is `None`.
fn apply_decode(input: &[u8], step: &DecodeStep) -> Option<Vec<u8>> {
    match step {
        DecodeStep::Base64 { alphabet, padding } => {
            base64_decode_strict(input, *alphabet, *padding)
        }
        DecodeStep::Hex { hex_case } => hex_decode_strict(input, *hex_case),
        DecodeStep::StripCodepoints { code_points } => {
            let text = std::str::from_utf8(input).ok()?;
            let points: Vec<char> = code_points
                .iter()
                .map(|p| char::from_u32(u32::from_str_radix(&p.as_str()[2..], 16).ok()?))
                .collect::<Option<_>>()?;
            if points.iter().any(|p| !text.contains(*p)) {
                return None;
            }
            Some(
                text.chars()
                    .filter(|c| !points.contains(c))
                    .collect::<String>()
                    .into_bytes(),
            )
        }
        DecodeStep::Normalize { .. } => None,
    }
}

fn base64_value(byte: u8, alphabet: Alphabet) -> Option<u32> {
    match byte {
        b'A'..=b'Z' => Some(u32::from(byte - b'A')),
        b'a'..=b'z' => Some(u32::from(byte - b'a') + 26),
        b'0'..=b'9' => Some(u32::from(byte - b'0') + 52),
        b'+' if alphabet == Alphabet::Standard => Some(62),
        b'/' if alphabet == Alphabet::Standard => Some(63),
        b'-' if alphabet == Alphabet::UrlSafe => Some(62),
        b'_' if alphabet == Alphabet::UrlSafe => Some(63),
        _ => None,
    }
}

/// Strict base64: the declared alphabet and padding, no whitespace, and
/// canonical (the unused trailing bits are zero).
pub fn base64_decode_strict(input: &[u8], alphabet: Alphabet, padding: Padding) -> Option<Vec<u8>> {
    let body_len = input.iter().rposition(|b| *b != b'=').map_or(0, |i| i + 1);
    let (body, pad) = input.split_at(body_len);
    match padding {
        Padding::Padded => {
            if input.len() % 4 != 0 || pad.len() > 2 {
                return None;
            }
        }
        Padding::Unpadded => {
            if !pad.is_empty() {
                return None;
            }
        }
    }
    if body.is_empty() || body.len() % 4 == 1 {
        return None;
    }
    let mut out = Vec::with_capacity(body.len() * 3 / 4);
    let (mut acc, mut bits) = (0u32, 0u32);
    for byte in body {
        acc = (acc << 6) | base64_value(*byte, alphabet)?;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(u8::try_from((acc >> bits) & 0xFF).ok()?);
            acc &= (1 << bits) - 1;
        }
    }
    (acc == 0).then_some(out)
}

/// Strict hex: an even number of digits, in the declared case.
pub fn hex_decode_strict(input: &[u8], hex_case: HexCase) -> Option<Vec<u8>> {
    if input.is_empty() || input.len() % 2 != 0 || !input.iter().all(u8::is_ascii_hexdigit) {
        return None;
    }
    let lower = input.iter().any(|b| (b'a'..=b'f').contains(b));
    let upper = input.iter().any(|b| (b'A'..=b'F').contains(b));
    let fits = match hex_case {
        HexCase::Lower => !upper,
        HexCase::Upper => !lower,
        HexCase::Mixed => lower && upper,
    };
    if !fits {
        return None;
    }
    let digit = |b: u8| {
        char::from(b)
            .to_digit(16)
            .and_then(|d| u8::try_from(d).ok())
    };
    input
        .chunks(2)
        .map(|pair| Some(digit(pair[0])? << 4 | digit(pair[1])?))
        .collect()
}

/// The facts of one case, as hashed into [`RepresentationReport::facts_digest`].
#[derive(Serialize)]
struct CaseFacts<'a> {
    case_id: &'a CaseId,
    #[serde(skip_serializing_if = "Option::is_none")]
    representation: Option<&'a Representation>,
    spans: Vec<SpanFacts<'a>>,
}

#[derive(Serialize)]
struct SpanFacts<'a> {
    index: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    base: Option<&'a CaseId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    fragments: Option<&'a Vec<ByteRange>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    decoded: Option<&'a DecodedFact>,
}

/// Digest of every representation fact of `cases`: canonical JSON of the
/// per-case facts, sorted by case id. Cases without facts do not contribute.
pub fn facts_digest(cases: &[Case]) -> Sha256Digest {
    let mut sorted: Vec<&Case> = cases.iter().filter(|c| case_has_facts(c)).collect();
    sorted.sort_by(|a, b| a.id.cmp(&b.id));
    let facts: Vec<CaseFacts<'_>> = sorted
        .into_iter()
        .map(|case| CaseFacts {
            case_id: &case.id,
            representation: case.representation.as_ref(),
            spans: case
                .expected
                .iter()
                .enumerate()
                .filter(|(_, s)| s.base.is_some() || s.fragments.is_some() || s.decoded.is_some())
                .map(|(index, s)| SpanFacts {
                    index,
                    base: s.base.as_ref(),
                    fragments: s.fragments.as_ref(),
                    decoded: s.decoded.as_ref(),
                })
                .collect(),
        })
        .collect();
    sha256_canonical(&facts)
}

impl CorpusSnapshot {
    /// Whether any case carries a representation fact.
    pub fn uses_representation(&self) -> bool {
        self.cases.iter().any(case_has_facts)
    }

    /// The account of the representation facts this snapshot carries, or
    /// `None` when it declares nothing and carries nothing (every snapshot
    /// before revision v1.3), so such a run artifact is byte-for-byte what it
    /// was. The snapshot must have passed [`CorpusSnapshot::validate`].
    pub fn representation_report(&self) -> Option<RepresentationReport> {
        if self.identity.representation.is_none() && !self.uses_representation() {
            return None;
        }
        let mut report = RepresentationReport {
            contract: RepresentationContract,
            facts_digest: facts_digest(&self.cases),
            cases: 0,
            transformed_cases: 0,
            chunked_cases: 0,
            expected_rejections: 0,
            fragmented_spans: 0,
            fragments: 0,
            decoded_spans: 0,
            decoded_verified: 0,
            decoded_unverified: 0,
        };
        for case in &self.cases {
            let Ok(s) = check_case(case) else { continue };
            report.cases += u64::from(s.has_facts);
            report.transformed_cases += u64::from(s.transformed);
            report.chunked_cases += u64::from(s.chunked);
            report.expected_rejections += u64::from(s.rejection);
            report.fragmented_spans += s.fragmented_spans;
            report.fragments += s.fragments;
            report.decoded_spans += s.decoded_spans;
            report.decoded_verified += s.decoded_verified;
            report.decoded_unverified += s.decoded_spans - s.decoded_verified;
        }
        Some(report)
    }
}

/// What an adapter did to place a finding that was reported in decoded
/// coordinates. Carried on the finding and on its artifact row so a consumer
/// can see which ranges are mapped, and how, and which are plain.
#[derive(
    Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(deny_unknown_fields)]
pub struct FindingMapping {
    /// What the mapped range is, relative to the decoded finding.
    pub bound: MappingBound,
    /// Decode layers between the original bytes and the finding (one to four).
    pub layers: u8,
    /// The codecs of those layers, sorted and unique.
    pub codecs: Vec<Codec>,
}

/// The bound a mapped range gives for a decoded finding.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "kebab-case")]
pub enum MappingBound {
    /// The range is the whole encoded segment of the original input; the
    /// finding lies somewhere inside its decoded text. Proved by re-deriving
    /// the decode from the original bytes (never by trusting the scanner).
    SourceSegment,
    /// The range is an encoded segment extended over the adjacent literal
    /// bytes the finding also matched (the depth-one base64 rule that
    /// predates this contract).
    SourceSegmentExtended,
    /// The range is a whole block whose body is encoded (a PEM block with a
    /// base64 body), by the rule that predates this contract.
    SourceBlock,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strict_base64_checks_alphabet_padding_and_canonical_form() {
        let std = Alphabet::Standard;
        assert_eq!(
            base64_decode_strict(b"YQ==", std, Padding::Padded),
            Some(b"a".to_vec())
        );
        assert_eq!(
            base64_decode_strict(b"YQ", std, Padding::Unpadded),
            Some(b"a".to_vec())
        );
        // padding mismatch both ways
        assert_eq!(base64_decode_strict(b"YQ", std, Padding::Padded), None);
        assert_eq!(base64_decode_strict(b"YQ==", std, Padding::Unpadded), None);
        // non-canonical trailing bits
        assert_eq!(base64_decode_strict(b"YR==", std, Padding::Padded), None);
        // alphabet mismatch
        assert_eq!(
            base64_decode_strict(b"+/+/", std, Padding::Padded).map(|v| v.len()),
            Some(3)
        );
        assert_eq!(
            base64_decode_strict(b"+/+/", Alphabet::UrlSafe, Padding::Padded),
            None
        );
        assert_eq!(
            base64_decode_strict(b"-_-_", Alphabet::UrlSafe, Padding::Padded).map(|v| v.len()),
            Some(3)
        );
        // whitespace, empty, a lone trailing character
        assert_eq!(base64_decode_strict(b"YQ ==", std, Padding::Padded), None);
        assert_eq!(base64_decode_strict(b"", std, Padding::Padded), None);
        assert_eq!(base64_decode_strict(b"YWJjZ", std, Padding::Unpadded), None);
    }

    #[test]
    fn strict_hex_checks_length_and_case() {
        assert_eq!(
            hex_decode_strict(b"6162", HexCase::Lower),
            Some(b"ab".to_vec())
        );
        assert_eq!(
            hex_decode_strict(b"4A4b", HexCase::Mixed),
            Some(b"JK".to_vec())
        );
        assert_eq!(hex_decode_strict(b"4a4b", HexCase::Upper), None);
        assert_eq!(hex_decode_strict(b"4A4B", HexCase::Lower), None);
        assert_eq!(hex_decode_strict(b"4A4B", HexCase::Mixed), None);
        assert_eq!(hex_decode_strict(b"616", HexCase::Lower), None);
        assert_eq!(hex_decode_strict(b"zz", HexCase::Lower), None);
        assert_eq!(hex_decode_strict(b"", HexCase::Lower), None);
    }
}
