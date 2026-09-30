// ILLUSTRATIVE TOY POLICY. Not the Redact Secret support policy.
//
// It reads a family view (family-view.mjs) and a threshold file (toy-policy.json)
// and assigns deliberately non-product labels. Every threshold lives in the
// config file, so changing policy never touches the engine, the artifact or the
// family view.

export const LABELS = Object.freeze({
  meets: 'toy-meets-bar',
  below: 'toy-below-bar',
  noEvidence: 'toy-no-scored-evidence',
  notMeasured: 'toy-not-measured',
});

const OUTCOMES = new Set(['EXACT', 'COVERED', 'OVERBROAD', 'PARTIAL', 'MISS']);
const INTEGER_KEYS = ['minimumScoredPositiveCases', 'maximumNonAcceptableSpans', 'maximumBenignFalseAlarms', 'minimumTwinPairs', 'maximumTwinFailures'];

/** Reject a malformed policy file up front instead of producing a misleading verdict. */
export function validatePolicy(policy) {
  const problems = [];
  if (policy?.policy !== 'toy-illustrative-policy') problems.push('policy: must be "toy-illustrative-policy"');
  if (!Number.isInteger(policy?.version) || policy.version < 1) problems.push('version: must be a positive integer');
  if (typeof policy?.notice !== 'string' || !policy.notice.includes('not the Redact Secret support policy')) problems.push('notice: must state that this is not the Redact Secret support policy');
  if (!Array.isArray(policy?.positiveKinds) || !policy.positiveKinds.every(k => k === 'must-redact' || k === 'policy')) problems.push('positiveKinds: must list must-redact and/or policy');
  if (!Array.isArray(policy?.acceptableOutcomes) || !policy.acceptableOutcomes.length || !policy.acceptableOutcomes.every(o => OUTCOMES.has(o))) problems.push('acceptableOutcomes: must list lattice outcomes');
  for (const key of INTEGER_KEYS) if (!Number.isInteger(policy?.[key]) || policy[key] < 0) problems.push(`${key}: must be a non-negative integer`);
  if (problems.length) throw new Error(`Invalid toy policy: ${problems.join('; ')}`);
  return policy;
}

function judge(family, policy) {
  const positives = policy.positiveKinds.map(kind => family.positives[kind]);
  const scored = positives.reduce((n, p) => n + p.cases, 0);
  const nonAcceptable = positives.reduce((n, p) =>
    n + Object.entries(p.outcomes).filter(([outcome]) => !policy.acceptableOutcomes.includes(outcome)).reduce((s, [, count]) => s + count, 0), 0);
  const twinFailures = family.twins.pairs - family.twins.discriminated;
  const figures = {
    scored_positive_cases: scored,
    non_acceptable_spans: nonAcceptable,
    benign_false_alarms: family.benign.flagged,
    twin_pairs: family.twins.pairs,
    twin_failures: twinFailures,
    pending_cases: family.pending,
  };

  if (scored === 0) return { label: LABELS.noEvidence, reasons: ['no scored positive case'], figures };
  const reasons = [];
  const atMost = (id, value, bound) => { if (value > bound) reasons.push(`${id}: ${value} > ${bound}`); };
  const atLeast = (id, value, bound) => { if (value < bound) reasons.push(`${id}: ${value} < ${bound}`); };
  atLeast('minimumScoredPositiveCases', scored, policy.minimumScoredPositiveCases);
  atMost('maximumNonAcceptableSpans', nonAcceptable, policy.maximumNonAcceptableSpans);
  atMost('maximumBenignFalseAlarms', family.benign.flagged, policy.maximumBenignFalseAlarms);
  atLeast('minimumTwinPairs', family.twins.pairs, policy.minimumTwinPairs);
  atMost('maximumTwinFailures', twinFailures, policy.maximumTwinFailures);
  return { label: reasons.length ? LABELS.below : LABELS.meets, reasons, figures };
}

/** Apply the toy policy to a family view. Output order follows the view (scanner, family). */
export function applyToyPolicy(view, policy) {
  validatePolicy(policy);
  return view.scanners.flatMap(run => run.families.map(family => {
    // A scanner that did not complete produced no observation. That is never
    // read as a miss: the verdict says "not measured" and names the status.
    if (run.status !== 'complete') {
      return { scanner: run.scanner, family: family.family, label: LABELS.notMeasured, reasons: [`scanner status ${run.status}`] };
    }
    return { scanner: run.scanner, family: family.family, ...judge(family, policy) };
  }));
}
