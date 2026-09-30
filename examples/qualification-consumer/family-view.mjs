// Derives the per-scanner, per-family view specified in
// docs/qualification-boundary.md ("Family view") from a validated run artifact.
//
// This is a pure projection. It counts the per-case measurements the engine
// already computed; it never re-derives an outcome from ranges, so the outcome
// lattice stays implemented in exactly one place (the Rust kernel).

export const FAMILY_VIEW_SCHEMA = 'credential-eval/family-view/v1';
export const UNASSIGNED = '(no-family)';
const OUTCOMES = ['EXACT', 'COVERED', 'OVERBROAD', 'PARTIAL', 'MISS'];
const LEAKING = new Set(['PARTIAL', 'MISS']);
// Protocol v1.1 strict twin rule (docs/contracts/outcomes.md): a pair
// discriminates only when every positive span is EXACT or COVERED and the
// twin is not flagged. This is protocol vocabulary, not policy.
const ACCEPTABLE = new Set(['EXACT', 'COVERED']);

const byteOrder = (a, b) => (a < b ? -1 : a > b ? 1 : 0);

const emptyPositive = () => ({
  cases: 0, spans: 0, outcomes: Object.fromEntries(OUTCOMES.map(o => [o, 0])),
  leaked_spans: 0, leaked_bytes: 0, collateral_bytes: 0,
});

const emptyFamily = () => ({
  cases: 0,
  pending: 0,
  not_measured: 0,
  positives: { 'must-redact': emptyPositive(), policy: emptyPositive() },
  benign: { cases: 0, flagged: 0, findings: 0 },
  twins: { pairs: 0, discriminated: 0, flagged: 0, co_detected: 0 },
});

/** Build the family view for every scanner in `artifact`. Output is sorted by (scanner, family). */
export function familyView(artifact) {
  const scanners = [...artifact.scanners].sort((a, b) => byteOrder(a.scanner, b.scanner)).map(run => {
    const families = new Map();
    const bucket = family => {
      const key = family ?? UNASSIGNED;
      if (!families.has(key)) families.set(key, emptyFamily());
      return families.get(key);
    };
    const byId = new Map(run.cases.map(c => [c.case_id, c]));

    for (const c of run.cases) {
      const f = bucket(c.family);
      f.cases++;
      const m = c.measurement;
      switch (m.type) {
        case 'pending': f.pending++; break;
        case 'not-measured': f.not_measured++; break;
        case 'positive': {
          const p = f.positives[c.kind];
          if (!p) throw new Error(`positive measurement on a ${c.kind} case`);
          p.cases++;
          p.spans += m.span_outcomes.length;
          for (const outcome of m.span_outcomes) {
            p.outcomes[outcome]++;
            if (LEAKING.has(outcome)) p.leaked_spans++;
          }
          p.leaked_bytes += m.leaked_bytes;
          p.collateral_bytes += m.collateral_bytes;
          break;
        }
        case 'control': {
          if (c.twin_of === undefined) {
            f.benign.cases++;
            if (m.flagged) f.benign.flagged++;
            f.benign.findings += m.findings;
            break;
          }
          // A pair is scored only when its positive was scored too.
          const positive = byId.get(c.twin_of)?.measurement;
          if (positive?.type !== 'positive') break;
          f.twins.pairs++;
          if (m.flagged) f.twins.flagged++;
          if (m.co_detected) f.twins.co_detected++;
          if (!m.flagged && positive.span_outcomes.every(o => ACCEPTABLE.has(o))) f.twins.discriminated++;
          break;
        }
        default:
          throw new Error(`unknown measurement type ${m.type}`);
      }
    }

    return {
      scanner: run.scanner,
      status: run.status,
      families: [...families.keys()].sort(byteOrder).map(family => ({ family, ...families.get(family) })),
    };
  });

  return {
    schema: FAMILY_VIEW_SCHEMA,
    source: {
      artifact_schema: artifact.schema,
      engine: artifact.manifest.engine,
      protocol_version: artifact.manifest.protocol_version,
      evidence: artifact.manifest.evidence,
      config_hash: artifact.manifest.config_hash,
    },
    scanners,
  };
}
