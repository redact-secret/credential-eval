// Legacy corpus exporter (issue #5, migration-only; delete with the compat layer).
//
// PARITY-ONLY. The output is an oracle projection of the legacy corpus for
// dual-run parity, not a canonical corpus: legacy coordinates (category and
// suite names, beta/milestone labels, detector ids) stay inside it and inside
// tools/parity, and never enter canonical identity. The canonical evidence
// model is credential-evidence's.
//
// Converts the pinned legacy fixture corpus of redact-secret-benchmarks into
// credential-eval inputs, importing the legacy TypeScript directly so that
// case construction inputs (assessments, targets, control axes, contract
// patterns) are read, never re-derived:
//
//   snapshot.json   CorpusSnapshot v1 over every non-calibration category.
//                   Case ids are `<category>--<fixtureId>`, paths are
//                   `<category>/<fixture path>` (unique across categories),
//                   `grouping.group` is the category.
//   evidence.json   Evaluation evidence: family contracts (patterns and the
//                   two segment rules legacy hard-codes), named validators,
//                   the benign taxonomy vocabulary and the `eval` family
//                   allowlist rule (legacy-map §2.11, kernel-deltas N4-N8).
//   legacy-index.json  Compatibility sidecar for the legacy writers: per
//                   category the raw corpus-file SHA-256 (legacy `corpusHash`)
//                   and fixture order, per case the legacy row `group` label,
//                   and the bench summary assignments
//                   (`benchmarks/fixture-detectors.json`).
//
// Usage (from the credential-eval repository root):
//
//   LEGACY=/path/to/redact-secret-benchmarks   # pinned at 1020d2b5905e8973098235e57c4cdca3359bba57
//   "$LEGACY/node_modules/.bin/tsx" tools/legacy-export/export.mts "$LEGACY" <out-dir>
//
// The output is deterministic (no timestamps, no host paths) and refuses any
// other legacy commit. Fixture content is the legacy repository's synthetic
// corpus; nothing here reads scanner output.

import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

const PINNED = '1020d2b5905e8973098235e57c4cdca3359bba57';
const [legacyRoot, outDir] = process.argv.slice(2);
if (!legacyRoot || !outDir) throw new Error('usage: export.mts <legacy-root> <out-dir>');
const commit = execFileSync('git', ['-C', legacyRoot, 'rev-parse', 'HEAD'], { encoding: 'utf8' }).trim();
if (commit !== PINNED) throw new Error(`legacy checkout is at ${commit}, expected ${PINNED}`);

const legacy = (p: string) => import(pathToFileURL(path.join(legacyRoot, p)).href);
const assessment = await legacy('benchmarks/evaluation/domains/credential/assessment.ts');
const scoring = await legacy('benchmarks/lib/scoring.ts');
const { buildCorpora } = await legacy('fixtures/generated/build.mjs');
const read = (p: string) => readFileSync(path.join(legacyRoot, p));
const sha256 = (b: Buffer | string) => createHash('sha256').update(b).digest('hex');

// Canonical JSON (docs/contracts/identity.md): keys sorted by UTF-8 bytes,
// compact, no insignificant whitespace.
const canonical = (v: unknown): string => {
  if (Array.isArray(v)) return `[${v.map(canonical).join(',')}]`;
  if (v && typeof v === 'object') {
    const keys = Object.keys(v).sort((a, b) => Buffer.compare(Buffer.from(a), Buffer.from(b)));
    return `{${keys.map(k => `${JSON.stringify(k)}:${canonical((v as Record<string, unknown>)[k])}`).join(',')}}`;
  }
  return JSON.stringify(v);
};
const byteOrder = (a: string, b: string) => Buffer.compare(Buffer.from(a), Buffer.from(b));

const categories: { id: string; corpus: string; calibrationOnly?: boolean }[] = JSON.parse(read('benchmarks/categories.json').toString('utf8'));
const detectorMap: Record<string, string[]> = JSON.parse(read('benchmarks/fixture-detectors.json').toString('utf8'));
const generated = buildCorpora();

const cases: unknown[] = [];
const index: {
  categories: { id: string; corpus: string; corpusHash: string; fixtures: string[]; reviewStatus: string | null }[];
  groups: Record<string, string>;
  duplicateTargets: Record<string, string[]>;
} = { categories: [], groups: {}, duplicateTargets: {} };

for (const category of categories) {
  if (category.calibrationOnly) continue; // legacy bench and eval both skip these
  const raw = read(category.corpus);
  const corpus = scoring.validateCorpus(JSON.parse(raw.toString('utf8')));
  if (corpus.schemaVersion !== 2) throw new Error(`corpus schema 2 required: ${category.id}`);
  // `bench` reads the file and `eval` rebuilds generated corpora in memory
  // (cases.ts:44-50); both must be the same bytes of evidence.
  if (generated[category.id] && canonical(generated[category.id]) !== canonical(JSON.parse(raw.toString('utf8'))))
    throw new Error(`stale generated corpus file: ${category.corpus}; regenerate the legacy fixtures`);
  index.categories.push({
    id: category.id, corpus: category.corpus, corpusHash: sha256(raw),
    fixtures: corpus.fixtures.map((f: any) => f.id), reviewStatus: corpus.reviewStatus ?? null,
  });
  for (const f of corpus.fixtures as any[]) {
    assessment.validateAssessment(f);
    if (JSON.stringify(f.assessment) !== JSON.stringify(assessment.classifyFixture(category.id, f)))
      throw new Error(`stale fixture assessment: ${category.id}/${f.id}`);
    if (/[\uD800-\uDFFF]/u.test(f.content.replace(/[\uD800-\uDBFF][\uDC00-\uDFFF]/g, '')))
      throw new Error(`lone surrogate in ${category.id}/${f.id}`); // legacy-map §2.1
    const slug = `${category.id}--${f.id}`;
    index.groups[slug] = f.group;
    // Evaluation targets exactly as loadCases builds them (cases.ts:69).
    const targets: string[] = [...(detectorMap[slug] ?? f.detectors ?? []), ...(f.arrivalTargets ?? [])];
    const unique = [...new Set(targets)].sort(byteOrder);
    if (unique.length !== targets.length) index.duplicateTargets[slug] = targets;
    const a = f.assessment;
    const control = !f.twinOf && !f.expected.some((e: any) => (e.role ?? 'secret') === 'secret');
    const taxonomy = control && a.tier !== 'T0' ? assessment.controlAxis(category.id, f) : null;
    cases.push({
      id: slug,
      path: `${category.id}/${f.path}`,
      content: f.content,
      expected: f.expected.map((e: any) => ({
        start: e.start, end: e.end, role: e.role ?? 'secret',
        ...(e.envelope ? { envelope: { start: e.envelope.start, end: e.envelope.end, reason: e.envelope.reason } } : {}),
      })),
      grouping: {
        kind: a.kind, tier: a.tier, ...(a.contract ? { family: a.contract } : {}), group: category.id,
        ...(unique.length ? { targets: unique } : {}),
        ...(taxonomy ? { taxonomy } : {}),
      },
      ...(f.twinOf ? { twin: { twin_of: `${category.id}--${f.twinOf}`, mutation: f.mutation, mutation_kind: f.mutationKind } } : {}),
    });
  }
}
cases.sort((a: any, b: any) => byteOrder(a.id, b.id));
const corpusDigest = `sha256:${sha256(canonical(cases))}`;
const snapshot = {
  schema: 'credential-eval/corpus-snapshot/v1',
  // A parity-only oracle projection, never a canonical corpus: its case ids
  // (`<category>--<fixtureId>`) and grouping are legacy coordinates.
  identity: { source: `redact-secret-benchmarks@${commit.slice(0, 7)} (legacy parity projection)`, revision: commit, evidence_schema: 'legacy-fixtures/v2 (parity projection)', corpus_digest: corpusDigest },
  cases,
};

// Evidence: every contract family (the `eval` classification allowlist is the
// key set of this table, normalization.ts:7), its pattern, the two segment
// rules legacy hard-codes (operators/structural.ts:27-31) and every legacy
// value validator, referenced by name.
const SEGMENTS: Record<string, { delimiter: string; removable: number[] }> = {
  'sendgrid-token': { delimiter: '.', removable: [1, 2] },
  'slack-token': { delimiter: '-', removable: [1, 2, 3] },
};
const VALIDATORS: Record<string, string> = {
  'discord-bot-token': 'legacy:discord-bot-token',
  'confluent-cloud-api-secret': 'legacy:confluent-cloud-api-secret',
  'gitlab-runner-authentication-token': 'legacy:gitlab-routable-optional',
  'gitlab-routable-personal-access-token': 'legacy:gitlab-routable-required',
};
const families: Record<string, unknown> = {};
const validators: Record<string, string> = {};
for (const id of Object.keys(assessment.contracts).sort(byteOrder)) {
  const c = assessment.contracts[id];
  families[id] = { ...(c.pattern ? { pattern: c.pattern } : {}), ...(SEGMENTS[id] ? { segments: SEGMENTS[id] } : {}) };
  if (c.validate) {
    if (!VALIDATORS[id]) throw new Error(`legacy contract ${id} has an unmapped validator`);
    validators[id] = VALIDATORS[id];
  }
}
for (const id of Object.keys(VALIDATORS)) if (!validators[id]) throw new Error(`validator ${id} no longer exists in legacy`);
const evidence = {
  schema: 'credential-eval/evaluation-evidence/v1',
  families,
  validators,
  benign_taxonomies: [...new Set([...assessment.AXES, ...assessment.REAL_WORLD_AXES])].sort(byteOrder),
  classification_allowlist: true,
};

const legacyIndex = {
  schema: 'credential-eval/legacy-index/v1',
  legacy: { repository: 'redact-secret/redact-secret-benchmarks', commit },
  corpus_digest: corpusDigest,
  categories: index.categories,
  groups: index.groups,
  bench_assignments: detectorMap,
  duplicate_targets: index.duplicateTargets,
};

mkdirSync(outDir, { recursive: true });
const write = (name: string, value: unknown) => writeFileSync(path.join(outDir, name), JSON.stringify(value) + '\n');
write('snapshot.json', snapshot);
write('evidence.json', evidence);
write('legacy-index.json', legacyIndex);
console.log(`${cases.length} cases from ${index.categories.length} categories; corpus ${corpusDigest}; legacy ${commit}`);
console.log(`evidence: ${Object.keys(families).length} families, ${Object.keys(validators).length} validators; duplicate target lists: ${Object.keys(index.duplicateTargets).length}`);
