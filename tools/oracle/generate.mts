// Legacy oracle generator for the credential-eval kernel (issue #3).
//
// Runs the legacy TypeScript engine of redact-secret-benchmarks on synthetic
// inputs and writes its raw outputs as JSON goldens. The Rust kernel tests
// (crates/credential-eval-kernel/tests/oracle_*.rs) replay the same inputs and
// require identical results.
//
// Usage (from the credential-eval repository root):
//
//   LEGACY=/path/to/redact-secret-benchmarks   # pinned at c403475476647bc98cc5864bccd7265eddebeb91
//   "$LEGACY/node_modules/.bin/tsx" tools/oracle/generate.mts "$LEGACY" tests/fixtures/oracle
//
// Everything is deterministic: a seeded PRNG builds the inputs, and no
// timestamps, run ids or host paths are written. All credential-like values
// are synthetic (`zq_…`, `SYN.…`, `syn-…`) and match no real provider format.

import { execFileSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

const [legacyRoot, outDir] = process.argv.slice(2);
if (!legacyRoot || !outDir) throw new Error('usage: generate.mts <legacy-root> <out-dir>');
const legacy = (p: string) => import(pathToFileURL(path.join(legacyRoot, p)).href);

const lattice = await legacy('benchmarks/lib/lattice.ts');
const scoring = await legacy('benchmarks/lib/scoring.ts');
const accounting = await legacy('benchmarks/evaluation/domains/credential/accounting.ts');
const primitives = await legacy('benchmarks/accounting/shared/primitives.ts');
const twinProbe = await legacy('benchmarks/lib/twin-probe.ts');
const runSummary = await legacy('benchmarks/evaluation/domains/credential/run-summary.ts');
const assessment = await legacy('benchmarks/evaluation/domains/credential/assessment.ts');
const execution = await legacy('benchmarks/evaluation/domains/credential/execution.ts');
const methodsIndex = await legacy('benchmarks/evaluation/domains/credential/methods/index.ts');
const operatorsIndex = await legacy('benchmarks/evaluation/domains/credential/operators/index.ts');
const lexical = await legacy('benchmarks/evaluation/domains/credential/operators/lexical.ts');
const model = await legacy('benchmarks/engine/model.ts');

const commit = execFileSync('git', ['-C', legacyRoot, 'rev-parse', 'HEAD'], { encoding: 'utf8' }).trim();
const provenance = {
  legacyRepository: 'redact-secret/redact-secret-benchmarks',
  legacyCommit: commit,
  generator: 'tools/oracle/generate.mts',
};

// ---------------------------------------------------------------------------
// Deterministic PRNG (mulberry32).
function prng(seed: number) {
  let a = seed >>> 0;
  const next = () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
  const int = (lo: number, hi: number) => lo + Math.floor(next() * (hi - lo + 1));
  const pick = <T>(xs: readonly T[]): T => xs[int(0, xs.length - 1)];
  const chance = (p: number) => next() < p;
  return { next, int, pick, chance };
}

const write = (name: string, value: unknown) => {
  mkdirSync(outDir, { recursive: true });
  writeFileSync(path.join(outDir, name), JSON.stringify({ provenance, ...value as object }) + '\n');
};

const bytes = (s: string) => Buffer.byteLength(s);

// ---------------------------------------------------------------------------
// 1. Mechanical primitives.
{
  const r = prng(1);
  const config = (over: Partial<Record<string, unknown>> = {}) => ({ minDenominator: 5, replays: 2, intervalZ: 1.96, intervalPrecision: 6, ...over });
  const round: [number, number, number][] = [];
  const values = [0, 0.5, 0.125, 0.375, 1 / 128, 3 / 128, 5 / 256, 1 / 1024, 0.0078125, 1.005, 2.5, 0.9999995, 1 / 3, 2 / 3, 99.99999999, 0.1 + 0.2, 1e-7, 123456.7890125];
  for (let k = 1; k < 512; k += 3) values.push(k / 512, k / 1024, k / 2048);
  for (let i = 0; i < 150; i++) values.push(r.next() * r.pick([1, 10, 1000]), r.int(0, 5000) / r.int(1, 700));
  for (const v of values) for (const p of [1, 2, 3, 6, 9, 12]) round.push([v, p, primitives.round(v, p)]);
  const wilson: unknown[] = [];
  for (let i = 0; i < 600; i++) {
    const n = r.int(1, 400), num = r.int(0, n), z = r.pick([1.0, 1.645, 1.96, 2.576, 0.5]), p = r.pick([1, 3, 6, 9, 12]);
    const dir = r.pick(['upper', 'lower'] as const);
    wilson.push([num / n, n, dir, z, p, primitives.wilson(num / n, n, dir, { intervalZ: z, intervalPrecision: p })]);
  }
  const proportion: unknown[] = [], ratio: unknown[] = [];
  for (let i = 0; i < 500; i++) {
    const den = r.int(0, 60), num = r.int(0, Math.max(den, 1) * r.pick([1, 1, 3])), n = r.chance(0.4) ? r.int(0, 40) : undefined;
    const c = config({ minDenominator: r.int(1, 8), intervalPrecision: r.int(1, 12), intervalZ: r.pick([1.0, 1.96, 2.2]) });
    const dir = r.pick(['upper', 'lower'] as const);
    proportion.push({ num, den, dir, n: n ?? null, config: c, out: primitives.proportion(num, den, dir, c, n) });
    ratio.push({ num, den, n: n ?? null, config: c, out: primitives.ratio(num, den, c, n) });
  }
  const counts: unknown[] = [];
  for (let i = 0; i < 100; i++) {
    const c = { pass: r.int(0, 12), fail: r.int(0, 5), 'review-required': r.int(0, 6), 'not-measured': r.int(0, 4) };
    const cfg = config({ minDenominator: r.int(1, 6) });
    counts.push({ counts: c, config: cfg, out: primitives.accountCounts(c, cfg) });
  }
  const unresolved: unknown[] = [];
  const strata = ['must-redact:T1', 'must-redact:T0', 'must-not-flag:T2', 'must-redact:T1->must-not-flag:T1', 'policy:T3'];
  for (let i = 0; i < 60; i++) {
    const summary: Record<string, Record<string, number>> = {};
    for (let j = r.int(0, 8); j > 0; j--) {
      const key = `${r.pick(['twin', 'mutation', 'metamorphic', 'benign', 'differential'])}/${r.pick(['sa', 'sb'])}/${r.pick(strata)}/${r.pick(['absolute', 'absent', 'same-detection'])}`;
      summary[key] = { pass: r.int(0, 9), fail: r.int(0, 3), 'review-required': r.int(0, 4), 'not-measured': r.int(0, 2) };
      if (r.chance(0.2)) summary[key] = { pass: 0, fail: 0, 'review-required': r.int(0, 3), 'not-measured': r.int(0, 2) };
    }
    const cfg = { version: '1.1', ...config(), resolvedRateFloor: r.pick([0.9, { default: 0.9, differential: 0 }, { default: 0.5, twin: 1 }, 0]),
      measurableShareFloor: 0.7, twinCoverageFloor: 0.5 };
    unresolved.push({ summary, config: cfg, out: accounting.unresolvedGroups(summary, cfg) });
  }
  write('primitives.json', { round, wilson, proportion, ratio, accountCounts: counts, unresolvedGroups: unresolved });
}

// ---------------------------------------------------------------------------
// Synthetic content and fixtures.
const ALPHABET = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 =:_-.';
const WIDE = ['é', '密', '钥', '🔑', 'ß'];
function content(r: ReturnType<typeof prng>, length: number) {
  const chars: string[] = [];
  for (let i = 0; i < length; i++) chars.push(r.chance(0.08) ? r.pick(WIDE) : r.pick(ALPHABET.split('')));
  return chars;
}
/** Byte offset of every char boundary. */
const boundaries = (chars: string[]) => {
  const out = [0];
  for (const c of chars) out.push(out.at(-1)! + bytes(c));
  return out;
};

// 2. Lattice rows.
{
  const r = prng(2);
  const rows: unknown[] = [];
  for (let i = 0; i < 700; i++) {
    const chars = content(r, r.int(8, 60));
    const b = boundaries(chars);
    const cuts = [...new Set(Array.from({ length: r.int(0, 6) * 2 }, () => r.int(0, chars.length)))].sort((x, y) => x - y);
    const expected: any[] = [];
    for (let j = 0; j + 1 < cuts.length; j += 2) {
      if (cuts[j] === cuts[j + 1]) continue;
      expected.push({ start: b[cuts[j]], end: b[cuts[j + 1]], role: r.chance(0.8) ? 'secret' : 'companion' });
    }
    // Envelopes: widen into the free gap on each side.
    expected.forEach((e, k) => {
      if (!r.chance(0.4)) return;
      const lo = k ? expected[k - 1].end : 0, hi = k + 1 < expected.length ? expected[k + 1].start : b.at(-1)!;
      const opts = b.filter(x => x >= lo && x <= e.start), ends = b.filter(x => x >= e.end && x <= hi);
      e.envelope = { start: r.pick(opts), end: r.pick(ends) };
    });
    const actual: any[] = [];
    for (let j = r.int(0, 5); j > 0; j--) {
      let s = r.int(0, chars.length - 1), t = r.int(s + 1, chars.length);
      if (expected.length && r.chance(0.6)) {
        const e = r.pick(expected), src = e.envelope && r.chance(0.5) ? e.envelope : e;
        const si = b.indexOf(src.start), ti = b.indexOf(src.end);
        s = Math.min(chars.length - 1, Math.max(0, si + r.int(-2, 2))); t = Math.min(chars.length, ti + r.int(-2, 2));
        if (t <= s) t = s + 1;
      }
      const a: any = { start: b[s], end: b[t] };
      if (r.chance(0.6)) a.family = r.pick(['fam-a', 'fam-b']);
      if (r.chance(0.3)) a.action = r.pick(['redact', 'warn']);
      actual.push(a);
    }
    const unique = [...new Map(actual.map(a => [`${a.start}:${a.end}`, a])).values()];
    const scope = r.chance(0.3) ? r.pick(['fam-a', 'fam-b']) : undefined;
    const spans = expected.filter(e => e.role === 'secret').map(e => ({ span: e, outcome: lattice.spanOutcome ? undefined : undefined }));
    void spans;
    rows.push({ expected, actual: unique, scope: scope ?? null, out: lattice.scoreRow(expected, unique, scope),
      union: lattice.union(unique), bytesOutside: lattice.bytesOutside(unique, expected.map((e: any) => e.envelope ?? e)) });
  }
  write('lattice.json', { rows });
}

// 3. Bench accounting over random suites.
type Fx = any;
function suite(r: ReturnType<typeof prng>, name: string, families: string[]) {
  const fixtures: Fx[] = [];
  const n = r.int(3, 20);
  for (let i = 0; i < n; i++) {
    const kind = r.pick(['must-redact', 'must-redact', 'must-not-flag', 'must-not-flag', 'policy'] as const);
    const tier = r.chance(0.18) ? 'T0' : r.pick(['T1', 'T2', 'T3']);
    const chars = content(r, r.int(10, 50));
    const b = boundaries(chars);
    const expected: any[] = [];
    if (kind !== 'must-not-flag') {
      const cuts = [...new Set(Array.from({ length: r.int(1, 3) * 2 }, () => r.int(0, chars.length)))].sort((x, y) => x - y);
      for (let j = 0; j + 1 < cuts.length; j += 2) if (cuts[j] !== cuts[j + 1]) expected.push({ start: b[cuts[j]], end: b[cuts[j + 1]], role: 'secret' });
      if (!expected.length) expected.push({ start: b[0], end: b[chars.length], role: 'secret' });
      if (expected.length > 1 && r.chance(0.3)) expected[0].role = 'companion';
      expected.forEach((e, k) => {
        if (!r.chance(0.35)) return;
        const lo = k ? expected[k - 1].end : 0, hi = k + 1 < expected.length ? expected[k + 1].start : b.at(-1)!;
        e.envelope = { start: r.pick(b.filter(x => x >= lo && x <= e.start)), end: r.pick(b.filter(x => x >= e.end && x <= hi)), reason: 'synthetic envelope' };
      });
    }
    const contract = r.chance(0.8) ? r.pick(families) : undefined;
    fixtures.push({ id: `${name}-f${i}`, path: `${name}/f${i}.txt`, content: chars.join(''), expected, group: name,
      assessment: { kind, tier, reason: 'synthetic', sources: [], ...(contract ? { contract } : {}) },
      detectors: contract ? (r.chance(0.3) ? [contract, 'fam-z'].sort() : [contract]) : [] });
  }
  // Twins: controls paired with positives of the suite.
  const positives = fixtures.filter(f => f.expected.some((e: any) => e.role === 'secret'));
  for (const f of fixtures) {
    if (f.assessment.kind !== 'must-not-flag' || !positives.length || !r.chance(0.55)) continue;
    const p = r.pick(positives);
    f.twinOf = p.id; f.mutation = 'synthetic single-property change'; f.mutationKind = r.pick(['length', 'alphabet', 'prefix']);
    if (p.assessment.contract) f.assessment.contract = p.assessment.contract; else delete f.assessment.contract;
    f.detectors = p.detectors;
  }
  scoring.validateCorpus({ fixtures });
  const findings: any[] = [];
  for (const f of fixtures) {
    const chars = [...f.content], b = boundaries(chars);
    for (let j = r.chance(0.25) ? 0 : r.int(1, 4); j > 0; j--) {
      let s = r.int(0, chars.length - 1), t = r.int(s + 1, chars.length);
      if (f.expected.length && r.chance(0.7)) {
        const e = r.pick(f.expected as any[]), src = e.envelope && r.chance(0.5) ? e.envelope : e;
        s = Math.min(chars.length - 1, Math.max(0, b.indexOf(src.start) + r.pick([0, 0, 0, -1, 1, -3]))); t = Math.min(chars.length, b.indexOf(src.end) + r.pick([0, 0, 0, 1, -1, 3]));
        if (t <= s) t = s + 1;
      }
      const finding: any = { path: f.path, start: b[s], end: b[t] };
      if (r.chance(0.7)) finding.family = r.pick([...families, 'fam-other']);
      if (r.chance(0.2)) finding.action = r.pick(['redact', 'warn', 'block']);
      findings.push(finding);
      if (r.chance(0.1)) findings.push({ ...finding, family: r.pick(families) });
    }
  }
  return { fixtures, findings };
}

const CONFIGS = [
  { version: '1.1', minDenominator: 5, resolvedRateFloor: { default: 0.9, differential: 0 }, measurableShareFloor: { default: 0.7, policy: 0 },
    twinCoverageFloor: { default: 0.5, policy: 0 }, replays: 2, intervalZ: 1.96, intervalPrecision: 6 },
  { version: '1.1', minDenominator: 1, resolvedRateFloor: 0.9, measurableShareFloor: 0.5, twinCoverageFloor: 0.2, replays: 2, intervalZ: 1.96, intervalPrecision: 6 },
  { version: '1.1', minDenominator: 2, resolvedRateFloor: 0.5, measurableShareFloor: 0.9, twinCoverageFloor: 0.8, replays: 3, intervalZ: 1.645, intervalPrecision: 3 },
  { version: '1.1', minDenominator: 3, resolvedRateFloor: 0, measurableShareFloor: 0, twinCoverageFloor: 0, replays: 2, intervalZ: 2.576, intervalPrecision: 9 },
];
const attempt = <T>(f: () => T): { ok: T } | { error: string } => { try { return { ok: f() }; } catch (e) { return { error: (e as Error).message }; } };
{
  const r = prng(3);
  const suites: unknown[] = [];
  for (let i = 0; i < 90; i++) {
    const { fixtures, findings } = suite(r, `s${i}`, ['fam-a', 'fam-b']);
    const config = CONFIGS[i % CONFIGS.length];
    const { rows } = scoring.score(fixtures, findings);
    suites.push({ config, fixtures, findings, rows,
      v10: attempt(() => lattice.aggregateGroups(rows)),
      groups: attempt(() => accounting.accountGroups(rows, config)),
      delta: attempt(() => accounting.accountingDelta(rows, config)),
      encoded: rows.map((row: any) => lattice.encodeOutcome(row)) });
  }
  write('accounting.json', { suites });

  // Cross-suite selection (summary.json overall/byDetector) and twin probe.
  const runs: unknown[] = [];
  for (let i = 0; i < 14; i++) {
    const cats = Array.from({ length: r.int(1, 3) }, (_, k) => suite(r, `c${i}x${k}`, ['fam-a', 'fam-b', 'fam-c']));
    const config = CONFIGS[i % CONFIGS.length];
    const reports = cats.map((c, k) => ({ runId: 'oracle', category: `c${i}x${k}`, accountingVersion: '1.1', accounting: config,
      scanners: [{ id: 'sc', name: 'sc', version: '1', mode: 'm', status: 'complete', rows: scoring.score(c.fixtures, c.findings).rows }] }));
    const assignments: Record<string, string[]> = {};
    cats.forEach((c, k) => c.fixtures.forEach((f: Fx) => { if (f.detectors.length && r.chance(0.85)) assignments[`c${i}x${k}--${f.id}`] = f.detectors; }));
    const summary = attempt(() => runSummary.summarizeRun(reports, assignments, 'fixed'));
    runs.push({ config, categories: cats, assignments, summary: 'ok' in summary ? { ok: { overall: (summary.ok as any).overall, byDetector: (summary.ok as any).byDetector } } : summary });
  }
  write('selection.json', { runs });

  const probes: unknown[] = [];
  for (let i = 0; i < 40; i++) {
    const { fixtures, findings } = suite(r, `p${i}`, ['fam-a', 'fam-b', 'fam-c']);
    const rows = r.chance(0.85) ? scoring.score(fixtures, findings).rows : undefined;
    const families = ['fam-a', 'fam-b', 'fam-c', 'fam-d'];
    const unprobeable: Record<string, any> = {};
    for (const fam of families) if (r.chance(0.3)) unprobeable[fam] = { unprobeable: { reason: `no mutable property for ${fam}`, observedAt: '2026-09-20' } };
    const probeFixtures = fixtures.map((f: Fx) => ({ id: f.id, detectors: f.detectors, twinOf: f.twinOf }));
    probes.push({ families, fixtures, findings, rowsPresent: Boolean(rows), unprobeable,
      out: attempt(() => twinProbe.twinProbe(families, probeFixtures, rows, unprobeable)) });
  }
  write('twin-probe.json', { probes });
}

// ---------------------------------------------------------------------------
// 4. Evaluation methods end to end (evaluation-v1): cases → variants →
//    fake scanners → assertions, comparisons, review queue, summaries.
{
  // Synthetic family contracts. `sendgrid-token` and `slack-token` are the two
  // families legacy `structural.remove-segment` hard-codes; their patterns are
  // replaced with synthetic formats so no real credential shape appears.
  const source = { url: 'https://example.invalid/format', observedAt: '2026-09-20', formatVersion: 'synthetic', covers: 'synthetic' };
  const synthetic: Record<string, any> = {
    'sendgrid-token': { tier: 'T1', pattern: '^SYN\\.[a-z]{4}\\.[a-z]{6}$', providerSource: source },
    'slack-token': { tier: 'T1', pattern: '^syn-[0-9]{3}-[0-9]{3}-[a-z]{5}$', providerSource: source },
    'synth-alpha': { tier: 'T2', pattern: '^zq_[A-Za-z0-9]{6,12}$', providerSource: source },
    'synth-upper': { tier: 'T1', pattern: '^[A-Z][a-z0-9]{8,12}$', providerSource: source },
    'synth-free': { tier: 'T2', structural: true, providerSource: source },
  };
  Object.assign(assessment.contracts, synthetic);

  const r = prng(4);
  const VALUES: Record<string, () => string> = {
    'sendgrid-token': () => `SYN.${word(4)}.${word(6)}`,
    'slack-token': () => `syn-${digits(3)}-${digits(3)}-${word(5)}`,
    'synth-alpha': () => `zq_${alnum(r.int(6, 12))}`,
    'synth-upper': () => `${r.pick('BCDEFGHJK'.split(''))}${lowerDigits(r.int(8, 12))}`,
    'synth-free': () => `free${alnum(10)}`,
  };
  function word(n: number) { return Array.from({ length: n }, () => r.pick('abcdefghijklmnopqrstuvwxyz'.split(''))).join(''); }
  function digits(n: number) { return Array.from({ length: n }, () => r.pick('0123456789'.split(''))).join(''); }
  function alnum(n: number) { return Array.from({ length: n }, () => r.pick('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'.split(''))).join(''); }
  function lowerDigits(n: number) { return Array.from({ length: n }, () => r.pick('abcdefghijklmnopqrstuvwxyz0123456789'.split(''))).join(''); }
  const CONTEXTS: [string, string][] = [['token = ', '\n'], ['key: ', ''], ['# café 密钥\nvalue=', '\n'], ['export X=', '\r\nnext\n'], ['', ''], ['"', '"'], ['it\'s ', ' here']];
  const AXIS = ['placeholder', 'near-miss', 'reference', 'ordinary-prose', 'realworld-config'];

  const categories: { id: string; fixtures: Fx[] }[] = [];
  for (let c = 0; c < 3; c++) {
    const cat = `cat${c}`;
    const fixtures: Fx[] = [];
    for (let i = 0; i < 7; i++) {
      const family = r.pick(Object.keys(VALUES));
      const [pre, post] = r.pick(CONTEXTS);
      const value = VALUES[family]();
      const tier = r.chance(0.12) ? 'T0' : synthetic[family].tier;
      const text = pre + value + post;
      const start = bytes(pre), end = start + bytes(value);
      const expected: any[] = [{ start, end, role: 'secret' }];
      if (r.chance(0.3) && pre.length > 2) expected[0].envelope = { start: start - 1, end, reason: 'synthetic envelope' };
      fixtures.push({ id: `pos-${i}`, path: `${cat}/pos-${i}.txt`, content: text, expected, group: cat,
        assessment: { kind: 'must-redact', tier, reason: 'synthetic positive', sources: tier === 'T0' ? [] : ['https://example.invalid'], contract: family },
        detectors: [family] });
    }
    // Authored twins of some positives (one-property and context twins).
    fixtures.filter(f => f.assessment.tier !== 'T0').slice(0, 4).forEach((p, k) => {
      const e = p.expected[0], value = Buffer.from(p.content).subarray(e.start, e.end).toString();
      let text: string, kind: string;
      if (k % 3 === 2) { text = 'note: ' + p.content; kind = 'context'; }
      else { text = Buffer.from(p.content).subarray(0, e.start).toString() + value.slice(0, -1) + '!' + Buffer.from(p.content).subarray(e.end).toString(); kind = 'alphabet'; }
      fixtures.push({ id: `twin-${k}`, path: `${cat}/twin-${k}.txt`, content: text, expected: [], group: cat, twinOf: p.id,
        mutation: 'synthetic single-property change', mutationKind: kind,
        assessment: { kind: 'must-not-flag', tier: 'T1', reason: 'synthetic twin', sources: ['https://example.invalid'], contract: p.assessment.contract },
        detectors: p.detectors });
    });
    // Benign controls.
    for (let i = 0; i < 4; i++) {
      const tier = r.chance(0.2) ? 'T0' : 'T2';
      const family = r.pick(Object.keys(VALUES));
      const text = r.pick([`placeholder ${family} value here\n`, `see docs for SYN.${word(3)}\n`, `zq_short\n`, `plain prose line ${i}`, `quote "x" and 'y'`]);
      fixtures.push({ id: `ctl-${i}`, path: `${cat}/ctl-${i}.txt`, content: text, expected: [], group: cat, axis: tier === 'T0' ? 'pending' : r.pick(AXIS),
        assessment: { kind: 'must-not-flag', tier, reason: 'synthetic control', sources: [] }, detectors: r.chance(0.5) ? [family] : [] });
    }
    scoring.validateCorpus({ fixtures });
    categories.push({ id: cat, fixtures });
  }

  // Case construction: a copy of loadCases (cases.ts:65-99) without file I/O.
  const operators = operatorsIndex.createOperators();
  const methods = methodsIndex.createMethods();
  const cases: any[] = [];
  for (const category of categories) {
    const corpus = { fixtures: category.fixtures };
    const corpusHash = model.hash(corpus);
    for (const f of corpus.fixtures) {
      const base: any = { targets: [...(f.detectors ?? [])], visibility: 'development', source: { category: category.id, fixtureId: f.id, path: `${category.id}.json` },
        seed: f, operators: [], provenance: { source: `${category.id}.json`, sourceHash: model.hash(f), corpusHash, rationale: f.assessment.reason,
          seed: `${category.id}/${f.id}`, reviewStatus: undefined, sources: f.assessment.sources } };
      const add = (method: string, extra: any = {}) => {
        const c = { ...base, id: `${category.id}--${f.id}--${method}`, method, ...extra };
        if (c.seed !== f) c.provenance = { ...c.provenance, sourceHash: model.hash(c.seed) };
        cases.push(c);
      };
      add('differential');
      if (f.twinOf) add('twin', { seed: corpus.fixtures.find(p => p.id === f.twinOf), twin: f, operators: [{ id: 'authored.twin' }] });
      else if (!model.secrets(f).length) add('benign', { taxonomy: f.assessment.tier === 'T0' ? 'pending' : f.axis });
      if (!f.twinOf) {
        const context = operators.values().filter((o: any) => /^(context|encoding)\./.test(o.id));
        add('metamorphic', { operators: context.map((o: any) => ({ id: o.id })) });
        const twin = corpus.fixtures.find(t => t.twinOf === f.id);
        const mutationSeed = { ...base, twin };
        const lex = operators.values().filter((o: any) => /^(lexical|boundary|structural)\./.test(o.id) || (o.id === 'authored.twin' && o.supports(mutationSeed)));
        add('mutation', { twin, operators: lex.map((o: any) => ({ id: o.id })) });
      }
    }
  }

  const { generated } = execution.evaluationInputs(cases, methods, operators);
  const plan = generated.map((g: any) => ({ case: g.case.id, method: g.case.method,
    variants: g.variants.map((v: any) => ({ id: v.id, path: v.fixture.path, content: v.fixture.content, expected: v.fixture.expected,
      kind: v.fixture.assessment.kind, tier: v.fixture.assessment.tier, contract: v.fixture.assessment.contract ?? null,
      strategy: v.strategy, transformation: v.transformation })),
    attempts: g.attempts.map(({ parametersHash: _h, ...a }: any) => a) }));

  // Fake scanners. Offsets are UTF-8 bytes of regex matches.
  const PATTERNS: [RegExp, string][] = [
    [/SYN\.[a-z]{3,5}\.?[a-z]{0,7}/g, 'sendgrid-token'], [/syn-[0-9]{3}-?[0-9]{0,3}-?[a-z]{0,6}/g, 'slack-token'],
    [/zq_[A-Za-z0-9!]{3,13}/g, 'synth-alpha'], [/\b[B-K][a-z0-9]{8,12}\b/g, 'synth-upper'], [/free[A-Za-z0-9]{10}/g, 'synth-free'],
  ];
  const matches = (text: string) => PATTERNS.flatMap(([re, family]) => [...text.matchAll(re)].map(m => ({
    start: bytes(text.slice(0, m.index)), end: bytes(text.slice(0, m.index! + m[0].length)), family })));
  let flaky = 0;
  const scanners = [
    { id: 'redact-secret', mode: 'oracle', configuration: { oracle: 'reference' }, version: async () => '1.0.0',
      scan: async (_d: string, inputs: any[]) => inputs.flatMap(i => matches(i.content).map(m => ({ path: i.path, ...m, action: 'redact' }))) },
    { id: 'peer-wide', mode: 'oracle', configuration: { oracle: 'wide' }, version: async () => '2.0.0',
      scan: async (_d: string, inputs: any[]) => inputs.flatMap(i => matches(i.content).map(m => {
        const buf = Buffer.from(i.content);
        const start = m.start > 0 && buf[m.start - 1] < 0x80 && m.family !== 'synth-alpha' ? m.start - 1 : m.start;
        const family = m.family === 'slack-token' ? 'sendgrid-token' : m.family === 'synth-free' ? undefined : m.family;
        return { path: i.path, start, end: m.end, ...(family ? { family } : {}) };
      })) },
    { id: 'peer-partial', mode: 'oracle', version: async () => '3.0.0',
      scan: async (_d: string, inputs: any[]) => inputs.flatMap(i => matches(i.content).filter(m => m.family !== 'synth-upper')
        .map(m => ({ path: i.path, start: m.start, end: Math.max(m.start + 1, m.end - 2), family: m.family === 'sendgrid-token' ? 'not-a-family' : m.family }))) },
    { id: 'peer-flaky', mode: 'oracle', version: async () => '4.0.0',
      scan: async (_d: string, inputs: any[]) => (flaky++ % 2 ? inputs.slice(0, 3) : inputs).flatMap(i => matches(i.content).map(m => ({ path: i.path, ...m }))) },
    { id: 'peer-missing', mode: 'oracle', version: async () => { throw new Error('unavailable'); }, scan: async () => [] },
    { id: 'peer-norange', mode: 'oracle', capabilities: { ranges: false, classification: true }, version: async () => '5.0.0', scan: async () => [] },
  ];
  let captured: any[] = [];
  const scratch = mkdtempSync(path.join(tmpdir(), 'credential-eval-oracle-'));
  const acct = { ...CONFIGS[0], minDenominator: 2 };
  let report: any;
  try {
    report = await execution.executeEvaluation({ cases, methods, operators, scanners, runId: 'oracle', scratchParent: scratch, accounting: acct,
      captureObservations: async (_f: unknown, observations: any[]) => { captured = structuredClone(observations); } });
  } finally { rmSync(scratch, { recursive: true, force: true }); }
  const observations = captured.map(o => ({ id: o.id, version: o.version, mode: o.mode, configuration: o.configuration, status: o.status,
    ...(o.findings ? { findings: o.findings } : {}), ...(o.replays ? { replays: o.replays } : {}) }));
  const results = report.results.map((c: any) => ({ id: c.id, method: c.method, targets: c.targets, taxonomy: c.taxonomy ?? null,
    variants: c.variants.map((v: any) => ({ id: v.id, kind: v.kind, tier: v.tier, strategy: v.strategy, transformation: { ...v.transformation, parametersHash: undefined } })),
    generation: c.generation.map(({ parametersHash: _h, ...a }: any) => a),
    scanners: c.scanners, comparisons: c.comparisons ?? null, complete: c.complete ?? null,
    observations: c.observations ?? null }));
  const reviewQueue = report.reviewQueue.map(({ id: _id, evidence: _e, ...entry }: any) => entry);
  write('evaluation.json', {
    accounting: acct, contracts: synthetic, categories, cases: cases.map(c => ({ id: c.id, method: c.method, seed: c.provenance.seed })),
    plan, observations, results, reviewQueue,
    summaries: { byMethod: report.byMethod, byDetector: report.byDetector, byTaxonomy: report.byTaxonomy, byOperator: report.byOperator, axesByDetector: report.axesByDetector },
    resolution: report.resolution, unresolvedGroups: report.unresolvedGroups, accountingDelta: report.accountingDelta,
    failures: report.failures.map((f: any) => ({ caseId: f.caseId, scanner: f.scanner, assertion: f.assertion })),
    exitCode: (await legacy('benchmarks/engine/runner.ts')).exitCode(report),
    seededChoices: ['cat0/pos-0', 'cat1/pos-3', 'x', 'é/密'].flatMap(seed => ['lexical.prefix-change', 'boundary.remove-delimiter', 'structural.remove-segment']
      .map(operator => ({ seed, operator, size: 25, out: lexical.seededChoice({ provenance: { seed } }, operator, 25) }))),
  });
}
console.log(`oracle goldens written to ${outDir} (legacy ${commit})`);
