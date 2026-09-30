#!/usr/bin/env node
// Dual-run parity comparator (issue #5; migration-only, delete with the compat layer).
//
// Compares the legacy TypeScript engine's outputs (redact-secret-benchmarks
// @c403475) with credential-eval's outputs rendered through the
// compatibility writer, dimension by dimension, and prints a sanitized
// summary: counts, case/row ids and digests only. It never prints fixture
// content, matched values or raw scanner output.
//
//   node tools/parity/compare.mjs bench <legacy public/results dir> <credential-eval compat dir>
//        [--observations <credential-eval observation set>] [--json <summary.json>]
//   node tools/parity/compare.mjs eval  <legacy evaluation.json> <credential-eval legacy-eval.json>
//        [--observations <credential-eval observation set>] [--snapshot <exported snapshot>]
//        [--json <summary.json>]
//
// Each pipeline is compared with its own rule (legacy-map §1, §6 hazards 5-6):
// bench rows carry unrestricted adapter families; eval rows carry families
// restricted to the contract table. Known, documented nondeterminism is
// classified, never hidden: a difference is `known-nondeterminism` only when
// the rows are equal family-blind and every differing range is one the same
// scanner reported under two or more families in credential-eval's raw
// observation set (--observations), with the legacy family among them. That is
// the gitleaks same-range/different-rule case (docs/adapters.md#determinism),
// where legacy keeps whichever rule gitleaks happened to emit last. Every
// effect of such a range (scores, groups, summaries) is listed by id.
//
// Exit code: 0 when every difference is classified as explained, 1 otherwise.

import { createHash } from 'node:crypto';
import { readFileSync, readdirSync, writeFileSync } from 'node:fs';
import path from 'node:path';

const [mode, legacyPath, oursPath, ...rest] = process.argv.slice(2);
const option = (name) => { const i = rest.indexOf(name); return i >= 0 ? rest[i + 1] : undefined; };
const jsonOut = option('--json');
const observationsPath = option('--observations');
const snapshotPath = option('--snapshot');
if (!['bench', 'eval'].includes(mode) || !legacyPath || !oursPath) {
  console.error('usage: compare.mjs bench|eval <legacy> <ours> [--observations <file>] [--json <summary.json>]');
  process.exit(2);
}
const read = (p) => JSON.parse(readFileSync(p, 'utf8'));

// Ranges a scanner reported under several families: `${scanner}|${path}@${start}:${end}` -> families.
const multiFamily = new Map();
if (observationsPath) {
  for (const o of read(observationsPath).observations) {
    if (o.result.status !== 'complete') continue;
    const seen = new Map();
    for (const f of o.result.findings) {
      const k = `${o.scanner.id}|${f.path}@${f.start}:${f.end}`;
      (seen.get(k) ?? seen.set(k, new Set()).get(k)).add(f.family ?? '');
    }
    for (const [k, families] of seen) if (families.size > 1) multiFamily.set(k, families);
  }
}
const knownRange = (scanner, filePath, f) => multiFamily.get(`${scanner}|${filePath}@${f.start}:${f.end}`)?.has(f.family ?? '') ?? false;

// ---------------------------------------------------------------------------
// Canonical helpers: key-order-free equality and stable digests.
const canonical = (v) => {
  if (Array.isArray(v)) return `[${v.map(canonical).join(',')}]`;
  if (v && typeof v === 'object') {
    const keys = Object.keys(v).filter((k) => v[k] !== undefined).sort();
    return `{${keys.map((k) => `${JSON.stringify(k)}:${canonical(v[k])}`).join(',')}}`;
  }
  return JSON.stringify(v ?? null);
};
const same = (a, b) => canonical(a) === canonical(b);
const digest = (v) => `sha256:${createHash('sha256').update(canonical(v)).digest('hex')}`;
const byRange = (a, b) => a.start - b.start || a.end - b.end || String(a.family ?? '').localeCompare(String(b.family ?? '')) || String(a.action ?? '').localeCompare(String(b.action ?? ''));
const sortActual = (list) => [...(list ?? [])].map(({ start, end, family, action }) => ({ start, end, ...(family !== undefined ? { family } : {}), ...(action !== undefined ? { action } : {}) })).sort(byRange);
const rangesOnly = (list) => sortActual(list).map(({ start, end }) => `${start}:${end}`);
const familyBlind = (list) => sortActual(list).map(({ start, end, action }) => ({ start, end, ...(action !== undefined ? { action } : {}) }));
const multiset = (items) => { const m = new Map(); for (const i of items) m.set(i, (m.get(i) ?? 0) + 1); return m; };
const multisetDiff = (a, b) => {
  const ma = multiset(a), mb = multiset(b), onlyA = [], onlyB = [];
  for (const [k, n] of ma) for (let i = 0; i < n - (mb.get(k) ?? 0); i++) onlyA.push(k);
  for (const [k, n] of mb) for (let i = 0; i < n - (ma.get(k) ?? 0); i++) onlyB.push(k);
  return { onlyA, onlyB };
};

// A dimension tallies compared items and differences; every difference has a
// classification (`unexplained` unless a documented rule explains it).
const dimensions = new Map();
const dim = (name) => {
  if (!dimensions.has(name)) dimensions.set(name, { compared: 0, matched: 0, deltas: {} });
  return dimensions.get(name);
};
const record = (name, equal, id, classification = 'unexplained') => {
  const d = dim(name);
  d.compared++;
  if (equal) { d.matched++; return; }
  (d.deltas[classification] ??= []).push(id);
};

// Row score fields (legacy ScoredRow, lattice.ts:76-97).
const SCORE = ['spanOutcomes', 'leakedBytes', 'collateralBytes', 'flagged', 'findings', 'coDetected', 'actionCounts'];
const scoreOf = (row) => Object.fromEntries(SCORE.filter((k) => row[k] !== undefined).map((k) => [k, row[k]]));
const META = ['path', 'kind', 'tier', 'contract', 'twinOf'];
const metaOf = (row, withGroup) => Object.fromEntries([...META, ...(withGroup ? ['group'] : [])].filter((k) => row[k] !== undefined).map((k) => [k, row[k]]));

/**
 * Compare one legacy row with ours. `known(legacyFinding)` says whether a
 * family-only difference on that range is the documented multi-family case.
 */
function compareRow(prefix, id, legacy, ours, { withGroup, known = () => false }) {
  record(`${prefix}.row-metadata`, same(metaOf(legacy, withGroup), metaOf(ours, withGroup)), id);
  record(`${prefix}.expected`, same(legacy.expected, ours.expected), id);
  const la = sortActual(legacy.actual), oa = sortActual(ours.actual);
  record(`${prefix}.byte-ranges`, same(rangesOnly(la), rangesOnly(oa)), id);
  const findingsEqual = same(la, oa);
  const explained = !findingsEqual && same(familyBlind(la), familyBlind(oa))
    && la.every((f, i) => same(f, oa[i]) || (known(f) && known(oa[i])));
  const cls = explained ? 'known-nondeterminism' : 'unexplained';
  record(`${prefix}.findings`, findingsEqual, id, cls);
  record(`${prefix}.outcome-lattice`, same(scoreOf(legacy), scoreOf(ours)), id, cls);
  return { findingsEqual, known: explained };
}

// ---------------------------------------------------------------------------
function bench() {
  const categories = readdirSync(legacyPath).filter((f) => f.endsWith('.json') && !['summary.json', 'run.json'].includes(f) && !f.startsWith('.')).sort();
  const oursFiles = new Set(readdirSync(oursPath).filter((f) => f.endsWith('.json')));
  const knownFamilyRanges = new Set();
  const affected = new Map(); // `${category}/${scanner}` -> row ids with a known family-only difference
  let rows = 0;
  for (const file of categories) {
    const category = file.slice(0, -5);
    const legacy = read(path.join(legacyPath, file));
    record('bench.categories', oursFiles.has(file), category);
    if (!oursFiles.has(file)) continue;
    const ours = read(path.join(oursPath, file));
    record('bench.corpus-identity', legacy.corpusHash === ours.corpusHash && legacy.fixtureCount === ours.fixtureCount && legacy.expectedCount === ours.expectedCount, category);
    const oursById = new Map(ours.scanners.map((s) => [s.id, s]));
    for (const ls of legacy.scanners) {
      const os = oursById.get(ls.id);
      const key = `${category}/${ls.id}`;
      record('bench.scanner-status', os && ls.status === os.status && ls.version === os.version && same(ls.replays ?? null, os.replays ?? null), key);
      if (!os || ls.status !== 'complete' || os.status !== 'complete') continue;
      const oursRows = new Map(os.rows.map((r) => [r.id, r]));
      record('bench.row-set', same(ls.rows.map((r) => r.id).sort(), os.rows.map((r) => r.id).sort()), key);
      let knownHere = false;
      for (const lr of ls.rows) {
        const or = oursRows.get(lr.id);
        if (!or) continue;
        rows++;
        const id = `${category}--${lr.id}/${ls.id}`;
        const r = compareRow('bench', id, lr, or, { withGroup: true, known: (f) => knownRange(ls.id, `${category}/${lr.path}`, f) });
        if (r.known) {
          knownHere = true;
          (affected.get(key) ?? affected.set(key, []).get(key)).push(lr.id);
          for (const f of sortActual(lr.actual)) if (knownRange(ls.id, `${category}/${lr.path}`, f)) knownFamilyRanges.add(`${category}--${lr.id}@${f.start}:${f.end}`);
        }
      }
      // Group accounting: an explained row difference may move its group figures.
      record('bench.group-accounting', same(ls.groups, os.groups), key, knownHere ? 'known-nondeterminism' : 'unexplained');
      record('bench.accounting-delta', same(ls.accountingDelta, os.accountingDelta), key, knownHere ? 'known-nondeterminism' : 'unexplained');
    }
  }
  // summary.json (cross-suite selection groups).
  const ls = read(path.join(legacyPath, 'summary.json')), os = read(path.join(oursPath, 'summary.json'));
  const knownScanners = new Set([...affected.keys()].map((k) => k.split('/')[1]));
  for (const scanner of Object.keys(ls.overall)) record('bench.summary-overall', same(ls.overall[scanner], os.overall?.[scanner]), scanner, knownScanners.has(scanner) ? 'known-nondeterminism' : 'unexplained');
  for (const detector of Object.keys(ls.byDetector))
    for (const scanner of new Set([...Object.keys(ls.byDetector[detector]), ...Object.keys(os.byDetector?.[detector] ?? {})]))
      record('bench.summary-by-detector', same(ls.byDetector[detector][scanner], os.byDetector?.[detector]?.[scanner]), `${detector}/${scanner}`, knownScanners.has(scanner) ? 'known-nondeterminism' : 'unexplained');
  return { rows, knownFamilyRanges: [...knownFamilyRanges].sort(), affectedRows: Object.fromEntries([...affected].sort()) };
}

// ---------------------------------------------------------------------------
function evaluation() {
  const legacy = read(legacyPath), ours = read(oursPath);
  // Kernel delta O2 (docs/migration/kernel-deltas.md): a mutation case attaches
  // the first twin of its seed by case id, legacy the first in corpus order.
  // They differ only for seeds with several authored twins, listed here from
  // the exported snapshot; everything their `authored.twin` variant touches is
  // classified `O2-first-twin`, and must match once it is set aside.
  const twins = new Map();
  if (snapshotPath) for (const c of read(snapshotPath).cases) if (c.twin) twins.set(c.twin.twin_of, (twins.get(c.twin.twin_of) ?? 0) + 1);
  const o2Case = (caseId) => caseId.endsWith('--mutation') && (twins.get(caseId.slice(0, -'--mutation'.length)) ?? 0) > 1;
  const O2 = 'O2-first-twin';
  const twinVariant = (a) => a.variant === 'authored.twin' || a.candidate === 'authored.twin';
  const o2Assertion = (caseId, a) => o2Case(caseId) && twinVariant(a);

  const statusOf = (list) => Object.fromEntries(list.map((s) => [s.id, { version: s.version ?? null, status: s.status }]));
  record('eval.scanner-status', same(statusOf(legacy.scanners), statusOf(ours.scanners)), 'scanners');
  record('eval.counts', legacy.caseCount === ours.caseCount && legacy.variantCount === ours.variantCount, 'caseCount/variantCount');
  const oursCases = new Map(ours.results.map((r) => [r.id, r]));
  record('eval.case-set', same(legacy.results.map((r) => r.id).sort(), ours.results.map((r) => r.id).sort()), 'cases');
  const clean = (o) => Object.fromEntries(Object.entries(o).filter(([, v]) => v !== null && v !== undefined));
  const transformation = (t) => { const { parametersHash: _h, ...rest } = t; return clean(rest); };
  const variantView = (v) => ({ id: v.id, path: v.path, strategy: v.strategy, kind: v.kind, tier: v.tier, transformation: transformation(v.transformation) });
  const attemptView = (a) => { const { parametersHash: _h, ...rest } = a; return clean(rest); };
  const assertionView = (a) => clean(a);
  // Compare lists; when they differ, set aside the O2 items and compare again.
  const compareList = (name, id, o2, l, o, keep) => {
    if (same(l, o)) return record(name, true, id);
    record(name, false, id, o2 && same(l.filter(keep), o.filter(keep)) ? O2 : 'unexplained');
  };
  let variantRows = 0;
  for (const lr of legacy.results) {
    const or = oursCases.get(lr.id);
    if (!or) continue;
    const m = lr.method, o2 = o2Case(lr.id);
    record(`eval.${m}.case-metadata`, same({ method: lr.method, targets: [...lr.targets].sort(), taxonomy: lr.taxonomy ?? null }, { method: or.method, targets: [...or.targets].sort(), taxonomy: or.taxonomy ?? null }), lr.id);
    compareList(`eval.${m}.variants`, lr.id, o2, lr.variants.map(variantView), or.variants.map(variantView), (v) => v.id !== 'authored.twin');
    compareList(`eval.${m}.generation`, lr.id, o2, lr.generation.map(attemptView), or.generation.map(attemptView), (a) => a.operator !== 'authored.twin');
    const oursScanners = new Map(or.scanners.map((s) => [s.scanner, s]));
    for (const ls of lr.scanners) {
      const os = oursScanners.get(ls.scanner);
      const key = `${lr.id}/${ls.scanner}`;
      record(`eval.${m}.scanner-status`, os && ls.status === os.status, key);
      if (!os) continue;
      compareList(`eval.${m}.assertions`, key, o2, ls.assertions.map(assertionView), os.assertions.map(assertionView), (a) => !twinVariant(a));
      const oursRows = new Map(os.variants.map((v) => [v.id, v.row]));
      for (const v of ls.variants) {
        variantRows++;
        const orow = oursRows.get(v.id);
        const id = `${key}/${v.id}`;
        if (o2 && v.id === 'authored.twin') {
          // A different authored twin: different fixture, so every row field may differ.
          record('eval.variant-rows.twin-choice', same(v.row, orow), id, O2);
          continue;
        }
        if (!orow) { record('eval.variant-rows.presence', false, id); continue; }
        compareRow('eval.variant-rows', id, v.row, orow, { withGroup: false, known: (f) => knownRange(ls.scanner, v.row.path, f) });
      }
    }
    if (lr.method === 'differential') {
      const cmp = (list) => (list ?? []).map((c) => canonical({ variant: c.variant, peer: c.peer, status: c.status, disagreement: c.disagreement ?? null, classification: c.classification ?? null, reason: c.reason ?? null })).sort();
      record('eval.differential.comparisons', same(cmp(lr.comparisons), cmp(or.comparisons)), lr.id);
      record('eval.differential.complete', lr.complete === or.complete, lr.id);
      const obs = (list) => (list ?? []).map((o) => ({ scanner: o.scanner, status: o.status, variants: o.variants.map((v) => ({ id: v.id, actual: sortActual(v.actual), classifications: v.classifications })) })).sort((a, b) => a.scanner.localeCompare(b.scanner));
      // The per-scanner `actual` keeps the last duplicate's family; on a
      // multi-family range that is emission order (known nondeterminism).
      // Classifications keep every family and must match exactly.
      const blind = (list) => obs(list).map((o) => ({ ...o, variants: o.variants.map((v) => ({ ...v,
        actual: v.actual.map((f) => (knownRange(o.scanner, `cases/${lr.id}/${v.id}.txt`, f) ? { start: f.start, end: f.end, ...(f.action !== undefined ? { action: f.action } : {}) } : f)) })) }));
      const equal = same(obs(lr.observations), obs(or.observations));
      record('eval.differential.observations', equal, lr.id,
        !equal && same(blind(lr.observations), blind(or.observations)) ? 'known-nondeterminism' : 'unexplained');
    }
  }

  // Summaries (reporting.ts:26-66), recomputed from each side's own results:
  // once with every assertion (must equal what that side published), and once
  // without the O2 assertions (must agree between the sides).
  const summarize = (results, drop) => {
    const byMethod = {}, byDetector = {}, byTaxonomy = {}, byOperator = {}, axisSets = {};
    const add = (dest, key, status) => { const row = (dest[key] ??= { pass: 0, fail: 0, 'review-required': 0, 'not-measured': 0 }); row[status]++; };
    for (const r of results) {
      const targets = r.targets.length ? r.targets : ['unassigned'];
      if (r.method === 'benign' && r.taxonomy) for (const t of targets) (axisSets[t] ??= new Set()).add(r.taxonomy);
      for (const a of r.generation) { const row = (byOperator[a.operator] ??= { generated: 0, unsupported: 0, error: 0, assertions: {} }); row[a.status]++; }
      const variants = new Map(r.variants.map((v) => [v.id, v]));
      const stratum = (id) => `${variants.get(id).kind}:${variants.get(id).tier}`;
      for (const s of r.scanners) for (const a of s.assertions) {
        if (drop && drop(r.id, a)) continue;
        const group = a.variant ? stratum(a.variant) : `${stratum(a.baseline)}->${stratum(a.candidate)}`;
        const key = `${r.method}/${s.scanner}/${group}/${a.type}`;
        add(byMethod, key, a.status);
        const op = variants.get(a.variant ?? a.candidate)?.transformation.operator;
        if (op && byOperator[op]) add((byOperator[op].assertions), key, a.status);
        if (r.taxonomy) add((byTaxonomy[r.taxonomy] ??= {}), key, a.status);
        for (const t of targets) add((byDetector[t] ??= {}), key, a.status);
      }
    }
    const axesByDetector = Object.fromEntries(Object.entries(axisSets).map(([t, axes]) => [t, [...axes].sort()]));
    return { byMethod, byDetector, byTaxonomy, byOperator, axesByDetector };
  };
  const SUMMARIES = ['byMethod', 'byDetector', 'byTaxonomy', 'byOperator', 'axesByDetector'];
  const fullL = summarize(legacy.results), fullO = summarize(ours.results);
  for (const s of SUMMARIES) {
    record('eval.summaries.self-consistency', same(fullL[s], legacy[s]), `legacy/${s}`);
    record('eval.summaries.self-consistency', same(fullO[s], ours[s]), `ours/${s}`);
  }
  const setL = summarize(legacy.results, o2Assertion), setO = summarize(ours.results, o2Assertion);
  const o2Keys = new Set();
  for (const s of SUMMARIES) {
    for (const k of new Set([...Object.keys(legacy[s]), ...Object.keys(ours[s])])) {
      const equal = same(legacy[s][k], ours[s][k]);
      const explained = !equal && same(setL[s][k], setO[s][k]);
      if (explained && s === 'byMethod') o2Keys.add(k);
      record(`eval.summaries.${s}`, equal, k, explained ? O2 : 'unexplained');
    }
  }
  // Resolution, unresolved strata and the assertion delta are pure functions
  // of byMethod; a difference is O2 only when its byMethod rows are.
  for (const k of new Set([...Object.keys(legacy.resolution), ...Object.keys(ours.resolution)]))
    record('eval.resolution', same(legacy.resolution[k], ours.resolution[k]), k, o2Keys.has(k) ? O2 : 'unexplained');
  const ul = new Set(legacy.unresolvedGroups), uo = new Set(ours.unresolvedGroups);
  for (const g of new Set([...ul, ...uo])) {
    const o2 = [...o2Keys].some((k) => k.startsWith(g.endsWith('/*') ? g.slice(0, -1) : `${g}/`));
    record('eval.unresolved-groups', ul.has(g) === uo.has(g), g, o2 ? O2 : 'unexplained');
  }
  const deltaGroup = (k) => k.split('/')[2].split('->')[0].replace(':', '/');
  for (const g of new Set([...Object.keys(legacy.accountingDelta.groups), ...Object.keys(ours.accountingDelta.groups)])) {
    const o2 = [...o2Keys].some((k) => deltaGroup(k) === g);
    record('eval.accounting-delta', same(legacy.accountingDelta.groups[g], ours.accountingDelta.groups[g]), g, o2 ? O2 : 'unexplained');
  }
  const failure = (f) => canonical({ caseId: f.caseId, scanner: f.scanner, assertion: assertionView(f.assertion) });
  const fd = multisetDiff(legacy.failures.map(failure), ours.failures.map(failure));
  for (const [side, list] of [['legacy-only', fd.onlyA], ['ours-only', fd.onlyB]])
    for (const item of list) { const f = JSON.parse(item); record('eval.failures', false, `${side}:${f.caseId}/${f.scanner}`, o2Assertion(f.caseId, f.assertion) ? O2 : 'unexplained'); }
  for (let i = 0; i < legacy.failures.length - fd.onlyA.length; i++) record('eval.failures', true, '');
  const genErr = (g) => canonical({ caseId: g.caseId, operator: g.operator });
  const gd = multisetDiff(legacy.generationErrors.map(genErr), ours.generationErrors.map(genErr));
  record('eval.generation-errors', !gd.onlyA.length && !gd.onlyB.length, `${legacy.generationErrors.length} vs ${ours.generationErrors.length}`);
  // Review queue by membership (kernel-deltas H1): ids hash legacy fixture objects.
  const sortMap = (m) => (m ? Object.fromEntries(Object.entries(m).sort(([a], [b]) => a.localeCompare(b))) : null);
  const member = (e) => canonical({ caseId: e.caseId, method: e.method, targets: [...e.targets].sort(), variant: e.variant, peer: e.peer ?? null, disagreement: e.disagreement ?? null,
    observations: sortMap(e.observations), classifications: sortMap(e.classifications), reason: e.reason ?? null });
  const qd = multisetDiff(legacy.reviewQueue.map(member), ours.reviewQueue.map(member));
  for (const [side, list] of [['legacy-only', qd.onlyA], ['ours-only', qd.onlyB]])
    for (const item of list) { const e = JSON.parse(item); record('eval.review-queue', false, `${side}:${e.caseId}/${e.variant}/${e.peer ?? 'pending'}`); }
  for (let i = 0; i < legacy.reviewQueue.length - qd.onlyA.length; i++) record('eval.review-queue', true, '');
  return { variantRows, o2Cases: [...new Set(legacy.results.map((r) => r.id).filter(o2Case))].length, reviewQueue: { legacy: legacy.reviewQueue.length, ours: ours.reviewQueue.length } };
}

const extra = mode === 'bench' ? bench() : evaluation();
const report = {};
let unexplained = 0;
for (const [name, d] of [...dimensions].sort(([a], [b]) => a.localeCompare(b))) {
  const deltas = Object.fromEntries(Object.entries(d.deltas).map(([k, ids]) => [k, { count: ids.length, ids: ids.slice(0, 1000) }]));
  unexplained += d.deltas.unexplained?.length ?? 0;
  report[name] = { compared: d.compared, matched: d.matched, deltas };
  const note = Object.entries(d.deltas).map(([k, ids]) => `${k} ${ids.length}`).join(', ');
  console.log(`${name.padEnd(44)} ${String(d.matched).padStart(7)} / ${String(d.compared).padEnd(7)} ${note}`);
}
const summary = { mode, legacyDigest: digest(read(mode === 'eval' ? legacyPath : path.join(legacyPath, 'summary.json'))), dimensions: report, ...extra, unexplained };
console.log(`unexplained differences: ${unexplained}`);
if (jsonOut) writeFileSync(jsonOut, JSON.stringify(summary, null, 2) + '\n');
process.exitCode = unexplained ? 1 : 0;
