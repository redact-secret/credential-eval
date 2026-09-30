// node --test examples/qualification-consumer/
//
// These tests pin behaviour that depends only on per-case measurements in the
// smoke artifact, not on its exact bytes, so kernel work that fills other
// sections (aggregates, assertions, ...) does not break them.

import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { buildReport } from './consume.mjs';
import { validate } from './validate.mjs';
import { familyView } from './family-view.mjs';
import { applyToyPolicy, LABELS } from './toy-policy.mjs';

const here = path.dirname(fileURLToPath(import.meta.url));
const repository = path.resolve(here, '../..');
const artifactBytes = readFileSync(path.join(repository, 'tests/fixtures/contracts-smoke/expected-run-artifact.json'));
const schema = JSON.parse(readFileSync(path.join(repository, 'schemas/run-artifact-v1.schema.json'), 'utf8'));
const policyBytes = readFileSync(path.join(here, 'toy-policy.json'));
const artifact = () => JSON.parse(artifactBytes.toString('utf8'));
const policy = () => JSON.parse(policyBytes.toString('utf8'));
const verdict = (verdicts, scanner, family) => verdicts.find(v => v.scanner === scanner && v.family === family);

test('the smoke artifact validates against the published schema', () => {
  assert.deepEqual(validate(schema, artifact()), []);
});

test('the validator rejects contract violations', () => {
  const cases = [
    ['unknown top-level field', a => { a.support_status = 'stable'; }],
    ['wrong schema tag', a => { a.schema = 'credential-eval/run-artifact/v2'; }],
    ['unknown measurement type', a => { a.scanners[0].cases[0].measurement = { type: 'stable' }; }],
    ['negative byte count', a => { a.scanners[0].cases[2].measurement.leaked_bytes = -1; }],
    ['unknown outcome', a => { a.scanners[0].cases[2].measurement.span_outcomes = ['GOOD']; }],
    ['unsafe fixture path', a => { a.scanners[0].cases[0].path = '../escape.txt'; }],
    ['missing manifest', a => { delete a.manifest; }],
  ];
  for (const [name, mutate] of cases) {
    const value = artifact();
    mutate(value);
    assert.notDeepEqual(validate(schema, value), [], name);
  }
});

test('buildReport refuses an artifact that fails validation', () => {
  const broken = artifact();
  broken.scanners[0].cases[0].measurement = { type: 'stable' };
  assert.throws(() => buildReport({ artifactBytes: Buffer.from(JSON.stringify(broken)), schema, policyBytes }), /does not match/);
});

test('the report is deterministic across repeated runs', () => {
  const first = JSON.stringify(buildReport({ artifactBytes, schema, policyBytes }));
  const second = JSON.stringify(buildReport({ artifactBytes, schema, policyBytes }));
  assert.equal(first, second);
});

test('the family view counts engine measurements without re-scoring', () => {
  const view = familyView(artifact());
  const a = view.scanners.find(s => s.scanner === 'fake-scanner-a');
  const apiKey = a.families.find(f => f.family === 'example-api-key');
  assert.deepEqual(apiKey.positives['must-redact'].outcomes, { EXACT: 1, COVERED: 0, OVERBROAD: 1, PARTIAL: 1, MISS: 0 });
  assert.equal(apiKey.positives['must-redact'].leaked_spans, 1);
  assert.equal(apiKey.pending, 1);
  assert.deepEqual(apiKey.benign, { cases: 1, flagged: 1, findings: 1 });
  assert.deepEqual(apiKey.twins, { pairs: 1, discriminated: 1, flagged: 0, co_detected: 1 });
  assert.deepEqual(a.families.map(f => f.family), ['example-api-key', 'example-bearer-token', 'example-key-pair']);
});

test('a scanner that did not complete is not measured, never a miss', () => {
  const view = familyView(artifact());
  const b = view.scanners.find(s => s.scanner === 'fake-scanner-b');
  assert.equal(b.status, 'timeout');
  for (const family of b.families) {
    assert.equal(family.not_measured, family.cases);
    assert.equal(family.positives['must-redact'].outcomes.MISS, 0);
  }
  for (const v of applyToyPolicy(view, policy()).filter(v => v.scanner === 'fake-scanner-b')) assert.equal(v.label, LABELS.notMeasured);
});

test('changing the policy file changes verdicts, not the engine output', () => {
  const view = familyView(artifact());
  const before = JSON.stringify(view);
  const strict = applyToyPolicy(view, policy());
  assert.equal(verdict(strict, 'fake-scanner-a', 'example-api-key').label, LABELS.below);
  assert.equal(verdict(strict, 'fake-scanner-a', 'example-bearer-token').label, LABELS.meets);
  assert.equal(verdict(strict, 'fake-scanner-a', 'example-key-pair').label, LABELS.below);

  // A different consumer tolerates overbroad and partial spans and one false alarm.
  const lenient = { ...policy(), acceptableOutcomes: ['EXACT', 'COVERED', 'OVERBROAD', 'PARTIAL'], maximumBenignFalseAlarms: 1 };
  const relaxed = applyToyPolicy(view, lenient);
  assert.equal(verdict(relaxed, 'fake-scanner-a', 'example-api-key').label, LABELS.meets);
  assert.equal(verdict(relaxed, 'fake-scanner-a', 'example-key-pair').label, LABELS.below);

  // Or requires twin evidence the bearer-token family does not have.
  const twinHungry = { ...policy(), minimumTwinPairs: 1 };
  assert.equal(verdict(applyToyPolicy(view, twinHungry), 'fake-scanner-a', 'example-bearer-token').label, LABELS.below);

  assert.equal(JSON.stringify(view), before, 'policy must not mutate the view');
});

test('a policy file without the non-product notice is refused', () => {
  const unlabelled = { ...policy(), notice: 'Official support policy' };
  assert.throws(() => applyToyPolicy(familyView(artifact()), unlabelled), /not the Redact Secret support policy/);
});
