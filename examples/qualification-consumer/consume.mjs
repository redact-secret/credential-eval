#!/usr/bin/env node
// Reference qualification consumer (issue #6).
//
// Reads a credential-eval run artifact, validates it against the published
// JSON Schema, projects it into the family view and applies an ILLUSTRATIVE
// TOY POLICY. It imports nothing from credential-eval except the schema file:
// the artifact is the whole interface.
//
//   node examples/qualification-consumer/consume.mjs \
//     --artifact tests/fixtures/contracts-smoke/expected-run-artifact.json \
//     [--schema schemas/run-artifact-v1.schema.json] \
//     [--policy examples/qualification-consumer/toy-policy.json]
//
// Writes the report to stdout. Exit code 2 means the input was rejected.

import { createHash } from 'node:crypto';
import { readFileSync, statSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { validate } from './validate.mjs';
import { familyView } from './family-view.mjs';
import { applyToyPolicy, validatePolicy } from './toy-policy.mjs';

const here = path.dirname(fileURLToPath(import.meta.url));
const repository = path.resolve(here, '../..');
export const ARTIFACT_SCHEMA_TAG = 'credential-eval/run-artifact/v1';
// Bounded input: the reference consumer refuses anything larger than this.
const MAX_INPUT_BYTES = 256 * 1024 * 1024;

const sha256 = bytes => `sha256:${createHash('sha256').update(bytes).digest('hex')}`;

function readBounded(file) {
  if (statSync(file).size > MAX_INPUT_BYTES) throw new Error(`${path.basename(file)} exceeds ${MAX_INPUT_BYTES} bytes`);
  return readFileSync(file);
}

/**
 * Build the toy report from raw bytes. Pure apart from its inputs, so repeated
 * runs over the same bytes produce byte-identical output.
 */
export function buildReport({ artifactBytes, schema, policyBytes }) {
  const artifact = JSON.parse(artifactBytes.toString('utf8'));
  if (artifact?.schema !== ARTIFACT_SCHEMA_TAG) throw new Error(`Unsupported artifact schema tag; expected ${ARTIFACT_SCHEMA_TAG}`);
  const errors = validate(schema, artifact);
  if (errors.length) throw new Error(`Artifact does not match ${schema.$id}:\n  ${errors.join('\n  ')}`);
  const policy = validatePolicy(JSON.parse(policyBytes.toString('utf8')));
  const view = familyView(artifact);
  return {
    report: 'toy-qualification-report',
    notice: policy.notice,
    policy: { id: policy.policy, version: policy.version, digest: sha256(policyBytes) },
    input: {
      artifact_digest: sha256(artifactBytes),
      artifact_schema: artifact.schema,
      engine: artifact.manifest.engine,
      protocol_version: artifact.manifest.protocol_version,
      evidence: artifact.manifest.evidence,
      config_hash: artifact.manifest.config_hash,
      scanners: artifact.manifest.scanners,
    },
    family_view: view,
    verdicts: applyToyPolicy(view, policy),
  };
}

function parseArgs(argv) {
  const options = {
    schema: path.join(repository, 'schemas/run-artifact-v1.schema.json'),
    policy: path.join(here, 'toy-policy.json'),
  };
  for (let i = 0; i < argv.length; i += 2) {
    const key = /^--(artifact|schema|policy)$/.exec(argv[i] ?? '')?.[1];
    if (!key || argv[i + 1] === undefined) throw new Error('Usage: consume.mjs --artifact <run-artifact.json> [--schema <schema.json>] [--policy <policy.json>]');
    options[key] = path.resolve(argv[i + 1]);
  }
  if (!options.artifact) throw new Error('Usage: consume.mjs --artifact <run-artifact.json> [--schema <schema.json>] [--policy <policy.json>]');
  return options;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    const options = parseArgs(process.argv.slice(2));
    const report = buildReport({
      artifactBytes: readBounded(options.artifact),
      schema: JSON.parse(readBounded(options.schema).toString('utf8')),
      policyBytes: readBounded(options.policy),
    });
    process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
  } catch (error) {
    console.error(error instanceof Error ? error.message : String(error));
    process.exitCode = 2;
  }
}
