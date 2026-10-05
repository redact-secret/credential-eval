// One measured detect() in a fresh process, so peak RSS belongs to it alone.
// usage: node worker.mjs <package-root> <profile> <case> <KiB> [dispositions.json]
// Prints one JSON line: sizes, time, finding counts and peak RSS. Never prints
// a matched value.
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { CASES } from './inputs.mjs';

const [root, profile, caseName, kib, dispositionsPath] = process.argv.slice(2);
const dir = path.join(path.resolve(root), 'node_modules', '@openredaction', 'core');
const require = createRequire(path.join(dir, 'package.json'));
const core = await import(pathToFileURL(require.resolve('@openredaction/core')).href);

const mapped = () => JSON.parse(readFileSync(dispositionsPath, 'utf8')).types
  .filter((t) => t.status === 'mapped').map((t) => t.type);
const PROFILES = {
  default: () => ({}),
  credentials: () => ({ categories: ['credentials'] }),
  'mapped-allowlist': () => ({ patterns: mapped() }),
};
const options = PROFILES[profile]();
const text = CASES[caseName](Number(kib) * 1024);
const detector = new core.OpenRedaction(options);

const started = performance.now();
const { detections } = await detector.detect(text);
const ms = performance.now() - started;
// A second call in the same process: the cost once the engine is warm (the
// cache is off by default, so the identical input is scanned again).
const again = performance.now();
await detector.detect(text);
const warmMs = performance.now() - again;

const byType = {};
for (const d of detections) byType[d.type] = (byType[d.type] ?? 0) + 1;
console.log(JSON.stringify({
  profile, case: caseName, bytes: Buffer.byteLength(text), patterns: detector.getPatterns().length,
  ms: Math.round(ms), warm_ms: Math.round(warmMs), findings: detections.length, types: Object.keys(byType).length, byType,
  maxRssKiB: process.resourceUsage().maxRSS,
}));
