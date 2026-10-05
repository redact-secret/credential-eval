// CPU attribution of one detect() over a diagnostic input, from a V8 CPU
// profile of a fresh process. Prints self-time shares per function name, so
// confirmed code behavior (reading the package) can be separated from measured
// time. usage: node attribute.mjs <package-root> <dispositions.json> <profile> <case> <KiB>
import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, readdirSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const [root, dispositions, profile, caseName, kib] = process.argv.slice(2);
const out = mkdtempSync(path.join(tmpdir(), 'oraudit-'));
const run = spawnSync('node', ['--cpu-prof', `--cpu-prof-dir=${out}`, '--cpu-prof-interval=500',
  path.join(here, 'worker.mjs'), root, profile, caseName, kib, dispositions], { encoding: 'utf8', timeout: 300000 });
if (run.status !== 0) { process.stderr.write('worker failed: ' + (run.error?.message ?? run.stderr.slice(0, 300)) + '\n'); process.exit(1); }
const file = readdirSync(out).find((f) => f.endsWith('.cpuprofile'));
const prof = JSON.parse(readFileSync(path.join(out, file), 'utf8'));
rmSync(out, { recursive: true, force: true });

const byId = new Map(prof.nodes.map((n) => [n.id, n]));
const self = new Map();
const dt = prof.timeDeltas;
prof.samples.forEach((id, i) => self.set(id, (self.get(id) ?? 0) + (dt[i] ?? 0)));
const total = [...self.values()].reduce((a, b) => a + b, 0);
const byName = new Map();
for (const [id, t] of self) {
  const f = byId.get(id).callFrame;
  const key = `${f.functionName || '(anonymous)'} ${path.basename(f.url || '')}`.trim();
  byName.set(key, (byName.get(key) ?? 0) + t);
}
const top = [...byName].sort((a, b) => b[1] - a[1]).slice(0, 12)
  .map(([name, t]) => ({ name, share: Math.round((t / total) * 1000) / 10 }));
console.log(JSON.stringify({ profile, case: caseName, kib: Number(kib), total_ms: Math.round(total / 1000), top }, null, 1));
