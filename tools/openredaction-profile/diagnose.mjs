// Bounded diagnostics driver: one worker process per measurement, a timeout on
// each, strictly serial. usage:
//   node diagnose.mjs <package-root> <dispositions.json> <profiles> <cases> <KiB,...> <repeats> [timeoutSeconds]
import { spawnSync } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const [root, dispositions, profiles, cases, sizes, repeats, timeout = '120'] = process.argv.slice(2);
const rows = [];
for (const c of cases.split(',')) for (const kib of sizes.split(',')) for (const p of profiles.split(',')) {
  for (let n = 0; n < Number(repeats); n++) {
    const run = spawnSync('node', [path.join(here, 'worker.mjs'), root, p, c, kib, dispositions],
      { encoding: 'utf8', timeout: Number(timeout) * 1000, maxBuffer: 1 << 20 });
    if (run.status === 0) rows.push({ ...JSON.parse(run.stdout), trial: n });
    else rows.push({ profile: p, case: c, kib: Number(kib), trial: n, failed: run.error?.code === 'ETIMEDOUT' ? `timeout ${timeout}s` : `exit ${run.status}` });
  }
}
process.stdout.write(`${JSON.stringify(rows)}\n`);
