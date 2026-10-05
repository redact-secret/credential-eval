// Runs the audit cases through the installed @openredaction/core (default
// options and categories:["credentials"]) and prints one JSON document with
// only types, ranges and span relations: never a matched value.
// usage: node probe.mjs <package-root> [--check]
// --check compares the result with expected.json and exits 1 on any difference.
import { readFile } from 'node:fs/promises';
import { createRequire } from 'node:module';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(process.argv[2] ?? '.');
const dir = path.join(root, 'node_modules', '@openredaction', 'core');
const pkg = JSON.parse(await readFile(path.join(dir, 'package.json'), 'utf8'));
const require = createRequire(path.join(dir, 'package.json'));
const core = await import(pathToFileURL(require.resolve('@openredaction/core')).href);
const { cases } = JSON.parse(await readFile(path.join(here, 'cases.json'), 'utf8'));
for (const c of cases) if (Array.isArray(c.text)) c.text = c.text.join('');

const profiles = {
  default: {},
  credentials: { categories: ['credentials'] },
  'no-false-positive-filter': { enableFalsePositiveFilter: false },
};
const out = { package: pkg.name, version: pkg.version, profiles: {} };
for (const [name, options] of Object.entries(profiles)) {
  const detector = new core.OpenRedaction(options);
  const rows = [];
  for (const c of cases) {
    const open = c.text.indexOf('⟦');
    const close = c.text.indexOf('⟧');
    const marked = open >= 0 ? [open, close - 1] : null; // UTF-16 offsets after removing both markers
    const text = c.text.replace('⟦', '').replace('⟧', '');
    const found = (await detector.detect(text)).detections.map((d) => ({
      type: d.type,
      start: d.position[0],
      end: d.position[1],
    }));
    const own = found.filter((d) => d.type === c.type);
    const relation = (d) => {
      if (!marked) return 'unmarked';
      const [s, e] = marked;
      if (d.start === s && d.end === e) return 'exact';
      if (d.start <= s && d.end >= e) return 'wider';
      if (d.start >= s && d.end <= e) return 'narrower';
      return d.end <= s || d.start >= e ? 'disjoint' : 'partial';
    };
    rows.push({
      id: c.id,
      type: c.type,
      polarity: c.polarity,
      detected_own: own.length > 0,
      own_span: own.length ? relation(own[0]) : null,
      own_start_offset: own.length && marked ? own[0].start - marked[0] : null,
      own_end_offset: own.length && marked ? own[0].end - marked[1] : null,
      all_types: [...new Set(found.map((d) => d.type))].sort(),
    });
  }
  out.profiles[name] = rows;
}
const text = `${JSON.stringify(out, null, 2)}\n`;
if (process.argv.includes('--check')) {
  const expected = await readFile(path.join(here, 'expected.json'), 'utf8');
  if (expected !== text) {
    process.stderr.write('openredaction audit probe differs from expected.json\n');
    process.exit(1);
  }
  process.stdout.write('openredaction audit probe matches expected.json\n');
} else {
  process.stdout.write(text);
}
