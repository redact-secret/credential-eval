// credential-eval Node shim: runs one npm-published scanner through its public
// API and reports finding positions only. It never prints matched values.
//
// Usage (spawned by credential-eval-adapters without a shell):
//   node shim.mjs version <scanner> <package-root>
//   node shim.mjs scan    <scanner> <package-root>   (request JSON on stdin)
//
// `scan` reads {"root": <dir>, "paths": [<relative path>...], "options": {...}}
// from stdin, reads each file as UTF-8 exactly as the legacy adapters did
// (redact-secret-benchmarks scanners/index.mjs), and writes one JSON line per
// finding: {"path", "start", "end", "label", "type"?, "action"?}, where start
// and end are the scanner's native UTF-16 code-unit offsets. The Rust adapter
// converts them to UTF-8 byte ranges and maps labels to families. A final
// line {"done": true, "findings": n} marks complete output.
//
// Exit codes: 0 ok; 2 usage; 3 package not installed (unavailable); 1 other.
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

const PACKAGES = {
  'redact-secret': '@redact-secret/core',
  'flare-redact': 'flare-redact',
  openredaction: '@openredaction/core',
};

class Unavailable extends Error {}

function pick(target) {
  if (typeof target === 'string') return target;
  if (target && typeof target === 'object') {
    for (const condition of ['import', 'node', 'default']) {
      if (Object.hasOwn(target, condition)) {
        const found = pick(target[condition]);
        if (found) return found;
      }
    }
  }
  return undefined;
}

async function manifest(root, name) {
  const dir = path.join(root, 'node_modules', ...name.split('/'));
  let text;
  try {
    text = await readFile(path.join(dir, 'package.json'), 'utf8');
  } catch {
    throw new Unavailable(`${name} is not installed`);
  }
  return { dir, pkg: JSON.parse(text) };
}

async function load(root, name) {
  const { dir, pkg } = await manifest(root, name);
  const exported = pkg.exports && (typeof pkg.exports === 'string' ? pkg.exports : pick(pkg.exports['.'] ?? pkg.exports));
  const entry = exported ?? pkg.main ?? 'index.js';
  return import(pathToFileURL(path.join(dir, entry)).href);
}

async function version(scanner, root) {
  const name = PACKAGES[scanner];
  if (scanner === 'redact-secret') {
    // Legacy reads the package's VERSION export.
    const { VERSION } = await load(root, name);
    return VERSION;
  }
  return (await manifest(root, name)).pkg.version;
}

async function readStdin() {
  const chunks = [];
  for await (const chunk of process.stdin) chunks.push(chunk);
  return JSON.parse(Buffer.concat(chunks).toString('utf8'));
}

// Output is batched and written with backpressure: one write per ~64 KiB
// instead of one per finding, and no more than one batch queued ahead of a slow
// reader, so memory stays bounded however many findings a scan reports. The
// bytes are exactly the one-line-per-finding stream, in the same order.
const BATCH_BYTES = 64 * 1024;
let batch = [];
let batched = 0;

async function flush() {
  if (batched === 0) return;
  const chunk = batch.join('');
  batch = [];
  batched = 0;
  if (!process.stdout.write(chunk)) {
    await new Promise((resolve, reject) => {
      const done = () => {
        process.stdout.off('drain', done);
        process.stdout.off('error', fail);
        resolve();
      };
      const fail = (error) => {
        process.stdout.off('drain', done);
        process.stdout.off('error', fail);
        reject(error);
      };
      process.stdout.once('drain', done);
      process.stdout.once('error', fail);
    });
  }
}

async function emit(finding) {
  const line = `${JSON.stringify(finding)}\n`;
  batch.push(line);
  batched += line.length;
  if (batched >= BATCH_BYTES) await flush();
}

async function scan(scanner, root) {
  const request = await readStdin();
  const options = request.options ?? {};
  const name = PACKAGES[scanner];
  let count = 0;
  const each = async (detect) => {
    for (const relative of request.paths) {
      const text = await readFile(path.join(request.root, relative), 'utf8');
      for (const finding of await detect(text)) {
        await emit({ path: relative, ...finding });
        count += 1;
      }
    }
  };
  if (scanner === 'redact-secret') {
    const { initialize, scan: detect } = await load(root, name);
    await initialize();
    await each((text) => detect(text).map((r) => ({
      start: r.start, end: r.end, label: r.detector,
      ...(typeof r.type === 'string' ? { type: r.type } : {}),
      ...(r.action !== undefined ? { action: r.action } : {}),
    })));
  } else if (scanner === 'flare-redact') {
    const { scan: detect } = await load(root, name);
    await each((text) => detect(text, options).map((r) => ({ start: r.start, end: r.end, label: r.detector })));
  } else if (scanner === 'openredaction') {
    const { OpenRedaction } = await load(root, name);
    const detector = new OpenRedaction(options);
    await each(async (text) => (await detector.detect(text)).detections.map((r) => ({
      start: r.position[0], end: r.position[1], label: r.type,
    })));
  }
  await emit({ done: true, findings: count });
  await flush();
}

const [command, scanner, root] = process.argv.slice(2);
if (!['version', 'scan'].includes(command) || !Object.hasOwn(PACKAGES, scanner) || !root) {
  process.stderr.write('usage: shim.mjs version|scan <scanner> <package-root>\n');
  process.exit(2);
}
try {
  if (command === 'version') {
    await emit({ version: await version(scanner, root) });
    await flush();
  }
  else await scan(scanner, root);
} catch (error) {
  // Never echo scanner output or input text; the message is fixed per class.
  process.stderr.write(error instanceof Unavailable ? `${error.message}\n` : 'shim failed\n');
  process.exit(error instanceof Unavailable ? 3 : 1);
}
