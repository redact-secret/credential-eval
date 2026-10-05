// Deterministic synthetic diagnostic inputs for the OpenRedaction profile study
// (ADR 0013). Every credential-shaped value is assembled at run time from
// invented fragments; none is a real or documented secret, and nothing here is
// ever printed. A diagnostic subset is not an official qualification input.

function lcg(seed) {
  let s = seed >>> 0;
  return () => (s = (Math.imul(s, 1664525) + 1013904223) >>> 0) / 2 ** 32;
}
const ALNUM = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
const HEX = '0123456789abcdef';
const word = (r, n, set = ALNUM) => Array.from({ length: n }, () => set[Math.floor(r() * set.length)]).join('');

// One generator per credential shape that the 1.1.5 patterns accept.
const SHAPES = {
  github: (r) => `gh${'p'}_${word(r, 36)}`,
  aws: (r) => `AK${'IA'}${word(r, 16, 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789')}`,
  stripe: (r) => `sk_${'test'}_${word(r, 24)}`,
  jwt: (r) => `eyJ${word(r, 12)}.eyJ${word(r, 16)}.${word(r, 22)}`,
  bearer: (r) => `Authorization: Bearer ${word(r, 32)}`,
  urlAuth: (r) => `https://u${word(r, 4)}:${word(r, 10)}@host${word(r, 3)}.invalid/p`,
  dbUrl: (r) => `postgres://app:${word(r, 10)}@db${word(r, 3)}.invalid:5432/app`,
  assignment: (r) => `api_key: ${word(r, 28)}`,
  password: (r) => `password: ${word(r, 12)}`,
};
const SHAPE_NAMES = Object.keys(SHAPES);

const FILLER = 'The quick brown fox jumps over the lazy dog while the build queue drains slowly. ';
const NEGATIVES = [
  'build 0123456789abcdef0123456789abcdef01234567 passed',
  'request 01234567-89ab-cdef-0123-456789abcdef done',
  'api_key: example_placeholder_value_0000',
  'password: example-placeholder',
  'token placeholder_value_do_not_use_000000',
];

function fillTo(bytes, make) {
  const parts = [];
  let size = 0;
  let i = 0;
  while (size < bytes) {
    const piece = make(i++);
    parts.push(piece);
    size += Buffer.byteLength(piece);
  }
  return parts.join('');
}

export const CASES = {
  // Repeated padding with no credentials: the pure scan cost of the pattern set.
  padding: (bytes) => fillTo(bytes, () => `${FILLER}\n`),
  // One credential per ~4 KiB of padding.
  sparse: (bytes, seed = 1) => {
    const r = lcg(seed);
    return fillTo(bytes, (i) =>
      i % 50 === 0 ? `${SHAPES[SHAPE_NAMES[(i / 50) % SHAPE_NAMES.length]](r)}\n` : `${FILLER}\n`);
  },
  // A credential on every line: high density.
  dense: (bytes, seed = 2) => {
    const r = lcg(seed);
    return fillTo(bytes, (i) => `line ${i} ${SHAPES[SHAPE_NAMES[i % SHAPE_NAMES.length]](r)}\n`);
  },
  // Credentials inside text that other patterns also claim (emails, URLs).
  overlap: (bytes, seed = 3) => {
    const r = lcg(seed);
    return fillTo(bytes, (i) =>
      `contact u${word(r, 5)}@mail${word(r, 3)}.invalid ${SHAPES.urlAuth(r)} ${SHAPES.dbUrl(r)}?owner=u${i}@mail.invalid\n`);
  },
  // Placeholder, hash and UUID lookalikes that must not produce credential claims.
  negative: (bytes) => fillTo(bytes, (i) => `${NEGATIVES[i % NEGATIVES.length]}\n`),
  // Multi-byte text (UTF-16 surrogate pairs, CJK) around credentials.
  unicode: (bytes, seed = 4) => {
    const r = lcg(seed);
    return fillTo(bytes, (i) =>
      i % 40 === 0 ? `비밀 😀 ${SHAPES[SHAPE_NAMES[(i / 40) % SHAPE_NAMES.length]](r)} 끝\n` : '안녕하세요 😀 이것은 채움 문장입니다 \n');
  },
  // Credentials wrapped by the transformations the methods apply.
  encoded: (bytes, seed = 5) => {
    const r = lcg(seed);
    return fillTo(bytes, (i) => {
      if (i % 40 !== 0) return `${FILLER}\n`;
      const v = SHAPES.assignment(r);
      return [JSON.stringify({ config: v }), encodeURIComponent(v), Buffer.from(v).toString('base64'), `"${v}"`][(i / 40) % 4] + '\n';
    });
  },
};
export const CASE_NAMES = Object.keys(CASES);
