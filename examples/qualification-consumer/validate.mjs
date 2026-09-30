// Minimal, dependency-free JSON Schema validator for the subset of draft
// 2020-12 that the generated credential-eval schemas use: $ref into $defs,
// type, const, enum, properties, required, additionalProperties, items,
// anyOf, oneOf, minimum, minLength, maxLength, pattern and the schemars
// integer formats. Any other keyword makes validation fail loudly instead of
// being ignored, so a schema change cannot silently weaken this check.
//
// A real consumer may use any conforming validator (e.g. Ajv). This file only
// exists so the reference consumer needs no npm install.

const ANNOTATIONS = new Set(['$schema', '$id', 'title', 'description', 'default', '$defs', 'examples']);
const KEYWORDS = new Set([
  '$ref', 'type', 'const', 'enum', 'properties', 'required', 'additionalProperties', 'items',
  'anyOf', 'oneOf', 'minimum', 'maximum', 'minLength', 'maxLength', 'pattern', 'format',
  'minItems', 'maxItems', 'uniqueItems',
]);
const MAX_ERRORS = 50;

const typeOf = value => {
  if (value === null) return 'null';
  if (Array.isArray(value)) return 'array';
  if (typeof value === 'number') return Number.isInteger(value) ? 'integer' : 'number';
  return typeof value;
};

const matchesType = (value, type) => {
  const actual = typeOf(value);
  return actual === type || (type === 'number' && actual === 'integer');
};

const deepEqual = (a, b) => JSON.stringify(a) === JSON.stringify(b);

// Code points, not UTF-16 units, as JSON Schema requires.
const length = string => [...string].length;

// schemars integer/float formats. 64-bit values must also be exact in a JS
// number; a consumer that needs larger counts should use a BigInt-aware parser.
const INTEGER_RANGES = {
  uint8: [0, 0xff], uint16: [0, 0xffff], uint32: [0, 0xffffffff], uint64: [0, Number.MAX_SAFE_INTEGER], uint: [0, Number.MAX_SAFE_INTEGER],
  int8: [-0x80, 0x7f], int16: [-0x8000, 0x7fff], int32: [-0x80000000, 0x7fffffff],
  int64: [Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER], int: [Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER],
};

function formatProblem(format, value) {
  if (Object.hasOwn(INTEGER_RANGES, format)) {
    const [low, high] = INTEGER_RANGES[format];
    return Number.isInteger(value) && value >= low && value <= high ? null : `is not a representable ${format}`;
  }
  if (format === 'double' || format === 'float') return Number.isFinite(value) ? null : `is not a finite ${format}`;
  return `uses unsupported format "${format}"`;
}

/**
 * Validate `value` against `root`. Returns a list of error strings (empty when
 * valid). Error messages name JSON pointers only, never values, so a malformed
 * artifact cannot leak content through the error channel.
 */
export function validate(root, value) {
  const errors = [];
  const patterns = new Map();
  const regex = pattern => {
    if (!patterns.has(pattern)) patterns.set(pattern, new RegExp(pattern, 'u'));
    return patterns.get(pattern);
  };
  const resolve = ref => {
    const match = /^#\/\$defs\/([^/]+)$/.exec(ref);
    const target = match && root.$defs?.[match[1]];
    if (!target) throw new Error(`Unsupported or unknown $ref ${ref}`);
    return target;
  };

  function check(schema, instance, pointer, sink) {
    if (sink.length >= MAX_ERRORS) return;
    if (schema === true) return;
    if (schema === false) { sink.push(`${pointer || '/'}: is not allowed`); return; }
    for (const key of Object.keys(schema)) {
      if (!KEYWORDS.has(key) && !ANNOTATIONS.has(key)) throw new Error(`Unsupported schema keyword "${key}" at ${pointer || '/'}`);
    }
    const fail = message => sink.push(`${pointer || '/'}: ${message}`);

    if (schema.$ref) check(resolve(schema.$ref), instance, pointer, sink);

    if (schema.type !== undefined) {
      const types = Array.isArray(schema.type) ? schema.type : [schema.type];
      if (!types.some(type => matchesType(instance, type))) { fail(`expected type ${types.join('|')}`); return; }
    }
    if ('const' in schema && !deepEqual(schema.const, instance)) fail('does not equal the required constant');
    if (schema.enum && !schema.enum.some(option => deepEqual(option, instance))) fail('is not one of the allowed values');

    if (typeof instance === 'string') {
      if (schema.minLength !== undefined && length(instance) < schema.minLength) fail(`is shorter than ${schema.minLength}`);
      if (schema.maxLength !== undefined && length(instance) > schema.maxLength) fail(`is longer than ${schema.maxLength}`);
      if (schema.pattern !== undefined && !regex(schema.pattern).test(instance)) fail('does not match the required pattern');
    }
    if (typeof instance === 'number') {
      if (schema.minimum !== undefined && instance < schema.minimum) fail(`is below ${schema.minimum}`);
      if (schema.maximum !== undefined && instance > schema.maximum) fail(`is above ${schema.maximum}`);
      if (schema.format !== undefined) {
        const problem = formatProblem(schema.format, instance);
        if (problem) fail(problem);
      }
    }

    if (typeOf(instance) === 'object') {
      const properties = schema.properties ?? {};
      for (const name of schema.required ?? []) {
        if (!Object.hasOwn(instance, name)) fail(`is missing required property "${name}"`);
      }
      for (const [name, child] of Object.entries(instance)) {
        const childPointer = `${pointer}/${name.replaceAll('~', '~0').replaceAll('/', '~1')}`;
        if (Object.hasOwn(properties, name)) check(properties[name], child, childPointer, sink);
        else if (schema.additionalProperties === false) sink.push(`${childPointer}: is not an allowed property`);
        else if (schema.additionalProperties && typeof schema.additionalProperties === 'object') check(schema.additionalProperties, child, childPointer, sink);
      }
    }
    if (Array.isArray(instance)) {
      if (schema.minItems !== undefined && instance.length < schema.minItems) fail(`has fewer than ${schema.minItems} items`);
      if (schema.maxItems !== undefined && instance.length > schema.maxItems) fail(`has more than ${schema.maxItems} items`);
      if (schema.uniqueItems === true && new Set(instance.map(item => JSON.stringify(item))).size !== instance.length) fail('has duplicate items');
      if (schema.items !== undefined) instance.forEach((item, index) => check(schema.items, item, `${pointer}/${index}`, sink));
    }

    if (schema.anyOf) {
      const passing = schema.anyOf.some(option => { const local = []; check(option, instance, pointer, local); return local.length === 0; });
      if (!passing) fail('matches none of anyOf');
    }
    if (schema.oneOf) {
      const passing = schema.oneOf.filter(option => { const local = []; check(option, instance, pointer, local); return local.length === 0; }).length;
      if (passing !== 1) fail(`matches ${passing} of oneOf (exactly 1 required)`);
    }
  }

  check(root, value, '', errors);
  return errors;
}
