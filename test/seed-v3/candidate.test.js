// The candidate boundary in JavaScript: explicit nullability, finite numbers, integer ranges,
// string/digest formats, and no boolean-as-integer acceptance in EITHER direction.
// The spec is declared independently in reader.js and compared here against the Python export.
import { fileURLToPath } from 'node:url';
import { dirname } from 'node:path';

const DIRNAME = dirname(fileURLToPath(import.meta.url));

import test from 'node:test';
import assert from 'node:assert';
import fs from 'node:fs';
import path from 'node:path';
import R from '../../seed/v3/reader.js';

const GOOD = {
  package_name: 'x', version: '1.0.0', published_s: 1700000000, lineage_id: 1, ord: 0,
  identity_digest: 'a'.repeat(64), tuple_digest: 'b'.repeat(64), maint_digest: 'c'.repeat(32),
  tool_name: 'npm', tool_key: 1001000, provenance_present: false, publish_method: 'unknown',
  has_scripts: false, body_digest: '', head_present: false, repo_digest: null,
  size_bytes: 1234, provider_class: 'unknown',
};

test('the JS boundary and the Python boundary are the SAME spec', () => {
  const p = path.join(DIRNAME, '..', '..', 'seed', 'v3', 'candidate-spec.json');
  const py = JSON.parse(fs.readFileSync(p, 'utf8'));
  // Declared independently on each side; this asserts they have not drifted apart.
  assert.deepStrictEqual(
    JSON.parse(JSON.stringify(R.CANDIDATE_SPEC)),
    JSON.parse(JSON.stringify(py)),
    'the JS candidate spec has drifted from the Python one',
  );
});

test('a fully stated candidate is accepted', () => {
  const c = R.candidateFromMapping({ ...GOOD });
  assert.strictEqual(c.package_name, 'x');
  assert.strictEqual(c.size_bytes, 1234);
});

test('every evaluable field must be stated — no defaults are manufactured', () => {
  assert.throws(() => R.candidateFromMapping({ package_name: 'x', version: '1' }), (e) => {
    assert.ok(e instanceof R.CandidateRejected);
    assert.match(e.message, /missing required candidate fields/);
    for (const f of ['has_scripts', 'provenance_present', 'size_bytes', 'published_s']) {
      assert.ok(e.message.includes(f), `did not name ${f}`);
    }
    return true;
  });
});

test('unknown fields are refused', () => {
  assert.throws(() => R.candidateFromMapping({ ...GOOD, surprise: 1 }), /unknown candidate fields: surprise/);
});

test('a boolean is not an integer and an integer is not a boolean', () => {
  assert.throws(() => R.candidateFromMapping({ ...GOOD, has_scripts: 1 }), /must be a boolean/);
  assert.throws(() => R.candidateFromMapping({ ...GOOD, ord: true }), /must be integer, not a boolean/);
  assert.throws(() => R.candidateFromMapping({ ...GOOD, size_bytes: false }), /must be integer, not a boolean/);
  assert.throws(() => R.candidateFromMapping({ ...GOOD, tool_key: true }), /must be number, not a boolean/);
});

test('numeric values must be finite and in range', () => {
  for (const v of [NaN, Infinity, -Infinity]) {
    assert.throws(() => R.candidateFromMapping({ ...GOOD, tool_key: v }), /must be finite/);
  }
  assert.throws(() => R.candidateFromMapping({ ...GOOD, tool_key: -1 }), /must be >= 0/);
  assert.throws(() => R.candidateFromMapping({ ...GOOD, published_s: -1 }), /must be >= 0/);
  assert.throws(() => R.candidateFromMapping({ ...GOOD, published_s: 9999999999999 }), /must be <= 4102444800/);
  assert.throws(() => R.candidateFromMapping({ ...GOOD, published_s: 1.5 }), /must be an integer/);
  assert.throws(() => R.candidateFromMapping({ ...GOOD, lineage_id: 0 }), /must be >= 1/);
  assert.throws(() => R.candidateFromMapping({ ...GOOD, ord: -1 }), /must be >= 0/);
  assert.throws(() => R.candidateFromMapping({ ...GOOD, size_bytes: -5 }), /must be >= 0/);
});

test('nullability is explicit per field', () => {
  // nullable
  for (const f of ['published_s', 'lineage_id', 'ord', 'identity_digest', 'tuple_digest', 'repo_digest', 'size_bytes']) {
    assert.doesNotThrow(() => R.candidateFromMapping({ ...GOOD, [f]: null }), `${f} should be nullable`);
  }
  // not nullable
  for (const f of ['package_name', 'version', 'maint_digest', 'tool_name', 'tool_key',
    'provenance_present', 'publish_method', 'has_scripts', 'body_digest', 'head_present', 'provider_class']) {
    assert.throws(() => R.candidateFromMapping({ ...GOOD, [f]: null }),
      /null is not a legitimate value here/, `${f} should not be nullable`);
  }
});

test('digest widths are enforced per field, and they are NOT uniform', () => {
  assert.throws(() => R.candidateFromMapping({ ...GOOD, identity_digest: 'abc' }), /64 lowercase hex/);
  assert.throws(() => R.candidateFromMapping({ ...GOOD, identity_digest: 'a'.repeat(32) }), /64 lowercase hex/);
  assert.throws(() => R.candidateFromMapping({ ...GOOD, identity_digest: 'A'.repeat(64) }), /64 lowercase hex/);
  assert.throws(() => R.candidateFromMapping({ ...GOOD, maint_digest: 'a'.repeat(64) }), /32 lowercase hex/);
  assert.throws(() => R.candidateFromMapping({ ...GOOD, body_digest: 'zz' }), /32 lowercase hex/);
  // md5-class fields legitimately carry '' meaning "no maintainers" / "no install body"
  assert.doesNotThrow(() => R.candidateFromMapping({ ...GOOD, maint_digest: '', body_digest: '' }));
});

test('strings that must not be empty, and the provider-class enum', () => {
  assert.throws(() => R.candidateFromMapping({ ...GOOD, package_name: '' }), /must not be empty/);
  assert.throws(() => R.candidateFromMapping({ ...GOOD, version: '' }), /must not be empty/);
  assert.doesNotThrow(() => R.candidateFromMapping({ ...GOOD, tool_name: '', publish_method: '' }));
  assert.throws(() => R.candidateFromMapping({ ...GOOD, provider_class: 'made-up' }), /must be one of/);
  for (const pc of R.PROVIDER_CLASSES) {
    assert.doesNotThrow(() => R.candidateFromMapping({ ...GOOD, provider_class: pc }));
  }
});

test('a non-object candidate is refused', () => {
  for (const v of [null, [], 'string', 42]) {
    assert.throws(() => R.candidateFromMapping(v), /candidate must be a JSON object/);
  }
});
