// The registry-to-candidate adapter, against fixed input -> normalised-value/digest vectors produced
// by the PRODUCER (make_vectors.py). The fixture pack cannot test this: its candidate fields are
// already normalised, so a wrong adapter still scores 152,804/152,804 and fails on the first release.
import { readFileSync } from 'node:fs';

import test from 'node:test';
import assert from 'node:assert';
import path from 'node:path';
import N from '../../seed/v3/normalize.js';

const V = JSON.parse(readFileSync(new URL('../../seed/v3/vectors.json', import.meta.url), 'utf8'));

test('vectors come from the producer, not from this implementation', () => {
  assert.ok(V._note.includes('never generated from the JS implementation'));
  assert.strictEqual(V.identity_domain_sep, N.IDENTITY_DOMAIN_SEP);
});

test('norm_email', () => {
  for (const v of V.norm_email) assert.deepStrictEqual(N.normEmail(v.in), v.out, JSON.stringify(v.in));
});

test('norm_name uses casefold, not toLowerCase', () => {
  for (const v of V.norm_name) assert.deepStrictEqual(N.normName(v.in), v.out, JSON.stringify(v.in));
  // The case that separates them: Python's casefold expands the sharp s.
  assert.strictEqual(N.normName('ß-sharp'), 'ss-sharp');
  assert.notStrictEqual('ß-sharp'.toLowerCase(), 'ss-sharp');
});

test('email_domain', () => {
  for (const v of V.email_domain) assert.deepStrictEqual(N.emailDomain(v.in), v.out, JSON.stringify(v.in));
});

test('identity_digest — domain separator is a NEWLINE and the label is `email`', () => {
  for (const v of V.identity_digest) assert.deepStrictEqual(N.identityDigest(v.in), v.out, JSON.stringify(v.in));
  assert.strictEqual(N.domainDigest('email', 'a@b.c'), N.sha256Hex(`${N.IDENTITY_DOMAIN_SEP}\nemail\na@b.c`));
});

test('tuple_digest', () => {
  for (const v of V.tuple_digest) {
    assert.deepStrictEqual(N.tupleDigest(v.name, v.email), v.out, JSON.stringify([v.name, v.email]));
  }
});

test('maintainers_digest, including non-ASCII names', () => {
  // The generator marks inputs whose Python repr JavaScript cannot reproduce (a number, or
  // integer-like object keys); those must REFUSE rather than return a digest.
  for (const v of V.maintainers_digest) {
    if (v.representable_in_js === false) {
      assert.throws(() => N.maintainersDigest(v.in), N.NonPortableInput, JSON.stringify(v.in));
    } else {
      assert.deepStrictEqual(N.maintainersDigest(v.in), v.out, JSON.stringify(v.in));
    }
  }
});

test('canonical JSON escapes non-ASCII the way Python json.dumps does', () => {
  // ensure_ascii=True on the producer side; JSON.stringify would emit these raw and diverge.
  assert.strictEqual(N.pyJsonString('Ünï'), '"\\u00dcn\\u00ef"');
  assert.strictEqual(N.pyJsonString('北'), '"\\u5317"');
  assert.strictEqual(N.pyJsonString('a"b\\c'), '"a\\"b\\\\c"');
  assert.notStrictEqual(N.pyJsonString('Ünï'), JSON.stringify('Ünï'));
});

test('python str() is the string itself; repr() quotes it', () => {
  assert.strictEqual(N.pyStr('alice'), 'alice');
  assert.strictEqual(N.pyRepr('alice'), "'alice'");
  assert.strictEqual(N.pyRepr({ email: 'a@b.c' }), "{'email': 'a@b.c'}");
  assert.strictEqual(N.pyRepr({}), '{}');
  // `{ name: 123 }` used to render as "{'name': 123}". It cannot: JSON.parse gives the same
  // Number for 123 and 123.0, whose Python reprs differ, so the repr path refuses numbers.
  assert.throws(() => N.pyRepr({ name: 123 }), N.NonPortableInput);
  assert.strictEqual(N.pyRepr("it's"), '"it\'s"');
});

test('a value whose Python repr cannot be derived is REFUSED, never guessed', () => {
  assert.throws(() => N.pyRepr(1.5), N.NonPortableInput, 'numbers are ambiguous after JSON parsing');
  assert.throws(() => N.pyRepr({ 1: 'a' }), N.NonPortableInput, 'JS reorders integer-like keys');
  assert.strictEqual(N.pyRepr('\u0001'), "'\\x01'", 'repr escapes it now');
});

test('install_body_digest', () => {
  for (const v of V.install_body_digest) {
    assert.deepStrictEqual(N.installBodyDigest(v.install, v.preinstall, v.postinstall), v.out);
  }
});

test('node_major and provider_class', () => {
  for (const v of V.node_major) assert.strictEqual(N.nodeMajor(v.in), v.out, JSON.stringify(v.in));
  for (const v of V.provider_class) {
    assert.strictEqual(N.providerClass(v.domain, v.count), v.out, JSON.stringify([v.domain, v.count]));
  }
});
