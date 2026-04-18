import { test } from 'node:test';
import assert from 'node:assert/strict';

import { normalizeIdentity } from '../../patterns/identity.js';

test('normalizeIdentity: email + name → "name <email>"', () => {
  assert.equal(
    normalizeIdentity('dominic.tarr@gmail.com', 'Dominic Tarr'),
    'Dominic Tarr <dominic.tarr@gmail.com>',
  );
});

test('normalizeIdentity: email is lowercased, name preserved as-is', () => {
  assert.equal(
    normalizeIdentity('FOO@BAR.COM', 'Foo Bar'),
    'Foo Bar <foo@bar.com>',
  );
});

test('normalizeIdentity: whitespace trimmed on both fields', () => {
  assert.equal(
    normalizeIdentity('  foo@bar.com  ', '  Foo Bar  '),
    'Foo Bar <foo@bar.com>',
  );
});

test('normalizeIdentity: email only → "<email>"', () => {
  assert.equal(normalizeIdentity('foo@bar.com', ''), '<foo@bar.com>');
  assert.equal(normalizeIdentity('foo@bar.com', null), '<foo@bar.com>');
  assert.equal(normalizeIdentity('foo@bar.com', undefined), '<foo@bar.com>');
});

test('normalizeIdentity: name only → "name"', () => {
  assert.equal(normalizeIdentity('', 'Foo Bar'), 'Foo Bar');
  assert.equal(normalizeIdentity(null, 'Foo Bar'), 'Foo Bar');
  assert.equal(normalizeIdentity(undefined, 'Foo Bar'), 'Foo Bar');
});

test('normalizeIdentity: both missing → null (caller must skip)', () => {
  assert.equal(normalizeIdentity('', ''), null);
  assert.equal(normalizeIdentity(null, null), null);
  assert.equal(normalizeIdentity(undefined, undefined), null);
  assert.equal(normalizeIdentity('   ', '   '), null);
});

test('normalizeIdentity: non-string inputs coerce to null/empty, never crash', () => {
  assert.equal(normalizeIdentity(123, 'Foo'), 'Foo');       // numeric email ignored
  assert.equal(normalizeIdentity('foo@bar.com', 123), '<foo@bar.com>');
  assert.equal(normalizeIdentity({}, []), null);
});

test('normalizeIdentity: case-variant emails collapse to one identity', () => {
  // Attacker case-variant dodge protection: same mailbox in different
  // casings must produce the same identity key.
  const a = normalizeIdentity('dev@example.com', 'Dev');
  const b = normalizeIdentity('DEV@EXAMPLE.COM', 'Dev');
  const c = normalizeIdentity('Dev@Example.Com', 'Dev');
  assert.equal(a, b);
  assert.equal(b, c);
});

test('normalizeIdentity: name casing variants are DISTINCT (intentional)', () => {
  // Name differences like "Dominic Tarr" vs "dominictarr" are real
  // signal — do not collapse them.
  const a = normalizeIdentity('same@example.com', 'Dominic Tarr');
  const b = normalizeIdentity('same@example.com', 'dominictarr');
  assert.notEqual(a, b);
});
