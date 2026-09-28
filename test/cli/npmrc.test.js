// U-04 — `init` adds a marked registry block to .npmrc and `stop` removes it. Everything else in the
// user's .npmrc (auth tokens, scoped registries, comments, other settings, Windows CRLF line endings)
// must survive both operations byte for byte; the only normalisation is that trailing blank lines
// collapse to a single final newline.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, rmSync, writeFileSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { applyChaingateBlock, removeChaingateBlock, readCurrentRegistry, findScopedRegistries } from '../../cli/npmrc.js';
import { NPMRC_MARKER_START, NPMRC_MARKER_END } from '../../cli/constants.js';

const PROXY = 'http://127.0.0.1:6173/';
const UNRELATED = [
  '; user settings',
  '//registry.npmjs.org/:_authToken=npm_EXAMPLEtokenEXAMPLEtoken',
  '@corp:registry=https://npm.corp.example/',
  '//npm.corp.example/:_authToken=corp-EXAMPLE',
  'save-exact=true',
  'fund=false',
];

function tmp(content) {
  const dir = mkdtempSync(join(tmpdir(), 'chaingate-npmrc-'));
  const file = join(dir, '.npmrc');
  if (content !== undefined) writeFileSync(file, content);
  return { file, cleanup: () => rmSync(dir, { recursive: true, force: true }) };
}

for (const [label, eol] of [['LF', '\n'], ['CRLF (Windows)', '\r\n']]) {
  test(`${label}: apply keeps every unrelated line verbatim; remove restores the file exactly`, () => {
    const original = UNRELATED.join(eol) + eol;
    const t = tmp(original);
    try {
      applyChaingateBlock(t.file, PROXY);
      const applied = readFileSync(t.file, 'utf8');
      for (const line of UNRELATED) assert.ok(applied.includes(line + eol), `kept verbatim: ${line}`);
      assert.equal(applied.split(NPMRC_MARKER_START).length - 1, 1, 'exactly one ChainGate block');
      assert.match(applied, new RegExp(`${NPMRC_MARKER_START}\\s*registry=${PROXY.replace(/[/.:]/g, '\\$&')}\\s*${NPMRC_MARKER_END}`));
      assert.equal(readCurrentRegistry(t.file), null, 'the registry line inside the block is not reported as the user registry');
      assert.deepEqual(findScopedRegistries(t.file).length > 0, true, 'the scoped registry is still visible');

      applyChaingateBlock(t.file, PROXY);   // idempotent: re-init does not stack blocks
      assert.equal(readFileSync(t.file, 'utf8'), applied, 'a second apply changes nothing');

      assert.equal(removeChaingateBlock(t.file), true);
      assert.equal(readFileSync(t.file, 'utf8'), original, 'byte-identical after stop');
      assert.equal(removeChaingateBlock(t.file), false, 'a second remove is a no-op');
      assert.equal(readFileSync(t.file, 'utf8'), original);
    } finally { t.cleanup(); }
  });
}

test('a user registry line outside the block is kept, and wins again after stop', () => {
  const original = 'registry=https://npm.corp.example/\nsave-exact=true\n';
  const t = tmp(original);
  try {
    applyChaingateBlock(t.file, PROXY);
    const applied = readFileSync(t.file, 'utf8');
    assert.ok(applied.startsWith(original.trimEnd()), 'the user line is untouched');
    assert.ok(applied.lastIndexOf(`registry=${PROXY}`) > applied.indexOf('registry=https://npm.corp.example/'),
      'the ChainGate registry comes after the user one (last assignment wins while ChainGate runs)');
    assert.equal(readCurrentRegistry(t.file), 'https://npm.corp.example', 'reported without the trailing slash, by design');
    removeChaingateBlock(t.file);
    assert.equal(readFileSync(t.file, 'utf8'), original);
  } finally { t.cleanup(); }
});

test('no .npmrc: apply creates one holding only the block; remove leaves no unrelated content behind', () => {
  const t = tmp(undefined);
  try {
    assert.equal(existsSync(t.file), false);
    applyChaingateBlock(t.file, PROXY);
    assert.equal(readFileSync(t.file, 'utf8'), `${NPMRC_MARKER_START}\nregistry=${PROXY}\n${NPMRC_MARKER_END}\n`);
    removeChaingateBlock(t.file);
    assert.equal(readFileSync(t.file, 'utf8'), '');
  } finally { t.cleanup(); }
});

test('documented normalisation: a missing final newline and extra trailing blank lines become one final newline', () => {
  for (const [original, expected] of [['save-exact=true', 'save-exact=true\n'], ['save-exact=true\n\n\n', 'save-exact=true\n']]) {
    const t = tmp(original);
    try {
      applyChaingateBlock(t.file, PROXY);
      removeChaingateBlock(t.file);
      assert.equal(readFileSync(t.file, 'utf8'), expected, JSON.stringify(original));
    } finally { t.cleanup(); }
  }
});
