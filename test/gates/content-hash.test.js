import { test } from 'node:test';
import assert from 'node:assert/strict';

import contentHash from '../../gates/content-hash.js';

const SHA512_A = 'sha512-aaaaaaaaaaaaaaaaBBBBBBBBBBBBBBBBcccccccccccccccc==';
const SHA512_B = 'sha512-zzzzzzzzzzzzzzzzYYYYYYYYYYYYYYYYxxxxxxxxxxxxxxxx==';
const SHA1_A = 'f05076f19e0b9f60b8f1b7a8a7f5a0a00fedf22d';
const SHA1_B = '854e14f2999c2ef7fab058654fd995dd183688f2';

function run({ baseline, incoming }) {
  return contentHash.evaluate({
    ecosystem: 'npm',
    packageName: 'axios',
    version: '1.7.9',
    incoming,
    baseline,
    history: [],
    config: {},
  });
}

test('baseline null → SKIP first-seen', () => {
  const r = run({ baseline: null, incoming: { integrity_hash: SHA512_A, content_hash: SHA1_A } });
  assert.equal(r.gate, 'content-hash');
  assert.equal(r.result, 'SKIP');
  assert.match(r.detail, /first-seen/);
});

test('baseline has no hash fields → SKIP (baseline data gap)', () => {
  const r = run({
    baseline: { integrity_hash: null, content_hash: null },
    incoming: { integrity_hash: SHA512_A, content_hash: SHA1_A },
  });
  assert.equal(r.result, 'SKIP');
  assert.match(r.detail, /baseline has no hash/);
});

test('incoming has no hash fields → SKIP (incoming data gap, not BLOCK)', () => {
  const r = run({
    baseline: { integrity_hash: SHA512_A, content_hash: SHA1_A },
    incoming: { integrity_hash: null, content_hash: null },
  });
  assert.equal(r.result, 'SKIP');
  assert.match(r.detail, /incoming packument missing/);
});

test('matching integrity on both sides → ALLOW', () => {
  const r = run({
    baseline: { integrity_hash: SHA512_A, content_hash: SHA1_A },
    incoming: { integrity_hash: SHA512_A, content_hash: SHA1_A },
  });
  assert.equal(r.result, 'ALLOW');
  assert.match(r.detail, /integrity hash matches baseline/);
});

test('integrity differs → BLOCK with truncated old→new', () => {
  const r = run({
    baseline: { integrity_hash: SHA512_A, content_hash: SHA1_A },
    incoming: { integrity_hash: SHA512_B, content_hash: SHA1_B },
  });
  assert.equal(r.result, 'BLOCK');
  assert.match(r.detail, /integrity hash differs from baseline/);
  assert.match(r.detail, /sha512-aaaaaaaaa…/);
  assert.match(r.detail, /sha512-zzzzzzzzz…/);
});

test('integrity matches but shasum drifts → ALLOW with re-shasum note', () => {
  const r = run({
    baseline: { integrity_hash: SHA512_A, content_hash: SHA1_A },
    incoming: { integrity_hash: SHA512_A, content_hash: SHA1_B },
  });
  assert.equal(r.result, 'ALLOW');
  assert.match(r.detail, /sha1 re-shasum/);
  assert.match(r.detail, /f05076f19e0b9f60…/);
  assert.match(r.detail, /854e14f2999c2ef7…/);
});

test('no integrity on either side, matching shasum → ALLOW', () => {
  const r = run({
    baseline: { integrity_hash: null, content_hash: SHA1_A },
    incoming: { integrity_hash: null, content_hash: SHA1_A },
  });
  assert.equal(r.result, 'ALLOW');
  assert.match(r.detail, /shasum matches baseline/);
});

test('no integrity, shasum differs → BLOCK', () => {
  const r = run({
    baseline: { integrity_hash: null, content_hash: SHA1_A },
    incoming: { integrity_hash: null, content_hash: SHA1_B },
  });
  assert.equal(r.result, 'BLOCK');
  assert.match(r.detail, /shasum differs from baseline/);
});

test('asymmetric: baseline integrity only, incoming shasum only → SKIP', () => {
  const r = run({
    baseline: { integrity_hash: SHA512_A, content_hash: null },
    incoming: { integrity_hash: null, content_hash: SHA1_A },
  });
  assert.equal(r.result, 'SKIP');
  assert.match(r.detail, /differing hash algorithms/);
});

test('asymmetric reversed: baseline shasum only, incoming integrity only → SKIP', () => {
  const r = run({
    baseline: { integrity_hash: null, content_hash: SHA1_A },
    incoming: { integrity_hash: SHA512_A, content_hash: null },
  });
  assert.equal(r.result, 'SKIP');
  assert.match(r.detail, /differing hash algorithms/);
});

test('deterministic: same input twice → byte-identical detail', () => {
  const input = {
    baseline: { integrity_hash: SHA512_A, content_hash: SHA1_A },
    incoming: { integrity_hash: SHA512_B, content_hash: SHA1_B },
  };
  assert.equal(run(input).detail, run(input).detail);
});

test('gate name is always content-hash regardless of outcome', () => {
  assert.equal(run({ baseline: null, incoming: {} }).gate, 'content-hash');
  assert.equal(
    run({
      baseline: { integrity_hash: SHA512_A },
      incoming: { integrity_hash: SHA512_A },
    }).gate,
    'content-hash',
  );
});
