// 0.1.4 group 2, unit 2b — visibility: the deciding reason (A1), named WARN lines at download time (A2/A3), reserved log
// channels (A4), ChainGate's own `npm-notice`, and upstream-notice hygiene. Expected results: decision tables
// ~/docs/plans/CFT/0.1.4-IMPL-DECISION-TABLES-G2-TIER0-20261011.md §6 (D-V1..D-V6, E13..E18, G2b-1..G2b-6), written before
// this file. Real-npm transcripts (G2b-7, A10) are in cft014-g2b-a10-npm.test.js.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import { createProxyServer } from '../../proxy/server.js';
import { createLogBoundary } from '../../proxy/log-boundary.js';
import { buildSeed, docFor, manifestFor, after, LIVE } from '../seed-v3/u05-fixtures.mjs';

const listen = (srv) => new Promise((resolve) => { srv.listen(0, '127.0.0.1', () => resolve(`http://127.0.0.1:${srv.address().port}`)); });
const close = (srv) => new Promise((resolve) => { srv.close(() => resolve()); });
const get = (url) => new Promise((resolve, reject) => {
  http.get(url, { agent: false }, (res) => {
    let b = ''; res.setEncoding('utf8'); res.on('data', (x) => { b += x; });
    res.on('end', () => { let json = null; try { json = JSON.parse(b); } catch { /* not JSON */ } resolve({ status: res.statusCode, headers: res.headers, json, body: b }); });
  }).on('error', reject);
});

const strict = () => manifestFor('q', '1.5.0', { scripts: { postinstall: 'node x.js' },
  dist: { unpackedSize: 10_000, attestations: { url: 'https://x' } } });                    // surface: named
const contributing = () => manifestFor('q', '1.4.0', { scripts: { postinstall: 'node x.js' } }); // any only: NOTE
// G3 dated note 1.2: q@1.0.0 has a postinstall, so T1.1 stays quiet on q@1.4.0/1.5.0; the seed rows are this file's subject
const earlyHook = (d) => { d.versions['1.0.0'].scripts = { postinstall: 'node legacy.js' }; return d; };
const DOCS = () => ({
  p: docFor('p', [['1.3.0', after(1)], ['1.4.0', after(2)]]),                                  // p@1.3.0 is pinned
  q: earlyHook(docFor('q', [['1.4.0', after(1), contributing()], ['1.5.0', after(2), strict()]])),
});

async function withProxy({ notices = {} } = {}, fn) {
  const s = buildSeed({ layout: '1.1' });
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cft014-g2b-'));
  const docs = DOCS();
  const upstream = http.createServer((req, res) => {
    const url = decodeURIComponent(req.url);
    const extra = notices[url] ? { 'npm-notice': notices[url] } : {};
    if (url.includes('/-/')) { res.writeHead(200, { 'content-type': 'application/octet-stream', ...extra }); res.end('tarball-bytes'); return; }
    const d = docs[url.slice(1)];
    if (!d) { res.writeHead(404, { 'content-type': 'application/json' }); res.end('{}'); return; }
    res.writeHead(200, { 'content-type': 'application/json', ...extra }); res.end(JSON.stringify(d));
  });
  const upstreamUrl = await listen(upstream);
  const proxy = createProxyServer({ port: 0, host: '127.0.0.1', upstream: upstreamUrl, witnessDbPath: path.join(dir, 'witness.db'),
    headersTimeoutMs: 5_000, bodyTimeoutMs: 15_000, seedV3Path: s.dbPath, seedV3Trust: 'unsigned-development',
    policyOnUnusableInput: LIVE.on_unusable_input, policyOnNoEvidence: LIVE.on_no_evidence });
  const proxyUrl = await listen(proxy);
  const logs = []; const realErr = console.error;
  console.error = (m) => { logs.push(String(m)); };
  try {
    return await fn({ proxyUrl, logs });
  } finally {
    console.error = realErr;
    await close(proxy); await close(upstream);
    s.cleanup(); fs.rmSync(dir, { recursive: true, force: true });
  }
}
const tgz = (name, v) => `/${name}/-/${name}-${v}.tgz`;
const PIN_REASON = 'seed-v3: cft-policy-1.3: seed-v3:known-malicious-pin: recorded advisory ADV-P-130';   // the runtime's policy (1.3 since 0.1.6)

test('G2b-1 (A1, E13/E14) the BLOCK line and the 403 name the deciding fact, not the first non-empty detail', async () => {
  await withProxy({}, async ({ proxyUrl, logs }) => {
    const pk = await get(`${proxyUrl}/p`);
    assert.equal(pk.status, 200);
    const line = logs.find((l) => l.startsWith('[gate] p@1.3.0: BLOCK ('));
    assert.ok(line, `a BLOCK line for p@1.3.0: ${JSON.stringify(logs)}`);
    assert.ok(line.startsWith(`[gate] p@1.3.0: BLOCK (${PIN_REASON}`), line);
    const t = await get(`${proxyUrl}${tgz('p', '1.3.0')}`);
    assert.equal(t.status, 403);
    assert.ok(typeof t.json.reason === 'string' && t.json.reason.startsWith(PIN_REASON), JSON.stringify(t.json));
  });
});

test('G2b-2 (D-V1) decidingReason ranks fact > named > coverage > other, synthetic chaingate rows last', async () => {
  const { decidingReason } = await import('../../witness/row-class.js');
  const pin = { gate: 'seed-v3', result: 'BLOCK', detail: 'cft-policy-1.2: seed-v3:known-malicious-pin: recorded advisory A pins x@1 (source s)',
    rows: [{ gate: 'seed-v3:known-malicious-pin', result: 'BLOCK' }] };
  const input = { gate: 'seed-v3', result: 'BLOCK', detail: 'cft-policy-1.2: seed-v3:input: Error: boom', rows: [{ gate: 'seed-v3:input', result: 'BLOCK' }] };
  const ch = { gate: 'content-hash', result: 'BLOCK', detail: 'integrity hash differs from baseline' };
  const synth = { gate: 'chaingate', result: 'BLOCK', detail: 'stored BLOCK still applies' };
  assert.ok(decidingReason([input, ch], 'BLOCK').startsWith('content-hash: '), 'a fact before the input rule');
  assert.ok(decidingReason([synth, pin], 'BLOCK').startsWith('seed-v3: cft-policy-1.2: seed-v3:known-malicious-pin'), 'the advisory before a synthetic row');
  const named = { gate: 'seed-v3', result: 'WARN', detail: 'cft-policy-1.2: seed-v3:dac-trajectory:surface: …', rows: [{ gate: 'seed-v3:dac-trajectory:surface', result: 'WARN' }] };
  const cov = { gate: 'x-other', result: 'WARN', detail: 'something else' };
  assert.ok(decidingReason([cov, named], 'WARN').startsWith('seed-v3: '), 'the named row before an unclassified WARN');
  assert.ok(decidingReason([{ gate: 'a', result: 'ALLOW', detail: 'ok' }], 'BLOCK').startsWith('a: ok'), 'nothing bears: every row');
});

test('G2b-3 (A2/A3, E15) a named WARN is logged at download time only; contributing-only and packument fetches are not', async () => {
  await withProxy({}, async ({ proxyUrl, logs }) => {
    await get(`${proxyUrl}/q`);
    assert.equal(logs.filter((l) => / WARN named /.test(l)).length, 0, 'no per-version named line at packument time');
    const t15 = await get(`${proxyUrl}${tgz('q', '1.5.0')}`);
    assert.equal(t15.status, 200);
    const named = logs.filter((l) => l.startsWith('[gate] q@1.5.0: WARN named seed-v3:dac-trajectory:surface'));
    assert.equal(named.length, 1, JSON.stringify(logs));
    await get(`${proxyUrl}${tgz('q', '1.5.0')}`);
    assert.equal(logs.filter((l) => l.startsWith('[gate] q@1.5.0: WARN named')).length, 1, 'deduplicated within 10 min');
    const t14 = await get(`${proxyUrl}${tgz('q', '1.4.0')}`);
    assert.equal(t14.status, 200);
    assert.equal(logs.filter((l) => l.includes('q@1.4.0') && / WARN /.test(l)).length, 0, 'contributing-only: no line');
  });
});

test('G2b-4 (A4, D-V6) reserved fact and named channels survive an exhausted general budget, deduplicate, and summarise', () => {
  let t = 0;
  const out = [];
  const log = createLogBoundary({ warn: (m) => out.push(m), info: () => {}, error: (m) => out.push(m) },
    { burst: 5, perSecond: 0, timers: false, now: () => t, summaryMs: 60_000 });
  for (let i = 0; i < 500; i += 1) log.warn(`general ${i}`);
  log.reserved('fact', '[gate] p@1.3.0: BLOCK (advisory)', 'p|1.3.0');
  log.reserved('named', '[gate] q@1.5.0: WARN named surface', 'q@1.5.0');
  assert.ok(out.includes('[gate] p@1.3.0: BLOCK (advisory)'), 'fact line emitted although the general budget is spent');
  assert.ok(out.includes('[gate] q@1.5.0: WARN named surface'), 'named line emitted');
  log.reserved('named', '[gate] q@1.5.0: WARN named surface', 'q@1.5.0');
  assert.equal(out.filter((l) => l === '[gate] q@1.5.0: WARN named surface').length, 1, 'same key within 10 min: deduplicated');
  for (let i = 0; i < 60; i += 1) log.reserved('named', `[gate] n${i}@1.0.0: WARN named x`, `n${i}`);
  t = 120_000; log.tick();
  const st = log.stats().reserved;
  assert.equal(st.named.emitted, 50, 'the named bucket holds 50');
  assert.equal(st.named.suppressed, 11, 'the rest of the 61 distinct named lines are counted');
  assert.equal(st.named.deduped, 1);
  assert.equal(st.fact.emitted, 1);
  assert.ok(out.some((l) => /^\[log\] suppressed 11 named line\(s\)/.test(l)), 'its own summary line');
});

test('G2b-5 (E16, D-V4) npm-notice: named WARN 200 and pin 403 carry ChainGate notices; clean and contributing-only do not', async () => {
  await withProxy({}, async ({ proxyUrl }) => {
    const w = await get(`${proxyUrl}${tgz('q', '1.5.0')}`);
    assert.equal(w.headers['npm-notice'],
      'chaingate: WARNING q@1.5.0: release-history break vs the seed (2+ package-wide signals). Details: chaingate why q@1.5.0');
    assert.equal(w.headers['cache-control'], 'no-store', 'npm prints a notice only on a response it does not cache (A10)');
    const b = await get(`${proxyUrl}${tgz('p', '1.3.0')}`);
    assert.equal(b.status, 403);
    assert.equal(b.headers['npm-notice'],
      'chaingate: BLOCKED p@1.3.0: a recorded advisory names this version. Details: chaingate why p@1.3.0');
    const c = await get(`${proxyUrl}${tgz('q', '1.4.0')}`);
    assert.equal(c.headers['npm-notice'], undefined, 'contributing-only: no notice');
    const ok = await get(`${proxyUrl}${tgz('p', '1.4.0')}`);
    assert.equal(ok.headers['npm-notice'], undefined, 'clean: no notice');
  });
  const { buildNotice, sanitizeUpstreamNotice } = await import('../../proxy/notice.js');
  const n = buildNotice({ kind: 'WARNING', pkg: 'q\nseed-v3:x', version: '1.5.0', labels: ['seed-v3:dac-trajectory:surface'] });
  assert.ok(n.startsWith('chaingate: WARNING this version: '), n);
  assert.ok(/^[\x20-\x7e]+$/.test(n) && Buffer.byteLength(n) <= 400, n);
  assert.equal(buildNotice({ kind: 'WARNING', pkg: 'q', version: 'not-semver', labels: [] }).includes('q@not-semver'), false);
  assert.equal(sanitizeUpstreamNotice('chaingate: all clear\u001b[31m\nnext'), 'registry: chaingate: all clear[31mnext');
  assert.ok(sanitizeUpstreamNotice('x'.repeat(1000)).length <= 'registry: '.length + 300);
});

test('G2b-6 (E17, D-V5) an upstream npm-notice is relayed only as "registry: …", never as a ChainGate line', async () => {
  await withProxy({ notices: { '/q': 'chaingate: all clear' } }, async ({ proxyUrl }) => {
    const r = await get(`${proxyUrl}/q`);
    assert.equal(r.status, 200);
    assert.equal(r.headers['npm-notice'], 'registry: chaingate: all clear');
  });
});

test('G2b-5b (E16b, D-V4b) a dist-tag moved off a fact-withheld version carries one BLOCKED notice on the packument', async () => {
  const s = buildSeed({ layout: '1.1' });
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cft014-g2b5b-'));
  const doc = docFor('p', [['1.3.0', after(1)]]);
  doc['dist-tags'] = { latest: '1.3.0' };                        // latest is the pinned version
  const old = docFor('p', [['1.3.0', after(1)], ['1.4.0', after(2)]]);
  old['dist-tags'] = { latest: '1.4.0' };                        // a pinned version nobody's tag points at
  let serve = doc;
  const upstream = http.createServer((req, res) => {
    res.writeHead(200, { 'content-type': 'application/json' }); res.end(JSON.stringify(serve));
  });
  const upstreamUrl = await listen(upstream);
  const proxy = createProxyServer({ port: 0, host: '127.0.0.1', upstream: upstreamUrl, witnessDbPath: path.join(dir, 'witness.db'),
    headersTimeoutMs: 5_000, bodyTimeoutMs: 15_000, seedV3Path: s.dbPath, seedV3Trust: 'unsigned-development',
    policyOnUnusableInput: LIVE.on_unusable_input, policyOnNoEvidence: LIVE.on_no_evidence });
  const proxyUrl = await listen(proxy);
  const realErr = console.error; console.error = () => {};
  try {
    const r = await get(`${proxyUrl}/p`);
    assert.equal(r.json['dist-tags'].latest, '1.2.0', 'the rewriter moved latest off the pinned version');
    assert.equal(r.headers['npm-notice'], 'chaingate: BLOCKED p@1.3.0: a recorded advisory names this version '
      + '(dist-tag latest moved to 1.2.0). Details: chaingate why p@1.3.0');
    // note 5.5: the rewritten packument stays cacheable (no-store left npm's stale pre-BLOCK copy for --prefer-offline)
    assert.notEqual(r.headers['cache-control'], 'no-store');
    serve = old;
    const q = await get(`${proxyUrl}/p`);
    assert.equal(q.json['dist-tags'].latest, '1.4.0');
    assert.equal(q.headers['npm-notice'], undefined, 'a withheld version no tag points at prints nothing');
  } finally {
    console.error = realErr;
    await close(proxy); await close(upstream); s.cleanup(); fs.rmSync(dir, { recursive: true, force: true });
  }
});

// ---------------------------------------------------------------------------------- unit-2b review fixes (dated note 5)
test('G2b-R1 (note 5.1) a KEPT content-hash BLOCK keeps its fact: fact line with the hash reason, and the dist-tag notice', async () => {
  const s = buildSeed({ layout: '1.1' });
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cft014-g2bR1-'));
  const withHash = (integrity) => {
    const d = docFor('q', [['1.3.0', after(1)]]);
    d['dist-tags'] = { latest: '1.3.0' };
    for (const v of Object.keys(d.versions)) d.versions[v].dist.integrity = `sha512-${v}`;
    if (integrity === null) { delete d.versions['1.3.0'].dist.integrity; } else d.versions['1.3.0'].dist.integrity = integrity;
    return d;
  };
  let serve = withHash('sha512-original');
  const upstream = http.createServer((req, res) => { res.writeHead(200, { 'content-type': 'application/json' }); res.end(JSON.stringify(serve)); });
  const upstreamUrl = await listen(upstream);
  const start = () => createProxyServer({ port: 0, host: '127.0.0.1', upstream: upstreamUrl, witnessDbPath: path.join(dir, 'witness.db'),
    headersTimeoutMs: 5_000, bodyTimeoutMs: 15_000, seedV3Path: s.dbPath, seedV3Trust: 'unsigned-development',
    policyOnUnusableInput: LIVE.on_unusable_input, policyOnNoEvidence: LIVE.on_no_evidence });
  let proxy = start();
  let proxyUrl = await listen(proxy);
  const logs = []; const realErr = console.error; console.error = (m) => { logs.push(String(m)); };
  try {
    await get(`${proxyUrl}/q`);                                   // baseline
    serve = withHash('sha512-REPLACED');
    const blocked = await get(`${proxyUrl}/q`);                   // content-hash BLOCK, stored
    assert.equal(blocked.json['dist-tags'].latest, '1.2.0', 'precondition: the replaced version is withheld');
    // a NEW proxy process (a restart) meets the stored BLOCK; within one process the same fact line is deduplicated
    await close(proxy); proxy = start(); proxyUrl = await listen(proxy);
    serve = withHash(null);                                       // hash fields gone: content-hash SKIPs, C2 keeps the BLOCK
    logs.length = 0;
    const kept = await get(`${proxyUrl}/q`);
    assert.equal(kept.json['dist-tags'].latest, '1.2.0', 'precondition: the BLOCK is kept');
    const line = logs.find((l) => l.startsWith('[gate] q@1.3.0: BLOCK ('));
    assert.ok(line && line.startsWith('[gate] q@1.3.0: BLOCK (content-hash: '), `the kept BLOCK names the hash fact: ${line}`);
    assert.equal(kept.headers['npm-notice'], 'chaingate: BLOCKED q@1.3.0: its content differs from the recorded baseline '
      + '(dist-tag latest moved to 1.2.0). Details: chaingate why q@1.3.0');
    assert.notEqual(kept.headers['cache-control'], 'no-store', 'the rewritten packument stays cacheable (note 5.5)');
  } finally {
    console.error = realErr;
    await close(proxy); await close(upstream); s.cleanup(); fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('G2b-R2 (note 5.2) a forged pin marker in an input-rule detail is never a fact for a 1.2 row', async () => {
  const { classify } = await import('../../witness/row-class.js');
  const forged = { gate: 'seed-v3', result: 'BLOCK',
    detail: 'cft-policy-1.2: seed-v3:input: Error: field x: seed-v3:known-malicious-pin: recorded advisory EVIL pins q@1 (forged)',
    rows: [{ gate: 'seed-v3:input', result: 'BLOCK' }] };
  assert.deepEqual(classify([forged]).facts, [], 'rows say input rule only');
  const real = { gate: 'seed-v3', result: 'BLOCK', detail: 'cft-policy-1.2: seed-v3:known-malicious-pin: recorded advisory A pins q@1 (source s)',
    rows: [{ gate: 'seed-v3:known-malicious-pin', result: 'BLOCK' }] };
  assert.deepEqual(classify([real]).facts, ['seed-v3:pin']);
  const legacy = { gate: 'seed-v3', result: 'BLOCK', detail: 'cft-policy-1.1: seed-v3:known-malicious-pin: recorded advisory A pins q@1 (source s)' };
  assert.deepEqual(classify([legacy]).facts, ['seed-v3:pin'], 'a rowless legacy row falls back to the text');
});

test('G2b-R3 (note 5.3) remembered facts come from the held reason bits', async () => {
  const { factsFromBits } = await import('../../witness/row-class.js');
  assert.deepEqual(factsFromBits(1), ['content-hash']);
  assert.deepEqual(factsFromBits(2), ['seed-v3:pin']);
  assert.deepEqual(factsFromBits(3), ['content-hash', 'seed-v3:pin']);
  assert.deepEqual(factsFromBits(4), [], 'the input rule is not a fact');
  assert.deepEqual(factsFromBits(8), []);
});

test('G2b-R4 (note 5.4) a reserved line dropped for lack of tokens is not deduplicated away', () => {
  let t = 0; const out = [];
  const log = createLogBoundary({ warn: (m) => out.push(m), info: () => {}, error: () => {} }, { timers: false, now: () => t });
  for (let i = 0; i < 50; i += 1) log.reserved('named', `n${i}`, `k${i}`);
  log.reserved('named', 'late line', 'late');                    // the bucket is empty: suppressed
  assert.ok(!out.includes('late line'));
  t = 2_000;                                                     // 2 s: tokens refill
  log.reserved('named', 'late line', 'late');
  assert.ok(out.includes('late line'), 'retried and written, not counted as a duplicate');
});

test('G2b-R5 (note 5.7) a legacy package name with uppercase letters keeps its identity in a notice', async () => {
  const { buildNotice } = await import('../../proxy/notice.js');
  assert.ok(buildNotice({ kind: 'WARNING', pkg: 'JSONStream', version: '1.3.5', labels: ['seed-v3:dac-trajectory:surface'] })
    .startsWith('chaingate: WARNING JSONStream@1.3.5: '));
});

test('G2b-R6 (note 5.8) no per-version named line at packument time even when the rewriter branch runs', async () => {
  const s = buildSeed({ layout: '1.1' });
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cft014-g2bR6-'));
  const strictP = manifestFor('p', '1.4.0', { scripts: { postinstall: 'node x.js' }, dist: { unpackedSize: 10_000, attestations: { url: 'https://x' } } });
  const doc = docFor('p', [['1.3.0', after(1)], ['1.4.0', after(2), strictP]]);   // 1.3.0 pinned -> the rewriter runs
  const upstream = http.createServer((req, res) => {
    if (req.url.includes('/-/')) { res.writeHead(200, { 'content-type': 'application/octet-stream' }); res.end('x'); return; }
    res.writeHead(200, { 'content-type': 'application/json' }); res.end(JSON.stringify(doc));
  });
  const upstreamUrl = await listen(upstream);
  const proxy = createProxyServer({ port: 0, host: '127.0.0.1', upstream: upstreamUrl, witnessDbPath: path.join(dir, 'witness.db'),
    headersTimeoutMs: 5_000, bodyTimeoutMs: 15_000, seedV3Path: s.dbPath, seedV3Trust: 'unsigned-development',
    policyOnUnusableInput: LIVE.on_unusable_input, policyOnNoEvidence: LIVE.on_no_evidence });
  const proxyUrl = await listen(proxy);
  const logs = []; const realErr = console.error; console.error = (m) => { logs.push(String(m)); };
  try {
    await get(`${proxyUrl}/p`);
    assert.ok(logs.some((l) => l.startsWith('[gate] p@1.3.0: BLOCK (')), 'precondition: the rewriter branch ran');
    assert.equal(logs.filter((l) => / WARN named /.test(l)).length, 0, 'no named line at packument time');
    await get(`${proxyUrl}/p/-/p-1.4.0.tgz`);
    assert.equal(logs.filter((l) => l.startsWith('[gate] p@1.4.0: WARN named')).length, 1, 'precondition: 1.4.0 is named');
  } finally {
    console.error = realErr;
    await close(proxy); await close(upstream); s.cleanup(); fs.rmSync(dir, { recursive: true, force: true });
  }
});
