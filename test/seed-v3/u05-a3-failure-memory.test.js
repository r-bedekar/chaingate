// U-05 Amendment 3 (owner decision 2, 2026-10-01): Table F (P3/P5b/P6a follow the configured failure policy and never
// weaken a known BLOCK), Table M (P6b: the proxy remembers BLOCKs it computed but could not store) and O1 (reporting
// after observation can never replace the returned decisions). Expected results come from the Amendment 3 tables,
// written before this file; the tests were run failing-first on a1e7a4d.
//
// Fixture: the U-05 synthetic seed (p@1.3.0 pinned ADV-P-130; p@1.4.0 and q@1.3.0 unpinned), a loopback registry that
// serves packuments and tarball bytes, and a SQLite trigger inside the proxy's own witness database that aborts the
// decision write for p@1.3.0 -- a BLOCK computed but not stored. Faults elsewhere are injected by wrapping methods of
// the proxy's own witness objects (`proxy.witness`, `proxy.witnessDb`, `proxy.seedV3`).
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import { createProxyServer } from '../../proxy/server.js';
import { buildSeed, docFor, manifestFor, after, failPinLookup, LIVE, WARNCFG } from './u05-fixtures.mjs';

const listen = (srv) => new Promise((resolve) => { srv.listen(0, '127.0.0.1', () => resolve(`http://127.0.0.1:${srv.address().port}`)); });
const close = (srv) => new Promise((resolve) => { srv.close(() => resolve()); });
const get = (url) => new Promise((resolve, reject) => {
  http.get(url, { agent: false }, (res) => {
    let b = ''; res.setEncoding('utf8'); res.on('data', (x) => { b += x; });
    res.on('end', () => { let json = null; try { json = JSON.parse(b); } catch { /* not JSON */ } resolve({ status: res.statusCode, json, body: b }); });
  }).on('error', reject);
});
const versionsOf = (r) => Object.keys(r.json?.versions ?? {});
const tgz = (name, v) => `/${name}/-/${name.split('/').pop()}-${v}.tgz`;
const TRIGGER = (pkg, ver) => `CREATE TRIGGER u05_a3_${pkg.replace(/\W/g, '_')} BEFORE INSERT ON gate_decisions
  WHEN NEW.package_name = '${pkg}'${ver ? ` AND NEW.version = '${ver}'` : ''} BEGIN SELECT RAISE(ABORT, 'injected write failure'); END;`;

const DOCS = () => ({
  p: docFor('p', [['1.3.0', after(1)], ['1.4.0', after(2)]]),
  q: docFor('q', [['1.3.0', after(1)]]),
  x: docFor('x', [['2.0.0', after(1)]]),
});

/**
 * One proxy on a loopback registry. `cfg` = LIVE | WARNCFG (seed-v3 configured) or null (pilot gates only, given by
 * `gateModules`). `dir` lets a second proxy reuse the same witness database (a restart).
 */
async function withProxy({ cfg = LIVE, gateModules = null, docs = DOCS(), rawBodies = {}, dir = null, seed = null }, fn) {
  const ownSeed = cfg && !seed ? buildSeed({ layout: '1.1' }) : null;
  const s = seed ?? ownSeed;
  const wdir = dir ?? fs.mkdtempSync(path.join(os.tmpdir(), 'u05-a3-'));
  const fetches = [];
  const upstream = http.createServer((req, res) => {
    const url = decodeURIComponent(req.url);
    fetches.push(url);
    if (url.includes('/-/')) { res.writeHead(200, { 'content-type': 'application/octet-stream' }); res.end('tarball-bytes'); return; }
    if (rawBodies[url.slice(1)] !== undefined) { res.writeHead(200, { 'content-type': 'application/json' }); res.end(rawBodies[url.slice(1)]); return; }
    const d = docs[url.slice(1)];
    if (!d) { res.writeHead(404, { 'content-type': 'application/json' }); res.end('{}'); return; }
    res.writeHead(200, { 'content-type': 'application/json' }); res.end(JSON.stringify(d));
  });
  const upstreamUrl = await listen(upstream);
  const conf = { port: 0, host: '127.0.0.1', upstream: upstreamUrl, witnessDbPath: path.join(wdir, 'witness.db'),
    headersTimeoutMs: 5_000, bodyTimeoutMs: 15_000 };
  if (cfg) Object.assign(conf, { seedV3Path: s.dbPath, seedV3Trust: 'unsigned-development',
    policyOnUnusableInput: cfg.on_unusable_input, policyOnNoEvidence: cfg.on_no_evidence });
  const proxy = createProxyServer(conf, gateModules ? { gateModules } : {});
  const proxyUrl = await listen(proxy);
  const logs = []; const realErr = console.error;
  console.error = (m) => { logs.push(String(m)); };
  try {
    return await fn({ proxy, proxyUrl, fetches, logs, dir: wdir, seed: s });
  } finally {
    console.error = realErr;
    await close(proxy); await close(upstream);
    if (!dir && !seed) { ownSeed?.cleanup(); fs.rmSync(wdir, { recursive: true, force: true }); }
  }
}
const self = async (u) => (await get(`${u}/_chaingate/self`)).json;

/** p@1.3.0's pin BLOCK computed but not stored: returns after the packument request that remembered it. */
async function rememberPinned({ proxy, proxyUrl }) {
  proxy.witnessDb.db.exec(TRIGGER('p', '1.3.0'));
  const r = await get(`${proxyUrl}/p`);
  assert.equal(r.status, 200);
  assert.ok(!versionsOf(r).includes('1.3.0'), 'the packument omits the pinned version');
  assert.equal(proxy.witnessDb.getLatestDecision('p', '1.3.0'), null, 'and nothing was stored for it');
}

// A pilot gate for the pilot-only cases. Named `content-hash` only because that name is exempt from the thin-history
// SKIP (gates/index.js HISTORY_INDEPENDENT_GATES); it is a test gate, not the real content-hash module.
const scriptedGate = (verdicts) => ({ name: 'content-hash', evaluate: (input) => {
  const v = verdicts(input);
  return v ? { gate: 'content-hash', result: v, detail: `scripted ${v} for ${input.packageName}@${input.version}` }
    : { gate: 'content-hash', result: 'ALLOW', detail: 'scripted ALLOW' };
} });

// ---------------------------------------------------------------- Table M (P6b)
test('M1 isolation: a remembered BLOCK refuses exactly that name@version tarball', async () => {
  for (const cfg of [LIVE, WARNCFG]) {
    await withProxy({ cfg }, async (h) => {
      await rememberPinned(h);
      const r = await get(`${h.proxyUrl}${tgz('p', '1.3.0')}`);
      assert.equal(r.status, 403, 'p@1.3.0 tarball refused');
      assert.equal(r.json?.error, 'blocked_by_chaingate');
      for (const [n, v] of [['p', '1.4.0'], ['q', '1.3.0'], ['p', '1.3.0-beta'], ['@s/p', '1.3.0']]) {
        const o = await get(`${h.proxyUrl}${tgz(n, v)}`);
        assert.notEqual(o.status, 403, `${n}@${v} is not affected`);
      }
    });
  }
});

test('M2 overrides are checked live; an override ALLOW keeps the entry; removing the override restores the BLOCK', async () => {
  for (const cfg of [LIVE, WARNCFG]) {
    await withProxy({ cfg }, async (h) => {
      await rememberPinned(h);
      h.proxy.witnessDb.insertOverride('p', '1.3.0', 'operator exception for the test');
      assert.equal((await get(`${h.proxyUrl}${tgz('p', '1.3.0')}`)).status, 200, 'override: allowed');
      const again = await get(`${h.proxyUrl}/p`);                   // the override ALLOW, combined with the write failure
      // A1-OV (ratified; as 0.1.2): on a write-failure path the failure declaration still applies to an overridden
      // version -- LIVE blocks it in the packument, WARN serves it. The tarball gate honours the override live.
      assert.equal(versionsOf(again).includes('1.3.0'), cfg.on_unusable_input !== 'BLOCK',
        `${cfg.on_unusable_input}: the packument follows A1-OV for the overridden version`);
      assert.equal((await self(h.proxyUrl)).unstored_blocks?.count, 1, 'the override ALLOW did not erase the entry');
      h.proxy.witnessDb.deleteOverride('p', '1.3.0');
      assert.equal((await get(`${h.proxyUrl}${tgz('p', '1.3.0')}`)).status, 403, 'override removed: refused again');
    });
  }
});

test('M3 persistence: a stored BLOCK replaces the entry; an evaluated unstored ALLOW supersedes it', async () => {
  await withProxy({ cfg: LIVE }, async (h) => {
    await rememberPinned(h);
    assert.equal((await self(h.proxyUrl)).unstored_blocks?.count, 1);
    h.proxy.witnessDb.db.exec('DROP TRIGGER u05_a3_p');               // storage works again
    await get(`${h.proxyUrl}/p`);
    assert.equal(h.proxy.witnessDb.getLatestDecision('p', '1.3.0')?.disposition, 'BLOCK', 'now stored');
    assert.equal((await self(h.proxyUrl)).unstored_blocks?.count, 0, 'and forgotten from memory');
    assert.equal((await get(`${h.proxyUrl}${tgz('p', '1.3.0')}`)).status, 403, 'still refused, through the database');
  });
  let calls = 0;
  const gate = scriptedGate((i) => (i.packageName === 'x' && i.version === '2.0.0' ? (calls++ === 0 ? 'BLOCK' : 'ALLOW') : null));
  await withProxy({ cfg: null, gateModules: [gate] }, async (h) => {
    h.proxy.witnessDb.db.exec(TRIGGER('x', '2.0.0'));
    await get(`${h.proxyUrl}/x`);
    assert.equal((await get(`${h.proxyUrl}${tgz('x', '2.0.0')}`)).status, 403, 'pilot BLOCK remembered');
    await get(`${h.proxyUrl}/x`);                                      // evaluated ALLOW, not stored
    assert.equal((await self(h.proxyUrl)).unstored_blocks?.count, 0, 'the newer evaluated decision governs');
    assert.equal((await get(`${h.proxyUrl}${tgz('x', '2.0.0')}`)).status, 200);
  });
});

test('M4 a failure decision never erases a remembered BLOCK (WARN policy), and Rule K keeps it out of the packument', async () => {
  await withProxy({ cfg: WARNCFG }, async (h) => {
    await rememberPinned(h);
    h.proxy.witness.observePackument = () => { throw new Error('injected observation failure'); };
    failPinLookup(h.proxy.seedV3);                                     // the failure decision cannot name the advisory
    const r = await get(`${h.proxyUrl}/p`);
    assert.equal(r.status, 200);
    assert.ok(!versionsOf(r).includes('1.3.0'), 'the known BLOCK stays out of the packument (Rule K)');
    assert.ok(versionsOf(r).includes('1.4.0'), 'the failure decision (WARN) still serves the rest');
    assert.equal((await get(`${h.proxyUrl}${tgz('p', '1.3.0')}`)).status, 403, 'and its tarball is still refused');
  });
});

test('M5 capacity: no eviction; every remembered BLOCK stays enforced; the count is reported', async () => {
  const N = 5000;
  const versions = {}; const time = {};
  for (let i = 0; i < N; i += 1) { const v = `1.0.${i}`; versions[v] = manifestFor('big', v); time[v] = after(1 + i / N); }
  const docs = { ...DOCS(), big: { name: 'big', 'dist-tags': { latest: `1.0.${N - 1}` }, versions, time } };
  const gate = scriptedGate((i) => (i.packageName === 'big' ? 'BLOCK' : null));
  await withProxy({ cfg: null, gateModules: [gate], docs }, async (h) => {
    h.proxy.witnessDb.db.exec(TRIGGER('big'));
    await get(`${h.proxyUrl}/big`);
    assert.equal((await self(h.proxyUrl)).unstored_blocks?.count, N);
    for (const v of ['1.0.0', `1.0.${N >> 1}`, `1.0.${N - 1}`]) {
      assert.equal((await get(`${h.proxyUrl}${tgz('big', v)}`)).status, 403, `big@${v} still refused`);
    }
  });
});

test('M6 restart forgets (documented P6c gap) and the next packument request remembers again', async () => {
  const seed = buildSeed({ layout: '1.1' });
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'u05-a3-restart-'));
  try {
    await withProxy({ cfg: LIVE, dir, seed }, async (h) => { await rememberPinned(h); });
    await withProxy({ cfg: LIVE, dir, seed }, async (h) => {        // same witness database: the trigger is still there
      assert.equal((await self(h.proxyUrl)).unstored_blocks?.count, 0, 'a new process remembers nothing');
      assert.equal((await get(`${h.proxyUrl}${tgz('p', '1.3.0')}`)).status, 200, 'direct tarball before any packument: P6c');
      await get(`${h.proxyUrl}/p`);
      assert.equal((await get(`${h.proxyUrl}${tgz('p', '1.3.0')}`)).status, 403, 'remembered again after re-evaluation');
    });
  } finally { seed.cleanup(); fs.rmSync(dir, { recursive: true, force: true }); }
});

test('M7 diagnostics: the count, the 403 says not stored, and the remember line is logged', async () => {
  await withProxy({ cfg: LIVE }, async (h) => {
    await rememberPinned(h);
    const s = await self(h.proxyUrl);
    assert.equal(s.unstored_blocks?.count, 1);
    assert.match(s.unstored_blocks?.note ?? '', /not stored/i);
    const r = await get(`${h.proxyUrl}${tgz('p', '1.3.0')}`);
    assert.equal(r.json?.persisted, false);
    assert.match(r.json?.detail ?? '', /not stored/i);
    assert.ok(h.logs.some((l) => /p@1\.3\.0/.test(l) && /NOT stored/.test(l)), 'the remember line names p@1.3.0');
  });
});

// ---------------------------------------------------------------- Table F (P3, P5b, P6a)
test('F1 P3 (no decision at all): LIVE refuses; WARN serves without remembered BLOCKs; pilot-only serves raw', async () => {
  const breakBoth = (h) => {
    h.proxy.witness.observePackument = () => { throw new Error('injected observation failure'); };
    h.proxy.witness.failureDecisionsFor = () => { throw new Error('injected failure-decision failure'); };
  };
  await withProxy({ cfg: LIVE }, async (h) => {
    breakBoth(h);
    const r = await get(`${h.proxyUrl}/p`);
    assert.equal(r.status, 502); assert.equal(r.json?.error, 'chaingate_enforcement_failed');
  });
  await withProxy({ cfg: WARNCFG }, async (h) => {
    await rememberPinned(h);
    breakBoth(h);
    const r = await get(`${h.proxyUrl}/p`);
    assert.equal(r.status, 200);
    assert.ok(!versionsOf(r).includes('1.3.0') && versionsOf(r).includes('1.4.0'), 'only the remembered BLOCK is removed');
    const q = await get(`${h.proxyUrl}/q`);
    assert.ok(versionsOf(q).includes('1.3.0'), 'nothing remembered for q: served as received');
  });
  await withProxy({ cfg: null, gateModules: [scriptedGate(() => null)] }, async (h) => {
    breakBoth(h);
    const r = await get(`${h.proxyUrl}/x`);
    assert.equal(r.status, 200); assert.ok(versionsOf(r).includes('2.0.0'), 'pilot-only: unchanged');
  });
});

test('F2 P5b (an error escapes before any decision): LIVE refuses; WARN refuses only with a remembered BLOCK', async () => {
  const unreadable = (h) => {
    h.proxy.witness.observePackument = () => ({ versionsSeen: 0, newBaselines: 0,
      get decisions() { throw new Error('injected: decisions unreadable'); } });
  };
  await withProxy({ cfg: LIVE }, async (h) => {
    unreadable(h);
    const r = await get(`${h.proxyUrl}/p`);
    assert.equal(r.status, 502); assert.equal(r.json?.error, 'chaingate_enforcement_failed');
  });
  await withProxy({ cfg: WARNCFG }, async (h) => {
    unreadable(h);
    const q = await get(`${h.proxyUrl}/q`);
    assert.equal(q.status, 200, 'WARN, nothing known: passthrough as before');
  });
  await withProxy({ cfg: WARNCFG }, async (h) => {
    await rememberPinned(h);
    unreadable(h);
    const r = await get(`${h.proxyUrl}/p`);
    assert.equal(r.status, 502, 'WARN with a remembered BLOCK: no raw passthrough');
    assert.ok(!versionsOf(r).includes('1.3.0'));
  });
});

test('F3 P6a (the stored-decision lookup throws): a remembered BLOCK is refused; otherwise the configured policy', async () => {
  for (const [cfg, unknownStatus] of [[LIVE, 503], [WARNCFG, 200]]) {
    await withProxy({ cfg }, async (h) => {
      await rememberPinned(h);
      h.proxy.witnessDb.getLatestDecision = () => { throw new Error('injected lookup failure'); };
      const known = await get(`${h.proxyUrl}${tgz('p', '1.3.0')}`);
      assert.equal(known.status, 403, `${cfg.on_unusable_input}: the remembered BLOCK is refused`);
      const unknown = await get(`${h.proxyUrl}${tgz('p', '1.4.0')}`);
      assert.equal(unknown.status, unknownStatus, `${cfg.on_unusable_input}: unknown version follows the policy`);
      if (unknownStatus === 503) assert.equal(unknown.json?.error, 'chaingate_decision_lookup_failed');
    });
  }
});

test('F4 P5b tarball (an error before the gate decided): LIVE refuses; WARN passes through unless remembered', async () => {
  const brokenRecord = (h) => {
    h.proxy.witnessDb.getLatestDecision = () => ({ get disposition() { throw new Error('injected: decision record unreadable'); } });
  };
  await withProxy({ cfg: LIVE }, async (h) => {
    brokenRecord(h);
    const r = await get(`${h.proxyUrl}${tgz('p', '1.4.0')}`);
    assert.equal(r.status, 502); assert.equal(r.json?.error, 'chaingate_enforcement_failed');
  });
  await withProxy({ cfg: WARNCFG }, async (h) => {
    await rememberPinned(h);
    brokenRecord(h);
    assert.equal((await get(`${h.proxyUrl}${tgz('p', '1.3.0')}`)).status, 403, 'remembered: refused');
    assert.equal((await get(`${h.proxyUrl}${tgz('p', '1.4.0')}`)).status, 200, 'not remembered: passthrough as before');
  });
});

test('F5 P1 (pins): a non-JSON packument body is relayed unchanged under every policy', async () => {
  for (const cfg of [LIVE, WARNCFG]) {
    await withProxy({ cfg, rawBodies: { n: 'this is not JSON' } }, async (h) => {
      const r = await get(`${h.proxyUrl}/n`);
      assert.equal(r.status, 200, `${cfg.on_unusable_input}: relayed`);
      assert.equal(r.body, 'this is not JSON', `${cfg.on_unusable_input}: byte-for-byte as received`);
    });
  }
});

// ---------------------------------------------------------------- O1
test('O1 a returned BLOCK survives a failure while reporting the observation, under both input policies', async () => {
  for (const cfg of [LIVE, WARNCFG]) {
    await withProxy({ cfg }, async (h) => {
      const real = h.proxy.witness.observePackument.bind(h.proxy.witness);
      h.proxy.witness.observePackument = (name, doc) => {
        const r = real(name, doc);
        const decisions = new Map(r.decisions);
        if (name === 'p') decisions.set('1.4.0', { disposition: 'BLOCK', results: [{ gate: 'u05-o1', result: 'BLOCK', detail: 'a computed BLOCK' }] });
        return { decisions, newBaselines: r.newBaselines, get versionsSeen() { throw new Error('injected reporting failure'); } };
      };
      const r = await get(`${h.proxyUrl}/p`);
      assert.equal(r.status, 200, cfg.on_unusable_input);
      assert.ok(!versionsOf(r).includes('1.4.0'), `${cfg.on_unusable_input}: the returned BLOCK is enforced`);
      assert.ok(versionsOf(r).includes('1.2.0'), `${cfg.on_unusable_input}: the returned decisions were not replaced`);
    });
  }
});
