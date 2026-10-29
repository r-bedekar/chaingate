// Since 0.1.6: the advisory pin overlay. Besides the seed's recorded advisories, the witness store keeps the pins of the
// last accepted pins feed cut; the seed is read first, then the overlay. A pin is a fact and BLOCKs, `allow` lifts it, a
// failed lookup is never "no pin", and a row absent from the next cut is no longer a pin. The feed's own format,
// signature and fetch are not tested here: rows are written to the store directly. Written before the code.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import { openWitnessDB } from '../../witness/db.js';
import POL from '../../seed/v3/policy.js';
import G from '../../seed/v3/gate.js';
import { createGateRunner } from '../../gates/index.js';
import { createProxyServer } from '../../proxy/server.js';
import { runCheck } from '../../cli/commands/check.js';
import { inputFromPackument } from '../../cli/check-record.js';
import { buildSeed, openFixtureSeed, docFor, after, LIVE } from './u05-fixtures.mjs';

const CUT = '2026-10-28T20:00:00Z';
const ROW = { package_name: 'q', version: '1.4.0', advisory_id: 'CG-2026-0001', source: 'chaingate-analyst', record_id: 'rec-17',
  evidence_json: JSON.stringify({ note: 'stage-two loader in postinstall' }), added_at: '2026-10-28T19:00:00Z' };
function withStore(fn) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'pin-overlay-'));
  const db = openWitnessDB(path.join(dir, 'witness.db')); db.applySchema();
  try { return fn(db, dir); } finally { db.close(); fs.rmSync(dir, { recursive: true, force: true }); }
}

// ------------------------------------------------------------------------------------------------ the store
test('PO1 a cut replaces the overlay whole, in one transaction; a failed replace keeps the previous cut', () => {
  withStore((db) => {
    assert.equal(db.advisoryPinFor('q', '1.4.0'), null); assert.equal(db.advisoryPinsFeed(), null);
    db.replaceAdvisoryPins({ cutAt: CUT, digest: 'a'.repeat(64), rows: [ROW, { ...ROW, version: '1.4.1', advisory_id: 'CG-2026-0002' }] });
    const pin = db.advisoryPinFor('q', '1.4.0');
    assert.equal(pin.advisory_id, 'CG-2026-0001'); assert.equal(pin.source, 'chaingate-analyst'); assert.equal(pin.record_id, 'rec-17');
    assert.equal(pin.feed_cut_at, CUT);
    assert.deepEqual({ ...db.advisoryPinsFeed(), accepted_at: null }, { cut_at: CUT, digest: 'a'.repeat(64), rows: 2, accepted_at: null });
    // the next cut drops 1.4.0
    db.replaceAdvisoryPins({ cutAt: '2026-10-28T21:00:00Z', digest: 'b'.repeat(64), rows: [{ ...ROW, version: '1.4.1', advisory_id: 'CG-2026-0002' }] });
    assert.equal(db.advisoryPinFor('q', '1.4.0'), null); assert.equal(db.advisoryPinFor('q', '1.4.1').advisory_id, 'CG-2026-0002');
    // a cut that fails part way (two rows with the same key) changes nothing
    assert.throws(() => db.replaceAdvisoryPins({ cutAt: '2026-10-28T22:00:00Z', digest: 'c'.repeat(64), rows: [ROW, ROW] }));
    assert.equal(db.advisoryPinFor('q', '1.4.1').advisory_id, 'CG-2026-0002'); assert.equal(db.advisoryPinsFeed().digest, 'b'.repeat(64));
  });
});

// ------------------------------------------------------------------------------------------------ the lookup
test('PO2 the seed is read first, then the overlay; an overlay that throws is a failed lookup, never "no pin"', () => {
  const s = buildSeed({ layout: '1.1' }); const seed = openFixtureSeed(s.dbPath);
  try {
    const overlay = (p, v) => (p === 'q' && v === '1.4.0' ? { ...ROW, feed_cut_at: CUT } : null);
    assert.equal(POL.lookupPin(seed, 'q', '1.4.0', overlay).pin.advisory_id, 'CG-2026-0001');
    assert.equal(POL.lookupPin(seed, 'q', '1.4.0', overlay).pin.origin, 'feed');
    assert.equal(POL.lookupPin(seed, 'p', '1.3.0', () => ({ ...ROW, advisory_id: 'X' })).pin.advisory_id, 'ADV-P-130', 'the seed wins');
    assert.equal(POL.lookupPin(seed, 'p', '1.3.0', null).pin.origin, 'seed');
    assert.equal(POL.lookupPin(seed, 'q', '1.4.0').pin, null, 'no overlay: as before');
    const failed = POL.lookupPin(seed, 'q', '1.4.0', () => { throw new Error('store unreadable'); });
    assert.equal(failed.pin, null); assert.match(failed.error.message, /store unreadable/);
  } finally { seed.close(); s.cleanup(); }
});

test('PO3 through the gate: an overlay pin BLOCKs, names the feed record, and the result carries the pin, validated', () => {
  const s = buildSeed({ layout: '1.1' }); const seed = openFixtureSeed(s.dbPath);
  try {
    const doc = docFor('q', [['1.4.0', after(1)]]);
    const pinOverlay = (p, v) => (p === 'q' && v === '1.4.0' ? { ...ROW, feed_cut_at: CUT } : null);
    const out = G.evaluateCandidate(seed, { config: LIVE, domainVersionCount: 'from-packument', pinOverlay }, inputFromPackument(doc, 'q', '1.4.0'));
    assert.equal(out.decision.disposition, 'BLOCK');
    const row = out.decision.results.find((x) => x.gate === POL.PIN_GATE);
    assert.equal(row.detail, 'recorded advisory CG-2026-0001 pins q@1.4.0 (source chaingate-analyst); ChainGate pins feed, record rec-17');
    assert.deepEqual(out.decision.pin, { origin: 'feed', source: 'chaingate-analyst', advisory_id: 'CG-2026-0001', record_id: 'rec-17' });
    const gate = G.createSeedV3Gate({ seed, config: LIVE, domainVersionCount: 'from-packument', pinOverlay });
    const r = createGateRunner({ modules: [gate] })({ ...inputFromPackument(doc, 'q', '1.4.0'), history: [] });
    assert.equal(r.disposition, 'BLOCK'); assert.deepEqual(r.results[0].pin, out.decision.pin, 'the runner keeps a valid pin member');
    // feed text is bounded: anything outside the closed character set is dropped, and long ids are capped
    const hostile = (p, v) => (p === 'q' ? { ...ROW, advisory_id: 'CG\u001b[31m-1', record_id: 'r'.repeat(300), feed_cut_at: CUT } : null);
    const h = G.evaluateCandidate(seed, { config: LIVE, domainVersionCount: 'from-packument', pinOverlay: hostile }, inputFromPackument(doc, 'q', '1.4.0'));
    const hd = h.decision.results.find((x) => x.gate === POL.PIN_GATE).detail;
    assert.ok(!/\u001b/.test(hd)); assert.ok(hd.length < 300, hd.length);
  } finally { seed.close(); s.cleanup(); }
});

// ------------------------------------------------------------------------------------------------ the proxy and check
const listen = (srv) => new Promise((resolve) => { srv.listen(0, '127.0.0.1', () => resolve(`http://127.0.0.1:${srv.address().port}`)); });
const close = (srv) => new Promise((resolve) => { srv.close(() => resolve()); });
const get = (url) => new Promise((resolve, reject) => {
  http.get(url, { agent: false }, (res) => {
    let b = ''; res.setEncoding('utf8'); res.on('data', (x) => { b += x; });
    res.on('end', () => { let json = null; try { json = JSON.parse(b); } catch { /* not JSON */ } resolve({ status: res.statusCode, headers: res.headers, json }); });
  }).on('error', reject);
});

test('PO4 through the proxy: an overlay pin removes the version and refuses its tarball with the analyst wording; the next cut without it clears it; allow lifts it', async () => {
  const s = buildSeed({ layout: '1.1' });
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'pin-overlay-proxy-'));
  const doc = docFor('q', [['1.4.0', after(1)]]);
  const upstream = http.createServer((req, res) => {
    const url = decodeURIComponent(req.url);
    if (url.includes('/-/')) { res.writeHead(200, { 'content-type': 'application/octet-stream' }); res.end('tarball-bytes'); return; }
    if (url === '/q') { res.writeHead(200, { 'content-type': 'application/json' }); res.end(JSON.stringify(doc)); return; }
    res.writeHead(404, { 'content-type': 'application/json' }); res.end('{}');
  });
  const upstreamUrl = await listen(upstream);
  const proxy = createProxyServer({ port: 0, host: '127.0.0.1', upstream: upstreamUrl, witnessDbPath: path.join(dir, 'witness.db'),
    headersTimeoutMs: 5_000, bodyTimeoutMs: 15_000, seedV3Path: s.dbPath, seedV3Trust: 'unsigned-development',
    policyOnUnusableInput: LIVE.on_unusable_input, policyOnNoEvidence: LIVE.on_no_evidence });
  const base = await listen(proxy);
  const realErr = console.error; console.error = () => {};
  try {
    proxy.witnessDb.replaceAdvisoryPins({ cutAt: CUT, digest: 'a'.repeat(64), rows: [ROW] });
    let pk = await get(`${base}/q`);
    assert.ok(!('1.4.0' in pk.json.versions), 'the pinned version is removed from the metadata npm sees');
    const t = await get(`${base}/q/-/q-1.4.0.tgz`);
    assert.equal(t.status, 403);
    assert.equal(t.headers['npm-notice'], 'chaingate: BLOCKED q@1.4.0: a ChainGate analyst record names this version. Details: chaingate why q@1.4.0');
    // the next cut no longer names it: the next evaluation clears the BLOCK
    proxy.witnessDb.replaceAdvisoryPins({ cutAt: '2026-10-28T21:00:00Z', digest: 'b'.repeat(64), rows: [] });
    pk = await get(`${base}/q`);
    assert.ok('1.4.0' in pk.json.versions, 'served again');
    // pinned again, then lifted by an exact-version override
    proxy.witnessDb.replaceAdvisoryPins({ cutAt: '2026-10-28T22:00:00Z', digest: 'c'.repeat(64), rows: [ROW] });
    pk = await get(`${base}/q`); assert.ok(!('1.4.0' in pk.json.versions));
    proxy.witnessDb.insertOverride('q', '1.4.0', 'reviewed: false positive');
    pk = await get(`${base}/q`); assert.ok('1.4.0' in pk.json.versions, 'allow lifts it');
  } finally {
    console.error = realErr; await close(proxy); await close(upstream); s.cleanup(); fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('PO5 check reads the same overlay the proxy uses: an overlay pin is a BLOCK, exit 3, and the record carries the pin', async () => {
  const s = buildSeed({ layout: '1.1' });
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'pin-overlay-check-'));
  try {
    const wdb = path.join(dir, 'w.db');
    const db = openWitnessDB(wdb); db.applySchema(); db.replaceAdvisoryPins({ cutAt: CUT, digest: 'a'.repeat(64), rows: [ROW] }); db.close();
    const pkf = path.join(dir, 'q.json'); fs.writeFileSync(pkf, JSON.stringify(docFor('q', [['1.4.0', after(1)]])));
    const env = { ...process.env, CHAINGATE_HOME: dir, CHAINGATE_SEED_V3: s.dbPath, CHAINGATE_SEED_V3_TRUST: 'unsigned-development',
      CHAINGATE_POLICY_ON_UNUSABLE_INPUT: 'WARN', CHAINGATE_POLICY_ON_NO_EVIDENCE: 'WARN', CHAINGATE_WITNESS_DB: wdb };
    const r = await runCheck({ name: 'q', version: '1.4.0', packument: pkf, env, cwd: dir });
    assert.equal(r.exit, 3); assert.equal(r.record.decision.disposition, 'BLOCK');
    assert.deepEqual(r.record.decision.pin, { origin: 'feed', source: 'chaingate-analyst', advisory_id: 'CG-2026-0001', record_id: 'rec-17' });
  } finally { s.cleanup(); fs.rmSync(dir, { recursive: true, force: true }); }
});

// ------------------------------------------------------------------------------------------------ capture integrity
test('PO6 a capture pin is compared with the registry integrity: matches, differs or absent is recorded; the BLOCK stands in all three', () => {
  const s = buildSeed({ layout: '1.1' }); const seed = openFixtureSeed(s.dbPath);
  try {
    const SRI = `sha512-${'A+/b'.repeat(21)}AB==`; const OTHER = `sha512-${'Zz09'.repeat(21)}AB==`;
    const capture = { ...ROW, advisory_id: 'CHAINGATE-0123456789abcdef', evidence_json: JSON.stringify({ kind: 'capture', sha256: 'a'.repeat(64),
      dist_integrity: SRI, also_advisories: [] }), feed_cut_at: CUT };
    const pinOverlay = (p, v) => (p === 'q' && v === '1.4.0' ? capture : null);
    const run = (integrity) => {
      const doc = docFor('q', [['1.4.0', after(1)]]);
      if (integrity !== undefined) doc.versions['1.4.0'].dist = { ...(doc.versions['1.4.0'].dist ?? {}), integrity };
      else if (doc.versions['1.4.0'].dist) delete doc.versions['1.4.0'].dist.integrity;
      return G.evaluateCandidate(seed, { config: LIVE, domainVersionCount: 'from-packument', pinOverlay }, inputFromPackument(doc, 'q', '1.4.0')).decision;
    };
    const words = { matches: /; the registry integrity matches the analysed tarball$/,
      differs: /; WARNING: the registry's integrity for this version differs from the analysed tarball$/, absent: /; no integrity in the metadata$/ };
    for (const [integrity, want] of [[SRI, 'matches'], [`${OTHER} sha1-abc=`, 'differs'], [`sha1-abc= ${SRI}`, 'matches'], [undefined, 'absent']]) {
      const d = run(integrity);
      assert.equal(d.disposition, 'BLOCK', want);
      assert.equal(d.pin.integrity, want);
      assert.match(d.results.find((x) => x.gate === POL.PIN_GATE).detail, words[want]);
    }
    // an advisory pin (not a capture) carries no comparison
    const adv = G.evaluateCandidate(seed, { config: LIVE, domainVersionCount: 'from-packument', pinOverlay: () => ({ ...ROW, source: 'osv',
      advisory_id: 'MAL-2026-1', evidence_json: JSON.stringify({ kind: 'advisory', advisory_id: 'MAL-2026-1' }), feed_cut_at: CUT }) },
    inputFromPackument(docFor('q', [['1.4.0', after(1)]]), 'q', '1.4.0')).decision;
    assert.equal(adv.pin.integrity, undefined);
    // the runner keeps the member; a bad value is dropped with the whole member
    const gate = G.createSeedV3Gate({ seed, config: LIVE, domainVersionCount: 'from-packument', pinOverlay });
    const r = createGateRunner({ modules: [gate] })({ ...inputFromPackument(docFor('q', [['1.4.0', after(1)]]), 'q', '1.4.0'), history: [] });
    assert.ok(['matches', 'differs', 'absent'].includes(r.results[0].pin.integrity));
  } finally { seed.close(); s.cleanup(); }
});
