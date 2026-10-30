// 0.1.5 per-version entry facts store (operator ruling R4 2026-10-21, option (a); design FOLLOWUPS #24). On every download, armed
// or not, the proxy keeps the bodies of the main and bin targets, computes the fileFacts summary of each and stores it once per
// served version in witness.db: role, path, size, sha256, the closed-vocabulary facts, and whether the file was read. S7 (R3)
// compares a version's entry files with those of the last version this proxy served before it; with none stored it is a cold start.
// Retention: the newest 3 served versions per package, and at most 200,000 served versions in all. Failing first: written before
// the code. Tarballs are synthetic; nothing is run.
import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import zlib from 'node:zlib';
import Database from 'better-sqlite3';
import { createProxyServer } from '../../proxy/server.js';
import { resetDependencyCache } from '../../gates/dependency-cache.js';
import { forgetManifestHooks } from '../../proxy/manifest-check.js';
import { openWitnessDB } from '../../witness/db.js';

const SC = () => import('../../proxy/static-checks.js');

const H = 3_600_000; const T0 = Date.parse('2026-03-01T00:00:00Z'); const at = (h) => new Date(T0 + h * H).toISOString();
function hdr(name, size) {
  const h = Buffer.alloc(512, 0); Buffer.from(name, 'utf8').copy(h, 0, 0, 100);
  h.write('0000644\0', 100); h.write('0000000\0', 108); h.write('0000000\0', 116); h.write(`${size.toString(8).padStart(11, '0')}\0`, 124, 'latin1');
  h.write('00000000000\0', 136); h.write('        ', 148); h.write('0', 156, 'latin1'); h.write('ustar\0', 257, 'latin1'); h.write('00', 263, 'latin1');
  let sum = 0; for (let i = 0; i < 512; i += 1) sum += h[i]; h.write(`${sum.toString(8).padStart(6, '0')}\0 `, 148, 'latin1'); return h;
}
const pad = (b) => Buffer.concat([b, Buffer.alloc((512 - (b.length % 512)) % 512, 0)]);
const tgz = (files) => zlib.gzipSync(Buffer.concat([...Object.entries(files).flatMap(([p, c]) => [hdr(`package/${p}`, Buffer.byteLength(c)), pad(Buffer.from(c))]), Buffer.alloc(1024, 0)]));
const sha = (s) => crypto.createHash('sha256').update(s).digest('hex');
const BENIGN = 'module.exports = 1;\n';
const NETTY = 'const https = require("https");\nhttps.request({ host: "h" }).end(require("os").hostname());\n';
const FACT_KEYS = ['binary', 'net_sinks', 'exec_sinks', 'obf_idents', 'decode_markers', 'hex_density', 'numeric_hex', 'cred_sources', 'sinks', 'overrides',
  'address_families', 'host_identity', 'dns_exfil'];   // dns_exfil: 1.9, a boolean (cft016-static-checks-1.9)

// g: two plain versions, nothing named or contributing -> NOT armed; main index.js, one bin
const G = { name: 'g', 'dist-tags': { latest: '1.1.0' }, time: { '1.0.0': at(0), '1.1.0': at(48) },
  versions: { '1.0.0': { name: 'g', version: '1.0.0', main: 'index.js', bin: { g: 'cli.js' } }, '1.1.0': { name: 'g', version: '1.1.0', main: 'index.js', bin: { g: 'cli.js' } } } };
const DOCS = { '/g': G };
const TARBALLS = {
  '/g/-/g-1.0.0.tgz': tgz({ 'package.json': JSON.stringify(G.versions['1.0.0']), 'index.js': BENIGN, 'cli.js': BENIGN }),
  '/g/-/g-1.1.0.tgz': tgz({ 'package.json': JSON.stringify(G.versions['1.1.0']), 'index.js': NETTY, 'cli.js': BENIGN }),
};
async function withProxy(fn) {
  resetDependencyCache(); forgetManifestHooks();
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cft015-ef-'));
  const upstream = http.createServer((req, res) => {
    const u = decodeURIComponent(req.url.split('?')[0]);
    if (TARBALLS[u]) { res.writeHead(200, { 'content-type': 'application/octet-stream' }); res.end(TARBALLS[u]); return; }
    if (DOCS[u]) { res.writeHead(200, { 'content-type': 'application/json' }); res.end(JSON.stringify(DOCS[u])); return; }
    res.writeHead(404, { 'content-type': 'application/json' }); res.end('{}');
  });
  await new Promise((r) => upstream.listen(0, '127.0.0.1', r));
  const proxy = createProxyServer({ port: 0, host: '127.0.0.1', upstream: `http://127.0.0.1:${upstream.address().port}`,
    witnessDbPath: path.join(dir, 'witness.db'), headersTimeoutMs: 10_000, bodyTimeoutMs: 10_000 });
  await new Promise((r) => proxy.listen(0, '127.0.0.1', r));
  const base = `http://127.0.0.1:${proxy.address().port}`;
  try { return await fn({ base, proxy }); } finally {
    await new Promise((r) => proxy.close(r)); await new Promise((r) => upstream.close(r)); fs.rmSync(dir, { recursive: true, force: true });
    resetDependencyCache(); forgetManifestHooks();
  }
}
const get = (u) => new Promise((resolve, reject) => http.get(u, { agent: false }, (res) => {
  const chunks = []; res.on('data', (x) => chunks.push(x)); res.on('end', () => resolve({ status: res.statusCode, body: Buffer.concat(chunks) }));
}).on('error', reject));
const settle = () => new Promise((r) => setTimeout(r, 200));
function withDb(fn) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cft015-efdb-'));
  const db = openWitnessDB(path.join(dir, 'witness.db')); db.applySchema();
  try { return fn(db, dir); } finally { db.close(); fs.rmSync(dir, { recursive: true, force: true }); }
}
const rec = (version, files = [{ role: 'main', path: 'index.js', state: 'read', size_bytes: 20, sha256: sha(BENIGN), facts: { net_sinks: [] } }], extra = {}) =>
  ({ package_name: 'a', version, walk: 'read', reason: null, static_checks_version: 'static-checks-1.3', files, ...extra });

// ------------------------------------------------------------------ the store (witness/db.js)
test('EF-U1 recordEntryFacts writes once per version; hasEntryFacts and the predecessor read it back', () => withDb((db) => {
  assert.equal(db.hasEntryFacts('a', '1.0.0'), false);
  assert.equal(db.recordEntryFacts(rec('1.0.0')), 'wrote');
  assert.equal(db.hasEntryFacts('a', '1.0.0'), true);
  assert.equal(db.recordEntryFacts(rec('1.0.0', [])), 'exists', 'tarballs are immutable per version: a second write changes nothing');
  assert.equal(db.predecessorEntryFacts('a', '1.0.0'), null, 'cold start: no other version served');
  assert.equal(db.recordEntryFacts(rec('1.1.0')), 'wrote');
  const p = db.predecessorEntryFacts('a', '1.1.0');
  assert.equal(p.version, '1.0.0'); assert.equal(p.walk, 'read'); assert.equal(p.static_checks_version, 'static-checks-1.3');
  assert.equal(p.files.length, 1);
  assert.deepEqual({ ...p.files[0], facts: p.files[0].facts }, { role: 'main', path: 'index.js', state: 'read', size_bytes: 20, sha256: sha(BENIGN), facts: { net_sinks: [] }, reason: null });
  assert.equal(db.predecessorEntryFacts('b', '1.0.0'), null, 'another package is never a predecessor');
}));

test('EF-U2 the predecessor is the last version SERVED before, by serving order, not by version number', () => withDb((db) => {
  db.recordEntryFacts(rec('2.0.0')); db.recordEntryFacts(rec('1.5.0'));
  assert.equal(db.predecessorEntryFacts('a', '3.0.0').version, '1.5.0');
  assert.equal(db.predecessorEntryFacts('a', '1.5.0').version, '2.0.0', 'the current version itself is never its own predecessor');
}));

test('EF-U3 a refused archive is stored as such, with no files, so S7 can say NOT_CHECKED rather than a clean delta', () => withDb((db) => {
  db.recordEntryFacts(rec('1.0.0', [], { walk: 'refused', reason: 'tar: truncated archive' }));
  const p = db.predecessorEntryFacts('a', '1.1.0');
  assert.equal(p.walk, 'refused'); assert.equal(p.reason, 'tar: truncated archive'); assert.deepEqual(p.files, []);
}));

test('EF-U4 retention: the newest 3 served versions per package are kept; a global cap prunes the oldest served first', () => withDb((db) => {
  for (const v of ['1.0.0', '1.1.0', '1.2.0', '1.3.0', '1.4.0']) db.recordEntryFacts(rec(v));
  assert.deepEqual(['1.0.0', '1.1.0', '1.2.0', '1.3.0', '1.4.0'].map((v) => db.hasEntryFacts('a', v)), [false, false, true, true, true]);
  for (const v of ['1.0.0', '1.1.0']) db.recordEntryFacts({ ...rec(v), package_name: 'b' }, { maxVersions: 4 });
  assert.equal(db.hasEntryFacts('a', '1.2.0'), false, 'over the global cap: the oldest served version goes first');
  assert.equal(db.hasEntryFacts('b', '1.1.0'), true);
  assert.equal(db.hasEntryFacts('a', '1.4.0'), true);
}));

test('EF-U5 a witness.db written by an older runtime (no entry facts tables) reads as empty and never throws', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cft015-efold-'));
  try {
    const p = path.join(dir, 'w.db'); new Database(p).close();
    const db = openWitnessDB(p, { readonly: true });
    try { assert.equal(db.hasEntryFacts('a', '1.0.0'), false); assert.equal(db.predecessorEntryFacts('a', '1.0.0'), null); } finally { db.close(); }
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

// ------------------------------------------------------------------ the facts of one walk (proxy/static-checks.js)
test('EF-U6 entryFactsOf: one entry per main and bin target, read with sha256 and closed-vocabulary facts, or not read with its reason', async () => {
  const S = await SC();
  const manifest = { name: 'g', main: 'index.js', bin: { g: 'cli.js', h: 'big.js' } };
  const walk = { ok: true, files: [{ path: 'index.js', buf: Buffer.from(NETTY) }],
    notKept: [{ path: 'big.js', reason: 'over the kept-file cap (1048576 bytes)', size: 2_000_000 }, { path: 'cli.js', reason: 'not in the archive' }] };
  const out = S.entryFactsOf({ manifest, walk });
  assert.equal(out.walk, 'read');
  const main = out.files.find((f) => f.role === 'main');
  assert.equal(main.path, 'index.js'); assert.equal(main.state, 'read'); assert.equal(main.size_bytes, Buffer.byteLength(NETTY)); assert.equal(main.sha256, sha(NETTY));
  assert.deepEqual(Object.keys(main.facts).sort(), [...FACT_KEYS].sort(), 'facts only: never the path, the size or text from the body');
  assert.ok(main.facts.net_sinks.length > 0, JSON.stringify(main.facts));
  const big = out.files.find((f) => f.path === 'big.js');
  assert.equal(big.role, 'bin'); assert.equal(big.state, 'not-read'); assert.equal(big.size_bytes, 2_000_000); assert.equal(big.sha256, null); assert.equal(big.facts, null);
  assert.match(big.reason, /kept-file cap/);
  const cli = out.files.find((f) => f.path === 'cli.js');
  assert.equal(cli.state, 'absent');
  assert.deepEqual(S.entryFactsOf({ manifest, walk: { ok: false, reason: 'tar: truncated archive' } }), { walk: 'refused', reason: 'tar: truncated archive', files: [] });
});

test('EF-U7 entryKeepFor lists only main and bin targets (with node-resolution variants for main), never hook targets', async () => {
  const S = await SC();
  const keep = S.entryKeepFor({ name: 'g', main: './lib/x', bin: 'cli.js', scripts: { postinstall: 'node install.js' } });
  assert.ok(keep.includes('lib/x') && keep.includes('lib/x.js') && keep.includes('cli.js'), JSON.stringify(keep));
  assert.ok(!keep.includes('install.js'));
  assert.ok(S.entryKeepFor(null).includes('index.js'), 'no manifest at all: main defaults to index.js');
});

// ------------------------------------------------------------------ the proxy (every download, armed or not)
test('EF-E1 an UNARMED download stores its entry facts once; the next version finds it as predecessor; a repeat writes nothing', async () => {
  await withProxy(async ({ base, proxy }) => {
    await get(`${base}/g`);
    const t = await get(`${base}/g/-/g-1.0.0.tgz`); assert.equal(t.status, 200); assert.ok(t.body.equals(TARBALLS['/g/-/g-1.0.0.tgz']));
    await settle();
    assert.equal(proxy.witnessDb.hasEntryFacts('g', '1.0.0'), true);
    // 0.1.6 every download is walked (deliberate change of expectation): the rows say what armed the walk, and no row armed this one
    assert.match(proxy.witnessDb.getLatestDecision('g', '1.0.0').gates_fired.find((r) => r.gate === 'static:S1-loader-in-hook-target')?.detail ?? '', /armed by every download$/, 'storing facts arms nothing');
    await get(`${base}/g/-/g-1.1.0.tgz`); await settle();
    const p = proxy.witnessDb.predecessorEntryFacts('g', '1.1.0');
    assert.equal(p?.version, '1.0.0');
    const main = p.files.find((f) => f.role === 'main'); assert.equal(main.state, 'read'); assert.equal(main.sha256, sha(BENIGN));
    assert.equal(p.files.find((f) => f.role === 'bin')?.path, 'cli.js');
    const n = new Database(proxy.witnessDb.db.name, { readonly: true });
    try {
      const before = n.prepare('SELECT COUNT(*) AS c FROM entry_facts').get().c;
      await get(`${base}/g/-/g-1.0.0.tgz`); await settle();
      assert.equal(n.prepare('SELECT COUNT(*) AS c FROM entry_facts').get().c, before, 'a version is written once');
    } finally { n.close(); }
  });
});

// ------------------------------------------------------------------ R8 (operator 2026-10-22): the proxy's own facts time, readable from the store
// entry_fact_versions.facts_ms: the milliseconds the proxy spent computing one served version's entry facts after its download (the
// summary R4 adds; the walk itself is MC's), so the first-week confirming measure is one SQL read with no code change.
test('EF-U8 recordEntryFacts stores facts_ms (null when not given); predecessorEntryFacts returns it', () => withDb((db) => {
  db.recordEntryFacts(rec('1.0.0', undefined, { facts_ms: 1.25 }));
  db.recordEntryFacts(rec('1.1.0'));
  const n = new Database(db.db.name, { readonly: true });
  try {
    assert.deepEqual(n.prepare('SELECT version, facts_ms FROM entry_fact_versions ORDER BY id').all(), [{ version: '1.0.0', facts_ms: 1.25 }, { version: '1.1.0', facts_ms: null }]);
  } finally { n.close(); }
  assert.equal(db.predecessorEntryFacts('a', '1.1.0').facts_ms, 1.25);
}));

test('EF-U9 a witness.db whose entry_fact_versions predates facts_ms gains the column on applySchema, its rows kept', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cft015-efmig-'));
  try {
    const p = path.join(dir, 'w.db'); const raw = new Database(p);
    raw.exec(`CREATE TABLE entry_fact_versions (id INTEGER PRIMARY KEY AUTOINCREMENT, package_name TEXT NOT NULL, version TEXT NOT NULL,
      served_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')), walk TEXT NOT NULL CHECK (walk IN ('read','refused')), reason TEXT,
      static_checks_version TEXT NOT NULL, UNIQUE (package_name, version));
      INSERT INTO entry_fact_versions (package_name, version, walk, static_checks_version) VALUES ('a', '0.9.0', 'read', 'static-checks-1.4');`);
    raw.close();
    const db = openWitnessDB(p); db.applySchema();
    try {
      assert.equal(db.recordEntryFacts(rec('1.0.0', undefined, { facts_ms: 0.5 })), 'wrote');
      const n = new Database(p, { readonly: true });
      try { assert.deepEqual(n.prepare('SELECT version, facts_ms FROM entry_fact_versions ORDER BY id').all(), [{ version: '0.9.0', facts_ms: null }, { version: '1.0.0', facts_ms: 0.5 }]); } finally { n.close(); }
    } finally { db.close(); }
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

test('EF-E2 a served version\'s facts time is stored: facts_ms is a finite number of milliseconds, one SQL read away', async () => {
  await withProxy(async ({ base, proxy }) => {
    await get(`${base}/g`); await get(`${base}/g/-/g-1.0.0.tgz`); await settle();
    const n = new Database(proxy.witnessDb.db.name, { readonly: true });
    try {
      const r = n.prepare("SELECT facts_ms FROM entry_fact_versions WHERE package_name = 'g' AND version = '1.0.0'").get();
      assert.ok(Number.isFinite(r?.facts_ms) && r.facts_ms >= 0, JSON.stringify(r));
    } finally { n.close(); }
  });
});
