// 0.1.5 shadow facts (operator ruling R11 2026-10-24, "Shadow first"): the triage noise-reduction rules the owner computes at runtime
// (chaingate-ops af922e7, docs/design/triage-noise-rules-20261023.md, section B), recorded per served version and shown in `why` and
// `report`, changing no verdict, no tier and no notice. Outside proxy/static-checks.js (the recon mirror stays byte for byte):
//   rule 3   the served version is not the `latest` dist-tag, and which tag points at it;
//   rule 5   transition half: a named sign on this version was already on the version this proxy served before ("not new since");
//   rule 8   packument half: the publisher is a known owner (a listed maintainer, an earlier publisher, the majority publisher);
//   8b       the size change attributed to docs, source maps, declaration files or a second module format.
// Failing first: written before the code. Tarballs are synthetic; nothing is run.
import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import zlib from 'node:zlib';
import { fileURLToPath } from 'node:url';
import Database from 'better-sqlite3';
import { createProxyServer } from '../../proxy/server.js';
import { createTarWalker } from '../../proxy/tar-walk.js';
import { openWitnessDB } from '../../witness/db.js';
import { resetDependencyCache } from '../../gates/dependency-cache.js';
import { forgetManifestHooks } from '../../proxy/manifest-check.js';

const SF = () => import('../../proxy/shadow-facts.js');
const CLI = fileURLToPath(new URL('../../cli/index.js', import.meta.url));
const VS = 'the version this proxy served before';

// ------------------------------------------------------------------ the package metadata a fact reads
const H = 3_600_000; const T0 = Date.parse('2026-03-01T00:00:00Z'); const at = (h) => new Date(T0 + h * H).toISOString();
const doc = ({ tags = { latest: '1.2.0' }, maintainers = [{ name: 'ann', email: 'ann@example.com' }], pubs } = {}) => {
  const vs = Object.keys(pubs);
  return { name: 'p', 'dist-tags': tags, maintainers, time: Object.fromEntries(vs.map((v, i) => [v, at(24 * i)])),
    versions: Object.fromEntries(vs.map((v) => [v, { name: 'p', version: v, ...(pubs[v] ? { _npmUser: pubs[v] } : {}) }])) };
};
const ANN = { name: 'ann', email: 'ann@example.com' }; const BOB = { name: 'bob', email: 'bob@example.com' };
const EVE = { name: 'eve', email: 'eve@example.invalid' };

test('SF-1 identity: shadow-facts-1.0, a record-only note; nothing joins the named or contributing lists; the policy is unchanged by it', async () => {
  const S = await SF();
  assert.equal(S.SHADOW_FACTS_VERSION, 'shadow-facts-1.0');
  assert.match(S.SHADOW_NOTE, /no verdict, tier or notice/);
  const POL = (await import('../../seed/v3/policy.js')).default; const R = await import('../../gates/row-class.js');
  assert.equal(POL.POLICY_CONTRACT_VERSION, 'cft-policy-1.3');   // 1.3 since 0.1.6 (the strict-row re-tier), not the shadow facts
  assert.ok(!POL.NAMED_RUNNER_GATES.some((g) => /shadow|fact/i.test(g)));
  assert.ok(![...R.CONTRIBUTING_GATES].some((g) => /shadow|fact/i.test(g)));
});

test('SF-2 rule 3: the latest tag, another tag, no tag; not known without the metadata', async () => {
  const S = await SF(); S.forgetPackumentFacts();
  S.rememberPackumentFacts('p', doc({ tags: { latest: '1.1.0', next: '1.2.0', beta: '1.2.0' }, pubs: { '1.0.0': ANN, '1.1.0': ANN, '1.2.0': ANN } }));
  const m = S.packumentFactsFor('p');
  assert.deepEqual(S.distTagFact(m, '1.1.0'), { state: 'known', latest: '1.1.0', tags: ['latest'], not_latest: false });
  assert.deepEqual(S.distTagFact(m, '1.2.0'), { state: 'known', latest: '1.1.0', tags: ['beta', 'next'], not_latest: true });
  assert.deepEqual(S.distTagFact(m, '1.0.0'), { state: 'known', latest: '1.1.0', tags: [], not_latest: true });
  assert.equal(S.distTagFact(undefined, '1.0.0').state, 'not-known');
  assert.equal(S.distTagFact(S.packumentFactsFor('nope'), '1.0.0').state, 'not-known');
});

test('SF-3 rule 8 (packument half): listed maintainer, earlier publisher, majority publisher; none; no publisher; a first version', async () => {
  const S = await SF(); S.forgetPackumentFacts();
  S.rememberPackumentFacts('p', doc({ pubs: { '1.0.0': ANN, '1.1.0': ANN, '1.2.0': BOB, '1.3.0': ANN, '1.4.0': EVE, '1.5.0': null } }));
  const m = S.packumentFactsFor('p');
  assert.deepEqual(S.knownOwnerFact(m, '1.3.0'), { state: 'known', publisher: 'ann', known_owner: true, listed_maintainer: true,
    earlier_publisher: true, majority_publisher: true, earlier_versions: 3, by_publisher: 2 });
  assert.deepEqual(S.knownOwnerFact(m, '1.2.0'), { state: 'known', publisher: 'bob', known_owner: false, listed_maintainer: false,
    earlier_publisher: false, majority_publisher: false, earlier_versions: 2, by_publisher: 0 });
  assert.deepEqual(S.knownOwnerFact(m, '1.4.0'), { state: 'known', publisher: 'eve', known_owner: false, listed_maintainer: false,
    earlier_publisher: false, majority_publisher: false, earlier_versions: 4, by_publisher: 0 });
  assert.equal(S.knownOwnerFact(m, '1.5.0').state, 'not-known', 'no _npmUser on the version');
  const first = S.knownOwnerFact(m, '1.0.0');
  assert.equal(first.earlier_versions, 0); assert.equal(first.majority_publisher, false); assert.equal(first.known_owner, true, 'a listed maintainer');
  // an earlier publisher who is no longer listed is still a known owner; matched by e-mail, case-insensitively
  S.rememberPackumentFacts('q', { ...doc({ maintainers: [], pubs: { '1.0.0': ANN, '1.1.0': { name: 'ann2', email: 'ANN@example.com' } } }), name: 'q' });
  const q = S.knownOwnerFact(S.packumentFactsFor('q'), '1.1.0');
  assert.equal(q.known_owner, true); assert.equal(q.earlier_publisher, true); assert.equal(q.listed_maintainer, false);
  assert.equal(S.knownOwnerFact(undefined, '1.0.0').state, 'not-known');
});

test('SF-4 8b file classes: manifest, docs, maps, declarations, cjs, esm, other', async () => {
  const S = await SF();
  const want = { 'package.json': 'manifest', 'README.md': 'docs', 'docs/guide.html': 'docs', 'LICENSE': 'docs', 'CHANGELOG': 'docs',
    'notes.txt': 'docs', 'dist/index.js.map': 'maps', 'dist/index.d.ts': 'types', 'dist/index.d.mts': 'types', 'dist/index.cjs': 'cjs',
    'dist/cjs/index.js': 'cjs', 'dist/index.mjs': 'esm', 'dist/esm/index.js': 'esm', 'index.js': 'other', 'lib/package.json': 'other',
    'src/readme.ts': 'other' };
  for (const [p, c] of Object.entries(want)) assert.equal(S.fileClass(p), c, p);
});

const shape = (files) => { return import('../../proxy/shadow-facts.js').then((S) => { const t = S.createShapeTally(); for (const [p, n] of Object.entries(files)) t.onFile(p, n); return t.result(); }); };

test('SF-5 8b size attribution: all in docs/maps/declarations; a code change; a second module format; cold start; not read', async () => {
  const S = await SF();
  const pred = await shape({ 'package.json': 500, 'index.js': 1000, 'README.md': 100 });
  const docsOnly = await shape({ 'package.json': 510, 'index.js': 1000, 'README.md': 2100, 'index.d.ts': 300, 'index.js.map': 50 });
  assert.deepEqual(S.sizeAttributionFact(docsOnly, { version: '1.0.0', shape: pred }), { state: 'known', vs: '1.0.0', delta_bytes: 2350,
    by: { docs: 2000, maps: 50, types: 300, second_format: 0, other: 0 }, all_attributed: true });
  const code = await shape({ 'package.json': 500, 'index.js': 1400, 'README.md': 100 });
  const c = S.sizeAttributionFact(code, { version: '1.0.0', shape: pred });
  assert.equal(c.all_attributed, false); assert.equal(c.by.other, 400); assert.equal(c.delta_bytes, 400);
  const dual = await shape({ 'package.json': 500, 'index.js': 1000, 'README.md': 100, 'dist/index.mjs': 900, 'dist/cjs/index.js': 0 });
  assert.equal(S.sizeAttributionFact(dual, { version: '1.0.0', shape: pred }).all_attributed, false, 'an .mjs file alone is no second format: there is no first');
  const pred2 = await shape({ 'package.json': 500, 'dist/index.cjs': 1000 });
  const both = await shape({ 'package.json': 500, 'dist/index.cjs': 1000, 'dist/index.mjs': 900 });
  const b = S.sizeAttributionFact(both, { version: '1.0.0', shape: pred2 });
  assert.equal(b.all_attributed, true); assert.equal(b.by.second_format, 900);
  assert.deepEqual(S.sizeAttributionFact(pred, { version: '1.0.0', shape: pred }), { state: 'known', vs: '1.0.0', delta_bytes: 0,
    by: { docs: 0, maps: 0, types: 0, second_format: 0, other: 0 }, all_attributed: false });
  assert.equal(S.sizeAttributionFact(pred, null).state, 'not-applicable');
  assert.equal(S.sizeAttributionFact(null, { version: '1.0.0', shape: pred }).state, 'not-checked');
  assert.equal(S.sizeAttributionFact(pred, { version: '1.0.0', shape: null }).state, 'not-checked');
});

test('SF-6 rule 5 (transition half): a named sign already on the version served before is not new; cold start; no stored decision', async () => {
  const S = await SF();
  const t = S.transitionFact(['install-introduced', 'static:S0-shell-fetch-in-hook'], { version: '1.0.0', named: ['install-introduced'] });
  assert.deepEqual(t, { state: 'known', vs: '1.0.0', signs: [{ gate: 'install-introduced', new: false }, { gate: 'static:S0-shell-fetch-in-hook', new: true }],
    all_not_new: false });
  assert.equal(S.transitionFact(['install-introduced'], { version: '1.0.0', named: ['install-introduced'] }).all_not_new, true);
  assert.deepEqual(S.transitionFact([], { version: '1.0.0', named: ['install-introduced'] }), { state: 'known', vs: '1.0.0', signs: [], all_not_new: false });
  assert.equal(S.transitionFact(['install-introduced'], null).state, 'not-applicable');
  assert.equal(S.transitionFact(['install-introduced'], { version: '1.0.0', named: null }).state, 'not-known');
});

test('SF-7 the lines `why` and `report` print, and which facts are notable', async () => {
  const S = await SF();
  const facts = { version: 'shadow-facts-1.0',
    dist_tag: { state: 'known', latest: '1.1.0', tags: ['next'], not_latest: true },
    known_owner: { state: 'known', publisher: 'ann', known_owner: true, listed_maintainer: true, earlier_publisher: true, majority_publisher: true, earlier_versions: 3, by_publisher: 2 },
    transition: { state: 'known', vs: '1.0.0', signs: [{ gate: 'install-introduced', new: false }], all_not_new: true },
    size: { state: 'known', vs: '1.0.0', delta_bytes: 2350, by: { docs: 2000, maps: 50, types: 300, second_format: 0, other: 0 }, all_attributed: true } };
  assert.deepEqual(S.shadowLines(facts), [
    'dist-tag: not the latest tag (latest is 1.1.0); tagged next',
    'publisher ann: a known owner (a listed maintainer; an earlier publisher; published 2 of 3 earlier versions)',
    `named signs vs 1.0.0 (${VS}): install-introduced not new since 1.0.0`,
    `size change vs 1.0.0 (${VS}): +2350 bytes, all in docs, source maps, declarations or a second module format (docs +2000, source maps +50, declarations +300)`,
  ]);
  assert.equal(S.notable(facts), true);
  const plain = { ...facts, dist_tag: { state: 'known', latest: '1.1.0', tags: ['latest'], not_latest: false },
    transition: { state: 'known', vs: '1.0.0', signs: [], all_not_new: false },
    size: { ...facts.size, by: { ...facts.size.by, other: 10 }, delta_bytes: 2360, all_attributed: false } };
  assert.equal(S.notable(plain), false, 'the latest tag, a known owner, no named sign, a code change: nothing to say');
  assert.deepEqual(S.shadowLines(plain).slice(0, 1), ['dist-tag: the latest tag']);
  assert.equal(S.shadowLines(plain)[2], `named signs vs 1.0.0 (${VS}): none on this version`);
  assert.match(S.shadowLines(plain)[3], /^size change vs 1\.0\.0 \(.*\): \+2360 bytes, not all in docs, source maps, declarations or a second module format \(other files \+10, docs \+2000, source maps \+50, declarations \+300\)$/);
  assert.equal(S.notable({ ...plain, known_owner: { ...facts.known_owner, known_owner: false } }), true, 'a publisher who is not a known owner is notable');
  const cold = S.shadowLines({ version: 'shadow-facts-1.0', dist_tag: { state: 'not-known', why: 'the package metadata is not at hand' },
    known_owner: { state: 'not-known', why: 'no publisher recorded for this version' }, transition: { state: 'not-applicable' }, size: { state: 'not-applicable' } });
  assert.deepEqual(cold, ['dist-tag: not known (the package metadata is not at hand)', 'publisher: not known (no publisher recorded for this version)',
    'named signs: not applicable (no earlier version served by this proxy)', 'size change: not applicable (no earlier version served by this proxy)']);
});

// ------------------------------------------------------------------ the walker's per-file callback (8b's source)
function hdr(name, size) {
  const h = Buffer.alloc(512, 0); Buffer.from(name, 'utf8').copy(h, 0, 0, 100);
  h.write('0000644\0', 100); h.write('0000000\0', 108); h.write('0000000\0', 116); h.write(`${size.toString(8).padStart(11, '0')}\0`, 124, 'latin1');
  h.write('00000000000\0', 136); h.write('        ', 148); h.write('0', 156, 'latin1'); h.write('ustar\0', 257, 'latin1'); h.write('00', 263, 'latin1');
  let sum = 0; for (let i = 0; i < 512; i += 1) sum += h[i]; h.write(`${sum.toString(8).padStart(6, '0')}\0 `, 148, 'latin1'); return h;
}
const pad = (b) => Buffer.concat([b, Buffer.alloc((512 - (b.length % 512)) % 512, 0)]);
const tgz = (files) => zlib.gzipSync(Buffer.concat([...Object.entries(files).flatMap(([p, c]) => [hdr(`package/${p}`, Buffer.byteLength(c)), pad(Buffer.from(c))]), Buffer.alloc(1024, 0)]));
const walkOf = async (buf, opts) => { const w = createTarWalker(opts); w.write(buf); return w.end(); };
const plainOf = (r) => JSON.parse(JSON.stringify(r, (k, v) => (v && v.type === 'Buffer' ? `buf:${v.data.length}` : v)));

test('SF-8 the walker calls onFile(path, size) for each regular file on the Linux view; without it the result is unchanged key for key', async () => {
  const PJ = '{"name":"p","version":"1.0.0"}';
  const buf = tgz({ 'package.json': PJ, 'README.md': 'x'.repeat(300), 'lib/index.js': 'module.exports = 1;\n' });
  const seen = [];
  const a = await walkOf(buf, { onFile: (p, n) => seen.push([p, n]) });
  const b = await walkOf(buf, {});
  assert.deepEqual(seen, [['package.json', Buffer.byteLength(PJ)], ['README.md', 300], ['lib/index.js', 20]]);
  assert.deepEqual(plainOf(a), plainOf(b));
  const k = []; await walkOf(buf, { keep: ['lib/index.js'], onFile: (p, n) => k.push(p) });
  assert.deepEqual(k, ['package.json', 'README.md', 'lib/index.js'], 'with a keep list too');
});

// ------------------------------------------------------------------ the store
const rec = (v, extra = {}) => ({ package_name: 'a', version: v, walk: 'read', static_checks_version: 'static-checks-1.5', files: [], ...extra });
function withDb(fn) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cft015-sf-'));
  const db = openWitnessDB(path.join(dir, 'witness.db')); db.applySchema();
  try { return fn(db); } finally { db.close(); fs.rmSync(dir, { recursive: true, force: true }); }
}

test('SF-9 the store: shape with the entry facts; the shadow facts written once; read back; the predecessor carries its shape', () => withDb((db) => {
  const s1 = { files: 2, by: { manifest: 10, docs: 0, maps: 0, types: 0, cjs: 0, esm: 0, other: 100 } };
  db.recordEntryFacts(rec('1.0.0', { shape: s1 })); db.recordEntryFacts(rec('1.1.0'));
  assert.deepEqual(db.predecessorEntryFacts('a', '1.1.0').shape, s1);
  assert.equal(db.predecessorEntryFacts('a', '1.2.0').shape, null, 'a version stored without a shape');
  assert.equal(db.shadowFactsFor('a', '1.1.0'), null);
  const f = { version: 'shadow-facts-1.0', dist_tag: { state: 'not-known', why: 'w' } };
  assert.equal(db.recordShadowFacts('a', '1.1.0', f), 1);
  assert.equal(db.recordShadowFacts('a', '1.1.0', { version: 'shadow-facts-1.0' }), 0, 'once per version');
  assert.deepEqual(db.shadowFactsFor('a', '1.1.0'), f);
  assert.equal(db.recordShadowFacts('a', '9.9.9', f), 0, 'no entry facts row: nothing written');
}));

test('SF-10 a witness.db whose entry_fact_versions predates shape and shadow gains both on applySchema; a read-only open of it reads null', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cft015-sfmig-'));
  try {
    const p = path.join(dir, 'w.db'); const raw = new Database(p);
    raw.exec(`CREATE TABLE entry_fact_versions (id INTEGER PRIMARY KEY AUTOINCREMENT, package_name TEXT NOT NULL, version TEXT NOT NULL,
      served_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')), walk TEXT NOT NULL CHECK (walk IN ('read','refused')), reason TEXT,
      static_checks_version TEXT NOT NULL, facts_ms REAL, UNIQUE (package_name, version));
      INSERT INTO entry_fact_versions (package_name, version, walk, static_checks_version) VALUES ('a', '0.9.0', 'read', 'static-checks-1.5');`);
    raw.close();
    const ro = openWitnessDB(p, { readonly: true });
    try { assert.equal(ro.shadowFactsFor('a', '0.9.0'), null, 'an old table: no shadow column, null, no throw'); } finally { ro.close(); }
    const db = openWitnessDB(p); db.applySchema();
    try {
      const cols = new Database(p, { readonly: true });
      try { const names = cols.prepare('PRAGMA table_info(entry_fact_versions)').all().map((c) => c.name); assert.ok(names.includes('shape') && names.includes('shadow'), names.join(',')); } finally { cols.close(); }
      assert.equal(db.recordShadowFacts('a', '0.9.0', { version: 'shadow-facts-1.0' }), 1);
    } finally { db.close(); }
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

// ------------------------------------------------------------------ end to end
const BENIGN = 'module.exports = 1;\n';
const REAL = (name, v, user = ANN) => ({ _npmUser: user, _npmVersion: '10.9.2', maintainers: [ANN],
  dist: { shasum: `shasum-${name}-${v}`, integrity: `sha512-${name}-${v}==`, tarball: `https://registry.npmjs.org/${name}/-/${name}-${v}.tgz`, unpackedSize: 1000 } });
const EV = Array.from({ length: 9 }, (_, i) => `1.${i}.0`);
// nine versions by ann; 1.8.0 is tagged next (latest stays 1.7.0) and adds only a longer README and a declaration file
const pkgDoc = (name, user8 = ANN) => ({ name, 'dist-tags': { latest: '1.7.0', next: '1.8.0' }, maintainers: [ANN],
  time: Object.fromEntries(EV.map((v, i) => [v, at(48 * i)])),
  versions: Object.fromEntries(EV.map((v) => [v, { name, version: v, main: 'index.js', ...REAL(name, v, v === '1.8.0' ? user8 : ANN) }])) });
const DOCS = { '/s': pkgDoc('s'), '/o': pkgDoc('o', EVE) };
const TARBALLS = {
  '/s/-/s-1.7.0.tgz': tgz({ 'package.json': JSON.stringify(DOCS['/s'].versions['1.7.0']), 'index.js': BENIGN, 'README.md': 'r'.repeat(100) }),
  '/s/-/s-1.8.0.tgz': tgz({ 'package.json': JSON.stringify(DOCS['/s'].versions['1.8.0']), 'index.js': BENIGN, 'README.md': 'r'.repeat(900), 'index.d.ts': 'export {};\n' }),
  '/o/-/o-1.7.0.tgz': tgz({ 'package.json': JSON.stringify(DOCS['/o'].versions['1.7.0']), 'index.js': BENIGN }),
  '/o/-/o-1.8.0.tgz': tgz({ 'package.json': JSON.stringify(DOCS['/o'].versions['1.8.0']), 'index.js': `${BENIGN}// more\n` }),
};
async function withProxy(fn) {
  resetDependencyCache(); forgetManifestHooks(); (await SF()).forgetPackumentFacts();
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cft015-sfe-'));
  const upstream = http.createServer((req, res) => {
    const u = decodeURIComponent(req.url.split('?')[0]);
    if (TARBALLS[u]) { res.writeHead(200, { 'content-type': 'application/octet-stream' }); res.end(TARBALLS[u]); return; }
    if (DOCS[u]) { res.writeHead(200, { 'content-type': 'application/json' }); res.end(JSON.stringify(DOCS[u])); return; }
    res.writeHead(404, { 'content-type': 'application/json' }); res.end('{}');
  });
  await new Promise((r) => upstream.listen(0, '127.0.0.1', r));
  const dbPath = path.join(dir, 'witness.db');
  const proxy = createProxyServer({ port: 0, host: '127.0.0.1', upstream: `http://127.0.0.1:${upstream.address().port}`,
    witnessDbPath: dbPath, headersTimeoutMs: 10_000, bodyTimeoutMs: 10_000 });
  await new Promise((r) => proxy.listen(0, '127.0.0.1', r));
  const base = `http://127.0.0.1:${proxy.address().port}`;
  try { return await fn({ base, proxy, dir, dbPath }); } finally {
    await new Promise((r) => proxy.close(r)); await new Promise((r) => upstream.close(r)); fs.rmSync(dir, { recursive: true, force: true });
    resetDependencyCache(); forgetManifestHooks();
  }
}
const get = (u) => new Promise((resolve, reject) => http.get(u, { agent: false }, (res) => {
  const chunks = []; res.on('data', (x) => chunks.push(x)); res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks) }));
}).on('error', reject));
const settle = () => new Promise((r) => setTimeout(r, 200));
const serve = async (base, name) => {
  await get(`${base}/${name}`); await get(`${base}/${name}`);
  await get(`${base}/${name}/-/${name}-1.7.0.tgz`); await settle();
  const t = await get(`${base}/${name}/-/${name}-1.8.0.tgz`); await settle(); return t;
};
const runCli = (args, env) => new Promise((resolve) => {
  const c = spawn(process.execPath, [CLI, ...args], { env: { ...process.env, NO_COLOR: '1', CI: '', ...env } });
  let out = ''; c.stdout.on('data', (d) => { out += d; }); c.stderr.on('data', (d) => { out += d; }); c.on('close', (code) => resolve({ code, out }));
});

test('SF-E1 a served version\'s shadow facts are stored once: not the latest tag, a known owner, the size change all in docs and declarations; no row, verdict or notice changes', async () => {
  await withProxy(async ({ base, proxy }) => {
    const t = await serve(base, 's');
    assert.equal(t.status, 200); assert.ok(t.body.equals(TARBALLS['/s/-/s-1.8.0.tgz']), 'served unchanged');
    assert.equal(t.headers['npm-notice'], undefined, 'no notice');
    const f = proxy.witnessDb.shadowFactsFor('s', '1.8.0');
    assert.equal(f?.version, 'shadow-facts-1.0', JSON.stringify(f));
    assert.deepEqual(f.dist_tag, { state: 'known', latest: '1.7.0', tags: ['next'], not_latest: true });
    assert.equal(f.known_owner.known_owner, true); assert.equal(f.known_owner.publisher, 'ann');
    assert.equal(f.transition.state, 'known'); assert.deepEqual(f.transition.signs, []);
    assert.equal(f.size.state, 'known'); assert.equal(f.size.vs, '1.7.0'); assert.equal(f.size.all_attributed, true, JSON.stringify(f.size));
    assert.equal(f.size.by.docs, 800); assert.equal(f.size.by.types, 11); assert.equal(f.size.by.other, 0);
    const cold = proxy.witnessDb.shadowFactsFor('s', '1.7.0');
    assert.equal(cold.size.state, 'not-applicable'); assert.equal(cold.transition.state, 'not-applicable');
    const rec = proxy.witnessDb.getLatestDecision('s', '1.8.0');
    assert.ok(!rec.gates_fired.some((g) => /shadow|fact/i.test(String(g?.gate))), 'no runner row carries a shadow fact');
    assert.equal(rec.disposition, 'ALLOW');
  });
});

test('SF-E2 `why` shows the facts under the rows, marked record-only; --json carries them', async () => {
  await withProxy(async ({ base, dbPath, dir }) => {
    await serve(base, 's');
    const w = await runCli(['why', 's@1.8.0'], { CHAINGATE_WITNESS_DB: dbPath, HOME: dir });
    assert.match(w.out, /Recorded facts \(shadow-facts-1\.0; recorded only: no verdict, tier or notice depends on it/);
    assert.match(w.out, /dist-tag: not the latest tag \(latest is 1\.7\.0\); tagged next/);
    assert.match(w.out, /publisher ann: a known owner/);
    assert.match(w.out, /size change vs 1\.7\.0 \(the version this proxy served before\): \+811 bytes, all in docs, source maps, declarations or a second module format/);
    const j = await runCli(['why', 's@1.8.0', '--json'], { CHAINGATE_WITNESS_DB: dbPath, HOME: dir });
    const parsed = JSON.parse(j.out.slice(j.out.indexOf('{')));
    assert.equal(parsed.shadow_facts?.version, 'shadow-facts-1.0');
  });
});

test('SF-E3 `report`: the facts event in --json, and a record-only block naming the notable version; a publisher who is not a known owner is named', async () => {
  await withProxy(async ({ base }) => {
    await serve(base, 'o');
    const r = await get(`${base}/_chaingate/report`);
    const j = JSON.parse(r.body.toString('utf8'));
    const ev = j.installs.flatMap((i) => i.events).filter((e) => e.kind === 'facts');
    const o8 = ev.find((e) => e.package === 'o' && e.version === '1.8.0');
    assert.equal(o8?.facts?.known_owner?.known_owner, false, JSON.stringify(ev));
    assert.equal(o8.facts.size.all_attributed, false);
    const { renderReport } = await import('../../cli/report-render.js');
    const text = renderReport(j, { source: 'proxy' }).text;
    assert.match(text, /Recorded facts \(shadow-facts-1\.0; recorded only: no verdict, tier or notice depends on it/);
    assert.match(text, /o@1\.8\.0: .*publisher eve: not a known owner/);
    assert.ok(!/o@1\.7\.0:/.test(text), 'a version with nothing notable is not listed');
    const before = renderReport({ ...j, installs: j.installs.map((i) => ({ ...i, events: i.events.filter((e) => e.kind !== 'facts') })) }, { source: 'proxy' });
    assert.equal(renderReport(j, { source: 'proxy' }).exit, before.exit, 'the facts change no exit code');
  });
});

test('SF-E4 a later download of a stored version reads its facts back into the report: no second computation', async () => {
  await withProxy(async ({ base, proxy }) => {
    await serve(base, 's');
    const stored = proxy.witnessDb.shadowFactsFor('s', '1.8.0');
    await settle(); await new Promise((r) => setTimeout(r, 50));
    await get(`${base}/s/-/s-1.8.0.tgz`); await settle();
    const j = JSON.parse((await get(`${base}/_chaingate/report?all=1`)).body.toString('utf8'));
    const evs = j.installs.flatMap((i) => i.events).filter((e) => e.kind === 'facts' && e.package === 's' && e.version === '1.8.0');
    assert.ok(evs.length >= 2, `${evs.length} facts events`);
    for (const e of evs) assert.deepEqual(e.facts, stored);
  });
});
