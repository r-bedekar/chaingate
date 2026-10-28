// 0.1.4 group 2, unit 2c — the conclusion, through the proxy: `GET /_chaingate/report` (D-R1, E19), the disk record
// `named_fact_events` (D-R2, E20), K end to end (D-R5), the tag-moved line (D-R6) and independence from the log (G2c-9).
// Expected results: decision tables ~/docs/plans/CFT/0.1.4-IMPL-DECISION-TABLES-G2-TIER0-20261011.md §7 and dated note 6,
// written before this file. Pure parts: cft014-g2c-summary.test.js; the CLI: test/cli/cft014-g2c-report-cli.test.js.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import { createProxyServer } from '../../proxy/server.js';
import { openWitnessDB } from '../../witness/db.js';
import { renderReport } from '../../cli/report-render.js';
import { buildSeed, docFor, manifestFor, after, iso, TIP_S, STEP_S, LIVE } from '../seed-v3/u05-fixtures.mjs';

const pkgVersion = JSON.parse(fs.readFileSync(new URL('../../package.json', import.meta.url), 'utf8')).version;
const listen = (srv) => new Promise((resolve) => { srv.listen(0, '127.0.0.1', () => resolve(`http://127.0.0.1:${srv.address().port}`)); });
const close = (srv) => new Promise((resolve) => { srv.close(() => resolve()); });
const get = (url, session) => new Promise((resolve, reject) => {
  http.get(url, { agent: false, headers: session ? { 'npm-session': session } : {} }, (res) => {
    let b = ''; res.setEncoding('utf8'); res.on('data', (x) => { b += x; });
    res.on('end', () => { let json = null; try { json = JSON.parse(b); } catch { /* not JSON */ } resolve({ status: res.statusCode, headers: res.headers, json, body: b }); });
  }).on('error', reject);
});

const strict = () => manifestFor('q', '1.5.0', { scripts: { postinstall: 'node x.js' },
  dist: { unpackedSize: 10_000, attestations: { url: 'https://x' } } });                    // surface: named
const contributing = () => manifestFor('q', '1.4.0', { scripts: { postinstall: 'node x.js' } }); // any only: NOTE
const DOCS = () => {
  const p = docFor('p', [['1.3.0', after(1)]]);
  p['dist-tags'] = { latest: '1.3.0' };                                                      // latest is the pinned version
  const q = docFor('q', [['1.4.0', after(1), contributing()],
    ['1.4.5', iso(TIP_S + 2 * STEP_S - 3600)],                                               // decoy: 1 h before 1.5.0, not settled
    ['1.5.0', after(2), strict()]]);
  q['dist-tags'] = { latest: '1.5.0' };
  q.versions['1.0.0'].scripts = { postinstall: 'node legacy.js' };   // G3 dated note 1.2: T1.1 stays quiet; the seed rows are the subject
  return { p, q, u: docFor('u', [['1.3.0', after(1)]]) };                                     // u: not covered by the seed
};

async function withProxy({ hooks = {} } = {}, fn) {
  const s = buildSeed({ layout: '1.1' });
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cft014-g2c-'));
  const docs = DOCS();
  const upstream = http.createServer((req, res) => {
    const url = decodeURIComponent(req.url);
    if (url.includes('/-/')) { res.writeHead(200, { 'content-type': 'application/octet-stream' }); res.end('tarball-bytes'); return; }
    const d = docs[url.slice(1)];
    if (!d) { res.writeHead(404, { 'content-type': 'application/json' }); res.end('{}'); return; }
    res.writeHead(200, { 'content-type': 'application/json' }); res.end(JSON.stringify(d));
  });
  const upstreamUrl = await listen(upstream);
  const dbPath = path.join(dir, 'witness.db');
  const proxy = createProxyServer({ port: 0, host: '127.0.0.1', upstream: upstreamUrl, witnessDbPath: dbPath,
    headersTimeoutMs: 5_000, bodyTimeoutMs: 15_000, seedV3Path: s.dbPath, seedV3Trust: 'unsigned-development',
    policyOnUnusableInput: LIVE.on_unusable_input, policyOnNoEvidence: LIVE.on_no_evidence }, hooks);
  const proxyUrl = await listen(proxy);
  const logs = []; const realErr = console.error;
  console.error = (m) => { logs.push(String(m)); };
  try {
    return await fn({ proxyUrl, logs, dbPath });
  } finally {
    console.error = realErr;
    await close(proxy); await close(upstream);
    s.cleanup(); fs.rmSync(dir, { recursive: true, force: true });
  }
}
const tgz = (name, v) => `/${name}/-/${name}-${v}.tgz`;
const strip = (e) => { const { at, ...rest } = e; return rest; };

/** The G2c-2 install: a tag-moved packument, a named WARN, a pin 403, a contributing-only, a clean and an uncovered tarball. */
async function install(proxyUrl, session) {
  for (const n of ['p', 'q', 'u']) assert.equal((await get(`${proxyUrl}/${n}`, session)).status, 200);
  assert.equal((await get(`${proxyUrl}${tgz('q', '1.5.0')}`, session)).status, 200);
  assert.equal((await get(`${proxyUrl}${tgz('p', '1.3.0')}`, session)).status, 403);
  assert.equal((await get(`${proxyUrl}${tgz('q', '1.4.0')}`, session)).status, 200);
  assert.equal((await get(`${proxyUrl}${tgz('p', '1.2.0')}`, session)).status, 200);
  assert.equal((await get(`${proxyUrl}${tgz('u', '1.2.0')}`, session)).status, 200);
}

test('G2c-2 (D-R1, E19) /_chaingate/report lists exactly what was served and refused, with classes, reasons and identity', async () => {
  await withProxy({}, async ({ proxyUrl }) => {
    await install(proxyUrl, 'sessg2c2');
    const r = await get(`${proxyUrl}/_chaingate/report`);
    assert.equal(r.status, 200);
    assert.equal(r.json.service, 'chaingate-proxy');
    assert.equal(r.json.version, pkgVersion);
    assert.equal(r.json.policy, 'cft-policy-1.3');   // since 0.1.6
    assert.match(r.json.seed.sha256, /^[0-9a-f]{64}$/);
    assert.equal(r.json.seed.history_cutoff, '2026-12-31T00:00:00Z');
    assert.ok(!Number.isNaN(Date.parse(r.json.started_at)));
    assert.equal(r.json.installs.length, 1);
    const [inst] = r.json.installs;
    assert.equal(inst.key, 'npm-session:sessg2c2');
    assert.equal(inst.grouping, 'npm-session');
    assert.equal(inst.dropped, 0);
    const ev = (kind, pkg, version) => inst.events.find((e) => e.kind === kind && e.package === pkg && (version == null || e.version === version));

    const q15 = ev('served', 'q', '1.5.0');
    assert.ok(q15, JSON.stringify(inst.events));
    assert.equal(q15.class, 'named');
    assert.equal(q15.coverage, 'checked');
    assert.deepEqual(q15.named, ['seed-v3:dac-trajectory:surface']);
    assert.ok(q15.reason.startsWith('seed-v3: cft-policy-1.3: seed-v3:dac-trajectory:surface'), q15.reason);
    assert.equal(q15.policy, 'cft-policy-1.3');
    assert.equal(q15.notice, true);
    assert.equal(q15.k, '1.4.0', 'K: 1.4.5 was published 1 h before 1.5.0 and is not settled (G2c-5)');

    const p13 = ev('refused', 'p', '1.3.0');
    assert.deepEqual(p13.facts, ['seed-v3:pin']);
    assert.equal(p13.status, 403);
    const tag = ev('tag-moved', 'p');
    assert.deepEqual([tag.tag, tag.from, tag.to, tag.facts], ['latest', '1.3.0', '1.2.0', ['seed-v3:pin']]);
    assert.equal(ev('served', 'q', '1.4.0').class, 'contributing');
    assert.deepEqual([ev('served', 'p', '1.2.0').class, ev('served', 'p', '1.2.0').coverage], ['clean', 'checked']);
    // G3 D-T3 (E29): the seed does not cover u, but T1.1 (a named rule) checked it, so it is clean, not "not checked"
    assert.deepEqual([ev('served', 'u', '1.2.0').class, ev('served', 'u', '1.2.0').coverage], ['clean', 'not-covered']);
    assert.equal(inst.events.filter((e) => e.kind === 'served').length, 4, 'exactly the four served tarballs');
    assert.equal(inst.events.filter((e) => e.kind === 'refused').length, 1);
    for (const e of inst.events) assert.ok(!Number.isNaN(Date.parse(e.at)), 'every event is timed');
  });
});

test('G2c-3a (D-R2, E20) the disk record holds named-served, fact-refused and fact-tag-moved rows only, once per install', async () => {
  await withProxy({}, async ({ proxyUrl, dbPath }) => {
    await install(proxyUrl, 'sessdisk1');
    await get(`${proxyUrl}/p`, 'sessdisk1');                                     // the same install: no second row
    await get(`${proxyUrl}${tgz('q', '1.5.0')}`, 'sessdisk1');
    const db = openWitnessDB(dbPath, { readonly: true });
    let rows;
    try { rows = db.listNamedFactEvents(); } finally { db.close(); }
    const key = (x) => `${x.kind} ${x.package_name}@${x.version}`;
    assert.deepEqual(rows.map(key).sort(), ['fact-refused p@1.3.0', 'fact-tag-moved p@1.3.0', 'named-served q@1.5.0'], JSON.stringify(rows));
    const named = rows.find((x) => x.kind === 'named-served');
    assert.equal(named.k_version, '1.4.0');
    assert.equal(named.policy_version, 'cft-policy-1.3');
    assert.match(named.seed_sha256, /^[0-9a-f]{64}$/);
    assert.equal(named.install_key, 'npm-session:sessdisk1');
    assert.deepEqual(named.classes.named, ['seed-v3:dac-trajectory:surface']);
    assert.ok(named.reason.startsWith('seed-v3: cft-policy-1.3: seed-v3:dac-trajectory:surface'));
    const tagRow = rows.find((x) => x.kind === 'fact-tag-moved');
    // dated note 7.3: one row per withheld version, carrying its (capped) tag list
    assert.deepEqual([tagRow.classes.tags, tagRow.classes.facts], [[{ tag: 'latest', to: '1.2.0' }], ['seed-v3:pin']]);
    await get(`${proxyUrl}/p`, 'sessdisk2');                                     // another install: its own row
    const db2 = openWitnessDB(dbPath, { readonly: true });
    try { assert.equal(db2.listNamedFactEvents().filter((x) => x.kind === 'fact-tag-moved').length, 2); } finally { db2.close(); }
  });
});

test('G2c-3b (D-R2) a missing table reads as empty on a read-only handle; prune keeps 365 days and at most maxRows', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cft014-g2c3b-'));
  try {
    const dbPath = path.join(dir, 'witness.db');
    const rw = openWitnessDB(dbPath).applySchema();
    rw.db.exec('DROP TABLE named_fact_events');                                  // what the 0.1.3 code created
    rw.close();
    const ro = openWitnessDB(dbPath, { readonly: true });
    try {
      assert.deepEqual(ro.listNamedFactEvents(), []);
      assert.ok(ro.getStoreCounts(), 'the eagerly prepared statements do not touch the new table');
    } finally { ro.close(); }
    const db = openWitnessDB(dbPath).applySchema();
    try {
      const at = (daysAgo) => new Date(Date.now() - daysAgo * 86_400_000).toISOString();
      for (const [i, d] of [[1, 400], [2, 10], [3, 5], [4, 1]]) {
        db.insertNamedFactEvent({ at: at(d), kind: 'named-served', package_name: `n${i}`, version: '1.0.0', classes: { named: [] },
          reason: 'r', policy_version: 'cft-policy-1.2', seed_sha256: null, install_key: 'k', k_version: null });
      }
      db.pruneNamedFactEvents({ maxAgeDays: 365, maxRows: 2 });
      assert.deepEqual(db.listNamedFactEvents().map((x) => x.package_name).sort(), ['n3', 'n4'], 'older than 365 days, then the oldest beyond 2');
      assert.deepEqual(db.listNamedFactEvents({ sinceIso: at(2) }).map((x) => x.package_name), ['n4']);
    } finally { db.close(); }
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

test('G2c-7b (D-R6) the tag moved off a pinned `latest` is reported, with "npm installed" when that tarball was served', async () => {
  await withProxy({}, async ({ proxyUrl }) => {
    await get(`${proxyUrl}/p`, 'sesstag1');
    await get(`${proxyUrl}${tgz('p', '1.2.0')}`, 'sesstag1');
    await get(`${proxyUrl}/p`, 'sesstag2');
    await get(`${proxyUrl}${tgz('q', '1.4.0')}`, 'sesstag2');
    const all = (await get(`${proxyUrl}/_chaingate/report?all=1`)).json;
    assert.equal(all.installs.length, 2);
    const text = (key) => renderReport({ ...all, installs: all.installs.filter((i) => i.key === key) }, { source: 'proxy' }).text;
    assert.ok(text('npm-session:sesstag1').includes(
      'p: dist-tag latest moved from 1.3.0 to 1.2.0: a recorded advisory names this version — npm installed 1.2.0'), text('npm-session:sesstag1'));
    const t2 = text('npm-session:sesstag2');
    assert.ok(t2.includes('p: dist-tag latest moved from 1.3.0 to 1.2.0: a recorded advisory names this version'), t2);
    assert.ok(!t2.includes('— npm installed'), 'the D-R6 suffix (the cache footer also says "npm installed")');
    const latest = (await get(`${proxyUrl}/_chaingate/report`)).json;
    assert.deepEqual(latest.installs.map((i) => i.key), ['npm-session:sesstag2'], 'by default: the latest install with a tarball');
  });
});

test('G2c-9 an exhausted log budget and a deduplicated named line change nothing in the report', async () => {
  await withProxy({ hooks: { logBudget: { burst: 0, perSecond: 0 } } }, async ({ proxyUrl, logs }) => {
    // the last download's facts event follows its response (R11): wait for an install's four facts events before going on, or
    // the second install may download u@1.2.0 before its facts exist, or the report may be read before the second install's last
    // facts event (a race in this test, not a report change)
    const factsOf = async (session) => ((await get(`${proxyUrl}/_chaingate/report?all=1`)).json.installs
      .find((i) => i.key === `npm-session:${session}`)?.events ?? []).filter((e) => e.kind === 'facts').length;
    const fourFacts = async (session) => {
      for (const until = Date.now() + 5000; (await factsOf(session)) < 4 && Date.now() < until;) await new Promise((r) => setTimeout(r, 50));
    };
    await install(proxyUrl, 'sesslogA');
    await fourFacts('sesslogA');
    await install(proxyUrl, 'sesslogB');
    await fourFacts('sesslogB');
    assert.equal(logs.filter((l) => l.startsWith('[gate] q@1.5.0: WARN named')).length, 1, 'the second named line was deduplicated');
    const all = (await get(`${proxyUrl}/_chaingate/report?all=1`)).json;
    const [a, b] = ['npm-session:sesslogA', 'npm-session:sesslogB'].map((k) => all.installs.find((i) => i.key === k));
    // 0.1.5 shadow facts (R11): a version's facts event follows its first download's walk, and is read back at once on a later
    // download, so its place among the events differs; compared as a set, the decision events in order
    const tarballs = (i) => i.events.filter((e) => e.kind !== 'tag-moved' && e.kind !== 'withheld' && e.kind !== 'facts').map(strip);
    const facts = (i) => i.events.filter((e) => e.kind === 'facts').map(strip).map((e) => JSON.stringify(e)).sort();
    assert.deepEqual(tarballs(b), tarballs(a), 'the second install reports exactly what the first did');
    assert.deepEqual(facts(b), facts(a), 'and the same recorded facts');
    assert.ok(b.events.some((e) => e.kind === 'served' && e.class === 'named' && e.package === 'q'));
  });
});

test('G2c-1e (D-R1) the endpoint is not cacheable; requests without an npm-session header are grouped by client idle gap', async () => {
  await withProxy({}, async ({ proxyUrl }) => {
    await get(`${proxyUrl}${tgz('p', '1.2.0')}`);
    const r = await get(`${proxyUrl}/_chaingate/report`);
    assert.equal(r.status, 200);
    assert.equal(r.json.installs[0].grouping, 'client-idle');
    assert.equal(r.headers['cache-control'], 'no-store');
  });
});
