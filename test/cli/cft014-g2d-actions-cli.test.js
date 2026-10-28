// 0.1.4 group 2, unit 2d — user actions on the CLI: `accept` (D-U2), `pin` / `unpin` (D-U4), conflicts (D-U7), the
// adjudication log (D-U8), 0.1.3 databases (G2d-11) and an older proxy (G2d-12). Expected results: decision tables
// ~/docs/plans/CFT/0.1.4-IMPL-DECISION-TABLES-G2-TIER0-20261011.md §8, written before this file. The CLI runs as a child
// process (asynchronously: the proxy under test runs in this process).
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import http from 'node:http';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { createProxyServer } from '../../proxy/server.js';
import { openWitnessDB } from '../../witness/db.js';
import { buildSeed, docFor, manifestFor, after, iso, TIP_S, STEP_S, LIVE } from '../seed-v3/u05-fixtures.mjs';

const CLI = fileURLToPath(new URL('../../cli/index.js', import.meta.url));
const listen = (srv) => new Promise((resolve) => { srv.listen(0, '127.0.0.1', () => resolve(srv.address().port)); });
const close = (srv) => new Promise((resolve) => { srv.close(() => resolve()); });
const freePort = async () => { const s = net.createServer(); const p = await listen(s); await close(s); return p; };
const get = (url) => new Promise((resolve, reject) => {
  http.get(url, { agent: false }, (res) => { res.resume(); res.on('end', () => resolve(res.statusCode)); }).on('error', reject);
});
function cli(args, env) {
  return new Promise((resolve) => {
    const c = spawn(process.execPath, [CLI, ...args], { env: { ...process.env, NO_COLOR: '1', CI: '', ...env } });
    let out = ''; let err = '';
    c.stdout.on('data', (b) => { out += b; }); c.stderr.on('data', (b) => { err += b; });
    const timer = setTimeout(() => c.kill('SIGKILL'), 60_000);
    c.on('close', (code) => { clearTimeout(timer); resolve({ code, out, err, all: out + err }); });
  });
}

const strict = () => manifestFor('q', '1.5.0', { scripts: { postinstall: 'node x.js' },
  dist: { unpackedSize: 10_000, attestations: { url: 'https://x' } } });
const DOCS = () => {
  const p = docFor('p', [['1.3.0', after(1)]]);
  p['dist-tags'] = { latest: '1.3.0' };
  const q = docFor('q', [['1.4.0', after(1), manifestFor('q', '1.4.0', { scripts: { postinstall: 'node x.js' } })],
    ['1.4.5', iso(TIP_S + 2 * STEP_S - 3600)], ['1.5.0', after(2), strict()], ['2.0.0', after(4)]]);
  q['dist-tags'] = { latest: '1.5.0' };
  q.versions['1.0.0'].scripts = { postinstall: 'node legacy.js' };   // G3 dated note 1.2: T1.1 stays quiet; the seed rows are the subject
  return { p, q };
};

/** A home whose witness DB has observed p and q through a real proxy (left running: `pin` asks it). */
async function withObservedHome(fn) {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'cft014-g2d-cli-'));
  const s = buildSeed({ layout: '1.1' });
  const docs = DOCS();
  const upstream = http.createServer((req, res) => {
    const url = decodeURIComponent(req.url);
    if (url.includes('/-/')) { res.writeHead(200); res.end('x'); return; }
    const d = docs[url.slice(1)];
    if (!d) { res.writeHead(404, { 'content-type': 'application/json' }); res.end('{}'); return; }
    res.writeHead(200, { 'content-type': 'application/json' }); res.end(JSON.stringify(d));
  });
  const up = await listen(upstream);
  const proxy = createProxyServer({ port: 0, host: '127.0.0.1', upstream: `http://127.0.0.1:${up}`, witnessDbPath: path.join(home, 'witness.db'),
    headersTimeoutMs: 5_000, bodyTimeoutMs: 15_000, seedV3Path: s.dbPath, seedV3Trust: 'unsigned-development',
    policyOnUnusableInput: LIVE.on_unusable_input, policyOnNoEvidence: LIVE.on_no_evidence });
  const port = await listen(proxy);
  const realErr = console.error; console.error = () => {};
  try {
    for (const n of ['p', 'q']) assert.equal(await get(`http://127.0.0.1:${port}/${n}`), 200);
    const env = { CHAINGATE_HOME: home, CHAINGATE_PORT: String(port) };
    const db = (f) => { const h = openWitnessDB(path.join(home, 'witness.db'), { readonly: true }); try { return f(h); } finally { h.close(); } };
    return await fn({ home, env, port, db });
  } finally {
    console.error = realErr;
    await close(proxy); await close(upstream); s.cleanup(); fs.rmSync(home, { recursive: true, force: true });
  }
}

test('G2d-1 (D-U2) accept: a named WARN is recorded with its named rows copied; BLOCK, unnamed and unknown are refused', async () => {
  await withObservedHome(async ({ env, db }) => {
    const ok = await cli(['accept', 'q@1.5.0'], env);
    assert.equal(ok.code, 0, ok.all);
    assert.match(ok.out, /Accepted: q@1\.5\.0/);
    assert.match(ok.out, /does not override a BLOCK/);
    db((h) => {
      const a = h.getAcceptance('q', '1.5.0');
      assert.deepEqual(a.named, ['seed-v3:dac-trajectory:surface']);
      const adj = h.listAdjudications().filter((r) => r.action === 'accept');
      assert.equal(adj.length, 1);
      assert.deepEqual(adj[0].classes.named, ['seed-v3:dac-trajectory:surface']);
      assert.equal(adj[0].policy_version, 'cft-policy-1.3');   // since 0.1.6
    });
    const block = await cli(['accept', 'p@1.3.0'], env);
    assert.equal(block.code, 1);
    assert.match(block.all, /accept never overrides a BLOCK; for a false positive use chaingate allow/);
    const unnamed = await cli(['accept', 'q@1.4.0'], env);
    assert.equal(unnamed.code, 1);
    assert.match(unnamed.all, /nothing to accept/);
    const unknown = await cli(['accept', 'q@9.9.9'], env);
    assert.equal(unknown.code, 1);
    assert.match(unknown.all, /ChainGate has no record of this version/);
    db((h) => { assert.equal(h.listAcceptances().length, 1, 'refusals write nothing'); });
    const list = await cli(['accept', '--list'], env);
    assert.equal(list.code, 0);
    assert.match(list.out, /q@1\.5\.0/);
    const rev = await cli(['accept', '--revoke', 'q@1.5.0'], env);
    assert.equal(rev.code, 0, rev.all);
    db((h) => {
      assert.equal(h.getAcceptance('q', '1.5.0'), null);
      assert.equal(h.listAdjudications().filter((r) => r.action === 'unaccept').length, 1);
    });
  });
});

test('G2d-4d/G2d-12 (D-U4) pin and unpin: withheld versions printed, in force through the running proxy, adjudications', async () => {
  await withObservedHome(async ({ env, db }) => {
    const r = await cli(['pin', 'q@1.4.0'], env);
    assert.equal(r.code, 0, r.all);
    assert.match(r.out, /Pinned q to 1\.4\.0 within 1\.x/);
    assert.match(r.out, /withholds now: 1\.4\.5, 1\.5\.0/);
    assert.match(r.out, /in force for new metadata requests/);
    db((h) => {
      assert.deepEqual(h.listPins().map((x) => [x.package_name, x.class_key, x.k_version]), [['q', '1', '1.4.0']]);
      assert.equal(h.listAdjudications().filter((x) => x.action === 'pin' && x.k_version === '1.4.0').length, 1);
    });
    const list = await cli(['pin', '--list'], env);
    assert.match(list.out, /q@1\.4\.0 \(1\.x\)/);
    const un = await cli(['unpin', 'q'], env);
    assert.equal(un.code, 0, un.all);
    db((h) => { assert.equal(h.listPins().length, 0); assert.equal(h.listAdjudications().filter((x) => x.action === 'unpin').length, 1); });
  });
  // G2d-12: an older proxy (its self has no `pins`)
  await withObservedHome(async ({ env }) => {
    const old = http.createServer((req, res) => { res.writeHead(200, { 'content-type': 'application/json' }); res.end(JSON.stringify({ service: 'chaingate-proxy', version: '0.1.3' })); });
    const port = await listen(old);
    try {
      const r = await cli(['pin', 'q@1.4.0'], { ...env, CHAINGATE_PORT: String(port) });
      assert.equal(r.code, 0, r.all);
      assert.match(r.out, /recorded, not in force until the proxy runs this version/);
    } finally { await close(old); }
  });
});

test('G2d-5 (D-U4) pin refusals: 0.0.z, unseen K, a stub, a BLOCKed K — exit 1, nothing written', async () => {
  await withObservedHome(async ({ env, db }) => {
    for (const [spec, re] of [['q@0.0.3', /0\.0\.z/], ['q@1.9.9', /has not seen q@1\.9\.9/], ['q@0.0.1-security', /0\.0\.z|stub/],
      ['p@1.3.0', /BLOCK/], ['bad name@1.0.0', /not a valid/]]) {
      const r = await cli(['pin', spec], env);
      assert.equal(r.code, 1, `${spec}: ${r.all}`);
      assert.match(r.all, re, spec);
    }
    db((h) => { assert.equal(h.listPins().length, 0); assert.equal(h.listAdjudications().length, 0); });
  });
});

test('G2d-9 (D-U7) an override on a version a pin withholds: both commands print the conflict; nothing is deleted', async () => {
  await withObservedHome(async ({ env, db }) => {
    assert.equal((await cli(['allow', 'q@1.5.0', '--reason', 'g2d-9'], env)).code, 0);
    const p = await cli(['pin', 'q@1.4.0'], env);
    assert.equal(p.code, 0, p.all);
    assert.match(p.out, /conflict: an exact override \(chaingate allow\) exists for q@1\.5\.0; the pin withholds it/);
    const a = await cli(['allow', 'q@1.4.5', '--reason', 'g2d-9b'], env);
    assert.equal(a.code, 0, a.all);
    assert.match(a.out, /conflict: your pin on q \(1\.4\.0\) withholds q@1\.4\.5; the pin wins until chaingate unpin q/);
    db((h) => { assert.ok(h.getOverride('q', '1.5.0')); assert.ok(h.getOverride('q', '1.4.5')); assert.equal(h.listPins().length, 1); });
  });
});

test('G2d-10 (D-U8) adjudications: allow, allow-revoke and why are logged with copied classes; why is unchanged and never fails', async () => {
  await withObservedHome(async ({ env, db, home }) => {
    const before = await cli(['why', 'q@1.5.0', '--cached'], env);
    assert.equal((await cli(['allow', 'q@1.5.0', '--reason', 'x'], { ...env, CI: 'true' })).code, 0);
    assert.equal((await cli(['overrides', 'revoke', 'q@1.5.0'], env)).code, 0);
    db((h) => {
      const rows = h.listAdjudications();
      const by = (a) => rows.filter((r) => r.action === a);
      assert.equal(by('why').length, 1);
      assert.deepEqual(by('why')[0].classes.named, ['seed-v3:dac-trajectory:surface'], 'classes copied at the time');
      assert.equal(by('allow').length, 1);
      assert.equal(by('allow')[0].ci, 1);
      assert.equal(by('allow-revoke').length, 1);
      assert.ok(rows.every((r) => r.interactive === 0), 'spawned without a TTY');
    });
    // a read-only witness DB: `why` behaves exactly as before
    fs.chmodSync(path.join(home, 'witness.db'), 0o444);
    try {
      const after = await cli(['why', 'q@1.5.0', '--cached'], env);
      assert.equal(after.code, before.code);
      assert.equal(after.out, before.out);
    } finally { fs.chmodSync(path.join(home, 'witness.db'), 0o644); }
  });
});

test('G2d-11 (D-U1) a witness DB the 0.1.3 code created: the new tables read as empty everywhere', async () => {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'cft014-g2d11-'));
  try {
    const db = openWitnessDB(path.join(home, 'witness.db')).applySchema();
    db.db.exec('DROP TABLE acceptances; DROP TABLE pins; DROP TABLE adjudications; DROP TABLE named_fact_events;');
    db.close();
    const env = { CHAINGATE_HOME: home, CHAINGATE_PORT: String(await freePort()) };
    for (const [args, codes] of [[['status'], [0]], [['accept', '--list'], [0]], [['pin', '--list'], [0]], [['report'], [0]],
      [['why', 'q@1.5.0', '--cached'], [4]]]) {
      const r = await cli(args, env);
      assert.ok(codes.includes(r.code), `${args.join(' ')} exited ${r.code}: ${r.all}`);
      assert.ok(!/no such table/i.test(r.all), `${args.join(' ')}: ${r.all}`);
    }
    const ro = openWitnessDB(path.join(home, 'witness.db'), { readonly: true });
    try {
      assert.deepEqual([ro.listPins(), ro.listAcceptances(), ro.listAdjudications(), ro.getAcceptance('q', '1.5.0')], [[], [], [], null]);
    } finally { ro.close(); }
  } finally { fs.rmSync(home, { recursive: true, force: true }); }
});

test('E27 the usage text lists accept, pin and unpin', async () => {
  const u = await cli(['--help'], {});
  for (const c of ['accept', 'pin', 'unpin']) assert.match(u.out, new RegExp(`^  ${c}\\s+`, 'm'), c);
});
