// 0.1.4 group 2, unit 2c — `chaingate report` (D-R3, E21): from a running proxy, from the disk record when none answers
// (G2c-10), and the commands that read a witness DB the 0.1.3 code created (G2c-3). Expected results: decision tables
// ~/docs/plans/CFT/0.1.4-IMPL-DECISION-TABLES-G2-TIER0-20261011.md §7 and dated note 6, written before this file.
// The CLI runs as a child process (asynchronously: the proxy under test runs in this process).
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
const get = (url, session) => new Promise((resolve, reject) => {
  http.get(url, { agent: false, headers: session ? { 'npm-session': session } : {} }, (res) => {
    res.resume(); res.on('end', () => resolve(res.statusCode));
  }).on('error', reject);
});
function cli(args, env) {
  return new Promise((resolve) => {
    const c = spawn(process.execPath, [CLI, ...args], { env: { ...process.env, NO_COLOR: '1', ...env } });
    let out = ''; let err = '';
    c.stdout.on('data', (b) => { out += b; }); c.stderr.on('data', (b) => { err += b; });
    const timer = setTimeout(() => c.kill('SIGKILL'), 60_000);
    c.on('close', (code) => { clearTimeout(timer); resolve({ code, out, err }); });
  });
}

const strict = () => manifestFor('q', '1.5.0', { scripts: { postinstall: 'node x.js' },
  dist: { unpackedSize: 10_000, attestations: { url: 'https://x' } } });
const DOCS = () => {
  const p = docFor('p', [['1.3.0', after(1)]]);
  p['dist-tags'] = { latest: '1.3.0' };
  const q = docFor('q', [['1.4.0', after(1), manifestFor('q', '1.4.0', { scripts: { postinstall: 'node x.js' } })],
    ['1.4.5', iso(TIP_S + 2 * STEP_S - 3600)], ['1.5.0', after(2), strict()]]);
  q['dist-tags'] = { latest: '1.5.0' };
  q.versions['1.0.0'].scripts = { postinstall: 'node legacy.js' };   // G3 dated note 1.2: T1.1 stays quiet; the seed rows are the subject
  return { p, q };
};

async function withHome(fn) {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'cft014-g2c-cli-'));
  try { return await fn(home); } finally { fs.rmSync(home, { recursive: true, force: true }); }
}
async function startProxy(home, s) {
  const docs = DOCS();
  const upstream = http.createServer((req, res) => {
    const url = decodeURIComponent(req.url);
    if (url.includes('/-/')) { res.writeHead(200, { 'content-type': 'application/octet-stream' }); res.end('tarball-bytes'); return; }
    const d = docs[url.slice(1)];
    if (!d) { res.writeHead(404, { 'content-type': 'application/json' }); res.end('{}'); return; }
    res.writeHead(200, { 'content-type': 'application/json' }); res.end(JSON.stringify(d));
  });
  const up = await listen(upstream);
  const proxy = createProxyServer({ port: 0, host: '127.0.0.1', upstream: `http://127.0.0.1:${up}`, witnessDbPath: path.join(home, 'witness.db'),
    headersTimeoutMs: 5_000, bodyTimeoutMs: 15_000, seedV3Path: s.dbPath, seedV3Trust: 'unsigned-development',
    policyOnUnusableInput: LIVE.on_unusable_input, policyOnNoEvidence: LIVE.on_no_evidence });
  const port = await listen(proxy);
  return { port, url: `http://127.0.0.1:${port}`, stop: async () => { await close(proxy); await close(upstream); } };
}
const tgz = (name, v) => `/${name}/-/${name}-${v}.tgz`;
const CACHE_LINE = 'Packages npm installed from its own cache never reach ChainGate and are not listed here.';

test('G2c-4b/G2c-8b (D-R3, D-R4, E21) `chaingate report` from a running proxy: the latest install, --all, --json, exit codes', async () => {
  await withHome(async (home) => {
    const s = buildSeed({ layout: '1.1' });
    const realErr = console.error; console.error = () => {};
    const px = await startProxy(home, s);
    try {
      const env = { CHAINGATE_HOME: home, CHAINGATE_PORT: String(px.port) };
      const empty = await cli(['report'], env);
      assert.equal(empty.code, 0, empty.out + empty.err);
      assert.match(empty.out, /No install recorded by the running proxy since \d{4}-\d\d-\d\dT/);

      await get(`${px.url}/q`, 'clinamed1');
      assert.equal(await get(`${px.url}${tgz('q', '1.5.0')}`, 'clinamed1'), 200);
      const a = await cli(['report'], env);
      assert.equal(a.code, 2, a.out + a.err);
      for (const line of [
        'q@1.5.0  NAMED WARNING: release-history break vs the seed (2+ package-wide signals)',
        "  last version without the signal: q@1.4.0 (based on this proxy's records)",
        '  to stay on 1.4.0: chaingate pin q@1.4.0',
        '  to accept this version: chaingate accept q@1.5.0',
        CACHE_LINE,
      ]) assert.ok(a.out.split('\n').includes(line), `missing ${JSON.stringify(line)} in:\n${a.out}`);

      await get(`${px.url}/p`, 'clifact2');
      assert.equal(await get(`${px.url}${tgz('p', '1.3.0')}`, 'clifact2'), 403);
      const b = await cli(['report'], env);
      assert.equal(b.code, 3, b.out);
      assert.ok(b.out.includes('p@1.3.0  BLOCKED (download refused): a recorded advisory names this version — npm could not install it'), b.out);
      assert.ok(!b.out.includes('q@1.5.0  NAMED WARNING'), 'by default only the latest install');

      const all = await cli(['report', '--all'], env);
      assert.equal(all.code, 3);
      assert.ok(all.out.includes('q@1.5.0  NAMED WARNING') && all.out.includes('p@1.3.0  BLOCKED'), all.out);

      const j = await cli(['report', '--json'], env);
      assert.equal(j.code, 3);
      const parsed = JSON.parse(j.out);
      assert.equal(parsed.source, 'proxy');
      assert.equal(parsed.exit, 3);
      assert.equal(parsed.installs.length, 1);
      assert.equal(parsed.policy, 'cft-policy-1.3');   // since 0.1.6
    } finally {
      console.error = realErr;
      await px.stop(); s.cleanup();
    }
  });
});

test('G2c-10 (D-R3) no proxy answering: the disk record of the last 24 h, with the stated limitation', async () => {
  await withHome(async (home) => {
    const s = buildSeed({ layout: '1.1' });
    const realErr = console.error; console.error = () => {};
    const px = await startProxy(home, s);
    try {
      await get(`${px.url}/q`, 'clidisk1');
      await get(`${px.url}${tgz('q', '1.5.0')}`, 'clidisk1');
      await get(`${px.url}/p`, 'clidisk1');
      await get(`${px.url}${tgz('p', '1.3.0')}`, 'clidisk1');
    } finally { console.error = realErr; await px.stop(); }
    try {
      const env = { CHAINGATE_HOME: home, CHAINGATE_PORT: String(await freePort()) };
      const r = await cli(['report'], env);
      assert.equal(r.code, 3, r.out + r.err);
      assert.match(r.out, /No ChainGate proxy answered on 127\.0\.0\.1:\d+/);
      assert.ok(r.out.includes('the per-install summary (every package served, and what was not checked) is held only by a running proxy'), r.out);
      assert.ok(r.out.includes('q@1.5.0  NAMED WARNING: release-history break vs the seed (2+ package-wide signals)'));
      assert.ok(r.out.includes("  last version without the signal: q@1.4.0 (based on this proxy's records)"), 'K as recorded when served');
      assert.ok(r.out.includes('p@1.3.0  BLOCKED (download refused): a recorded advisory names this version'));
      assert.ok(r.out.includes('p: dist-tag latest moved from 1.3.0 to 1.2.0: a recorded advisory names this version'));
      assert.ok(r.out.includes(CACHE_LINE));
      const j = JSON.parse((await cli(['report', '--json'], env)).out);
      assert.equal(j.source, 'disk');
      assert.equal(j.events.length, 3);
      assert.equal((await cli(['report', '--since', '7d'], env)).code, 3);
      const bad = await cli(['report', '--since', 'soon'], env);
      assert.equal(bad.code, 4);
      assert.match(bad.err, /--since/);
    } finally { s.cleanup(); }
  });
});

test('G2c-3c (D-R2) a witness DB the 0.1.3 code created: status, why --cached, check, report, allow, overrides all work', async () => {
  await withHome(async (home) => {
    const s = buildSeed({ layout: '1.1' });
    try {
      const dbPath = path.join(home, 'witness.db');
      const db = openWitnessDB(dbPath).applySchema();
      db.recordBaseline('p', '1.2.0', { published_at: iso(TIP_S) });
      db.insertGateDecision('p', '1.2.0', 'ALLOW', [{ gate: 'seed-v3', result: 'ALLOW', detail: 'cft-policy-1.1: ok' }]);
      db.db.exec('DROP TABLE named_fact_events');
      db.close();
      const pk = path.join(home, 'p.json');
      fs.writeFileSync(pk, JSON.stringify(docFor('p')));
      const env = { CHAINGATE_HOME: home, CHAINGATE_PORT: String(await freePort()), CHAINGATE_SEED_V3: s.dbPath,
        CHAINGATE_SEED_V3_TRUST: 'unsigned-development', CHAINGATE_POLICY_ON_UNUSABLE_INPUT: LIVE.on_unusable_input,
        CHAINGATE_POLICY_ON_NO_EVIDENCE: LIVE.on_no_evidence };
      const runs = [
        [['status'], [0]],
        [['why', 'p@1.2.0', '--cached'], [4]],
        [['check', 'p@1.2.0', '--packument', pk], [0, 2, 3]],
        [['report'], [0]],
        [['allow', 'p@1.2.0', '--reason', 'g2c-3c'], [0]],
        [['overrides'], [0]],
      ];
      for (const [args, codes] of runs) {
        const r = await cli(args, env);
        assert.ok(codes.includes(r.code), `${args.join(' ')} exited ${r.code}:\n${r.out}\n${r.err}`);
        assert.ok(!/no such table/i.test(r.out + r.err), `${args.join(' ')}:\n${r.err}`);
      }
    } finally { s.cleanup(); }
  });
});

test('E21 the usage text lists `report`, and `report --help` prints its synopsis', async () => {
  const u = await cli(['--help'], {});
  assert.match(u.out, /^ {2}report\s+/m);
  const h = await cli(['report', '--help'], {});
  assert.equal(h.code, 0);
  assert.match(h.out, /chaingate report \[--all \| --since <dur>\] \[--json\]/);
});
