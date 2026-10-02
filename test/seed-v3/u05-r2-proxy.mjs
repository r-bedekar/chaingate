// Shared harness for the U-05 gap-closure r2 proxy tests (owner decision 6). Not a test file and not a capture script:
// it only builds a loopback fixture registry and an in-process proxy on a throwaway witness database.
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import { createProxyServer } from '../../proxy/server.js';
import { buildSeed, docFor, manifestFor, after } from './u05-fixtures.mjs';

export const listen = (srv) => new Promise((resolve) => { srv.listen(0, '127.0.0.1', () => resolve(`http://127.0.0.1:${srv.address().port}`)); });
export const close = (srv) => new Promise((resolve) => { srv.close(() => resolve()); });
export const get = (url) => new Promise((resolve, reject) => {
  http.get(url, { agent: false }, (res) => {
    let b = ''; res.setEncoding('utf8'); res.on('data', (x) => { b += x; });
    res.on('end', () => { let json = null; try { json = JSON.parse(b); } catch { /* not JSON */ } resolve({ status: res.statusCode, json, body: b }); });
  }).on('error', reject);
});
export const versionsOf = (r) => Object.keys(r.json?.versions ?? {});
export const tgz = (name, v) => `/${name}/-/${name.split('/').pop()}-${v}.tgz`;
export const TRIGGER = (pkg, ver) => `CREATE TRIGGER r2_${pkg.replace(/\W/g, '_')}_${String(ver ?? 'all').replace(/\W/g, '_')}
  BEFORE INSERT ON gate_decisions WHEN NEW.package_name = '${pkg}'${ver ? ` AND NEW.version = '${ver}'` : ''}
  BEGIN SELECT RAISE(ABORT, 'injected write failure'); END;`;
export const DROP = (pkg, ver) => `DROP TRIGGER r2_${pkg.replace(/\W/g, '_')}_${String(ver ?? 'all').replace(/\W/g, '_')}`;

export const DOCS = () => ({
  p: docFor('p', [['1.3.0', after(1)], ['1.4.0', after(2)]]),
  q: docFor('q', [['1.3.0', after(1)]]),
  n: docFor('n', [['1.0.1', after(1)]]),
  w: docFor('w', [['2.0.0', after(1)]]),
  x: docFor('x', [['2.0.0', after(1)]]),
  y: docFor('y', [['2.0.0', after(1)]]),
  z: docFor('z', [['2.0.0', after(1)]]),
});
/** A packument whose manifests are all unreadable (store.js S1 path). */
export const unreadableDoc = (name) => {
  const d = docFor(name, [['2.0.0', after(1)]]);
  return { ...d, versions: Object.fromEntries(Object.keys(d.versions).map((v) => [v, 'not-a-manifest'])) };
};
export { manifestFor };

/** A pilot test gate (named content-hash: exempt from the thin-history SKIP) whose verdicts a test can change. */
export function scriptedGate(verdicts = {}) {
  const gate = { name: 'content-hash', verdicts, evaluate: (i) => {
    const v = gate.verdicts[`${i.packageName}@${i.version}`];
    // Owner decision 10 (C2): an explicit scripted ALLOW stands for content-hash's DEFINITIVE clearance, in its own words;
    // only that clears a held or stored content-hash BLOCK (a plain ALLOW or a SKIP no longer does).
    if (v === 'ALLOW') return { gate: 'content-hash', result: 'ALLOW', detail: `integrity hash matches baseline (scripted for ${i.packageName}@${i.version})` };
    return v ? { gate: 'content-hash', result: v, detail: `scripted ${v} for ${i.packageName}@${i.version}` }
      : { gate: 'content-hash', result: 'ALLOW', detail: 'scripted ALLOW' };
  } };
  return gate;
}

/**
 * One proxy on a loopback registry. `cfg` = LIVE | WARNCFG (seed-v3 configured, policy from cfg) or null (pilot only).
 * `gateModules` replaces the gate modules (the seed is still opened, so the configured failure policy applies). `conf`
 * adds config overrides (e.g. the unstored-BLOCK caps); `hooks` is passed through (e.g. logBudget).
 */
export async function withProxy({ cfg = null, gateModules = null, docs = DOCS(), dir = null, seed = null, conf = {},
  hooks = {}, quiet = true } = {}, fn) {
  const ownSeed = cfg && !seed ? buildSeed({ layout: '1.1' }) : null;
  const s = seed ?? ownSeed;
  const wdir = dir ?? fs.mkdtempSync(path.join(os.tmpdir(), 'u05-r2-'));
  const fetches = [];
  const upstream = http.createServer((req, res) => {
    const url = decodeURIComponent(req.url);
    fetches.push(url);
    if (url.includes('/-/')) { res.writeHead(200, { 'content-type': 'application/octet-stream' }); res.end('tarball-bytes'); return; }
    const d = docs[url.slice(1)];
    if (!d) { res.writeHead(404, { 'content-type': 'application/json' }); res.end('{}'); return; }
    res.writeHead(200, { 'content-type': 'application/json' }); res.end(JSON.stringify(d));
  });
  const upstreamUrl = await listen(upstream);
  const config = { port: 0, host: '127.0.0.1', upstream: upstreamUrl, witnessDbPath: path.join(wdir, 'witness.db'),
    headersTimeoutMs: 5_000, bodyTimeoutMs: 15_000, ...conf };
  if (cfg) Object.assign(config, { seedV3Path: s.dbPath, seedV3Trust: 'unsigned-development',
    policyOnUnusableInput: cfg.on_unusable_input, policyOnNoEvidence: cfg.on_no_evidence });
  const logs = []; const realErr = console.error;
  console.error = (m) => { logs.push(String(m)); if (!quiet) realErr(m); };
  let proxy;
  try {
    proxy = createProxyServer(config, { ...(gateModules ? { gateModules } : {}), ...hooks });
  } catch (err) { console.error = realErr; await close(upstream); throw err; }
  const proxyUrl = await listen(proxy);
  const h = {
    proxy, proxyUrl, fetches, logs, dir: wdir, seed: s,
    get: (p) => get(`${proxyUrl}${p}`),
    tarball: async (n, v) => get(`${proxyUrl}${tgz(n, v)}`),
    self: async () => (await get(`${proxyUrl}/_chaingate/self`)).json,
    exec: (sql) => proxy.witnessDb.db.exec(sql),
  };
  try {
    return await fn(h);
  } finally {
    console.error = realErr;
    await close(proxy); await close(upstream);
    if (!dir && !seed) { ownSeed?.cleanup(); fs.rmSync(wdir, { recursive: true, force: true }); }
  }
}
