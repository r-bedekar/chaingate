// U-05 owner decision 10 (C1, C2, D-1, D-2): shared fixtures for the in-process proxy tests.
// A loopback registry serving the synthetic packages (`p`, plus any added), with per-test control of the document
// (N normal, R the D4 refusal path), per-version integrity (real | alt | none), extra versions, metadata status,
// malformed bodies, connection resets and delays. It records every request it receives, in order.
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import { createHash } from 'node:crypto';
import Database from 'better-sqlite3';

import { createProxyServer } from '../../proxy/server.js';
import { openWitnessDB } from '../../witness/db.js';
import { DEFAULT_GATE_MODULES } from '../../gates/index.js';
import { createSeedV3Gate } from '../../seed/v3/gate.js';
import { openSeed, TRUST_UNSIGNED_DEV } from '../../seed/v3/reader.js';
import { buildSeed, docFor, after, manifestFor, PINS } from '../seed-v3/u05-fixtures.mjs';

export { PINS };
export const tgzBytes = (name, version) => Buffer.from(`synthetic tarball ${name}@${version}`);
const sha512 = (b) => `sha512-${createHash('sha512').update(b).digest('base64')}`;
export const tmp = (tag) => fs.mkdtempSync(path.join(os.tmpdir(), `u05-d10-${tag}-`));
const listen = (srv, port = 0) => new Promise((r) => { srv.listen(port, '127.0.0.1', () => r(srv.address().port)); });
const closeServer = (srv) => new Promise((r) => { srv.close(() => r()); srv.closeAllConnections?.(); });

/** The synthetic seed (contract 1.1 layout). `withoutPin` removes one pinned version ("before the advisory"). */
export function seed({ withoutPin = null } = {}) {
  const pins = withoutPin ? PINS.filter((x) => !(x.name === 'p' && x.version === withoutPin)) : PINS;
  return buildSeed({ layout: '1.1', pins });
}

export async function registry() {
  const log = [];
  const pkgs = new Map();            // name -> { extra: [[v, time]], doc: 'N'|'R', mode: {v: real|alt|none}, status, malformed, reset, delayMs }
  const state = (name) => {
    if (!pkgs.has(name)) pkgs.set(name, { extra: [['1.3.0', after(1)], ['1.4.0', after(2)]], doc: 'N', mode: {} });
    return pkgs.get(name);
  };
  const srv = http.createServer(async (req, res) => {
    const u = decodeURIComponent(req.url);
    const t = u.match(/^\/((?:@[^/]+\/)?[^/@][^/]*)\/-\/([^/]+)$/);
    if (t) {
      log.push({ kind: 'tarball', path: u });
      const m = t[2].match(/^(?:.*?)-(\d[^/]*)\.tgz$/);
      res.writeHead(200, { 'content-type': 'application/octet-stream' }); res.end(tgzBytes(t[1], m ? m[1] : t[2])); return;
    }
    const name = u.slice(1);
    log.push({ kind: 'packument', path: u });
    if (!pkgs.has(name) && name !== 'p') { res.writeHead(404, { 'content-type': 'application/json' }); res.end('{}'); return; }
    const s = state(name);
    if (s.delayMs) await new Promise((r) => setTimeout(r, s.delayMs));
    if (s.reset) { req.socket.destroy(); return; }
    if (s.status && s.status !== 200) { res.writeHead(s.status, { 'content-type': 'application/json' }); res.end('{"error":"upstream says no"}'); return; }
    if (s.malformed) { res.writeHead(200, { 'content-type': 'application/json' }); res.end(s.malformed === true ? '{"versions": [not json' : s.malformed); return; }
    const bad = (v) => manifestFor(name, v, { _npmUser: 'alice' });
    const d = docFor(name, s.extra.map(([v, tm]) => (s.doc === 'R' ? [v, tm, bad(v)] : [v, tm])));
    for (const [v, man] of Object.entries(d.versions)) {
      const mode = s.mode[v] ?? 'real';
      const dist = { ...(man.dist ?? {}), tarball: `https://registry.npmjs.org/${name}/-/${name}-${v}.tgz` };
      if (mode === 'real') dist.integrity = sha512(tgzBytes(name, v));
      if (mode === 'alt') dist.integrity = sha512(Buffer.from(`replaced ${name}@${v}`));
      man.dist = dist;
    }
    res.writeHead(200, { 'content-type': 'application/json' }); res.end(JSON.stringify(d));
  });
  const port = await listen(srv);
  return { url: `http://127.0.0.1:${port}`, log, set: (name, patch) => Object.assign(state(name), patch),
    count: (kind, p) => log.filter((e) => e.kind === kind && (!p || e.path === p)).length, close: () => closeServer(srv) };
}

/** A switch that makes the seed handle refuse every read ("the seed cannot be read"). */
export function faultySeed(seedHandle, sw) {
  const wrap = (obj) => new Proxy(obj, { get(t, k) {
    const v = Reflect.get(t, k, t);
    if (typeof v === 'function') {
      return (...a) => { if (sw.on) throw new Error('injected: the seed cannot be read'); const out = v.apply(t, a); return out && typeof out === 'object' ? wrap(out) : out; };
    }
    return v;
  } });
  return new Proxy(seedHandle, { get(t, k) { const v = Reflect.get(t, k, t); return k === 'db' ? wrap(v) : (typeof v === 'function' ? v.bind(t) : v); } });
}

/**
 * The proxy under test (this tree), in this process. policy: 'BLOCK' | 'WARN'; v3:false = no v3 seed (legacy/--no-seed).
 * seedFault: a switch object; the shipped gate set is then built exactly as proxy/server.js builds it, with the seed
 * handle behind the switch. hooks: passed through (C1 limits for the tracking tests).
 */
export async function proxy({ upstream, witness, policy = 'BLOCK', v3 = true, seedDb, seedFault = null, hooks = {}, config = {} }) {
  const cfg = { port: 0, host: '127.0.0.1', upstream, witnessDbPath: witness, headersTimeoutMs: 5_000, bodyTimeoutMs: 15_000, ...config };
  if (v3) Object.assign(cfg, { seedV3Path: seedDb, seedV3Trust: 'unsigned-development', policyOnUnusableInput: policy, policyOnNoEvidence: 'WARN' });
  const h = { ...hooks };
  let handle = null;
  if (seedFault) {
    handle = openSeed(seedDb, { trust: TRUST_UNSIGNED_DEV });
    h.gateModules = [...DEFAULT_GATE_MODULES, createSeedV3Gate({ seed: faultySeed(handle, seedFault),
      config: { on_unusable_input: policy, on_no_evidence: 'WARN' }, domainVersionCount: 'from-packument' })];
  }
  const px = createProxyServer(cfg, h);
  const port = await listen(px);
  let stopped = null;
  const p = { px, url: `http://127.0.0.1:${port}`, stop: () => {
    // Idempotent; a test may stop a proxy itself and the cleanup stops every proxy still live (stopAll).
    stopped ??= (async () => { LIVE.delete(p); await closeServer(px); try { handle?.close?.(); } catch { /* closed */ } })();
    return stopped;
  } };
  LIVE.add(p);
  return p;
}

// Every proxy still running. Windows cannot delete a file a live proxy holds open (EBUSY), and a proxy left running keeps
// the test file's process alive, so each test's cleanup stops them all FIRST (harness correction, CI run 37024289506).
const LIVE = new Set();
export async function stopAll() { for (const p of [...LIVE]) { try { await p.stop(); } catch { /* reported by the test */ } } }
/** Run one cleanup step; a failure in it never skips the next one. */
export async function safely(fn) { try { await fn(); } catch { /* best effort */ } }

export function getJson(url) {
  return new Promise((resolve, reject) => {
    http.get(url, { agent: false }, (res) => {
      let b = ''; res.setEncoding('utf8'); res.on('data', (x) => { b += x; });
      res.on('end', () => { let json = null; try { json = JSON.parse(b); } catch { /* not JSON */ } resolve({ status: res.statusCode, json, body: b }); });
    }).on('error', reject);
  });
}
export const tarball = (px, name, version, file = null) => getJson(`${px.url}/${name}/-/${file ?? `${name}-${version}.tgz`}`);
export const packument = async (px, name) => { const r = await getJson(`${px.url}/${name}`); return { status: r.status, versions: Object.keys(r.json?.versions ?? {}) }; };

export function rows(witness, name, version) {
  const d = new Database(witness, { readonly: true });
  try {
    return d.prepare('SELECT id, disposition, gates_fired, decided_at FROM gate_decisions WHERE package_name = ? AND version = ? ORDER BY id')
      .all(name, version);
  } finally { d.close(); }
}
export const dispositions = (witness, name, version) => rows(witness, name, version).map((r) => r.disposition);

/** A witness whose decision inserts for `name` fail (storage failing), created with this tree's schema. */
export function failingWitness(dir, name = 'p') {
  const w = path.join(dir, 'witness.db');
  const d = openWitnessDB(w); d.applySchema(); d.close();
  const raw = new Database(w);
  raw.exec(`CREATE TRIGGER d10_inject BEFORE INSERT ON gate_decisions WHEN NEW.package_name = '${name}'
    BEGIN SELECT RAISE(ABORT, 'injected: decision storage refuses this write'); END;`);
  raw.close();
  return w;
}
export function repairWitness(w) { const raw = new Database(w); raw.exec('DROP TRIGGER IF EXISTS d10_inject'); raw.close(); }

/** Rows exactly as a test states them (ids and content preserved), into a witness with this tree's schema. */
export function insertRows(w, list, overrides = []) {
  const d = openWitnessDB(w); d.applySchema(); d.close();
  const raw = new Database(w);
  const ins = raw.prepare('INSERT INTO gate_decisions (id, package_name, version, disposition, gates_fired, decided_at) VALUES (?, ?, ?, ?, ?, ?)');
  const tx = raw.transaction(() => {
    for (const r of list) ins.run(r.id, r.package_name, r.version, r.disposition, typeof r.gates_fired === 'string' ? r.gates_fired : JSON.stringify(r.gates_fired), r.decided_at);
    for (const o of overrides) raw.prepare('INSERT INTO overrides (package_name, version, reason, created_at) VALUES (?, ?, ?, ?)').run(o.package_name, o.version, o.reason, o.created_at ?? '2026-01-01 00:00:00');
  });
  tx(); raw.close();
}

const HIST = path.join(path.dirname(new URL(import.meta.url).pathname), '..', 'fixtures', 'u05-d10-historical');
/** A scenario's rows as WRITTEN BY a published runtime (fixtures captured by capture.mjs). */
export function historical(runtimeVersion, scenario) {
  const f = JSON.parse(fs.readFileSync(path.join(HIST, `${runtimeVersion}.json`), 'utf8'));
  const s = f.scenarios[scenario];
  if (!s || s.error) throw new Error(`no captured scenario ${scenario} for ${runtimeVersion}: ${s?.error}`);
  return { provenance: f.provenance, policy: s.policy, rows: s.gate_decisions, overrides: s.overrides };
}
export const PUBLISHED = ['0.1.0', '0.1.1', '0.1.2'];
