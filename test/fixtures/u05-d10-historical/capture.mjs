// U-05 owner decision 10 (C2, F10): capture decision histories WRITTEN BY A PUBLISHED RUNTIME, as fixtures for the
// candidate's applicable-BLOCK rule. NOT a test (no .test. in the name); run once per published version, through qrun.
//
//   node capture.mjs <published runtime dir> <its published tarball sha256> <runtime worktree> <out.json>
//
// The published runtime's OWN proxy (createProxyServer) runs in this process against a loopback registry serving the
// synthetic package `p` (seed: contract 1.0 layout, p@1.3.0 pinned as ADV-P-130). Every row is what that published code
// wrote; nothing is edited. Documents: N = normal; R = the D4 refusal path (a malformed `_npmUser` makes the seed-v3
// input unusable). Integrity modes per version: real | alt (a different sha512) | none (no hash fields).
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { pathToFileURL } from 'node:url';

const [PKG, TGZ_SHA, WT, OUTARG] = process.argv.slice(2);
if (!PKG || !TGZ_SHA || !WT || !OUTARG) { console.error('usage: node capture.mjs <runtime dir> <tarball sha256> <worktree> <out.json>'); process.exit(2); }
const imp = (rel) => import(pathToFileURL(path.join(PKG, rel)).href);
const { createProxyServer } = await imp('proxy/server.js');
const { openWitnessDB } = await imp('witness/db.js');
const F = await import(pathToFileURL(path.join(WT, 'test', 'seed-v3', 'u05-fixtures.mjs')).href);
const runtimeVersion = JSON.parse(fs.readFileSync(path.join(PKG, 'package.json'), 'utf8')).version;
const sha512 = (s) => `sha512-${createHash('sha512').update(s).digest('base64')}`;
const quiet = () => {}; console.error = quiet; console.warn = quiet;

const bad = (v) => F.manifestFor('p', v, { _npmUser: 'alice' });
const DOCS = {
  N: F.docFor('p', [['1.3.0', F.after(1)], ['1.4.0', F.after(2)]]),
  R: F.docFor('p', [['1.3.0', F.after(1), bad('1.3.0')], ['1.4.0', F.after(2), bad('1.4.0')]]),
};
let doc = 'N'; const mode = {};
const registry = http.createServer((req, res) => {
  if (decodeURIComponent(req.url) !== '/p') { res.writeHead(404); res.end('{}'); return; }
  const d = structuredClone(DOCS[doc]);
  for (const [v, man] of Object.entries(d.versions)) {
    const m = mode[v] ?? 'real';
    const dist = { ...(man.dist ?? {}) };
    if (m === 'real') dist.integrity = sha512(`p@${v} synthetic tarball`);
    if (m === 'alt') dist.integrity = sha512(`p@${v} REPLACED bytes`);
    man.dist = dist;
  }
  res.writeHead(200, { 'content-type': 'application/json' }); res.end(JSON.stringify(d));
});
const listen = (s) => new Promise((r) => s.listen(0, '127.0.0.1', () => r(`http://127.0.0.1:${s.address().port}`)));
const close = (s) => new Promise((r) => { s.close(() => r()); s.closeAllConnections?.(); });
const get = (u) => new Promise((resolve, reject) => http.get(u, { agent: false }, (r) => { r.resume(); r.on('end', () => resolve(r.statusCode)); }).on('error', reject));
const UP = await listen(registry);
const seed = F.buildSeed({ layout: '1.0' });

async function scenario(id, policy, steps) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), `d10-hist-${id}-`)); const w = path.join(dir, 'witness.db');
  const out = { policy, steps: [], error: null };
  try {
    for (const s of steps) {
      if (s.override === 'add' || s.override === 'remove') {
        const d = openWitnessDB(w); try { if (s.override === 'add') d.insertOverride('p', s.version, 'fixture: operator override'); else d.deleteOverride('p', s.version); } finally { d.close(); }
        out.steps.push({ override: s.override, version: s.version }); continue;
      }
      doc = s.doc ?? 'N'; for (const k of Object.keys(mode)) delete mode[k]; Object.assign(mode, s.mode ?? {});
      const px = createProxyServer({ port: 0, host: '127.0.0.1', upstream: UP, witnessDbPath: w, seedV3Path: seed.dbPath,
        seedV3Trust: 'unsigned-development', policyOnUnusableInput: policy, policyOnNoEvidence: 'WARN' }, {});
      const url = await listen(px);
      const status = await get(`${url}/p`);
      await close(px);
      out.steps.push({ doc, mode: { ...mode }, packument_status: status });
    }
    const d = openWitnessDB(w);
    try {
      out.gate_decisions = d.db.prepare("SELECT id, package_name, version, disposition, gates_fired, decided_at FROM gate_decisions WHERE package_name = 'p' ORDER BY id").all();
      out.overrides = d.db.prepare("SELECT * FROM overrides WHERE package_name = 'p'").all();
    } finally { d.close(); }
  } catch (e) { out.error = e.message; }
  fs.rmSync(dir, { recursive: true, force: true });
  return out;
}

const R = { real: 'real', alt: 'alt', none: 'none' };
const scenarios = {
  // pin BLOCK; the refusal path under WARN writes an input-rule row over it (D4 in 1.0); repeated; back to the pin
  'pin-input-warn': ['WARN', [{ doc: 'N' }, { doc: 'R' }, { doc: 'R' }, { doc: 'N' }, { doc: 'R' }]],
  // control: under BLOCK the refusal path BLOCKs too (no state change for the pinned version)
  'pin-input-block': ['BLOCK', [{ doc: 'N' }, { doc: 'R' }, { doc: 'N' }]],
  // content-hash BLOCK, evidence gap, definitive match (not written: same disposition), BLOCK again, gap again
  'ch-gap': ['BLOCK', [{ mode: { '1.4.0': R.real } }, { mode: { '1.4.0': R.alt } }, { mode: { '1.4.0': R.none } },
    { mode: { '1.4.0': R.none } }, { mode: { '1.4.0': R.real } }, { mode: { '1.4.0': R.alt } }, { mode: { '1.4.0': R.none } }]],
  // content-hash BLOCK, then a definitive match: legitimate clearance
  'ch-clear': ['BLOCK', [{ mode: { '1.4.0': R.real } }, { mode: { '1.4.0': R.alt } }, { mode: { '1.4.0': R.real } }]],
  // pin BLOCK, an override recorded and applied, then the override revoked (no further observation)
  'override-revoke': ['BLOCK', [{ doc: 'N' }, { override: 'add', version: '1.3.0' }, { doc: 'N' }, { override: 'remove', version: '1.3.0' }]],
  // a row with TWO blocking gates (content-hash + pin), then a row that clears only content-hash
  'multi': ['WARN', [{ doc: 'N', mode: { '1.3.0': R.real } }, { doc: 'R', mode: { '1.3.0': R.real } },
    { doc: 'N', mode: { '1.3.0': R.alt } }, { doc: 'R', mode: { '1.3.0': R.real } }]],
  // a long history: pin BLOCK, then 40 alternating refusal-path and gap observations under WARN
  'long': ['WARN', [{ doc: 'N' }, ...Array.from({ length: 40 }, (_, i) => (i % 2
    ? { doc: 'R', mode: { '1.3.0': R.none, '1.4.0': R.none } } : { doc: 'N', mode: { '1.3.0': R.none, '1.4.0': R.real } }))]],
};
const result = { provenance: { runtime_version: runtimeVersion, published_tarball_sha256: TGZ_SHA, node: process.version,
  captured_at: new Date().toISOString(), capture_script_sha256: createHash('sha256').update(fs.readFileSync(new URL(import.meta.url))).digest('hex'),
  seed: 'u05-fixtures buildSeed layout 1.0 (p@1.3.0 ADV-P-130)' }, scenarios: {} };
for (const [id, [policy, steps]] of Object.entries(scenarios)) result.scenarios[id] = await scenario(id, policy, steps);
await close(registry); seed.cleanup();
fs.writeFileSync(OUTARG, `${JSON.stringify(result, null, 1)}\n`);
const summary = Object.fromEntries(Object.entries(result.scenarios).map(([k, v]) => [k, v.error ? `ERROR ${v.error}` : `${v.gate_decisions.length} rows`]));
process.stdout.write(`${runtimeVersion}: ${JSON.stringify(summary)}\n`);
