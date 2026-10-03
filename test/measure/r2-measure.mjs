// U-05 gap-closure r2 §3.9: resource and log measurement of a runtime package (installed, or this checkout in CI).
// NOT a test file (outside the suite glob). Synthetic seed, loopback registry, a throwaway witness database whose
// decision writes are made to fail by a trigger, so every BLOCK is held in the unstored record.
//
//   node test/measure/r2-measure.mjs --pkg <runtime dir> --wt <checkout with test/seed-v3> --scenario <S> --out <json>
//        [--reduced] [--seconds <n>] [--rate <req/s>]
//   S: M1 distinct keys to 10k / cap / cap+10k        M2 maximum-size identities and details (byte cap binds)
//      M3 one key replaced (module level)             M4 one version per package, then full removal (module level)
//      L1 log bytes, repeated key   L2 distinct keys  L3 churn of two key sets   L4 sustained FULL (10 min)
//      P1 requests/s on two workloads (run it on the baseline package too, and compare)
//
// The driver re-runs itself as a child whose stdout and stderr ARE the proxy log file, opened in append mode as
// `chaingate init` opens proxy.log for the proxy it spawns, so the log bytes reported are what the proxy wrote. The
// child loads the package's proxy in-process and is run with --expose-gc. Expected values are written below, before any
// run, and every result carries its verdict against them. Figures are per platform; nothing here tunes a default.
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { pathToFileURL, fileURLToPath } from 'node:url';

const argv = process.argv.slice(2);
const arg = (k, d = null) => { const i = argv.indexOf(`--${k}`); return i >= 0 ? argv[i + 1] : d; };
const flag = (k) => argv.includes(`--${k}`);
const SELF = fileURLToPath(import.meta.url);
const PKG = path.resolve(arg('pkg') ?? '.');
const WT = path.resolve(arg('wt') ?? '.');
const SCENARIO = arg('scenario');
const OUT = path.resolve(arg('out') ?? `r2-measure-${SCENARIO}.json`);
const REDUCED = flag('reduced');

// ---- the expected values (written before the runs) --------------------------------------------------------------------
const KIB = 1024;
const LOG = { burst: 300, perSecond: 1, lineBytes: 1024, summaryPerMinute: 1 };
/** Upper bound for proxy.log bytes over `seconds` of output: the burst, the refill, one summary a minute, 8 KiB slack for
 *  the start-up lines. Every line is at most 1 KiB plus its newline. */
const logBound = (seconds) => (LOG.burst + Math.ceil(seconds) * LOG.perSecond + Math.ceil(seconds / 60 + 1) * 2) * (LOG.lineBytes + 1) + 8 * KIB;
const EXPECTED = {
  M1: 'count = min(keys, entry cap); FULL set when the first entry BEYOND the cap is refused; estimated bytes and count constant '
    + 'after it; response statuses recorded; retained heap and RSS stop growing with the record (within GC noise); '
    + 'proxy.log within the log budget',
  M2: 'maximum-size identities (name 214, version 256) and long details: the estimated byte cap binds before the entry '
    + 'cap; FULL is set then; estimated bytes never exceed the byte cap',
  M3: 'one key replaced many times: count stays 1; the estimate equals C_FIXED + P + E(current detail) after every '
    + 'replacement, matching recompute()',
  M4: 'N packages with one version each: estimate = C_FIXED + sum(P + E); after every entry is stored and removed, the '
    + 'estimate returns to C_FIXED and the count to 0',
  L1: 'repeated key: proxy.log bytes within the budget bound for the run length',
  L2: 'distinct keys: proxy.log bytes within the budget bound',
  L3: 'churn of two key sets larger than any per-key structure: proxy.log bytes within the budget bound',
  L4: 'sustained FULL for 10 minutes at a fixed rate: proxy.log bytes within the budget bound; heap flat',
  P1: 'requests/s reported for both workloads; compared with the baseline package by the caller. A slowdown over 10 % is '
    + 'reported, not tuned away',
};

// ---- driver --------------------------------------------------------------------------------------------------------------
if (!flag('child')) {
  if (!EXPECTED[SCENARIO]) { console.error(`--scenario must be one of ${Object.keys(EXPECTED).join(' ')}`); process.exit(2); }
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), `cg-measure-${SCENARIO}-`));
  const logPath = path.join(dir, 'proxy.log');
  const fd = fs.openSync(logPath, 'a');
  const t0 = Date.now();
  const child = spawn(process.execPath, ['--expose-gc', SELF, ...argv, '--child', '--dir', dir, '--log', logPath],
    { stdio: ['ignore', fd, fd] });
  const code = await new Promise((r) => child.on('close', (c) => r(c)));
  fs.closeSync(fd);
  let result = null;
  try { result = JSON.parse(fs.readFileSync(path.join(dir, 'result.json'), 'utf8')); } catch { /* the child failed */ }
  const logBytes = fs.statSync(logPath).size;
  const out = { ...(result ?? { scenario: SCENARIO, error: `child exited ${code} without a result` }), child_exit: code,
    wall_s: (Date.now() - t0) / 1000, proxy_log_bytes_final: logBytes,
    proxy_log_tail: fs.readFileSync(logPath, 'utf8').split('\n').slice(-6) };
  if (result?.log_bound != null) out.verdict.log_within_bound = logBytes <= result.log_bound;
  out.ok = Boolean(result) && code === 0 && Object.values(out.verdict ?? { failed: false }).every(Boolean);
  fs.writeFileSync(OUT, `${JSON.stringify(out, null, 2)}\n`);
  console.log(`${SCENARIO}: ${out.ok ? 'PASS' : 'FAIL'}  log ${logBytes} B  ${JSON.stringify(out.verdict ?? {})}  -> ${OUT}`);
  fs.rmSync(dir, { recursive: true, force: true });
  process.exit(out.ok ? 0 : 1);
}

// ---- child: everything below writes to the proxy log only through the proxy -----------------------------------------
const DIR = arg('dir'); const LOGP = arg('log');
const imp = (base, rel) => import(pathToFileURL(path.join(base, rel)).href);
const version = JSON.parse(fs.readFileSync(path.join(PKG, 'package.json'), 'utf8')).version;
const result = { scenario: SCENARIO, expected: EXPECTED[SCENARIO], package: PKG, package_version: version,
  node: process.version, platform: `${process.platform}-${process.arch}`, reduced: REDUCED, checkpoints: [], verdict: {} };
const finish = (extra = {}) => { fs.writeFileSync(path.join(DIR, 'result.json'), JSON.stringify({ ...result, ...extra })); process.exit(0); };
const gc = () => { global.gc(); global.gc(); };
const mem = () => { gc(); const m = process.memoryUsage(); return { heap_used_mb: +(m.heapUsed / 1048576).toFixed(2), rss_mb: +(m.rss / 1048576).toFixed(2) }; };

// M3 and M4 are about the record's own accounting: module level.
if (SCENARIO === 'M3' || SCENARIO === 'M4') {
  const U = await imp(PKG, 'proxy/unstored-blocks.js');
  const u = U.createUnstoredBlocks({ log: { warn() {}, info() {}, error() {}, transition() {} } });
  const block = (detail, persisted = false) => ({ disposition: 'BLOCK', persisted,
    results: [{ gate: 'seed-v3', result: 'BLOCK', detail }] });
  if (SCENARIO === 'M3') {
    let mismatches = 0; let n = 0;
    for (let i = 0; i < (REDUCED ? 20_000 : 200_000); i += 1) {
      const len = 10 + (i % 291);
      u.note('one-package', '1.0.0', block('d'.repeat(len)));
      n += 1;
      if (u.count !== 1 || u.recompute() !== u.estimatedBytes) mismatches += 1;
    }
    result.checkpoints.push({ notes: n, count: u.count, estimated_bytes: u.estimatedBytes, ...mem() });
    result.verdict = { count_stays_1: u.count === 1, estimate_matches_recompute_every_time: mismatches === 0 };
    finish();
  }
  const N = REDUCED ? 10_000 : 40_000;
  for (let i = 0; i < N; i += 1) u.note(`pkg-${i}`, '1.0.0', block(`advisory MAL-M4-${i}`));
  const filled = { count: u.count, estimated_bytes: u.estimatedBytes, recompute: u.recompute(), ...mem() };
  for (let i = 0; i < N; i += 1) u.note(`pkg-${i}`, '1.0.0', block(`advisory MAL-M4-${i}`, true));
  const emptied = { count: u.count, estimated_bytes: u.estimatedBytes, ...mem() };
  result.checkpoints.push({ stage: 'filled', ...filled }, { stage: 'emptied', ...emptied });
  result.verdict = { filled_matches_recompute: filled.estimated_bytes === filled.recompute,
    back_to_C_FIXED: emptied.estimated_bytes === U.LIMITS.C_FIXED && emptied.count === 0 };
  finish();
}

// Everything else runs the proxy.
const { createProxyServer } = await imp(PKG, 'proxy/server.js');
const F = await imp(WT, 'test/seed-v3/u05-fixtures.mjs');
const Database = (await import(pathToFileURL(path.join(WT, 'node_modules/better-sqlite3/lib/index.js')).href)).default;

const M2 = SCENARIO === 'M2';
const longName = (i) => `m${String(i).padStart(8, '0')}${'n'.repeat(214 - 9)}`;          // 214 characters
const longVersion = (i) => `1.0.0-${String(i).padStart(8, '0')}${'v'.repeat(256 - 14)}`;  // 256 characters
const keyName = (prefix, i) => (M2 ? longName(i) : `${prefix}-${i}`);
const keyVersion = (i) => (M2 ? longVersion(i) : '9.9.9');
const ADV = (i) => (M2 ? `MAL-M2-${i}-${'x'.repeat(900)}` : `MAL-R2-${i}`);

const caps = { M1: REDUCED ? 5_000 : 50_000, L4: 1_000 };
const nKeys = { M1: caps.M1 + (REDUCED ? 1_000 : 10_000), M2: 50_000, L2: 200_000, L3: 4_000, L4: 200_000, P1: 6_000 }[SCENARIO] ?? 1;

// a 1.1-layout synthetic seed whose pins name every key (bulk-inserted in one transaction)
const seed = F.buildSeed({ layout: '1.1', pins: [] });
{
  const db = new Database(seed.dbPath);
  const ins = db.prepare('INSERT INTO known_malicious_pins VALUES (?,?,?,?,?)');
  db.transaction(() => { for (let i = 0; i < nKeys; i += 1) ins.run(100_000 + i, keyName('b', i), keyVersion(i), ADV(i), 'synthetic-measure'); })();
  db.close();
  fs.writeFileSync(`${seed.dbPath}.sha256`, `${createHash('sha256').update(fs.readFileSync(seed.dbPath)).digest('hex')}  chaingate-seed.db\n`);
}
const docs = new Map();
const upstream = http.createServer((req, res) => {
  const name = decodeURIComponent(req.url.slice(1));
  const m = /^(b|a)-(\d+)$/.exec(name) ?? (M2 ? [null, 'b', String(Number(name.slice(1, 9)))] : null);
  if (!m) { res.writeHead(404); res.end('{}'); return; }
  const i = Number(m[2]);
  const doc = F.docFor(name, [[m[1] === 'b' ? keyVersion(i) : '9.9.9', F.after(1)]], { seeded: [] });
  res.writeHead(200, { 'content-type': 'application/json' }); res.end(JSON.stringify(doc));
});
const listen = (s) => new Promise((r) => s.listen(0, '127.0.0.1', () => r(`http://127.0.0.1:${s.address().port}`)));
const upstreamUrl = await listen(upstream);
const config = { port: 0, host: '127.0.0.1', upstream: upstreamUrl, witnessDbPath: path.join(DIR, 'witness.db'),
  headersTimeoutMs: 5_000, bodyTimeoutMs: 15_000, seedV3Path: seed.dbPath, seedV3Trust: 'unsigned-development',
  policyOnUnusableInput: F.LIVE.on_unusable_input, policyOnNoEvidence: F.LIVE.on_no_evidence,
  ...(caps[SCENARIO] ? { unstoredBlockCapEntries: caps[SCENARIO] } : {}) };
const proxy = createProxyServer(config);
const proxyUrl = await listen(proxy);
if (SCENARIO !== 'P1') proxy.witnessDb.db.exec("CREATE TRIGGER measure_fail BEFORE INSERT ON gate_decisions BEGIN SELECT RAISE(ABORT, 'measurement: decision storage made to fail'); END;");
const agent = new http.Agent({ keepAlive: true, maxSockets: 16 });
const get = (p) => new Promise((resolve) => {
  http.get(`${proxyUrl}${p}`, { agent }, (r) => { let b = ''; r.on('data', (x) => { b += x; }); r.on('end', () => resolve({ status: r.statusCode, body: b })); })
    .on('error', (e) => resolve({ status: 0, body: e.message }));
});
const self = async () => { try { return JSON.parse((await get('/_chaingate/self')).body); } catch { return null; } };
const logBytes = () => fs.statSync(LOGP).size;
const t0 = Date.now();
const snap = async (label, extra = {}) => {
  const s = await self();
  const u = s?.unstored_blocks ?? {};
  result.checkpoints.push({ label, t_s: (Date.now() - t0) / 1000, count: u.count, estimated_bytes: u.estimated_bytes,
    full: u.full, storage_state: s?.storage?.state, logging: s?.logging, log_bytes: logBytes(), ...mem(), ...extra });
};
const statuses = {};
async function drive(paths, concurrency = 16) {
  let next = 0;
  await Promise.all(Array.from({ length: concurrency }, async () => {
    while (next < paths.length) { const r = await get(paths[next++]); statuses[r.status] = (statuses[r.status] ?? 0) + 1; }
  }));
}
async function atRate(seconds, rate, pathFor) {
  let i = 0; const end = Date.now() + seconds * 1000; const inflight = new Set();
  while (Date.now() < end) {
    const tick = Date.now();
    for (let k = 0; k < rate; k += 1) {
      const p = get(pathFor(i++)).then((r) => { statuses[r.status] = (statuses[r.status] ?? 0) + 1; inflight.delete(p); });
      inflight.add(p);
    }
    await new Promise((r) => setTimeout(r, Math.max(0, 1000 - (Date.now() - tick))));
  }
  await Promise.all(inflight);
  return i;
}

try {
  if (SCENARIO === 'M1' || SCENARIO === 'M2') {
    const marks = M2 ? [] : [REDUCED ? 1_000 : 10_000, caps.M1, nKeys];
    let done = 0;
    for (const mark of [...marks, nKeys]) {
      if (mark <= done) continue;
      const batch = []; for (let i = done; i < mark; i += 1) batch.push(`/${encodeURIComponent(keyName('b', i))}`);
      await drive(batch); done = mark;
      await snap(`after ${done} keys`);
      if (M2 && result.checkpoints.at(-1).full) break;
    }
    if (M2) { // continue in steps until the byte cap binds
      while (!result.checkpoints.at(-1).full && done < nKeys) {
        const step = Math.min(done + 2_000, nKeys); const batch = [];
        for (let i = done; i < step; i += 1) batch.push(`/${encodeURIComponent(keyName('b', i))}`);
        await drive(batch); done = step; await snap(`after ${done} keys`);
      }
    }
    const last = result.checkpoints.at(-1);
    const capCp = result.checkpoints.find((c) => c.full);
    result.statuses = statuses;
    result.log_bound = logBound((Date.now() - t0) / 1000);
    if (SCENARIO === 'M1') {
      const atCap = result.checkpoints.find((c) => c.count === caps.M1);
      result.verdict = { count_capped: last.count === caps.M1, full_once_beyond_cap: Boolean(last.full),
        estimate_constant_after_cap: Boolean(atCap) && last.estimated_bytes === atCap.estimated_bytes };
    } else {
      result.verdict = { full_reached: Boolean(capCp), byte_cap_bound_first: Boolean(capCp) && capCp.count < 50_000,
        estimate_within_byte_cap: result.checkpoints.every((c) => (c.estimated_bytes ?? 0) <= 64 * 1024 * 1024) };
    }
  } else if (SCENARIO === 'P1') {
    const n = REDUCED ? 1_000 : 3_000;
    const runs = {};
    for (const [label, prefix] of [['allow_path_storage_healthy', 'a'], ['block_path_storage_healthy', 'b']]) {
      const paths = Array.from({ length: n }, (_, i) => `/${prefix}-${i}`);
      const s = Date.now(); await drive(paths); runs[label] = { requests: n, seconds: (Date.now() - s) / 1000 };
      runs[label].req_per_s = +(n / runs[label].seconds).toFixed(1);
    }
    result.runs = runs; result.statuses = statuses; result.verdict = { completed: Object.keys(runs).length === 2 };
    await snap('end');
  } else {
    const seconds = Number(arg('seconds') ?? (SCENARIO === 'L4' ? 600 : (REDUCED ? 60 : 180)));
    const rate = Number(arg('rate') ?? (SCENARIO === 'L4' ? 20 : 50));
    if (SCENARIO === 'L4') { // fill the record to FULL first
      await drive(Array.from({ length: caps.L4 + 10 }, (_, i) => `/b-${i}`));
      await snap('filled to FULL');
    }
    const offset = SCENARIO === 'L4' ? caps.L4 + 10 : 0;
    const pathFor = { L1: () => '/b-0', L2: (i) => `/b-${offset + i}`,
      L3: (i) => `/b-${(Math.floor(i / 2_000) % 2) * 2_000 + (i % 2_000)}`, L4: (i) => `/b-${offset + i}` }[SCENARIO];
    const logBefore = logBytes();
    await snap('start of the timed run');
    const sent = await atRate(seconds, rate, pathFor);
    await snap('end of the timed run', { requests_sent: sent });
    result.statuses = statuses;
    result.timed_run = { seconds, rate, requests: sent, log_bytes_during: logBytes() - logBefore };
    result.log_bound = logBound((Date.now() - t0) / 1000);
    result.verdict = { timed_run_log_within_bound: result.timed_run.log_bytes_during <= logBound(seconds) };
    if (SCENARIO === 'L4') {
      const [a, b] = [result.checkpoints.at(-2), result.checkpoints.at(-1)];
      result.verdict.full_throughout = Boolean(a.full && b.full);
      result.verdict.heap_flat_within_10pct = b.heap_used_mb <= a.heap_used_mb * 1.10 + 2;
    }
  }
} catch (e) {
  result.verdict.no_error = false; result.error = `${e.name}: ${e.message}`;
}
agent.destroy();
await new Promise((r) => proxy.close(r)); await new Promise((r) => upstream.close(r));
seed.cleanup();
finish();
