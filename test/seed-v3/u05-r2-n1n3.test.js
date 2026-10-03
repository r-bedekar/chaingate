// U-05 gap-closure r2 (owner decision 6), N1 + N3 together: ONE prior-decision rule for the store's writes and the tarball
// gate's reads. Expected values come from U-05-GAP-CLOSURE-R2-ADDENDUM-1-20261001.md table A (written before this file);
// FF cases were run failing-first on 3ee5aba.
//
// Fixture: a witness database written by the real store (createWitness) through a real gate runner, and read by a real
// proxy (createProxyServer) on the SAME database file for tarball requests. x@2.0.0 is decided by a scripted test gate
// whose declared failure result emulates the configured input policy (WARN or BLOCK); p@1.3.0 is pinned (ADV-P-130) in
// the U-05 synthetic seed for the failure-path pin cases. "Runner throws" = the whole runner throws (store.js runner-threw
// path); "module throws" = one module throws inside the runner (T1b, deferred).
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import G from '../../seed/v3/gate.js';
import { createGateRunner } from '../../gates/index.js';
import { openWitnessDB } from '../../witness/db.js';
import { createWitness } from '../../witness/store.js';
import { createProxyServer } from '../../proxy/server.js';
import { buildSeed, openFixtureSeed, docFor, after, WARNCFG, namingRow } from './u05-fixtures.mjs';

const quiet = { info() {}, warn() {}, error() {} };
const DOC_X = () => docFor('x', [['2.0.0', after(1)]]);
const DOC_P = () => docFor('p', [['1.3.0', after(1)], ['1.4.0', after(2)]]);
const O_ROW = [{ gate: 'override', result: 'ALLOW', detail: 'override: synthetic' }];
const F_WARN_ROW = [{ gate: 'observation_error', result: 'SKIP', detail: 'runner threw: legacy' },
  { gate: 'content-hash', result: 'WARN', detail: 'gate_error: legacy' }];
const E_BLOCK_ROW = [{ gate: 'content-hash', result: 'BLOCK', detail: 'synthetic evaluated BLOCK' }];

const listen = (srv) => new Promise((resolve) => { srv.listen(0, '127.0.0.1', () => resolve(`http://127.0.0.1:${srv.address().port}`)); });
const close = (srv) => new Promise((resolve) => { srv.close(() => resolve()); });
const get = (url) => new Promise((resolve, reject) => {
  http.get(url, { agent: false }, (res) => {
    let b = ''; res.setEncoding('utf8'); res.on('data', (c) => { b += c; });
    res.on('end', () => { let json = null; try { json = JSON.parse(b); } catch { /* not JSON */ } resolve({ status: res.statusCode, json }); });
  }).on('error', reject);
});

/**
 * A store over a fresh witness database plus a proxy reading the same file. `failAs` is the scripted gate's declared
 * failure result (WARN emulates on_unusable_input WARN, BLOCK emulates LIVE). `pinned` adds the real seed-v3 gate.
 */
async function bench({ failAs = 'WARN', pinned = false, dir = null } = {}, fn) {
  const wdir = dir ?? fs.mkdtempSync(path.join(os.tmpdir(), 'u05-r2-n1n3-'));
  const dbPath = path.join(wdir, 'witness.db');
  const db = openWitnessDB(dbPath); db.applySchema();
  const mode = { verdict: 'ALLOW', runnerThrows: false, moduleThrows: false };
  const scripted = { name: 'content-hash', onErrorResult: failAs, evaluate: (i) => {
    if (i.packageName === 'x' && i.version === '2.0.0') {
      if (mode.moduleThrows) throw new Error('injected module failure');
      // Owner decision 10 (C2): a scripted ALLOW is content-hash's DEFINITIVE clearance, in its own words.
      return { gate: 'content-hash', result: mode.verdict,
        detail: mode.verdict === 'ALLOW' ? 'integrity hash matches baseline (scripted)' : `scripted ${mode.verdict}` };
    }
    return { gate: 'content-hash', result: 'ALLOW', detail: 'scripted ALLOW' };
  } };
  let s = null; let seed = null; const modules = [scripted];
  if (pinned) {
    s = buildSeed({ layout: '1.1' }); seed = openFixtureSeed(s.dbPath);
    modules.splice(0, 1, G.createSeedV3Gate({ seed, config: WARNCFG, domainVersionCount: 'from-packument' }));
  }
  const rg = createGateRunner({ modules, getOverride: (n, v) => db.getOverride(n, v), logger: quiet });
  const runGates = (input) => { if (mode.runnerThrows) throw new Error('injected runner failure'); return rg(input); };
  runGates.failureDecision = rg.failureDecision;
  const witness = createWitness({ db, runGates, config: {}, logger: quiet });

  const upstream = http.createServer((req, res) => { res.writeHead(200, { 'content-type': 'application/octet-stream' }); res.end('tarball-bytes'); });
  const upstreamUrl = await listen(upstream);
  const proxy = createProxyServer({ port: 0, host: '127.0.0.1', upstream: upstreamUrl, witnessDbPath: dbPath,
    headersTimeoutMs: 5_000, bodyTimeoutMs: 15_000 });
  const proxyUrl = await listen(proxy);
  const realErr = console.error; console.error = () => {};
  const h = {
    db, mode, proxy,
    observe: (doc) => witness.observePackument(doc.name, doc).decisions,
    rows: (n, v) => db.db.prepare('SELECT disposition, gates_fired FROM gate_decisions WHERE package_name = ? AND version = ? ORDER BY decided_at, id')
      .all(n, v).map((r) => ({ disposition: r.disposition, gates: (() => { try { return JSON.parse(r.gates_fired).map((x) => x.gate); } catch { return ['<unparseable>']; } })() })),
    tarball: async (n, v) => (await get(`${proxyUrl}/${n}/-/${n.split('/').pop()}-${v}.tgz`)).status,
  };
  try {
    return await fn(h);
  } finally {
    console.error = realErr;
    await close(proxy); await close(upstream);
    try { db.close(); } catch { /* closed */ }
    seed?.close(); s?.cleanup();
    if (!dir) fs.rmSync(wdir, { recursive: true, force: true });
  }
}

/** E-BLOCK, then an override and a re-observation that stores the override ALLOW (O). Returns with the override live. */
function blockThenOverride(h) {
  h.mode.verdict = 'BLOCK'; h.observe(DOC_X());
  h.db.insertOverride('x', '2.0.0', 'operator exception for the test');
  h.observe(DOC_X());
  const r = h.rows('x', '2.0.0');
  assert.deepEqual(r.map((x) => x.disposition), ['BLOCK', 'ALLOW'], 'history: E-BLOCK, O');
  assert.ok(r[1].gates.includes('override'), 'the second row is the stored override ALLOW');
}
const preserved = (d) => d.disposition === 'BLOCK' && d.results.some((x) => /stored BLOCK preserved/.test(x.detail ?? ''));

// --------------------------------------------------------------------------- (a)
test('A-a W: override revoked, then a whole-runner failure: no downgrade; stored BLOCK preserved; tarball 403', async () => {
  await bench({ failAs: 'WARN' }, async (h) => {
    blockThenOverride(h);
    h.db.deleteOverride('x', '2.0.0');
    h.mode.runnerThrows = true;
    const d = h.observe(DOC_X()).get('2.0.0');
    assert.deepEqual(h.rows('x', '2.0.0').map((x) => x.disposition), ['BLOCK', 'ALLOW'], 'nothing inserted');
    assert.ok(preserved(d), 'the packument decision is the preserved stored BLOCK (version omitted)');
    assert.equal(await h.tarball('x', '2.0.0'), 403, 'tarball refused: the revoked override row is not applicable');
  });
});

test('A-a L: override revoked, then a whole-runner failure (infrastructure BLOCK): compared with the effective E-BLOCK', async () => {
  await bench({ failAs: 'BLOCK' }, async (h) => {
    blockThenOverride(h);
    h.db.deleteOverride('x', '2.0.0');
    h.mode.runnerThrows = true;
    const d = h.observe(DOC_X()).get('2.0.0');
    assert.equal(d.disposition, 'BLOCK');
    assert.deepEqual(h.rows('x', '2.0.0').map((x) => x.disposition), ['BLOCK', 'ALLOW'], 'same disposition as the effective row: no insert');
    assert.equal(await h.tarball('x', '2.0.0'), 403);
  });
});

// --------------------------------------------------------------------------- (b), (c)
test('A-b: override revoked, then a genuine non-override ALLOW becomes the effective decision (W1)', async () => {
  await bench({}, async (h) => {
    blockThenOverride(h);
    h.db.deleteOverride('x', '2.0.0');
    h.mode.verdict = 'ALLOW';
    const d = h.observe(DOC_X()).get('2.0.0');
    assert.equal(d.disposition, 'ALLOW');
    assert.deepEqual(h.rows('x', '2.0.0').map((x) => x.disposition), ['BLOCK', 'ALLOW', 'ALLOW'], 'E-ALLOW inserted');
    assert.ok(!h.rows('x', '2.0.0')[2].gates.includes('override'), 'and it is not an override row');
    assert.equal(await h.tarball('x', '2.0.0'), 200, 'the new evaluation governs; the old BLOCK is not resurrected');
  });
});

test('A-c1 (amended by owner decision 10, C2): override revoked, then a WARN that does not clear the BLOCK', async () => {
  // C2: a WARN from the gate that BLOCKed is not that gate's definitive clearance, so the BLOCK still applies. The row is
  // written once as evidence. A definitive clearance after a revoke is the E-ALLOW test above (served).
  await bench({}, async (h) => {
    blockThenOverride(h);
    h.db.deleteOverride('x', '2.0.0');
    h.mode.verdict = 'WARN';
    assert.equal(h.observe(DOC_X()).get('2.0.0').disposition, 'BLOCK', 'the applicable BLOCK is kept');
    assert.deepEqual(h.rows('x', '2.0.0').map((x) => x.disposition), ['BLOCK', 'ALLOW', 'WARN']);
    assert.equal(await h.tarball('x', '2.0.0'), 403, 'the BLOCK applies at the tarball gate');
  });
});

test('A-c2: override revoked, then a genuine BLOCK: same as the effective row, stored, tarball 403', async () => {
  await bench({}, async (h) => {
    blockThenOverride(h);
    h.db.deleteOverride('x', '2.0.0');
    h.mode.verdict = 'BLOCK';
    const d = h.observe(DOC_X()).get('2.0.0');
    assert.equal(d.disposition, 'BLOCK'); assert.notEqual(d.persisted, false, 'reported as stored');
    assert.deepEqual(h.rows('x', '2.0.0').map((x) => x.disposition), ['BLOCK', 'ALLOW'], 'no new row (W1)');
    assert.equal(await h.tarball('x', '2.0.0'), 403);
  });
});

// --------------------------------------------------------------------------- (d)
test('A-d1: override still live, then the runner throws: A1-OV responses unchanged; nothing inserted', async () => {
  for (const failAs of ['WARN', 'BLOCK']) {
    await bench({ failAs }, async (h) => {
      blockThenOverride(h);
      h.mode.runnerThrows = true;
      const d = h.observe(DOC_X()).get('2.0.0');
      assert.equal(d.disposition, failAs, `${failAs}: the failure declaration, as 0.1.2 (A1-OV)`);
      assert.deepEqual(h.rows('x', '2.0.0').map((x) => x.disposition), ['BLOCK', 'ALLOW'], `${failAs}: nothing inserted`);
      assert.equal(await h.tarball('x', '2.0.0'), 200, `${failAs}: the live override allows the tarball`);
    });
  }
});

test('A-d2: several override rows, override revoked: all skipped; tarball 403', async () => {
  await bench({}, async (h) => {
    h.db.insertGateDecision('x', '2.0.0', 'BLOCK', E_BLOCK_ROW);
    h.db.insertGateDecision('x', '2.0.0', 'ALLOW', O_ROW);
    h.db.insertGateDecision('x', '2.0.0', 'ALLOW', O_ROW);
    assert.equal(await h.tarball('x', '2.0.0'), 403);
  });
});

test("A-d2' (amended by owner decision 10, C2): override rows around a WARN that does not clear the BLOCK", async () => {
  await bench({}, async (h) => {
    h.mode.verdict = 'ALLOW'; h.observe(DOC_X());                     // baseline (first-seen E-ALLOW)
    for (const [d, r] of [['BLOCK', E_BLOCK_ROW], ['ALLOW', O_ROW], ['WARN', [{ gate: 'content-hash', result: 'WARN', detail: 'synthetic' }]], ['ALLOW', O_ROW]]) {
      h.db.insertGateDecision('x', '2.0.0', d, r);
    }
    assert.equal(await h.tarball('x', '2.0.0'), 403, 'C2: the synthetic WARN is not a definitive clearance: refused');
    h.mode.runnerThrows = true;
    const before = h.rows('x', '2.0.0').length;
    assert.ok(preserved(h.observe(DOC_X()).get('2.0.0')), 'a failure preserves the applicable BLOCK');
    assert.equal(h.rows('x', '2.0.0').length, before, 'nothing inserted over it');
  });
});

test('A-d3: override present but its lookup throws: not established; tarball 403; a failure preserves the BLOCK', async () => {
  await bench({}, async (h) => {
    blockThenOverride(h);
    h.proxy.witnessDb.getOverride = () => { throw new Error('injected override lookup failure'); };
    assert.equal(await h.tarball('x', '2.0.0'), 403, 'tarball: an unestablished override never permits');
    h.db.getOverride = () => { throw new Error('injected override lookup failure'); };
    h.mode.runnerThrows = true;
    assert.ok(preserved(h.observe(DOC_X()).get('2.0.0')), 'store: the failure cannot downgrade the underlying BLOCK');
  });
});

test('A-d4: no earlier non-override row: after the revoke the version has no effective decision', async () => {
  await bench({}, async (h) => {
    h.db.insertOverride('x', '2.0.0', 'operator exception for the test');
    h.observe(DOC_X());                                                // first seen WITH the override: O only
    assert.deepEqual(h.rows('x', '2.0.0').map((x) => x.disposition), ['ALLOW']);
    h.db.deleteOverride('x', '2.0.0');
    assert.equal(await h.tarball('x', '2.0.0'), 200, 'never evaluated without the override: unchanged outside FULL');
    h.mode.runnerThrows = true;
    h.observe(DOC_X());
    assert.deepEqual(h.rows('x', '2.0.0').map((x) => x.disposition), ['ALLOW', 'WARN'], 'effective none: the failure WARN is inserted');
  });
});

test('A-d5 (closed by owner decision 10, C2; was a pinned limitation): a legacy failure row after a BLOCK does not clear it', async () => {
  await bench({}, async (h) => {
    h.mode.verdict = 'ALLOW'; h.observe(DOC_X());
    h.db.insertGateDecision('x', '2.0.0', 'BLOCK', E_BLOCK_ROW);
    h.db.insertGateDecision('x', '2.0.0', 'WARN', F_WARN_ROW);
    assert.equal(await h.tarball('x', '2.0.0'), 403, 'the F row is read as it was written and does not clear the BLOCK (no migration)');
    h.mode.runnerThrows = true;
    const before = h.rows('x', '2.0.0').length;
    assert.ok(preserved(h.observe(DOC_X()).get('2.0.0')), 'a failure preserves the applicable BLOCK');
    assert.equal(h.rows('x', '2.0.0').length, before, 'nothing inserted over it');
  });
});

test('A-d6: legacy override row with no live override: skipped; tarball 403', async () => {
  await bench({}, async (h) => {
    h.db.insertGateDecision('x', '2.0.0', 'BLOCK', E_BLOCK_ROW);
    h.db.insertGateDecision('x', '2.0.0', 'ALLOW', O_ROW);
    assert.equal(await h.tarball('x', '2.0.0'), 403);
  });
});

test('A-d7 (amended by owner decision 10, C2): a row whose gates_fired does not parse is not an override row and not a clearance', async () => {
  await bench({}, async (h) => {
    h.db.insertGateDecision('x', '2.0.0', 'BLOCK', E_BLOCK_ROW);
    h.db.db.prepare("INSERT INTO gate_decisions (package_name, version, disposition, gates_fired) VALUES ('x', '2.0.0', 'ALLOW', 'not json')").run();
    assert.equal(await h.tarball('x', '2.0.0'), 403, 'unrecognised content never clears a BLOCK');
  });
});

// --------------------------------------------------------------------------- T rows
test('T1: E-BLOCK, then the runner throws (W): preserved, not downgraded; tarball 403', async () => {
  await bench({}, async (h) => {
    h.mode.verdict = 'BLOCK'; h.observe(DOC_X());
    h.mode.runnerThrows = true;
    const d = h.observe(DOC_X()).get('2.0.0');
    assert.ok(preserved(d), 'stored BLOCK preserved');
    assert.deepEqual(h.rows('x', '2.0.0').map((x) => x.disposition), ['BLOCK']);
    assert.equal(await h.tarball('x', '2.0.0'), 403);
  });
});

test('T1b (closed by owner decision 10, C2; was a pinned limitation): a module-level failure after E-BLOCK does not supersede it', async () => {
  await bench({}, async (h) => {
    h.mode.verdict = 'BLOCK'; h.observe(DOC_X());
    h.mode.moduleThrows = true;
    assert.equal(h.observe(DOC_X()).get('2.0.0').disposition, 'BLOCK', 'the module error (gate_error) is not a clearance');
    assert.deepEqual(h.rows('x', '2.0.0').map((x) => x.disposition), ['BLOCK', 'WARN'], 'the error row is written once, as evidence');
    assert.equal(await h.tarball('x', '2.0.0'), 403, 'the BLOCK applies');
  });
});

test('T2: no rows; the runner throws with a recorded pin: F-PIN-BLOCK stored and applicable', async () => {
  await bench({ pinned: true }, async (h) => {
    h.mode.runnerThrows = true;
    const d = h.observe(DOC_P()).get('1.3.0');
    assert.equal(d.disposition, 'BLOCK'); assert.ok(namingRow(d.results, 'ADV-P-130'));
    const r = h.rows('p', '1.3.0');
    assert.equal(r.at(-1).disposition, 'BLOCK'); assert.ok(r.at(-1).gates.includes('observation_error'), 'a failure-derived BLOCK');
    assert.equal(await h.tarball('p', '1.3.0'), 403, 'a failure-derived pin BLOCK stays applicable (D4)');
  });
});

test('T3: E-ALLOW, then a failure-path pin BLOCK: inserted and applicable', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'u05-r2-t3-'));
  try {
    await bench({ dir }, async (h) => { h.mode.verdict = 'ALLOW'; h.observe(DOC_P()); });   // scripted only: E-ALLOW for p@1.3.0
    await bench({ dir, pinned: true }, async (h) => {
      assert.equal(h.rows('p', '1.3.0').at(-1).disposition, 'ALLOW');
      h.mode.runnerThrows = true;
      assert.equal(h.observe(DOC_P()).get('1.3.0').disposition, 'BLOCK');
      assert.equal(h.rows('p', '1.3.0').at(-1).disposition, 'BLOCK');
      assert.equal(await h.tarball('p', '1.3.0'), 403);
    });
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

test('T4: an infrastructure BLOCK (LIVE) is not downgraded by a later WARN-policy failure (stated over-blocking)', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'u05-r2-t4-'));
  try {
    await bench({ dir, failAs: 'BLOCK' }, async (h) => {
      h.mode.runnerThrows = true; h.observe(DOC_X());
      assert.equal(h.rows('x', '2.0.0').at(-1).disposition, 'BLOCK', 'F-INFRA-BLOCK');
      assert.equal(await h.tarball('x', '2.0.0'), 403);
    });
    await bench({ dir, failAs: 'WARN' }, async (h) => {
      h.mode.runnerThrows = true;
      assert.ok(preserved(h.observe(DOC_X()).get('2.0.0')), 'the underlying (infrastructure) BLOCK is preserved');
      assert.equal(h.rows('x', '2.0.0').length, 1, 'no F-WARN inserted');
      assert.equal(await h.tarball('x', '2.0.0'), 403);
      h.mode.runnerThrows = false; h.mode.verdict = 'ALLOW';
      h.observe(DOC_X());
      assert.equal(await h.tarball('x', '2.0.0'), 200, 'a successful evaluation clears it');
    });
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

test('T5: E-BLOCK, then a genuine evaluated ALLOW: inserted; served', async () => {
  await bench({}, async (h) => {
    h.mode.verdict = 'BLOCK'; h.observe(DOC_X());
    h.mode.verdict = 'ALLOW'; h.observe(DOC_X());
    assert.deepEqual(h.rows('x', '2.0.0').map((x) => x.disposition), ['BLOCK', 'ALLOW']);
    assert.equal(await h.tarball('x', '2.0.0'), 200);
  });
});
