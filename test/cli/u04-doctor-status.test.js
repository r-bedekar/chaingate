// U-04 — what a new tester reads to decide whether installation worked:
//   * `doctor --json` must return valid structured output, with a FAILED seed-v3 check, when the
//     activation link exists but does not resolve (it used to abort with no checks and no JSON);
//   * `status` must describe the active v3 seed (it used to say "none" because it read only the
//     legacy witness seed), and must say BROKEN, with a non-zero exit, for a broken activation.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

import doctor from '../../cli/commands/doctor.js';
import status from '../../cli/commands/status.js';
import { stageBundle, activateBundle } from '../../cli/seed-bundle.js';
import { openWitnessDB } from '../../witness/db.js';
import { buildSyntheticSeed } from '../seed-v3/u01-cases.mjs';

async function capture(fn) {
  const out = []; const err = [];
  const l = console.log; const e = console.error;
  console.log = (...a) => out.push(a.join(' ')); console.error = (...a) => err.push(a.join(' '));
  try { return { code: await fn(), out: out.join('\n'), err: err.join('\n') }; } finally { console.log = l; console.error = e; }
}
const plain = (s) => s.replace(/\x1b\[[0-9;]*m/g, '');

function host({ activate = true } = {}) {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'chaingate-u04-ds-'));
  const base = path.join(home, '.chaingate'); fs.mkdirSync(base, { recursive: true });
  const seed = buildSyntheticSeed();
  let id = null;
  if (activate) {
    id = stageBundle({ dbPath: seed.dbPath, sha256Path: `${seed.dbPath}.sha256` }, base, { trust: 'unsigned-development' }).dir_name;
    activateBundle(base, id);
  }
  openWitnessDB(path.join(base, 'witness.db')).applySchema().close();
  const prev = process.env.CHAINGATE_HOME; process.env.CHAINGATE_HOME = base;
  return { base, id, cleanup: () => {
    if (prev === undefined) delete process.env.CHAINGATE_HOME; else process.env.CHAINGATE_HOME = prev;
    fs.rmSync(home, { recursive: true, force: true }); fs.rmSync(seed.dir, { recursive: true, force: true });
  } };
}
const breakIt = (h) => fs.renameSync(path.join(h.base, 'seeds', h.id), path.join(h.base, 'seeds', `${h.id}.moved-aside`));

test('status describes the ACTIVE v3 seed (not "none"), in text and JSON', async () => {
  const h = host();
  try {
    const j = await capture(() => status(['--json']));
    assert.equal(j.code, 0);
    const rec = JSON.parse(j.out);
    assert.equal(rec.seed_v3.active, true);
    assert.equal(rec.seed_v3.bundle_id, h.id);
    assert.equal(rec.seed_v3.trust, 'unsigned-development');
    assert.match(rec.seed_v3.sha256, /^[0-9a-f]{64}$/);
    assert.equal(rec.seed_v3.verified, false, 'status reports the recorded manifest; doctor verifies');
    const t = await capture(() => status([]));
    const text = plain(t.out);
    assert.match(text, new RegExp(`Detection seed \\(v3\\):\\s+bundle ${h.id}`));
    assert.match(text, /trust unsigned-development/);
    assert.doesNotMatch(text, /observing from live traffic/);
    assert.match(text, /Legacy witness seed:\s+none installed/);
  } finally { h.cleanup(); }
});

test('status on a host with no v3 bundle says none active and exits 0', async () => {
  const h = host({ activate: false });
  try {
    const j = await capture(() => status(['--json']));
    assert.equal(j.code, 0);
    assert.deepEqual(JSON.parse(j.out).seed_v3, { active: false });
    assert.match(plain((await capture(() => status([]))).out), /Detection seed \(v3\):\s+none active/);
  } finally { h.cleanup(); }
});

test('status on a BROKEN activation says BROKEN and exits non-zero (text and JSON)', async () => {
  const h = host();
  try {
    breakIt(h);
    const j = await capture(() => status(['--json']));
    assert.equal(j.code, 1);
    const rec = JSON.parse(j.out);
    assert.equal(rec.seed_v3.broken, true);
    assert.equal(rec.seed_v3.active, false);
    const t = await capture(() => status([]));
    assert.equal(t.code, 1);
    assert.match(plain(t.out), /Detection seed \(v3\):\s+BROKEN: the activation link .* does not resolve/);
  } finally { h.cleanup(); }
});

test('doctor --json on a BROKEN activation: valid JSON, failed seed-v3 check, the other checks still run', async () => {
  const h = host();
  try {
    breakIt(h);
    const r = await capture(() => doctor(['--json']));
    assert.equal(r.code, 1, 'a failed check, not an aborted run');
    const checks = JSON.parse(r.out);   // throws if the output is not JSON
    const sv = checks.find((c) => c.name === 'seed-v3');
    assert.equal(sv.pass, false);
    assert.equal(sv.broken_activation, true);
    assert.match(sv.detail, /does not resolve/);
    assert.match(sv.detail, /update-seed --rollback/);
    assert.doesNotMatch(sv.detail, /no v3 bundle active/, 'never reported as "no seed"');
    for (const name of ['native-sqlite', 'policy', 'chaingate-dir', 'witness-db', 'proxy-port']) {
      assert.ok(checks.find((c) => c.name === name), `${name} was still checked`);
    }
    assert.equal(checks.find((c) => c.name === 'policy').pass, false, 'no policy can be in force without a seed');
  } finally { h.cleanup(); }
});

test('doctor (text) on a BROKEN activation lists the failure with the fix and keeps going', async () => {
  const h = host();
  try {
    breakIt(h);
    const r = await capture(() => doctor([]));
    const text = plain(r.out);
    assert.equal(r.code, 1);
    assert.match(text, /✗ seed-v3\s+activation link .* does not resolve/);
    assert.match(text, /native-sqlite/);
    assert.match(text, /check\(s\) failed/);
  } finally { h.cleanup(); }
});

test('doctor --json on a healthy v3 host: seed-v3 passes with the bundle identity', async () => {
  const h = host();
  try {
    const checks = JSON.parse((await capture(() => doctor(['--json']))).out);
    const sv = checks.find((c) => c.name === 'seed-v3');
    assert.equal(sv.pass, true);
    assert.match(sv.detail, new RegExp(`bundle ${h.id}`));
  } finally { h.cleanup(); }
});
