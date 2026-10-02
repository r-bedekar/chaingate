// U-05 owner decision 10, C1: a tarball is served only on a decision this process made for that EXACT version.
// Expected results are the decision table in U-05-OWNER-DECISION-10-C1-C2-SCOPE-20261002.md §3.1, written before this
// file; run failing-first on 8f90e6a. Each request is a tarball GET with no preceding metadata request: what `npm ci`
// and `npm install` send from a complete lockfile (decision-9 G3, measured with npm 10.9.7).
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';

import { seed, registry, proxy, tarball, packument, failingWitness, tmp } from '../helpers/u05-d10.mjs';

const silence = () => { const e = console.error; const w = console.warn; console.error = () => {}; console.warn = () => {}; return () => { console.error = e; console.warn = w; }; };
async function world(t) {
  const dir = tmp('c1'); const reg = await registry(); const s = seed();
  const restore = silence();
  t.after(async () => { restore(); await reg.close(); s.cleanup(); fs.rmSync(dir, { recursive: true, force: true }); });
  return { dir, reg, s, witness: path.join(dir, 'witness.db') };
}

for (const policy of ['BLOCK', 'WARN']) {
  test(`C1-1 (${policy}) a tarball never evaluated: the pinned version is refused, the clean one served`, async (t) => {
    const w = await world(t);
    const px = await proxy({ upstream: w.reg.url, witness: w.witness, policy, seedDb: w.s.dbPath });
    t.after(() => px.stop());
    const bad = await tarball(px, 'p', '1.3.0');
    assert.equal(bad.status, 403, `pinned p@1.3.0: ${bad.status}`);
    assert.equal(bad.json?.error, 'blocked_by_chaingate');
    assert.equal((await tarball(px, 'p', '1.4.0')).status, 200);
    assert.equal(w.reg.count('packument', '/p'), 1, 'one metadata evaluation for the package');
    assert.equal(w.reg.count('tarball', '/p/-/p-1.3.0.tgz'), 0, 'the refused tarball never reached upstream');
  });
}

test('C1-2 a decision stored before the active seed pinned the version: refused after the seed update and restart', async (t) => {
  const w = await world(t); const before = seed({ withoutPin: '1.3.0' }); t.after(() => before.cleanup());
  let px = await proxy({ upstream: w.reg.url, witness: w.witness, seedDb: before.dbPath });
  assert.ok((await packument(px, 'p')).versions.includes('1.3.0'), 'before the advisory: allowed and stored');
  assert.equal((await tarball(px, 'p', '1.3.0')).status, 200);
  await px.stop();
  px = await proxy({ upstream: w.reg.url, witness: w.witness, seedDb: w.s.dbPath });
  t.after(() => px.stop());
  const r = await tarball(px, 'p', '1.3.0');
  assert.equal(r.status, 403, `after the seed update: ${r.status}`);
});

test('C1-3 a version not present in the package\'s first evaluation is evaluated before it is served', async (t) => {
  const w = await world(t);
  const px = await proxy({ upstream: w.reg.url, witness: w.witness, seedDb: w.s.dbPath });
  t.after(() => px.stop());
  assert.equal((await tarball(px, 'p', '1.4.0')).status, 200);
  assert.equal(w.reg.count('packument', '/p'), 1);
  w.reg.set('p', { extra: [['1.3.0', '2026-01-04T11:20:00.000Z'], ['1.4.0', '2026-01-05T15:06:40.000Z'],
    ['1.5.0', '2026-01-06T18:53:20.000Z'], ['1.6.0', '2026-01-07T22:40:00.000Z']] });
  assert.equal((await tarball(px, 'p', '1.5.0')).status, 403, 'the newly published, pinned 1.5.0');
  assert.equal(w.reg.count('packument', '/p'), 2, 're-evaluated for the new version');
  assert.equal((await tarball(px, 'p', '1.6.0')).status, 200, 'the newly published, clean 1.6.0');
  assert.equal(w.reg.count('packument', '/p'), 2, '1.6.0 was evaluated by that same evaluation');
});

test('C1-4 evaluations are reused within the process: a resolving request first, then tarballs, one metadata request', async (t) => {
  const w = await world(t);
  const px = await proxy({ upstream: w.reg.url, witness: w.witness, seedDb: w.s.dbPath });
  t.after(() => px.stop());
  await packument(px, 'p');
  assert.equal((await tarball(px, 'p', '1.4.0')).status, 200);
  assert.equal((await tarball(px, 'p', '1.4.0')).status, 200);
  assert.equal((await tarball(px, 'p', '1.3.0')).status, 403);
  assert.equal(w.reg.count('packument', '/p'), 1);
});

test('C1-5 concurrent first requests share one evaluation and none is served before it settles', async (t) => {
  const w = await world(t); w.reg.set('p', { delayMs: 400 });
  const px = await proxy({ upstream: w.reg.url, witness: w.witness, seedDb: w.s.dbPath });
  t.after(() => px.stop());
  const all = await Promise.all([...Array(4)].map(() => tarball(px, 'p', '1.3.0')).concat([...Array(4)].map(() => tarball(px, 'p', '1.4.0'))));
  assert.deepEqual(all.map((r) => r.status), [403, 403, 403, 403, 200, 200, 200, 200]);
  assert.equal(w.reg.count('packument', '/p'), 1, 'single flight');
  const firstTarball = w.reg.log.findIndex((e) => e.kind === 'tarball');
  const pk = w.reg.log.findIndex((e) => e.kind === 'packument');
  assert.ok(pk >= 0 && firstTarball > pk, 'no tarball reached upstream before the evaluation');
});

test('C1-6 restart while decision storage fails: the first tarball re-evaluates before serving (G4)', async (t) => {
  const w = await world(t); const witness = failingWitness(w.dir);
  let px = await proxy({ upstream: w.reg.url, witness, seedDb: w.s.dbPath });
  await packument(px, 'p');
  assert.equal((await tarball(px, 'p', '1.3.0')).status, 403, 'held before the restart');
  await px.stop();
  px = await proxy({ upstream: w.reg.url, witness, seedDb: w.s.dbPath });
  t.after(() => px.stop());
  const r = await tarball(px, 'p', '1.3.0');
  assert.equal(r.status, 403, `after the restart: ${r.status}`);
  assert.equal(r.json?.persisted, false, 'computed again and held again');
});

test('C1-7 the tracking limit: an evicted version is evaluated again, never served on the strength of the eviction', async (t) => {
  const w = await world(t);
  for (const n of ['q', 'r']) w.reg.set(n, {});
  const px = await proxy({ upstream: w.reg.url, witness: w.witness, seedDb: w.s.dbPath, hooks: { c1: { maxVersions: 6 } } });
  t.after(() => px.stop());
  assert.equal((await tarball(px, 'p', '1.4.0')).status, 200);
  assert.equal((await tarball(px, 'q', '1.4.0')).status, 200);
  assert.equal((await tarball(px, 'r', '1.4.0')).status, 200);  // p's five versions are the oldest: evicted
  assert.equal((await tarball(px, 'p', '1.3.0')).status, 403, 'after eviction the pinned version is still refused');
  assert.equal(w.reg.count('packument', '/p'), 2, 'p was evaluated again after its eviction');
});

test('C1-8 the tracking limit never evicts a held BLOCK', async (t) => {
  const w = await world(t); const witness = failingWitness(w.dir);
  for (const n of ['q', 'r']) w.reg.set(n, {});
  const px = await proxy({ upstream: w.reg.url, witness, seedDb: w.s.dbPath, hooks: { c1: { maxVersions: 6 } } });
  t.after(() => px.stop());
  await packument(px, 'p');
  await tarball(px, 'q', '1.4.0'); await tarball(px, 'r', '1.4.0');
  w.reg.set('p', { status: 503 });                                        // p cannot be re-evaluated now
  const r = await tarball(px, 'p', '1.3.0');
  assert.equal(r.status, 403, 'still refused from the held record');
  assert.equal(r.json?.persisted, false);
});

test('C1-9 capacity: requests beyond the evaluation bound are refused, never served', async (t) => {
  const w = await world(t);
  for (const n of ['a', 'b', 'c']) w.reg.set(n, { delayMs: 500 });
  const px = await proxy({ upstream: w.reg.url, witness: w.witness, seedDb: w.s.dbPath, hooks: { c1: { maxInFlight: 1, maxWaiting: 1 } } });
  t.after(() => px.stop());
  const [a, b, c] = await Promise.all(['a', 'b', 'c'].map((n) => tarball(px, n, '1.4.0')));
  const statuses = [a.status, b.status, c.status].sort();
  assert.deepEqual(statuses, [200, 200, 503], `got ${[a, b, c].map((x) => `${x.status} ${x.json?.error ?? ''}`).join(', ')}`);
  assert.equal([a, b, c].find((x) => x.status === 503).json?.error, 'chaingate_evaluation_busy');
});
