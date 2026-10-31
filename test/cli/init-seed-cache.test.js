// Since 0.1.6: `chaingate init` sets up the seed cache when no --seed is given and the cache is on: it fetches the root and the
// buckets of the project's lockfile, writes the policy, and the proxy then reads the cache in place of a full seed. When the host
// cannot serve a cache (none published yet, or unreachable), init says so and goes on exactly as before. Run in-process against a
// local host serving the seed lane's fixture (the started proxy is another process, with the embedded seed key). Written before
// the code.
import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { installSeeds } from '../../cli/commands/init.js';
import { resolvePaths } from '../../cli/paths.js';
import { shardSource } from '../../cli/seed-shards.js';
import { readConfigStrict, writeConfig, DEFAULT_POLICY } from '../../config-store.js';
import { loadConfig } from '../../proxy/config.js';
import { fixtureRel, caPathOf, fixtureRoot } from '../helpers/shards-host.mjs';

const FIX = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'fixtures', 'shards-1.0');
const EXPECTED = JSON.parse(fs.readFileSync(path.join(FIX, 'good', 'expected.json'), 'utf8'));
const SEED_KEY = crypto.createPublicKey(fs.readFileSync(path.join(FIX, 'good', 'fixture-seed-pub.pem')));
const NOW = Date.parse(EXPECTED.now);

async function withHome({ status = 200, cfg = {} } = {}, fn) {
  const seen = [];
  const host = http.createServer((req, res) => {
    const rel = decodeURIComponent(new URL(req.url, 'http://x').pathname.slice(1)); seen.push(rel);
    if (status !== 200) { res.writeHead(status); return res.end(); }
    try { const b = fs.readFileSync(path.join(FIX, 'good', fixtureRel(rel))); res.writeHead(200); return res.end(b); } catch { res.writeHead(404); return res.end(); }
  });
  await new Promise((r) => host.listen(0, '127.0.0.1', r));
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'cg016-init-'));
  const proj = path.join(home, 'proj'); fs.mkdirSync(proj);
  fs.writeFileSync(path.join(proj, 'package-lock.json'), JSON.stringify({ lockfileVersion: 3, packages: { '': {}, 'node_modules/pkg-b': {} } }));
  writeConfig(path.join(home, 'config.json'), { advisory_feed: false, static_withhold: true, ...cfg });
  const paths = resolvePaths('user', proj, { CHAINGATE_HOME: home });
  const deps = { projectDir: proj, seedCache: { get: shardSource(`http://127.0.0.1:${host.address().port}/`), seedKey: SEED_KEY, bits: 3, now: NOW },
    fetchSeedBundle: async () => { throw new Error('no download in this test'); } };
  const out = []; const log = console.log; const err = console.error;
  console.log = (...a) => out.push(a.join(' ')); console.error = (...a) => out.push(a.join(' '));
  try { return await fn({ home, paths, deps, seen, out }); } finally {
    console.log = log; console.error = err; host.close(); fs.rmSync(home, { recursive: true, force: true });
  }
}
const OPTS = { scope: 'user', noSeed: false, seedPath: null, force: false, dryRun: false, unsignedDev: false };

test('IC1 init sets up the cache from the lockfile, writes the policy, keeps the other settings; the proxy then reads the cache', async () => {
  await withHome({}, async ({ home, paths, deps, seen, out }) => {
    const r = await installSeeds({ ...OPTS }, paths, deps, null);
    assert.equal(r.exit, undefined, out.join('\n'));
    assert.match(r.intended.seed_cache_root, /^[0-9a-f]{64}$/); assert.equal(r.intended.trust, 'authenticated');
    assert.ok(seen.includes(caPathOf(fixtureRoot(FIX), 2)), 'the bucket of the lockfile\'s package, by its content address');
    const cfg = readConfigStrict(paths.configFile);
    assert.deepEqual(cfg.policy, DEFAULT_POLICY); assert.equal(cfg.static_withhold, true); assert.equal(cfg.advisory_feed, false);
    assert.ok(fs.existsSync(paths.witnessDb));
    assert.ok(out.some((l) => /seed cache .*root of 2026-10-29T12:00:00Z/.test(l)), out.join('\n'));
    const c = loadConfig({ CHAINGATE_HOME: home });
    assert.equal(c.seedV3Path, paths.seedCache);
  });
});

test('IC2 a host with no cache yet: init says so and goes on as before', async () => {
  await withHome({ status: 404 }, async ({ paths, deps, out }) => {
    const r = await installSeeds({ ...OPTS }, paths, deps, null);
    assert.ok(out.some((l) => /seed cache is not available yet .*HTTP 404/.test(l)), out.join('\n'));
    assert.ok(out.some((l) => /Seed download failed: no download in this test/.test(l)), 'the earlier path ran');
    assert.equal(r.intended ?? null, null);
  });
});

test('IC3 seed_cache false, --no-seed or --seed: init fetches nothing from the cache host', async () => {
  for (const [cfg, opts] of [[{ seed_cache: false }, {}], [{}, { noSeed: true }]]) {
    await withHome({ cfg }, async ({ paths, deps, seen }) => {
      await installSeeds({ ...OPTS, ...opts }, paths, deps, null);
      assert.deepEqual(seen, [], JSON.stringify({ cfg, opts }));
    });
  }
});

test('IC6 what init and status say the proxy reads: the seed cache root when it serves one, else the active bundle', async () => {
  const { servedSeedLine } = await import('../../cli/commands/init.js');
  const { bundleNote } = await import('../../cli/commands/status.js');
  assert.equal(servedSeedLine({ seed_cache_root: 'ab'.repeat(32), bundle_id: null, sha256: null }), `seed cache, root ${'ab'.repeat(8)}...`);
  assert.equal(servedSeedLine({ bundle_id: 'fa41735ffad28100', sha256: '1408e015a7026ea292' }), 'active bundle fa41735ffad28100 sha256 1408e015a7026ea2...');
  assert.doesNotMatch(servedSeedLine({ seed_cache_root: 'cd'.repeat(32) }), /null/);
  assert.equal(bundleNote({ cacheInUse: true }), '(installed; the seed cache is read instead while it is on)');
  assert.equal(bundleNote({ cacheInUse: false }), '(recorded; `chaingate doctor` verifies it)');
});
