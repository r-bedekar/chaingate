// U-05 R2-2 legacy part, owner decision 7 requirements 4 and 5.
//   4. A missing witness.db is created from a complete, verified, closed staging file in the destination directory and
//      published with link(2), which refuses an existing destination; a destination created first takes the
//      existing-database path; an unsupported link REFUSES (no copy fallback); a kill never exposes a partial witness.db.
//   (Module level: installLegacySeed. The kill case C-4 and requirement 5 are in u05-r22-legacy-concurrency.test.js.)
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import http from 'node:http';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';

import { freshHome, runCli, runNode, startMutator, freePort, exists, PROXY, ROOT } from '../helpers/u05-r22.mjs';
import { testKey, buildLegacySeed, legacyWitness, snapshot, project, DEFAULT_PKGS, NEW_PKGS } from '../helpers/u05-r22-legacy.mjs';
import { installLegacySeed, MARKER_FILE } from '../../cli/legacy-seed.js';
import { acquireSeedMutationLock, releaseSeedMutationLock } from '../../cli/seed-mutation-lock.js';
import { resolvePaths } from '../../cli/paths.js';
import { docFor } from '../seed-v3/u05-fixtures.mjs';

const key = testKey();
const env = (bundle) => ({ U05_LEGACY_BUNDLE: bundle.dir, U05_TEST_SPKI: key.spki });
const fileSha = (f) => createHash('sha256').update(fs.readFileSync(f)).digest('hex');
const pathsFor = (base) => resolvePaths('user', process.cwd(), { CHAINGATE_HOME: base });
const stagedOf = (seed) => ({ path: seed.db, size: seed.size, digest: seed.digest, sha256Bytes: fs.readFileSync(seed.sha),
  sigBytes: fs.readFileSync(seed.sig), source: 'test' });
const leftovers = (base) => fs.readdirSync(base).filter((n) => /staging|install-pending/.test(n));
const LOCAL = { decisions: [{ id: 5, pkg: 'alpha', ver: '1.0.0', disposition: 'BLOCK', at: '2026-02-01 00:00:00' }] };

function withLock(base, fn) { const t = acquireSeedMutationLock(base); try { return fn(t); } finally { releaseSeedMutationLock(t); } }

// ---- requirement 4 ---------------------------------------------------------------------------------------------------
test('C-1 a missing witness database is created by link() from the verified copy: the seed bytes, nothing left behind', () => {
  const { home, base } = freshHome('create');
  try {
    const seed = buildLegacySeed(path.join(home, 'seed'), { key });
    const p = pathsFor(base);
    const did = withLock(base, (lock) => installLegacySeed(p, stagedOf(seed), { lock, mode: 'create-only' }));
    assert.equal(did.created, true);
    assert.equal(fileSha(p.witnessDb), seed.digest, 'witness.db is exactly the verified seed');
    assert.deepEqual(leftovers(base), [], 'no staging copy and no marker remain');
    assert.equal(fs.readFileSync(p.witnessDbSha256, 'utf8').trim(), seed.digest);
  } finally { fs.rmSync(home, { recursive: true, force: true }); }
});

test('C-2 the destination appears first (a proxy start): link() refuses it and the existing-database path refreshes it', () => {
  const { home, base } = freshHome('create');
  try {
    const seed = buildLegacySeed(path.join(home, 'seed'), { key, pkgs: NEW_PKGS });
    const p = pathsFor(base);
    const hooks = { beforeWitnessLink: () => legacyWitness(base, { from: 'runtime', local: LOCAL }) };
    const did = withLock(base, (lock) => installLegacySeed(p, stagedOf(seed), { lock, mode: 'create-only', hooks }));
    assert.equal(did.created, false); assert.ok(did.refreshed?.committed, 'refreshed in place');
    const after = snapshot(p.witnessDb);
    assert.deepEqual(project(after.rows.packages, ['id', 'package_name']), project(snapshot(seed.db).rows.packages, ['id', 'package_name']));
    assert.equal(after.rows.gate_decisions.find((d) => d.id === 5)?.package_name, 'alpha', 'the creator\'s local row is kept');
    assert.deepEqual(leftovers(base), []);
  } finally { fs.rmSync(home, { recursive: true, force: true }); }
});

test('C-3 link() unsupported: REFUSED clearly; no witness.db, no staging copy, no marker; no copy fallback', () => {
  const { home, base } = freshHome('create');
  try {
    const seed = buildLegacySeed(path.join(home, 'seed'), { key });
    const p = pathsFor(base);
    const fsImpl = { linkSync: () => { throw Object.assign(new Error('operation not permitted'), { code: 'EPERM' }); } };
    assert.throws(() => withLock(base, (lock) => installLegacySeed(p, stagedOf(seed), { lock, mode: 'create-only', fsImpl })),
      /cannot create the witness database without risking an overwrite \(link: EPERM\); nothing was installed/);
    assert.equal(exists(p.witnessDb), false);
    assert.deepEqual(leftovers(base), []);
  } finally { fs.rmSync(home, { recursive: true, force: true }); }
});

