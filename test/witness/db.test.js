import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { openWitnessDB } from '../../witness/db.js';

function tmpDbPath() {
  const dir = mkdtempSync(join(tmpdir(), 'chaingate-witness-'));
  return { path: join(dir, 'witness.db'), dir };
}

// Hand-built axios@1.7.9 fixture — shape matches the output of
// witness/baseline.js (Day 4). Enough to exercise every column group.
function axiosFixture(version = '1.7.9') {
  return {
    published_at: '2024-12-23T00:00:00.000Z',
    content_hash: 'f05076f19e0b9f60b8f1b7a8a7f5a0a00fedf22d',
    content_hash_algo: 'sha1',
    integrity_hash: 'sha512-LhLcE7U6p8/IJhvZTZsiRBvkaHFULjCjfMCKpxRPxP6+ArxR8Y7yJRe0mLxGUpHE4A==',
    git_head: '9e0b9f60b8f1b7a8a7f5a0a00fedf22df05076f1',
    package_size_bytes: 432109,
    dependency_count: 3,
    dependencies: {
      'follow-redirects': '^1.15.6',
      'form-data': '^4.0.0',
      'proxy-from-env': '^1.1.0',
    },
    dev_dependencies: { mocha: '^10.2.0' },
    peer_dependencies: null,
    optional_dependencies: null,
    bundled_dependencies: null,
    dev_dependency_count: 1,
    peer_dependency_count: 0,
    optional_dependency_count: 0,
    bundled_dependency_count: 0,
    publisher_name: 'jasonsaayman',
    publisher_email: 'jasonsaayman@gmail.com',
    publisher_tool: '10.9.2',
    maintainers: [{ name: 'jasonsaayman', email: 'jasonsaayman@gmail.com' }],
    publish_method: 'token',
    provenance_present: false,
    provenance_details: null,
    has_install_scripts: false,
    source_repo_url: 'git+https://github.com/axios/axios.git',
    license: 'MIT',
    files: [
      {
        filename: 'axios-1.7.9.tgz',
        packagetype: 'tarball',
        content_hash: 'f05076f19e0b9f60b8f1b7a8a7f5a0a00fedf22d',
        content_hash_algo: 'sha1',
        size_bytes: 432109,
        uploaded_at: '2024-12-23T00:00:00.000Z',
        url: 'https://registry.npmjs.org/axios/-/axios-1.7.9.tgz',
      },
    ],
  };
}

test('createSchema is idempotent', () => {
  const { path, dir } = tmpDbPath();
  try {
    const db = openWitnessDB(path);
    db.createSchema();
    db.createSchema();
    db.close();
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('recordBaseline → getBaseline round-trip preserves JSON columns', () => {
  const { path, dir } = tmpDbPath();
  try {
    const db = openWitnessDB(path);
    const fixture = axiosFixture();
    db.recordBaseline('axios', '1.7.9', fixture);

    const baseline = db.getBaseline('axios', '1.7.9');
    assert.ok(baseline, 'baseline should exist after record');
    assert.equal(baseline.version, '1.7.9');
    assert.equal(baseline.integrity_hash, fixture.integrity_hash);
    assert.equal(baseline.publisher_email, 'jasonsaayman@gmail.com');
    assert.deepEqual(baseline.dependencies, fixture.dependencies);
    assert.deepEqual(baseline.maintainers, fixture.maintainers);
    assert.equal(baseline.provenance_present, 0, 'bool → int 0');
    assert.equal(baseline.has_install_scripts, 0);

    assert.equal(baseline.files.length, 1);
    assert.equal(baseline.files[0].filename, 'axios-1.7.9.tgz');
    assert.equal(baseline.files[0].content_hash, fixture.content_hash);

    db.close();
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('getBaseline returns null for unknown package/version', () => {
  const { path, dir } = tmpDbPath();
  try {
    const db = openWitnessDB(path);
    assert.equal(db.getBaseline('ghost-pkg', '0.0.0'), null);
    db.recordBaseline('axios', '1.7.9', axiosFixture());
    assert.equal(db.getBaseline('axios', '9.9.9'), null);
    db.close();
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('recordBaseline is idempotent (INSERT OR IGNORE)', () => {
  const { path, dir } = tmpDbPath();
  try {
    const db = openWitnessDB(path);
    const id1 = db.recordBaseline('axios', '1.7.9', axiosFixture());
    const id2 = db.recordBaseline('axios', '1.7.9', axiosFixture());
    assert.equal(id1, id2, 'second call returns same version_id');

    const rows = db.db.prepare('SELECT COUNT(*) AS n FROM versions').get();
    assert.equal(rows.n, 1, 'no duplicate version row');
    const fileRows = db.db.prepare('SELECT COUNT(*) AS n FROM version_files').get();
    assert.equal(fileRows.n, 1, 'no duplicate file row');
    db.close();
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('recordBaseline bumps last_seen_at on re-observe', () => {
  const { path, dir } = tmpDbPath();
  try {
    const db = openWitnessDB(path);
    db.recordBaseline('axios', '1.7.9', axiosFixture());
    const first = db.getBaseline('axios', '1.7.9').last_seen_at;
    assert.ok(first, 'last_seen_at populated on first record');

    db.recordBaseline('axios', '1.7.9', axiosFixture());
    const second = db.getBaseline('axios', '1.7.9').last_seen_at;
    assert.ok(second >= first, 'last_seen_at monotonic');
    db.close();
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('getHistory orders newest-first and decodes JSON', () => {
  const { path, dir } = tmpDbPath();
  try {
    const db = openWitnessDB(path);
    const v1 = axiosFixture('1.7.8');
    v1.published_at = '2024-10-01T00:00:00.000Z';
    v1.integrity_hash = 'sha512-old==';
    const v2 = axiosFixture('1.7.9');
    v2.published_at = '2024-12-23T00:00:00.000Z';
    db.recordBaseline('axios', '1.7.8', v1);
    db.recordBaseline('axios', '1.7.9', v2);

    const history = db.getHistory('axios');
    assert.equal(history.length, 2);
    assert.equal(history[0].version, '1.7.9', 'newest-first ordering');
    assert.equal(history[1].version, '1.7.8');
    assert.deepEqual(history[0].dependencies, v2.dependencies);
    db.close();
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('insertGateDecision + gate_decisions is append-only', () => {
  const { path, dir } = tmpDbPath();
  try {
    const db = openWitnessDB(path);
    const gates = [
      { gate: 'content-hash', result: 'SKIP', detail: 'first-seen' },
      { gate: 'dep-structure', result: 'WARN', detail: 'new dep: form-data' },
    ];
    const id1 = db.insertGateDecision('axios', '1.7.9', 'WARN', gates);
    const id2 = db.insertGateDecision('axios', '1.7.9', 'WARN', gates);
    assert.notEqual(id1, id2, 'every decision is a new row');

    const row = db.db.prepare(
      'SELECT disposition, gates_fired FROM gate_decisions WHERE id = ?',
    ).get(id1);
    assert.equal(row.disposition, 'WARN');
    assert.deepEqual(JSON.parse(row.gates_fired), gates);
    db.close();
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('insertGateDecision rejects invalid disposition', () => {
  const { path, dir } = tmpDbPath();
  try {
    const db = openWitnessDB(path);
    assert.throws(
      () => db.insertGateDecision('axios', '1.7.9', 'MAYBE', []),
      /CHECK/i,
    );
    db.close();
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('getOverride returns null when absent, row after insert', () => {
  const { path, dir } = tmpDbPath();
  try {
    const db = openWitnessDB(path);
    assert.equal(db.getOverride('axios', '1.14.1'), null);
    db.insertOverride('axios', '1.14.1', 'allowed per incident #42');
    const row = db.getOverride('axios', '1.14.1');
    assert.equal(row.reason, 'allowed per incident #42');
    assert.ok(row.created_at);
    db.close();
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('insertOverride updates reason on conflict', () => {
  const { path, dir } = tmpDbPath();
  try {
    const db = openWitnessDB(path);
    db.insertOverride('axios', '1.14.1', 'first reason');
    db.insertOverride('axios', '1.14.1', 'second reason');
    assert.equal(db.getOverride('axios', '1.14.1').reason, 'second reason');
    const n = db.db.prepare('SELECT COUNT(*) AS n FROM overrides').get().n;
    assert.equal(n, 1, 'overrides stay unique per (pkg, version)');
    db.close();
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('seed_metadata get/set round-trip', () => {
  const { path, dir } = tmpDbPath();
  try {
    const db = openWitnessDB(path);
    assert.equal(db.getSeedMetadata('seed_version'), null);
    db.setSeedMetadata('seed_version', '2026-04-14');
    db.setSeedMetadata('signing_key_fingerprint', 'ed25519:abcd…');
    assert.equal(db.getSeedMetadata('seed_version'), '2026-04-14');
    assert.equal(db.getSeedMetadata('signing_key_fingerprint'), 'ed25519:abcd…');
    db.setSeedMetadata('seed_version', '2026-05-01');
    assert.equal(db.getSeedMetadata('seed_version'), '2026-05-01');
    db.close();
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('package uniqueness across ecosystems enforced by CHECK', () => {
  const { path, dir } = tmpDbPath();
  try {
    const db = openWitnessDB(path);
    db.recordBaseline('axios', '1.7.9', axiosFixture());
    db.recordBaseline('axios', '1.7.9', axiosFixture());
    const n = db.db.prepare('SELECT COUNT(*) AS n FROM packages').get().n;
    assert.equal(n, 1, 'packages upsert is idempotent');
    db.close();
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
