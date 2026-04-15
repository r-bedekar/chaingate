import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { openWitnessDB } from '../../witness/db.js';
import { createWitness } from '../../witness/store.js';
import { createGateRunner } from '../../gates/index.js';

function tmpDb() {
  const dir = mkdtempSync(join(tmpdir(), 'chaingate-store-'));
  const path = join(dir, 'witness.db');
  return {
    path,
    cleanup: () => rmSync(dir, { recursive: true, force: true }),
  };
}

function axiosPackument({ versions = ['1.7.8', '1.7.9'], shasumMap = {} } = {}) {
  const versionsObj = {};
  const time = {};
  for (const v of versions) {
    versionsObj[v] = {
      name: 'axios',
      version: v,
      dependencies: { 'follow-redirects': '^1.15.6' },
      devDependencies: { mocha: '^10.2.0' },
      _npmUser: { name: 'jasonsaayman', email: 'j@example.com' },
      _npmVersion: '10.9.2',
      dist: {
        shasum: shasumMap[v] ?? `sha1-${v}`,
        integrity: `sha512-${v}==`,
        tarball: `https://registry.npmjs.org/axios/-/axios-${v}.tgz`,
        unpackedSize: 432109,
      },
      repository: { type: 'git', url: 'git+https://github.com/axios/axios.git' },
    };
    time[v] = `2024-12-${v.replace(/\./g, '').padEnd(2, '0')}T00:00:00.000Z`;
  }
  return { name: 'axios', 'dist-tags': { latest: versions[versions.length - 1] }, versions: versionsObj, time };
}

const allowRunner = () => ({ disposition: 'ALLOW', results: [] });

test('observePackument on empty DB → N baselines, N first-seen decisions', () => {
  const { path, cleanup } = tmpDb();
  try {
    const db = openWitnessDB(path);
    const w = createWitness({ db, runGates: allowRunner, config: {} });
    const result = w.observePackument('axios', axiosPackument());
    assert.equal(result.versionsSeen, 2);
    assert.equal(result.newBaselines, 2);
    assert.equal(result.decisions.size, 2);
    for (const dec of result.decisions.values()) assert.equal(dec.disposition, 'ALLOW');

    assert.ok(db.getBaseline('axios', '1.7.8'));
    assert.ok(db.getBaseline('axios', '1.7.9'));
    const decisionCount = db.db
      .prepare(`SELECT COUNT(*) AS n FROM gate_decisions WHERE package_name = 'axios'`)
      .get().n;
    assert.equal(decisionCount, 2);
    w.close();
  } finally {
    cleanup();
  }
});

test('re-observe same packument → 0 new baselines, 0 new decisions (sparsity)', () => {
  const { path, cleanup } = tmpDb();
  try {
    const db = openWitnessDB(path);
    const w = createWitness({ db, runGates: allowRunner, config: {} });
    w.observePackument('axios', axiosPackument());
    const second = w.observePackument('axios', axiosPackument());
    assert.equal(second.newBaselines, 0);
    const decisionCount = db.db
      .prepare(`SELECT COUNT(*) AS n FROM gate_decisions WHERE package_name = 'axios'`)
      .get().n;
    assert.equal(decisionCount, 2);
    w.close();
  } finally {
    cleanup();
  }
});

test('mixed new + known → only new gets baseline + decision row', () => {
  const { path, cleanup } = tmpDb();
  try {
    const db = openWitnessDB(path);
    const w = createWitness({ db, runGates: allowRunner, config: {} });
    w.observePackument('axios', axiosPackument({ versions: ['1.7.8'] }));
    const second = w.observePackument('axios', axiosPackument({ versions: ['1.7.8', '1.7.9'] }));
    assert.equal(second.newBaselines, 1);
    assert.equal(second.versionsSeen, 2);
    const decisionCount = db.db
      .prepare(`SELECT COUNT(*) AS n FROM gate_decisions WHERE package_name = 'axios'`)
      .get().n;
    assert.equal(decisionCount, 2);
    w.close();
  } finally {
    cleanup();
  }
});

test('runGates throws per-version → caught, other versions still processed', () => {
  const { path, cleanup } = tmpDb();
  try {
    const db = openWitnessDB(path);
    const runGates = (input) => {
      if (input.version === '1.7.8') throw new Error('gate boom');
      return { disposition: 'ALLOW', results: [] };
    };
    const w = createWitness({ db, runGates, config: {}, logger: { info() {}, warn() {}, error() {} } });
    const result = w.observePackument('axios', axiosPackument());
    assert.equal(result.versionsSeen, 2);
    // Both still recorded — throw is caught, baseline recorded with synthetic runner_error SKIP
    assert.ok(db.getBaseline('axios', '1.7.8'));
    assert.ok(db.getBaseline('axios', '1.7.9'));
    w.close();
  } finally {
    cleanup();
  }
});

test('getHistory called exactly once per observePackument', () => {
  const { path, cleanup } = tmpDb();
  try {
    const db = openWitnessDB(path);
    let callCount = 0;
    const origGetHistory = db.getHistory.bind(db);
    db.getHistory = (name) => {
      callCount += 1;
      return origGetHistory(name);
    };
    const w = createWitness({ db, runGates: allowRunner, config: {} });
    w.observePackument('axios', axiosPackument());
    assert.equal(callCount, 1);
    w.close();
  } finally {
    cleanup();
  }
});

test('observeTarball returns ALLOW (Day 4 stub)', () => {
  const { path, cleanup } = tmpDb();
  try {
    const db = openWitnessDB(path);
    const w = createWitness({ db, runGates: allowRunner, config: {} });
    assert.deepEqual(w.observeTarball('axios', 'axios-1.7.9.tgz'), { disposition: 'ALLOW' });
    w.close();
  } finally {
    cleanup();
  }
});

test('sparsity: 10× observations → exactly N decision rows', () => {
  const { path, cleanup } = tmpDb();
  try {
    const db = openWitnessDB(path);
    const w = createWitness({ db, runGates: allowRunner, config: {} });
    for (let i = 0; i < 10; i += 1) {
      w.observePackument('axios', axiosPackument());
    }
    const decisionCount = db.db
      .prepare(`SELECT COUNT(*) AS n FROM gate_decisions WHERE package_name = 'axios'`)
      .get().n;
    assert.equal(decisionCount, 2);
    w.close();
  } finally {
    cleanup();
  }
});

test('disposition flip → new decision row appended', () => {
  const { path, cleanup } = tmpDb();
  try {
    const db = openWitnessDB(path);
    let mode = 'ALLOW';
    const runGates = () => ({ disposition: mode, results: [{ gate: 'stub', result: mode, detail: '' }] });
    const w = createWitness({ db, runGates, config: {} });
    w.observePackument('axios', axiosPackument({ versions: ['1.7.8'] }));
    mode = 'WARN';
    w.observePackument('axios', axiosPackument({ versions: ['1.7.8'] }));
    mode = 'WARN';
    w.observePackument('axios', axiosPackument({ versions: ['1.7.8'] }));
    mode = 'BLOCK';
    w.observePackument('axios', axiosPackument({ versions: ['1.7.8'] }));
    const rows = db.db
      .prepare(`SELECT disposition FROM gate_decisions WHERE package_name='axios' AND version='1.7.8' ORDER BY id`)
      .all();
    assert.deepEqual(rows.map((r) => r.disposition), ['ALLOW', 'WARN', 'BLOCK']);
    w.close();
  } finally {
    cleanup();
  }
});

test('per-version catch does not roll back other versions in transaction', () => {
  const { path, cleanup } = tmpDb();
  try {
    const db = openWitnessDB(path);
    // Runner returns ALLOW for all. We simulate a per-version failure by monkey
    // patching getBaseline to throw for one specific version.
    const origGetBaseline = db.getBaseline.bind(db);
    db.getBaseline = (name, version) => {
      if (version === '1.7.8') throw new Error('read boom');
      return origGetBaseline(name, version);
    };
    const w = createWitness({ db, runGates: allowRunner, config: {}, logger: { info() {}, warn() {}, error() {} } });
    w.observePackument('axios', axiosPackument());
    // 1.7.9 should have been written despite 1.7.8 failing
    db.getBaseline = origGetBaseline;
    assert.ok(db.getBaseline('axios', '1.7.9'));
    assert.equal(db.getBaseline('axios', '1.7.8'), null);
    w.close();
  } finally {
    cleanup();
  }
});

test('config wiring: witness.config === injected config', () => {
  const { path, cleanup } = tmpDb();
  try {
    const db = openWitnessDB(path);
    const cfg = { foo: 'bar' };
    const w = createWitness({ db, runGates: allowRunner, config: cfg });
    assert.equal(w.config, cfg);
    w.close();
  } finally {
    cleanup();
  }
});

test('createWitness requires db + runGates', () => {
  assert.throws(() => createWitness({ runGates: allowRunner }), /db is required/);
  assert.throws(() => createWitness({ db: {}, runGates: null }), /runGates/);
});

// ---- P5.5: real runner + override wiring ----------------------------------

test('zero-module runner (P5.5 default) + first-seen still records ALLOW', () => {
  const { path, cleanup } = tmpDb();
  try {
    const db = openWitnessDB(path);
    const runGates = createGateRunner({
      modules: [],
      getOverride: (pkg, ver) => db.getOverride(pkg, ver),
    });
    const w = createWitness({ db, runGates, config: {} });
    const res = w.observePackument('axios', axiosPackument({ versions: ['1.7.9'] }));
    assert.equal(res.newBaselines, 1);
    assert.equal(res.decisions.get('1.7.9').disposition, 'ALLOW');
    w.close();
  } finally {
    cleanup();
  }
});

test('override row → runner short-circuits, decision log includes override entry', () => {
  const { path, cleanup } = tmpDb();
  try {
    const db = openWitnessDB(path);
    // Gate that would BLOCK, paired with an override that rescues it.
    const blockingModule = {
      name: 'always-block',
      evaluate: () => ({ result: 'BLOCK', detail: 'simulated' }),
    };
    const runGates = createGateRunner({
      modules: [blockingModule],
      getOverride: (pkg, ver) => db.getOverride(pkg, ver),
    });
    db.insertOverride('axios', '1.7.9', 'trusted internal mirror');
    const w = createWitness({ db, runGates, config: {} });
    w.observePackument('axios', axiosPackument({ versions: ['1.7.9'] }));
    const dec = db.getLatestDecision('axios', '1.7.9');
    assert.equal(dec.disposition, 'ALLOW');
    // First-seen entry + override entry both in gates_fired.
    const gates = dec.gates_fired.map((r) => r.gate);
    assert.ok(gates.includes('override'), `expected override gate in ${JSON.stringify(gates)}`);
    const override = dec.gates_fired.find((r) => r.gate === 'override');
    assert.match(override.detail, /trusted internal mirror/);
    w.close();
  } finally {
    cleanup();
  }
});

test('runner flips ALLOW→BLOCK on second observation → new BLOCK decision row', () => {
  const { path, cleanup } = tmpDb();
  try {
    const db = openWitnessDB(path);
    let mode = 'ALLOW';
    const toggleMod = {
      name: 'toggle',
      evaluate: () => ({ result: mode, detail: `mode=${mode}` }),
    };
    const runGates = createGateRunner({ modules: [toggleMod] });
    const w = createWitness({ db, runGates, config: {} });
    w.observePackument('axios', axiosPackument({ versions: ['1.7.9'] }));
    mode = 'BLOCK';
    w.observePackument('axios', axiosPackument({ versions: ['1.7.9'] }));
    const rows = db.db
      .prepare(`SELECT disposition FROM gate_decisions WHERE package_name='axios' AND version='1.7.9' ORDER BY id`)
      .all();
    assert.deepEqual(rows.map((r) => r.disposition), ['ALLOW', 'BLOCK']);
    w.close();
  } finally {
    cleanup();
  }
});
