import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';

import {
  findInstallRoot,
  readLockfileIntegrity,
  hasAnyChaingateInWitness,
  checkSelfWitness,
} from '../../cli/self-witness.js';

const SRI = 'sha512-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==';
const SRI_OTHER = 'sha512-BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB==';

function makeTree({ version = '0.1.0', writeLock = true, lockIntegrity = SRI } = {}) {
  const root = mkdtempSync(join(tmpdir(), 'chaingate-self-'));
  const nm = join(root, 'node_modules');
  const cgDir = join(nm, 'chaingate');
  const cliDir = join(cgDir, 'cli');
  mkdirSync(cliDir, { recursive: true });

  writeFileSync(
    join(cgDir, 'package.json'),
    JSON.stringify({ name: 'chaingate', version }),
  );
  // A synthetic entry file; self-witness walks up from this URL.
  const entryFile = join(cliDir, 'index.js');
  writeFileSync(entryFile, '// synthetic');

  if (writeLock) {
    writeFileSync(
      join(nm, '.package-lock.json'),
      JSON.stringify({
        name: 'chaingate',
        lockfileVersion: 3,
        packages: {
          'node_modules/chaingate': { version, integrity: lockIntegrity },
        },
      }),
    );
  }

  return {
    root,
    entryFileUrl: pathToFileURL(entryFile).href,
    installRoot: cgDir,
    cleanup: () => rmSync(root, { recursive: true, force: true }),
  };
}

function makeWitness({ baselineIntegrity, history = null } = {}) {
  return {
    getBaseline(name, version) {
      if (name !== 'chaingate') return null;
      if (baselineIntegrity === null) return null;
      return { version, integrity_hash: baselineIntegrity };
    },
    getHistory(name) {
      if (history != null) return history;
      return baselineIntegrity ? [{ version: '0.0.1' }] : [];
    },
  };
}

// ---- findInstallRoot ------------------------------------------------------

test('findInstallRoot: locates chaingate package.json by walking up', () => {
  const t = makeTree();
  try {
    const info = findInstallRoot(t.entryFileUrl);
    assert.ok(info);
    assert.equal(info.root, t.installRoot);
    assert.equal(info.version, '0.1.0');
  } finally {
    t.cleanup();
  }
});

test('findInstallRoot: returns null when no chaingate package.json up-tree', () => {
  const dir = mkdtempSync(join(tmpdir(), 'chaingate-noroot-'));
  try {
    const entry = join(dir, 'foo.js');
    writeFileSync(entry, '// nothing');
    // Put a package.json with a DIFFERENT name to ensure we don't false-match.
    writeFileSync(join(dir, 'package.json'), JSON.stringify({ name: 'other' }));
    const info = findInstallRoot(pathToFileURL(entry).href);
    assert.equal(info, null);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

// ---- readLockfileIntegrity ------------------------------------------------

test('readLockfileIntegrity: returns the recorded SRI string', () => {
  const t = makeTree({ lockIntegrity: SRI });
  try {
    assert.equal(readLockfileIntegrity(t.installRoot), SRI);
  } finally {
    t.cleanup();
  }
});

test('readLockfileIntegrity: returns null when lockfile is absent', () => {
  const t = makeTree({ writeLock: false });
  try {
    assert.equal(readLockfileIntegrity(t.installRoot), null);
  } finally {
    t.cleanup();
  }
});

// ---- hasAnyChaingateInWitness ---------------------------------------------

test('hasAnyChaingateInWitness: true when history non-empty', () => {
  assert.equal(hasAnyChaingateInWitness(makeWitness({ baselineIntegrity: SRI })), true);
});

test('hasAnyChaingateInWitness: false when history empty', () => {
  assert.equal(
    hasAnyChaingateInWitness(makeWitness({ baselineIntegrity: null, history: [] })),
    false,
  );
});

test('hasAnyChaingateInWitness: false when getHistory throws', () => {
  const w = { getHistory() { throw new Error('db closed'); } };
  assert.equal(hasAnyChaingateInWitness(w), false);
});

// ---- checkSelfWitness -----------------------------------------------------

test('checkSelfWitness: verified when installed integrity matches witness', () => {
  const t = makeTree({ lockIntegrity: SRI });
  try {
    const r = checkSelfWitness(makeWitness({ baselineIntegrity: SRI }), {
      startFileUrl: t.entryFileUrl,
    });
    assert.equal(r.status, 'verified');
    assert.equal(r.reason, 'integrity_match');
    assert.equal(r.version, '0.1.0');
    assert.equal(r.integrity, SRI);
  } finally {
    t.cleanup();
  }
});

test('checkSelfWitness: tamper when installed integrity differs from witness', () => {
  const t = makeTree({ lockIntegrity: SRI });
  try {
    const r = checkSelfWitness(makeWitness({ baselineIntegrity: SRI_OTHER }), {
      startFileUrl: t.entryFileUrl,
    });
    assert.equal(r.status, 'tamper');
    assert.equal(r.reason, 'integrity_mismatch');
    assert.equal(r.installedIntegrity, SRI);
    assert.equal(r.witnessIntegrity, SRI_OTHER);
  } finally {
    t.cleanup();
  }
});

test('checkSelfWitness: unverifiable when chaingate not in witness (pre-publish)', () => {
  const t = makeTree({ lockIntegrity: SRI });
  try {
    const r = checkSelfWitness(makeWitness({ baselineIntegrity: null, history: [] }), {
      startFileUrl: t.entryFileUrl,
    });
    assert.equal(r.status, 'unverifiable');
    assert.equal(r.reason, 'not_in_witness');
    assert.match(r.detail, /pre-publish/);
    assert.equal(r.version, '0.1.0');
  } finally {
    t.cleanup();
  }
});

test('checkSelfWitness: unverifiable when no lockfile (dev install / npm link)', () => {
  const t = makeTree({ writeLock: false });
  try {
    const r = checkSelfWitness(makeWitness({ baselineIntegrity: SRI }), {
      startFileUrl: t.entryFileUrl,
    });
    assert.equal(r.status, 'unverifiable');
    assert.equal(r.reason, 'lockfile_missing');
    assert.equal(r.version, '0.1.0');
  } finally {
    t.cleanup();
  }
});

test('checkSelfWitness: unverifiable when install root cannot be located', () => {
  const dir = mkdtempSync(join(tmpdir(), 'chaingate-noinstall-'));
  try {
    const entry = join(dir, 'foo.js');
    writeFileSync(entry, '// nothing');
    const r = checkSelfWitness(makeWitness({ baselineIntegrity: SRI }), {
      startFileUrl: pathToFileURL(entry).href,
    });
    assert.equal(r.status, 'unverifiable');
    assert.equal(r.reason, 'install_root_not_found');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('checkSelfWitness: unverifiable when witness read throws', () => {
  const t = makeTree({ lockIntegrity: SRI });
  try {
    const brokenWitness = {
      getBaseline() { throw new Error('db locked'); },
      getHistory() { return []; },
    };
    const r = checkSelfWitness(brokenWitness, { startFileUrl: t.entryFileUrl });
    assert.equal(r.status, 'unverifiable');
    assert.equal(r.reason, 'witness_read_failed');
    assert.match(r.detail, /db locked/);
  } finally {
    t.cleanup();
  }
});
