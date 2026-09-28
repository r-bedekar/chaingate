// U-04 — recognising a missing or mismatched better-sqlite3 native module, and the fix it prints.
// The guidance must allow only better-sqlite3's own install script, never all dependency scripts.
import { test } from 'node:test';
import assert from 'node:assert/strict';

import { classifyNativeSqliteError, probeNativeSqlite, nativeSqliteHelp } from '../../cli/native-sqlite.js';

test('classifies the real failure messages', () => {
  const missing = new Error('Could not locate the bindings file. Tried:\n → /x/node_modules/better-sqlite3/build/better_sqlite3.node');
  assert.equal(classifyNativeSqliteError(missing), 'missing');
  const abi = new Error("The module '/x/better_sqlite3.node' was compiled against a different Node.js version using NODE_MODULE_VERSION 115. This version of Node.js requires NODE_MODULE_VERSION 127.");
  assert.equal(classifyNativeSqliteError(abi), 'abi');
  const dl = Object.assign(new Error('/x/better_sqlite3.node: invalid ELF header'), { code: 'ERR_DLOPEN_FAILED' });
  assert.equal(classifyNativeSqliteError(dl), 'other');
  assert.equal(classifyNativeSqliteError(new Error('ENOENT: no such file, open /tmp/x.json')), null, 'unrelated errors are left alone');
  assert.equal(classifyNativeSqliteError(undefined), null);
});

test('the installed native module loads in this environment', () => {
  const p = probeNativeSqlite();
  assert.equal(p.ok, true, p.message);
  assert.match(p.version, /^\d+\.\d+\.\d+$/);
});

test('guidance enables only better-sqlite3 scripts, and never recommends enabling all dependency scripts', () => {
  for (const kind of ['missing', 'other', 'abi']) {
    const text = nativeSqliteHelp(kind, '11.10.0').join('\n');
    assert.match(text, /better-sqlite3 11\.10\.0/);
    assert.match(text, /chaingate doctor/);
    for (const line of text.split('\n')) {
      if (/--allow-scripts|--ignore-scripts=false/.test(line)) {
        assert.match(line, /better-sqlite3/, `a script-enabling command must name better-sqlite3: ${line}`);
        assert.doesNotMatch(line, /--allow-scripts(=\*|=all|\s|$)/, `no blanket allow: ${line}`);
      }
    }
    assert.doesNotMatch(text, /npm config set ignore-scripts false|--foreground-scripts|allow-scripts=\*/);
  }
  const missing = nativeSqliteHelp('missing', '11.10.0').join('\n');
  assert.match(missing, /npm install -g @cgsec\/chaingate --allow-scripts=better-sqlite3/);
  assert.match(missing, /npm rebuild better-sqlite3 --ignore-scripts=false/);
  assert.match(missing, /PowerShell: .*npm rebuild better-sqlite3 --ignore-scripts=false/);
});
