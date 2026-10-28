// Recognising a better-sqlite3 native module that does not load, and the fix it prints. better-sqlite3 ships its native
// part ready-built inside the npm package for Linux (glibc and musl), macOS and Windows on x64 and arm64, and has no
// install script; on any other system it looks for a local build in build/Release. The guidance never enables an
// install script: there is none to enable.
import { test } from 'node:test';
import assert from 'node:assert/strict';

import { classifyNativeSqliteError, probeNativeSqlite, nativeSqliteHelp } from '../../cli/native-sqlite.js';

test('classifies the real failure messages', () => {
  // better-sqlite3 13 on a system with no ready-built part and no local build (message as Node prints it)
  const missing = Object.assign(new Error("Cannot find module '/x/node_modules/better-sqlite3/build/Release/better_sqlite3.node'\n"
    + 'Require stack:\n- /x/node_modules/better-sqlite3/lib/binding.js\n- /x/node_modules/better-sqlite3/lib/index.js'), { code: 'MODULE_NOT_FOUND' });
  assert.equal(classifyNativeSqliteError(missing), 'missing');
  const dl = Object.assign(new Error('/x/node_modules/better-sqlite3/prebuilds/linux-x64.node: invalid ELF header'), { code: 'ERR_DLOPEN_FAILED' });
  assert.equal(classifyNativeSqliteError(dl), 'other');
  const glibc = Object.assign(new Error("/lib/x86_64-linux-gnu/libc.so.6: version `GLIBC_2.38' not found (required by /x/better-sqlite3/prebuilds/linux-x64.node)"),
    { code: 'ERR_DLOPEN_FAILED' });
  assert.equal(classifyNativeSqliteError(glibc), 'other', 'a ready-built part the system cannot load is not a missing one');
  assert.equal(classifyNativeSqliteError(new Error('ENOENT: no such file, open /tmp/x.json')), null, 'unrelated errors are left alone');
  assert.equal(classifyNativeSqliteError(new Error("Cannot find module '/x/other.node'")), null);
  assert.equal(classifyNativeSqliteError(undefined), null);
});

test('the installed native module loads in this environment', () => {
  const p = probeNativeSqlite();
  assert.equal(p.ok, true, p.message);
  assert.match(p.version, /^\d+\.\d+\.\d+$/);
});

test('guidance names the version and doctor, is plain ASCII, and never enables an install script', () => {
  for (const kind of ['missing', 'other']) {
    const text = nativeSqliteHelp(kind, '13.0.3', 'freebsd-x64').join('\n');
    assert.match(text, /better-sqlite3 13\.0\.3/);
    assert.match(text, /chaingate doctor/);
    assert.doesNotMatch(text, /[^\x20-\x7e\n]/, 'plain ASCII');
    assert.doesNotMatch(text, /allow-scripts|allowScripts|approve-scripts|ignore-scripts|npm rebuild|--foreground-scripts/);
  }
});

test('a missing native part: names the system, the ready-built systems, and how to build from source', () => {
  const text = nativeSqliteHelp('missing', '13.0.3', 'freebsd-x64').join('\n');
  assert.match(text, /freebsd-x64/);
  assert.match(text, /Linux, macOS and Windows on x64 and arm64/);
  assert.match(text, /Python and a C\+\+ compiler/);
  assert.match(text, /cd "\$\(npm root -g\)\/@cgsec\/chaingate\/node_modules\/better-sqlite3" && npm run build-release/);
  assert.match(text, /cd node_modules\/better-sqlite3 && npm run build-release/);
  assert.match(text, /not tested or supported/);
});

test('a native part that does not load: reinstall, global or project', () => {
  const text = nativeSqliteHelp('other', '13.0.3', 'linux-x64').join('\n');
  assert.match(text, /did not load/);
  assert.match(text, /npm install -g @cgsec\/chaingate/);
  assert.match(text, /npm install @cgsec\/chaingate/);
  assert.doesNotMatch(text, /build-release/);
});
