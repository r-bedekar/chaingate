// U-04 — the proxy's direct-run check (proxy/server.js). `chaingate init` starts the proxy as
// `node <install>/proxy/server.js`; if the check fails, the process loads and exits without
// listening. The old check compared `import.meta.url` with `file://${process.argv[1]}`, which is
// wrong on Windows (`C:\...` against `file:///C:/...`) and on any path whose characters URL
// encoding changes (spaces, non-ASCII). These tests pin the predicate and then start the real proxy
// from a copy of the runtime installed under such a path.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import net from 'node:net';
import http from 'node:http';
import { mkdtempSync, rmSync, symlinkSync, readFileSync, existsSync, readdirSync, realpathSync, statSync, mkdirSync,
  copyFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

import { isDirectEntry } from '../../proxy/server.js';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const oldCheck = (moduleUrl, entryPath) => moduleUrl === `file://${entryPath}`;

test('direct-run predicate: Windows install paths (drive letters, spaces, backslashes)', () => {
  const cases = [
    ['C:\\Users\\Riz\\AppData\\Roaming\\npm\\node_modules\\@cgsec\\chaingate\\proxy\\server.js',
      'file:///C:/Users/Riz/AppData/Roaming/npm/node_modules/@cgsec/chaingate/proxy/server.js'],
    ['C:\\Users\\Jane Doe\\AppData\\Roaming\\npm\\node_modules\\@cgsec\\chaingate\\proxy\\server.js',
      'file:///C:/Users/Jane%20Doe/AppData/Roaming/npm/node_modules/@cgsec/chaingate/proxy/server.js'],
    ['D:\\tools\\node\\node_modules\\@cgsec\\chaingate\\proxy\\server.js',
      'file:///D:/tools/node/node_modules/@cgsec/chaingate/proxy/server.js'],
  ];
  for (const [argv1, moduleUrl] of cases) {
    assert.equal(isDirectEntry(moduleUrl, argv1, { windows: true }), true, argv1);
    assert.equal(oldCheck(moduleUrl, argv1), false, `the old check failed here: ${argv1}`);
  }
  // A different file is not a direct run.
  assert.equal(isDirectEntry('file:///C:/other/server.js', 'C:\\x\\server.js', { windows: true }), false);
});

test('direct-run predicate: POSIX paths, including spaces and non-ASCII', () => {
  // Expected URLs written out as import.meta.url produces them (space → %20, ë → %C3%AB; '@' stays).
  const cases = [
    ['/usr/lib/node_modules/@cgsec/chaingate/proxy/server.js',
      'file:///usr/lib/node_modules/@cgsec/chaingate/proxy/server.js', true],
    ['/Users/Jane Doe/.npm-global/lib/node_modules/@cgsec/chaingate/proxy/server.js',
      'file:///Users/Jane%20Doe/.npm-global/lib/node_modules/@cgsec/chaingate/proxy/server.js', false],
    ['/home/zoë/.npm-global/lib/node_modules/@cgsec/chaingate/proxy/server.js',
      'file:///home/zo%C3%AB/.npm-global/lib/node_modules/@cgsec/chaingate/proxy/server.js', false],
  ];
  for (const [argv1, moduleUrl, oldWorked] of cases) {
    assert.equal(isDirectEntry(moduleUrl, argv1, { windows: false }), true, argv1);
    assert.equal(oldCheck(moduleUrl, argv1), oldWorked, `old check on ${argv1}`);
  }
  assert.equal(isDirectEntry('file:///a/server.js', '/b/server.js', { windows: false }), false);
});

test('direct-run predicate: no entry script (node -e, REPL) is not a direct run', () => {
  assert.equal(isDirectEntry('file:///x/server.js', undefined), false);
  assert.equal(isDirectEntry('file:///x/server.js', ''), false);
});

function freePort() {
  return new Promise((resolve, reject) => {
    const s = net.createServer();
    s.once('error', reject);
    s.listen(0, '127.0.0.1', () => { const { port } = s.address(); s.close(() => resolve(port)); });
  });
}

function getJson(url) {
  return new Promise((resolve, reject) => {
    http.get(url, { agent: false }, (res) => {
      let b = ''; res.setEncoding('utf8'); res.on('data', (d) => { b += d; });
      res.on('end', () => { try { resolve({ status: res.statusCode, body: JSON.parse(b) }); } catch (e) { reject(e); } });
    }).on('error', reject);
  });
}

const LINK_TYPE = process.platform === 'win32' ? 'junction' : 'dir';   // a junction needs no privilege on Windows

/** A copy of the shipped runtime (the package.json "files" set) under `base`; dependencies linked. */
function installCopy(base) {
  const inst = join(base, 'node_modules', '@cgsec', 'chaingate');
  const files = JSON.parse(readFileSync(join(ROOT, 'package.json'), 'utf8')).files;
  // A plain recursive copy: fs.cpSync on Windows did not place the files under a destination whose
  // name has a non-ASCII character (CI run 36545649230: entry missing, readdir ENOENT), while node
  // itself starts from such paths fine (test/acceptance/spawn-diagnostic.mjs).
  const copy = (src, dst) => {
    if (statSync(src).isDirectory()) {
      mkdirSync(dst, { recursive: true });
      for (const n of readdirSync(src)) copy(join(src, n), join(dst, n));
    } else { mkdirSync(dirname(dst), { recursive: true }); copyFileSync(src, dst); }
  };
  for (const f of files) {
    if (/\.md$|^LICENSE$/.test(f)) continue;
    copy(join(ROOT, f), join(inst, f));
  }
  copy(join(ROOT, 'package.json'), join(inst, 'package.json'));
  symlinkSync(join(ROOT, 'node_modules'), join(inst, 'node_modules'), LINK_TYPE);
  return inst;
}

/** Start the proxy exactly as `chaingate init` does (node <abs path>) and ask it who it is. */
async function startFrom(t, entry, home) {
  const port = await freePort();
  t.diagnostic(`entry: ${entry}`);
  const child = spawn(process.execPath, [entry], {
    env: { ...process.env, CHAINGATE_HOME: home, CHAINGATE_PORT: String(port), CHAINGATE_HOST: '127.0.0.1',
      CHAINGATE_WITNESS_DB: join(home, 'witness.db') },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  let out = ''; child.stdout.on('data', (d) => { out += d; }); child.stderr.on('data', (d) => { out += d; });
  const exited = new Promise((r) => child.once('exit', (code) => r(code)));
  try {
    let iv; let timer;
    const listening = await Promise.race([
      new Promise((r) => { iv = setInterval(() => { if (/chaingate-proxy listening/.test(out)) r(true); }, 25); }),
      exited.then(() => false),
      new Promise((r) => { timer = setTimeout(() => r(false), 15_000); }),
    ]).finally(() => { clearInterval(iv); clearTimeout(timer); });
    if (!listening) {
      // Evidence for a failure on an unfamiliar platform: is the file there, and what is its real path?
      let real = null; let listing = null;
      try { real = realpathSync(entry); } catch (e) { real = `realpath failed: ${e.code}`; }
      try { listing = readdirSync(dirname(entry)).join(', '); } catch (e) { listing = `readdir failed: ${e.code}`; }
      assert.fail(`the proxy did not start listening.\n  entry exists: ${existsSync(entry)}\n  realpath: ${real}\n`
        + `  directory: ${listing}\n  output:\n${out}`);
    }
    const self = await getJson(`http://127.0.0.1:${port}/_chaingate/self`);
    assert.equal(self.status, 200);
    assert.equal(self.body.pid, child.pid, 'the answering proxy is the process started from this path');
  } finally {
    child.kill('SIGTERM');
    await Promise.race([exited, new Promise((r) => setTimeout(r, 5_000))]);
  }
}

test('the real proxy starts and serves when installed under a path with a space and a non-ASCII character', async (t) => {
  const base = mkdtempSync(join(tmpdir(), 'chaingate u04 zoë '));
  try {
    const inst = installCopy(base);
    await startFrom(t, join(inst, 'proxy', 'server.js'), join(base, 'home'));
  } finally { rmSync(base, { recursive: true, force: true }); }
});

test('the real proxy starts when its install directory is reached through a symlink (macOS /var, symlinked prefixes)', async (t) => {
  const base = mkdtempSync(join(tmpdir(), 'chaingate u04 link '));
  try {
    const inst = installCopy(join(base, 'real'));
    const linked = join(base, 'linked ë');
    symlinkSync(inst, linked, LINK_TYPE);
    await startFrom(t, join(linked, 'proxy', 'server.js'), join(base, 'home'));
  } finally { rmSync(base, { recursive: true, force: true }); }
});
