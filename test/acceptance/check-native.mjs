#!/usr/bin/env node
// Proves the installed better-sqlite3 native module is the ready-built binary shipped inside the npm package for this
// platform (byte-identical to the recorded one), that it is the one that loads, and that nothing was compiled locally
// (no build/ directory). Optionally checks an npm install log for any node-gyp / compiler run or install script.
//   node check-native.mjs <dir containing node_modules/better-sqlite3> [install-log]
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const [root, log] = process.argv.slice(2);
const expected = JSON.parse(fs.readFileSync(path.join(HERE, 'better-sqlite3-prebuilds.json'), 'utf8'));
const mod = path.resolve(root, 'node_modules', 'better-sqlite3');
const version = JSON.parse(fs.readFileSync(path.join(mod, 'package.json'), 'utf8')).version;
const musl = process.platform === 'linux' && !process.report.getReport().header.glibcVersionRuntime;
const target = `${musl ? 'linuxmusl' : process.platform}-${process.arch}`;
const node = path.join(mod, 'prebuilds', `${target}.node`);
const want = expected.native_sha256[target];
const got = fs.existsSync(node) ? crypto.createHash('sha256').update(fs.readFileSync(node)).digest('hex') : null;
const problems = [];
if (version !== expected.version) problems.push(`better-sqlite3 ${version} installed, expected ${expected.version}`);
if (!want) problems.push(`no ready-built binary recorded for ${target}`);
if (!got) problems.push(`${node} missing`);
else if (want && got !== want) problems.push(`native module ${got} is not the recorded ${target} binary ${want}`);
if (fs.existsSync(path.join(mod, 'build'))) problems.push('a build/ directory exists (a local compile)');
let loaded = null;
try {
  const req = createRequire(path.join(mod, 'package.json'));
  loaded = req(path.join(mod, 'lib', 'binding.js')).getPrebuildPath();
  if (loaded && path.resolve(loaded) !== path.resolve(node)) problems.push(`better-sqlite3 loads ${loaded}, not ${node}`);
  if (!loaded) problems.push('better-sqlite3 finds no ready-built binary for this platform');
} catch (e) { problems.push(`binding lookup failed: ${e.message}`); }
if (log && fs.existsSync(log)) {
  const text = fs.readFileSync(log, 'utf8');
  if (/gyp info|gyp ERR!|MSBuild|cc1plus|clang\+\+|g\+\+ /.test(text)) problems.push('the install log shows a node-gyp / compiler run');
  if (/better-sqlite3@[^\s]* (install|preinstall|postinstall)\b|prebuild-install/.test(text)) problems.push('the install log shows an install script of better-sqlite3');
}
console.log(JSON.stringify({ platform: target, node: process.version, better_sqlite3: version, native_sha256: got, expected: want, loads: loaded, ok: problems.length === 0, problems }));
process.exitCode = problems.length ? 1 : 0;
