#!/usr/bin/env node
// Proves the installed better-sqlite3 native module is the OFFICIAL prebuilt binary for this platform
// and Node ABI (byte-identical to the verified release asset), not a local compile. Optionally checks an
// npm install log for any node-gyp / compiler fallback.
//   node check-native.mjs <dir containing node_modules/better-sqlite3> [install-log]
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const [root, log] = process.argv.slice(2);
const expected = JSON.parse(fs.readFileSync(path.join(HERE, 'better-sqlite3-prebuilds.json'), 'utf8'));
const mod = path.join(root, 'node_modules', 'better-sqlite3');
const version = JSON.parse(fs.readFileSync(path.join(mod, 'package.json'), 'utf8')).version;
const node = path.join(mod, 'build', 'Release', 'better_sqlite3.node');
const plat = `${process.platform}-${process.arch}`;
const abi = process.versions.modules;
const want = expected.native_sha256[plat]?.[abi];
const got = fs.existsSync(node) ? crypto.createHash('sha256').update(fs.readFileSync(node)).digest('hex') : null;
const problems = [];
if (version !== expected.version) problems.push(`better-sqlite3 ${version} installed, expected ${expected.version}`);
if (!want) problems.push(`no verified prebuild recorded for ${plat} ABI ${abi}`);
if (!got) problems.push(`${node} missing`);
else if (want && got !== want) problems.push(`native module ${got} is not the official ${plat} ABI ${abi} prebuild ${want} (a local build?)`);
if (log && fs.existsSync(log)) {
  // Drop the install script's own command line (`prebuild-install || node-gyp rebuild --release`), which
  // npm echoes; anything else from node-gyp or a compiler means the prebuild was not used.
  const text = fs.readFileSync(log, 'utf8').split('\n').filter((l) => !l.includes('prebuild-install || node-gyp')).join('\n');
  if (/gyp info|gyp ERR!|MSBuild|cc1plus|clang\+\+|g\+\+ /.test(text)) problems.push('the install log shows a node-gyp / compiler run');
}
console.log(JSON.stringify({ platform: plat, node: process.version, abi, better_sqlite3: version, native_sha256: got, expected: want, ok: problems.length === 0, problems }));
process.exitCode = problems.length ? 1 : 0;
