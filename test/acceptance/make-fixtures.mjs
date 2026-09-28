#!/usr/bin/env node
// Builds the disposable fixtures acceptance.mjs uses: three small SYNTHETIC v3 seeds (A; B, which
// differs from A in one metadata value; BAD, whose .sha256 does not match) and three packuments with
// known fresh results (ALLOW / WARN / BLOCK). No real seed and no network are involved.
//   node test/acceptance/make-fixtures.mjs <output-dir>
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';
import Database from 'better-sqlite3';
import { buildSyntheticSeed, syntheticCases } from '../seed-v3/u01-cases.mjs';

const F = path.resolve(process.argv[2] || path.join(path.dirname(fileURLToPath(import.meta.url)), 'fixtures'));
fs.rmSync(F, { recursive: true, force: true });
const sha = (f) => crypto.createHash('sha256').update(fs.readFileSync(f)).digest('hex');
const put = (name, src) => {
  const d = path.join(F, name); fs.mkdirSync(d, { recursive: true });
  const db = path.join(d, 'chaingate-seed.db'); fs.copyFileSync(src, db); return db;
};
const a = buildSyntheticSeed();
const A = put('seed-A', a.dbPath); fs.writeFileSync(`${A}.sha256`, `${sha(A)}\n`);
const B = put('seed-B', a.dbPath);
const db = new Database(B); db.prepare("UPDATE seed_metadata SET value = ? WHERE key = 'corpus_snapshot_digest'").run('e'.repeat(64)); db.close();
fs.writeFileSync(`${B}.sha256`, `${sha(B)}\n`);
const X = put('seed-BAD', a.dbPath); fs.writeFileSync(`${X}.sha256`, `${'0'.repeat(64)}\n`);
fs.rmSync(a.dir, { recursive: true, force: true });
const want = { 'allow-append': ['ALLOW', 0], 'warn-trajectory': ['WARN', 2], 'pin-block-append': ['BLOCK', 3] };
const cases = [];
for (const c of syntheticCases()) {
  if (!want[c.id]) continue;
  const f = `${c.id}.json`; fs.writeFileSync(path.join(F, f), JSON.stringify(c.doc));
  cases.push({ id: c.id, package: c.doc.name, version: c.version, packument: f, effective: want[c.id][0], exit: want[c.id][1] });
}
fs.writeFileSync(path.join(F, 'cases.json'), JSON.stringify({ seedA_sha256: sha(A), seedB_sha256: sha(B), cases }, null, 2));
console.log(`fixtures: ${F}`);
