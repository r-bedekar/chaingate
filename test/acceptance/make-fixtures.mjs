#!/usr/bin/env node
// Builds the disposable fixtures acceptance.mjs uses: three small SYNTHETIC v3 seeds (A; B, which
// differs from A in one metadata value; BAD, whose .sha256 does not match) and three packuments with
// known fresh results (ALLOW / WARN / BLOCK). No real seed and no network are involved.
//   node test/acceptance/make-fixtures.mjs <output-dir>
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { spawnSync } from 'node:child_process';
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

// U-05 S6 (option M): the intended distribution shape -- one .tar.gz holding the database, its .sha256 file and its
// manifest, as the verified rc3 transfer archive does. seed-A.tar.gz is the genuine archive. seed-SUBST.tar.gz is a
// SUBSTITUTED one: self-consistent (its .sha256 matches its database, which is seed B) but not the trusted database.
const archive = (name, db) => {
  const d = path.join(F, `archive-${name}`); fs.mkdirSync(d, { recursive: true });
  fs.copyFileSync(db, path.join(d, 'chaingate-seed.db'));
  fs.copyFileSync(`${db}.sha256`, path.join(d, 'chaingate-seed.db.sha256'));
  fs.writeFileSync(path.join(d, 'chaingate-seed.db.manifest.json'), `${JSON.stringify({ fixture: `synthetic seed ${name}` })}\n`);
  const out = path.join(F, `seed-${name}.tar.gz`);
  const r = spawnSync('tar', ['-czf', out, '-C', d, 'chaingate-seed.db', 'chaingate-seed.db.sha256', 'chaingate-seed.db.manifest.json'],
    { encoding: 'utf8' });
  if (r.status !== 0) throw new Error(`tar could not build ${out}: ${r.stderr || r.error}`);
  fs.rmSync(d, { recursive: true, force: true });
  return out;
};
const archiveA = archive('A', A);
archive('SUBST', B);
const want = { 'allow-append': ['ALLOW', 0], 'warn-trajectory': ['WARN', 2], 'pin-block-append': ['BLOCK', 3] };
const cases = [];
for (const c of syntheticCases()) {
  if (!want[c.id]) continue;
  const f = `${c.id}.json`; fs.writeFileSync(path.join(F, f), JSON.stringify(c.doc));
  cases.push({ id: c.id, package: c.doc.name, version: c.version, packument: f, effective: want[c.id][0], exit: want[c.id][1] });
}
fs.writeFileSync(path.join(F, 'cases.json'), JSON.stringify({ seedA_sha256: sha(A), seedB_sha256: sha(B),
  archives: { A: 'seed-A.tar.gz', SUBST: 'seed-SUBST.tar.gz' }, archiveA_sha256: sha(archiveA), cases }, null, 2));
console.log(`fixtures: ${F}`);
