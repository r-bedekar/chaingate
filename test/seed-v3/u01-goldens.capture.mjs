#!/usr/bin/env node
// U-01 A1 — capture goldens from the gate AS IT IS. Run ONLY at a tree whose seed/, proxy/ and cli/
// are byte-identical to 306bccde; the script refuses otherwise. Not a test (no *.test.js suffix), so
// the suite never re-captures: re-capturing after a refactor would make the goldens agree with the
// refactor by construction.
//
//   node test/seed-v3/u01-goldens.capture.mjs                      # synthetic cases
//   CFT04_CANDIDATE=<rc3 dir> node test/seed-v3/u01-goldens.capture.mjs --rc3
import fs from 'node:fs';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import R from '../../seed/v3/reader.js';
import G from '../../seed/v3/gate.js';
import {
  syntheticCases, rc3Cases, buildSyntheticSeed, inputFromPackument, canonical, sha256, RC3_DIR,
} from './u01-cases.mjs';

const FROZEN = '306bccdef845a5d6b072d7ed55a023b4bb8ae85e';
const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.join(HERE, '..', '..');
const OUT = path.join(ROOT, 'test', 'fixtures', 'u01-goldens');

const git = (...a) => execFileSync('git', a, { cwd: ROOT, encoding: 'utf8' }).trim();
const drift = git('diff', '--name-only', FROZEN, '--', 'seed', 'proxy', 'cli', 'gates', 'witness',
  'config-store.js', 'constants.js');
const dirty = git('status', '--porcelain', '--', 'seed', 'proxy', 'cli', 'gates', 'witness');
if (drift || dirty) {
  console.error(`refusing to capture: runtime sources differ from ${FROZEN}:\n${drift}\n${dirty}`);
  process.exit(4);
}

function runCase(seed, c) {
  const decisions = [];
  const gate = G.createSeedV3Gate({ seed, config: c.policy, domainVersionCount: 'from-packument',
    onDecision: (d) => decisions.push(d) });
  const input = inputFromPackument(c.doc, c.version);
  let gateResult = null; let threw = null;
  try { gateResult = gate.evaluate(input); } catch (e) { threw = `${e.name}: ${e.message}`; }
  return {
    id: c.id, seed: c.seed, policy: c.policy, note: c.note,
    request: { package: c.doc.name, version: c.version, document_sha256: sha256(canonical(c.doc)) },
    gate_result: gateResult, threw, decision: decisions.length === 1 ? decisions[0] : null,
    n_decisions: decisions.length,
  };
}

function write(name, records, extra) {
  fs.mkdirSync(OUT, { recursive: true });
  const body = `${JSON.stringify({ captured_from: FROZEN, tree: git('rev-parse', 'HEAD^{tree}'),
    head: git('rev-parse', 'HEAD'), ...extra, n: records.length, records }, null, 1)}\n`;
  const file = path.join(OUT, name);
  fs.writeFileSync(file, body);
  console.log(`${name}: ${records.length} records, sha256 ${sha256(body)}`);
}

if (process.argv.includes('--rc3')) {
  if (!RC3_DIR) { console.error('set CFT04_CANDIDATE'); process.exit(4); }
  const seed = R.openSeed(path.join(RC3_DIR, 'chaingate-seed.db'), { trust: R.TRUST_UNSIGNED_DEV });
  try {
    const records = rc3Cases(seed.db).map((c) => runCase(seed, c));
    write('rc3.json', records, { seed_sha256: seed.report.content_sha256,
      seed_meta: seed.meta, candidate_dir_basename: path.basename(RC3_DIR) });
  } finally { seed.close(); }
} else {
  const { dir, dbPath } = buildSyntheticSeed();
  const seed = R.openSeed(dbPath, { trust: R.TRUST_UNSIGNED_DEV });
  try {
    const records = syntheticCases().map((c) => runCase(seed, c));
    write('synthetic.json', records, { seed_sha256: fs.readFileSync(`${dbPath}.sha256`, 'utf8').split(/\s/)[0] });
  } finally { seed.close(); fs.rmSync(dir, { recursive: true, force: true }); }
}
