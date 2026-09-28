#!/usr/bin/env node
// U-01 A7 — record explanation goldens for the named cases. The explanation module is NEW in U-01,
// so these lock its bytes for review and regression; they are not frozen-implementation goldens.
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import R from '../../seed/v3/reader.js';
import { buildCheckRecord, inputFromPackument } from '../../cli/check-record.js';
import { syntheticCases, buildSyntheticSeed } from './u01-cases.mjs';

export const EXPLAIN_GOLDEN_IDS = ['publisher-broke-beside-unevaluated', 'uncovered', 'cold-start-new-major',
  'refuse-malformed-npmuser', 'refuse-missing-manifest', 'notime-pin-block-ineligible', 'warn-trajectory',
  'recorded-deep-beyond-spine', 'allow-append'];

export function explainRecords() {
  const { dir, dbPath } = buildSyntheticSeed();
  const seed = R.openSeed(dbPath, { trust: R.TRUST_UNSIGNED_DEV });
  try {
    const cases = new Map(syntheticCases().map((c) => [c.id, c]));
    return EXPLAIN_GOLDEN_IDS.map((id) => {
      const c = cases.get(id);
      return buildCheckRecord({ seed, policy: c.policy, domainVersionCount: 'from-packument',
        input: inputFromPackument(c.doc, c.doc.name, c.version),
        request: { package: c.doc.name, version: c.version }, tool: { name: 'chaingate', version: 'golden' } });
    });
  } finally { seed.close(); fs.rmSync(dir, { recursive: true, force: true }); }
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const out = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'fixtures', 'u01-goldens', 'explain.json');
  const recs = explainRecords();
  fs.writeFileSync(out, `${JSON.stringify(recs.map((r, i) => ({ id: EXPLAIN_GOLDEN_IDS[i], explanation: r.explanation })), null, 1)}\n`);
  console.log(`explain.json: ${recs.length} records`);
}
