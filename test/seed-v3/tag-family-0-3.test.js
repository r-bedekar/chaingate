// Since 0.1.6: tag family 0.3 for contract 1.3 seeds. A 1.3 seed groups prereleases by the 0.2 family, then "@" and the
// prerelease's platform tokens (a closed list), so a platform build's predecessor is the previous build for the same platform:
// "2.0.0-beta.25" is "beta" and "2.0.0-beta.25-darwin-arm64" is "beta@darwin-arm64". A 1.2 seed keeps 0.2, and the runtime places
// a release by the rule its seed was built with. Ported by hand from the seed side (collector/drift_cooccurrence.py tag_family,
// chaingate-ops main 374c6a5) and pinned by its fixture, copied unchanged. Written before the code.
import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import G from '../../seed/v3/gate.js';
import { PLATFORM_TOKENS, tagFamily } from '../../seed/v3/tag-family.js';

const FILE = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'fixtures', 'rl2', 'lineage-tag-family-cases-0.3.json');
const bytes = fs.readFileSync(FILE);
assert.equal(crypto.createHash('sha256').update(bytes).digest('hex'), '82f551e75df644954b7813dc6fcb804369f67e0c565b3e318ccf31d8971ffe37');
const FIX = JSON.parse(bytes.toString('utf8'));

test('TF1 tagFamily with platforms reproduces every case of lineage-tag-family-cases-0.3; without, the 0.2 family', () => {
  assert.equal(FIX.version, 'lineage-tag-family-cases-0.3');
  assert.deepEqual([...PLATFORM_TOKENS].sort(), [...FIX.platform_tokens].sort());
  assert.equal(PLATFORM_TOKENS.size, 49);
  assert.equal(FIX.cases.length, 56);
  for (const c of FIX.cases) {
    assert.equal(tagFamily(c.version, { platforms: true }), c.family, `${c.version} (${c.note})`);
    assert.equal(tagFamily(c.version), c.family.split('@')[0], `${c.version}: 0.2`);
  }
  assert.equal(tagFamily('2.0.0-beta.25-darwin-arm64', { platforms: true }), 'beta@darwin-arm64');
  assert.equal(tagFamily('1.0.0+linux', { platforms: true }), 'release', 'release never gains a suffix');
});

test('TF2 placement follows the seed\'s rule: under 0.3 a platform build appends to its own platform chain, under 0.2 to the family', () => {
  const rows = [
    { id: 1, lineage_key: '2', tag_family: 'beta', last_version: '2.0.0-beta.24', last_published_s: 100 },
    { id: 2, lineage_key: '2', tag_family: 'beta@darwin-arm64', last_version: '2.0.0-beta.24-darwin-arm64', last_published_s: 100 },
  ];
  const v = '2.0.0-beta.25-darwin-arm64';
  assert.equal(G.placeRl2(rows, v, 200, { platforms: true }).lineage_id, 2);
  assert.equal(G.placeRl2(rows.slice(0, 1), v, 200).lineage_id, 1);
  assert.equal(G.placeRl2(rows, '2.0.0-beta.25', 200, { platforms: true }).lineage_id, 1, 'the shim stays in the family chain');
  const cold = G.placeRl2(rows.slice(0, 1), v, 200, { platforms: true });
  assert.equal(cold.kind, G.PLACEMENTS.NEW_FAMILY_COLD_START);
  assert.match(cold.reason, /beta@darwin-arm64/);
});
