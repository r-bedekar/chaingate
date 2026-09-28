// CFT-06 (first half) — JS↔fixture parity over the exact rc3-bound pack.
//
// The JS evaluator computes every finding ITSELF from the seed. It never calls Python and never reads
// an expected answer before producing its own. Acceptance runs BEFORE any comparison: a harness that
// trusts an advertised digest can pass an empty file.
import { pathToFileURL } from 'node:url';

import fs from 'node:fs';
import path from 'node:path';
import readline from 'node:readline';
import R from './reader.js';
import L from './logical.js';

const tri = (d) => [d?.value ?? null, d?.coverage ?? null, d?.reason ?? null];
const aggOf = (x) => ({
  M: x.M, n_broke: x.n_broke, n_evaluable: x.n_evaluable, n_unevaluable: x.n_unevaluable,
  thresholds: x.thresholds.map((t) => [t.name, t.threshold, t.threshold_result, t.threshold_determinacy,
    [...t.interval]]),
});
const mapTri = (o) => Object.fromEntries(Object.keys(o).sort().map((k) => [k, tri(o[k])]));

/** Key order is not semantic. The fixtures were serialised with sorted keys and this evaluator builds
 *  objects in declaration order, so a raw JSON.stringify comparison reports every record as differing
 *  while the structural diff finds nothing — which is how this was caught. Compare stably. */
function stable(v) {
  if (Array.isArray(v)) return v.map(stable);
  if (v !== null && typeof v === 'object') {
    return Object.fromEntries(Object.keys(v).sort().map((k) => [k, stable(v[k])]));
  }
  return v;
}
const eq = (a, b) => JSON.stringify(stable(a)) === JSON.stringify(stable(b));

/** The compared projection. Per-Tri `evidence` is diagnostic and declared out of comparison. */
function canonical(f) {
  const ca = f.channel_a; const dac = f.dac_trajectory; const cand = f.candidate || {};
  return {
    identity: { candidate_digest: cand.candidate_digest ?? null, provider_class: cand.provider_class ?? null },
    channel_a: {
      predecessor_version: ca.predecessor_version ?? null,
      groups: mapTri(ca.groups),
      publisher_constituents: mapTri(ca.publisher_constituents || {}),
      install_body: ca.install_body ?? null,
      ...aggOf(ca),
    },
    dac_trajectory: { predicates: mapTri(dac.predicates), ...aggOf(dac) },
  };
}

function diff(pathStr, exp, got, out) {
  const isObj = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);
  if (isObj(exp) && isObj(got)) {
    for (const k of [...new Set([...Object.keys(exp), ...Object.keys(got)])].sort()) {
      if (!(k in got)) out.push({ kind: 'missing', path: `${pathStr}.${k}`, expected: exp[k] });
      else if (!(k in exp)) out.push({ kind: 'extra', path: `${pathStr}.${k}`, got: got[k] });
      else diff(`${pathStr}.${k}`, exp[k], got[k], out);
    }
  } else if (!eq(exp, got)) {
    out.push({ kind: 'differing', path: pathStr, expected: exp, got });
  }
}

function acceptance(fixturesDir, seed) {
  const checks = {};
  // The identities this run ESTABLISHES, for anything downstream that must be bound to the same
  // artifacts (the composed vectors are). Recomputed/re-derived here, never read from a manifest.
  const verified = { seed_logical_digest: null, fixtures_digest: null, established: {} };
  const mPath = path.join(fixturesDir, 'manifest.json');
  const fPath = path.join(fixturesDir, 'fixtures.jsonl');
  if (!fs.existsSync(mPath) || !fs.existsSync(fPath)) {
    checks.artifacts_present = `missing ${!fs.existsSync(mPath) ? 'manifest.json' : 'fixtures.jsonl'}`;
    return { checks, man: null, verified };
  }
  checks.artifacts_present = true;
  const man = JSON.parse(fs.readFileSync(mPath, 'utf8'));
  const actual = R.sha256File(fPath);
  verified.fixtures_digest = actual;
  verified.established.fixtures_digest = 'recomputed from fixtures.jsonl';
  checks.fixtures_digest_recomputed = actual === man.fixtures_digest ? true
    : `recomputed ${actual} != manifest ${man.fixtures_digest}`;
  checks.oracle_defect_count_zero = man.oracle_defect_count === 0 ? true
    : `oracle_defect_count=${man.oracle_defect_count}`;
  checks.contract_version = man.contract_version === R.IMPLEMENTED_DETECTION_CONTRACT ? true
    : `manifest ${man.contract_version} != ${R.IMPLEMENTED_DETECTION_CONTRACT}`;
  checks['seed_binding.corpus_snapshot_digest'] = man.corpus_snapshot_digest
    && man.corpus_snapshot_digest === seed.meta.corpus_snapshot_digest ? true
    : `manifest ${man.corpus_snapshot_digest} != seed ${seed.meta.corpus_snapshot_digest}`;
  checks['seed_binding.rule_versions'] = JSON.stringify(man.rule_versions) === JSON.stringify(seed.meta.rule_versions)
    ? true : `manifest ${JSON.stringify(man.rule_versions)} != seed ${JSON.stringify(seed.meta.rule_versions)}`;
  // EXACT binding. corpus_snapshot_digest and rule_versions are shared by every build of the same
  // snapshot under the same rules, so on their own they let a pack generated against a DIFFERENT seed
  // pass. The manifest's seed_logical_digest is the exact identity, and it is RE-DERIVED from the file
  // rather than read from the manifest that claims it — a seed cannot self-report this digest, because
  // it covers seed_metadata.
  try {
    const rederived = L.logicalDigestOfDb(seed.db);
    verified.seed_logical_digest = rederived;
    verified.established.seed_logical_digest = 're-derived from the seed file';
    checks.seed_logical_digest_rederived = rederived === man.seed_logical_digest ? true
      : `re-derived ${rederived} != manifest ${man.seed_logical_digest}`;
  } catch (e) {
    verified.established.seed_logical_digest = `could not re-derive: ${e.name}: ${e.message}`;
    checks.seed_logical_digest_rederived = `could not re-derive: ${e.name}: ${e.message}`;
  }
  return { checks, man, verified };
}

async function run(fixturesDir, seedPath, { trust = R.TRUST_UNSIGNED_DEV, maxItems = 50, progress = null } = {}) {
  const seed = R.openSeed(seedPath, { trust });
  try {
    const { checks, man, verified } = acceptance(fixturesDir, seed);
    if (!man || Object.values(checks).some((v) => v !== true)) {
      return { status: 'FAIL', failure: 'acceptance', acceptance: checks, verified, candidates: 0,
        agreeing: 0, disagreeing: 0, items: [] };
    }
    const seen = new Set();
    let n = 0; let agree = 0; let duplicates = 0;
    const problems = [];
    const rl = readline.createInterface({
      input: fs.createReadStream(path.join(fixturesDir, 'fixtures.jsonl')), crlfDelay: Infinity });
    for await (const line of rl) {
      if (!line) continue;
      const rec = JSON.parse(line);
      n += 1;
      const key = JSON.stringify([rec.package, rec.lineage_id, rec.ord]);
      if (seen.has(key)) {
        duplicates += 1;
        if (problems.length < maxItems) problems.push({ kind: 'duplicate', path: '.membership', package: rec.package });
      }
      seen.add(key);
      const cand = R.candidateFromMapping({ ...rec.candidate_fields, package_name: rec.package });
      const got = canonical(seed.check(cand));
      const exp = canonical({ candidate: rec.expected?.candidate || {}, channel_a: rec.expected.channel_a,
        dac_trajectory: rec.expected.dac_trajectory });
      if (eq(exp, got)) agree += 1;
      else {
        const items = []; diff('', exp, got, items);
        for (const it of items) {
          if (problems.length < maxItems) {
            problems.push({ package: rec.package, version: rec.candidate_fields.version, ord: rec.ord, ...it });
          }
        }
      }
      if (progress && n % 20000 === 0) progress(n, agree);
    }
    checks.record_count_matches_manifest = n === man.candidates ? true : `${n} records != manifest ${man.candidates}`;
    checks.membership_unique = duplicates === 0 ? true : `${duplicates} duplicate keys`;
    checks.membership_count_matches = seen.size === man.candidates ? true
      : `${seen.size} distinct != manifest ${man.candidates}`;
    const kinds = {};
    for (const p of problems) kinds[p.kind] = (kinds[p.kind] || 0) + 1;
    const ok = agree === n && n > 0 && Object.values(checks).every((v) => v === true);
    return { status: ok ? 'PASS' : 'FAIL', candidates: n, agreeing: agree, disagreeing: n - agree,
      itemised_kinds: kinds, items: problems, acceptance: checks, verified,
      fixtures_digest: man.fixtures_digest, slice_digest: man.slice_digest,
      canonical_form: 'decision-bearing projection incl. install_body and identity; per-Tri evidence is diagnostic and out of comparison' };
  } finally { seed.close(); }
}

export { canonical, diff, acceptance, run, stable, eq };


// A default export as well: the consumer is used both as `import R from` and
// `import { verify } from`, and the runtime package is ESM.
export default { canonical, diff, acceptance, run, stable, eq
};
// process.argv[1] is undefined under `node -e`, where pathToFileURL would throw — so importing
// this module for its exports must not depend on there being a script path.
const __isMain = Boolean(process.argv[1]) && import.meta.url === pathToFileURL(process.argv[1]).href;
if (__isMain) {
  const [fixturesDir, seedPath] = process.argv.slice(2);
  if (!fixturesDir || !seedPath) { console.error('usage: node parity.js <fixtures-dir> <seed.db>'); process.exit(2); }
  const t0 = Date.now();
  run(fixturesDir, seedPath, {
    progress: (n, a) => console.log(`  ... ${n.toLocaleString()} compared, ${a.toLocaleString()} agreeing  ${((Date.now() - t0) / 1000).toFixed(0)}s`),
  })
    .then((r) => {
      console.log(JSON.stringify({ ...r, items: r.items.slice(0, 8) }, null, 2));
      console.log(`[js-parity] ${r.status} ${r.agreeing.toLocaleString()}/${r.candidates.toLocaleString()} in ${((Date.now() - t0) / 1000).toFixed(0)}s`);
      process.exit(r.status === 'PASS' ? 0 : 3);
    })
    .catch((e) => { console.error(e); process.exit(1); });
}
