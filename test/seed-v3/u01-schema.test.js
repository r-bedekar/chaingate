// U-01 A9 — every chaingate.check/1 shape validates against seed/v3/chaingate-check-1.schema.json, every
// finding against the CFT-03 finding schema (byte copy in test/fixtures/cft03, sha256 3ce4f826…), and
// the schema REJECTS invented, null-filled and cross-shape members.
//
// Two validators. ajv 8.17.1 is the approved one (a pinned, test-only devDependency, acquired once
// under an operator-authorized network exception and installed offline into the U-01 worktree's own
// dependency tree). Python jsonschema (draft 2020-12) runs beside it as an independent cross-check.
// The ajv test skips only if ajv is absent, and says so.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';
import R from '../../seed/v3/reader.js';
import { buildCheckRecord, toolErrorRecord, inputFromPackument } from '../../cli/check-record.js';
import { syntheticCases, rc3Cases, buildSyntheticSeed, RC3_DIR } from './u01-cases.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.join(HERE, '..', '..');
const CHECK_SCHEMA = path.join(ROOT, 'seed', 'v3', 'chaingate-check-1.schema.json');
const FINDING_SCHEMA = path.join(ROOT, 'test', 'fixtures', 'cft03', 'finding.schema.json');
const TOOL = { name: 'chaingate', version: '0.1.0' };

function records() {
  const out = [];
  const add = (seed, c, override = null, bundleId = null) => out.push(buildCheckRecord({
    seed, bundleId, policy: c.policy, domainVersionCount: 'from-packument',
    input: inputFromPackument(c.doc, c.doc.name, c.version),
    request: { package: c.doc.name, version: c.version,
      source: { kind: 'packument-file', path: `/tmp/${c.id}.json`, sha256: 'a'.repeat(64) } },
    override, tool: TOOL }));
  const { dir, dbPath } = buildSyntheticSeed();
  const seed = R.openSeed(dbPath, { trust: R.TRUST_UNSIGNED_DEV });
  try {
    const cases = syntheticCases();
    for (const c of cases) add(seed, c, null, 'abcdef0123456789');
    const pinned = cases.find((c) => c.id === 'pin-block-append');
    add(seed, pinned, { reason: 'reviewed fork', created_at: '2026-09-27 10:00:00' });
    add(seed, cases.find((c) => c.id === 'refuse-missing-manifest'), { reason: 'x', created_at: null });
  } finally { seed.close(); fs.rmSync(dir, { recursive: true, force: true }); }
  if (RC3_DIR) {
    const rc3 = R.openSeed(path.join(RC3_DIR, 'chaingate-seed.db'), { trust: R.TRUST_UNSIGNED_DEV });
    try { for (const c of rc3Cases(rc3.db)) add(rc3, c, null, 'bf5b8bf1ec68897e'); } finally { rc3.close(); }
  }
  out.push(toolErrorRecord({ tool: TOOL, request: { package: 'p', version: '1.0.0' }, code: 'no_active_seed', message: 'none' }));
  out.push(toolErrorRecord({ tool: TOOL, request: { package: 'p', version: '1.0.0',
    source: { kind: 'packument-file', path: 'x.json', sha256: 'b'.repeat(64) } }, code: 'packument_invalid_json', message: 'bad' }));
  return out;
}

/** Records the schema must reject, each derived from a valid one by ONE change. */
function invalids(valid) {
  const ev = valid.find((r) => r.result === 'evaluated');
  const rf = valid.find((r) => r.result === 'refused');
  const te = valid.find((r) => r.result === 'tool_error');
  const c = (r) => structuredClone(r);
  const bad = {};
  bad.invented_top_level = { ...c(ev), verdict: 'malicious' };
  bad.null_filled_candidate = { ...c(ev), candidate: null };
  bad.evaluated_without_explanation = (() => { const r = c(ev); delete r.explanation; return r; })();
  bad.refused_with_finding = { ...c(rf), finding: c(ev.finding) };
  bad.refused_with_candidate = { ...c(rf), candidate: c(ev.candidate) };
  bad.refused_null_finding = { ...c(rf), finding: null };
  bad.tool_error_with_seed = { ...c(te), seed: c(ev.seed) };
  bad.tool_error_with_decision = { ...c(te), decision: c(ev.decision) };
  bad.unknown_schema = { ...c(ev), schema: 'chaingate.check/2' };
  bad.unknown_result = { ...c(ev), result: 'maybe' };
  bad.override_blocking = { ...c(ev), effective: { action: 'BLOCK', basis: 'override',
    override: { reason: 'x', created_at: null, scope: 'exact-version' } } };
  bad.override_without_provenance = { ...c(ev), effective: { action: 'ALLOW', basis: 'override' } };
  bad.skip_disposition = (() => { const r = c(ev); r.decision.disposition = 'SKIP'; return r; })();
  bad.action_in_finding = (() => { const r = c(ev); r.finding.disposition = 'BLOCK'; return r; })();
  bad.invented_seed_member = (() => { const r = c(ev); r.seed.signed = false; return r; })();
  bad.source_url = (() => { const r = c(ev); r.request.source = { kind: 'url', path: 'https://x', sha256: 'a'.repeat(64) }; return r; })();
  bad.short_seed_digest = (() => { const r = c(ev); r.seed.sha256 = 'abc'; return r; })();
  return bad;
}

function writeSets() {
  const work = fs.mkdtempSync(path.join(os.tmpdir(), 'u01-schema-'));
  const validDir = path.join(work, 'valid'); const invalidDir = path.join(work, 'invalid');
  fs.mkdirSync(validDir); fs.mkdirSync(invalidDir);
  const valid = records();
  valid.forEach((r, i) => fs.writeFileSync(path.join(validDir, `${String(i).padStart(4, '0')}.json`), JSON.stringify(r)));
  const bad = invalids(valid);
  for (const [k, r] of Object.entries(bad)) fs.writeFileSync(path.join(invalidDir, `${k}.json`), JSON.stringify(r));
  return { work, validDir, invalidDir, valid, bad };
}

const havePyJsonschema = spawnSync('python3', ['-c', 'import jsonschema'], { encoding: 'utf8' }).status === 0;

test('A9 (cross-check: Python jsonschema, draft 2020-12) all shapes valid, findings valid, invalid shapes rejected',
  { skip: havePyJsonschema ? false : 'python3 jsonschema not available', timeout: 600000 }, () => {
    const s = writeSets();
    try {
      const r = spawnSync('python3', [path.join(HERE, 'u01_validate_schema.py'), CHECK_SCHEMA, FINDING_SCHEMA,
        s.validDir, s.invalidDir], { encoding: 'utf8' });
      const summary = JSON.parse(r.stdout.trim().split('\n').at(-1));
      console.log(`schema summary ${JSON.stringify({ ...summary, failures: summary.failures.length })}`);
      assert.deepEqual(summary.failures, []);
      assert.equal(r.status, 0, r.stderr);
      assert.equal(summary.valid_ok, s.valid.length);
      assert.equal(summary.findings_ok, s.valid.filter((x) => x.result === 'evaluated').length);
      assert.equal(summary.invalid_rejected, Object.keys(s.bad).length);
      const kinds = new Set(s.valid.map((x) => x.result));
      assert.deepEqual([...kinds].sort(), ['evaluated', 'refused', 'tool_error']);
      assert.ok(s.valid.some((x) => x.effective?.basis === 'override'));
    } finally { fs.rmSync(s.work, { recursive: true, force: true }); }
  });

let Ajv2020 = null;
try { Ajv2020 = createRequire(import.meta.url)('ajv/dist/2020.js'); } catch { /* not installed */ }

test('A9 (ajv, the approved validator) all shapes valid, findings valid, invalid shapes rejected',
  { skip: Ajv2020 ? false : 'ajv is not installed in this dependency tree (U-01 pins ajv 8.17.1 as a devDependency; run the offline install)',
    timeout: 600000 }, () => {
    const AjvCtor = Ajv2020.default || Ajv2020;
    const version = JSON.parse(fs.readFileSync(createRequire(import.meta.url).resolve('ajv/package.json'), 'utf8')).version;
    assert.equal(version, '8.17.1', 'the pinned ajv is the one executing');
    const findingSchema = JSON.parse(fs.readFileSync(FINDING_SCHEMA, 'utf8'));
    const checkSchema = JSON.parse(fs.readFileSync(CHECK_SCHEMA, 'utf8'));
    // The NEW check schema passes ajv's FULL strict mode (finding referenced through a stub here).
    {
      const full = new AjvCtor({ strict: true });
      full.addSchema({ $schema: 'https://json-schema.org/draft/2020-12/schema', $id: findingSchema.$id, type: 'object' });
      assert.doesNotThrow(() => full.compile(checkSchema), 'chaingate-check-1 passes full strict mode');
    }
    // The FROZEN CFT-03 finding schema trips exactly one strict lint, strictRequired: a `required` inside
    // an if/then branch names a property defined outside that branch. That is valid JSON Schema, and the
    // finding schema is a frozen contract that U-01 must not change, so only that lint is relaxed.
    assert.throws(() => new AjvCtor({ strict: true }).compile(findingSchema), /strictRequired/);
    const ajv = new AjvCtor({ strict: true, strictRequired: false, allErrors: false });
    ajv.addSchema(findingSchema);
    const validate = ajv.compile(checkSchema);
    const validateFinding = ajv.getSchema(findingSchema.$id);
    const valid = records();
    let findings = 0;
    for (const r of valid) {
      assert.ok(validate(r), `${r.request.package}@${r.request.version}: ${JSON.stringify(validate.errors)}`);
      if (r.finding) { assert.ok(validateFinding(r.finding), JSON.stringify(validateFinding.errors)); findings++; }
    }
    const bad = invalids(valid);
    for (const [k, r] of Object.entries(bad)) assert.equal(validate(r), false, `${k} must be rejected`);
    console.log(`ajv summary ${JSON.stringify({ validator: `ajv ${version} (draft 2020-12, strict; strictRequired off for the frozen finding schema only)`, valid_ok: valid.length,
      findings_ok: findings, invalid_rejected: Object.keys(bad).length })}`);
  });

test('A9 the CFT-03 finding schema copy is byte-identical to the frozen producer copy', () => {
  const digest = spawnSync('sha256sum', [FINDING_SCHEMA], { encoding: 'utf8' }).stdout.split(' ')[0];
  assert.equal(digest, '3ce4f8262a8d74def8090bd0aef1339fae07d6a05a3ec7196ca0b5561e8a306f');
});
