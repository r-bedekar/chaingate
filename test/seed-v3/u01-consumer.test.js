// U-01 A10/A11 — the offline CI consumer, fed by the real `chaingate check` CLI. Every process runs
// under the network guard and the attempt log is asserted empty at the end.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { stageBundle, activateBundle } from '../../cli/seed-bundle.js';
import { writeConfig } from '../../config-store.js';
import { openWitnessDB } from '../../witness/db.js';
import { syntheticCases, buildSyntheticSeed, PROXY_POLICY } from './u01-cases.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.join(HERE, '..', '..');
const CLI = path.join(ROOT, 'cli', 'index.js');
const CONSUMER = path.join(ROOT, 'examples', 'ci', 'chaingate-ci.mjs');
const GUARD = path.join(ROOT, 'test', 'helpers', 'deny-network.mjs');
const CASES = new Map(syntheticCases().map((c) => [c.id, c]));

const WORK = fs.mkdtempSync(path.join(os.tmpdir(), 'u01-ci-'));
const NET_LOG = path.join(WORK, 'network-attempts.log');
test.after(() => fs.rmSync(WORK, { recursive: true, force: true }));
const env = (home) => ({ PATH: process.env.PATH, HOME: home, NO_COLOR: '1', U01_NET_LOG: NET_LOG });

// one host, one override on p@1.3.0 (a pinned BLOCK)
const HOME = path.join(WORK, 'home');
const BASE = path.join(HOME, '.chaingate');
fs.mkdirSync(BASE, { recursive: true });
{
  const { dir, dbPath } = buildSyntheticSeed();
  activateBundle(BASE, stageBundle({ dbPath, sha256Path: `${dbPath}.sha256` }, BASE, { trust: 'unsigned-development' }).dir_name);
  fs.rmSync(dir, { recursive: true, force: true });
  writeConfig(path.join(BASE, 'config.json'), { policy: PROXY_POLICY });
  const w = openWitnessDB(path.join(BASE, 'witness.db')).applySchema();
  w.insertOverride('p', '1.3.0', 'reviewed fork'); w.close();
}

/** Run the real check CLI for a case and return its JSON text. */
function checkOut(id) {
  const c = CASES.get(id);
  const doc = path.join(WORK, `doc-${id}.json`);
  fs.writeFileSync(doc, JSON.stringify(c.doc));
  const r = spawnSync(process.execPath, ['--import', GUARD, CLI, 'check', `${c.doc.name}@${c.version}`, '--packument', doc, '--json'],
    { env: env(HOME), encoding: 'utf8' });
  assert.ok([0, 2, 3].includes(r.status), `${id}: check exit ${r.status} ${r.stderr}`);
  return r.stdout;
}
const OUT = {};
for (const id of ['allow-append', 'notime-recorded-unpinned', 'warn-trajectory', 'pin-block-append',
  'notime-pin-block-ineligible', 'refuse-malformed-npmuser']) OUT[id] = checkOut(id);
const toolErr = spawnSync(process.execPath, ['--import', GUARD, CLI, 'check', 'p@1.5.0', '--packument', path.join(WORK, 'absent.json'), '--json'],
  { env: env(HOME), encoding: 'utf8' });
OUT['tool-error'] = toolErr.stdout;
const SEED = JSON.parse(OUT['allow-append']).seed.sha256;
const pairOf = (id) => (id === 'tool-error' ? 'p@1.5.0' : `${CASES.get(id).doc.name}@${CASES.get(id).version}`);

let n = 0;
/** Lay out a results dir and a manifest, run the consumer, return {status, stdout, summary}. */
function consume({ ids = [], expected = null, extraFiles = {}, args = [], trusted = [SEED] }) {
  const dir = path.join(WORK, `run-${++n}`);
  const results = path.join(dir, 'results');
  fs.mkdirSync(results, { recursive: true });
  for (const id of ids) fs.writeFileSync(path.join(results, `${id}.json`), OUT[id]);
  for (const [name, body] of Object.entries(extraFiles)) fs.writeFileSync(path.join(results, name), body);
  const manifest = path.join(dir, 'expected.txt');
  fs.writeFileSync(manifest, `# expected\n${(expected ?? ids.map(pairOf)).join('\n')}\n`);
  const summaryFile = path.join(dir, 'summary.json');
  const r = spawnSync(process.execPath, ['--import', GUARD, CONSUMER, '--expected', manifest, '--results', results,
    ...trusted.flatMap((t) => ['--trusted-seed', t]), '--summary', summaryFile, ...args],
  { env: { PATH: process.env.PATH, U01_NET_LOG: NET_LOG }, encoding: 'utf8' });
  const summary = fs.existsSync(summaryFile) ? JSON.parse(fs.readFileSync(summaryFile, 'utf8')) : null;
  return { status: r.status, stdout: r.stdout, stderr: r.stderr, summary };
}
const mutate = (id, f) => { const r = JSON.parse(OUT[id]); f(r); return JSON.stringify(r); };

test('A11 pass on all-ALLOW', () => {
  const r = consume({ ids: ['allow-append', 'notime-recorded-unpinned'] });
  assert.equal(r.status, 0, r.stdout);
  assert.equal(r.summary.passed, true);
  assert.match(r.stdout, /chaingate-ci: PASS \(2 result\(s\), 0 warning\(s\)\)/);
});

test('A11 a WARN passes and is annotated with its explanation', () => {
  const r = consume({ ids: ['allow-append', 'warn-trajectory'] });
  assert.equal(r.status, 0);
  assert.match(r.stdout, /::warning title=chaingate WARN p@1\.6\.0::.*decided by:/);
  assert.match(r.stdout, /install_introduced: BROKE/);
  assert.equal(r.summary.warnings.length, 1);
});

test('A11 fail on BLOCK, on refused, on tool_error', () => {
  const block = consume({ ids: ['allow-append', 'notime-pin-block-ineligible'] });
  assert.equal(block.status, 1);
  assert.ok(block.summary.failures.some((m) => /p@1\.4\.0: BLOCK/.test(m)));
  const refused = consume({ ids: ['refuse-malformed-npmuser'] });
  assert.equal(refused.status, 1);
  assert.ok(refused.summary.failures.some((m) => /REFUSED/.test(m)));
  const te = consume({ ids: ['tool-error'] });
  assert.equal(te.status, 1);
  assert.ok(te.summary.failures.some((m) => /tool error packument_unreadable/.test(m)));
});

test('A10 consumer: an overridden BLOCK passes by default and fails with --ignore-overrides', () => {
  const rec = JSON.parse(OUT['pin-block-append']);
  assert.equal(rec.decision.disposition, 'BLOCK');
  assert.equal(rec.effective.basis, 'override');
  const byDefault = consume({ ids: ['pin-block-append'] });
  assert.equal(byDefault.status, 0, byDefault.stdout);
  assert.match(byDefault.stdout, /PASS \(override\)\s+p@1\.3\.0/);
  const strict = consume({ ids: ['pin-block-append'], args: ['--ignore-overrides'] });
  assert.equal(strict.status, 1);
  assert.ok(strict.summary.failures.some((m) => /p@1\.3\.0: BLOCK \(override ignored\)/.test(m)));
});

test('A11 set completeness: missing, empty set, empty manifest, duplicate, unexpected, wrong version', () => {
  const missing = consume({ ids: ['allow-append'], expected: ['p@1.5.0', 'p@1.2.0'] });
  assert.equal(missing.status, 1);
  assert.ok(missing.summary.failures.includes('p@1.2.0: no result'));

  const empty = consume({ ids: [], expected: ['p@1.5.0'] });
  assert.equal(empty.status, 1);
  assert.ok(empty.summary.failures.some((m) => /no \*\.json results/.test(m)));

  const noManifest = consume({ ids: ['allow-append'], expected: [] });
  assert.equal(noManifest.status, 1);
  assert.ok(noManifest.summary.failures.some((m) => /lists no expected/.test(m)));

  const dup = consume({ ids: ['allow-append'], extraFiles: { 'copy.json': OUT['allow-append'] } });
  assert.equal(dup.status, 1);
  assert.ok(dup.summary.failures.some((m) => /p@1\.5\.0: 2 results/.test(m)));

  const unexpected = consume({ ids: ['allow-append', 'warn-trajectory'], expected: ['p@1.5.0'] });
  assert.equal(unexpected.status, 1);
  assert.ok(unexpected.summary.failures.some((m) => /p@1\.6\.0 is not an expected pair/.test(m)));

  const wrong = consume({ extraFiles: { 'x.json': mutate('allow-append', (r) => { r.request.version = '1.5.1'; }) }, expected: ['p@1.5.0'] });
  assert.equal(wrong.status, 1);
  assert.ok(wrong.summary.failures.some((m) => /p@1\.5\.1 is not an expected pair/.test(m)));
  assert.ok(wrong.summary.failures.includes('p@1.5.0: no result'));
});

test('A11 validation: unknown schema, missing seed.sha256, untrusted seed, truncated, malformed, extra member, inconsistent effective', () => {
  const cases = {
    'unknown schema': [mutate('allow-append', (r) => { r.schema = 'chaingate.check/2'; }), /schema is "chaingate\.check\/2"/],
    'missing seed.sha256': [mutate('allow-append', (r) => { delete r.seed.sha256; }), /seed\.sha256 is missing/],
    truncated: [OUT['allow-append'].slice(0, 200), /unparseable or truncated/],
    malformed: ['{"schema": "chaingate.check/1",,}', /unparseable or truncated/],
    'extra member': [mutate('allow-append', (r) => { r.verdict = 'clean'; }), /member verdict is not allowed/],
    'refused with finding': [mutate('refuse-malformed-npmuser', (r) => { r.finding = {}; }), /member finding is not allowed for result refused/],
    'inconsistent effective': [mutate('warn-trajectory', (r) => { r.effective.action = 'ALLOW'; }), /disagrees with decision\.disposition WARN/],
    'override that blocks': [mutate('pin-block-append', (r) => { r.effective.action = 'BLOCK'; }), /an override can only make the effective action ALLOW/],
    'unknown result': [mutate('allow-append', (r) => { r.result = 'maybe'; }), /result is "maybe"/],
  };
  for (const [name, [body, re]] of Object.entries(cases)) {
    const pair = { 'inconsistent effective': 'p@1.6.0', 'override that blocks': 'p@1.3.0' }[name] ?? 'p@1.5.0';
    const r = consume({ extraFiles: { 'r.json': body }, expected: [pair] });
    assert.equal(r.status, 1, `${name}: must fail`);
    assert.ok(r.summary.failures.some((m) => re.test(m)), `${name}: ${JSON.stringify(r.summary.failures)}`);
  }
  const untrusted = consume({ ids: ['allow-append'], trusted: ['0'.repeat(64)] });
  assert.equal(untrusted.status, 1);
  assert.ok(untrusted.summary.failures.some((m) => /is not in the trusted-seed list/.test(m)));
});

test('A11 usage errors exit 2', () => {
  const r = spawnSync(process.execPath, [CONSUMER, '--results', WORK], { encoding: 'utf8' });
  assert.equal(r.status, 2);
  const bad = spawnSync(process.execPath, [CONSUMER, '--expected', 'x', '--results', WORK, '--trusted-seed', 'ABC'], { encoding: 'utf8' });
  assert.equal(bad.status, 2);
});

test('A11 networking disabled: no process in this file reached the network guard', () => {
  const attempts = fs.existsSync(NET_LOG) ? fs.readFileSync(NET_LOG, 'utf8') : '';
  assert.equal(attempts, '', attempts);
});

test('A11 the consumer imports only node: built-ins', () => {
  const src = fs.readFileSync(CONSUMER, 'utf8');
  const imports = [...src.matchAll(/^import .* from '([^']+)';$/gm)].map((m) => m[1]);
  assert.ok(imports.length > 0);
  assert.ok(imports.every((m) => m.startsWith('node:')), imports.join(', '));
});

// --- A11 structural validation, member by member (operator review 2026-09-27) -----------------------
import { validateRecord } from '../../examples/ci/chaingate-ci.mjs';
import R from '../../seed/v3/reader.js';
import { buildCheckRecord, toolErrorRecord, inputFromPackument } from '../../cli/check-record.js';

function everyRecordShape() {
  const out = [];
  const { dir, dbPath } = buildSyntheticSeed();
  const seed = R.openSeed(dbPath, { trust: R.TRUST_UNSIGNED_DEV });
  try {
    for (const c of syntheticCases()) {
      for (const override of [null, { reason: 'reviewed', created_at: '2026-09-27 10:00:00' }]) {
        out.push(buildCheckRecord({ seed, bundleId: 'abcdef0123456789', policy: c.policy, domainVersionCount: 'from-packument',
          input: inputFromPackument(c.doc, c.doc.name, c.version), override, tool: { name: 'chaingate', version: '0.1.0' },
          request: { package: c.doc.name, version: c.version, source: { kind: 'packument-file', path: 'x.json', sha256: 'a'.repeat(64) } } }));
      }
    }
  } finally { seed.close(); fs.rmSync(dir, { recursive: true, force: true }); }
  out.push(toolErrorRecord({ tool: { name: 'chaingate', version: '0.1.0' }, request: { package: 'p', version: '1' }, code: 'no_active_seed', message: 'm' }));
  return out;
}
const ALL = everyRecordShape();
const EV = JSON.parse(OUT['allow-append']);             // a real ALLOW record from the CLI
const RF = JSON.parse(OUT['refuse-malformed-npmuser']);
const TE = JSON.parse(OUT['tool-error']);

test('A11 validator accepts every record check can produce (all cases, with and without override)', () => {
  assert.ok(ALL.length > 50);
  for (const r of [...ALL, EV, RF, TE, JSON.parse(OUT['pin-block-append'])]) {
    assert.deepEqual(validateRecord(r), [], `${r.request.package}@${r.request.version} ${r.result}`);
  }
});

test('A11 validator: the three operator-reproduced cases are rejected', () => {
  const m = (f) => { const r = structuredClone(EV); f(r); return validateRecord(r); };
  const a = m((r) => { r.candidate.placement = { kind: 'append' }; });
  for (const k of ['reason', 'lineage_id', 'ord', 'channel_a_usable']) assert.ok(a.includes(`candidate.placement.${k} is missing`), k);
  assert.ok(m((r) => { r.candidate.placement.kind = 'made-up-placement'; }).some((x) => /candidate\.placement\.kind must be one of/.test(x)));
  assert.ok(m((r) => { r.decision.policy_config_sha256 = [r.decision.policy_config_sha256]; })
    .some((x) => /decision\.policy_config_sha256 must be a lowercase sha256 string/.test(x)));
});

test('A11 validator: every single-change mutation of a defined member is rejected', () => {
  const cases = [
    [EV, (r) => { r.tool.version = 1; }, /tool\.version/], [EV, (r) => { delete r.tool.name; }, /tool\.name is missing/],
    [EV, (r) => { r.tool.extra = 'x'; }, /tool\.extra is not an allowed member/],
    [EV, (r) => { r.request.package = ''; }, /request\.package/], [EV, (r) => { r.request.x = 1; }, /request\.x is not an allowed/],
    [EV, (r) => { r.request.source.sha256 = [r.request.source.sha256]; }, /request\.source\.sha256/],
    [EV, (r) => { r.request.source.kind = 'url'; }, /request\.source\.kind/], [EV, (r) => { delete r.request.source.path; }, /request\.source\.path is missing/],
    [EV, (r) => { r.seed.sha256 = [r.seed.sha256]; }, /seed\.sha256/], [EV, (r) => { r.seed.sha256 = r.seed.sha256.toUpperCase(); }, /seed\.sha256/],
    [EV, (r) => { r.seed.trust = 'trusted'; }, /seed\.trust/], [EV, (r) => { r.seed.authenticated = 'false'; }, /seed\.authenticated/],
    [EV, (r) => { r.seed.bundle_id = 7; }, /seed\.bundle_id/], [EV, (r) => { r.seed.rule_versions = { channel_a: 1 }; }, /seed\.rule_versions/],
    [EV, (r) => { r.seed.corpus_snapshot_digest = null; }, /seed\.corpus_snapshot_digest/], [EV, (r) => { r.seed.signed = true; }, /seed\.signed is not an allowed/],
    [EV, (r) => { delete r.seed.contract_version; }, /seed\.contract_version is missing/],
    [EV, (r) => { r.candidate.candidate_digest = 'abc'; }, /candidate\.candidate_digest/], [EV, (r) => { r.candidate.x = 1; }, /candidate\.x is not an allowed/],
    [EV, (r) => { r.candidate.placement.lineage_id = '1'; }, /candidate\.placement\.lineage_id/],
    [EV, (r) => { r.candidate.placement.ord = -1; }, /candidate\.placement\.ord/],
    [EV, (r) => { r.candidate.placement.channel_a_usable = 1; }, /candidate\.placement\.channel_a_usable/],
    [EV, (r) => { r.candidate.placement.reason = 5; }, /candidate\.placement\.reason/],
    [EV, (r) => { r.decision.policy_version = ''; }, /decision\.policy_version/],
    [EV, (r) => { r.decision.disposition = 'SKIP'; }, /decision\.disposition/], [EV, (r) => { r.decision.results = []; }, /decision\.results/],
    [EV, (r) => { r.decision.results[0].result = 'MAYBE'; }, /decision\.results\[0\]\.result/],
    [EV, (r) => { delete r.decision.results[0].detail; }, /decision\.results\[0\]\.detail is missing/],
    [EV, (r) => { r.decision.results[0].x = 1; }, /decision\.results\[0\]\.x is not an allowed/],
    [EV, (r) => { r.decision.evidence_complete = 'yes'; }, /decision\.evidence_complete/],
    [EV, (r) => { r.decision.not_evaluated = [{ where: 'a', name: 'b' }]; }, /decision\.not_evaluated\[0\]\.reason is missing/],
    [EV, (r) => { r.decision.not_evaluated = [{ where: 'a', name: 'b', reason: null, stated_by: 'x' }]; }, /stated_by/],
    [EV, (r) => { r.decision.extra = 1; }, /decision\.extra is not an allowed/],
    [EV, (r) => { r.effective.basis = 'magic'; }, /effective\.basis/], [EV, (r) => { r.effective.action = 'SKIP'; }, /effective\.action/],
    [EV, (r) => { r.effective = { action: 'ALLOW', basis: 'override' }; }, /effective\.override is missing/],
    [EV, (r) => { r.effective = { action: 'ALLOW', basis: 'override', override: { reason: 'x', created_at: null, scope: 'package' } }; }, /effective\.override\.scope/],
    [EV, (r) => { r.explanation.text = 'x'; }, /explanation\.text/], [EV, (r) => { r.explanation.structured = []; }, /explanation\.structured/],
    [EV, (r) => { r.explanation.more = 1; }, /explanation\.more is not an allowed/],
    [EV, (r) => { delete r.finding.channel_a; }, /finding\.channel_a is missing/], [EV, (r) => { r.finding.disposition = 'BLOCK'; }, /finding\.disposition is not an allowed/],
    [RF, (r) => { r.seed.sha256 = 5; }, /seed\.sha256/], [RF, (r) => { r.decision.disposition = null; }, /decision\.disposition/],
    [TE, (r) => { r.error.code = ['x']; }, /error\.code/], [TE, (r) => { delete r.error.message; }, /error\.message is missing/],
    [TE, (r) => { r.error.stack = 's'; }, /error\.stack is not an allowed/],
  ];
  for (const [base, f, re] of cases) {
    const r = structuredClone(base); f(r);
    const problems = validateRecord(r);
    assert.ok(problems.some((x) => re.test(x)), `${re}: ${JSON.stringify(problems)}`);
  }
  assert.equal(cases.length, 47);
});

test('A11 the three reproduced cases fail the consumer end to end (exit 1)', () => {
  const m = (f) => { const r = structuredClone(EV); f(r); return JSON.stringify(r); };
  for (const [name, body] of [
    ['placement missing fields', m((r) => { r.candidate.placement = { kind: 'append' }; })],
    ['made-up placement', m((r) => { r.candidate.placement.kind = 'made-up-placement'; })],
    ['policy digest array', m((r) => { r.decision.policy_config_sha256 = [r.decision.policy_config_sha256]; })],
  ]) {
    const r = consume({ extraFiles: { 'r.json': body }, expected: ['p@1.5.0'] });
    assert.equal(r.status, 1, name);
  }
});

test('A11 networking disabled (final): still no network attempt after every consumer run above', () => {
  const attempts = fs.existsSync(NET_LOG) ? fs.readFileSync(NET_LOG, 'utf8') : '';
  assert.equal(attempts, '', attempts);
});

// --- A11 result type and prototype names (operator review 2 2026-09-27) --------------------------------
const PROTO_NAMES = ['__proto__', 'constructor', 'toString', 'hasOwnProperty', 'valueOf', 'isPrototypeOf'];

test('A11 validator: result must be a string AND an own permitted value (arrays, prototype names rejected, no throw)', () => {
  for (const v of [['evaluated'], ['refused'], ['tool_error'], [], 1, null, true, { evaluated: 1 }, ...PROTO_NAMES]) {
    const r = structuredClone(EV); r.result = v;
    let problems;
    assert.doesNotThrow(() => { problems = validateRecord(r); }, `${JSON.stringify(v)} must not throw`);
    assert.deepEqual(problems, [`result is ${JSON.stringify(v)}, expected one of evaluated|refused|tool_error`], JSON.stringify(v));
  }
});

test('A11 consumer end to end: result ["evaluated"] and prototype-name results FAIL with exit 1 (no PASS, no crash)', () => {
  const variants = { array: ['evaluated'], ...Object.fromEntries(PROTO_NAMES.map((n) => [n, n])) };
  for (const [name, v] of Object.entries(variants)) {
    const text = OUT['allow-append'].replace(/"result": "evaluated"/, `"result": ${JSON.stringify(v)}`);
    assert.notEqual(text, OUT['allow-append'], 'the mutation applied');
    const r = consume({ extraFiles: { 'r.json': text }, expected: ['p@1.5.0'] });
    assert.equal(r.status, 1, `${name}: ${r.stdout}${r.stderr}`);
    assert.doesNotMatch(r.stdout, /chaingate-ci: PASS/, name);
    assert.ok(r.summary.failures.some((m) => /result is .* expected one of evaluated\|refused\|tool_error/.test(m)), name);
    assert.equal(r.stderr, '', `${name}: no uncaught exception`);
  }
});

test('A11 validator: prototype-name MEMBERS never count as present and are reported as not allowed', () => {
  // JSON.parse makes "__proto__" an own data property; it must not satisfy or smuggle a member.
  const text = OUT['allow-append'].replace(/"sha256": "([0-9a-f]{64})",\n    "trust"/, '"__proto__": { "sha256": "$1" },\n    "trust"');
  assert.notEqual(text, OUT['allow-append'], 'the mutation applied');
  const problems = validateRecord(JSON.parse(text));
  assert.ok(problems.includes('seed.sha256 is missing'), JSON.stringify(problems));
  assert.ok(problems.includes('seed.__proto__ is not an allowed member'), JSON.stringify(problems));
  for (const n of PROTO_NAMES.filter((x) => x !== '__proto__')) {
    const r = structuredClone(EV); r.decision[n] = 'x';
    assert.ok(validateRecord(r).includes(`decision.${n} is not an allowed member`), n);
    const t = structuredClone(EV); t[n] = 'x';
    assert.ok(validateRecord(t).includes(`member ${n} is not allowed for result evaluated`), n);
  }
});

test('A11 networking disabled (after result-type tests): no network attempt', () => {
  const attempts = fs.existsSync(NET_LOG) ? fs.readFileSync(NET_LOG, 'utf8') : '';
  assert.equal(attempts, '', attempts);
});
