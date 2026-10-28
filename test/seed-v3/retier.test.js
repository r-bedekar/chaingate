// Since 0.1.6 (cft-policy-1.3): the re-tier of the seed's strict rows. A strict WARN becomes a NOTE only when every flag that
// broke already held on the release this one follows (the baseline: same flavor, then same release line, then the previous
// release) and no guard holds. Never below NOTE, never a BLOCK touched. Written before the code; the fixtures under
// test/fixtures/retier are registry documents of real releases (2026-10-28), cut at each release and with every person
// replaced by a placeholder that keeps which accounts and domains match.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';
import RT from '../../seed/v3/retier.js';
import POL from '../../seed/v3/policy.js';
import G from '../../seed/v3/gate.js';
import { buildCheckRecord, inputFromPackument, SUPPORTED_RECORDS } from '../../cli/check-record.js';
import { validateRecord } from '../../examples/ci/chaingate-ci.mjs';
import { validRetier } from '../../gates/row-class.js';
import { createGateRunner } from '../../gates/index.js';
import { buildSeed, openFixtureSeed, docFor, manifestFor, iso, TIP_S, STEP_S, WARNCFG } from './u05-fixtures.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const FIX = path.join(HERE, '..', 'fixtures', 'retier');
const V3 = path.join(HERE, '..', '..', 'seed', 'v3');
const load = (f) => JSON.parse(fs.readFileSync(path.join(FIX, f), 'utf8'));
const DAY = 86_400_000;
const STRICT = ['seed-v3:channel-a:critical', 'seed-v3:dac-trajectory:surface'];

/** A finding whose named Channel-A groups and DAC predicates broke (the only members the re-tier reads). */
const finding = (ch = [], dac = []) => ({
  channel_a: { groups: Object.fromEntries(ch.map((k) => [k, { value: true }])) },
  dac_trajectory: { predicates: Object.fromEntries(dac.map((k) => [k, { value: true }])) },
});
const APPEND = Object.freeze({ kind: 'append', channel_a_usable: true });
const retier = (doc, version, f, extra = {}) => RT.retierOf({ packageName: doc.name, version, finding: f, placement: APPEND,
  notEvaluated: [], rawVersions: doc.versions, rawTimes: doc.time, ...extra });

/** A small document: [version, ISO time, manifest overrides] rows of package `x`. */
function doc(rows) {
  const versions = {}; const time = {};
  for (const [v, t, over = {}] of rows) {
    versions[v] = { name: 'x', version: v, _npmUser: { name: 'alice', email: 'alice@example.com' }, _npmVersion: '10.2.3',
      maintainers: [{ name: 'alice', email: 'alice@example.com' }], gitHead: `g${v.replace(/\W/g, '')}`, dist: { unpackedSize: 1000 }, ...over };
    time[v] = t;
  }
  return { name: 'x', versions, time };
}
const T = (d) => new Date(Date.parse('2026-01-01T00:00:00Z') + d * DAY).toISOString();
const BOB = { _npmUser: { name: 'bob', email: 'bob@example.net' }, maintainers: [{ name: 'bob', email: 'bob@example.net' }] };

// ------------------------------------------------------------------------------------------------ the baseline
test('RT1 the baseline: same flavor first, then the same release line, then the previous release; sibling builds excluded', () => {
  const d = doc([['1.0.0', T(0)], ['2.0.0-beta.1', T(1)], ['1.1.0', T(2)], ['2.0.0-beta.2', T(3)], ['2.0.0-beta.2-linux-x64', T(3.5)],
    ['1.2.0', T(4)], ['2.0.0-beta.3', T(5)], ['3.0.0', T(6)]]);
  let c = RT.chooseBaseline(d.versions, d.time, '2.0.0-beta.3');
  assert.equal(c.baseline, '2.0.0-beta.2'); assert.equal(c.basis, 'same flavor'); assert.deepEqual(c.problems, []);
  c = RT.chooseBaseline(d.versions, d.time, '1.2.0');
  assert.equal(c.baseline, '1.1.0'); assert.equal(c.basis, 'same flavor');
  c = RT.chooseBaseline(d.versions, d.time, '3.0.0');
  assert.equal(c.baseline, '2.0.0-beta.3'); assert.equal(c.basis, 'previous release', 'a new major has no line of its own yet');
  // a platform build published beside its release is a sibling, never its baseline
  const s = doc([['1.0.0', T(0)], ['1.1.0-linux-x64', T(10), { gitHead: 'same' }], ['1.1.0', T(10.1), { gitHead: 'same' }]]);
  assert.equal(RT.chooseBaseline(s.versions, s.time, '1.1.0').baseline, '1.0.0');
  assert.equal(RT.flavor('2.0.0-beta.5-linux-x64'), 'beta.#.linux.x64'); assert.equal(RT.lineKey('0.48.0-node'), 'pre:0.48:node');
});

test('RT2 no clean baseline keeps every flag counting: no earlier version, a tie, a removed version between, an untimed or invalid key', () => {
  const f = finding(['publisher', 'git', 'size']);
  const cases = [
    [doc([['1.0.0', T(0)]]), '1.0.0', /no earlier version/],
    [doc([['1.0.0', T(0)], ['1.0.1', T(5)], ['1.1.0', T(5)]]), '1.1.0', /share this version's publish time/],
    [doc([['1.0.0', T(0)], ['1.0.1', T(0)], ['1.1.0', T(5)]]), '1.1.0', /shares the baseline/],
    [(() => { const d = doc([['1.0.0', T(0)], ['1.1.0', T(5)]]); d.time['1.0.5'] = T(2); return d; })(), '1.1.0', /removed version/],
    [(() => { const d = doc([['1.0.0', T(0)], ['1.1.0', T(5)]]); d.versions['1.0.7'] = d.versions['1.0.0']; return d; })(), '1.1.0', /no usable publish time/],
    [(() => { const d = doc([['1.0.0', T(0)], ['1.1.0', T(5)]]); d.versions['1.0.x\u001b[31m'] = {}; d.time['1.0.x\u001b[31m'] = T(1); return d; })(), '1.1.0', /not valid versions/],
  ];
  for (const [d, v, why] of cases) {
    const r = retier(d, v, f);
    assert.equal(r.placement, 'raised', String(why)); assert.ok(r.flags.every((x) => x.counts), String(why));
    assert.match(r.words, why);
  }
  assert.equal(retier({ name: 'x', versions: null, time: null }, '1.0.0', f).placement, 'raised', 'no document: every flag counts');
  assert.equal(RT.retierOf({ packageName: 'x', version: '1.0.0', finding: finding(), rawVersions: {}, rawTimes: {} }), null, 'nothing broke: no block');
});

// ------------------------------------------------------------------------------------------------ the flags
test('RT3 each flag is re-read against the baseline with the checker\'s own meaning; a side that cannot be read counts', () => {
  const base = [['1.0.0', T(0), BOB], ['1.1.0', T(30), BOB]];
  const read = (over, flags, dac = []) => retier(doc([...base, ['1.2.0', T(60), { ...BOB, ...over }]]), '1.2.0', finding(flags, dac)).flags;
  assert.deepEqual(read({}, ['publisher', 'git', 'size']).map((x) => x.counts), [false, false, false], 'the same state as the baseline');
  assert.equal(read({ _npmUser: { name: 'carol', email: 'carol@example.org' } }, ['publisher'])[0].counts, true, 'another account');
  assert.equal(read({ maintainers: [{ name: 'bob', email: 'bob@example.net' }, { name: 'eve', email: 'e@x.y' }] }, ['publisher'])[0].counts, true, 'maintainers changed');
  assert.equal(read({ _npmUser: { ...BOB._npmUser, trustedPublisher: { id: 'github', oidcConfigId: 'oidc:1' } } }, ['publisher'])[0].counts, true,
    'a trusted publisher configuration that differs counts');
  assert.equal(read({ gitHead: undefined }, ['git'])[0].counts, true, 'gitHead dropped');
  assert.equal(read({ dist: { unpackedSize: 1600 } }, ['size'])[0].counts, true, 'size +60 %');
  assert.equal(read({ dist: { unpackedSize: 1400 } }, ['size'])[0].counts, false, 'size +40 %');
  assert.equal(read({ dist: { unpackedSize: 4999 } }, [], ['size_jump_5x'])[0].counts, false, 'x4.999 is no x5 jump');
  assert.equal(read({ dist: {} }, ['size'])[0].counts, true, 'size unknown on this release counts');
  // provenance: never having it is not a drop; losing it is
  const noProv = doc([['1.0.0', T(0)], ['1.1.0', T(30)], ['1.2.0', T(60)]]);
  assert.equal(retier(noProv, '1.2.0', finding([], ['prov_dropped'])).flags[0].counts, false);
  const prov = doc([['1.0.0', T(0)], ['1.1.0', T(30), { dist: { unpackedSize: 1000, attestations: { url: 'u' } } }], ['1.2.0', T(60)]]);
  assert.equal(retier(prov, '1.2.0', finding([], ['prov_dropped'])).flags[0].counts, true);
  // install hooks: the same hooks as the baseline do not count; different ones do; none never counts
  const hooks = (h) => doc([['1.0.0', T(0)], ['1.1.0', T(30), { scripts: { postinstall: 'node a.js' } }], ['1.2.0', T(60), { scripts: h }]]);
  assert.equal(retier(hooks({ postinstall: 'node a.js' }), '1.2.0', finding(['install'])).flags[0].counts, false);
  assert.equal(retier(hooks({ postinstall: 'node b.js' }), '1.2.0', finding(['install'])).flags[0].counts, true);
  assert.equal(retier(hooks({}), '1.2.0', finding([], ['install_introduced'])).flags[0].counts, false);
  assert.equal(retier(doc([['1.0.0', T(0)], ['1.1.0', T(30)]]), '1.1.0', finding(['not_a_flag'])).flags[0].counts, true, 'an unknown flag counts');
});

// ------------------------------------------------------------------------------------------------ the guards
test('RT4 every guard keeps the warning, even when no flag is new', () => {
  const quiet = [['1.0.0', T(0), BOB], ['1.1.0', T(30), BOB]];
  const at = (over, extra = {}) => retier(doc([...quiet, ['1.2.0', T(60), { ...BOB, ...over }]]), '1.2.0',
    finding(['publisher'], ['first_pkg_appearance_new_publisher']), extra);
  const ids = (r) => r.guards.map((g) => g.id);
  assert.equal(at({}).placement, 'recorded', 'control: nothing new, no guard');
  assert.deepEqual(ids(at({ scripts: { postinstall: 'node x.js' } })), ['install-hook']);
  assert.deepEqual(ids(at({ gypfile: true })), ['install-hook'], 'gypfile and no version ever had an install hook');
  assert.deepEqual(ids(at({ dependencies: { leftpad: '1.0.0' } })), ['dependency']);
  assert.deepEqual(ids(at({ dependencies: { leftpad: 'github:evil/leftpad' } })), ['dependency'], 'a source outside the registry');
  assert.deepEqual(ids(at({}, { notEvaluated: [{ where: 'channel_a.group', name: 'size', reason: 'beyond_spine' }] })), ['evidence-incomplete']);
  assert.deepEqual(ids(at({}, { placement: { kind: 'new-major-cold-start', channel_a_usable: false } })), ['evidence-incomplete']);
  const p = retier(doc([['1.0.0', T(0)], ['1.1.0', T(30), { dist: { unpackedSize: 1000, attestations: { url: 'u' } } }], ['1.2.0', T(60)]]),
    '1.2.0', finding(['publisher']));
  assert.ok(ids(p).includes('provenance-drop'));
  // releases after the seed tip are no guard: the baseline is read from the registry document
  assert.equal(RT.retierOf({ packageName: 'x', version: '1.2.0', finding: finding(['publisher']), placement: APPEND, notEvaluated: [],
    staleSeed: { checked: true, k: 3, tip: '1.0.0', versions: [] }, rawVersions: doc([...quiet, ['1.2.0', T(60), BOB]]).versions,
    rawTimes: doc([...quiet, ['1.2.0', T(60), BOB]]).time }).placement, 'recorded');
});

test('RT5 a state that began less than 7 days before the release keeps the warning; 7 days or more does not', () => {
  const mk = (gap) => doc([['1.0.0', T(0)], ['1.1.0', T(30), BOB], ['1.2.0', T(30 + gap), BOB]]);
  const recent = retier(mk(6.9), '1.2.0', finding(['publisher'], ['first_pkg_appearance_new_publisher']));
  assert.equal(recent.placement, 'raised'); assert.deepEqual([...new Set(recent.guards.map((g) => g.id))], ['recent-state']);
  assert.equal(recent.flags[0].state_since, '1.1.0');
  const old = retier(mk(7), '1.2.0', finding(['publisher'], ['first_pkg_appearance_new_publisher']));
  assert.equal(old.placement, 'recorded'); assert.equal(old.flags[0].state_since, '1.1.0');
  // the walk follows the state back through the line: three releases by bob, the first 40 days earlier
  const long = doc([['1.0.0', T(0)], ['1.1.0', T(30), BOB], ['1.1.1', T(66), BOB], ['1.2.0', T(70), BOB]]);
  assert.equal(retier(long, '1.2.0', finding(['publisher'])).placement, 'recorded');
});

// ------------------------------------------------------------------------------------------------ real releases
test('RT6 the 2026-10-28 releases: contentful 5.0.0 is not new; faststore 1.12.52 repeats a publisher state one day old; art-template 4.13.3 is new', () => {
  const c = load('contentful-app-sdk-5.0.0.json');
  const rc = retier(c, '5.0.0', finding(['publisher', 'git', 'size']));
  assert.equal(rc.placement, 'recorded', rc.words); assert.equal(rc.baseline, '4.76.0'); assert.equal(rc.basis, 'previous release');
  assert.deepEqual(rc.flags_dropped, ['publisher', 'git', 'size']);
  const f = load('faststore-api-1.12.52.json');
  const rf = retier(f, '1.12.52', finding([], ['prov_dropped', 'first_pkg_appearance_new_publisher']));
  assert.equal(rf.baseline, '1.12.51'); assert.equal(rf.basis, 'same flavor'); assert.deepEqual(rf.flags_dropped, ['prov_dropped', 'first_pkg_appearance_new_publisher']);
  assert.equal(rf.placement, 'raised'); assert.deepEqual([...new Set(rf.guards.map((g) => g.id))], ['recent-state'],
    'a new account published 1.12.51 the day before, after two years of quiet: the shape a takeover leaves');
  const n = load('niimbluelib-0.48.0-node.json');
  const rn = retier(n, '0.48.0-node', finding([], ['prov_dropped', 'size_jump_5x']));
  assert.equal(rn.placement, 'recorded'); assert.match(rn.flags[0].words, /never having it is not a drop/);
  const a = load('art-template-4.13.3.json');   // a labelled compromise
  const ra = retier(a, '4.13.3', finding(['publisher', 'git', 'size'], ['first_pkg_appearance_new_publisher']));
  assert.equal(ra.placement, 'raised'); assert.equal(ra.baseline, '4.13.2');
  assert.deepEqual(ra.flags.filter((x) => x.counts).map((x) => x.flag), ['publisher', 'git', 'size', 'first_pkg_appearance_new_publisher']);
  const h = load('home-assistant-js-websocket-9.8.0.json');
  const rh = retier(h, '9.8.0', finding(['install'], ['install_introduced']));
  assert.equal(rh.placement, 'raised'); assert.ok(rh.guards.some((g) => g.id === 'install-hook'), 'the registry entry adds a hook');
});

// ------------------------------------------------------------------------------------------------ policy
const decide = (f, rt, extra = {}) => POL.decide(f, { config: WARNCFG, placement: { kind: 'append', channel_a_usable: true }, retier: rt, ...extra });
const realFinding = (strict) => {
  // a finding as the checker writes it: strict, Channel-A 3 of 5 broke (critical) and DAC 2 of 4 (surface); else nothing broke
  const known = (v) => ({ value: v, coverage: 'EVALUATED' });
  const groups = { publisher: known(strict), provenance: known(false), install: known(false), size: known(strict), git: known(strict) };
  const preds = { install_introduced: known(false), size_jump_5x: known(false), prov_dropped: known(strict), first_pkg_appearance_new_publisher: known(strict) };
  const agg = (items, th, m) => { const nb = Object.values(items).filter((x) => x.value).length;
    return { M: m, n_broke: nb, n_evaluable: m, n_unevaluable: 0, thresholds: th.map(([name, t]) => ({ name, threshold: t, threshold_result: nb >= t, threshold_determinacy: 'determinate', interval: [nb, nb] })) }; };
  return { contract_version: POL.IMPLEMENTED_DETECTION_CONTRACT, candidate: { package: 'x', version: '1.2.0', provider_class: 'unverified' },
    channel_a: { groups, publisher_constituents: {}, ...agg(groups, [['critical', 3]], 5) },
    dac_trajectory: { predicates: preds, ...agg(preds, [['surface', 2], ['any', 1]], 4) }, seed: {} };
};
const REC = { version: RT.RETIER_VERSION, placement: 'recorded', baseline: '1.1.0', basis: 'same flavor', flags: [], flags_dropped: ['publisher'], guards: [],
  words: 'not new against 1.1.0 (same flavor): publisher already held there' };

test('RT7 policy 1.3: a recorded re-tier turns each strict WARN into a NOTE, never an ALLOW row; raised or absent changes nothing', () => {
  assert.equal(POL.POLICY_CONTRACT_VERSION, 'cft-policy-1.3');
  const f = realFinding(true);
  const none = decide(f, null); const raised = decide(f, { ...REC, placement: 'raised' }); const rec = decide(f, REC);
  const row = (d, g) => d.results.find((x) => x.gate === g);
  for (const g of STRICT) { assert.equal(row(none, g).result, 'WARN'); assert.equal(row(raised, g).result, 'WARN'); assert.equal(row(rec, g).result, 'NOTE'); }
  assert.equal(none.disposition, 'WARN'); assert.equal(raised.disposition, 'WARN'); assert.equal(rec.disposition, 'ALLOW');
  assert.match(row(rec, STRICT[0]).detail, /3\/5 witnesses broke, threshold 3 .*; not new: not new against 1\.1\.0/);
  assert.match(row(rec, STRICT[0]).detail, /\(a note, not a warning\)$/);
  assert.deepEqual(none.results.map((x) => x.gate), rec.results.map((x) => x.gate), 'the same rows, in the same order');
  assert.ok(rec.results.every((x) => !STRICT.includes(x.gate) || x.result !== 'ALLOW'), 'never an ALLOW row');
  assert.equal(rec.retier, REC); assert.equal(raised.retier.placement, 'raised'); assert.ok(!('retier' in none));
  // only a strict WARN moves: the contributing row and the pin keep theirs; a pin BLOCK stays a BLOCK
  assert.equal(row(rec, 'seed-v3:dac-trajectory:any').result, 'NOTE');
  const pinned = decide(f, REC, { pin: { advisory_id: 'ADV-1', source: 's' } });
  assert.equal(pinned.disposition, 'BLOCK'); assert.equal(row(pinned, 'seed-v3:known-malicious-pin').result, 'BLOCK');
  // a decision with no strict WARN carries no block, whatever the gate passed
  const quiet = decide(realFinding(false), REC);
  assert.ok(!('retier' in quiet)); assert.equal(row(quiet, 'seed-v3:dac-trajectory:surface').result, 'ALLOW');
});

// ------------------------------------------------------------------------------------------------ the gate, end to end
function withSeed(fn) {
  const s = buildSeed({ layout: '1.1' }); const seed = openFixtureSeed(s.dbPath);
  try { return fn(seed); } finally { seed.close(); s.cleanup(); }
}
const BOBM = (name, v, over = {}) => manifestFor(name, v, { _npmUser: { name: 'bob', email: 'bob@example.net' },
  maintainers: [{ name: 'bob', email: 'bob@example.net' }], gitHead: undefined, dist: { unpackedSize: 3000 }, ...over });
// the seed records q 1.0.0-1.2.0 by alice (gitHead, provenance, 1000 B); bob's releases follow it
const takeover = (gapSteps) => docFor('q', [['1.3.0', iso(TIP_S + STEP_S), BOBM('q', '1.3.0')], ['1.4.0', iso(TIP_S + (1 + gapSteps) * STEP_S), BOBM('q', '1.4.0')]]);
const evaluate = (seed, d, v) => G.evaluateCandidate(seed, { config: WARNCFG, domainVersionCount: 'from-packument' }, inputFromPackument(d, d.name, v));

test('RT8 through the gate on a seed: a state the registry shows since an older release is a NOTE; the same state one day old, or a new one, warns', () => {
  withSeed((seed) => {
    // 1.4.0 follows bob's 1.3.0 by 99 steps (about 114 days): Channel-A against the seed tip breaks publisher, provenance, size and git
    const old = evaluate(seed, takeover(99), '1.4.0');
    const rows = Object.fromEntries(old.decision.results.map((x) => [x.gate, x.result]));
    assert.equal(rows['seed-v3:channel-a:critical'], 'NOTE', JSON.stringify(old.decision.results));
    assert.equal(old.decision.retier.placement, 'recorded'); assert.equal(old.decision.retier.baseline, '1.3.0');
    assert.equal(old.decision.disposition, 'ALLOW');
    // the gate result carries the compact block, and the runner keeps it
    const gate = G.createSeedV3Gate({ seed, config: WARNCFG, domainVersionCount: 'from-packument' });
    const gr = gate.evaluate(inputFromPackument(takeover(99), 'q', '1.4.0'));
    assert.deepEqual(validRetier(gr.retier), gr.retier); assert.equal(gr.retier.placement, 'recorded');
    const run = createGateRunner({ modules: [gate] })({ ...inputFromPackument(takeover(99), 'q', '1.4.0'), packageName: 'q', version: '1.4.0', history: [] });
    assert.deepEqual(run.results.find((x) => x.gate === 'seed-v3').retier, gr.retier, 'normalizeResult keeps a valid block');
    // one step (about 28 hours) after bob's first release: the state is new enough to keep the warning
    const fresh = evaluate(seed, takeover(1), '1.4.0');
    assert.equal(fresh.decision.disposition, 'WARN'); assert.equal(fresh.decision.retier.placement, 'raised');
    assert.ok(fresh.decision.retier.guards.some((g) => g.id === 'recent-state'));
    // a third account on 1.4.0: new against 1.3.0
    const carol = docFor('q', [['1.3.0', iso(TIP_S + STEP_S), BOBM('q', '1.3.0')],
      ['1.4.0', iso(TIP_S + 100 * STEP_S), BOBM('q', '1.4.0', { _npmUser: { name: 'carol', email: 'carol@example.org' } })]]);
    const c = evaluate(seed, carol, '1.4.0');
    assert.equal(c.decision.disposition, 'WARN'); assert.ok(c.decision.retier.flags.some((x) => x.flag === 'publisher' && x.counts));
  });
});

// ------------------------------------------------------------------------------------------------ the record
let Ajv2020 = null; try { Ajv2020 = createRequire(import.meta.url)('ajv/dist/2020.js'); } catch { /* not installed */ }
const read = (p) => JSON.parse(fs.readFileSync(p, 'utf8'));

test('RT9 /5 equals /4 plus exactly the documented delta: the schema const and the optional decision.retier and decision.pin members', () => {
  const want = read(path.join(V3, 'chaingate-check-4.schema.json')); const got = read(path.join(V3, 'chaingate-check-5.schema.json'));
  want.$id = 'https://chaingate.dev/schemas/chaingate-check-5.json';
  for (const shape of want.oneOf) shape.properties.schema.const = 'chaingate.check/5';
  want.$defs.decision.properties.retier = got.$defs.decision.properties.retier;
  want.$defs.decision.properties.pin = got.$defs.decision.properties.pin;
  assert.ok(!want.$defs.decision.required.includes('retier') && !want.$defs.decision.required.includes('pin'), 'optional');
  want.title = got.title; want.description = got.description;
  assert.deepEqual(got, want);
  assert.ok(/^[\x20-\x7e\n]*$/.test(fs.readFileSync(path.join(V3, 'chaingate-check-5.schema.json'), 'utf8')), 'ASCII only');
  assert.equal(SUPPORTED_RECORDS['chaingate.check/5'].policy_version, 'cft-policy-1.3');
});

test('RT10 a re-tiered check writes /5 with the compact block; the schema, the CI consumer and the compatibility check accept it', () => {
  withSeed((seed) => {
    const rec = buildCheckRecord({ seed, policy: WARNCFG, domainVersionCount: 'from-packument', input: inputFromPackument(takeover(99), 'q', '1.4.0'),
      request: { package: 'q', version: '1.4.0' }, tool: { name: 'chaingate', version: 'test' } });
    assert.equal(rec.schema, 'chaingate.check/5'); assert.equal(rec.decision.policy_version, 'cft-policy-1.3');
    assert.deepEqual(Object.keys(rec.decision.retier).sort(), ['baseline', 'basis', 'flags_dropped', 'guards', 'placement', 'version', 'words']);
    assert.equal(rec.decision.retier.placement, 'recorded'); assert.equal(rec.effective.action, 'ALLOW');
    assert.deepEqual(validateRecord(rec), []);
    if (Ajv2020) {
      const Ctor = Ajv2020.default || Ajv2020; const ajv = new Ctor({ strict: true, strictRequired: false, allErrors: true });
      ajv.addSchema(read(path.join(HERE, '..', 'fixtures', 'cft03', 'finding.schema.json')));
      const v5 = ajv.compile(read(path.join(V3, 'chaingate-check-5.schema.json')));
      assert.ok(v5(rec), JSON.stringify(v5.errors));
      const bad = structuredClone(rec); bad.decision.retier.placement = 'hidden';
      assert.equal(v5(bad), false, 'a placement outside the vocabulary is refused');
    }
    const bad = structuredClone(rec); bad.decision.retier.flags_dropped = 'publisher';
    assert.ok(validateRecord(bad).some((x) => /decision\.retier\.flags_dropped/.test(x)));
  });
});

test('RT11 the compact block is bounded and validated; a malformed one is dropped by the runner, never trusted', () => {
  const big = { ...REC, flags_dropped: ['publisher', 'evil'], guards: [{ id: 'install-hook' }, { id: 'made-up' }], words: 'w'.repeat(900), baseline: '1.0.0\u202e' };
  const c = RT.compact(big);
  assert.deepEqual(c.flags_dropped, ['publisher']); assert.deepEqual(c.guards, ['install-hook']); assert.equal(c.baseline, null);
  assert.ok(c.words.length <= 403); assert.deepEqual(RT.validCompact(c), c);
  for (const x of [null, { ...c, version: 'retier-9' }, { ...c, placement: 'gone' }, { ...c, guards: ['x'] }, { ...c, baseline: 'not a version' },
    { ...c, words: 'w'.repeat(500) }, { ...c, flags_dropped: Array(10).fill('git') }]) assert.equal(validRetier(x), null, JSON.stringify(x)?.slice(0, 80));
  const run = createGateRunner({ modules: [{ name: 'seed-v3', evaluate: () => ({ gate: 'seed-v3', result: 'ALLOW', detail: 'd', retier: { placement: 'recorded' } }) }] });
  assert.ok(!('retier' in run({ packageName: 'x', version: '1.0.0', history: [] }).results[0]), 'an invalid block is not kept');
});

test('RT12 the document index is built once per document and only for the versions map it was built with', () => {
  const d = doc([['1.0.0', T(0)], ['1.1.0', T(1)], ['1.2.0', T(2)]]);
  const a = RT.indexFor(d.versions, d.time);
  assert.equal(RT.indexFor(d.versions, d.time), a, 'same document: the memoised index');
  assert.notEqual(RT.indexFor({ ...d.versions }, d.time), a, 'another versions map: rebuilt');
  assert.deepEqual(a.entries.map(([, v]) => v), ['1.0.0', '1.1.0', '1.2.0']);
});
