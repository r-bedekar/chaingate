#!/usr/bin/env node
// chaingate-ci — one offline CI consumer of `chaingate.check/1` results. Node standard library only.
//
//   node chaingate-ci.mjs --expected <manifest> --results <dir> --trusted-seed <sha256> [...]
//                         [--trusted-seeds-file <file>] [--ignore-overrides] [--summary <file>]
//
//   --expected          text file, one `package@version` per line (blank lines and # comments ignored)
//   --results           directory of `chaingate check --json` outputs (*.json), one per expected pair
//   --trusted-seed      a seed database sha256 your CI accepts; repeatable
//   --trusted-seeds-file  one sha256 per line
//   --ignore-overrides  gate on decision.disposition (the evaluated result) instead of effective.action
//   --summary           write a JSON summary to this file
//
// Exit 0: every expected pair has exactly one valid result and none fails the gate.
// Exit 1: any BLOCK, any refused or tool_error result, or any validation failure.
// Exit 2: usage error.
//
// WHAT IT CHECKS. Not full JSON Schema validation (that runs in the chaingate test suite, against
// seed/v3/chaingate-check-1.schema.json). It performs this specified structural validation:
//   schema id exactly chaingate.check/1 · result one of evaluated|refused|tool_error · the members
//   each shape requires and no others · inside every object the contract defines (tool, request,
//   source, seed, candidate, placement, decision and its rows, effective, override, explanation,
//   error): every required member present, no other member, each of the right type or enum, with
//   no coercion · the finding's CFT-03 top-level members present and no others ·
//   request.package/version is an expected pair · exactly one result per expected pair (missing,
//   duplicate, unexpected and empty sets all fail) · evaluated/refused results carry a seed.sha256 in
//   the trusted list · `effective` consistent with `decision` and the override rule · unparseable or
//   truncated files fail.
//
// THE OVERRIDE RULE. decision.disposition is the evaluated disposition and is never rewritten.
// effective.action is ALLOW with basis "override" and the override's provenance when an exact-version
// override exists, otherwise it equals decision.disposition with basis "evaluation". By default this
// consumer gates on effective.action; --ignore-overrides gates on decision.disposition.
//
// TRUST BOUNDARY. This consumer trusts outputs produced by its own controlled CI step. The seed-digest
// check pins WHICH seed that step used; it does not authenticate the JSON. No signing is introduced.
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const SCHEMA_ID = 'chaingate.check/1';
const DISPOSITIONS = ['ALLOW', 'WARN', 'BLOCK'];
const RESULT_VALUES = ['ALLOW', 'WARN', 'BLOCK', 'SKIP'];
const HEX64 = /^[0-9a-f]{64}$/;
const SHAPES = {
  evaluated: ['schema', 'result', 'tool', 'request', 'seed', 'candidate', 'finding', 'decision', 'effective', 'explanation'],
  refused: ['schema', 'result', 'tool', 'request', 'seed', 'decision', 'effective', 'explanation'],
  tool_error: ['schema', 'result', 'tool', 'request', 'error'],
};

const isObj = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);
const has = (o, k) => Object.hasOwn(o, k);   // own properties only: nothing inherited counts as present
const isStr = (v) => typeof v === 'string';
const isNStr = (v) => v === null || typeof v === 'string';

function usage(msg) {
  if (msg) console.error(`chaingate-ci: ${msg}`);
  console.error('usage: chaingate-ci --expected <manifest> --results <dir> --trusted-seed <sha256> [...] '
    + '[--trusted-seeds-file <file>] [--ignore-overrides] [--summary <file>]');
  process.exit(2);
}

function parseArgs(argv) {
  const o = { expected: null, results: null, trusted: [], ignoreOverrides: false, summary: null };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    const val = () => { if (i + 1 >= argv.length) usage(`${a} needs a value`); return argv[++i]; };
    if (a === '--expected') o.expected = val();
    else if (a === '--results') o.results = val();
    else if (a === '--trusted-seed') o.trusted.push(val());
    else if (a === '--trusted-seeds-file') {
      const f = val();
      try {
        o.trusted.push(...fs.readFileSync(f, 'utf8').split('\n').map((l) => l.trim()).filter((l) => l && !l.startsWith('#')));
      } catch (e) { usage(`cannot read ${f}: ${e.code || e.message}`); }
    } else if (a === '--ignore-overrides') o.ignoreOverrides = true;
    else if (a === '--summary') o.summary = val();
    else usage(`unknown argument ${a}`);
  }
  if (!o.expected || !o.results) usage('--expected and --results are required');
  if (!o.trusted.length) usage('at least one --trusted-seed (or --trusted-seeds-file) is required');
  for (const t of o.trusted) if (!HEX64.test(t)) usage(`trusted seed ${JSON.stringify(t)} is not a lowercase sha256`);
  return o;
}

/** Split `package@version` at the LAST @ (scoped names start with one). */
function splitPair(s) {
  const at = s.lastIndexOf('@');
  if (at <= 0 || at === s.length - 1) return null;
  return { package: s.slice(0, at), version: s.slice(at + 1) };
}

// ---------------------------------------------------------------------------------------------
// Structural validation. Every object this contract defines is checked for its REQUIRED members,
// for NO OTHER members, and for each member's type or enum. Type predicates never coerce: a hex
// digest must first BE a string (RegExp.test would turn ['<digest>'] into '<digest>' and pass it).
// ---------------------------------------------------------------------------------------------
const PLACEMENTS = ['recorded', 'append', 'new-major-cold-start', 'historical-omitted', 'ineligible-stub',
  'ineligible-no-publication-time', 'uncovered-package', 'unresolved'];
const FINDING_MEMBERS = ['contract_version', 'timestamp_precision', 'corpus_context', 'candidate', 'channel_a',
  'dac_trajectory', 'seed'];

const T = {
  str: (v) => typeof v === 'string',
  nonEmpty: (v) => typeof v === 'string' && v.length > 0,
  nstr: (v) => v === null || typeof v === 'string',
  bool: (v) => typeof v === 'boolean',
  hex64: (v) => typeof v === 'string' && HEX64.test(v),
  nhex64: (v) => v === null || (typeof v === 'string' && HEX64.test(v)),
  nint: (min) => (v) => v === null || (Number.isInteger(v) && v >= min),
  oneOf: (vals) => (v) => typeof v === 'string' && vals.includes(v),
  constant: (c) => (v) => v === c,
  obj: (v) => isObj(v),
  strMap: (v) => isObj(v) && Object.keys(v).length > 0 && Object.values(v).every((x) => typeof x === 'string' && x.length > 0),
  strArray: (v) => Array.isArray(v) && v.every((x) => typeof x === 'string'),
};
const TYPE_NAMES = new Map([[T.str, 'a string'], [T.nonEmpty, 'a non-empty string'], [T.nstr, 'a string or null'],
  [T.bool, 'a boolean'], [T.hex64, 'a lowercase sha256 string'], [T.nhex64, 'a lowercase sha256 string or null'],
  [T.obj, 'an object'], [T.strMap, 'a non-empty object of strings'], [T.strArray, 'an array of strings']]);

/** Check one object against {member: predicate}; `optional` members may be absent. */
function checkObject(where, value, spec, problems, { optional = [] } = {}) {
  if (!isObj(value)) { problems.push(`${where} must be an object`); return false; }
  for (const k of Object.keys(spec)) {
    if (!has(value, k)) { if (!optional.includes(k)) problems.push(`${where}.${k} is missing`); continue; }
    const pred = spec[k];
    if (!pred(value[k])) {
      problems.push(`${where}.${k} ${pred.expect ? `must be ${pred.expect}` : `must be ${TYPE_NAMES.get(pred) ?? 'valid'}`}`
        + `, got ${JSON.stringify(value[k])?.slice(0, 80)}`);
    }
  }
  for (const k of Object.keys(value)) if (!has(spec, k)) problems.push(`${where}.${k} is not an allowed member`);
  return true;
}
const expect = (pred, text) => Object.assign((v) => pred(v), { expect: text });

const SPEC = {
  tool: { name: T.nonEmpty, version: T.nonEmpty },
  request: { package: T.nonEmpty, version: T.nonEmpty, source: T.obj },
  source: { kind: expect(T.constant('packument-file'), '"packument-file"'), path: T.nonEmpty, sha256: T.hex64 },
  seed: { bundle_id: T.nstr, sha256: T.hex64,
    trust: expect(T.oneOf(['authenticated', 'unsigned-development']), 'authenticated|unsigned-development'),
    authenticated: T.bool, contract_version: T.nonEmpty, rule_versions: T.strMap, corpus_snapshot_digest: T.hex64 },
  candidate: { candidate_digest: T.nhex64, placement: T.obj },
  placement: { kind: expect(T.oneOf(PLACEMENTS), `one of ${PLACEMENTS.join('|')}`), reason: T.nstr,
    lineage_id: expect(T.nint(1), 'an integer >= 1 or null'), ord: expect(T.nint(0), 'an integer >= 0 or null'),
    channel_a_usable: T.bool },
  decision: { policy_version: T.nonEmpty, policy_config_sha256: T.hex64,
    disposition: expect(T.oneOf(DISPOSITIONS), 'ALLOW|WARN|BLOCK'),
    results: expect((v) => Array.isArray(v) && v.length > 0, 'a non-empty array'),
    evidence_complete: T.bool, not_evaluated: expect(Array.isArray, 'an array') },
  result_row: { gate: T.nonEmpty, result: expect(T.oneOf(RESULT_VALUES), 'ALLOW|WARN|BLOCK|SKIP'), detail: T.str },
  not_evaluated_row: { where: T.nonEmpty, name: T.nonEmpty, reason: T.nstr,
    stated_by: expect(T.constant('placement'), '"placement"') },
  effective: { action: expect(T.oneOf(DISPOSITIONS), 'ALLOW|WARN|BLOCK'),
    basis: expect(T.oneOf(['evaluation', 'override']), 'evaluation|override'), override: T.obj },
  override: { reason: T.str, created_at: T.nstr, scope: expect(T.constant('exact-version'), '"exact-version"') },
  explanation: { text: expect((v) => T.strArray(v) && v.length > 0, 'a non-empty array of strings'), structured: T.obj },
  error: { code: expect((v) => typeof v === 'string' && /^[a-z][a-z_]*$/.test(v), 'a lower_snake_case string'), message: T.str },
};

/** Structural validation of one record. Returns a list of problems (empty = valid). */
export function validateRecord(rec) {
  const p = [];
  if (!isObj(rec)) return ['top level is not an object'];
  if (rec.schema !== SCHEMA_ID) return [`schema is ${JSON.stringify(rec.schema)}, expected ${SCHEMA_ID}`];
  // A string, and an OWN key of SHAPES: an array would coerce to its element (["evaluated"] ->
  // "evaluated") and a prototype name ("__proto__", "constructor", "toString") would find an inherited
  // property instead of a shape.
  if (typeof rec.result !== 'string' || !Object.hasOwn(SHAPES, rec.result)) {
    return [`result is ${JSON.stringify(rec.result)}, expected one of ${Object.keys(SHAPES).join('|')}`];
  }
  const allowed = SHAPES[rec.result];
  for (const k of allowed) if (!has(rec, k)) p.push(`missing member ${k} for result ${rec.result}`);
  for (const k of Object.keys(rec)) if (!allowed.includes(k)) p.push(`member ${k} is not allowed for result ${rec.result}`);
  if (p.length) return p;

  checkObject('tool', rec.tool, SPEC.tool, p);
  if (checkObject('request', rec.request, SPEC.request, p, { optional: ['source'] }) && has(rec.request, 'source')) {
    checkObject('request.source', rec.request.source, SPEC.source, p);
  }
  if (rec.result === 'tool_error') {
    checkObject('error', rec.error, SPEC.error, p);
    return p;
  }

  checkObject('seed', rec.seed, SPEC.seed, p);
  const d = rec.decision;
  if (checkObject('decision', d, SPEC.decision, p)) {
    if (Array.isArray(d.results)) d.results.forEach((r, i) => checkObject(`decision.results[${i}]`, r, SPEC.result_row, p));
    if (Array.isArray(d.not_evaluated)) {
      d.not_evaluated.forEach((m, i) => checkObject(`decision.not_evaluated[${i}]`, m, SPEC.not_evaluated_row, p,
        { optional: ['stated_by'] }));
    }
  }
  const e = rec.effective;
  if (checkObject('effective', e, SPEC.effective, p, { optional: ['override'] })) {
    if (e.basis === 'evaluation') {
      if (has(e, 'override')) p.push('effective.override present with basis "evaluation"');
      if (isObj(d) && e.action !== d.disposition) p.push(`effective.action ${e.action} disagrees with decision.disposition ${d.disposition}`);
    } else if (e.basis === 'override') {
      if (e.action !== 'ALLOW') p.push('an override can only make the effective action ALLOW');
      if (!has(e, 'override')) p.push('effective.override is missing for basis "override"');
      else checkObject('effective.override', e.override, SPEC.override, p);
    }
  }
  checkObject('explanation', rec.explanation, SPEC.explanation, p);

  if (rec.result === 'evaluated') {
    if (checkObject('candidate', rec.candidate, SPEC.candidate, p) && isObj(rec.candidate.placement)) {
      checkObject('candidate.placement', rec.candidate.placement, SPEC.placement, p);
    }
    if (!isObj(rec.finding)) p.push('finding must be an object');
    else {
      for (const k of FINDING_MEMBERS) if (!has(rec.finding, k)) p.push(`finding.${k} is missing`);
      for (const k of Object.keys(rec.finding)) if (!FINDING_MEMBERS.includes(k)) p.push(`finding.${k} is not an allowed member`);
      if (!T.nonEmpty(rec.finding.contract_version)) p.push('finding.contract_version must be a non-empty string');
    }
  }
  return p;
}

function main() {
  const o = parseArgs(process.argv.slice(2));
  const failures = []; const warnings = []; const rows = [];
  const fail = (msg) => failures.push(msg);

  let manifestText = '';
  try { manifestText = fs.readFileSync(o.expected, 'utf8'); } catch (e) { usage(`cannot read ${o.expected}: ${e.code || e.message}`); }
  const expected = new Map();
  for (const [n, raw] of manifestText.split('\n').entries()) {
    const line = raw.trim();
    if (!line || line.startsWith('#')) continue;
    const pair = splitPair(line);
    if (!pair) { fail(`manifest line ${n + 1}: ${JSON.stringify(line)} is not package@version`); continue; }
    const key = `${pair.package}@${pair.version}`;
    if (expected.has(key)) fail(`manifest lists ${key} twice`);
    expected.set(key, []);
  }
  if (expected.size === 0) fail('the manifest lists no expected package@version pairs');

  let files = [];
  try { files = fs.readdirSync(o.results).filter((f) => f.endsWith('.json')).sort(); } catch (e) {
    fail(`cannot read results directory ${o.results}: ${e.code || e.message}`);
  }
  if (files.length === 0) fail(`no *.json results in ${o.results}`);

  const trusted = new Set(o.trusted);
  for (const f of files) {
    const file = path.join(o.results, f);
    let rec;
    try { rec = JSON.parse(fs.readFileSync(file, 'utf8')); } catch (e) {
      fail(`${f}: unparseable or truncated (${e.message})`);
      continue;
    }
    let problems;
    try { problems = validateRecord(rec); } catch (e) { problems = [`could not be validated (${e.message})`]; }
    if (problems.length) { for (const m of problems) fail(`${f}: ${m}`); continue; }
    const key = `${rec.request.package}@${rec.request.version}`;
    if (!expected.has(key)) { fail(`${f}: ${key} is not an expected pair`); continue; }
    expected.get(key).push({ f, rec });
  }

  for (const [key, got] of expected) {
    if (got.length === 0) { fail(`${key}: no result`); continue; }
    if (got.length > 1) { fail(`${key}: ${got.length} results (${got.map((g) => g.f).join(', ')}); exactly one is required`); continue; }
    const { f, rec } = got[0];
    if (rec.result === 'tool_error') {
      fail(`${key}: tool error ${rec.error.code}: ${rec.error.message}`);
      rows.push({ pair: key, file: f, result: rec.result, gate_on: null, outcome: 'FAIL' });
      continue;
    }
    if (!trusted.has(rec.seed.sha256)) {
      fail(`${key}: seed ${rec.seed.sha256} is not in the trusted-seed list`);
      rows.push({ pair: key, file: f, result: rec.result, gate_on: null, outcome: 'FAIL' });
      continue;
    }
    const gateOn = o.ignoreOverrides ? rec.decision.disposition : rec.effective.action;
    const row = { pair: key, file: f, result: rec.result, disposition: rec.decision.disposition,
      effective: rec.effective.action, basis: rec.effective.basis, gate_on: gateOn, seed: rec.seed.sha256 };
    if (rec.result === 'refused') {
      fail(`${key}: REFUSED — ${rec.explanation.text[1]?.trim() ?? 'no finding exists'}`);
      row.outcome = 'FAIL';
    } else if (gateOn === 'BLOCK') {
      fail(`${key}: BLOCK${o.ignoreOverrides && rec.effective.basis === 'override' ? ' (override ignored)' : ''}`
        + ` — ${rec.explanation.text.find((l) => /^\s{4}\S/.test(l))?.trim() ?? ''}`);
      row.outcome = 'FAIL';
    } else if (gateOn === 'WARN') {
      const why = rec.explanation.text.slice(1).map((l) => l.trim()).join(' | ');
      warnings.push({ pair: key, why });
      console.log(`::warning title=chaingate WARN ${key}::${why.replace(/%/g, '%25').replace(/\r?\n/g, ' ')}`);
      row.outcome = 'WARN';
    } else {
      row.outcome = rec.effective.basis === 'override' ? 'PASS (override)' : 'PASS';
    }
    rows.push(row);
  }

  const summary = { consumer: 'chaingate-ci', schema: SCHEMA_ID, gate_on: o.ignoreOverrides ? 'decision.disposition' : 'effective.action',
    expected: expected.size, results: files.length, passed: failures.length === 0, failures, warnings, rows };
  if (o.summary) fs.writeFileSync(o.summary, `${JSON.stringify(summary, null, 2)}\n`);
  for (const r of rows) console.log(`${r.outcome.padEnd(16)} ${r.pair}${r.basis === 'override' ? '  (override)' : ''}`);
  for (const m of failures) console.log(`::error title=chaingate::${m.replace(/%/g, '%25').replace(/\r?\n/g, ' ')}`);
  console.log(failures.length ? `chaingate-ci: FAIL (${failures.length} problem(s))` : `chaingate-ci: PASS (${rows.length} result(s), ${warnings.length} warning(s))`);
  process.exit(failures.length ? 1 : 0);
}

// Run main() only when this file is the entry script. `new URL(import.meta.url).pathname` is not a
// file path: on Windows it is /D:/..., and any space or non-ASCII character is percent-encoded, so the
// comparison failed there and the consumer exited 0 without checking anything. Compare real paths.
function isEntryScript() {
  if (!process.argv[1]) return false;
  const self = fileURLToPath(import.meta.url);
  try { return fs.realpathSync(process.argv[1]) === fs.realpathSync(self); } catch { return path.resolve(process.argv[1]) === self; }
}
if (isEntryScript()) main();
