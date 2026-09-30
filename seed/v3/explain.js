// U-01 / CFT-04 R6 — the explanation is a PURE FUNCTION of a check result.
//
//   explain(result) -> { text: string[], structured }
//
// It reads only the object it is given: no seed, no network, no clock, no environment. The same
// input renders the same bytes, and its strings are never rule inputs. `result` is a
// `chaingate.check/1` or `/2` record (its own `explanation` member, if present, is ignored), so a SAVED
// output can be explained again later without evaluating anything (`why --from`).
//
// TWO RENDERERS, chosen by the record's schema (U-05 Amendment 1). `chaingate.check/1` records -- written by 0.1.2
// and earlier -- are explained by version 1, unchanged byte for byte. `chaingate.check/2` records (0.1.3) use
// version 2, which differs in one respect: a REFUSED explanation names the rows that decided it, in the text and in
// the structure (`decided_by`). Under cft-policy-1.1 a refusal can be decided by a recorded advisory pin, and version
// 1 could only say "an unusable input is decided by on_unusable_input", which would misattribute that BLOCK.
//
// What it must never do (R5/R6):
//   * render NOT_EVALUATED as clean, or let it disappear. Every group, publisher constituent and
//     predicate that was not evaluated is named, with its reason, in the text AND the structure;
//   * drop a publisher constituent because another one decided the group;
//   * explain anything but the refusal when the input was refused: no finding exists, so there is
//     nothing else to explain.
import K from './contract.js';

const EXPLAIN_VERSION_1 = 'chaingate-explain-1';
const EXPLAIN_VERSION_2 = 'chaingate-explain-2';
/** What this runtime writes. */
const EXPLAIN_VERSION = EXPLAIN_VERSION_2;
/** The explanation version each supported check schema carries. */
const EXPLAIN_VERSION_FOR_SCHEMA = Object.freeze({
  'chaingate.check/1': EXPLAIN_VERSION_1,
  'chaingate.check/2': EXPLAIN_VERSION_2,
});

const has = (o, k) => o !== null && typeof o === 'object' && Object.prototype.hasOwnProperty.call(o, k);

/** The not_evaluated entry for (where, name), if the decision recorded one. */
function neFor(decision, where, name) {
  return (decision.not_evaluated || []).find((m) => m.where === where && m.name === name) || null;
}

/** One observation's state: the decision's NOT_EVALUATED record wins (it carries a placement's own
 *  reason where Channel-A could not be placed); otherwise the finding's tri-state. */
function stateOf(decision, where, name, tri) {
  const ne = neFor(decision, where, name);
  if (ne) {
    const out = { name, state: 'NOT_EVALUATED', reason: ne.reason ?? null };
    if (ne.stated_by) out.stated_by = ne.stated_by;
    return out;
  }
  if (!tri || tri.coverage !== K.EVALUATED || tri.value === null) {
    // A tri-state the decision did not list is still not evaluated; never fall through to "held".
    return { name, state: 'NOT_EVALUATED', reason: tri?.reason ?? null };
  }
  return { name, state: tri.value === true ? 'BROKE' : 'HELD' };
}

const word = (s) => (s.state === 'NOT_EVALUATED'
  ? `NOT EVALUATED (${s.reason ?? 'no reason recorded'})`
  : (s.state === 'BROKE' ? 'BROKE' : 'held'));

/** Version 1, unchanged: historical `chaingate.check/1` records. */
function explainRefused1(result) {
  const d = result.decision;
  const req = result.request;
  const refusal = (d.results || []).find((x) => x.gate === 'seed-v3:input') || null;
  const structured = {
    explain_version: EXPLAIN_VERSION_1,
    result: 'refused',
    package: req.package,
    version: req.version,
    refusal: refusal ? refusal.detail : null,
    disposition: d.disposition,
    effective: { action: result.effective.action, basis: result.effective.basis },
    not_evaluated: (d.not_evaluated || []).map((m) => ({ where: m.where, name: m.name, reason: m.reason ?? null })),
  };
  if (result.effective.override) structured.effective.override = { ...result.effective.override };
  const text = [
    `${req.package}@${req.version}: ${result.effective.action} — REFUSED: no finding exists for this input`,
    `  reason: ${structured.refusal ?? 'no reason recorded'}`,
    `  policy ${d.policy_version}: an unusable input is decided by on_unusable_input -> ${d.disposition}`,
  ];
  if (result.effective.basis === 'override') {
    text.push(`  override in force (${result.effective.override.scope}): "${result.effective.override.reason}"`
      + ` created ${result.effective.override.created_at}; the evaluated disposition stays ${d.disposition}`);
  }
  text.push('  nothing was evaluated: this is NOT a clean result');
  return { text, structured };
}

/** Version 2: a refusal names what decided it -- the input rule, a recorded advisory pin, or both. */
function explainRefused2(result) {
  const d = result.decision;
  const req = result.request;
  const refusal = (d.results || []).find((x) => x.gate === 'seed-v3:input') || null;
  const bearing = (d.results || []).filter((x) => x.result === d.disposition);
  const structured = {
    explain_version: EXPLAIN_VERSION_2,
    result: 'refused',
    package: req.package,
    version: req.version,
    refusal: refusal ? refusal.detail : null,
    disposition: d.disposition,
    effective: { action: result.effective.action, basis: result.effective.basis },
    decided_by: bearing.map((x) => ({ gate: x.gate, detail: x.detail })),
    not_evaluated: (d.not_evaluated || []).map((m) => ({ where: m.where, name: m.name, reason: m.reason ?? null })),
  };
  if (result.effective.override) structured.effective.override = { ...result.effective.override };
  const text = [
    `${req.package}@${req.version}: ${result.effective.action} — REFUSED: no finding exists for this input`,
    `  reason: ${structured.refusal ?? 'no reason recorded'}`,
    `  evaluated disposition: ${d.disposition} under ${d.policy_version}`,
  ];
  if (result.effective.basis === 'override') {
    text.push(`  override in force (${result.effective.override.scope}): "${result.effective.override.reason}"`
      + ` created ${result.effective.override.created_at}; the evaluated disposition stays ${d.disposition}`);
  }
  text.push('  decided by:');
  for (const x of bearing) text.push(`    ${x.gate}: ${x.detail}`);
  // The input itself is the refusal named above; anything else not evaluated (a failed advisory lookup) is listed.
  const more = structured.not_evaluated.filter((m) => !(m.where === 'policy' && m.name === 'input'));
  if (more.length) {
    text.push(`  NOT EVALUATED (${more.length}) — none of these is a clean result:`);
    for (const m of more) text.push(`    ${m.where} ${m.name}: ${m.reason ?? 'no reason recorded'}`);
  }
  text.push('  no finding was evaluated: this is NOT a clean result');
  return { text, structured };
}

function explainEvaluated(result, explainVersion) {
  const d = result.decision;
  const f = result.finding;
  const req = result.request;
  const placement = result.candidate.placement;

  const groups = K.CHANNEL_A_GROUPS.map((g) => stateOf(d, 'channel_a.group', g, f.channel_a.groups[g]));
  const constituents = K.PUBLISHER_CONSTITUENTS.map((c) => stateOf(d, 'channel_a.publisher_constituent', c,
    f.channel_a.publisher_constituents[c]));
  const predicates = K.DAC_PREDICATES.map((p) => stateOf(d, 'dac_trajectory.predicate', p,
    f.dac_trajectory.predicates[p]));
  const bearing = (d.results || []).filter((x) => x.result === d.disposition);
  const notEvaluated = [
    ...groups.filter((s) => s.state === 'NOT_EVALUATED').map((s) => ({ where: 'channel_a.group', ...s })),
    ...constituents.filter((s) => s.state === 'NOT_EVALUATED')
      .map((s) => ({ where: 'channel_a.publisher_constituent', ...s })),
    ...predicates.filter((s) => s.state === 'NOT_EVALUATED')
      .map((s) => ({ where: 'dac_trajectory.predicate', ...s })),
  ].map(({ where, name, reason }) => ({ where, name, reason }));
  const evaluatedCount = [...groups, ...constituents, ...predicates].filter((s) => s.state !== 'NOT_EVALUATED').length;

  const structured = {
    explain_version: explainVersion,
    result: 'evaluated',
    package: req.package,
    version: req.version,
    effective: { action: result.effective.action, basis: result.effective.basis },
    disposition: d.disposition,
    policy_version: d.policy_version,
    placement: { kind: placement.kind, reason: placement.reason ?? null },
    decided_by: bearing.map((x) => ({ gate: x.gate, detail: x.detail })),
    results: (d.results || []).map((x) => ({ gate: x.gate, result: x.result, detail: x.detail })),
    channel_a: { groups, publisher_constituents: constituents },
    dac_trajectory: { predicates },
    not_evaluated: notEvaluated,
    evidence_complete: d.evidence_complete,
    evaluated_any: evaluatedCount > 0,
  };
  if (result.effective.override) structured.effective.override = { ...result.effective.override };

  const text = [];
  text.push(`${req.package}@${req.version}: ${result.effective.action}`
    + (result.effective.basis === 'override' ? ' (by OVERRIDE)' : ''));
  if (result.effective.basis === 'override') {
    const o = result.effective.override;
    text.push(`  override (${o.scope}): "${o.reason}" created ${o.created_at}`);
    text.push(`  the EVALUATED disposition is ${d.disposition}; the override does not change it`);
  }
  text.push(`  evaluated disposition: ${d.disposition} under ${d.policy_version}`);
  text.push(`  placement: ${placement.kind}${placement.reason ? ` — ${placement.reason}` : ''}`);
  text.push('  decided by:');
  for (const x of bearing) text.push(`    ${x.gate}: ${x.detail}`);
  text.push('  all results:');
  for (const x of d.results || []) text.push(`    [${x.result}] ${x.gate}: ${x.detail}`);
  text.push('  channel-a witness groups:');
  for (const s of groups) {
    text.push(`    ${s.name}: ${word(s)}`);
    if (s.name === 'publisher') {
      for (const c of constituents) text.push(`      constituent ${c.name}: ${word(c)}`);
    }
  }
  text.push('  dac trajectory predicates:');
  for (const s of predicates) text.push(`    ${s.name}: ${word(s)}`);
  if (notEvaluated.length) {
    text.push(`  NOT EVALUATED (${notEvaluated.length}) — none of these is a clean result:`);
    for (const m of notEvaluated) text.push(`    ${m.where} ${m.name}: ${m.reason ?? 'no reason recorded'}`);
  }
  if (!structured.evaluated_any) {
    text.push('  nothing in this finding was evaluated: this is NOT a clean result');
  } else if (!d.evidence_complete) {
    text.push('  evidence incomplete: the result above is NOT a clean bill of health');
  }
  return { text, structured };
}

/**
 * Explain one check result. Pure: `result` is only read, never written, and nothing outside it is
 * consulted. Throws on a shape it cannot explain (a tool error has no evaluation to explain).
 */
function explain(result) {
  if (!result || typeof result !== 'object') throw new TypeError('explain: result must be an object');
  const version = typeof result.schema === 'string' && Object.hasOwn(EXPLAIN_VERSION_FOR_SCHEMA, result.schema)
    ? EXPLAIN_VERSION_FOR_SCHEMA[result.schema] : null;
  if (version === null) {
    throw new TypeError(`explain: no explanation for check schema ${JSON.stringify(result.schema ?? null)}; `
      + `this runtime explains ${Object.keys(EXPLAIN_VERSION_FOR_SCHEMA).join(' and ')}`);
  }
  if (result.result === 'refused') return version === EXPLAIN_VERSION_1 ? explainRefused1(result) : explainRefused2(result);
  if (result.result === 'evaluated') {
    if (!has(result, 'finding') || !has(result, 'candidate') || !has(result, 'decision')) {
      throw new TypeError('explain: an evaluated result needs finding, candidate and decision');
    }
    return explainEvaluated(result, version);
  }
  throw new TypeError(`explain: nothing to explain for result ${JSON.stringify(result.result)}`);
}

export { EXPLAIN_VERSION, EXPLAIN_VERSION_1, EXPLAIN_VERSION_2, EXPLAIN_VERSION_FOR_SCHEMA, explain };
export default { EXPLAIN_VERSION, EXPLAIN_VERSION_1, EXPLAIN_VERSION_2, EXPLAIN_VERSION_FOR_SCHEMA, explain };
