// `chaingate why` — explain, never re-decide (CFT-04 R6).
//
//   why <package>@<version> --packument <file>   evaluate through `check`, then explain that result
//   why --from <check.json>                      explain a SAVED check output; evaluates nothing
//   why <package>@<version> --cached             show the legacy stored row, labelled UNBOUND, exit 4
//
// The explanation is `explain()`, a pure function of the check result. `--cached` is an approved
// LEGACY DIAGNOSTIC (U-01 approval, clarification 3): a `gate_decisions` row records no seed, rule
// or policy identity, so it does NOT meet R4's identity requirement and is never shown as current.
import { existsSync, readFileSync } from 'node:fs';
import { fmt, renderGate } from '../format.js';
import { resolvePaths } from '../paths.js';
import { openWitnessDB } from '../../witness/db.js';
import { explain } from '../../seed/v3/explain.js';
import { CHECK_SCHEMA_IDS, EXIT_TOOL_ERROR, recordCompatibility } from '../check-record.js';
import { runCheck, parseTarget } from './check.js';

export const UNBOUND_LABEL = 'CACHED — UNBOUND: produced without recorded seed/rule/policy identities; '
  + 'not a current evaluation';

export const USAGE = 'Usage:\n'
  + '  chaingate why <package>@<version> --packument <file> [--json]   evaluate, then explain\n'
  + '  chaingate why --from <check.json> [--json]                      explain a saved check output\n'
  + '  chaingate why <package>@<version> --cached [--json]             legacy stored row (UNBOUND, exit 4)';

function parseArgs(args) {
  const opts = { scope: 'user', json: false, target: null, packument: null, from: null, cached: false, errors: [] };
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    const value = () => (args[i + 1] && !args[i + 1].startsWith('--') ? args[++i] : (opts.errors.push(`${a} needs a value`), null));
    if (a === '--scope') opts.scope = value() ?? opts.scope;
    else if (a === '--json') opts.json = true;
    else if (a === '--packument') opts.packument = value();
    else if (a === '--from') opts.from = value();
    else if (a === '--cached') opts.cached = true;
    else if (a.startsWith('-')) opts.errors.push(`unknown option ${a}`);
    else if (!opts.target) opts.target = a;
    else opts.errors.push(`unexpected argument ${a}`);
  }
  const modes = [opts.packument !== null, opts.from !== null, opts.cached].filter(Boolean).length;
  if (modes !== 1) opts.errors.push('choose exactly one of --packument, --from, --cached');
  if (opts.from === null && !parseTarget(opts.target)) opts.errors.push('a <package>@<version> is required');
  if (opts.from !== null && opts.target) opts.errors.push('--from takes no <package>@<version>');
  return opts;
}

function print(expl, json) {
  if (json) console.log(JSON.stringify(expl, null, 2));
  else for (const line of expl.text) console.log(line);
}

/** Explain a saved record. Evaluates nothing; reads only the file. */
export function explainSaved(file) {
  let rec;
  try { rec = JSON.parse(readFileSync(file, 'utf8')); } catch (e) {
    return { error: `cannot read a check result from ${file}: ${e.code || e.message}` };
  }
  if (!rec || !CHECK_SCHEMA_IDS.includes(rec.schema)) {
    return { error: `${file} is not a ${CHECK_SCHEMA_IDS.join(' or ')} result (schema ${JSON.stringify(rec?.schema ?? null)})` };
  }
  if (rec.result === 'tool_error') {
    return { error: `${file} is a tool error (${rec.error?.code}): nothing was evaluated, so there is nothing to explain` };
  }
  // A supported schema id is not enough: the policy, explanation, detection and seed versions must be the combination
  // that schema carries, and a refused explanation's deciding rows must be the decision's (U-05 Amendment 1).
  const problems = recordCompatibility(rec);
  if (problems.length) return { error: `${file} is not a record this chaingate reads: ${problems.join('; ')}` };
  try { return { explanation: explain(rec) }; } catch (e) {
    return { error: `${file}: ${e.message}` };
  }
}

function showCached(parsed, opts) {
  const paths = resolvePaths(opts.scope);
  const dbPath = process.env.CHAINGATE_WITNESS_DB || paths.witnessDb;
  if (!existsSync(dbPath)) {
    console.error(fmt.fail(`No witness database at ${dbPath}.`));
    return EXIT_TOOL_ERROR;
  }
  const db = openWitnessDB(dbPath, { readonly: true });
  try {
    const row = db.getLatestDecision(parsed.name, parsed.version);
    if (opts.json) {
      console.log(JSON.stringify({ label: 'CACHED-UNBOUND', note: UNBOUND_LABEL,
        package: parsed.name, version: parsed.version, cached: row || null }, null, 2));
    } else {
      console.log(fmt.yellow ? fmt.yellow(UNBOUND_LABEL) : UNBOUND_LABEL);
      if (!row) {
        console.log(`  no stored row for ${parsed.name}@${parsed.version}`);
      } else {
        console.log(`  ${parsed.name}@${parsed.version}  stored disposition ${row.disposition}  at ${row.decided_at}`);
        for (const gate of row.gates_fired || []) console.log(renderGate(gate));
      }
      console.log(`  For a current evaluation: chaingate check ${parsed.name}@${parsed.version} --packument <file>`);
    }
  } finally { db.close(); }
  // Exit 4 whether or not a row exists: a cached row is never a check result.
  return EXIT_TOOL_ERROR;
}

export default async function why(args) {
  const opts = parseArgs(args);
  if (opts.errors.length) {
    for (const e of opts.errors) console.error(`chaingate why: ${e}`);
    console.error(USAGE);
    return EXIT_TOOL_ERROR;
  }
  if (opts.from !== null) {
    const r = explainSaved(opts.from);
    if (r.error) { console.error(fmt.fail(r.error)); return EXIT_TOOL_ERROR; }
    print(r.explanation, opts.json);
    return 0;
  }
  const parsed = parseTarget(opts.target);
  if (opts.cached) return showCached(parsed, opts);

  const { record } = runCheck({ name: parsed.name, version: parsed.version, packument: opts.packument,
    scope: opts.scope });
  if (record.result === 'tool_error') {
    console.error(fmt.fail(`${parsed.name}@${parsed.version}: tool error (${record.error.code}): ${record.error.message}`));
    return EXIT_TOOL_ERROR;
  }
  print(record.explanation, opts.json);
  return 0;
}
