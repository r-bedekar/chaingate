// `chaingate check <package>@<version> --packument <file>` — a FRESH evaluation (CFT-04 R4).
//
// It evaluates the candidate the proxy would hand the gate from that packument document, against
// the active seed, under the operator's policy, through the gate's own evaluation path. It never
// reads a stored decision: `gate_decisions` rows carry no seed/rule/policy identity and can never be
// bound (plan §2). Offline: the document is a local file and the seed is local; nothing is fetched.
//
// Exit code follows `effective.action`: 0 ALLOW, 2 WARN, 3 BLOCK; 4 tool error.
import { existsSync, readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { fmt, colorDisposition } from '../format.js';
import { resolvePaths } from '../paths.js';
import { openWitnessDB } from '../../witness/db.js';
import { loadConfig } from '../../proxy/config.js';
import { openSeed, TRUST_AUTHENTICATED, TRUST_UNSIGNED_DEV } from '../../seed/v3/reader.js';
import { CHAINGATE_SEED_PUBKEY_B64 } from '../../witness/seed_verify.js';
import {
  buildCheckRecord, toolErrorRecord, inputFromPackument, exitCodeFor, EXIT_TOOL_ERROR,
} from '../check-record.js';

const HERE = dirname(fileURLToPath(import.meta.url));
const PKG = JSON.parse(readFileSync(join(HERE, '..', '..', 'package.json'), 'utf8'));
const TOOL = Object.freeze({ name: PKG.name, version: PKG.version });

export const USAGE = 'Usage: chaingate check <package>@<version> --packument <file> [--json] [--scope user|project]\n'
  + '  Evaluates the release described by that packument document against the active seed.\n'
  + '  Exit codes: 0=ALLOW, 2=WARN, 3=BLOCK, 4=tool error (exit follows the effective action).';

export function parseArgs(args) {
  const opts = { scope: 'user', json: false, target: null, packument: null, errors: [] };
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a === '--scope') { if (args[i + 1]) opts.scope = args[++i]; else opts.errors.push('--scope needs a value'); }
    else if (a === '--json') opts.json = true;
    else if (a === '--packument') {
      if (args[i + 1] && !args[i + 1].startsWith('--')) opts.packument = args[++i];
      else opts.errors.push('--packument needs a file');
    } else if (a.startsWith('-')) opts.errors.push(`unknown option ${a}`);
    else if (!opts.target) opts.target = a;
    else opts.errors.push(`unexpected argument ${a}`);
  }
  return opts;
}

export function parseTarget(target) {
  if (!target) return null;
  const at = target.lastIndexOf('@');
  if (at <= 0 || at === target.length - 1) return null;
  return { name: target.slice(0, at), version: target.slice(at + 1) };
}

/** The environment the proxy for this scope runs with (init.js childEnv): same base, same witness DB. */
function scopedEnv(paths, env = process.env) {
  return { ...env, CHAINGATE_HOME: paths.base, CHAINGATE_WITNESS_DB: env.CHAINGATE_WITNESS_DB || paths.witnessDb };
}

class ToolError extends Error {
  constructor(code, message) { super(message); this.code = code; }
}

/** Read and parse the packument file; its bytes are hashed exactly as read. */
function readPackument(file, packageName) {
  let bytes;
  try { bytes = readFileSync(file); } catch (e) {
    throw new ToolError('packument_unreadable', `cannot read ${file}: ${e.code || e.message}`);
  }
  const source = { kind: 'packument-file', path: file, sha256: createHash('sha256').update(bytes).digest('hex') };
  let doc;
  try { doc = JSON.parse(bytes.toString('utf8')); } catch (e) {
    throw Object.assign(new ToolError('packument_invalid_json', `${file} is not JSON: ${e.message}`), { source });
  }
  if (!doc || typeof doc !== 'object' || Array.isArray(doc)) {
    throw Object.assign(new ToolError('packument_not_object', `${file} is not a packument object`), { source });
  }
  if (doc.name !== packageName) {
    throw Object.assign(new ToolError('packument_name_mismatch',
      `${file} describes ${JSON.stringify(doc.name ?? null)}, not ${JSON.stringify(packageName)}`), { source });
  }
  return { doc, source };
}

/** Resolve the active seed ONCE and open it read-only, as the proxy does at start-up. */
function openActiveSeed(env) {
  let config;
  try { config = loadConfig(env); } catch (e) {
    throw new ToolError('config_unusable', e.message);
  }
  if (!config.seedV3Path) {
    throw new ToolError('no_active_seed', 'no v3 seed bundle is active. Run `chaingate init --seed <bundle>` first.');
  }
  if (!['authenticated', 'unsigned-development'].includes(config.seedV3Trust)) {
    throw new ToolError('config_unusable', `seed trust must be 'authenticated' or 'unsigned-development', `
      + `got ${JSON.stringify(config.seedV3Trust)}`);
  }
  const policy = { on_unusable_input: config.policyOnUnusableInput, on_no_evidence: config.policyOnNoEvidence };
  const unset = Object.entries(policy).filter(([, v]) => !v).map(([k]) => k);
  if (unset.length) {
    throw new ToolError('policy_not_configured', `policy ${unset.join(' and ')} is not configured: an unresolved `
      + 'policy produces no disposition. Run `chaingate init` to record it.');
  }
  const trust = config.seedV3Trust === 'unsigned-development' ? TRUST_UNSIGNED_DEV : TRUST_AUTHENTICATED;
  let seed;
  try { seed = openSeed(config.seedV3Path, { trust, pubkey: CHAINGATE_SEED_PUBKEY_B64 }); } catch (e) {
    throw new ToolError('seed_refused', e.message);
  }
  return { seed, config, policy };
}

/** The exact-version override, if any, from the witness DB the proxy for this scope uses. */
function lookupOverride(witnessDbPath, name, version) {
  if (!witnessDbPath || !existsSync(witnessDbPath)) return null;
  let db;
  try {
    db = openWitnessDB(witnessDbPath, { readonly: true });
    return db.getOverride(name, version) || null;
  } catch (e) {
    throw new ToolError('override_store_unreadable', `cannot read overrides from ${witnessDbPath}: ${e.message}`);
  } finally { try { db?.close(); } catch { /* already closed */ } }
}

/**
 * Run a check and return { record, exit }. No output; the caller prints. Exported for `why` and for
 * tests, which call it in-process with an explicit environment.
 */
export function runCheck({ name, version, packument, scope = 'user', env = process.env, cwd = process.cwd() }) {
  const request = { package: name, version };
  let seed = null;
  try {
    const { doc, source } = readPackument(packument, name);
    request.source = source;
    const paths = resolvePaths(scope, cwd, env);
    const senv = scopedEnv(paths, env);
    const active = openActiveSeed(senv);
    seed = active.seed;
    const override = lookupOverride(active.config.witnessDbPath, name, version);
    const record = buildCheckRecord({
      // A seed named by CHAINGATE_SEED_V3 is not the active bundle, so the bundle id would describe a
      // different file: report none rather than a wrong one.
      seed, bundleId: senv.CHAINGATE_SEED_V3 ? null : (active.config.seedV3BundleId ?? null), policy: active.policy,
      domainVersionCount: active.config.domainVersionCount,
      input: inputFromPackument(doc, name, version), request, override, tool: TOOL,
    });
    return { record, exit: exitCodeFor(record) };
  } catch (e) {
    if (e.source && !request.source) request.source = e.source;
    const code = e instanceof ToolError ? e.code : 'internal_error';
    const record = toolErrorRecord({ tool: TOOL, request, code, message: e.message });
    return { record, exit: EXIT_TOOL_ERROR };
  } finally {
    try { seed?.close(); } catch { /* already closed */ }
  }
}

export function printHuman(record) {
  if (record.result === 'tool_error') {
    console.error(fmt.fail(`${record.request.package}@${record.request.version}: tool error `
      + `(${record.error.code}): ${record.error.message}`));
    return;
  }
  const [head, ...rest] = record.explanation.text;
  const action = record.effective.action;
  console.log(head.replace(action, colorDisposition(action)));
  for (const line of rest) console.log(line);
  const s = record.seed;
  console.log(fmt.dim(`  seed ${s.bundle_id ?? '(named directly)'} sha256 ${s.sha256.slice(0, 16)}... `
    + `trust ${s.trust}${s.authenticated ? '' : ' (NOT authenticated)'}`));
}

export default async function check(args) {
  const opts = parseArgs(args);
  const parsed = parseTarget(opts.target);
  if (!parsed || !opts.packument || opts.errors.length) {
    for (const e of opts.errors) console.error(`chaingate check: ${e}`);
    if (parsed && !opts.packument && !opts.errors.length) {
      console.error('chaingate check: --packument <file> is required. A check evaluates a release; it never '
        + 'reports a stored decision (see `chaingate why --cached`).');
    }
    console.error(USAGE);
    return EXIT_TOOL_ERROR;
  }
  const { record, exit } = runCheck({ name: parsed.name, version: parsed.version, packument: opts.packument,
    scope: opts.scope });
  if (opts.json) console.log(JSON.stringify(record, null, 2));
  else printHuman(record);
  return exit;
}
