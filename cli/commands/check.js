// `chaingate check <package>@<version> --packument <file>` — a FRESH evaluation.
// 0.1.5: `--tarball <file>` also runs the manifest check and the five tarball static checks offline over a
// LOCAL archive (the walker's keep list from the packument's manifest, else from the tarball's own package.json, stated) and
// REPORTS their rows in a `tarball` member: the record becomes `chaingate.check/4` (/3 plus that optional member). The tarball
// rows never change the decision, the effective action or the exit code in 0.1.5; a CI consumer may read tarball.disposition.
//
// It evaluates the candidate the proxy would hand the gate from that packument document, against
// the active seed, under the operator's policy, through the gate's own evaluation path. It never
// reads a stored decision: `gate_decisions` rows carry no seed/rule/policy identity and can never be
// bound. Offline: the document is a local file and the seed is local; nothing is fetched.
//
// Exit code follows `effective.action`: 0 ALLOW, 2 WARN, 3 BLOCK; 4 tool error.
import { existsSync, readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { fmt, colorDisposition } from '../format.js';
import { createTarWalker } from '../../proxy/tar-walk.js';
import { hookDict, mcRow } from '../../proxy/manifest-check.js';
import { keepListFor, staticRows, STATIC_CHECKS_VERSION, createMemberTally, FACTS_LIMITS } from '../../proxy/static-checks.js';
import { withRole } from '../../gates/row-class.js';
import { resolvePaths } from '../paths.js';
import { openWitnessDB } from '../../witness/db.js';
import { loadConfig } from '../../proxy/config.js';
import { openSeed, TRUST_AUTHENTICATED, TRUST_UNSIGNED_DEV } from '../../seed/v3/reader.js';
import { CHAINGATE_SEED_PUBKEY_B64 } from '../../witness/seed_verify.js';
import { createSeedCache, DEFAULT_SEED_CACHE_WAIT_MS } from '../../proxy/seed-cache.js';
import { shardSource } from '../seed-shards.js';
import {
  buildCheckRecord, toolErrorRecord, inputFromPackument, exitCodeFor, EXIT_TOOL_ERROR, withTarball,
} from '../check-record.js';

const HERE = dirname(fileURLToPath(import.meta.url));
const PKG = JSON.parse(readFileSync(join(HERE, '..', '..', 'package.json'), 'utf8'));
const TOOL = Object.freeze({ name: PKG.name, version: PKG.version });

export const USAGE = 'Usage: chaingate check <package>@<version> --packument <file> [--tarball <file>] [--json] [--scope user|project]\n'
  + '  Evaluates the release described by that packument document against the active seed.\n'
  + '  --tarball <file>: also reads that local archive offline (the manifest check and the tarball static checks); the rows are\n'
  + '  reported in the record\'s tarball member (chaingate.check/4) and never change the decision or the exit code.\n'
  + '  Exit codes: 0=ALLOW, 2=WARN, 3=BLOCK, 4=tool error (exit follows the effective action).';

export function parseArgs(args) {
  const opts = { scope: 'user', json: false, target: null, packument: null, tarball: null, errors: [] };
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a === '--scope') { if (args[i + 1]) opts.scope = args[++i]; else opts.errors.push('--scope needs a value'); }
    else if (a === '--json') opts.json = true;
    else if (a === '--packument') {
      if (args[i + 1] && !args[i + 1].startsWith('--')) opts.packument = args[++i];
      else opts.errors.push('--packument needs a file');
    } else if (a === '--tarball') {
      if (args[i + 1] && !args[i + 1].startsWith('--')) opts.tarball = args[++i];
      else opts.errors.push('--tarball needs a file');
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

/**
 * Resolve the active seed ONCE and open it read-only, as the proxy does at start-up. `seams` exist for the seed cache tests (a
 * toy root of 3 bits under a fixture key, a fixed clock, a local host); production passes none.
 */
function openActiveSeed(env, seams = {}) {
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
  try {
    seed = openSeed(config.seedV3Path, { trust, pubkey: seams.seedKey ?? CHAINGATE_SEED_PUBKEY_B64,
      ...(seams.shardBits ? { shardBits: seams.shardBits } : {}), ...(seams.now ? { now: seams.now } : {}) });
  } catch (e) {
    throw new ToolError('seed_refused', e.message);
  }
  return { seed, config, policy };
}

/**
 * Since 0.1.6: the pins feed overlay of the witness DB the proxy for this scope uses, as a lookup for the gate (the proxy and
 * `check` see the same pins). No database: no overlay. A read that fails throws, and the gate records a failed pin lookup.
 */
function overlayFor(witnessDbPath) {
  if (!witnessDbPath || !existsSync(witnessDbPath)) return null;
  return (name, version) => {
    let db;
    try { db = openWitnessDB(witnessDbPath, { readonly: true }); return db.advisoryPinFor(name, version); }
    finally { try { db?.close(); } catch { /* already closed */ } }
  };
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

/** The walk's root package.json (Linux view) parsed, or null; a UTF-8 BOM is dropped as npm does. */
function parsedPackageJson(walk) {
  if (!walk?.ok || !walk.packageJson) return null;
  try { const pj = JSON.parse(walk.packageJson.toString('utf8').replace(/^\uFEFF/, '')); return pj !== null && typeof pj === 'object' && !Array.isArray(pj) ? pj : null; } catch { return null; }
}

/**
 * 0.1.5: the manifest check and the static checks over a LOCAL tarball, offline. The keep list comes from the
 * packument's manifest for this version when it has one (what npm acts on), else from the tarball's own package.json as the
 * walker's keep function; both are stated. Rows carry their 1.2 roles (a static WARN is NOTE). Never a verdict, never a BLOCK.
 */
async function evaluateTarball({ file, manifest }) {
  let bytes;
  try { bytes = readFileSync(file); } catch (e) {
    throw new ToolError('tarball_unreadable', `cannot read ${file}: ${e.code || e.message}`);
  }
  const source = { kind: 'tarball-file', path: file, sha256: createHash('sha256').update(bytes).digest('hex'), bytes: bytes.length };
  const man = manifest && typeof manifest === 'object' && !Array.isArray(manifest) ? manifest : null;
  const kl = man ? keepListFor(man) : null;
  // static-checks-1.8: S8 and S9 read the member facts of every archive member, gathered on the first walk as the proxy's armed walk does
  const tally = createMemberTally();
  const walkWith = async (keep, onMember = null) => {
    const walker = createTarWalker({ keep, ...(onMember ? { onMember, memberWindow: FACTS_LIMITS.windowBytes } : {}) });
    for (let i = 0; i < bytes.length; i += 65536) walker.write(bytes.subarray(i, i + 65536));
    return walker.end();
  };
  let walk = await walkWith(man ? kl.paths : (pj) => keepListFor(pj).paths, tally.onMember);
  const pj = parsedPackageJson(walk);
  let candidates = man ? kl.paths.length : (pj ? keepListFor(pj).paths.length : 0);
  // offline, the archive is at hand: the targets only the tarball's package.json names (a hook the registry entry lacks: MC's case)
  // are read too, by a second walk over the same bytes, so a loader hidden that way is a row and not only "not kept"
  if (man && walk.ok && pj) {
    const extra = keepListFor(pj).paths.filter((p) => !kl.roles[p]);
    if (extra.length) {
      const w2 = await walkWith(extra); candidates += extra.length;
      if (w2.ok) walk = { ...walk, files: [...walk.files, ...w2.files], notKept: [...walk.notKept, ...w2.notKept] };
    }
  }
  const rows = [mcRow(walk, man ? hookDict(man) : undefined),
    ...staticRows({ manifest: man, packageJson: pj, walk, armed: 'chaingate check --tarball',
      ...(({ members, over }) => ({ members, membersOver: over }))(tally.result()) }).map(withRole)];
  const disposition = rows.some((r) => r.result === 'WARN') ? 'WARN' : rows.some((r) => r.result === 'ALLOW' || r.result === 'NOTE') ? 'ALLOW' : 'SKIP';
  return { source, static_checks_version: STATIC_CHECKS_VERSION, walk: walk.ok ? { ok: true } : { ok: false, reason: walk.reason },
    keep_list: { source: man ? 'registry manifest' : 'tarball package.json', candidates },
    rows, disposition };
}

/**
 * Run a check and return { record, exit }. No output; the caller prints. Exported for `why` and for
 * tests, which call it in-process with an explicit environment. Async since 0.1.5 (the tarball walk streams).
 */
export async function runCheck({ name, version, packument, tarball = null, scope = 'user', env = process.env, cwd = process.cwd(),
  seams = {} }) {
  const request = { package: name, version };
  let seed = null;
  try {
    const { doc, source } = readPackument(packument, name);
    request.source = source;
    const paths = resolvePaths(scope, cwd, env);
    const senv = scopedEnv(paths, env);
    const active = openActiveSeed(senv, seams);
    seed = active.seed;
    // Since 0.1.6: on a seed cache, the package's bucket is fetched first when the cache does not hold it, waiting at most the
    // proxy's bound; one that has not arrived leaves the package not checked by the seed, as in the proxy
    if (seed.shards && active.config.seedCacheUrl) {
      const sc = createSeedCache({ get: seams.get ?? shardSource(active.config.seedCacheUrl), cachePath: active.config.seedV3Path,
        seedKey: seams.seedKey ?? null, ...(seams.shardBits ? { bits: seams.shardBits } : {}), ...(seams.now ? { now: seams.now } : {}),
        waitMs: seams.waitMs ?? DEFAULT_SEED_CACHE_WAIT_MS });
      sc.attach(seed);
      await sc.need(name);
    }
    const override = lookupOverride(active.config.witnessDbPath, name, version);
    const record = buildCheckRecord({
      // A seed named by CHAINGATE_SEED_V3 is not the active bundle, so the bundle id would describe a
      // different file: report none rather than a wrong one.
      seed, bundleId: senv.CHAINGATE_SEED_V3 ? null : (active.config.seedV3BundleId ?? null), policy: active.policy,
      domainVersionCount: active.config.domainVersionCount,
      input: inputFromPackument(doc, name, version), request, override, tool: TOOL,
      pinOverlay: overlayFor(active.config.witnessDbPath),
    });
    if (tarball) {
      const versions = doc.versions && typeof doc.versions === 'object' && !Array.isArray(doc.versions) ? doc.versions : {};
      withTarball(record, await evaluateTarball({ file: tarball, manifest: Object.hasOwn(versions, version) ? versions[version] : null }));
    }
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
  const t = record.tarball;
  if (t) {
    console.log(`  tarball ${t.source.path} sha256 ${t.source.sha256.slice(0, 16)}... : ${colorDisposition(t.disposition)} over the tarball rows `
      + `(${t.walk.ok ? 'walked' : `not walked: ${t.walk.reason}`}; keep list from the ${t.keep_list.source}; ${t.static_checks_version})`);
    for (const r of t.rows) console.log(`    ${r.gate}: ${r.result} -- ${r.detail}`);
    console.log(fmt.dim('  the tarball rows are reported, never the exit code (0.1.5); a static row is contributing (NOTE)'));
  }
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
  const { record, exit } = await runCheck({ name: parsed.name, version: parsed.version, packument: opts.packument,
    tarball: opts.tarball, scope: opts.scope });
  if (opts.json) console.log(JSON.stringify(record, null, 2));
  else printHuman(record);
  return exit;
}
