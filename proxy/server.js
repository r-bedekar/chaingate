import http from 'node:http';
import { mkdirSync, readFileSync, realpathSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { pipeline } from 'node:stream/promises';

import { loadConfig } from './config.js';
import {
  fetchPackument,
  fetchTarball,
  RELAY_RESPONSE_HEADERS,
  UpstreamTimeoutError,
  UpstreamError,
} from './registry.js';
import { openWitnessDB, isOverrideRow } from '../witness/db.js';
import { DepCache } from '../witness/dep-cache.js';
import { createWitness } from '../witness/store.js';
import { createGateRunner, DEFAULT_GATE_MODULES } from '../gates/index.js';
import { createSeedV3Gate } from '../seed/v3/gate.js';
import { openSeed, TRUST_AUTHENTICATED, TRUST_UNSIGNED_DEV } from '../seed/v3/reader.js';
import { CHAINGATE_SEED_PUBKEY_B64, CHAINGATE_SEED_PUBKEY_FINGERPRINT } from '../witness/seed_verify.js';
import { rewritePackument } from '../gates/rewriter.js';
import { createUnstoredBlocks } from './unstored-blocks.js';
import { createLogBoundary } from './log-boundary.js';
import { storageReport } from './storage-health.js';
import { createDepFetcher } from './dep-fetcher.js';

// Read our own package version once at module-load — used by `/_chaingate/self`
// so `chaingate doctor` can confirm the running proxy matches the installed CLI.
const __dirname = dirname(fileURLToPath(import.meta.url));
let PROXY_VERSION = 'unknown';
try {
  const pkg = JSON.parse(readFileSync(join(__dirname, '..', 'package.json'), 'utf8'));
  if (pkg?.version) PROXY_VERSION = pkg.version;
} catch { /* fall through with 'unknown' */ }

// Canonical package name form: decode %2F once so that /@babel/core and
// /@babel%2Fcore collide on the same packages.package_name row and the
// same gate_decisions lookup key.
export function normalizePackageName(raw) {
  if (typeof raw !== 'string') return raw;
  return raw.replace(/%2[Ff]/g, '/');
}

// Parse `<basename>-<version>.tgz` → version string, or null if it doesn't match.
// Uses the canonical package name to derive the expected basename — safer than
// a greedy regex on filenames that contain dashes.
export function parseTarballVersion(canonicalName, filename) {
  if (typeof filename !== 'string' || !filename.endsWith('.tgz')) return null;
  const basename = canonicalName.startsWith('@')
    ? canonicalName.slice(canonicalName.indexOf('/') + 1)
    : canonicalName;
  const prefix = `${basename}-`;
  if (!filename.startsWith(prefix)) return null;
  return filename.slice(prefix.length, -'.tgz'.length);
}

// URL classifier — accepts '/@scope/name' and '/@scope%2Fname' forms.
export function classify(pathname) {
  if (!pathname || pathname === '/' || pathname === '/-/ping') {
    return { kind: 'unknown' };
  }
  const p = pathname.replace(/^\/+/, '');

  const tarballScoped = p.match(/^(@[^/]+(?:\/|%2[Ff])[^/]+)\/-\/([^/]+\.tgz)$/);
  if (tarballScoped) {
    return { kind: 'tarball', name: tarballScoped[1], filename: tarballScoped[2] };
  }
  const tarballUnscoped = p.match(/^([^/@][^/]*)\/-\/([^/]+\.tgz)$/);
  if (tarballUnscoped) {
    return { kind: 'tarball', name: tarballUnscoped[1], filename: tarballUnscoped[2] };
  }

  const packScoped = p.match(/^(@[^/]+(?:\/|%2[Ff])[^/]+)$/);
  if (packScoped) {
    return { kind: 'packument', name: packScoped[1] };
  }
  const packUnscoped = p.match(/^([^/@][^/]*)$/);
  if (packUnscoped) {
    return { kind: 'packument', name: packUnscoped[1] };
  }

  return { kind: 'unknown' };
}

// U-05 Amendment 2 (P4a/P5a): a version of this package is already BLOCKed and the response that removes it could not be
// built or sent. The original document must not be served instead -- it carries the very version the gates refused -- so
// this one request fails; other packages and later requests are unaffected. Headers already sent: cut the response.
function refuseUnenforceable(res, packageName, detail) {
  if (res.headersSent) {
    if (!res.writableEnded) res.destroy(new Error(detail));
    return;
  }
  writeJson(res, 502, {
    error: 'chaingate_enforcement_failed',
    package: packageName,
    detail: `a version of ${packageName} is BLOCKed and chaingate could not remove it from the response `
      + `(${detail}); the document is not served`,
  });
}

// U-05 Amendment 3 (P3/P5b): no decision could be made and the configured failure policy refuses.
function refuseNoDecision(res, packageName, detail) {
  if (res.headersSent) {
    if (!res.writableEnded) res.destroy(new Error(detail));
    return;
  }
  writeJson(res, 502, {
    error: 'chaingate_enforcement_failed',
    package: packageName,
    detail: `no decision could be made for ${packageName} (${detail}); the configured failure policy `
      + '(on_unusable_input: BLOCK) refuses it',
  });
}

// U-05 Amendment 3 (Rule K): a failure decision never makes a remembered BLOCK servable.
function preserveKnownBlock(packageName, version, decision, known) {
  return {
    disposition: 'BLOCK',
    results: [{ gate: 'chaingate', result: 'BLOCK',
      detail: `known BLOCK preserved: this proxy process decided BLOCK for ${packageName}@${version} and could not `
        + `store it (${known.detail}); a failure decision cannot make it servable` },
    ...(Array.isArray(decision?.results) ? decision.results : [])],
    persisted: false,
    evaluated: false,
  };
}

function writeJson(res, status, obj) {
  const body = JSON.stringify(obj);
  res.writeHead(status, {
    'content-type': 'application/json; charset=utf-8',
    'content-length': Buffer.byteLength(body),
  });
  res.end(body);
}

function relayResponseHeaders(upstreamHeaders) {
  const out = {};
  if (!upstreamHeaders) return out;
  for (const key of RELAY_RESPONSE_HEADERS) {
    const v = upstreamHeaders[key] ?? upstreamHeaders[key.toLowerCase()];
    if (v != null) out[key] = v;
  }
  return out;
}

async function streamUpstream(res, upstream, statusCode) {
  const headers = relayResponseHeaders(upstream.headers);
  res.writeHead(statusCode, headers);
  if (statusCode === 304 || statusCode === 204) {
    await upstream.body.dump();
    res.end();
    return;
  }
  try {
    await pipeline(upstream.body, res);
  } catch (err) {
    if (!res.writableEnded) res.destroy(err);
  }
}

// Buffer upstream packument, run it through the witness, then either:
//   - rewrite + serve (if the witness returned any BLOCK disposition)
//   - serve original bytes (byte-for-byte fidelity when nothing is blocked)
//
// Content-encoding is stripped unconditionally because fetchPackument forces
// `accept-encoding: identity`, so both branches produce the same header shape.
async function observeAndSendPackument(res, upstream, witness, packageName, log, state = {}, ctx = {}) {
  if (upstream.statusCode !== 200) {
    await streamUpstream(res, upstream, upstream.statusCode);
    return;
  }
  let raw;
  try {
    raw = Buffer.from(await upstream.body.arrayBuffer());
  } catch (err) {
    writeJson(res, 502, { error: 'upstream_body_read_failed', detail: err.message });
    return;
  }

  let parsed;
  try {
    parsed = JSON.parse(raw.toString('utf8'));
  } catch (err) {
    log?.warn?.(`[proxy] ${packageName}: non-JSON packument body: ${err.message}`);
  }

  let observed = null;
  let observeErr = null;
  let noDecision = false;
  if (parsed && witness) {
    // Only the observation itself is guarded here. Reporting it comes after (U-05 Amendment 3, O1): a failure while
    // reporting used to land in this catch and let fallback decisions replace the ones just returned.
    try {
      observed = witness.observePackument(packageName, parsed);
    } catch (err) {
      observeErr = err;
    }
    if (observeErr) {
      if (ctx.counters) ctx.counters.observation_errors += 1;
      log?.warn?.(`[witness] ${packageName}: observe failed: ${observeErr.message}`);
      // Serving the raw document here discarded every decision the packument would have earned --
      // one exception anywhere in the observe path and a known-malware version went straight
      // through. Ask the witness what the configured gates say a total failure means instead.
      try {
        observed = typeof witness.failureDecisionsFor === 'function'
          ? witness.failureDecisionsFor(parsed, observeErr, packageName) : null;
      } catch (inner) {
        log?.error?.(`[witness] ${packageName}: failure decision unavailable: ${inner.message}`);
        observed = null;
        noDecision = true;
      }
    }
  }

  // U-05 Amendment 3 (P3): no decision at all. The configured failure policy decides; a remembered BLOCK is never
  // served under any policy.
  if (noDecision) {
    if (ctx.failuresBlock) {
      refuseNoDecision(res, packageName, `observation and its failure decision both failed: ${observeErr.message}`);
      return;
    }
    const known = new Map();
    for (const [version, entry] of ctx.unstored?.forPackage(packageName) ?? []) {
      if (parsed?.versions && Object.prototype.hasOwnProperty.call(parsed.versions, version)
        && !ctx.overriddenLive?.(packageName, version)) {
        known.set(version, preserveKnownBlock(packageName, version, null, entry));
      }
    }
    if (known.size) observed = { decisions: known };
  }

  // Reading the returned decisions may itself throw; that escapes to the handler (P5b), before any decision counts.
  const decisions = observed ? observed.decisions : null;
  if (decisions instanceof Map && ctx.unstored && !noDecision) {
    // P6b: remember BLOCKs that were not stored, forget entries a newer decision replaces (Amendment 3, Table M).
    for (const [version, decision] of decisions) ctx.unstored.note(packageName, version, decision);
    // Rule K: a failure decision never makes a remembered BLOCK servable (override checked live).
    for (const [version, decision] of decisions) {
      if (decision?.evaluated !== false || decision.disposition === 'BLOCK') continue;
      const known = ctx.unstored.get(packageName, version);
      if (known && !ctx.overriddenLive?.(packageName, version)) {
        decisions.set(version, preserveKnownBlock(packageName, version, decision, known));
      }
    }
  }
  if (decisions) state.decided = true;
  if (observed && !observeErr) {
    try {
      log?.info?.(
        `[witness] ${packageName}: observed ${observed.versionsSeen} versions, +${observed.newBaselines} new`,
      );
    } catch { /* U-05 Amendment 3 (O1): reporting can never replace the returned decisions */ }
  }

  // Rewriter branch: any BLOCK → re-serialize. Otherwise serve raw bytes.
  const hasBlock = decisions && hasBlockDisposition(decisions);
  if (hasBlock) {
    state.blockComputed = true;
    try {
      const { packument: rewritten, changed, summary } = rewritePackument(parsed, decisions);
      if (changed) {
        for (const b of summary.blocked) {
          log?.warn?.(`[gate] ${packageName}@${b.version}: BLOCK (${b.reason || 'no detail'})`);
        }
        for (const w of summary.warned) {
          log?.info?.(`[gate] ${packageName}@${w.version}: WARN (${w.reason || 'no detail'})`);
        }
        for (const d of summary.dist_tag_downgrades) {
          log?.warn?.(
            `[rewriter] ${packageName}: dist-tag ${d.tag} ${d.from} -> ${d.to ?? 'DROPPED'}`,
          );
        }
        const body = Buffer.from(JSON.stringify(rewritten), 'utf8');
        const headers = relayResponseHeaders(upstream.headers);
        delete headers['content-encoding'];
        delete headers.etag; // etag would be stale against rewritten body
        headers['content-type'] = 'application/json';
        headers['content-length'] = String(body.length);
        res.writeHead(200, headers);
        res.end(body);
        return;
      }
      // No change means no BLOCKed version is in this document: decisions are keyed by its own version strings
      // (U-05 Amendment 2, P4b), so serving it as received below is safe.
    } catch (err) {
      // U-05 Amendment 2 (P4a): this used to serve the original document ("a rewriter bug must never DoS the
      // registry"), which hands npm the version that was just BLOCKed. Only this package's request fails now.
      refuseUnenforceable(res, packageName, `the BLOCK could not be applied: ${err.message}`);
      log?.warn?.(`[rewriter] ${packageName}: rewrite failed, document NOT served (a BLOCK could not be enforced): ${err.message}`);
      return;
    }
  }

  const headers = relayResponseHeaders(upstream.headers);
  delete headers['content-encoding'];
  headers['content-length'] = String(raw.length);
  res.writeHead(200, headers);
  res.end(raw);
}

function hasBlockDisposition(decisions) {
  if (!decisions || typeof decisions.values !== 'function') return false;
  for (const d of decisions.values()) {
    const disposition = typeof d === 'string' ? d : d?.disposition;
    if (disposition === 'BLOCK') return true;
  }
  return false;
}

// Tarball BLOCK gate. Checks gate_decisions for a recorded BLOCK against
// (pkg, version) extracted from the tarball filename. Honors overrides.
//
// U-05 Amendment 3: a BLOCK this process computed but could not store (P6b) is checked FIRST -- a stored decision
// would have replaced it, so it is always the newer one -- and a failed stored-decision lookup follows the configured
// failure policy (P6a). `state.tarballDecided` marks that the gate reached a decision (P5b).
export function enforceTarballGate(db, canonicalName, filename, log, ctx = {}, state = {}) {
  if (!db) return null;
  const version = parseTarballVersion(canonicalName, filename);
  if (version == null) return null;
  state.tarballVersion = version;
  const known = ctx.unstored?.get(canonicalName, version) ?? null;
  if (known) {
    if (ctx.overriddenLive?.(canonicalName, version)) {
      log?.info?.(`[override] ${canonicalName}@${version}: allowing a BLOCK that was not stored`);
      state.tarballDecided = true;
      return null;
    }
    return {
      package: canonicalName,
      version,
      gates: known.gates,
      decided_at: known.remembered_at,
      persisted: false,
      detail: `BLOCK decided by this proxy process and NOT stored (${known.detail}); a restart forgets it`,
      how_to_override: `chaingate allow ${canonicalName}@${version} --reason "<reason>"`,
    };
  }
  const lookupFailed = (err) => {
    log?.warn?.(`[tarball-gate] decision lookup failed: ${err.message}`);
    if (ctx.failuresBlock) {
      return { refuse: { status: 503, error: 'chaingate_decision_lookup_failed',
        detail: `the stored decision for ${canonicalName}@${version} could not be read (${err.message}); the `
          + 'configured failure policy (on_unusable_input: BLOCK) refuses it' } };
    }
    log?.warn?.(`[tarball-gate] ${canonicalName}@${version}: served without a decision (configured failure policy)`);
    state.tarballDecided = true;
    return null;
  };
  let decision;
  try {
    decision = db.getLatestDecision(canonicalName, version);
  } catch (err) {
    return lookupFailed(err);
  }
  // U-05 gap-closure r2, N3: a stored override ALLOW applies only while that exact override still exists. The store
  // compares new decisions with the same rows (witness/store.js effectivePrior), so the two never disagree.
  if (decision && isOverrideRow(decision.gates_fired)) {
    if (ctx.overriddenLive?.(canonicalName, version)) {
      log?.info?.(`[override] ${canonicalName}@${version}: allowing (stored override, still present)`);
      state.tarballDecided = true;
      return null;
    }
    try {
      decision = db.getLatestNonOverrideDecision(canonicalName, version);
    } catch (err) {
      return lookupFailed(err);
    }
  }
  if (!decision || decision.disposition !== 'BLOCK') { state.tarballDecided = true; return null; }
  let override = null;
  try {
    override = db.getOverride(canonicalName, version);
  } catch (err) {
    log?.warn?.(`[tarball-gate] override lookup failed: ${err.message}`);
  }
  if (override) {
    log?.info?.(
      `[override] ${canonicalName}@${version}: allowing (reason: ${override.reason})`,
    );
    state.tarballDecided = true;
    return null;
  }
  return {
    package: canonicalName,
    version,
    gates: decision.gates_fired,
    decided_at: decision.decided_at,
    how_to_override: `chaingate allow ${canonicalName}@${version} --reason "<reason>"`,
  };
}

function defaultLogger() {
  return {
    info: () => {},
    warn: (msg) => { console.error(msg); },
    error: (msg) => { console.error(msg); },
  };
}

export function createProxyServer(configOverrides = {}, hooks = {}) {
  const config = loadConfig(process.env, configOverrides);

  // U-05 gap-closure r2, A1: every line goes through ONE boundary. A logger that throws can no longer turn a handled
  // error into an unhandled request failure, and output is rate-bounded (proxy/log-boundary.js). `info` is a no-op in the
  // shipped logger and spends no budget. `hooks.logBudget` is for tests only.
  // Its once-a-minute tick (suppression summary, pending transitions) starts when the server listens, so a start-up that
  // refuses leaves no timer behind.
  const log = createLogBoundary(defaultLogger(), { silentLevels: ['info'], timers: false, ...(hooks.logBudget ?? {}) });

  // Fail-LOUD on witness open. If the DB path is unwritable, corrupt, or
  // points at a missing parent dir we cannot auto-create, the proxy refuses
  // to start rather than running degraded. At request time the witness path
  // is fail-open (Section 7 item 2 of docs/V2_DESIGN.md) — see the
  // observeAndSendPackument try/catch and the handler-level fallback below.
  let witness = null;
  let witnessDb = null;
  let seedV3 = null;
  let depCache = null;
  let depFetcher = null;
  if (config.witnessDbPath) {
    try {
      mkdirSync(dirname(config.witnessDbPath), { recursive: true });
    } catch (err) {
      if (err.code !== 'EEXIST') throw err;
    }
    try {
      witnessDb = openWitnessDB(config.witnessDbPath);
      witnessDb.applySchema();
    } catch (err) {
      const msg =
        `chaingate-proxy: failed to open witness DB at ${config.witnessDbPath}: ${err.message}\n` +
        `  Fix: ensure the path is writable, or run \`chaingate init --force\` to recreate it,\n` +
        `       or set CHAINGATE_WITNESS_DB to a different path.`;
      const wrapped = new Error(msg);
      wrapped.cause = err;
      throw wrapped;
    }
    depCache = new DepCache(witnessDb);
    // Background dep-first-publish fetcher for the scope-boundary gate.
    // Uses the same upstream fetchPackument helper as the main request path,
    // but runs out-of-band so gates stay synchronous.
    depFetcher = createDepFetcher({
      depCache,
      fetchPackument: (name) => fetchPackument(name, { config }),
      logger: log,
    });
    // The v3 detection gate, wired from CONFIGURATION rather than injected by a test. This is the
    // path a real startup takes: `CHAINGATE_SEED_V3` names a seed, the reader opens it read-only and
    // authenticated by default, and the operator's two policy choices come from the environment.
    //
    // Fail-LOUD, matching the witness-open precedent above. A configured seed that cannot be opened
    // or trusted must not leave the proxy running WITHOUT the detection gate: that is the same
    // silent degradation as serving a packument raw, moved to startup.
    let seedV3Gate = null;
    if (config.seedV3Path) {
      try {
        if (!['authenticated', 'unsigned-development'].includes(config.seedV3Trust)) {
          throw new Error(`CHAINGATE_SEED_V3_TRUST must be 'authenticated' or `
            + `'unsigned-development', got ${JSON.stringify(config.seedV3Trust)}`);
        }
        const trust = config.seedV3Trust === 'unsigned-development'
          ? TRUST_UNSIGNED_DEV : TRUST_AUTHENTICATED;
        // THE PINNED TRUST ANCHOR, wired through. Opening with a trust mode but no key meant
        // `authenticated` could never actually authenticate: the reader refuses that combination,
        // and any signature present went unchecked. The anchor is the same embedded literal the
        // CLI verifies bundles with, so startup and `chaingate init` agree about what is trusted.
        seedV3 = openSeed(config.seedV3Path, { trust, pubkey: CHAINGATE_SEED_PUBKEY_B64 });
        // UNRESOLVED ENFORCEMENT POLICY MUST NOT BECOME PERMISSION. An unset choice makes policy
        // decline, the gate can only answer SKIP, SKIP does not count, and the package installs --
        // so silence permitted. A proxy that ENFORCES must be told what these cases mean.
        const missingPolicy = ['on_unusable_input', 'on_no_evidence']
          .filter((k) => !(k === 'on_unusable_input'
            ? config.policyOnUnusableInput : config.policyOnNoEvidence));
        if (missingPolicy.length) {
          throw new Error(`policy ${missingPolicy.join(' and ')} is not configured: an unresolved `
            + 'policy produces no disposition, which enforcement cannot tell apart from '
            + `permission.\n  Fix: run \`chaingate init\` to record it${config.configSource
              ? `, or set it in ${config.configSource}` : ''}.`);
        }

        const policyConfig = {
          on_unusable_input: config.policyOnUnusableInput,
          on_no_evidence: config.policyOnNoEvidence,
        };
        seedV3Gate = createSeedV3Gate({
          seed: seedV3, config: policyConfig, domainVersionCount: config.domainVersionCount });
        log.info?.(`[seed-v3] ${config.seedV3Path} opened (trust=${config.seedV3Trust}`
          + `${seedV3.report?.authenticated ? ` anchor=${CHAINGATE_SEED_PUBKEY_FINGERPRINT}` : ''}, `
          + `snapshot=${seedV3.meta.corpus_snapshot_digest?.slice(0, 12)}, `
          + `policy=${JSON.stringify(policyConfig)}`
          + `${config.configSource ? `, from ${config.configSource}` : ''})`);
        if (config.seedV3Trust === 'unsigned-development') {
          log.warn(`[seed-v3] trust=unsigned-development: this seed is NOT authenticated`);
        }
        log.info?.('[seed-v3] provider_class domain_version_count=from-packument (internal: the '
          + 'package-scoped count is computed from each document, which is CURRENT where the seed '
          + 'counted as of its history cutoff)');
      } catch (err) {
        try { seedV3?.close?.(); } catch { /* already closed */ }
        // Refusing to start must not leave the witness database open: on Windows an open handle
        // keeps the file locked for as long as the calling process lives.
        try { witnessDb?.close?.(); } catch { /* already closed */ }
        const msg =
          `chaingate-proxy: failed to open v3 seed at ${config.seedV3Path}: ${err.message}\n`
          + '  The proxy refuses to start WITHOUT the detection gate it was configured with.\n'
          + `  Fix: re-run \`chaingate init --seed <bundle>\`, or edit ${
            config.configSource || 'the chaingate config file'} to correct or remove the seed entry.`;
        const wrapped = new Error(msg);
        wrapped.cause = err;
        throw wrapped;
      }
    }

    const configured = seedV3Gate ? [...DEFAULT_GATE_MODULES, seedV3Gate] : DEFAULT_GATE_MODULES;
    const modules =
      Array.isArray(hooks.gateModules) ? hooks.gateModules : configured;
    const runGates = createGateRunner({
      modules,
      getOverride: (pkg, ver) => witnessDb.getOverride(pkg, ver),
      services: {
        lookupDepFirstPublish: (name) => depCache.lookup(name),
        enqueueDepLookup: (name) => depFetcher.enqueue(name),
      },
      logger: log,
    });
    witness = createWitness({ db: witnessDb, runGates, config, logger: log });
  }

  // U-05 Amendment 3. The configured failure policy (P3/P5b/P6a): only a seed-v3 gate configured with
  // on_unusable_input BLOCK refuses when no decision can be made; pilot-only setups keep their ALLOW declaration.
  const unstored = createUnstoredBlocks({ log });
  const failuresBlock = Boolean(seedV3) && config.policyOnUnusableInput === 'BLOCK';
  const overriddenLive = (name, version) => {
    try { return Boolean(witnessDb?.getOverride(name, version)); } catch { return false; }
  };
  const counters = { observation_errors: 0 };
  const ctx = { unstored, failuresBlock, overriddenLive, counters };

  const handler = async (req, res) => {
    if (req.method !== 'GET' && req.method !== 'HEAD') {
      writeJson(res, 405, { error: 'method_not_allowed', method: req.method });
      return;
    }

    const url = new URL(req.url, 'http://internal');

    // Internal self-attestation endpoint for `chaingate doctor` — lets the CLI
    // confirm the running proxy matches the installed CLI. Bound to the same
    // 127.0.0.1 interface as the rest of the proxy; exposes no secrets.
    if (url.pathname === '/_chaingate/self') {
      writeJson(res, 200, {
        service: 'chaingate-proxy',
        version: PROXY_VERSION,
        pid: process.pid,
        // WHAT THIS PROCESS ACTUALLY LOADED. A listening port only says something bound it; `init`
        // and `doctor` need to know it is running the seed and policy that were just configured,
        // and after a rollback they need to see the RESTORED identity rather than the newer one.
        seed_v3: seedV3 ? {
          path: config.seedV3Path,
          bundle_id: config.seedV3BundleId ?? null,
          bundle_dir: config.seedV3BundleDir ?? null,
          // The digest THIS process computed over the bytes it opened. Readiness is checked against
          // identity, not against a path: a symlink before and after an update has the same path
          // over different bytes.
          sha256: seedV3.report?.content_sha256 ?? null,
          trust: config.seedV3Trust,
          authenticated: Boolean(seedV3.report?.authenticated),
          schema_version: seedV3.meta?.schema_version ?? null,
          corpus_snapshot_digest: seedV3.meta?.corpus_snapshot_digest ?? null,
          contract_version: seedV3.meta?.contract_version ?? null,
          policy: {
            on_unusable_input: config.policyOnUnusableInput,
            on_no_evidence: config.policyOnNoEvidence,
          },
          config_source: config.configSource ?? null,
        } : null,
        unstored_blocks: unstored.describe(),
        // U-05 gap-closure r2, Addendum 1 §B: the process's decision-storage state, from its own signals.
        storage: storageReport({ health: witness?.storageHealth?.() ?? null, count: unstored.count,
          full: Boolean(unstored.full), observationErrors: counters.observation_errors }),
        logging: (({ emitted, suppressed, truncated, failures, transitions, transitions_suppressed }) => ({ emitted,
          suppressed, truncated, failures, transitions, transitions_suppressed }))(log.stats()),
      });
      return;
    }

    const route = classify(url.pathname);

    if (route.kind === 'unknown') {
      writeJson(res, 404, { error: 'not_found', path: url.pathname });
      return;
    }

    const canonicalName = normalizePackageName(route.name);
    const state = {};            // U-05 Amendment 2 (P5a): set when a BLOCK was computed for this request

    try {
      if (route.kind === 'packument') {
        const upstream = await fetchPackument(route.name, {
          config,
          requestHeaders: req.headers,
        });
        await observeAndSendPackument(res, upstream, witness, canonicalName, log, state, ctx);
      } else {
        // Tarball BLOCK gate — check BEFORE contacting upstream so we don't
        // waste bandwidth on something we're going to refuse.
        const blocked = enforceTarballGate(witnessDb, canonicalName, route.filename, log, ctx, state);
        if (blocked?.refuse) {
          writeJson(res, blocked.refuse.status, { error: blocked.refuse.error, package: canonicalName,
            detail: blocked.refuse.detail });
          return;
        }
        if (blocked) {
          writeJson(res, 403, { error: 'blocked_by_chaingate', ...blocked });
          return;
        }
        const upstream = await fetchTarball(route.name, route.filename, {
          config,
          requestHeaders: req.headers,
        });
        await streamUpstream(res, upstream, upstream.statusCode);
      }
    } catch (err) {
      if (err instanceof UpstreamTimeoutError) {
        writeJson(res, 504, { error: 'upstream_timeout', detail: err.message });
        return;
      }
      if (err instanceof UpstreamError) {
        writeJson(res, 502, { error: 'upstream_unreachable', detail: err.message });
        return;
      }
      // Fail-open (Section 7 item 2): an unexpected internal error must
      // not break `npm install`. Log loudly, then attempt a raw upstream
      // passthrough that bypasses the witness entirely. If headers are
      // already sent we can't recover — just destroy the socket so the
      // client sees a clean failure instead of a half-written response.
      // U-05 Amendment 3 (P5b): before any decision exists, the configured failure policy decides, and a remembered
      // BLOCK is never passed through. Once a decision exists the passthrough is unchanged (Amendment 2 covers BLOCK).
      let refusal = null;
      if (state.blockComputed) refusal = 'a BLOCK was computed';
      else if (route.kind === 'packument' && !state.decided) {
        if (failuresBlock) refusal = 'no decision was made and the configured failure policy refuses';
        else if (unstored.forPackage(canonicalName).some(([v]) => !overriddenLive(canonicalName, v))) {
          refusal = 'no decision was made and the package has a BLOCK this process could not store';
        }
      } else if (route.kind !== 'packument' && !state.tarballDecided) {
        const v = state.tarballVersion;
        if (v != null && unstored.get(canonicalName, v) && !overriddenLive(canonicalName, v)) refusal = 'remembered';
        else if (failuresBlock) refusal = 'the tarball gate did not decide and the configured failure policy refuses';
      }
      log?.warn?.(
        `[proxy] internal error on ${req.method} ${req.url}: ${err.stack || err.message} `
          + (refusal ? `(${refusal}: NOT falling back to raw upstream)` : '(falling back to raw upstream)'),
      );
      if (res.headersSent) {
        if (!res.writableEnded) res.destroy(err);
        return;
      }
      if (state.blockComputed) {
        // U-05 Amendment 2 (P5a): a raw passthrough would serve the version that was just BLOCKed.
        refuseUnenforceable(res, canonicalName, `internal error after the BLOCK was computed: ${err.message}`);
        return;
      }
      if (refusal === 'remembered') {
        const known = unstored.get(canonicalName, state.tarballVersion);
        writeJson(res, 403, { error: 'blocked_by_chaingate', package: canonicalName, version: state.tarballVersion,
          gates: known.gates, decided_at: known.remembered_at, persisted: false,
          detail: `BLOCK decided by this proxy process and NOT stored (${known.detail}); a restart forgets it` });
        return;
      }
      if (refusal && route.kind === 'packument' && !failuresBlock) {
        refuseUnenforceable(res, canonicalName, `internal error before a decision, with a BLOCK this process could not store: ${err.message}`);
        return;
      }
      if (refusal) {
        refuseNoDecision(res, canonicalName, `internal error before a decision: ${err.message}`);
        return;
      }
      try {
        let upstream;
        if (route.kind === 'packument') {
          upstream = await fetchPackument(route.name, {
            config,
            requestHeaders: req.headers,
          });
        } else {
          upstream = await fetchTarball(route.name, route.filename, {
            config,
            requestHeaders: req.headers,
          });
        }
        await streamUpstream(res, upstream, upstream.statusCode);
      } catch (fallbackErr) {
        if (res.headersSent) {
          if (!res.writableEnded) res.destroy(fallbackErr);
          return;
        }
        if (fallbackErr instanceof UpstreamTimeoutError) {
          writeJson(res, 504, { error: 'upstream_timeout', detail: fallbackErr.message });
        } else {
          writeJson(res, 502, {
            error: 'upstream_unreachable',
            detail: fallbackErr.message,
          });
        }
      }
    }
  };

  // The last guard (U-05 gap-closure r2, A1): whatever escapes the handler -- a response that cannot be written inside
  // its own catch, for example -- ends this one request without a logger and without an unhandled rejection.
  const finalGuard = (res, err) => {
    try {
      if (res.headersSent) { if (!res.writableEnded) res.destroy(err); return; }
      writeJson(res, 500, { error: 'chaingate_internal_error' });
    } catch { try { res.destroy(); } catch { /* nothing left */ } }
  };
  const server = http.createServer((req, res) => {
    Promise.resolve().then(() => handler(req, res)).catch((err) => finalGuard(res, err));
  });
  let logTick = null;
  server.on('listening', () => {
    if (logTick) return;
    logTick = setInterval(() => { try { log.tick(); } catch { /* reporting only */ } }, 60_000);
    logTick.unref?.();
  });
  server.config = config;
  server.witness = witness;
  server.witnessDb = witnessDb;
  server.seedV3 = seedV3;
  server.depCache = depCache;
  server.depFetcher = depFetcher;
  const origClose = server.close.bind(server);
  server.close = (cb) => {
    // Drain the background dep fetcher first so no in-flight HTTP requests
    // touch a closing DB. stop() is graceful — current request finishes,
    // queue aborts, promise resolves.
    const finish = () => {
      if (logTick) { clearInterval(logTick); logTick = null; }
      log.tick();                                            // the last suppression summary, if any
      origClose(() => {
        try { witness?.close(); } catch { /* already closed */ }
        try { seedV3?.close(); } catch { /* already closed */ }
        if (cb) cb();
      });
    };
    if (depFetcher) {
      depFetcher.stop().then(finish, finish);
    } else {
      finish();
    }
  };
  return server;
}

export async function startProxyServer(configOverrides = {}) {
  const server = createProxyServer(configOverrides);
  const { port, host } = server.config;
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(port, host, resolve);
  });
  return server;
}

/**
 * True when `entryPath` (process.argv[1]) is the module at `moduleUrl`, i.e. this file was run
 * directly (`node proxy/server.js`, which is how `chaingate init` starts the proxy).
 * `file://${path}` matched only POSIX paths with no characters that URL encoding changes: on Windows
 * (`C:\\...` against `file:///C:/...`) and on any install path with a space or non-ASCII character,
 * the proxy process loaded and exited without listening. `pathToFileURL` builds the same form as
 * `import.meta.url` (the idiom seed/v3/parity.js and conformance.js already use). `windows` is for
 * tests only; normal use passes nothing and needs no launcher variable.
 */
export function isDirectEntry(moduleUrl, entryPath, { windows } = {}) {
  if (!entryPath) return false; // `node -e` / REPL: no entry script
  const opts = windows === undefined ? undefined : { windows };
  if (moduleUrl === pathToFileURL(entryPath, opts).href) return true;
  // Node loads the entry module by its REAL path, so an entry path through a symlink (macOS's
  // /var -> /private/var, a symlinked install prefix) must be compared by its real path too.
  if (windows !== undefined) return false;             // test-only form: no filesystem to consult
  try { return moduleUrl === pathToFileURL(realpathSync(entryPath)).href; } catch { return false; }
}

const isDirectRun = isDirectEntry(import.meta.url, process.argv[1]);
if (isDirectRun) {
  const server = await startProxyServer();
  const { port, host, upstream, witnessDbPath } = server.config;
  console.log(
    `chaingate-proxy listening on http://${host}:${port}, upstream ${upstream} (pid ${process.pid})`,
  );
  console.log(`chaingate-proxy witness db: ${witnessDbPath}`);
  const shutdown = (signal) => () => {
    console.log(`[${signal}] shutting down chaingate-proxy`);
    server.close(() => process.exit(0));
    setTimeout(() => process.exit(1), 5_000).unref();
  };
  process.on('SIGINT', shutdown('SIGINT'));
  process.on('SIGTERM', shutdown('SIGTERM'));
}
