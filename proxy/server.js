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
import { openWitnessDB } from '../witness/db.js';
import { DepCache } from '../witness/dep-cache.js';
import { createWitness } from '../witness/store.js';
import { createGateRunner, DEFAULT_GATE_MODULES } from '../gates/index.js';
import { createSeedV3Gate } from '../seed/v3/gate.js';
import { openSeed, TRUST_AUTHENTICATED, TRUST_UNSIGNED_DEV } from '../seed/v3/reader.js';
import { CHAINGATE_SEED_PUBKEY_B64, CHAINGATE_SEED_PUBKEY_FINGERPRINT } from '../witness/seed_verify.js';
import { rewritePackument } from '../gates/rewriter.js';
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
async function observeAndSendPackument(res, upstream, witness, packageName, log) {
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
  if (parsed && witness) {
    try {
      observed = witness.observePackument(packageName, parsed);
      log?.info?.(
        `[witness] ${packageName}: observed ${observed.versionsSeen} versions, +${observed.newBaselines} new`,
      );
    } catch (err) {
      log?.warn?.(`[witness] ${packageName}: observe failed: ${err.message}`);
      // Serving the raw document here discarded every decision the packument would have earned --
      // one exception anywhere in the observe path and a known-malware version went straight
      // through. Ask the witness what the configured gates say a total failure means instead.
      try {
        observed = typeof witness.failureDecisionsFor === 'function'
          ? witness.failureDecisionsFor(parsed, err, packageName) : null;
      } catch (inner) {
        log?.error?.(`[witness] ${packageName}: failure decision unavailable: ${inner.message}`);
        observed = null;
      }
    }
  }

  // Rewriter branch: any BLOCK → re-serialize. Otherwise serve raw bytes.
  const hasBlock = observed && hasBlockDisposition(observed.decisions);
  if (hasBlock) {
    try {
      const { packument: rewritten, changed, summary } = rewritePackument(parsed, observed.decisions);
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
    } catch (err) {
      // Fail-open: rewriter bug must never DoS the registry.
      log?.warn?.(`[rewriter] ${packageName}: rewrite failed, serving original: ${err.message}`);
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
function enforceTarballGate(db, canonicalName, filename, log) {
  if (!db) return null;
  const version = parseTarballVersion(canonicalName, filename);
  if (version == null) return null;
  let decision;
  try {
    decision = db.getLatestDecision(canonicalName, version);
  } catch (err) {
    log?.warn?.(`[tarball-gate] decision lookup failed: ${err.message}`);
    return null;
  }
  if (!decision || decision.disposition !== 'BLOCK') return null;
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

  const log = defaultLogger();

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
      });
      return;
    }

    const route = classify(url.pathname);

    if (route.kind === 'unknown') {
      writeJson(res, 404, { error: 'not_found', path: url.pathname });
      return;
    }

    const canonicalName = normalizePackageName(route.name);

    try {
      if (route.kind === 'packument') {
        const upstream = await fetchPackument(route.name, {
          config,
          requestHeaders: req.headers,
        });
        await observeAndSendPackument(res, upstream, witness, canonicalName, log);
      } else {
        // Tarball BLOCK gate — check BEFORE contacting upstream so we don't
        // waste bandwidth on something we're going to refuse.
        const blocked = enforceTarballGate(witnessDb, canonicalName, route.filename, log);
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
      log?.warn?.(
        `[proxy] internal error on ${req.method} ${req.url}: ${err.stack || err.message} (falling back to raw upstream)`,
      );
      if (res.headersSent) {
        if (!res.writableEnded) res.destroy(err);
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

  const server = http.createServer(handler);
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
