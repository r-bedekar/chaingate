import http from 'node:http';
import { mkdirSync } from 'node:fs';
import { dirname } from 'node:path';
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
import { createWitness } from '../witness/store.js';
import { createGateRunner, DEFAULT_GATE_MODULES } from '../gates/index.js';
import { rewritePackument } from '../gates/rewriter.js';

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
      observed = null;
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
            `[rewriter] ${packageName}: dist-tag ${d.tag} ${d.from} → ${d.to ?? 'DROPPED'}`,
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
    how_to_override: `scw allow ${canonicalName}@${version} --reason "<reason>"`,
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
  // to start rather than running degraded.
  let witness = null;
  let witnessDb = null;
  if (config.witnessDbPath) {
    try {
      mkdirSync(dirname(config.witnessDbPath), { recursive: true });
    } catch (err) {
      if (err.code !== 'EEXIST') throw err;
    }
    witnessDb = openWitnessDB(config.witnessDbPath);
    const modules =
      Array.isArray(hooks.gateModules) ? hooks.gateModules : DEFAULT_GATE_MODULES;
    const runGates = createGateRunner({
      modules,
      getOverride: (pkg, ver) => witnessDb.getOverride(pkg, ver),
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
      writeJson(res, 500, { error: 'internal', detail: err.message });
    }
  };

  const server = http.createServer(handler);
  server.config = config;
  server.witness = witness;
  server.witnessDb = witnessDb;
  const origClose = server.close.bind(server);
  server.close = (cb) =>
    origClose(() => {
      try { witness?.close(); } catch { /* already closed */ }
      if (cb) cb();
    });
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

const isDirectRun = import.meta.url === `file://${process.argv[1]}`;
if (isDirectRun) {
  const server = await startProxyServer();
  const { port, host, upstream, witnessDbPath } = server.config;
  console.log(
    `chaingate-proxy listening on http://${host}:${port} → ${upstream} (pid ${process.pid})`,
  );
  console.log(`chaingate-proxy witness db → ${witnessDbPath}`);
  const shutdown = (signal) => () => {
    console.log(`[${signal}] shutting down chaingate-proxy`);
    server.close(() => process.exit(0));
    setTimeout(() => process.exit(1), 5_000).unref();
  };
  process.on('SIGINT', shutdown('SIGINT'));
  process.on('SIGTERM', shutdown('SIGTERM'));
}
