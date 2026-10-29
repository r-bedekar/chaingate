import http from 'node:http';
import { mkdirSync, readFileSync, realpathSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { pipeline } from 'node:stream/promises';
import { Transform } from 'node:stream';

import { loadConfig } from './config.js';
import {
  fetchPackument,
  fetchTarball,
  fetchAttestationBundle,
  RELAY_RESPONSE_HEADERS,
  UpstreamTimeoutError,
  UpstreamError,
} from './registry.js';
import { openWitnessDB } from '../witness/db.js';
import { refreshPins, urlSource, PINS_REFRESH_MS } from '../cli/pins-feed.js';
import { shardSource } from '../cli/seed-shards.js';
import { createSeedCache, DEFAULT_SEED_CACHE_WAIT_MS, SEED_CACHE_REFRESH_MS } from './seed-cache.js';
import { DepCache } from '../witness/dep-cache.js';
import { createWitness } from '../witness/store.js';
import { createGateRunner, DEFAULT_GATE_MODULES } from '../gates/index.js';
import { createSeedV3Gate } from '../seed/v3/gate.js';
import { openSeed, TRUST_AUTHENTICATED, TRUST_UNSIGNED_DEV } from '../seed/v3/reader.js';
import { CHAINGATE_SEED_PUBKEY_B64, CHAINGATE_SEED_PUBKEY_FINGERPRINT } from '../witness/seed_verify.js';
import { rewritePackument } from '../gates/rewriter.js';
import { createUnstoredBlocks, validateCaps } from './unstored-blocks.js';
import { createEvaluationTracker, EvaluationBusy } from './evaluation-tracker.js';
import { createLogBoundary } from './log-boundary.js';
// The deciding reason, the row classes, and ChainGate's npm-notice.
import { classify as classifyRows, decidingReason, factsFromBits, pendingFacts, policyPrefix, servedClass } from '../witness/row-class.js';
import { buildNotice, factLabels, pinNotice, sanitizeUpstreamNotice, identity, NOTICE_CACHE_CONTROL } from './notice.js';
// The user's pins (a live serving overlay) and acceptances.
import { createPinSet, withheldBy } from '../witness/pins.js';
// N1h judged at tarball time, bounded; the dependency cache's stats on /self
import { judgeAtTarball } from './dependency-judge.js';
import { dependencyCacheStats, setDependencyDoc } from '../gates/dependency-cache.js';
// MC while the tarball streams
import { createTarWalker } from './tar-walk.js';
import { rememberManifestHooks, manifestHooksFor, manifestEntryFor, mcRow, recordLate, mcDeterminate, hookDict, GATE as MC_GATE } from './manifest-check.js';
import { tarballRow } from '../gates/install-introduced.js';
import { reraise } from '../gates/retier-late.js';
import { DEFAULT_STATIC_WALK_WAIT_MS } from '../config-store.js';
import { armedBy, walkReason, keepListFor, staticRows, budgetRows, noManifestRows, staticSettled, MAX_ARMED_WALKS, STATIC_WITHHOLD_CAP_BYTES,
  withholdingChecks, entryKeepFor, entryFactsOf, MAX_FACTS_WALKS, STATIC_CHECKS_VERSION, FACTS_LIMITS, makeBase64Share, createMemberTally,
  staticFactsOf } from './static-checks.js';
import { withRole } from '../gates/row-class.js';
import { rememberPackumentFacts, packumentFactsFor, createShapeTally, shadowFactsOf, publicStaticFacts, repoClaimFact, REPO_CLAIM_LIMITS } from './shadow-facts.js';
/** 0.1.5: the walk's root package.json (Linux view) parsed for the static checks, or null; a UTF-8 BOM is dropped as npm does. */
function parsedPackageJson(walk) {
  if (!walk?.ok || !walk.packageJson) return null;
  try { const pj = JSON.parse(walk.packageJson.toString('utf8').replace(/^\uFEFF/, '')); return pj !== null && typeof pj === 'object' && !Array.isArray(pj) ? pj : null; } catch { return null; }
}
let factsWalks = 0;                                         // 0.1.5: entry-facts-only walks in flight (ceiling MAX_FACTS_WALKS)
let armedWalks = 0;                                        // 0.1.5: armed keep-list walks in flight (process-wide ceiling MAX_ARMED_WALKS)
// Since 0.1.6 a download that finds every walk slot busy waits for one, first come first served, up to static_walk_wait_ms
// (default 10 s, at most half the upstream body timeout so a waiting body never times out); past it it is served unwalked.
const walkWaiters = [];
function takeWalkSlot(waitMs) {
  if (armedWalks < MAX_ARMED_WALKS && !walkWaiters.length) { armedWalks += 1; return Promise.resolve({ ok: true, waitedMs: 0 }); }
  if (!(waitMs > 0)) return Promise.resolve({ ok: false, waitedMs: 0 });
  const t0 = performance.now();
  return new Promise((resolve) => {
    const w = { done: false };
    w.take = () => {
      if (w.done) return false;
      w.done = true; clearTimeout(w.timer); armedWalks += 1; resolve({ ok: true, waitedMs: performance.now() - t0 }); return true;
    };
    w.timer = setTimeout(() => {
      if (w.done) return;
      w.done = true; const i = walkWaiters.indexOf(w); if (i >= 0) walkWaiters.splice(i, 1);
      resolve({ ok: false, waitedMs: performance.now() - t0 });
    }, waitMs);
    walkWaiters.push(w);
  });
}
function freeWalkSlot() {
  armedWalks -= 1;
  while (walkWaiters.length && armedWalks < MAX_ARMED_WALKS) if (walkWaiters.shift().take()) break;
}
let claimFetches = 0;                                      // 0.1.5: attestation bundle fetches in flight (REPO_CLAIM_LIMITS.maxInFlight)
// The install summary, the disk record and the last version without the signal.
import { createInstallSummary, isLoopbackPeer } from './install-summary.js';
import { lastVersionWithoutSignal } from '../witness/last-without-signal.js';
import { POLICY_CONTRACT_VERSION, NAMED_RUNNER_GATES } from '../seed/v3/policy.js';
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

// A version of this package is already BLOCKed and the response that removes it could not be
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

// No decision could be made and the configured failure policy refuses.
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

// No decision could be made and the unstored-BLOCK record is FULL, under every configuration.
function refuseFull(res, packageName, detail) {
  if (res.headersSent) {
    if (!res.writableEnded) res.destroy(new Error(detail));
    return;
  }
  writeJson(res, 502, {
    error: 'chaingate_enforcement_failed',
    package: packageName,
    detail: `no decision could be made for ${packageName} (${detail}); the unstored-BLOCK record is full, so it cannot `
      + 'tell whether a version of it is BLOCKed (a resource-safety refusal, not a finding about this package)',
  });
}

// A failure decision never makes a remembered BLOCK servable.
function preserveKnownBlock(packageName, version, decision, known) {
  return {
    disposition: 'BLOCK',
    held: { facts: factsFromBits(known?.reasons), rows: null },   // the held facts
    results: [{ gate: 'chaingate', result: 'BLOCK',
      detail: `known BLOCK preserved: this proxy process decided BLOCK for ${packageName}@${version} and could not `
        + `store it (${known.detail}); a failure decision cannot make it servable` },
    ...(Array.isArray(decision?.results) ? decision.results : [])],
    persisted: false,
    evaluated: false,
  };
}

function writeJson(res, status, obj, extraHeaders = {}) {
  const body = JSON.stringify(obj);
  res.writeHead(status, {
    'content-type': 'application/json; charset=utf-8',
    'content-length': Buffer.byteLength(body),
    ...extraHeaders,
  });
  res.end(body);
}

function relayResponseHeaders(upstreamHeaders) {
  const out = {};
  if (!upstreamHeaders) return out;
  for (const key of RELAY_RESPONSE_HEADERS) {
    const v = upstreamHeaders[key] ?? upstreamHeaders[key.toLowerCase()];
    if (v == null) continue;
    // An upstream notice is printed by npm as-is, so it is relayed only as `registry: …` and can
    // never pass for a ChainGate line.
    out[key] = key === 'npm-notice' ? sanitizeUpstreamNotice(v) : v;
  }
  return out;
}

/** Our notice beside a relayed one; a 200 carrying ours is `no-store`, or npm never prints it. */
function withNotice(headers, notice, { noStore = true } = {}) {
  if (!notice) return headers;
  const out = { ...headers };
  out['npm-notice'] = out['npm-notice'] ? [notice, out['npm-notice']] : notice;
  if (noStore) out['cache-control'] = NOTICE_CACHE_CONTROL;
  return out;
}

async function streamUpstream(res, upstream, statusCode, extraHeaders = null, tap = null) {
  const headers = extraHeaders ? extraHeaders(relayResponseHeaders(upstream.headers)) : relayResponseHeaders(upstream.headers);
  res.writeHead(statusCode, headers);
  if (statusCode === 304 || statusCode === 204) {
    await upstream.body.dump();
    res.end();
    return;
  }
  try {
    // `tap` sees a copy of every chunk; the chunk itself goes to npm unchanged and undelayed
    if (tap) {
      await pipeline(upstream.body, new Transform({ transform(chunk, _enc, cb) {
        try { tap(chunk); } catch { /* the walk never affects the download */ }
        cb(null, chunk);
      } }), res);
    } else await pipeline(upstream.body, res);
  } catch (err) {
    if (!res.writableEnded) res.destroy(err);
  }
}

/** Resolves when `res` can take more bytes, or when it has gone away (so a held download never waits on a closed socket). */
function drained(res) {
  return new Promise((resolve) => {
    const done = () => { res.removeListener('drain', done); res.removeListener('close', done); resolve(); };
    res.once('drain', done); res.once('close', done);
  });
}
/** Resolves once `res` has finished or closed. */
function settled(res) {
  return new Promise((resolve) => {
    if (res.writableFinished || res.destroyed) { resolve(); return; }
    const done = () => { res.removeListener('finish', done); res.removeListener('close', done); resolve(); };
    res.once('finish', done); res.once('close', done);
  });
}

/**
 * 0.1.5 (the per-user `static_withhold` switch): hold an ARMED download in memory while the static checks read it, so a named
 * static WARN can withhold the download that reveals it. Every chunk goes to `tap` (the walker) as it arrives.
 *   { held: true, headers, body }   the whole body arrived within `cap`; nothing has been sent (the caller serves or withholds it)
 *   { held: false }                 streamed as today: a status other than 200, a Content-Length over `cap`, or the cap reached
 *                                   mid-stream (the held bytes are flushed first, the rest streams)
 *   { aborted: true }               npm went away, or the upstream failed, while holding: nothing to record
 */
async function holdUpstream(res, upstream, statusCode, extraHeaders, tap, cap) {
  const headersOf = () => (extraHeaders ? extraHeaders(relayResponseHeaders(upstream.headers)) : relayResponseHeaders(upstream.headers));
  const announced = Number(upstream.headers?.['content-length']);
  if (statusCode !== 200 || (Number.isFinite(announced) && announced > cap)) {
    await streamUpstream(res, upstream, statusCode, extraHeaders, tap);
    return { held: false };
  }
  let gone = false;
  const onClose = () => { if (!res.writableFinished) { gone = true; upstream.body?.destroy?.(); } };
  res.once('close', onClose);
  const chunks = []; let size = 0; let streaming = false;
  try {
    for await (const chunk of upstream.body) {
      if (gone) break;
      try { tap(chunk); } catch { /* the walk never affects the download */ }
      if (streaming) { if (!res.write(chunk)) await drained(res); continue; }
      chunks.push(chunk); size += chunk.length;
      if (size > cap) {                                     // the cap reached mid-stream: serve as today from here
        streaming = true;
        res.writeHead(statusCode, headersOf());
        for (const c of chunks.splice(0)) if (!res.write(c)) await drained(res);
      }
    }
  } catch (err) {
    if (!res.writableEnded) res.destroy(err);
    return streaming ? { held: false } : { aborted: true };
  } finally {
    res.removeListener('close', onClose);
  }
  if (gone) return { aborted: true };
  if (streaming) { res.end(); await settled(res); return { held: false }; }
  return { held: true, headers: headersOf(), body: Buffer.concat(chunks) };
}

/** 0.1.5: the 403 of a download the user's static_withhold switch withholds (a serving choice; the decision stays WARN). */
function staticWithheldResponse(pkg, version, checks) {
  const id = `${pkg}@${version}`;
  const detail = `${id} is withheld by your static_withhold setting: ${checks.join(', ')}; details: chaingate why ${id}; `
    + `to install it anyway: chaingate accept ${id}`;
  const notice = buildNotice({ kind: 'WITHHELD', pkg, version, labels: checks, tail: '(your static_withhold setting)' });
  return { body: { error: 'withheld_by_static_check', package: pkg, version, checks, detail }, detail, notice };
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
    if (parsed && typeof parsed === 'object') {
      rememberManifestHooks(packageName, parsed.versions);   // MC: the manifest's install hooks
      rememberPackumentFacts(packageName, parsed);            // 0.1.5 shadow facts: dist-tags, maintainers, publishers
      setDependencyDoc(packageName, parsed);                 // N1h judges from what npm already fetched
    }
  } catch (err) {
    log?.warn?.(`[proxy] ${packageName}: non-JSON packument body: ${err.message}`);
  }

  let observed = null;
  let observeErr = null;
  let noDecision = false;
  if (parsed && witness) {
    // Only the observation itself is guarded here. Reporting it comes after: a failure while
    // reporting used to land in this catch and let fallback decisions replace the ones just returned.
    // since 0.1.6: a seed cache fetches this package's bucket first, waiting a bounded time (never throws)
    if (ctx.seedCache) await ctx.seedCache.need(packageName);
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

  // No decision at all. The configured failure policy decides; a remembered BLOCK is never
  // served under any policy.
  if (noDecision) {
    // While the record is FULL this is refused as such under every configuration (it says why).
    if (ctx.unstored?.full) {
      refuseFull(res, packageName, `observation and its failure decision both failed: ${observeErr.message}`);
      return;
    }
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

  // Reading the returned decisions may itself throw; that escapes to the handler, before any decision counts.
  const decisions = observed ? observed.decisions : null;
  if (decisions instanceof Map && ctx.unstored && !noDecision) {
    // Remember BLOCKs that were not stored, forget entries a newer decision replaces.
    for (const [version, decision] of decisions) ctx.unstored.note(packageName, version, decision);
    // A resolving request evaluates too; its actually evaluated versions need no second evaluation.
    if (observed?.actual && ctx.tracker) ctx.tracker.markAll(packageName, observed.actual);
    // A failure decision never makes a remembered BLOCK servable (override checked live).
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
    } catch { /* reporting can never replace the returned decisions */ }
  }

  // Rewriter branch: any BLOCK, or any version a user pin withholds → re-serialize. Otherwise serve raw bytes.
  const hasBlock = decisions && hasBlockDisposition(decisions);
  const pins = Array.isArray(state.pins) ? state.pins : [];
  const pinnedOf = (v) => withheldBy(pins, packageName, v);
  const hasPinned = pins.length > 0 && Object.keys(parsed?.versions ?? {}).some((v) => pinnedOf(v));
  if (hasBlock || hasPinned) {
    if (hasBlock) state.blockComputed = true;
    try {
      const { packument: rewritten, changed, summary } = rewritePackument(parsed, decisions ?? new Map(), { pinned: pinnedOf });
      const pinMoves = summary.dist_tag_downgrades.filter((d) => d.pin);
      summary.dist_tag_downgrades = summary.dist_tag_downgrades.filter((d) => !d.pin);   // BLOCK moves only, below
      let tagNotice = null;
      if (changed) {
        // A BLOCK resting on a fact goes through the reserved fact channel, deduplicated per (package, set of
        // fact-blocked versions, version) for 10 min; any other BLOCK line uses the general budget, as before.
        // A kept or preserved BLOCK carries what it rests on in `held`: its facts, and the stored BLOCK's
        // rows, which give the reason. Keys are per version: never the package's whole set.
        const factOf = (v) => {
          const d = decisions.get(v);
          return [...new Set([...classifyRows(d?.results).facts, ...(Array.isArray(d?.held?.facts) ? d.held.facts : [])])].sort();
        };
        for (const b of summary.blocked) {
          const held = decisions.get(b.version)?.held;
          const reason = Array.isArray(held?.rows) ? `${decidingReason(held.rows, 'BLOCK')} | ${b.reason}` : b.reason;
          const line = `[gate] ${packageName}@${b.version}: BLOCK (${reason || 'no detail'})`;
          const facts = factOf(b.version);
          if (facts.length) log?.reserved?.('fact', line, `${packageName}@${b.version}|${facts.join(',')}`);
          else log?.warn?.(line);
        }
        // One notice when a dist-tag was moved off a version withheld for a fact (the user would have got it).
        for (const d of summary.dist_tag_downgrades) {
          const facts = factOf(d.from);
          if (!facts.length) continue;
          const tag = /^[A-Za-z0-9._-]{1,64}$/.test(String(d.tag)) ? d.tag : 'a dist-tag';
          const to = d.to == null ? 'dropped' : (identity('x', String(d.to)) ? `moved to ${d.to}` : 'moved');
          const dd = decisions.get(d.from);
          tagNotice = buildNotice({ kind: 'BLOCKED', pkg: packageName, version: d.from, labels: factLabels(facts, dd?.held?.rows ?? dd?.results),
            tail: `(dist-tag ${tag} ${to})` });
          break;
        }
        // Every dist-tag moved off a withheld version is an install event (on disk when it rests on
        // a fact); withheld versions no tag pointed at are context only.
        const reasonOf = (v) => {
          const d = decisions.get(v);
          return Array.isArray(d?.held?.rows) ? decidingReason(d.held.rows, 'BLOCK') : decidingReason(d?.results, 'BLOCK');
        };
        const policyOf = (v) => {
          const d = decisions.get(v);
          return policyPrefix(Array.isArray(d?.held?.rows) ? d.held.rows : d?.results);
        };
        // The packument controls how many tags there are, so at most 20 tag events per response (`latest`
        // first; the rest counted on the last one), and one disk row per withheld version carrying its capped tag list.
        const TAG_EVENTS = 20;
        const moved = new Set(summary.dist_tag_downgrades.map((d) => d.from));
        const downgrades = [...summary.dist_tag_downgrades].sort((a, b) => (b.tag === 'latest') - (a.tag === 'latest'));
        const tagOf = (d) => (/^[A-Za-z0-9._-]{1,64}$/.test(String(d.tag)) ? d.tag : 'a dist-tag');
        const toOf = (d) => (d.to == null ? null : String(d.to));
        downgrades.slice(0, TAG_EVENTS).forEach((d, i, shown) => {
          const more = i === shown.length - 1 ? downgrades.length - shown.length : 0;
          state.note?.({ kind: 'tag-moved', package: packageName, tag: tagOf(d), from: d.from, to: toOf(d), facts: factOf(d.from),
            reason: reasonOf(d.from), ...(more ? { more } : {}) });
        });
        for (const from of moved) {
          const facts = factOf(from);
          if (!facts.length) continue;
          const mine = downgrades.filter((d) => d.from === from);
          state.note?.(null, { kind: 'fact-tag-moved', package_name: packageName, version: from,
            classes: { tags: mine.slice(0, TAG_EVENTS).map((d) => ({ tag: tagOf(d), to: toOf(d) })), facts,
              ...(mine.length > TAG_EVENTS ? { more: mine.length - TAG_EVENTS } : {}) },
            reason: reasonOf(from), policy_version: policyOf(from) });
        }
        // What the user's pins withheld here, per pin, as context (no exit code): versions and tag moves, capped
        const byPin = new Map();
        for (const x of summary.pinned) byPin.set(x.k_version, [...(byPin.get(x.k_version) ?? []), x.version]);
        for (const [k, versions] of byPin) {
          const tags = pinMoves.filter((d) => d.pin.k_version === k);
          state.note?.({ kind: 'pin-withheld', package: packageName, k, versions: versions.slice(0, TAG_EVENTS),
            more: Math.max(0, versions.length - TAG_EVENTS), tags: tags.slice(0, TAG_EVENTS).map((d) => ({ tag: tagOf(d), from: d.from, to: toOf(d) })) });
        }
        const withheld = summary.blocked.filter((b) => !moved.has(b.version));
        if (withheld.length) {
          state.note?.({ kind: 'withheld', package: packageName,
            versions: withheld.slice(0, 20).map((b) => ({ version: b.version, facts: factOf(b.version) })),
            more: Math.max(0, withheld.length - 20) });
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
        // The rewritten packument stays CACHEABLE (no-store would leave npm's stale pre-BLOCK copy for
        // --prefer-offline); npm 10/11 then do not print this notice, and `chaingate report` carries the case.
        const headers = withNotice(relayResponseHeaders(upstream.headers), tagNotice, { noStore: false });
        delete headers['content-encoding'];
        delete headers.etag; // etag would be stale against rewritten body
        // Nor last-modified -- with it npm revalidates its cached REWRITTEN copy (If-Modified-Since → upstream 304)
        // and keeps a stale view after an unpin or a cleared BLOCK; without validators it fetches again after max-age.
        delete headers['last-modified'];
        headers['content-type'] = 'application/json';
        headers['content-length'] = String(body.length);
        res.writeHead(200, headers);
        res.end(body);
        return;
      }
      // No change means no BLOCKed version is in this document: decisions are keyed by its own version strings,
      // so serving it as received below is safe.
    } catch (err) {
      // This used to serve the original document ("a rewriter bug must never DoS the
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
// A BLOCK this process computed but could not store is checked FIRST -- a stored decision
// would have replaced it, so it is always the newer one -- and a failed stored-decision lookup follows the configured
// failure policy. `state.tarballDecided` marks that the gate reached a decision.
/**
 * The tarball gate while the unstored-BLOCK record is FULL. It runs BEFORE every
 * other return, so neither a missing database nor an unparseable name, nor a stored ALLOW or WARN, nor no decision at all
 * serves a tarball: a BLOCK the record could not hold might be any of them. The one exception is an exact override that
 * is established (looked up without error). Anything that cannot be read is refused.
 */
function enforceWhileFull(db, canonicalName, filename, log, ctx, state) {
  let version = null;
  const refuse = (why) => ({ refuse: { status: 503, error: 'chaingate_storage_degraded',
    detail: `${canonicalName}${version != null ? `@${version}` : ` (${filename})`}: ${why}. The unstored-BLOCK record is full `
      + '(a resource-safety refusal; not a finding about this package): tarballs without a stored BLOCK or an exact '
      + 'override are refused until the proxy is restarted after storage is repaired' } });
  try {
    version = parseTarballVersion(canonicalName, filename);
    if (version == null) return refuse('the version cannot be derived from the tarball name');
    state.tarballVersion = version;
    if (!db) return refuse('no witness database');
    if (ctx.overriddenLive?.(canonicalName, version)) {
      log?.info?.(`[override] ${canonicalName}@${version}: allowing while the unstored-BLOCK record is full`);
      state.tarballDecided = true;
      state.override = true;                                   // served under an exact override
      return null;
    }
    const known = ctx.unstored?.get(canonicalName, version) ?? null;
    if (known) {
      state.blockFacts = factsFromBits(known.reasons);    // as on the normal path
      return rememberedBlock(canonicalName, version, known);
    }
    // The one applicable-BLOCK rule (override handled above).
    const applicable = db.getApplicableDecision(canonicalName, version, { overrideLive: false });
    if (applicable.block) {
      try { state.blockFacts = pendingFacts(db.getDecisionHistory(canonicalName, version), applicable.pending); } catch { state.blockFacts = []; }
      return storedBlock(canonicalName, version, applicable.block);
    }
    return refuse(applicable.latest ? `its applicable stored decision is ${applicable.disposition}, which is not permission `
      + 'while the record is full' : 'it has no stored decision');
  } catch (err) {
    return refuse(`its stored decision could not be read (${err.message})`);
  }
}

function rememberedBlock(canonicalName, version, known) {
  return {
    package: canonicalName,
    version,
    gates: known.gates,
    decided_at: known.remembered_at,
    persisted: false,
    detail: `BLOCK decided by this proxy process and NOT stored (${known.detail}); a restart forgets it`,
    reason: known.detail,                                      // what the record kept of the reason
    how_to_override: `chaingate allow ${canonicalName}@${version} --reason "<reason>"`,
  };
}

function storedBlock(canonicalName, version, decision) {
  return {
    package: canonicalName,
    version,
    gates: decision.gates_fired,
    decided_at: decision.decided_at,
    reason: decidingReason(decision.gates_fired, 'BLOCK'),       // the deciding reason
    how_to_override: `chaingate allow ${canonicalName}@${version} --reason "<reason>"`,
  };
}

/**
 * No evaluation covers the requested version and no BLOCK applies. The configuration's
 * existing "no decision could be made" semantics decide: a v3 seed with on_unusable_input BLOCK refuses; WARN, and
 * configurations without a v3 seed (the pilot gates' ALLOW declaration), serve, logged. Never marked as evaluated.
 */
function evaluationFailed(canonicalName, what, why, log, ctx, state) {
  if (ctx.failuresBlock) {
    return { refuse: { status: 503, error: 'chaingate_evaluation_failed',
      detail: `${canonicalName} (${what}) was not evaluated: ${why}; the configured failure policy `
        + '(on_unusable_input: BLOCK) refuses it' } };
  }
  log?.warn?.(`[tarball-gate] ${canonicalName} (${what}): served without an evaluation (${why}; configured failure policy)`);
  state.tarballDecided = true;
  return null;
}

export function enforceTarballGate(db, canonicalName, filename, log, ctx = {}, state = {}) {
  if (ctx.unstored?.full) return enforceWhileFull(db, canonicalName, filename, log, ctx, state);
  if (!db) return null;
  const version = parseTarballVersion(canonicalName, filename);
  // No exact version, so no evaluation can cover it; the configured failure semantics decide.
  if (version == null) return evaluationFailed(canonicalName, filename, 'the version cannot be derived from the tarball name', log, ctx, state);
  state.tarballVersion = version;
  const known = ctx.unstored?.get(canonicalName, version) ?? null;
  if (known) {
    if (ctx.overriddenLive?.(canonicalName, version)) {
      log?.info?.(`[override] ${canonicalName}@${version}: allowing a BLOCK that was not stored`);
      state.tarballDecided = true;
      state.override = true;
      return null;
    }
    state.blockFacts = factsFromBits(known.reasons);    // the held reason bits, never the newest text
    return rememberedBlock(canonicalName, version, known);
  }
  const lookupFailed = (err) => {
    log?.warn?.(`[tarball-gate] decision lookup failed: ${err.message}`);
    // Without a v3 seed there is no failure policy, and a lookup error is refused. An
    // explicitly configured on_unusable_input WARN keeps availability; a held BLOCK was refused above.
    if (ctx.lookupErrorsRefuse ?? ctx.failuresBlock) {
      return { refuse: { status: 503, error: 'chaingate_decision_lookup_failed',
        detail: `the stored decision for ${canonicalName}@${version} could not be read (${err.message}); `
          + (ctx.failuresBlock ? 'the configured failure policy (on_unusable_input: BLOCK) refuses it'
            : 'without a v3 seed a decision that cannot be read is refused') } };
    }
    log?.warn?.(`[tarball-gate] ${canonicalName}@${version}: served without a decision (configured failure policy)`);
    state.tarballDecided = true;
    return null;
  };
  // An exact override applies while it exists. One that cannot be read is no override, as before.
  let override = null;
  try {
    override = db.getOverride(canonicalName, version);
  } catch (err) {
    log?.warn?.(`[tarball-gate] override lookup failed: ${err.message}`);
  }
  if (override) {
    log?.info?.(`[override] ${canonicalName}@${version}: allowing (reason: ${override.reason})`);
    state.tarballDecided = true;
    state.override = true;
    return null;
  }
  // The decision that APPLIES under the one applicable-BLOCK rule (witness/decision-rule.js),
  // the same rule the store uses for its writes: a later SKIP, error, input-rule or unrecognised row never clears a BLOCK.
  let applicable;
  try {
    applicable = db.getApplicableDecision(canonicalName, version, { overrideLive: false });
  } catch (err) {
    return lookupFailed(err);
  }
  if (applicable.block) {
    // The reasons that still apply, each confirmed by a stored row's structural facts
    try { state.blockFacts = pendingFacts(db.getDecisionHistory(canonicalName, version), applicable.pending); } catch { state.blockFacts = []; }
    return storedBlock(canonicalName, version, applicable.block);
  }
  state.applicable = applicable;          // what the served version's record says
  // No applicable BLOCK. Serve only on an evaluation this process made for this exact version.
  if (state.c1?.busy) {
    return { refuse: { status: 503, error: 'chaingate_evaluation_busy',
      detail: `${canonicalName}@${version} could not be evaluated now (${state.c1.why}); a resource refusal, not a finding` } };
  }
  if (state.c1 && !state.c1.ok) return evaluationFailed(canonicalName, version, state.c1.why, log, ctx, state);
  state.tarballDecided = true;
  return null;
}

function defaultLogger() {
  return {
    info: () => {},
    warn: (msg) => { console.error(msg); },
    error: (msg) => { console.error(msg); },
  };
}

// The internal endpoints answer only a local, non-browser request -- a loopback
// peer, a Host naming a loopback literal (so a rebinding hostname fails), no Origin, and Sec-Fetch-Site absent or `none`.
const LOCAL_HOST_RE = /^(?:127\.\d{1,3}\.\d{1,3}\.\d{1,3}|localhost|\[::1\])(?::\d{1,5})?$/i;
export function localOnly(req) {
  if (!isLoopbackPeer(req.socket?.remoteAddress)) return false;
  const host = req.headers.host;
  if (typeof host !== 'string' || !LOCAL_HOST_RE.test(host)) return false;
  if (req.headers.origin !== undefined) return false;
  const site = req.headers['sec-fetch-site'];
  return site === undefined || site === 'none';
}

export function createProxyServer(configOverrides = {}, hooks = {}) {
  const config = loadConfig(process.env, configOverrides);
  // Before anything is opened: bad caps refuse start-up by name.
  const caps = validateCaps({ entries: config.unstoredBlockCapEntries, bytes: config.unstoredBlockCapBytes });

  // Every line goes through ONE boundary. A logger that throws can no longer turn a handled
  // error into an unhandled request failure, and output is rate-bounded (proxy/log-boundary.js). `info` is a no-op in the
  // shipped logger and spends no budget. `hooks.logBudget` is for tests only.
  // Its once-a-minute tick (suppression summary, pending transitions) starts when the server listens, so a start-up that
  // refuses leaves no timer behind.
  const log = createLogBoundary(defaultLogger(), { silentLevels: ['info'], timers: false, ...(hooks.logBudget ?? {}) });

  // Fail-LOUD on witness open. If the DB path is unwritable, corrupt, or
  // points at a missing parent dir we cannot auto-create, the proxy refuses
  // to start rather than running degraded. At request time the witness path
  // is fail-open — see the
  // observeAndSendPackument try/catch and the handler-level fallback below.
  let witness = null;
  let witnessDb = null;
  let seedV3 = null;
  const integrityLogged = new Set();       // since 0.1.6: capture pins already logged as differing from the registry
  let depCache = null;
  let depFetcher = null;
  let witnessDbReal = null;               // reported by /_chaingate/self
  if (config.witnessDbPath) {
    try {
      mkdirSync(dirname(config.witnessDbPath), { recursive: true });
    } catch (err) {
      if (err.code !== 'EEXIST') throw err;
    }
    try {
      witnessDb = openWitnessDB(config.witnessDbPath);
      witnessDb.applySchema();
      try { witnessDbReal = realpathSync.native(config.witnessDbPath); } catch { witnessDbReal = config.witnessDbPath; }
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
        // since 0.1.6 the path may be a seed cache, checked on its signed root (tests pass their own key, bits and clock)
        seedV3 = openSeed(config.seedV3Path, { trust, pubkey: config.seedCacheKey ?? CHAINGATE_SEED_PUBKEY_B64,
          ...(config.seedCacheBits ? { shardBits: config.seedCacheBits } : {}), ...(config.seedCacheNow ? { now: config.seedCacheNow } : {}) });
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
          seed: seedV3, config: policyConfig, domainVersionCount: config.domainVersionCount,
          // since 0.1.6: the pins feed overlay in the witness store, read after the seed's own pins
          pinOverlay: (p, v) => (witnessDb ? witnessDb.advisoryPinFor(p, v) : null),
          // since 0.1.6: a capture pin whose analysed tarball differs from the registry's integrity is logged once per
          // version, so a wrong record is seen and corrected; the BLOCK stands
          onDecision: (d) => {
            if (d.pin?.integrity !== 'differs') return;
            const key = `${d.package}@${d.version}`;
            if (integrityLogged.has(key)) return;
            if (integrityLogged.size >= 10_000) integrityLogged.clear();
            integrityLogged.add(key);
            log.warn(`[advisories] ${key}: the registry's integrity differs from the tarball the advisory feed record was made from; `
              + 'the version stays blocked');
          } });
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

  // The configured failure policy: only a seed-v3 gate configured with
  // on_unusable_input BLOCK refuses when no decision can be made; pilot-only setups keep their ALLOW declaration.
  const unstored = createUnstoredBlocks({ log, caps });
  const failuresBlock = Boolean(seedV3) && config.policyOnUnusableInput === 'BLOCK';
  const overriddenLive = (name, version) => {
    try { return Boolean(witnessDb?.getOverride(name, version)); } catch { return false; }
  };
  const counters = { observation_errors: 0 };
  // Decision-lookup errors are refused without a v3 seed too (healthy path unchanged).
  const lookupErrorsRefuse = failuresBlock || !seedV3;
  // The exact versions this process evaluated, and the bounded single-flight evaluations.
  const tracker = witness ? createEvaluationTracker(hooks.c1 ?? {}) : null;
  // The user's pins, read live (PRAGMA data_version), last good set kept on a read failure
  const pinSet = witnessDb ? createPinSet(witnessDb, { log }) : null;
  // Since 0.1.6: the seed cache, kept current while the proxy runs (proxy/seed-cache.js). Its bucket fetch waits at most 5 s
  // per decision and never more than half the body timeout. With no cache in use yet it is fetched for the next start.
  const seedCache = config.seedCacheUrl && config.seedCachePath ? createSeedCache({
    get: config.seedCacheGet ?? shardSource(config.seedCacheUrl), cachePath: config.seedCachePath, seedKey: config.seedCacheKey ?? null,
    ...(config.seedCacheBits ? { bits: config.seedCacheBits } : {}), ...(config.seedCacheNow ? { now: config.seedCacheNow } : {}),
    waitMs: Math.min(config.seedCacheWaitMs ?? DEFAULT_SEED_CACHE_WAIT_MS, Math.floor((config.bodyTimeoutMs ?? 30_000) / 2)),
    feedKeys: async () => (pinsGet ? pinsGet('keys.json') : null), log,
  }) : null;
  seedCache?.attach(seedV3);
  const ctx = { unstored, failuresBlock, lookupErrorsRefuse, overriddenLive, counters, tracker, pins: pinSet, seedCache };

  // What this process served and refused, per install (memory), and the named and fact events
  // also kept on disk, once per install. Neither can fail a request: a recording error is logged and counted.
  const startedAt = new Date().toISOString();
  const installs = createInstallSummary(hooks.installSummary ?? {});
  const reportCounters = { record_failures: 0, disk_failures: 0, disk_pruned: 0 };
  if (witnessDb) {
    try { reportCounters.disk_pruned = witnessDb.pruneNamedFactEvents(); } catch (err) {
      log?.warn?.(`[report] could not prune the named/fact event record: ${err.message}`);
    }
  }
  const seedSha = () => seedV3?.report?.content_sha256 ?? null;
  // `event` goes to the summary; `disk` (or null) is written once per install and disk event: its claim is
  // keyed by its own kind and package@version, so no other event can use it up. `event` null: a disk row only.
  function noteInstall(req, event, disk = null) {
    const who = { session: req.headers['npm-session'], client: req.socket?.remoteAddress };
    let recorded;
    try {
      recorded = event == null ? installs.touch(who) : installs.record(who, event);
    } catch (err) {
      reportCounters.record_failures += 1;
      log?.warn?.(`[report] could not record a ${event?.kind ?? disk?.kind} event: ${err.message}`);
      return;
    }
    if (!disk || !witnessDb) return;
    const claim = `${disk.kind}|${disk.package_name}@${disk.version}${disk.diskKey ? `|${disk.diskKey}` : ''}`;   // keyed per version
    if (!installs.claimDisk(recorded.key, claim)) return;
    try {
      const { diskKey: _k, ...row } = disk;
      witnessDb.insertNamedFactEvent({ ...row, at: recorded.at, install_key: recorded.key, seed_sha256: seedSha() });
    } catch (err) {
      reportCounters.disk_failures += 1;
      log?.warn?.(`[report] could not write a ${disk.kind} event to disk: ${err.message}`);
    }
  }

  /**
   * Evaluate a package exactly as a resolving request would (the same upstream client, metadata and observation),
   * without serving its document. Returns { ok } or { ok: false, why }. Marks only the versions actually evaluated.
   */
  async function evaluatePackage(rawName, canonicalName, authorization) {
    let upstream;
    try {
      upstream = await fetchPackument(rawName, { config, requestHeaders: authorization ? { authorization } : {} });
    } catch (err) {
      return { ok: false, why: `the metadata request failed (${err.message})` };
    }
    if (upstream.statusCode !== 200) {
      try { await upstream.body.dump(); } catch { /* nothing to drain */ }
      return { ok: false, why: `the registry answered ${upstream.statusCode} for the metadata` };
    }
    let parsed;
    try {
      parsed = JSON.parse(Buffer.from(await upstream.body.arrayBuffer()).toString('utf8'));
      if (parsed && typeof parsed === 'object') {
        rememberManifestHooks(canonicalName, parsed.versions);   // MC: the manifest's install hooks
        rememberPackumentFacts(canonicalName, parsed);            // 0.1.5 shadow facts
        setDependencyDoc(canonicalName, parsed);                 // N1h judges from this document
      }
    } catch (err) {
      return { ok: false, why: `the metadata could not be read (${err.message})` };
    }
    if (!parsed || typeof parsed !== 'object' || !parsed.versions || typeof parsed.versions !== 'object') {
      return { ok: false, why: 'the metadata lists no versions' };
    }
    let observed;
    if (seedCache) await seedCache.need(canonicalName);
    try {
      observed = witness.observePackument(canonicalName, parsed);
    } catch (err) {
      counters.observation_errors += 1;
      // As on the metadata path: what the configured gates say a total failure means is remembered (held BLOCKs); the
      // package is not marked evaluated.
      try {
        const f = witness.failureDecisionsFor(parsed, err, canonicalName);
        for (const [v, d] of f.decisions) unstored.note(canonicalName, v, d);
      } catch { /* no failure decision either: nothing is marked, the failure semantics decide */ }
      return { ok: false, why: `the observation failed (${err.message})` };
    }
    for (const [v, d] of observed.decisions) unstored.note(canonicalName, v, d);
    if (observed.actual) tracker.markAll(canonicalName, observed.actual);
    return { ok: true };
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
    // The install summary for `chaingate report`. It lists installed package
    // names, so only a loopback peer gets it.
    if ((url.pathname === '/_chaingate/report' || url.pathname === '/_chaingate/self') && !localOnly(req)) {
      // A loopback peer is not enough -- a browser page whose name resolves to 127.0.0.1 is one
      // (DNS rebinding). Both endpoints also need a loopback Host and no browser-origin headers.
      writeJson(res, 404, { error: 'not_found', path: url.pathname });
      return;
    }
    if (url.pathname === '/_chaingate/report') {
      const all = url.searchParams.get('all') === '1';
      const snap = installs.snapshot({ all });
      writeJson(res, 200, {
        service: 'chaingate-proxy',
        version: PROXY_VERSION,
        started_at: startedAt,
        view: all ? 'all' : 'latest',
        policy: seedV3 ? POLICY_CONTRACT_VERSION : null,
        seed: seedV3 ? { sha256: seedSha(), history_cutoff: seedV3.meta?.history_cutoff ?? null, trust: config.seedV3Trust } : null,
        installs: snap.installs,
        stats: { ...snap.stats, ...reportCounters },
      }, { 'cache-control': 'no-store' });
      return;
    }

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
          // since 0.1.6, a seed cache: the digest of the root it is read under (no file digest: imports change the file)
          seed_cache_root: seedV3.shards?.root.digest ?? null,
          trust: config.seedV3Trust,
          authenticated: Boolean(seedV3.report?.authenticated),
          schema_version: seedV3.meta?.schema_version ?? null,
          corpus_snapshot_digest: seedV3.meta?.corpus_snapshot_digest ?? null,
          contract_version: seedV3.meta?.contract_version ?? null,
          // 0.1.4: how old the history behind every seed comparison is. The seed binds it (SEED_BINDING_KEYS);
          // null when the seed does not carry it, never a guessed date.
          history_cutoff: seedV3.meta?.history_cutoff ?? null,
          policy: {
            on_unusable_input: config.policyOnUnusableInput,
            on_no_evidence: config.policyOnNoEvidence,
          },
          config_source: config.configSource ?? null,
        } : null,
        unstored_blocks: unstored.describe(),
        // Whether this process enforces the user's pins, and what it holds
        pins: pinSet ? pinSet.stats() : { enforced: false, count: 0, generation: 0, last_error: 'no witness database' },
        // The database this process reads, so `pin`/`accept`/`unpin` can tell whether it applies their write
        witness_db: witnessDb ? witnessDbReal : null,
        dependency_cache: dependencyCacheStats(),                 // N1h's dependency cache
        evaluation: tracker ? tracker.stats() : null,
        // The process's decision-storage state, from its own signals.
        storage: storageReport({ health: witness?.storageHealth?.() ?? null, count: unstored.count,
          full: Boolean(unstored.full), observationErrors: counters.observation_errors }),
        logging: (({ emitted, suppressed, truncated, failures, transitions, transitions_suppressed, reserved }) => ({ emitted,
          suppressed, truncated, failures, transitions, transitions_suppressed, reserved }))(log.stats()),
      });
      return;
    }

    const route = classify(url.pathname);

    if (route.kind === 'unknown') {
      writeJson(res, 404, { error: 'not_found', path: url.pathname });
      return;
    }

    const canonicalName = normalizePackageName(route.name);
    const state = {};            // set when a BLOCK was computed for this request
    state.note = (event, disk) => noteInstall(req, event, disk);

    try {
      if (route.kind === 'packument') {
        // A pinned package is fetched without conditional headers -- a 304 would leave npm on its cached
        // document from before the pin.
        state.pins = pinSet ? pinSet.forPackage(canonicalName) : [];
        const requestHeaders = state.pins.length ? Object.fromEntries(Object.entries(req.headers)
          .filter(([h]) => h !== 'if-none-match' && h !== 'if-modified-since')) : req.headers;
        const upstream = await fetchPackument(route.name, {
          config,
          requestHeaders,
        });
        await observeAndSendPackument(res, upstream, witness, canonicalName, log, state, ctx);
      } else {
        // A version this process has not evaluated is evaluated BEFORE the gate decides --
        // single flight per package, bounded -- unless a held BLOCK or a live exact override already decides it, or the
        // record is FULL (its own rules refuse).
        const version = witness && tracker && !unstored.full ? parseTarballVersion(canonicalName, route.filename) : null;
        if (version != null && !unstored.get(canonicalName, version) && !overriddenLive(canonicalName, version)
          && !tracker.isEvaluated(canonicalName, version)) {
          try {
            const r = await tracker.run(canonicalName, () => evaluatePackage(route.name, canonicalName, req.headers.authorization));
            state.c1 = tracker.isEvaluated(canonicalName, version) ? { ok: true }
              : { ok: false, why: r.ok ? 'the requested version was not actually evaluated (absent from the metadata, or decided '
                + 'by a failure or the input rule)' : r.why };
          } catch (err) {
            state.c1 = err instanceof EvaluationBusy ? { busy: true, why: err.message } : { ok: false, why: err.message };
          }
        } else if (version != null && !unstored.get(canonicalName, version) && !overriddenLive(canonicalName, version)
          && manifestHooksFor(canonicalName, version) === undefined) {
          // The version was evaluated, but the registry manifest MC compares against
          // is no longer in the hook map. Re-run the evaluation to refill it -- unless MC is already final for this version. Best effort:
          // a failure here changes neither the stored record nor the serve decision; MC then records "not checked".
          // Nor for a version that will not be served (an applicable BLOCK, or one the user's pin withholds)
          let final = true;
          try {
            const app = witnessDb.getApplicableDecision(canonicalName, version, { overrideLive: false });
            // a version whose static walk is still due needs the manifest too (the keep list's source); since 0.1.6 every version's is
            final = Boolean(app.block) || (mcDeterminate(app.latest) && staticSettled(app.latest))
              || Boolean(pinSet && withheldBy(pinSet.forPackage(canonicalName), canonicalName, version));
          } catch { final = true; }
          if (!final) {
            try { await tracker.run(canonicalName, () => evaluatePackage(route.name, canonicalName, req.headers.authorization)); } catch { /* busy or failed */ }
          }
        }
        // Tarball BLOCK gate — check BEFORE contacting upstream so we don't
        // waste bandwidth on something we're going to refuse.
        const blocked = enforceTarballGate(witnessDb, canonicalName, route.filename, log, ctx, state);
        if (blocked?.refuse) {
          noteInstall(req, { kind: 'refused', package: canonicalName, version: state.tarballVersion ?? null, facts: [],
            status: blocked.refuse.status, reason: blocked.refuse.detail, policy: null });
          writeJson(res, blocked.refuse.status, { error: blocked.refuse.error, package: canonicalName,
            detail: blocked.refuse.detail });
          return;
        }
        if (blocked) {
          // A refusal resting on a fact names it in npm's own output (a 403 is never cached, so npm prints it).
          const facts = Array.isArray(state.blockFacts) ? state.blockFacts : [];
          const reason = blocked.reason ?? blocked.detail ?? null;
          const policy = Array.isArray(blocked.gates) ? policyPrefix(blocked.gates) : null;
          noteInstall(req, { kind: 'refused', package: canonicalName, version: blocked.version, facts, status: 403, reason, policy },
            facts.length ? { kind: 'fact-refused', package_name: canonicalName, version: blocked.version, classes: { facts },
              reason, policy_version: policy } : null);
          const notice = facts.length ? buildNotice({ kind: 'BLOCKED', pkg: canonicalName, version: blocked.version,
            labels: factLabels(facts, blocked.gates) }) : null;
          writeJson(res, 403, { error: 'blocked_by_chaingate', ...blocked }, notice ? { 'npm-notice': notice } : {});
          return;
        }
        // After the BLOCK gate (a BLOCK keeps its own reason) and the override (a pin wins over it), a version the
        // user's pin withholds is refused.
        const pin = state.tarballVersion != null && pinSet ? withheldBy(pinSet.forPackage(canonicalName), canonicalName, state.tarballVersion) : null;
        if (pin) {
          const detail = `${canonicalName}@${state.tarballVersion} is withheld by your pin on ${canonicalName} (${pin.k_version}); `
            + `undo: chaingate unpin ${canonicalName}`;
          noteInstall(req, { kind: 'refused', package: canonicalName, version: state.tarballVersion, facts: [], status: 403,
            reason: detail, policy: null, pinned: { k: pin.k_version } });
          const notice = pinNotice(canonicalName, state.tarballVersion, pin.k_version);
          writeJson(res, 403, { error: 'withheld_by_pin', package: canonicalName, version: state.tarballVersion, pinned_to: pin.k_version,
            detail }, notice ? { 'npm-notice': notice } : {});
          return;
        }
        // N1h's pending dependencies are fetched and judged now, before the notice is decided.
        if (state.applicable?.latest && !state.override && state.tarballVersion != null && witnessDb) {
          try {
            const outcome = await judgeAtTarball({ db: witnessDb, pkg: canonicalName, version: state.tarballVersion,
              latest: state.applicable.latest, fetchPackument, config, authorization: req.headers.authorization,
              budgetMs: hooks.dependencyBudgetMs, log });
            // written, or a concurrent writer won: either way the response follows the record as it is now
            if (outcome) state.applicable = witnessDb.getApplicableDecision(canonicalName, state.tarballVersion, { overrideLive: false });
          } catch (err) {
            log?.warn?.(`[n1h] ${canonicalName}@${state.tarballVersion}: not judged at download (${err.message})`);
          }
        }
        // A named WARN is said at the moment its tarball is fetched: a reserved log line and npm's own output.
        let named = [];
        const latest = state.applicable?.latest;
        if (latest && latest.disposition === 'WARN') named = classifyRows(latest.gates_fired).named;
        // An acceptance covering every named row of the decision applied now quiets the notice (the response is
        // then cacheable again); a later or different named signal is not accepted.
        let accepted = false;
        if (named.length && state.tarballVersion && witnessDb) {
          try {
            const acc = witnessDb.getAcceptance(canonicalName, state.tarballVersion);
            accepted = Boolean(acc) && Array.isArray(acc.named) && named.every((n) => acc.named.includes(n));
          } catch (err) {
            log?.warn?.(`[accept] ${canonicalName}@${state.tarballVersion}: acceptance not readable (${err.message}); notice kept`);
          }
        }
        if (named.length && state.tarballVersion) {
          log?.reserved?.('named', `[gate] ${canonicalName}@${state.tarballVersion}: WARN named ${named.join(', ')} `
            + `(${decidingReason(latest.gates_fired, 'WARN')})${accepted ? ' (accepted)' : ''}`, `${canonicalName}@${state.tarballVersion}`);
        }
        // 0.1.5: with the static_withhold switch on, a version whose record carries a named static WARN the user has not
        // accepted is withheld at every download, as a pin withholds (`chaingate accept` releases it). Off: served with its notice.
        if (config.staticWithhold && latest && state.tarballVersion != null && !state.override && !accepted) {
          const checks = withholdingChecks(latest.gates_fired);
          if (checks.length) {
            const w = staticWithheldResponse(canonicalName, state.tarballVersion, checks);
            noteInstall(req, { kind: 'refused', package: canonicalName, version: state.tarballVersion, facts: [], status: 403,
              reason: w.detail, policy: policyPrefix(latest.gates_fired) });
            writeJson(res, 403, w.body, w.notice ? { 'npm-notice': w.notice } : {});
            return;
          }
        }
        const notice = named.length && !accepted
          ? buildNotice({ kind: 'WARNING', pkg: canonicalName, version: state.tarballVersion, labels: named }) : null;
        const upstream = await fetchTarball(route.name, route.filename, {
          config,
          requestHeaders: req.headers,
        });
        if (upstream.statusCode === 200) {
          // What was served, classed from the record the gate applied; K for a named warning, now. Served
          // WITHOUT this process's evaluation (a failed evaluation under a serving failure policy, or no derivable version): not
          // checked, never the older stored row.
          const unevaluated = state.c1 && !state.c1.ok ? `served without an evaluation (${state.c1.why})`
            : (state.tarballVersion == null ? 'served without an evaluation (the version cannot be derived from the tarball name)' : null);
          const failed = { class: 'not-checked', coverage: 'failed', named: [], contributing: [] };
          const cls = state.override ? { class: 'override', coverage: null, named: [], contributing: [] }
            : (unevaluated ? failed : (latest ? servedClass(latest.gates_fired) : failed));
          const fromRecord = latest && !state.override && !unevaluated;
          const reason = fromRecord ? decidingReason(latest.gates_fired, latest.disposition)
            : (state.override ? 'served under an exact-version override (chaingate allow)' : (unevaluated ?? 'served without a stored decision'));
          const policy = fromRecord ? policyPrefix(latest.gates_fired) : null;
          let k = null;
          if (cls.class === 'named' && witnessDb && state.tarballVersion != null) {
            try { k = lastVersionWithoutSignal(witnessDb, canonicalName, state.tarballVersion); } catch (err) {
              log?.warn?.(`[report] ${canonicalName}@${state.tarballVersion}: last version without the signal not computed: ${err.message}`);
            }
          }
          noteInstall(req, { kind: 'served', package: canonicalName, version: state.tarballVersion ?? null, ...cls, reason, policy,
            notice: Boolean(notice), k, ...(accepted ? { accepted: true } : {}) },
          cls.class === 'named' ? { kind: 'named-served', package_name: canonicalName, version: state.tarballVersion,
            classes: { named: cls.named, contributing: cls.contributing, coverage: cls.coverage,
              history_cutoff: seedV3?.meta?.history_cutoff ?? null, ...(accepted ? { accepted: true } : {}) },
            reason, policy_version: policy, k_version: k } : null);
        }
        // Walk a copy of the stream unless the record already holds a determinate MC outcome;
        // only onto a record the CURRENT runner wrote (it carries install-introduced), never after a failed evaluation
        const current = state.applicable?.latest?.gates_fired?.some?.((g) => g && g.gate === 'install-introduced');
        const walkLatest = upstream.statusCode === 200 && state.tarballVersion != null && !state.override && witnessDb
          && current && !(state.c1 && !state.c1.ok) ? state.applicable.latest : null;
        // Static checks: since 0.1.6 EVERY download's keep list is walked, from the registry manifest remembered with the hook map;
        // the rows name what armed it (a named WARN row, the identity-break NOTE, the entry-path-change NOTE, the seed's coverage
        // WARN) or "every download". A settled static outcome is never walked for again (tarballs are immutable per version); a "no
        // manifest" or ceiling outcome, or 0.1.5's "not armed", is retried at the next download. The walk stays on a copy of the
        // stream; the download is held only with the static_withhold switch.
        const armed = walkLatest ? walkReason(walkLatest.gates_fired) : null;
        const staticDue = Boolean(walkLatest && !staticSettled(walkLatest));
        let keepOpts = {}; let staticWhy = null; let armedSlot = false; let staticManifest; let walkWaitMs = null;
        if (walkLatest && (!mcDeterminate(walkLatest) || staticDue) && armed) {
          staticManifest = manifestEntryFor(canonicalName, state.tarballVersion);
          if (staticManifest === undefined) staticWhy = 'no-manifest';
          else {
            const waitMs = Math.min(config.staticWalkWaitMs ?? DEFAULT_STATIC_WALK_WAIT_MS, Math.floor((config.bodyTimeoutMs ?? 30_000) / 2));
            const slot = await takeWalkSlot(waitMs);
            walkWaitMs = Number(slot.waitedMs.toFixed(3));
            if (!slot.ok) staticWhy = 'budget';
            else { armedSlot = true; staticWhy = 'armed'; keepOpts = { keep: keepListFor(staticManifest).paths }; }
          }
        }
        const mcWalk = Boolean(walkLatest && (!mcDeterminate(walkLatest) || staticDue));
        // 0.1.5 entry facts: EVERY served version, armed or not, has its main and bin facts stored
        // once (witness.db entry_facts), for S7's predecessor. An armed walk keeps them already; any other walk keeps only them,
        // under its own ceiling (MAX_FACTS_WALKS); past it, or on a storage error, the version is tried again at its next download.
        let factsDue = false; let factsSlot = false; let factsManifest;
        try {
          factsDue = Boolean(upstream.statusCode === 200 && state.tarballVersion != null && witnessDb
            && !witnessDb.hasEntryFacts(canonicalName, state.tarballVersion));
        } catch (err) { log?.warn?.(`[facts] ${canonicalName}@${state.tarballVersion}: not readable (${err.message}); not stored`); }
        if (factsDue) {
          factsManifest = staticWhy === 'armed' ? staticManifest : manifestEntryFor(canonicalName, state.tarballVersion);
          if (staticWhy === 'armed') factsSlot = false;              // the armed keep list holds main and bin already
          else if (factsWalks >= MAX_FACTS_WALKS) factsDue = false;
          else {
            factsWalks += 1; factsSlot = true;
            keepOpts = { keep: factsManifest === undefined ? (pj) => entryKeepFor(pj) : entryKeepFor(factsManifest) };
          }
        }
        // 0.1.5 shadow facts: the facts walk also tallies every file's size by class, for the next version's size change
        const shapeTally = factsDue ? createShapeTally() : null;
        if (shapeTally) keepOpts = { ...keepOpts, onFile: shapeTally.onFile };
        // 0.1.5 static-checks-1.6: an ARMED walk also reads every file's first 2 MiB for the member facts and streams a hook
        // target over the keep cap through the base64 counter; facts only, stored beside the entry facts, never a row
        const memberTally = staticWhy === 'armed' ? createMemberTally() : null;
        if (memberTally) keepOpts = { ...keepOpts, onMember: memberTally.onMember, memberWindow: FACTS_LIMITS.windowBytes, shareOf: makeBase64Share };
        const walker = mcWalk || factsDue ? createTarWalker(keepOpts) : null;
        const headerFn = notice && upstream.statusCode === 200 ? (h) => withNotice(h, notice) : null;
        const tap = walker ? (c) => walker.write(c) : null;
        let held = null;
        try {
          // 0.1.5: with the user's static_withhold switch on, an ARMED download is held (up to 8 MiB) while the checks read it
          if (config.staticWithhold && armedSlot && walker) {
            held = await holdUpstream(res, upstream, upstream.statusCode, headerFn, tap, STATIC_WITHHOLD_CAP_BYTES);
          } else await streamUpstream(res, upstream, upstream.statusCode, headerFn, tap);
        } catch (err) {
          if (armedSlot) { freeWalkSlot(); armedSlot = false; }            // the slot is freed on every exit, or the ceiling would stick
          if (factsSlot) { factsWalks -= 1; factsSlot = false; }
          throw err;
        }
        const walk = walker ? await walker.end() : null;
        if (armedSlot) { freeWalkSlot(); armedSlot = false; }
        if (factsSlot) { factsWalks -= 1; factsSlot = false; }
        // a complete walk is the tarball's facts; a refused archive is stored as refused only once the whole download was served
        // (an aborted one, or a walk that fell behind, says nothing about the archive and is tried again)
        let factsWrote = false; let factsShape = null;
        if (walk && factsDue && (walk.ok || (res.writableFinished && !/fell behind/.test(String(walk.reason))))) {
          try {
            // the proxy's own facts time for this download, stored with the facts
            const t0 = performance.now();
            const ef = entryFactsOf({ manifest: factsManifest ?? null, packageJson: walk.ok ? parsedPackageJson(walk) : null, walk });
            const factsMs = Number((performance.now() - t0).toFixed(3));
            factsShape = walk.ok && shapeTally ? shapeTally.result() : null;
            factsWrote = witnessDb.recordEntryFacts({ package_name: canonicalName, version: state.tarballVersion,
              static_checks_version: STATIC_CHECKS_VERSION, facts_ms: factsMs, shape: factsShape, walk_wait_ms: walkWaitMs, ...ef }) === 'wrote';
          } catch (err) {
            log?.warn?.(`[facts] ${canonicalName}@${state.tarballVersion}: not stored (${err.message})`);
          }
        }
        if (walk && mcWalk) {
          // S7's predecessor: the last version this proxy served before this one; a read failure is "not checked", never a cold start
          const predecessorFacts = (pkg, v) => {
            try { return witnessDb.predecessorEntryFacts(pkg, v); } catch (err) {
              log?.warn?.(`[facts] ${pkg}@${v}: predecessor not readable (${err.message})`); return 'unreadable';
            }
          };
          let lateRows = null;                                  // MC's row and the static rows (1.2 roles), computed once
          // since 0.1.6: then install-introduced re-read against the tarball package.json npm runs, and the seed-v3 result when a
          // late guard puts a re-tiered strict row back to WARN (gates/retier-late.js)
          const withTarball = (rows) => {
            const out = [...rows];
            const pj = walk.ok ? parsedPackageJson(walk) : null;
            const reg = manifestHooksFor(canonicalName, state.tarballVersion);
            const prevII = walkLatest.gates_fired?.find?.((g) => g && g.gate === 'install-introduced');
            const ii = pj && reg !== undefined ? tarballRow(prevII, hookDict(pj), reg) : null;
            if (ii) out.push(ii);
            const merged = [...(walkLatest.gates_fired || []).filter((g) => g && !out.some((r) => r.gate === g.gate)), ...out];
            const rr = reraise(merged);
            if (rr) out.push(rr);
            return out;
          };
          const rowsOfWalk = () => lateRows ?? (lateRows = withTarball([mcRow(walk, manifestHooksFor(canonicalName, state.tarballVersion)),
            ...(staticWhy === 'armed' ? staticRows({ manifest: staticManifest, packageJson: parsedPackageJson(walk), walk, armed,
              predecessor: predecessorFacts(canonicalName, state.tarballVersion),
              // static-checks-1.8: S8 and S9 read the member facts the armed walk gathered
              ...(memberTally ? (({ members, over }) => ({ members, membersOver: over }))(memberTally.result()) : {}) })
              : staticWhy === 'no-manifest' ? noManifestRows(armed)
                : budgetRows(walkWaitMs ?? 0)).map(withRole)]));
          // 0.1.5: a held download is served or withheld only now, after the walk; withheld only for a named static WARN
          // the user has not accepted (while every check is contributing this never happens, and the held bytes are served)
          let staticHold = null;
          if (held?.held) {
            let checks = [];
            try { checks = withholdingChecks(rowsOfWalk().slice(1)); } catch (err) {
              log?.warn?.(`[static] ${canonicalName}@${state.tarballVersion}: rows not computed (${err.message}); served`);
            }
            if (checks.length) {
              try {
                const acc = witnessDb.getAcceptance(canonicalName, state.tarballVersion);
                if (acc && Array.isArray(acc.named) && checks.every((c) => acc.named.includes(c))) checks = [];
              } catch (err) {
                log?.warn?.(`[accept] ${canonicalName}@${state.tarballVersion}: acceptance not readable (${err.message}); withheld`);
              }
            }
            if (checks.length) {
              staticHold = staticWithheldResponse(canonicalName, state.tarballVersion, checks);
              noteInstall(req, { kind: 'refused', package: canonicalName, version: state.tarballVersion, facts: [], status: 403,
                reason: staticHold.detail, policy: policyPrefix(walkLatest.gates_fired) });
              writeJson(res, 403, staticHold.body, staticHold.notice ? { 'npm-notice': staticHold.notice } : {});
            } else {
              res.writeHead(upstream.statusCode, held.headers);
              res.end(held.body);
            }
            await settled(res);
          }
          // an aborted download is not recorded: it is walked again next time (a withheld one is recorded: its rows withheld it)
          if (res.writableFinished || staticHold) {
            try {
              const [row, ...sRows] = rowsOfWalk();
              // the late rows that are a NEW named WARN: MC's, and (since 0.1.5, S0 and S5) a named static check's
              const changed = (r) => { const prev = walkLatest.gates_fired?.find?.((g) => g && g.gate === r.gate); return !(prev && prev.result === r.result && prev.detail === r.detail); };
              const lateNamed = [row, ...sRows].filter((r) => r.result === 'WARN' && (r.gate === MC_GATE || r.gate === 'seed-v3' || NAMED_RUNNER_GATES.includes(r.gate)) && changed(r));
              const outcome = recordLate({ db: witnessDb, pkg: canonicalName, version: state.tarballVersion, latest: walkLatest, rows: [row, ...sRows] });
              if (outcome === 'wrote' && lateNamed.length) {
                for (const r of lateNamed) {
                  log?.reserved?.('named', `[gate] ${canonicalName}@${state.tarballVersion}: WARN named ${r.gate} (${r.detail})`,
                    `${canonicalName}@${state.tarballVersion}|${r.gate}`);
                }
              }
              // a withheld download was already reported as refused (its rows withheld it): no served late event for it
              if (outcome === 'wrote' && lateNamed.length && !staticHold) {
                const now = witnessDb.getLatestDecision(canonicalName, state.tarballVersion);
                const reason = decidingReason(now.gates_fired, 'WARN');
                const cls = servedClass(now.gates_fired);
                let k = null;                                          // K for the late event too
                try { k = lastVersionWithoutSignal(witnessDb, canonicalName, state.tarballVersion); } catch { k = null; }
                noteInstall(req, { kind: 'served', package: canonicalName, version: state.tarballVersion, ...cls, reason,
                  policy: policyPrefix(now.gates_fired), notice: false, k, late: true },
                { kind: 'named-served', package_name: canonicalName, version: `${state.tarballVersion}`, diskKey: 'late',
                  classes: { named: cls.named, contributing: cls.contributing, coverage: cls.coverage, late: true,
                    history_cutoff: seedV3?.meta?.history_cutoff ?? null }, reason,
                  policy_version: policyPrefix(now.gates_fired), k_version: k });
              }
            } catch (err) {
              log?.warn?.(`[mc] ${canonicalName}@${state.tarballVersion}: not recorded (${err.message})`);
            }
            // 0.1.5 static-checks-1.6: the armed walk's facts, once per version, when its rows are recorded; no row reads them
            if (memberTally) {
              try {
                if (!witnessDb.staticFactsFor(canonicalName, state.tarballVersion)) {
                  const t = memberTally.result(); const t1 = performance.now();
                  const sf = staticFactsOf({ manifest: staticManifest, packageJson: walk.ok ? parsedPackageJson(walk) : null, walk,
                    members: t.members, membersOver: t.over });
                  // the time 1.6 added to this walk (the walker's memberMs plus staticFactsOf), beside facts_ms; no bar in 0.1.5
                  const ms = (Number.isFinite(walk.memberMs) ? walk.memberMs : 0) + performance.now() - t1;
                  witnessDb.recordStaticFacts(canonicalName, state.tarballVersion, publicStaticFacts(sf), Number(ms.toFixed(3)));
                }
              } catch (err) {
                log?.warn?.(`[facts] ${canonicalName}@${state.tarballVersion}: static facts not recorded (${err.message})`);
              }
            }
          }
        }
        // 0.1.5 shadow facts: the dist-tag, sign-transition, known-owner and size-change facts, computed once per served
        // version after its first download's rows are final, stored beside its entry facts and shown in `why` and `report` (a later
        // download reads them back). Record only: nothing here is a runner row, so no verdict, tier or notice depends on it.
        if (upstream.statusCode === 200 && state.tarballVersion != null && witnessDb) {
          try {
            let facts = witnessDb.shadowFactsFor(canonicalName, state.tarballVersion);
            if (!facts && factsWrote) {
              const named = (v) => { const r = witnessDb.getLatestDecision(canonicalName, v); return r ? classifyRows(r.gates_fired).named : null; };
              const pred = witnessDb.predecessorEntryFacts(canonicalName, state.tarballVersion);
              facts = shadowFactsOf({ memo: packumentFactsFor(canonicalName), version: state.tarballVersion, shape: factsShape,
                predecessor: pred ? { version: pred.version, shape: pred.shape, named: named(pred.version) } : null,
                named: named(state.tarballVersion) ?? [] });
              witnessDb.recordShadowFacts(canonicalName, state.tarballVersion, facts);
              // an armed version's repository claim, once, after its response is finished: the one attestation bundle fetch,
              // bounded in time, bytes and fetches in flight; a failure is recorded as NOT_FETCHED with its reason. Since 0.1.6 every
              // download is walked, but only a version a recorded row arms costs this outbound fetch, as in 0.1.5
              if (staticWhy === 'armed' && armedBy(walkLatest.gates_fired) && !witnessDb.repoClaimFor(canonicalName, state.tarballVersion)) {
                await settled(res);
                if (res.writableFinished) {
                  const t2 = performance.now();
                  const limit = config.attestationMaxInFlight ?? REPO_CLAIM_LIMITS.maxInFlight;
                  const rc = await repoClaimFact({ memo: packumentFactsFor(canonicalName), name: canonicalName, version: state.tarballVersion,
                    predecessor: pred?.version ?? null,
                    fetchBundle: async (n, v) => {
                      if (claimFetches >= limit) return { ok: false, reason: 'too many provenance fetches in flight' };
                      claimFetches += 1;
                      try {
                        return await fetchAttestationBundle(n, v, { config, timeoutMs: config.attestationTimeoutMs ?? REPO_CLAIM_LIMITS.timeoutMs,
                          maxBytes: config.attestationMaxBytes ?? REPO_CLAIM_LIMITS.maxBytes });
                      } finally { claimFetches -= 1; }
                    } });
                  witnessDb.recordRepoClaim(canonicalName, state.tarballVersion, rc, Number((performance.now() - t2).toFixed(3)));
                }
              }
            }
            // static-checks-1.6: every walked version has them since 0.1.6 (`why` shows them); the report event carries them only for a
            // version a recorded row arms (a named static WARN included), as in 0.1.5, so a large install's report is not every package
            const sx = facts && armedBy(witnessDb.getLatestDecision(canonicalName, state.tarballVersion)?.gates_fired)
              ? witnessDb.staticFactsFor(canonicalName, state.tarballVersion) : null;
            const rc = facts ? witnessDb.repoClaimFor(canonicalName, state.tarballVersion) : null;      // the repository claim, armed versions only (a row arms)
            if (facts) noteInstall(req, { kind: 'facts', package: canonicalName, version: state.tarballVersion, facts, ...(sx ? { static_facts: sx } : {}),
              ...(rc ? { repo_claim: rc } : {}) });
          } catch (err) {
            log?.warn?.(`[facts] ${canonicalName}@${state.tarballVersion}: shadow facts not recorded (${err.message})`);
          }
        }
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
      // Fail-open: an unexpected internal error must
      // not break `npm install`. Log loudly, then attempt a raw upstream
      // passthrough that bypasses the witness entirely. If headers are
      // already sent we can't recover — just destroy the socket so the
      // client sees a clean failure instead of a half-written response.
      // Before any decision exists, the configured failure policy decides, and a remembered
      // BLOCK is never passed through. Once a decision exists the passthrough is unchanged (a computed BLOCK is refused below).
      let refusal = null;
      if (state.blockComputed) refusal = 'a BLOCK was computed';
      else if (route.kind === 'packument' && !state.decided) {
        if (unstored.full) refusal = 'full';
        else if (failuresBlock) refusal = 'no decision was made and the configured failure policy refuses';
        else if (unstored.forPackage(canonicalName).some(([v]) => !overriddenLive(canonicalName, v))) {
          refusal = 'no decision was made and the package has a BLOCK this process could not store';
        }
      } else if (route.kind !== 'packument' && !state.tarballDecided) {
        const v = state.tarballVersion;
        if (v != null && unstored.get(canonicalName, v) && !overriddenLive(canonicalName, v)) refusal = 'remembered';
        else if (failuresBlock) refusal = 'the tarball gate did not decide and the configured failure policy refuses';
        else if (unstored.full) refusal = 'full';
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
        // A raw passthrough would serve the version that was just BLOCKed.
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
      if (refusal === 'full') {
        // Defence in depth -- the FULL gate itself refuses anything it cannot read.
        if (route.kind === 'packument') refuseFull(res, canonicalName, `internal error before a decision: ${err.message}`);
        else {
          writeJson(res, 503, { error: 'chaingate_storage_degraded', package: canonicalName,
            detail: `internal error before the tarball gate decided (${err.message}); the unstored-BLOCK record is full `
              + '(a resource-safety refusal; not a finding about this package)' });
        }
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

  // The last guard: whatever escapes the handler -- a response that cannot be written inside
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
  // Since 0.1.6: the pins feed (users see "advisory feed"), fetched at start and hourly while a seed is in use and a feed URL is configured (a test
  // passes `pinsFeedGet` and `pinsSeedKey`). One fetch at a time; a feed problem is one log line and the kept cut keeps serving.
  const pinsGet = (seedV3 && witnessDb) ? (config.pinsFeedGet ?? (config.pinsFeedUrl ? urlSource(config.pinsFeedUrl) : null)) : null;
  let pinsTimer = null;
  let pinsBusy = null;
  let seedCacheTimer = null;
  const refreshPinsFeed = () => {
    if (!pinsGet) return Promise.resolve(null);
    pinsBusy ??= refreshPins({ get: pinsGet, db: witnessDb, ...(config.pinsSeedKey ? { seedKey: config.pinsSeedKey } : {}) })
      .then((r) => {
        if (r.outcome === 'accepted') log.info?.(`[advisories] advisory feed cut ${r.cut_at} accepted: ${r.rows} versions`);
        else if (r.outcome === 'held') log.warn(`[advisories] advisory feed cut ${r.cut_at} held: ${r.why}. Take it with: chaingate update-advisories --accept-cut ${r.digest}`);
        else if (r.outcome !== 'same') log.warn(`[advisories] advisory feed ${r.outcome}: ${r.why}; the kept cut keeps serving`);
        return r;
      }, (err) => { log.warn(`[advisories] the advisory feed result could not be recorded: ${err.message}`); return null; })
      .finally(() => { pinsBusy = null; });
    return pinsBusy;
  };
  server.on('listening', () => {
    if (logTick) return;
    logTick = setInterval(() => { try { log.tick(); } catch { /* reporting only */ } }, 60_000);
    logTick.unref?.();
    if (pinsGet && !pinsTimer) {
      refreshPinsFeed();
      pinsTimer = setInterval(refreshPinsFeed, PINS_REFRESH_MS);
      pinsTimer.unref?.();
    }
    if (seedCache && !seedCacheTimer) {
      seedCache.refresh();
      seedCacheTimer = setInterval(() => seedCache.refresh(), SEED_CACHE_REFRESH_MS);
      seedCacheTimer.unref?.();
    }
  });
  server.config = config;
  server.witness = witness;
  server.witnessDb = witnessDb;
  server.seedV3 = seedV3;
  server.refreshPinsFeed = refreshPinsFeed;
  server.refreshSeedCache = () => (seedCache ? seedCache.refresh() : Promise.resolve(null));
  server.seedCacheState = () => (seedCache ? seedCache.state() : null);
  server.seedCacheIdle = () => (seedCache ? seedCache.idle() : Promise.resolve());
  server.depCache = depCache;
  server.depFetcher = depFetcher;
  const origClose = server.close.bind(server);
  server.close = (cb) => {
    // Drain the background dep fetcher first so no in-flight HTTP requests
    // touch a closing DB. stop() is graceful — current request finishes,
    // queue aborts, promise resolves.
    const finish = () => {
      if (logTick) { clearInterval(logTick); logTick = null; }
      if (pinsTimer) { clearInterval(pinsTimer); pinsTimer = null; }
      if (seedCacheTimer) { clearInterval(seedCacheTimer); seedCacheTimer = null; }
      log.tick();                                            // the last suppression summary, if any
      origClose(() => {
        try { witness?.close(); } catch { /* already closed */ }
        try { seedV3?.close(); } catch { /* already closed */ }
        if (cb) cb();
      });
    };
    // a pins fetch in flight finishes (or fails) before the store closes
    const pinsDone = pinsBusy ? pinsBusy.catch(() => {}) : null;
    if (depFetcher) {
      Promise.all([depFetcher.stop(), pinsDone]).then(finish, finish);
    } else if (pinsDone) {
      pinsDone.then(finish, finish);
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
