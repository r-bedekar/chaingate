#!/usr/bin/env node
// Submit every unique citation URL to archive.org Save Page Now, wait for
// the snapshot to settle, fetch the archived HTML, compute its SHA-256,
// and patch every source entry in reconstructed-attacks.json with:
//   - archive_url       (https://web.archive.org/web/<timestamp>/<url>)
//   - archived_at       (YYYY-MM-DDTHH:MM:SSZ)
//   - archive_sha256    (hex digest of the archived response body)
//
// The sha256 binds a specific immutable snapshot to the citation so later
// tampering of the archive (or our fixture) is detectable.
//
// Run:  node validation/fixtures/archive-citations.js

import { readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';
import { createHash } from 'node:crypto';

const here = dirname(fileURLToPath(import.meta.url));
const FIXTURE_PATH = resolve(here, 'reconstructed-attacks.json');
const UA = 'chaingate-citation-archiver/1.0 (+https://github.com/r-bedekar/chaingate)';
const SPN_BASE = 'https://web.archive.org/save/';
const AVAIL_BASE = 'https://archive.org/wayback/available?url=';
const SPN_THROTTLE_MS = 10_000;
const SPN_TIMEOUT_MS = 60_000;
const MAX_SNAPSHOT_AGE_MS = 365 * 24 * 3600 * 1000; // 12 months

function sleep(ms) { return new Promise((r) => setTimeout(r, ms)); }

async function fetchText(url, extraHeaders = {}) {
  const ctl = new AbortController();
  const t = setTimeout(() => ctl.abort(), 60_000);
  try {
    const res = await fetch(url, {
      headers: { 'user-agent': UA, accept: '*/*', ...extraHeaders },
      redirect: 'follow',
      signal: ctl.signal,
    });
    if (!res.ok) throw new Error(`HTTP ${res.status} on ${url}`);
    return await res.text();
  } finally {
    clearTimeout(t);
  }
}

async function fetchBuffer(url) {
  const ctl = new AbortController();
  const t = setTimeout(() => ctl.abort(), 60_000);
  try {
    const res = await fetch(url, {
      headers: { 'user-agent': UA, accept: '*/*' },
      redirect: 'follow',
      signal: ctl.signal,
    });
    if (!res.ok) throw new Error(`HTTP ${res.status} on ${url}`);
    return Buffer.from(await res.arrayBuffer());
  } finally {
    clearTimeout(t);
  }
}

async function availability(url) {
  const body = await fetchText(AVAIL_BASE + encodeURIComponent(url));
  const j = JSON.parse(body);
  const snap = j?.archived_snapshots?.closest;
  if (!snap?.available || !snap?.url) return null;
  return { url: snap.url.replace(/^http:/, 'https:'), timestamp: snap.timestamp };
}

function tsToIso(ts) {
  const m = ts.match(/^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})$/);
  if (!m) return null;
  return `${m[1]}-${m[2]}-${m[3]}T${m[4]}:${m[5]}:${m[6]}Z`;
}

async function spnCapture(url) {
  // GET https://web.archive.org/save/<url> with manual redirect. A
  // successful synchronous save returns 302 with `Location:
  // https://web.archive.org/web/<ts>/<url>`.
  const ctl = new AbortController();
  const t = setTimeout(() => ctl.abort(), SPN_TIMEOUT_MS);
  try {
    const res = await fetch(SPN_BASE + url, {
      headers: { 'user-agent': UA, accept: '*/*' },
      redirect: 'manual',
      signal: ctl.signal,
    });
    if (res.status === 302 || res.status === 301) {
      const loc = res.headers.get('location');
      if (!loc) throw new Error(`${res.status} without location header`);
      const m = loc.match(/\/web\/(\d{14})\/(.*)$/);
      if (!m) throw new Error(`unexpected Location: ${loc}`);
      return { snapUrl: loc.replace(/^http:/, 'https:'), timestamp: m[1] };
    }
    if (res.status === 429 || res.status >= 500) {
      throw new Error(`SPN rate/server ${res.status}`);
    }
    throw new Error(`SPN unexpected status ${res.status}`);
  } finally {
    clearTimeout(t);
  }
}

function tsToDate(ts) {
  const m = ts.match(/^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})$/);
  if (!m) return null;
  return new Date(Date.UTC(+m[1], +m[2] - 1, +m[3], +m[4], +m[5], +m[6]));
}

async function hashArchive(snapUrl) {
  const idUrl = snapUrl.replace(/\/web\/(\d+)\//, '/web/$1id_/');
  const buf = await fetchBuffer(idUrl);
  const sha = createHash('sha256').update(buf).digest('hex');
  return { sha, bytes: buf.length };
}

async function resolveSnapshot(url) {
  process.stdout.write(`\n${url}\n`);

  // Step 1: availability — reuse a snapshot if it's within 12 months.
  let existing = null;
  try {
    existing = await availability(url);
  } catch (e) {
    process.stdout.write(`      avail API warn: ${e.message}\n`);
  }
  if (existing) {
    const d = tsToDate(existing.timestamp);
    const ageMs = d ? Date.now() - d.getTime() : Infinity;
    const ageDays = Math.round(ageMs / 86400000);
    if (ageMs <= MAX_SNAPSHOT_AGE_MS) {
      process.stdout.write(`      EXISTING snapshot (${ageDays}d old): ${existing.url}\n`);
      const h = await hashArchive(existing.url);
      process.stdout.write(`      sha256: ${h.sha} (${h.bytes} bytes)\n`);
      return {
        source: 'existing',
        archive_url: existing.url,
        archived_at: tsToIso(existing.timestamp),
        archive_sha256: h.sha,
      };
    }
    process.stdout.write(`      existing snapshot is ${ageDays}d old (> 12 months) — will SPN\n`);
  } else {
    process.stdout.write('      no existing snapshot — will SPN\n');
  }

  // Step 2: SPN (one attempt, 60s timeout).
  try {
    const snap = await spnCapture(url);
    process.stdout.write(`      SPN captured: ${snap.snapUrl}\n`);
    const h = await hashArchive(snap.snapUrl);
    process.stdout.write(`      sha256: ${h.sha} (${h.bytes} bytes)\n`);
    return {
      source: 'spn',
      archive_url: snap.snapUrl,
      archived_at: tsToIso(snap.timestamp),
      archive_sha256: h.sha,
    };
  } catch (e) {
    process.stdout.write(`      SPN failed: ${e.message}\n`);
    if (existing) {
      const h = await hashArchive(existing.url).catch(() => null);
      if (h) {
        process.stdout.write(`      falling back to stale snapshot: ${existing.url}\n`);
        return {
          source: 'existing-stale',
          archive_url: existing.url,
          archived_at: tsToIso(existing.timestamp),
          archive_sha256: h.sha,
        };
      }
    }
    throw new Error(`no archive available: ${e.message}`);
  }
}

async function main() {
  const doc = JSON.parse(readFileSync(FIXTURE_PATH, 'utf8'));

  const urls = new Set();
  for (const rec of doc.records) {
    for (const f of Object.values(rec.fields || {})) {
      for (const s of f.sources || []) urls.add(s.url);
    }
  }
  const uniqueUrls = [...urls];
  process.stdout.write(`Unique URLs to archive: ${uniqueUrls.length}\n\n`);

  const results = new Map();
  const failures = [];
  let spnCalls = 0;
  for (const u of uniqueUrls) {
    const needsSpn = await (async () => {
      try {
        const e = await availability(u);
        if (!e) return true;
        const d = tsToDate(e.timestamp);
        return !d || (Date.now() - d.getTime()) > MAX_SNAPSHOT_AGE_MS;
      } catch { return true; }
    })();
    if (needsSpn && spnCalls > 0) {
      await sleep(SPN_THROTTLE_MS);
    }
    try {
      const r = await resolveSnapshot(u);
      if (r.source === 'spn') spnCalls++;
      results.set(u, r);
    } catch (e) {
      failures.push({ url: u, reason: e.message });
    }
  }

  for (const rec of doc.records) {
    for (const f of Object.values(rec.fields || {})) {
      for (const s of f.sources || []) {
        const r = results.get(s.url);
        if (!r) continue;
        s.archive_url = r.archive_url;
        s.archived_at = r.archived_at;
        s.archive_sha256 = r.archive_sha256;
      }
    }
  }

  writeFileSync(FIXTURE_PATH, JSON.stringify(doc, null, 2) + '\n');
  const covered = uniqueUrls.length - failures.length;
  console.log(`\n════════════════════════════════════════`);
  console.log(`Archived: ${covered}/${uniqueUrls.length} URLs (SPN calls: ${spnCalls})`);
  if (failures.length) {
    console.log('\nUNARCHIVED (handle manually):');
    for (const f of failures) console.log(`  ${f.url}  →  ${f.reason}`);
  }
  console.log(`\nFixture patched: ${FIXTURE_PATH}`);
  process.exit(failures.length === 0 ? 0 : 2);
}

main().catch((e) => {
  console.error('FATAL', e);
  process.exit(2);
});
