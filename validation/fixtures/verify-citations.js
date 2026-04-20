#!/usr/bin/env node
// Live-verification for reconstructed-attacks.json citations.
//
// For every (url, quote) in the fixture:
//   1. Fetch the URL live (HTML or JSON).
//   2. Normalize: cheerio-strip tags, decode entities, fold smart-quotes/
//      em-dashes/nbsp, collapse whitespace, lowercase.
//   3. Progressive match against the normalized body:
//      a. exact normalized substring, OR
//      b. strip trailing parenthetical annotation, retry, OR
//      c. split on ellipses (…/...), retry each part, OR
//      d. for quotes that embed ASCII-quoted tokens or version/email/
//         timestamp signals, require every signal to appear.
//   4. If step 3 fails, look up the most-recent Wayback snapshot via the
//      Availability API and retry against that. Wayback's snapshot is
//      post-JS-render, so it also bypasses client-rendered content.
//   5. Any citation still missing → NEEDS_MANUAL_REVIEW. Non-zero exit.

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';
import { load as loadHtml } from 'cheerio';

const here = dirname(fileURLToPath(import.meta.url));
const FIXTURE_PATH = resolve(here, 'reconstructed-attacks.json');

const UA = 'chaingate-citation-verifier/1.0 (+https://github.com/r-bedekar/chaingate)';
const FETCH_TIMEOUT_MS = 30_000;
const WAYBACK_AVAIL = 'https://archive.org/wayback/available?url=';

function normalize(s) {
  return s
    .replace(/[\u2018\u2019\u201A\u201B]/g, "'")
    .replace(/[\u201C\u201D\u201E\u201F]/g, '"')
    .replace(/[\u2013\u2014\u2015]/g, '-')
    .replace(/[\u00A0\u2000-\u200A\u202F\u205F\u3000]/g, ' ')
    .replace(/[\u2026]/g, '...')
    .replace(/\s+/g, ' ')
    .trim()
    .toLowerCase();
}

function htmlToText(html) {
  const $ = loadHtml(html);
  $('script, style, noscript, template').remove();
  return $.root().text();
}

function isJsonUrl(url) {
  return /^https:\/\/registry\.npmjs\.org\//.test(url);
}

function stripAllParens(s) {
  let out = s;
  for (let i = 0; i < 4; i++) {
    const next = out.replace(/\s*\([^()]*\)\s*/g, ' ');
    if (next === out) break;
    out = next;
  }
  return out;
}

function quotedSignals(quote) {
  // Extract from the quote MINUS all parenthetical groups — editorial prose
  // in parens routinely references adjacent versions or dates that aren't
  // on the cited page (e.g. "… 3.3.5 (4 days before 3.3.6)" when the URL
  // is the 3.3.5 packument).
  const body = stripAllParens(quote);
  const signals = new Set();
  const dq = body.match(/"[^"]{2,}"/g) || [];
  for (const m of dq) signals.add(m);
  const emails = body.match(/[\w.+-]+@[\w.-]+\.[a-zA-Z]{2,}/g) || [];
  for (const m of emails) signals.add(m);
  const semver = body.match(/\b\d+\.\d+\.\d+(?:[-+][\w.-]+)?\b/g) || [];
  for (const m of semver) signals.add(m);
  const iso = body.match(/\d{4}-\d{2}-\d{2}t\d{2}:\d{2}:\d{2}(?:\.\d+)?z/gi) || [];
  for (const m of iso) signals.add(m);
  return [...signals].map(normalize);
}

function packageNameFromRegistryUrl(url) {
  const m = url.match(/^https:\/\/registry\.npmjs\.org\/(@[^/]+\/[^/]+|[^/]+)(?:\/|$)/);
  return m ? decodeURIComponent(m[1]) : null;
}

const STOPWORDS = new Set([
  'the', 'and', 'for', 'only', 'with', 'from', 'that', 'this', 'was', 'are',
  'its', 'has', 'been', 'were', 'but', 'not', 'also', 'any', 'all', 'per',
  'via', 'into', 'onto', 'over', 'under', 'about', 'between', 'across',
  'against', 'after', 'before', 'during', 'same', 'other', 'each', 'such',
]);

function contentKeywords(quote) {
  const norm = normalize(stripAllParens(quote));
  const words = norm.match(/[a-z][a-z0-9-]{5,}/g) || [];
  return [...new Set(words.filter((w) => !STOPWORDS.has(w)))];
}

function matchQuote(quoteRaw, bodyNorm, ctx = {}) {
  const full = normalize(quoteRaw);
  if (bodyNorm.includes(full)) return { ok: true, via: 'full' };

  const noTrailParen = normalize(quoteRaw.replace(/\s*\([^()]*\)\s*$/, ''));
  if (noTrailParen && bodyNorm.includes(noTrailParen)) return { ok: true, via: 'trim-paren' };

  const parts = quoteRaw
    .split(/\s*(?:\.\.\.|\u2026)\s*/)
    .map((p) => p.replace(/\s*\([^()]*\)\s*$/, ''))
    .map(normalize)
    .filter((p) => p.length >= 8);
  if (parts.length > 1 && parts.every((p) => bodyNorm.includes(p))) {
    return { ok: true, via: 'split-ellipsis' };
  }

  const signals = quotedSignals(quoteRaw);
  if (signals.length > 0 && signals.every((s) => bodyNorm.includes(s))) {
    return { ok: true, via: 'signals', signalCount: signals.length };
  }

  // Registry-packument tautology: quote like "packument returned for this
  // name" is self-referential (the page IS the packument). Verify by
  // confirming the body parses as JSON and includes the package name from
  // the URL path.
  if (ctx.registryPackage && /packument/.test(full)) {
    const pkg = normalize(ctx.registryPackage);
    if (bodyNorm.includes(`"name":"${pkg}"`) || bodyNorm.includes(`"name": "${pkg}"`)) {
      return { ok: true, via: 'packument-tautology' };
    }
  }

  // inference_weaker is explicitly "inferred, not stated verbatim" per
  // source_type_legend. Relax to: URL reachable + every multi-char content
  // keyword (≥6 chars, non-stopword) from the quote's non-parenthetical
  // portion is present in the body.
  if (ctx.type === 'inference_weaker') {
    const kws = contentKeywords(quoteRaw);
    if (kws.length > 0 && kws.every((k) => bodyNorm.includes(k))) {
      return { ok: true, via: 'inference-keywords', kwCount: kws.length };
    }
  }

  return { ok: false, attempted: { full, noTrailParen, parts, signals } };
}

async function fetchText(url, { timeoutMs = FETCH_TIMEOUT_MS } = {}) {
  const ctl = new AbortController();
  const t = setTimeout(() => ctl.abort(), timeoutMs);
  try {
    const res = await fetch(url, {
      headers: { 'user-agent': UA, accept: '*/*' },
      redirect: 'follow',
      signal: ctl.signal,
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return await res.text();
  } finally {
    clearTimeout(t);
  }
}

async function waybackSnapshotUrl(url) {
  const res = await fetch(WAYBACK_AVAIL + encodeURIComponent(url), {
    headers: { 'user-agent': UA },
  });
  if (!res.ok) return null;
  const j = await res.json();
  const snap = j?.archived_snapshots?.closest;
  if (!snap?.available || !snap?.url) return null;
  return { url: snap.url.replace(/^http:/, 'https:'), timestamp: snap.timestamp };
}

async function collectBody(url) {
  const html = await fetchText(url);
  const text = isJsonUrl(url) ? html : htmlToText(html);
  return normalize(text);
}

function collectCitations(doc) {
  const out = [];
  for (const [ri, rec] of doc.records.entries()) {
    const tag = `${rec.package_name}@${rec.version}`;
    for (const [fieldName, f] of Object.entries(rec.fields || {})) {
      if (!Array.isArray(f.sources)) continue;
      for (const [si, src] of f.sources.entries()) {
        if (src.type === 'unavailable') continue;
        out.push({
          path: `records[${ri}].fields.${fieldName}.sources[${si}]`,
          tag,
          field: fieldName,
          url: src.url,
          quote: src.quote,
          type: src.type,
        });
      }
    }
  }
  return out;
}

async function main() {
  const doc = JSON.parse(readFileSync(FIXTURE_PATH, 'utf8'));
  const citations = collectCitations(doc);
  const byUrl = new Map();
  for (const c of citations) {
    if (!byUrl.has(c.url)) byUrl.set(c.url, []);
    byUrl.get(c.url).push(c);
  }

  const result = { live: [], archive: [], manual: [], fetch_fail: [] };

  for (const [url, group] of byUrl) {
    process.stdout.write(`\nFETCH ${url}\n`);
    let bodyNorm;
    try {
      bodyNorm = await collectBody(url);
    } catch (e) {
      console.error(`  ! fetch failed: ${e.message}`);
      for (const c of group) result.fetch_fail.push({ ...c, reason: e.message });
      continue;
    }

    const registryPackage = packageNameFromRegistryUrl(url);
    const misses = [];
    for (const c of group) {
      const m = matchQuote(c.quote, bodyNorm, { type: c.type, registryPackage });
      if (m.ok) {
        result.live.push({ ...c, via: m.via });
        process.stdout.write(`  VERIFIED_LIVE (${m.via}): ${c.tag} ${c.field}\n`);
      } else {
        misses.push(c);
      }
    }

    if (misses.length === 0) continue;

    let waybackBody = null;
    let wayback = null;
    try {
      wayback = await waybackSnapshotUrl(url);
      if (wayback) {
        process.stdout.write(`  wayback: ${wayback.url}\n`);
        const html = await fetchText(wayback.url);
        const text = isJsonUrl(url) ? html : htmlToText(html);
        waybackBody = normalize(text);
      }
    } catch (e) {
      console.error(`  ! wayback failed: ${e.message}`);
    }

    for (const c of misses) {
      if (waybackBody) {
        const m = matchQuote(c.quote, waybackBody, { type: c.type, registryPackage });
        if (m.ok) {
          result.archive.push({
            ...c,
            via: m.via,
            archive_url: wayback.url,
            archive_timestamp: wayback.timestamp,
          });
          process.stdout.write(`  VERIFIED_ARCHIVE (${m.via}): ${c.tag} ${c.field}\n`);
          continue;
        }
      }
      result.manual.push(c);
      process.stdout.write(`  NEEDS_MANUAL_REVIEW: ${c.tag} ${c.field}\n    quote: ${c.quote.slice(0, 140)}\n`);
    }
  }

  console.log('\n════════════════════════════════════════');
  console.log(`Total citations:      ${citations.length}`);
  console.log(`VERIFIED_LIVE:        ${result.live.length}`);
  console.log(`VERIFIED_ARCHIVE:     ${result.archive.length}`);
  console.log(`NEEDS_MANUAL_REVIEW:  ${result.manual.length}`);
  console.log(`FETCH_FAIL:           ${result.fetch_fail.length}`);

  if (result.archive.length) {
    console.log('\nArchive-fallback URLs:');
    const uniq = new Set();
    for (const a of result.archive) uniq.add(`${a.url}  →  ${a.archive_url}`);
    for (const u of uniq) console.log('  ' + u);
  }
  if (result.manual.length) {
    console.log('\nManual-review citations:');
    for (const m of result.manual) {
      console.log(`  • ${m.path}`);
      console.log(`    tag:   ${m.tag} / ${m.field} (${m.type})`);
      console.log(`    url:   ${m.url}`);
      console.log(`    quote: ${m.quote}`);
    }
  }
  if (result.fetch_fail.length) {
    console.log('\nFetch failures:');
    const seen = new Set();
    for (const f of result.fetch_fail) {
      if (seen.has(f.url)) continue;
      seen.add(f.url);
      console.log(`  • ${f.url}  →  ${f.reason}`);
    }
  }

  process.exit(result.manual.length === 0 && result.fetch_fail.length === 0 ? 0 : 1);
}

main().catch((e) => {
  console.error('FATAL', e);
  process.exit(2);
});
