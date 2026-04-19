#!/usr/bin/env node
// Verifier for validation/fixtures/reconstructed-attacks.json.
//
// Per the 2026-04-19 ground rules for Step 3, enforces:
//   1. every record has reconstructed: true
//   2. every required data field exists with a `sources: [...]` entry
//   3. every source entry has a non-empty URL
//   4. every source entry has a non-empty quote
//   5. every source entry has a recognized `type`
//   6. null values are paired with at least one `unavailable` source
//
// Run:  node validation/fixtures/verify-reconstruction.js
// Exits non-zero on any violation. CI-assertable.

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';

const here = dirname(fileURLToPath(import.meta.url));
const FIXTURE_PATH = resolve(here, 'reconstructed-attacks.json');

const REQUIRED_FIELDS = [
  'package_name',
  'version',
  'published_at_ms',
  'publisher_name',
  'publisher_email',
  'integrity_hash',
  'has_install_scripts',
  'provenance_present',
  'dependencies',
];

const ALLOWED_SOURCE_TYPES = new Set([
  'registry_data',
  'direct_quote',
  'corroboration',
  'inference_weaker',
  'unavailable',
]);

const EXPECTED_RECORDS = [
  ['axios', '1.14.1'],
  ['event-stream', '3.3.6'],
  ['ua-parser-js', '0.7.29'],
  ['ua-parser-js', '0.8.0'],
  ['ua-parser-js', '1.0.0'],
];

const violations = [];
function fail(path, msg) {
  violations.push(`${path}: ${msg}`);
}

const raw = readFileSync(FIXTURE_PATH, 'utf8');
let doc;
try {
  doc = JSON.parse(raw);
} catch (e) {
  console.error(`FATAL: ${FIXTURE_PATH} is not valid JSON — ${e.message}`);
  process.exit(2);
}

if (!Array.isArray(doc.records)) {
  console.error('FATAL: top-level `records` must be an array');
  process.exit(2);
}

const seen = new Set();
for (const [pkg, ver] of EXPECTED_RECORDS) {
  const match = doc.records.find(
    (r) => r.package_name === pkg && r.version === ver,
  );
  if (!match) fail('records', `missing required record ${pkg}@${ver}`);
  else seen.add(`${pkg}@${ver}`);
}

for (let i = 0; i < doc.records.length; i++) {
  const r = doc.records[i];
  const tag = `${r.package_name ?? '?'}@${r.version ?? '?'}`;
  const base = `records[${i}] (${tag})`;

  if (r.reconstructed !== true) {
    fail(base, 'reconstructed must be true');
  }

  if (!r.fields || typeof r.fields !== 'object') {
    fail(base, 'fields object missing');
    continue;
  }

  for (const fieldName of REQUIRED_FIELDS) {
    const path = `${base}.fields.${fieldName}`;
    const f = r.fields[fieldName];
    if (!f || typeof f !== 'object') {
      fail(path, 'required field object missing');
      continue;
    }
    if (!('value' in f)) {
      fail(path, 'field must have a `value` key (null is allowed)');
    }
    if (!Array.isArray(f.sources) || f.sources.length === 0) {
      fail(path, '`sources` must be a non-empty array');
      continue;
    }
    for (let s = 0; s < f.sources.length; s++) {
      const src = f.sources[s];
      const spath = `${path}.sources[${s}]`;
      if (!src || typeof src !== 'object') {
        fail(spath, 'source entry must be an object');
        continue;
      }
      if (typeof src.url !== 'string' || src.url.length === 0) {
        fail(spath, 'missing or empty `url`');
      } else if (!/^https?:\/\//.test(src.url)) {
        fail(spath, `url must start with http(s):// — got ${src.url}`);
      }
      if (typeof src.quote !== 'string' || src.quote.length === 0) {
        fail(spath, 'missing or empty `quote`');
      }
      if (typeof src.type !== 'string' || !ALLOWED_SOURCE_TYPES.has(src.type)) {
        fail(spath, `type must be one of ${[...ALLOWED_SOURCE_TYPES].join('|')} — got ${src.type}`);
      }
      if (typeof src.accessed_at !== 'string' || !/^\d{4}-\d{2}-\d{2}$/.test(src.accessed_at)) {
        fail(spath, `accessed_at must be YYYY-MM-DD — got ${src.accessed_at}`);
      }
    }
    if (f.value === null) {
      const hasUnavailable = f.sources.some((s) => s && s.type === 'unavailable');
      if (!hasUnavailable) {
        fail(path, 'null value must have at least one source with type=unavailable');
      }
    }
  }
}

if (violations.length === 0) {
  const total = doc.records.length;
  const required = EXPECTED_RECORDS.length;
  console.log(
    `verify-reconstruction: OK — ${total} record(s), all ${required} required records present, ` +
      `${REQUIRED_FIELDS.length} fields per record verified.`,
  );
  process.exit(0);
}

console.error(`verify-reconstruction: ${violations.length} violation(s):`);
for (const v of violations) console.error(`  - ${v}`);
process.exit(1);
