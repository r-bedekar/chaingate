// U-05 Amendment 3 (P6b): BLOCKs this proxy process computed but could not store.
//
// The tarball gate reads STORED decisions. When the witness database cannot store a BLOCK (Amendment 1, A3:
// `persisted: false`), the packument already leaves the version out, but a direct tarball request found no stored BLOCK
// and was served. This record closes that gap for the life of the process, keyed by the exact canonical package name and
// the exact version string.
//
// Lifecycle, per returned decision for name@version (Amendment 3, Table M; unchanged):
//   BLOCK, not stored                              -> remember (the latest replaces the earlier)
//   BLOCK, stored                                  -> forget: the database now governs
//   non-BLOCK, evaluated, not override-based       -> forget: the newest evaluated decision governs
//   non-BLOCK failure decision (evaluated: false)  -> keep: a failure never erases a known BLOCK
//   override-based ALLOW                           -> keep: overrides are checked live, so removing one restores the BLOCK
//
// Bounded (U-05 gap-closure r2, owner decision 6, revision 2 §3; F2). Nothing is ever evicted or forgotten to make room:
//   - every retained string has a hard limit; an IDENTITY over its limit (name 214, version 256) is never truncated,
//     hashed or normalised -- the record enters FULL instead;
//   - every insert, replacement and removal is charged exactly (estimate T, below); a new key that does not fit (count or
//     bytes) sends the record to FULL; a replacement that does not fit keeps the old entry and only moves its timestamp;
//   - FULL is sticky for the life of the process. While FULL the tarball gate refuses every tarball that has neither a
//     stored or remembered BLOCK nor an established exact override (proxy/server.js): a BLOCK that could not be
//     remembered is never made downloadable. It is a resource-safety refusal, not a finding about any package.
// Accounting model (an estimate, enforced exactly; NOT a measurement of heap, and NOT a bound on total proxy memory):
//   entry   E = 2*(len(version) + len(detail) + sum(len(gates)) + 24) + C_ENTRY
//   package P = 2*len(name) + C_PKG                 T = sum(E) + sum(P) + C_FIXED
// Nothing is persisted: a restart forgets every entry and the FULL state.

export const LIMITS = Object.freeze({
  NAME_MAX: 214, VERSION_MAX: 256, DETAIL_MAX: 160, GATES_MAX: 8, GATE_NAME_MAX: 64, TS_LEN: 24,
  C_ENTRY: 256, C_PKG: 192, C_FIXED: 65536,
});
export const DEFAULT_CAPS = Object.freeze({ entries: 50_000, bytes: 64 * 1024 * 1024 });
const CAP_RANGE = Object.freeze({ entries: [1, 10_000_000], bytes: [1024 * 1024, 4 * 1024 ** 3] });
const WATERMARK = 10_000;
const SAMPLE_MAX = 50;
const NOTE = 'BLOCKs this proxy process computed that were NOT stored; it enforces them for tarball requests '
  + 'until a stored decision replaces them. They are not persisted: a restart forgets them (and the FULL state).';

/**
 * Validate the caps, refusing start-up by name. Unset (undefined, null or '') means the default. Accepts numbers or
 * numeric strings (the environment).
 */
export function validateCaps({ entries, bytes } = {}) {
  const one = (key, value, def, [lo, hi]) => {
    if (value === undefined || value === null || value === '') return def;
    const n = typeof value === 'number' ? value : (typeof value === 'string' && /^\d+$/.test(value.trim()) ? Number(value) : NaN);
    if (!Number.isInteger(n) || n < lo || n > hi) {
      throw new Error(`${key} must be an integer from ${lo} to ${hi}, got ${JSON.stringify(value)}`);
    }
    return n;
  };
  return {
    entries: one('unstored_block_cap_entries', entries, DEFAULT_CAPS.entries, CAP_RANGE.entries),
    bytes: one('unstored_block_cap_bytes', bytes, DEFAULT_CAPS.bytes, CAP_RANGE.bytes),
  };
}

export function isOverrideBased(decision) {
  return Array.isArray(decision?.results) && decision.results.some((r) => r?.gate === 'override');
}

/** Cut a diagnostic string to `max` UTF-16 units, marking the cut, without splitting a surrogate pair. */
function clipText(s, max) {
  const str = String(s);
  if (str.length <= max) return str;
  let end = max - 1;
  const code = str.charCodeAt(end - 1);
  if (code >= 0xd800 && code <= 0xdbff) end -= 1;
  return `${str.slice(0, end)}…`;
}

function blockDetail(decision) {
  const rows = Array.isArray(decision?.results) ? decision.results : [];
  const row = rows.find((r) => r?.result === 'BLOCK' && typeof r.detail === 'string' && r.detail)
    ?? rows.find((r) => typeof r?.detail === 'string' && r.detail);
  return clipText(row ? row.detail : 'no detail', LIMITS.DETAIL_MAX);
}

function blockGates(decision) {
  const names = (decision?.results ?? []).filter((r) => r?.result === 'BLOCK')
    .map((r) => clipText(String(r.gate ?? 'unknown'), LIMITS.GATE_NAME_MAX));
  if (names.length <= LIMITS.GATES_MAX) return names;
  const keep = names.slice(0, LIMITS.GATES_MAX - 1);
  return [...keep, `+${names.length - keep.length} more`];
}

const entryCost = (version, e) => 2 * (version.length + e.detail.length
  + e.gates.reduce((a, g) => a + g.length, 0) + LIMITS.TS_LEN) + LIMITS.C_ENTRY;
const packageCost = (name) => 2 * name.length + LIMITS.C_PKG;

/**
 * @param log   the proxy's log boundary (warn/error, and transition when present)
 * @param caps  { entries, bytes } -- already validated by the caller (validateCaps); defaults if absent
 * @param now   clock, for tests
 */
export function createUnstoredBlocks({ log = null, caps = DEFAULT_CAPS, now = Date.now } = {}) {
  const cap = { entries: caps?.entries ?? DEFAULT_CAPS.entries, bytes: caps?.bytes ?? DEFAULT_CAPS.bytes };
  const byPackage = new Map();          // name -> { versions: Map(version -> entry), charged }
  let count = 0;
  let total = LIMITS.C_FIXED;
  let nextWarning = WATERMARK;
  let full = false;
  let fullSince = null;
  const counters = { overflowed: 0, identity_rejected: 0, replacement_detail_kept: 0 };

  // Reporting is never allowed to undo what it reports (Amendment 3, O1).
  const say = (level, msg) => { try { log?.[level]?.(msg); } catch { /* reporting only */ } };
  const iso = () => new Date(now()).toISOString();

  function overflow(name, version, why) {
    counters.overflowed += 1;
    say('warn', `[witness] ${String(name).slice(0, 100)}@${String(version).slice(0, 60)}: BLOCK computed but NOT stored `
      + `and NOT remembered (${why}); the full-record refusal enforces it`);
    if (full) return;
    full = true; fullSince = iso();
    const msg = `[witness] unstored-BLOCK record FULL (${count} entries, about ${total} bytes estimated; ${why}): tarballs `
      + 'without a stored BLOCK or an exact override are refused until the proxy is restarted after storage is repaired '
      + '(a resource-safety refusal, not a finding about any package)';
    try { if (typeof log?.transition === 'function') log.transition('unstored-full', 'full', msg); else log?.warn?.(msg); } catch { /* reporting only */ }
  }

  function forget(name, version) {
    const pkg = byPackage.get(name);
    const entry = pkg?.versions.get(version);
    if (!entry) return;
    pkg.versions.delete(version);
    count -= 1; total -= entry.charged;
    if (pkg.versions.size === 0) { byPackage.delete(name); total -= pkg.charged; }
  }

  function remember(name, version, decision) {
    if (name.length > LIMITS.NAME_MAX || version.length > LIMITS.VERSION_MAX) {
      counters.identity_rejected += 1;
      overflow(name, version, `identity longer than the record holds (name ${name.length}/${LIMITS.NAME_MAX}, `
        + `version ${version.length}/${LIMITS.VERSION_MAX}); it is never truncated`);
      return;
    }
    const entry = { remembered_at: iso(), detail: blockDetail(decision), gates: blockGates(decision), charged: 0 };
    entry.charged = entryCost(version, entry);
    const pkg = byPackage.get(name);
    const existing = pkg?.versions.get(version);
    if (existing) {
      const delta = entry.charged - existing.charged;
      if (total + delta <= cap.bytes) { pkg.versions.set(version, entry); total += delta; }
      else { existing.remembered_at = entry.remembered_at; counters.replacement_detail_kept += 1; }
    } else {
      const add = entry.charged + (pkg ? 0 : packageCost(name));
      if (count + 1 > cap.entries || total + add > cap.bytes) {
        overflow(name, version, count + 1 > cap.entries ? `entry cap ${cap.entries} reached`
          : `estimated byte cap ${cap.bytes} reached`);
        return;
      }
      if (pkg) pkg.versions.set(version, entry);
      else byPackage.set(name, { versions: new Map([[version, entry]]), charged: packageCost(name) });
      count += 1; total += add;
    }
    const shown = pkg?.versions.get(version) ?? byPackage.get(name).versions.get(version);
    say('warn', `[witness] ${name}@${version}: BLOCK computed but NOT stored; enforced by this proxy process only `
      + `(a restart forgets it): ${shown.detail}`);
    if (count >= nextWarning) {
      say('warn', `[witness] ${count} BLOCKs are held in memory because they could not be stored; none is evicted`);
      nextWarning *= 10;
    }
  }

  return {
    /** Apply Table M to one returned decision. */
    note(name, version, decision) {
      if (typeof name !== 'string' || typeof version !== 'string' || !decision || typeof decision !== 'object') return;
      const block = decision.disposition === 'BLOCK';
      const stored = decision.persisted !== false;
      if (block && !stored) { remember(name, version, decision); return; }
      if (block) { forget(name, version); return; }
      if (decision.evaluated === false || isOverrideBased(decision)) return;
      forget(name, version);
    },
    get(name, version) { return byPackage.get(name)?.versions.get(version) ?? null; },
    forPackage(name) { return [...(byPackage.get(name)?.versions ?? new Map())]; },
    get count() { return count; },
    get full() { return full; },
    get estimatedBytes() { return total; },
    /** Test aid: T recomputed from scratch, to check the incremental accounting. */
    recompute() {
      let t = LIMITS.C_FIXED;
      for (const [name, pkg] of byPackage) {
        t += packageCost(name);
        for (const [version, e] of pkg.versions) t += entryCost(version, e);
      }
      return t;
    },
    describe() {
      const sample = [];
      outer: for (const [name, pkg] of byPackage) {
        for (const version of pkg.versions.keys()) {
          if (sample.length >= SAMPLE_MAX) break outer;
          sample.push(`${name}@${version}`);
        }
      }
      return { count, cap: { entries: cap.entries, bytes_estimated: cap.bytes }, estimated_bytes: total, full,
        full_since: fullSince, ...counters, sample, note: NOTE };
    },
  };
}
