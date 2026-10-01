// U-05 Amendment 3 (P6b): BLOCKs this proxy process computed but could not store.
//
// The tarball gate reads STORED decisions. When the witness database cannot store a BLOCK (Amendment 1, A3:
// `persisted: false`), the packument already leaves the version out, but a direct tarball request found no stored BLOCK
// and was served. This record closes that gap for the life of the process, keyed by the exact canonical package name and
// the exact version string.
//
// Lifecycle, per returned decision for name@version (Amendment 3, Table M):
//   BLOCK, not stored                              -> remember (the latest replaces the earlier)
//   BLOCK, stored                                  -> forget: the database now governs
//   non-BLOCK, evaluated, not override-based       -> forget: the newest evaluated decision governs
//   non-BLOCK failure decision (evaluated: false)  -> keep: a failure never erases a known BLOCK
//   override-based ALLOW                           -> keep: overrides are checked live, so removing one restores the BLOCK
//
// Capacity: nothing is ever evicted and there is no cap -- evicting or dropping an entry would make a known BLOCK
// downloadable. Growth is bounded by the distinct versions this process BLOCKed while storage was failing; the count is
// reported, with a warning at every tenfold step from 10,000. Nothing is persisted: a restart forgets every entry.

const WATERMARK = 10_000;
const NOTE = 'BLOCKs this proxy process computed that were NOT stored; it enforces them for tarball requests '
  + 'until a stored decision replaces them. They are not persisted: a restart forgets them.';

export function isOverrideBased(decision) {
  return Array.isArray(decision?.results) && decision.results.some((r) => r?.gate === 'override');
}

function blockDetail(decision) {
  const rows = Array.isArray(decision?.results) ? decision.results : [];
  const row = rows.find((r) => r?.result === 'BLOCK' && typeof r.detail === 'string' && r.detail)
    ?? rows.find((r) => typeof r?.detail === 'string' && r.detail);
  return row ? String(row.detail).slice(0, 300) : 'no detail';
}

export function createUnstoredBlocks({ log = null } = {}) {
  const byPackage = new Map();          // name -> Map(version -> entry)
  let count = 0;
  let nextWarning = WATERMARK;

  // Reporting is never allowed to undo what it reports (Amendment 3, O1).
  const say = (level, msg) => { try { log?.[level]?.(msg); } catch { /* reporting only */ } };

  function forget(name, version) {
    const versions = byPackage.get(name);
    if (!versions || !versions.delete(version)) return;
    count -= 1;
    if (versions.size === 0) byPackage.delete(name);
  }

  function remember(name, version, decision) {
    let versions = byPackage.get(name);
    if (!versions) { versions = new Map(); byPackage.set(name, versions); }
    if (!versions.has(version)) count += 1;
    const entry = {
      remembered_at: new Date().toISOString(),
      detail: blockDetail(decision),
      gates: (decision.results ?? []).filter((r) => r?.result === 'BLOCK').map((r) => r.gate),
    };
    versions.set(version, entry);
    say('warn', `[witness] ${name}@${version}: BLOCK computed but NOT stored; enforced by this proxy process only `
      + `(a restart forgets it): ${entry.detail}`);
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
    get(name, version) { return byPackage.get(name)?.get(version) ?? null; },
    forPackage(name) { return [...(byPackage.get(name) ?? new Map())]; },
    get count() { return count; },
    describe() { return { count, note: NOTE }; },
  };
}
