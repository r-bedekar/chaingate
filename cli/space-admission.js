// U-05 R2-2 (d): space admission before a staging copy (R2-2 §4.2, Addendum 1 §7, Addendum 2 §2.4).
//
// What a pass means, stated once: the operation was not refused up front. Other writers can consume space after the
// check, so admission guarantees nothing about space at copy time. The safety property is the cleanup of a failed copy,
// not this check. Sizes come from fstat/statfs as BigInt and every sum and comparison is BigInt.
import fs from 'node:fs';

export const RESERVE = 64n * 1024n * 1024n;              // R: kept free for everything else on the filesystem
export const ALLOC_BLOCKS = 4n;                           // A = 4 x f_bsize, allocation rounding
/** C for a v3 bundle: .sig + .sha256 + bundle.json + activation temp + intent. */
export const V3_SIDECARS = 4096n + 4096n + 65536n + 4096n + 4096n;
/** C for a legacy install: the two persisted sidecars and the pending-install marker. */
export const LEGACY_SIDECARS = 4096n + 4096n + 4096n;

const big = (v) => (typeof v === 'bigint' ? v : BigInt(v));

/** "1.9 GiB"-style figure for messages. */
export function human(bytes) {
  const n = Number(bytes); const u = ['bytes', 'KiB', 'MiB', 'GiB', 'TiB']; let i = 0; let v = n;
  while (v >= 1024 && i < u.length - 1) { v /= 1024; i += 1; }
  return i === 0 ? `${n} bytes` : `${v.toFixed(1)} ${u[i]}`;
}

/**
 * Admit a set of copies. `entries`: [{ dir, bytes, what }] where `bytes` is what that copy will add (BigInt or a safe
 * integer). Entries on the same device (st_dev) are SUMMED, because their copies coexist.
 *
 * @param {{statfs?: Function, stat?: Function}} [seam]  test seam; the real fs by default
 * @returns {{ok: boolean, refusal: string|null, warnings: string[], devices: object[]}}
 */
export function admit(entries, seam = {}) {
  const statfs = seam.statfs ?? ((d) => fs.statfsSync(d, { bigint: true }));
  const stat = seam.stat ?? ((d) => fs.statSync(d, { bigint: true }));
  const byDev = new Map();
  for (const e of entries) {
    const key = String(stat(e.dir).dev);
    const g = byDev.get(key) ?? { dir: e.dir, what: [], data: 0n };
    g.data += big(e.bytes); g.what.push(e.what); byDev.set(key, g);
  }
  const warnings = []; const devices = [];
  for (const g of byDev.values()) {
    let fsInfo = null; let why = null;
    try { fsInfo = statfs(g.dir); } catch (e) { why = e.code || e.message; }
    const bsize = fsInfo ? big(fsInfo.bsize) : 0n;
    if (!why && (bsize <= 0n || big(fsInfo.bavail) < 0n)) why = `the filesystem reported a block size of ${bsize}`;
    if (why) {
      // P2: a finite, bounded copy proceeds; a failed copy is cleaned up (decision D-d1, Addendum 1 §7)
      warnings.push(`free space could not be determined for ${g.dir} (${why}); the copy proceeds, and a copy failure `
        + 'is cleaned up with the active seed unchanged');
      devices.push({ dir: g.dir, what: g.what, required: null, available: null, determined: false });
      continue;
    }
    const required = g.data + ALLOC_BLOCKS * bsize + RESERVE;
    const available = big(fsInfo.bavail) * bsize;            // space an unprivileged process may use; never f_bfree
    devices.push({ dir: g.dir, what: g.what, required, available, determined: true });
    if (available < required) {
      return { ok: false, warnings, devices,
        refusal: `not enough free space: ${g.what.join(' and ')} needs about ${human(required)}, and `
          + `${human(available)} is available on the filesystem holding ${g.dir}. That is the data copied, in addition `
          + `to existing use, plus sidecars and a ${human(RESERVE)} reserve. Nothing was changed.` };
    }
  }
  return { ok: true, refusal: null, warnings, devices };
}
