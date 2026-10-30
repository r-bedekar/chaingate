// Bucket paths as the seed cache host serves them since 0.1.6: buckets/NNNNN/<gz_sha256>.gz. A test host maps one to the
// fixture's file for that bucket (buckets/NNNNN.db.gz, or a case's replacement), so a case's changed bytes are served under the
// name the root gives; any other path under buckets/ is not a bucket.
import fs from 'node:fs';
import path from 'node:path';

export const CA_BUCKET = /^buckets\/(\d{5})\/([0-9a-f]{64})\.gz$/;
/** The fixture path a request for `rel` reads: root and key files as they are, a bucket by its index, else null. */
export function fixtureRel(rel) {
  const m = CA_BUCKET.exec(rel);
  if (m) return `buckets/${m[1]}.db.gz`;
  return rel.startsWith('buckets/') ? null : rel;
}
/** The path a root names for bucket `i`. */
export function caPathOf(root, i) {
  return `buckets/${String(i).padStart(5, '0')}/${root.buckets[i].gz_sha256}.gz`;
}
/** The good fixture's root, parsed (no verification: tests verify where they mean to). */
export function fixtureRoot(fixDir) {
  return JSON.parse(fs.readFileSync(path.join(fixDir, 'good', 'root.json'), 'utf8'));
}
