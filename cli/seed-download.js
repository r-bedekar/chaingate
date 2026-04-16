import { writeFileSync, mkdirSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { randomBytes } from 'node:crypto';
import { SEED_RELEASE_URL, SEED_FILES } from './constants.js';

/**
 * Download seed bundle (db + sha256 + sig) to a temp directory.
 * Uses Node's built-in fetch (available in Node 22+).
 *
 * @param {string} [baseUrl] Override the release URL.
 * @returns {Promise<{dir: string, dbPath: string, sha256Path: string, sigPath: string}>}
 */
export async function fetchSeedBundle(baseUrl = SEED_RELEASE_URL) {
  const dir = join(tmpdir(), `chaingate-seed-${randomBytes(6).toString('hex')}`);
  mkdirSync(dir, { recursive: true });

  const paths = {};
  for (const filename of SEED_FILES) {
    const url = `${baseUrl}/${filename}`;
    const resp = await fetch(url, { redirect: 'follow' });
    if (!resp.ok) {
      throw new Error(`Failed to download ${filename}: HTTP ${resp.status}`);
    }
    const buf = Buffer.from(await resp.arrayBuffer());
    const dest = join(dir, filename);
    writeFileSync(dest, buf);

    if (filename.endsWith('.sha256')) paths.sha256Path = dest;
    else if (filename.endsWith('.sig')) paths.sigPath = dest;
    else paths.dbPath = dest;
  }

  return { dir, ...paths };
}
