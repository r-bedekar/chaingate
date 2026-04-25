import { createWriteStream, mkdirSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { randomBytes } from 'node:crypto';
import { SEED_FILES } from './constants.js';
import { resolveLatestSeedAssets } from './seed-resolver.js';

function formatMB(bytes) {
  return (bytes / (1024 * 1024)).toFixed(1);
}

function renderProgress(filename, received, total) {
  if (!process.stdout.isTTY) return;
  if (total > 0) {
    const pct = ((received / total) * 100).toFixed(1);
    process.stdout.write(
      `\r  ${filename}: ${formatMB(received)} MB / ${formatMB(total)} MB (${pct}%)`
    );
  } else {
    process.stdout.write(`\r  ${filename}: ${formatMB(received)} MB`);
  }
}

async function downloadStream(url, dest, filename) {
  const resp = await fetch(url, { redirect: 'follow' });
  if (!resp.ok) throw new Error(`Failed to download ${filename}: HTTP ${resp.status}`);

  const total = Number(resp.headers.get('content-length') || 0);
  const showProgress = total > 1024 * 1024 && process.stdout.isTTY;
  let received = 0;
  let lastRender = 0;

  const out = createWriteStream(dest);
  try {
    for await (const chunk of resp.body) {
      received += chunk.length;
      out.write(chunk);
      if (showProgress) {
        const now = Date.now();
        if (now - lastRender > 100) {
          renderProgress(filename, received, total);
          lastRender = now;
        }
      }
    }
  } finally {
    out.end();
    await new Promise((resolve, reject) => {
      out.on('finish', resolve);
      out.on('error', reject);
    });
    if (showProgress) {
      renderProgress(filename, received, total);
      process.stdout.write('\n');
    }
  }
}

/**
 * Download seed bundle (db + sha256 + sig) to a temp directory.
 * Resolves the latest seed release dynamically via the GitHub API,
 * then streams each asset (large DB file with a progress bar on TTYs).
 *
 * @returns {Promise<{dir: string, dbPath: string, sha256Path: string, sigPath: string, tagName: string}>}
 */
export async function fetchSeedBundle() {
  const { tagName, urls } = await resolveLatestSeedAssets();

  const dir = join(tmpdir(), `chaingate-seed-${randomBytes(6).toString('hex')}`);
  mkdirSync(dir, { recursive: true });

  const paths = {};
  for (const filename of SEED_FILES) {
    const url = urls[filename];
    const dest = join(dir, filename);
    await downloadStream(url, dest, filename);

    if (filename.endsWith('.sha256')) paths.sha256Path = dest;
    else if (filename.endsWith('.sig')) paths.sigPath = dest;
    else paths.dbPath = dest;
  }

  return { dir, ...paths, tagName };
}
