import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { homedir } from 'node:os';
import { NPMRC_MARKER_START, NPMRC_MARKER_END } from './constants.js';

/**
 * Locate the target .npmrc.
 * - scope=project → <cwd>/.npmrc
 * - scope=user    → ~/.npmrc
 */
export function npmrcPath(scope = 'user', cwd = process.cwd()) {
  return scope === 'project' ? join(cwd, '.npmrc') : join(homedir(), '.npmrc');
}

/**
 * Read the current registry from .npmrc (first match of `registry=...`).
 * Returns null if the file doesn't exist or has no registry line.
 */
export function readCurrentRegistry(npmrcFile) {
  if (!existsSync(npmrcFile)) return null;
  const lines = readFileSync(npmrcFile, 'utf8').split('\n');
  for (const line of lines) {
    // Skip lines inside our own marker block
    const trimmed = line.trim();
    if (trimmed === NPMRC_MARKER_START) break;
    const m = trimmed.match(/^registry\s*=\s*(.+)/);
    if (m) return m[1].trim().replace(/\/+$/, '');
  }
  return null;
}

/**
 * Insert or replace the chaingate marker block in .npmrc.
 * Idempotent: re-running with the same registryUrl produces the same file.
 *
 * @param {string} npmrcFile
 * @param {string} registryUrl  e.g. 'http://127.0.0.1:6173'
 */
export function applyChaingateBlock(npmrcFile, registryUrl) {
  const block = [
    NPMRC_MARKER_START,
    `registry=${registryUrl}`,
    NPMRC_MARKER_END,
  ].join('\n');

  if (!existsSync(npmrcFile)) {
    writeFileSync(npmrcFile, block + '\n', 'utf8');
    return;
  }

  const content = readFileSync(npmrcFile, 'utf8');
  const lines = content.split('\n');
  const out = [];
  let inBlock = false;

  for (const line of lines) {
    if (line.trim() === NPMRC_MARKER_START) {
      inBlock = true;
      continue;
    }
    if (line.trim() === NPMRC_MARKER_END) {
      inBlock = false;
      continue;
    }
    if (!inBlock) out.push(line);
  }

  // Remove trailing empty lines before appending
  while (out.length > 0 && out[out.length - 1].trim() === '') out.pop();
  out.push('', block, '');

  writeFileSync(npmrcFile, out.join('\n'), 'utf8');
}

/**
 * Remove the chaingate marker block from .npmrc.
 * Idempotent: no-op if the block is absent.
 */
export function removeChaingateBlock(npmrcFile) {
  if (!existsSync(npmrcFile)) return false;

  const content = readFileSync(npmrcFile, 'utf8');
  if (!content.includes(NPMRC_MARKER_START)) return false;

  const lines = content.split('\n');
  const out = [];
  let inBlock = false;

  for (const line of lines) {
    if (line.trim() === NPMRC_MARKER_START) {
      inBlock = true;
      continue;
    }
    if (line.trim() === NPMRC_MARKER_END) {
      inBlock = false;
      continue;
    }
    if (!inBlock) out.push(line);
  }

  // Clean up trailing blank lines
  while (out.length > 0 && out[out.length - 1].trim() === '') out.pop();
  if (out.length > 0) out.push('');

  writeFileSync(npmrcFile, out.join('\n'), 'utf8');
  return true;
}

/**
 * Check if a scoped registry is present (e.g. @myorg:registry=...).
 * Returns array of scoped entries found.
 */
export function findScopedRegistries(npmrcFile) {
  if (!existsSync(npmrcFile)) return [];
  const lines = readFileSync(npmrcFile, 'utf8').split('\n');
  const scoped = [];
  for (const line of lines) {
    const m = line.trim().match(/^(@[^:]+):registry\s*=\s*(.+)/);
    if (m) scoped.push({ scope: m[1], registry: m[2].trim() });
  }
  return scoped;
}
