import { homedir } from 'node:os';
import { join } from 'node:path';

// ── Seed download ──────────────────────────────────────────────────
export const SEED_RELEASE_URL =
  'https://github.com/r-bedekar/chaingate/releases/latest/download';

export const SEED_FILES = [
  'chaingate-seed.db',
  'chaingate-seed.db.sha256',
  'chaingate-seed.db.sig',
];

// ── Default paths ──────────────────────────────────────────────────
export const DEFAULT_CHAINGATE_DIR = join(homedir(), '.chaingate');
export const PROXY_PID_FILENAME = 'proxy.pid';
export const PROXY_LOG_FILENAME = 'proxy.log';
export const WITNESS_DB_FILENAME = 'witness.db';
export const CONFIG_FILENAME = 'config.json';

// ── Proxy ──────────────────────────────────────────────────────────
export const DEFAULT_PORT = 6173;
export const DEFAULT_HOST = '127.0.0.1';
export const DEFAULT_UPSTREAM = 'https://registry.npmjs.org';

// ── .npmrc markers (idempotent block insertion) ────────────────────
export const NPMRC_MARKER_START = '# >>> chaingate';
export const NPMRC_MARKER_END = '# <<< chaingate';

// ── Exit codes for `chaingate check` ────────────────────────────────────
export const EXIT = {
  OK: 0,
  ERROR: 1,
  WARN: 2,
  BLOCK: 3,
  TOOL_ERROR: 4,
};
