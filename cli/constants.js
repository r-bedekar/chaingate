import { homedir } from 'node:os';
import { join } from 'node:path';

// ── Seed download ──────────────────────────────────────────────────
// chaingate's CLI dynamically resolves the latest seed release via GitHub API,
// rather than relying on a fixed download URL. This handles the future case
// where CLI version releases (vN.M.K) and seed releases (seed-vN.M) coexist
// on the same repo: the CLI filters by SEED_TAG_PATTERN and picks the most
// recently published matching release.
export const SEED_REPO = 'r-bedekar/chaingate';
export const SEED_TAG_PATTERN = /^seed-v\d+(\.\d+)*$/;

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
// Seed signature artifacts persisted beside witness.db so `chaingate doctor`
// can re-verify the Ed25519 signature on every run, not just at init time.
export const WITNESS_DB_SHA256_FILENAME = 'witness.db.sha256';
export const WITNESS_DB_SIG_FILENAME = 'witness.db.sig';
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
  // Section 7 item 3: self-verification failure modes.
  // TAMPER = cryptographic disagreement (treat as attack signal).
  // UNVERIFIABLE = check can't complete (pre-publish, dev install, missing
  // lockfile). Doctor emits; integrity gate decides whether to accept.
  INTEGRITY_TAMPER: 5,
  INTEGRITY_UNVERIFIABLE: 6,
};
