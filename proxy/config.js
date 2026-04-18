import { homedir } from 'node:os';
import { join } from 'node:path';

const DEFAULTS = {
  port: 6173,
  host: '127.0.0.1',
  upstream: 'https://registry.npmjs.org',
  headersTimeoutMs: 10_000,
  bodyTimeoutMs: 30_000,
  witnessDbPath: join(homedir(), '.chaingate', 'witness.db'),
  releaseAgeHours: 72,
};

function toInt(name, value, fallback) {
  if (value == null || value === '') return fallback;
  const n = Number(value);
  if (!Number.isFinite(n) || n <= 0) {
    throw new Error(`${name} must be a positive integer, got ${value}`);
  }
  return n;
}

export function loadConfig(env = process.env, overrides = {}) {
  const base = {
    port: toInt('CHAINGATE_PORT', env.CHAINGATE_PORT, DEFAULTS.port),
    host: env.CHAINGATE_HOST ?? DEFAULTS.host,
    upstream: (env.CHAINGATE_UPSTREAM ?? DEFAULTS.upstream).replace(/\/+$/, ''),
    headersTimeoutMs: toInt(
      'CHAINGATE_UPSTREAM_HEADERS_TIMEOUT_MS',
      env.CHAINGATE_UPSTREAM_HEADERS_TIMEOUT_MS ?? env.CHAINGATE_UPSTREAM_TIMEOUT_MS,
      DEFAULTS.headersTimeoutMs,
    ),
    bodyTimeoutMs: toInt(
      'CHAINGATE_UPSTREAM_BODY_TIMEOUT_MS',
      env.CHAINGATE_UPSTREAM_BODY_TIMEOUT_MS,
      DEFAULTS.bodyTimeoutMs,
    ),
    witnessDbPath: env.CHAINGATE_WITNESS_DB ?? DEFAULTS.witnessDbPath,
    releaseAgeHours: toInt(
      'CHAINGATE_RELEASE_AGE_HOURS',
      env.CHAINGATE_RELEASE_AGE_HOURS,
      DEFAULTS.releaseAgeHours,
    ),
  };
  return { ...base, ...overrides };
}
