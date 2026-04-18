import { join } from 'node:path';
import {
  DEFAULT_CHAINGATE_DIR,
  PROXY_PID_FILENAME,
  PROXY_LOG_FILENAME,
  WITNESS_DB_FILENAME,
  WITNESS_DB_SHA256_FILENAME,
  WITNESS_DB_SIG_FILENAME,
  CONFIG_FILENAME,
} from './constants.js';

/**
 * Resolve all ChainGate paths relative to a base directory.
 * @param {'user'|'project'} [scope='user']
 * @param {string} [projectDir=process.cwd()]
 */
export function resolvePaths(scope = 'user', projectDir = process.cwd()) {
  const base =
    scope === 'project' ? join(projectDir, '.chaingate') : DEFAULT_CHAINGATE_DIR;

  return {
    base,
    witnessDb: join(base, WITNESS_DB_FILENAME),
    witnessDbSha256: join(base, WITNESS_DB_SHA256_FILENAME),
    witnessDbSig: join(base, WITNESS_DB_SIG_FILENAME),
    pidFile: join(base, PROXY_PID_FILENAME),
    logFile: join(base, PROXY_LOG_FILENAME),
    configFile: join(base, CONFIG_FILENAME),
  };
}
