import { join } from 'node:path';
import {
  DEFAULT_CHAINGATE_DIR,
  PROXY_PID_FILENAME,
  PROXY_LOG_FILENAME,
  WITNESS_DB_FILENAME,
  WITNESS_DB_SHA256_FILENAME,
  WITNESS_DB_SIG_FILENAME,
  CONFIG_FILENAME,
  SEED_V3_FILENAME,
  SEED_V3_SHA256_FILENAME,
  SEED_V3_SIG_FILENAME,
} from './constants.js';

/**
 * Resolve all ChainGate paths relative to a base directory.
 * @param {'user'|'project'} [scope='user']
 * @param {string} [projectDir=process.cwd()]
 */
export function resolvePaths(scope = 'user', projectDir = process.cwd(), env = process.env) {
  // CHAINGATE_HOME names the base directory for BOTH the CLI and the proxy. Without it here the two
  // could resolve different directories from the same invocation — `init` writing configuration to
  // one and the process it starts reading another — which is exactly the divergence that made
  // project-scope configuration invisible to the proxy.
  const base = env.CHAINGATE_HOME
    || (scope === 'project' ? join(projectDir, '.chaingate') : DEFAULT_CHAINGATE_DIR);

  return {
    base,
    witnessDb: join(base, WITNESS_DB_FILENAME),
    witnessDbSha256: join(base, WITNESS_DB_SHA256_FILENAME),
    witnessDbSig: join(base, WITNESS_DB_SIG_FILENAME),
    pidFile: join(base, PROXY_PID_FILENAME),
    logFile: join(base, PROXY_LOG_FILENAME),
    configFile: join(base, CONFIG_FILENAME),
    // immutable detection evidence, deliberately not witness.db
    seedV3: join(base, SEED_V3_FILENAME),
    seedV3Sha256: join(base, SEED_V3_SHA256_FILENAME),
    seedV3Sig: join(base, SEED_V3_SIG_FILENAME),
  };
}
