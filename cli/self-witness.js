// Self-witness check: compares two RECORDED integrity values for ChainGate's own package.
//
// What it compares:
//   - the tarball integrity (npm SRI string, e.g. `sha512-<base64>`) that npm recorded at install
//     time in `node_modules/.package-lock.json`, and
//   - the integrity the witness store holds for the same version. That baseline comes from a
//     legacy witness seed, or from the proxy recording the registry's metadata when it saw the
//     package. Neither source is authenticated for v3-only setups.
//
// What it does NOT do:
//   - It does not hash the installed files. Changes made to the installed files after install are
//     not detected (that would need the tarball rebuilt from the installed files).
//   - It cannot run where npm records no install integrity: normal `npm install -g` installs (npm
//     writes no `.package-lock.json` for global installs), `npm link`, and other package managers
//     (pnpm, yarn berry). Doctor reports these as skipped.
//   - It needs a witness baseline for the installed version; without one it has nothing to compare.
//
// Pre-publish state: until chaingate is published to npm and a seed run
// picks it up, witness.getBaseline(OWN_PACKAGE_NAME, v) returns null → status
// 'unverifiable' with reason 'not_in_witness'. The integrity gate treats
// this as a soft-pass when the witness has no chaingate entries at all
// (bootstrapping), and as a hard-fail once at least one is present.

import { readFileSync, existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const WALK_LIMIT = 10;

// OUR OWN npm package name, read from our own package.json — never a literal. The package is
// published as `@cgsec/chaingate`; the unscoped `chaingate` on npm is an UNRELATED project. A
// hard-coded 'chaingate' here would look up that project's versions in the witness store and
// compare our install against them.
export const OWN_PACKAGE_NAME = JSON.parse(
  readFileSync(join(dirname(fileURLToPath(import.meta.url)), '..', 'package.json'), 'utf8')).name;

export function findInstallRoot(startFileUrl, name = OWN_PACKAGE_NAME) {
  let dir = dirname(fileURLToPath(startFileUrl));
  for (let i = 0; i < WALK_LIMIT; i += 1) {
    const pkgPath = join(dir, 'package.json');
    if (existsSync(pkgPath)) {
      try {
        const pkg = JSON.parse(readFileSync(pkgPath, 'utf8'));
        if (pkg && pkg.name === name && typeof pkg.version === 'string') {
          return { root: dir, version: pkg.version };
        }
      } catch {
        // unreadable or malformed — keep walking
      }
    }
    const parent = dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }
  return null;
}

export function readLockfileIntegrity(installRoot, name = OWN_PACKAGE_NAME) {
  // npm writes node_modules/.package-lock.json; the install root is node_modules/<name>, which is
  // ONE level down for `chaingate` and TWO for `@cgsec/chaingate`: climb once per name segment.
  const lockPath = join(installRoot, ...name.split('/').map(() => '..'), '.package-lock.json');
  if (!existsSync(lockPath)) return null;
  let parsed;
  try {
    parsed = JSON.parse(readFileSync(lockPath, 'utf8'));
  } catch {
    return null;
  }
  const entry = parsed?.packages?.[`node_modules/${name}`];
  const integrity = entry?.integrity;
  return typeof integrity === 'string' && integrity.length > 0 ? integrity : null;
}

export function hasAnyChaingateInWitness(witnessDb, name = OWN_PACKAGE_NAME) {
  try {
    const history = witnessDb.getHistory(name);
    return Array.isArray(history) && history.length > 0;
  } catch {
    return false;
  }
}

export function checkSelfWitness(witnessDb, { startFileUrl = import.meta.url, name = OWN_PACKAGE_NAME } = {}) {
  const install = findInstallRoot(startFileUrl, name);
  if (!install) {
    return {
      status: 'unverifiable',
      reason: 'install_root_not_found',
      detail: `could not locate the ${name} install root (not running from an npm install?)`,
    };
  }

  const installedIntegrity = readLockfileIntegrity(install.root, name);
  if (!installedIntegrity) {
    return {
      status: 'unverifiable',
      reason: 'lockfile_missing',
      detail: `npm recorded no install integrity for ${install.root} (normal for global installs, which have no .package-lock.json; also npm link and other package managers), so there is nothing to compare`,
      version: install.version,
    };
  }

  let baseline;
  try {
    baseline = witnessDb.getBaseline(name, install.version);
  } catch (err) {
    return {
      status: 'unverifiable',
      reason: 'witness_read_failed',
      detail: err.message,
      version: install.version,
      installedIntegrity,
    };
  }

  if (!baseline || !baseline.integrity_hash) {
    return {
      status: 'unverifiable',
      reason: 'not_in_witness',
      detail: `${name}@${install.version} has no witness baseline yet, so there is nothing to compare`,
      version: install.version,
      installedIntegrity,
    };
  }

  if (baseline.integrity_hash !== installedIntegrity) {
    return {
      status: 'tamper',
      reason: 'integrity_mismatch',
      detail: `npm's recorded integrity for ${name} differs from the witness baseline: the package npm installed is not the one the witness recorded (registry tampering, or a wrong baseline)`,
      version: install.version,
      installedIntegrity,
      witnessIntegrity: baseline.integrity_hash,
    };
  }

  return {
    status: 'verified',
    reason: 'integrity_match',
    detail: `npm's recorded integrity for ${name}@${install.version} matches the witness baseline (installed files are not re-hashed)`,
    version: install.version,
    integrity: baseline.integrity_hash,
  };
}
