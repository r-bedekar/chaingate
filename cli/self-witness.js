// Self-witness check — ChainGate verifies its own installed integrity
// against its own witness store.
//
// The witness records every published `chaingate` version's `dist.integrity`
// (npm SRI string, e.g. `sha512-<base64>`) from the registry packument. The
// seed that delivers the witness is signed with an Ed25519 key independent of
// npm. The installed package's integrity — npm's own hash from install time —
// is recorded in `node_modules/.package-lock.json`. Doctor compares the two.
//
// Trust boundaries (all three must be compromised for a silent attack):
//   1. npm publish pipeline (→ registry integrity → installed lockfile)
//   2. VPS collector + Ed25519 seed signing key (→ witness integrity)
//   3. GitHub Release tarball delivery (seed bundle)
//
// Scope this check does NOT cover:
//   - Post-install file tampering of node_modules/chaingate/** (requires
//     reproducible tarball reconstruction; out of scope for V1).
//   - Package managers that don't write .package-lock.json next to the
//     install root (pnpm, yarn berry). These report 'unverifiable'.
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
      detail: `could not locate the ${name} install root (not running from npm install?)`,
    };
  }

  const installedIntegrity = readLockfileIntegrity(install.root, name);
  if (!installedIntegrity) {
    return {
      status: 'unverifiable',
      reason: 'lockfile_missing',
      detail: `no .package-lock.json integrity next to ${install.root} (dev install, npm link, or non-npm package manager)`,
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
      detail: `${name}@${install.version} not yet in witness store (expected for pre-publish installs; run \`chaingate update-seed\` after a release lands)`,
      version: install.version,
      installedIntegrity,
    };
  }

  if (baseline.integrity_hash !== installedIntegrity) {
    return {
      status: 'tamper',
      reason: 'integrity_mismatch',
      detail: `installed ${name} integrity differs from witness baseline — trust path broken (registry tamper or seed compromise)`,
      version: install.version,
      installedIntegrity,
      witnessIntegrity: baseline.integrity_hash,
    };
  }

  return {
    status: 'verified',
    reason: 'integrity_match',
    detail: `${name}@${install.version} integrity matches seed-recorded baseline`,
    version: install.version,
    integrity: baseline.integrity_hash,
  };
}
