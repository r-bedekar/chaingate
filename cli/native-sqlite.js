// The SQLite module (better-sqlite3) has a native part. better-sqlite3 ships it ready-built inside the npm package
// for Linux (glibc and musl), macOS and Windows on x64 and arm64, and runs no install script, so installing ChainGate
// needs no script approval and works with `ignore-scripts=true`. On any other system it looks for a local build in
// build/Release, and the first database open fails with "Cannot find module". This module recognises that failure
// and a ready-built part that does not load, and says how to fix each. It never suggests enabling install scripts.
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);

const MISSING = /Cannot find module '[^'\n]*better_sqlite3\.node'/i;

/** 'missing' (no ready-built part for this system and no local build), 'other', or null. */
export function classifyNativeSqliteError(err) {
  const text = `${err?.code ?? ''} ${err?.message ?? ''}`;
  if (MISSING.test(text)) return 'missing';
  if (/ERR_DLOPEN_FAILED|better_sqlite3/i.test(text)) return 'other';
  return null;
}

/** Load better-sqlite3 and open an in-memory database: the first point the native part is needed. */
export function probeNativeSqlite() {
  let version = null;
  try {
    version = require('better-sqlite3/package.json').version;
    const Database = require('better-sqlite3');
    const db = new Database(':memory:');
    db.prepare('SELECT 1').get();
    db.close();
    return { ok: true, version };
  } catch (err) {
    return { ok: false, version, kind: classifyNativeSqliteError(err) ?? 'other', message: err.message };
  }
}

/** This system as better-sqlite3 names its ready-built parts, for example linux-x64. */
function currentSystem() {
  return `${process.platform}-${process.arch}`;
}

/** Plain-text guidance, one line per array entry. */
export function nativeSqliteHelp(kind, version, system = currentSystem()) {
  const mod = `better-sqlite3${version ? ` ${version}` : ''}`;
  const lines = [];
  if (kind === 'missing') {
    lines.push(`ChainGate's SQLite module (${mod}) has no ready-built native part for this system (${system}).`,
      'Ready-built parts ship inside the npm package for Linux, macOS and Windows on x64 and arm64.',
      'On another system the part must be built from source, which needs Python and a C++ compiler:',
      '  Global install:  cd "$(npm root -g)/@cgsec/chaingate/node_modules/better-sqlite3" && npm run build-release',
      '  Project install: cd node_modules/better-sqlite3 && npm run build-release   (in the project directory)',
      'Such systems are not tested or supported.');
  } else {
    lines.push(`ChainGate's SQLite module (${mod}) is installed, but its native part did not load on this system (${system}).`,
      'Reinstall ChainGate so npm restores the package files:',
      '  Global install:  npm install -g @cgsec/chaingate',
      '  Project install: npm install @cgsec/chaingate   (in the project directory)');
  }
  lines.push('Then run `chaingate doctor` to confirm.');
  return lines;
}
