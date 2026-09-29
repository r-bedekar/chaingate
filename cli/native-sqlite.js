// The SQLite module (better-sqlite3) has a native part that npm installs through the package's own
// install script. npm currently runs dependency install scripts by default and warns about ones not
// covered by `allowScripts`; npm documents that a future release will block them, and an
// `ignore-scripts=true` configuration skips them today. The package then installs "successfully"
// and fails the first time a database is opened, with a stack trace about a missing bindings file. This module recognises that failure and says how to fix it,
// allowing only better-sqlite3's own script — never all dependency scripts.
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);

const MISSING = /Could not locate the bindings file|better_sqlite3\.node.*(no such file|cannot find|not found)/i;
const ABI = /NODE_MODULE_VERSION|compiled against a different Node\.js version/i;

/** 'missing' (install script skipped), 'abi' (Node changed since install), 'other', or null. */
export function classifyNativeSqliteError(err) {
  const text = `${err?.code ?? ''} ${err?.message ?? ''}`;
  if (MISSING.test(text)) return 'missing';
  if (ABI.test(text)) return 'abi';
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

/** Plain-text guidance, one line per array entry. */
export function nativeSqliteHelp(kind, version) {
  const mod = `better-sqlite3${version ? ` ${version}` : ''}`;
  const lines = [];
  if (kind === 'abi') {
    lines.push(`ChainGate's SQLite module (${mod}) was built for a different Node.js version than the one running now.`,
      'Rebuild it with the Node.js version you will use:',
      '  Global install:  cd "$(npm root -g)/@cgsec/chaingate" && npm rebuild better-sqlite3',
      '  Project install: npm rebuild better-sqlite3   (in the project directory)');
  } else {
    lines.push(`ChainGate cannot load its SQLite module (${mod}): the native part is not installed.`,
      "npm installs it with better-sqlite3's install script, which did not run during installation.",
      "Fix it by allowing that one package's script (never all dependency scripts):",
      '  Global install:',
      '    npm install -g @cgsec/chaingate --allow-scripts=better-sqlite3',
      '  Project install (npm versions with allowScripts), in the project directory:',
      '    npm approve-scripts better-sqlite3 && npm rebuild better-sqlite3',
      'If your npm configuration sets ignore-scripts=true, rebuild only that package from the install directory:',
      '  cd "$(npm root -g)/@cgsec/chaingate" && npm rebuild better-sqlite3 --ignore-scripts=false',
      "  PowerShell: Set-Location (Join-Path (npm root -g) '@cgsec/chaingate'); npm rebuild better-sqlite3 --ignore-scripts=false");
  }
  lines.push('For a project install with ignore-scripts=true, run `npm rebuild better-sqlite3 --ignore-scripts=false` in the project directory.',
    'Then run `chaingate doctor` to confirm.');
  return lines;
}
