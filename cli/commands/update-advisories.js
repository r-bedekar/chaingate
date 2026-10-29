import { existsSync } from 'node:fs';
import { fmt } from '../format.js';
import { resolvePaths } from '../paths.js';
import { openWitnessDB } from '../../witness/db.js';
import { readConfigStrict, validateConfig } from '../../config-store.js';
import { refreshPins, urlSource, dirSource } from '../pins-feed.js';
import { EXIT } from '../constants.js';

function parseArgs(args) {
  const opts = { scope: 'user', json: false, file: null, accept: null, bad: null };
  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--scope' && args[i + 1]) opts.scope = args[++i];
    else if (args[i] === '--json') opts.json = true;
    else if (args[i] === '--file' && args[i + 1]) opts.file = args[++i];
    else if (args[i] === '--accept-cut' && args[i + 1]) opts.accept = args[++i];
    else opts.bad = args[i];
  }
  return opts;
}

/**
 * Since 0.1.6: fetch the ChainGate advisory feed (the signed pins feed of known malicious versions) now (the proxy also does this at start and hourly), or read it from a local
 * directory with --file. A cut held for its age or its size is taken only with --accept-cut and that cut's digest.
 * Exit 0 when the kept cut is current, 2 when a cut is held, 1 when the feed was refused or could not be read.
 * `deps` is for tests: { seedKey, get }.
 */
export default async function updateAdvisories(args, deps = {}) {
  const opts = parseArgs(args);
  if (opts.bad) { console.error(fmt.fail(`update-advisories: unknown argument ${opts.bad}`)); return EXIT.ERROR; }
  if (opts.accept !== null && !/^[0-9a-f]{64}$/.test(opts.accept)) {
    console.error(fmt.fail('--accept-cut takes the 64-character sha256 of the held cut (shown by `chaingate status`)'));
    return EXIT.ERROR;
  }
  const paths = resolvePaths(opts.scope);
  if (!existsSync(paths.witnessDb)) {
    console.error(fmt.fail('No witness database found. Run `chaingate init` first.'));
    return EXIT.ERROR;
  }
  let get = deps.get ?? null;
  if (!get && opts.file) get = dirSource(opts.file);
  if (!get) {
    let feed;
    try { feed = validateConfig(readConfigStrict(paths.configFile) || {}, paths.configFile).pinsFeed; } catch (err) {
      console.error(fmt.fail(err.message)); return EXIT.ERROR;
    }
    if (!feed.enabled) {
      console.error(fmt.fail('The advisory feed is off ("advisory_feed": false in the configuration): remove it, or pass --file <dir>.'));
      return EXIT.ERROR;
    }
    get = urlSource(feed.url);
  }

  const db = openWitnessDB(paths.witnessDb);
  let r;
  try {
    db.applySchema();
    r = await refreshPins({ get, db, accept: opts.accept, ...(deps.seedKey ? { seedKey: deps.seedKey } : {}) });
  } finally { db.close(); }

  if (opts.json) console.log(JSON.stringify(r, null, 2));
  else if (r.outcome === 'accepted') console.log(fmt.ok(`Advisory feed cut ${r.cut_at} accepted: ${r.rows} versions${r.walked ? ` (${r.walked} cuts between checked)` : ''}`));
  else if (r.outcome === 'same') console.log(fmt.ok(`Advisory feed is current: cut ${r.cut_at}, ${r.rows} versions`));
  else if (r.outcome === 'held') {
    console.log(fmt.warn(`Advisory feed cut ${r.cut_at} HELD: ${r.why}`));
    console.log(fmt.dim(`  Take it with: chaingate update-advisories --accept-cut ${r.digest}`));
  } else {
    console.error(fmt.fail(`Advisory feed ${r.outcome}: ${r.why}`));
    console.error(fmt.dim(r.cut_at ? `  The kept cut ${r.cut_at} keeps serving.` : '  No cut is kept yet.'));
  }
  return r.outcome === 'held' ? EXIT.WARN : ['accepted', 'same'].includes(r.outcome) ? EXIT.OK : EXIT.ERROR;
}
