// U-05 R2-2 legacy part, DL child: call the REAL fetchSeedBundle with only the GitHub API listing stubbed (it names
// loopback asset URLs; the asset bytes come from the parent's loopback server). Prints "RESULT <json>".
//   node u05-r22-download-child.mjs <assetBase> <base or ->       env U05_DL_OPTS = JSON options (timeouts, maxDb)
import fs from 'node:fs';
const [assetBase, base] = process.argv.slice(2);
const realFetch = globalThis.fetch;
globalThis.fetch = async (url, init) => {
  if (String(url).startsWith('https://api.github.com/')) {
    const assets = ['chaingate-seed.db', 'chaingate-seed.db.sha256', 'chaingate-seed.db.sig']
      .map((name) => ({ name, browser_download_url: `${assetBase}/${name}` }));
    return new Response(JSON.stringify([{ tag_name: 'seed-v9.9', published_at: '2026-10-01T00:00:00Z', assets }]),
      { status: 200, headers: { 'content-type': 'application/json' } });
  }
  return realFetch(url, init);
};
const say = (o) => fs.writeSync(1, `RESULT ${JSON.stringify(o)}\n`);
const { fetchSeedBundle } = await import('../../cli/seed-download.js');
const opts = JSON.parse(process.env.U05_DL_OPTS || '{}');
try {
  const b = await fetchSeedBundle({ ...(base && base !== '-' ? { base } : {}), ...opts });
  say({ ok: true, dir: b.dir, size: b.size ?? null, files: fs.readdirSync(b.dir) });
  if (process.env.U05_DL_CLEANUP === '1') { b.cleanup?.(); say({ cleaned: true, dirLeft: fs.existsSync(b.dir) }); }
} catch (e) {
  say({ ok: false, name: e.name, kind: e.kind ?? null, code: e.code ?? null, message: e.message });
}
