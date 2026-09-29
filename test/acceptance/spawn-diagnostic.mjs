#!/usr/bin/env node
// Windows diagnostic for "Cannot find module" when starting node on a file under the temp
// directory (seen with the 8.3 short path C:\Users\RUNNER~1\...). Starts a trivial script from
// several directory forms and reports which ones work. Information only.
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

const bases = {
  tmpdir: os.tmpdir(),
  'tmpdir (realpath.native, long form)': (() => { try { return fs.realpathSync.native(os.tmpdir()); } catch { return null; } })(),
  RUNNER_TEMP: process.env.RUNNER_TEMP || null,
};
const names = ['cg diag', 'cg diag zoë', 'cgdiag'];
const rows = [];
for (const [label, base] of Object.entries(bases)) {
  if (!base) continue;
  for (const n of names) {
    const d = fs.mkdtempSync(path.join(base, `${n} `));
    const f = path.join(d, 'node_modules', '@x', 'y', 'server.js');
    fs.mkdirSync(path.dirname(f), { recursive: true });
    fs.writeFileSync(f, "console.log('ran ' + process.argv[1]);\n");
    const r = spawnSync(process.execPath, [f], { encoding: 'utf8', timeout: 30_000 });
    rows.push({ base: label, dir: n, file: f, exists: fs.existsSync(f), exit: r.status,
      out: `${r.stdout}${r.stderr}`.trim().split('\n')[0].slice(0, 160) });
    fs.rmSync(d, { recursive: true, force: true });
  }
}
for (const r of rows) console.log(`${r.exit === 0 ? 'OK  ' : 'FAIL'} ${r.base} / "${r.dir}" exists=${r.exists} exit=${r.exit} :: ${r.out}`);
console.log(JSON.stringify({ tmpdir: bases.tmpdir, realpath_native: bases['tmpdir (realpath.native, long form)'] }));
