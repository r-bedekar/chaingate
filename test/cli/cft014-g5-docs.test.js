// 0.1.4 group 5 — release docs (G5-1): the README describes what 0.1.4 does and promises nothing it does not. Expected
// results: ~/docs/plans/CFT/0.1.4-IMPL-DECISION-TABLES-G4-CLOSEOUT-20261012.md §4 (D-D1, D-D2), written before the edits.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { fileURLToPath } from 'node:url';

const read = (f) => fs.readFileSync(fileURLToPath(new URL(`../../${f}`, import.meta.url)), 'utf8');

test('G5-1 (D-D1, D-D2) the README and SECURITY.md describe 0.1.4: commands, record, policy, check scope; no forbidden promise', () => {
  const readme = read('README.md');
  for (const c of ['init', 'status', 'check', 'why', 'history', 'allow', 'overrides', 'update-seed', 'doctor', 'stop', 'report', 'accept', 'pin', 'unpin']) {
    assert.ok(readme.includes(`\`${c}\``), c);
  }
  assert.match(readme, /Fourteen commands/);
  assert.match(readme, /chaingate\.check\/5/);   // the record this runtime writes (0.1.4: /3; since 0.1.6: /5)
  // 0.1.5: the rules are described in plain words, without their internal labels (operator 2026-10-25)
  assert.match(readme.replace(/\s+/g, ' '), /`chaingate check` \(the CI command\) evaluates the seed\. The rules on introduced install scripts, added dependencies and differing install scripts are reported by the proxy/);
  for (const k of ['an install script is introduced', 'an added dependency runs install scripts', 'install scripts differ', 'chaingate report', 'chaingate accept', 'chaingate pin', 'chaingate unpin', 'no-store']) {
    assert.ok(readme.includes(k), k);
  }
  for (const re of [/you will be told/i, /will be blocked/i, /will be held/i, /re-checked later/i, /\b0 warnings\b/i]) assert.doesNotMatch(readme, re);
  const security = read('SECURITY.md');
  assert.match(security, /`chaingate accept`, `chaingate pin` and\s+`chaingate unpin` -- pass the same integrity gate/);
});

test('G5-2 (D-D3) `chaingate why <pkg>@<ver>` with no mode shows the recorded decision (UNBOUND, exit 4) and points to the report', async () => {
  const os = await import('node:os');
  const path = await import('node:path');
  const { spawnSync } = await import('node:child_process');
  const { openWitnessDB } = await import('../../witness/db.js');
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'cft014-g5-2-'));
  try {
    const db = openWitnessDB(path.join(home, 'witness.db')).applySchema();
    db.recordBaseline('x', '2.0.0', { published_at: '2026-06-01T00:00:00.000Z' });
    db.insertGateDecision('x', '2.0.0', 'WARN', [{ gate: 'install-introduced', result: 'WARN',
      detail: 'postinstall (node s.js) present; no earlier version (settled 24 h: 3 versions) had an install hook' },
    { gate: 'publisher-identity', result: 'NOTE', detail: 'publisher changed' }]);
    db.close();
    const cli = fileURLToPath(new URL('../../cli/index.js', import.meta.url));
    const r = spawnSync(process.execPath, [cli, 'why', 'x@2.0.0'], { env: { ...process.env, CHAINGATE_HOME: home, NO_COLOR: '1' }, encoding: 'utf8' });
    assert.equal(r.status, 4, r.stdout + r.stderr);
    assert.match(r.stdout, /UNBOUND/);
    assert.match(r.stdout, /install-introduced/);
    assert.match(r.stdout, /publisher-identity/, 'contributing rows are listed');
    assert.match(r.stdout, /chaingate report/);
    assert.doesNotMatch(r.stdout + r.stderr, /choose exactly one/);
  } finally { fs.rmSync(home, { recursive: true, force: true }); }
});

test('G5-3 (dated note 3) the README states the rules exactly as built', () => {
  const readme = read('README.md').replace(/\s+/g, ' ');               // the README wraps lines; compare its words
  for (const s of ['A package\'s first version is not judged', 'Git, URL and file dependencies are not judged', 'more than 10',
    'npm caches', 'Other refusals', 'no command displays it in 0.1.4 or 0.1.5', 'chaingate why <pkg>@<ver>']) assert.ok(readme.includes(s), s);
  assert.match(read('examples/ci/README.md'), /chaingate\.check\/3/);
});
