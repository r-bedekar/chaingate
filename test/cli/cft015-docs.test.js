// 0.1.5 release docs: the README describes the rules 0.1.5 adds, as built (gates/size-jump-provenance.js, identity-break.js,
// entry-path-change.js, gates/row-class.js, config-store.js static_withhold), and its contributing list is current
// (S0 and S5 were named in 0.1.5, so "the five tarball static checks" is no longer the contributing set).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { fileURLToPath } from 'node:url';

const read = (f) => fs.readFileSync(fileURLToPath(new URL(`../../${f}`, import.meta.url)), 'utf8');
const words = (f) => read(f).replace(/\s+/g, ' ');

test('D1 the README names size-jump-provenance as a named rule, with both of its facts and the predecessor it compares', () => {
  const r = words('README.md');
  assert.match(r, /\*\*a size jump with a broken repository link\*\*/);
  assert.match(r, /at least 5 times/);
  assert.match(r, /gitHead/);
  assert.match(r, /previous version of its own tag/);
  assert.match(r, /its tarball grew fivefold and its link to the repository broke/, 'the npm notice text, as proxy/notice.js has it');
});

test('D2 the README lists identity-break and entry-path-change as contributing, and S1 to S4 (not five) as the contributing static checks', () => {
  const r = words('README.md');
  assert.match(r, /\*\*a publisher break\*\*/);
  assert.match(r, /\*\*an entry point change\*\*/);
  assert.doesNotMatch(r, /the five tarball static checks/);
  assert.match(r, /The other tarball checks are contributing notes/);
});

test('D3 the README describes the static_withhold switch: off by default, 8 MiB, a 403, the decision stays WARN', () => {
  const r = words('README.md');
  assert.match(r, /`static_withhold`/);
  assert.match(r, /off by default/);
  assert.match(r, /8 MiB/);
  assert.match(r, /403/);
  assert.match(r, /stays WARN/);
});

test('D4 README and SEEDS.md say --seed takes the compressed database', () => {
  assert.match(words('README.md'), /`--seed` also takes the compressed database, `chaingate-seed-v3\.db\.gz`/);
  assert.match(words('SEEDS.md'), /chaingate-seed-v3\.db\.gz/);
});

test('D5 the package is 0.1.6: package.json and both version fields of package-lock.json', () => {
  assert.equal(JSON.parse(read('package.json')).version, '0.1.6');
  const lock = JSON.parse(read('package-lock.json'));
  assert.equal(lock.version, '0.1.6');
  assert.equal(lock.packages[''].version, '0.1.6');
});

test('D6 the README says which commands honour CHAINGATE_PORT (doctor, report, pin) and which use the default port 6173 (init, stop, status)', () => {
  const r = words('README.md');
  assert.match(r, /`chaingate doctor`, `chaingate report` and `chaingate pin` reach the proxy at `CHAINGATE_PORT` when it is set/);
  assert.match(r, /`chaingate init`, `chaingate stop` and `chaingate status` always use port 6173/);
});

test('D7 the 0.1.6 README points at seed-v3.3-full as a .gz and says it needs 0.1.6', () => {
  const r = words('README.md');
  assert.match(r, /\[seed-v3\.3-full\]\(https:\/\/github\.com\/cgsec-labs\/chaingate\/releases\/tag\/seed-v3\.3-full\)/);
  assert.match(r, /seed-v3\.3-full needs ChainGate 0\.1\.6 or later/);
  assert.doesNotMatch(r, /releases\/tag\/seed-v3\.[12]-full/, 'the published seed the README sends users to is v3.3');
  assert.match(r, /the current one is `seed-v3\.3-full`/);
  assert.match(r, /\$ chaingate init --seed \.\/seed-v3\.3\/chaingate-seed-v3\.db\.gz/);
  assert.match(r, /\*\*Supported platforms\.\*\*/);
  assert.doesNotMatch(r, /In 0\.1\.4 it warns|evaluates the seed only in 0\.1\.4|In 0\.1\.4 `check`/, 'no current-behaviour sentence still says 0.1.4');
});

test('D8 the README, SECURITY.md and SEEDS.md carry no internal labels: rule codes, policy and contract identifiers, marker-list versions, research or process terms (operator 2026-10-25)', () => {
  const labels = [/cft-policy/, /cft-seed/, /\bN1h\b/, /\bMC\b/, /\bS[0-7]\b/, /static-checks-\d/, /qualification of/, /\boperator\b/i, /\brecon\b/i];
  for (const f of ['README.md', 'SECURITY.md', 'SEEDS.md']) for (const re of [...labels, /\bg10-/, /\bcorpus\b/i]) {
    if (f === 'SECURITY.md' && /corpus/.test(re.source)) continue;   // SECURITY.md names the seed's corpus snapshot identifier
    assert.doesNotMatch(words(f), re, `${f}: ${re}`);
  }
  for (const re of [/\bcorpus\b/i, /\bshadow\b/i]) assert.doesNotMatch(words('README.md'), re, `README.md: ${re}`);
});

test('D9 the strings the runtime prints carry no internal rule or plan codes (operator 2026-10-25)', () => {
  // code lines only (comments are prose); proxy/static-checks.js mirrors the offline scanner byte for byte, and its two notes are
  // replaced with plain ones before the facts are stored or shown (proxy/shadow-facts.js publicStaticFacts, T4/T5)
  const codes = /FU-2|— D1\b|\bD1 (?:fails|SKIPs|does)|operator ruling|recon pattern|\bU-05\b|dated note/;
  const files = [];
  const walk = (d) => { for (const e of fs.readdirSync(d, { withFileTypes: true })) { const p = `${d}/${e.name}`; if (e.isDirectory()) walk(p); else if (p.endsWith('.js')) files.push(p); } };
  const root = fileURLToPath(new URL('../../', import.meta.url));
  for (const d of ['cli', 'gates', 'proxy', 'witness', 'seed', 'patterns']) walk(`${root}${d}`);
  const hits = [];
  for (const f of files) {
    if (f.endsWith('proxy/static-checks.js')) continue;
    fs.readFileSync(f, 'utf8').split('\n').forEach((l, i) => {
      const t = l.trim();
      if (t.startsWith('//') || t.startsWith('*') || t.startsWith('/*')) return;
      if (codes.test(l.split(' // ')[0])) hits.push(`${f.slice(root.length)}:${i + 1}`);
    });
  }
  assert.deepEqual(hits, []);
});
