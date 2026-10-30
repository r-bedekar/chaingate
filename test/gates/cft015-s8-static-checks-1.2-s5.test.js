// 0.1.5 tarball static checks: static-checks-1.2, the proxy mirror of the ops recon tool's 1.2 (chaingate-ops 7251caa, suite and
// manifest 690f149, tools/recon/v6.6/static-checks.mjs). Operator ruling 2026-10-15, path (a): the oversized hook target is its own
// gate, static:S5-oversized-hook-target; 1.1 is never shipped. Adding S5 means a sixth gate in CHECKS, CONTRIBUTING first in
// gates/row-class.js, a notice line only once the operator words it, and the role pins; the identity stays cft-policy-1.2 (a new gate
// name is a role-table change, contract P5). The S0/S2/S3 markers and the nothing-read wording are as the bump test (cft015-s7).
//   (A) identity: static-checks-1.2; six gates, S5 last with recon's entry;
//   (S5) one fact: a hook target's size from the tar header, over the 1 MiB kept-file cap; S1 is the loader alone (1.0 behaviour);
//   (W) the walker states the header size of every target it does not keep for a cap; end to end through the real walker;
//   (R) roles: S5 contributing, never named, no notice label; every five-row shape is six rows.
// Written failing-first against the held bump tree (28e473f). Fixtures are TEXT; nothing here is a payload.
import test from 'node:test';
import assert from 'node:assert/strict';
import zlib from 'node:zlib';
import { createTarWalker } from '../../proxy/tar-walk.js';

const SC = () => import('../../proxy/static-checks.js');
const REASON = 'no eligible file in the tarball';
const S5G = 'static:S5-oversized-hook-target';

const file = (path, src, extra = {}) => ({ path, buf: Buffer.isBuffer(src) ? src : Buffer.from(src), name: `package/${path}`, platformsNotChecked: [], ...extra });
const walkOf = (files, notKept = []) => ({ ok: true, packageJson: null, views: [], approx: [], files, notKept });
const row = (rows, id) => rows.find((r) => r.gate.startsWith(`static:${id}-`));
const HOOKED = { name: 'p', version: '1.0.0', main: 'index.js', scripts: { postinstall: 'node install.js' } };
const PLAIN = { name: 'p', version: '1.0.0', main: 'index.js' };
const MAIN = file('index.js', 'module.exports = 1;\n');
const OVER = { path: 'install.js', reason: 'over the kept-file cap (1048576 bytes)', size: 2000000 };

test('A1 identity: static-checks-1.2 (now 1.3, declared: wording-only, cft015-s9); S5 sixth with recon 1.2\'s gate, roles and notice (S6, S7 follow: R2, R3, cft015-s6-s7)', async () => {
  const S = await SC();
  assert.equal(S.STATIC_CHECKS_VERSION, 'static-checks-1.9');   // declared (1.7 bound-module sinks, 1.8 S8 and S9, cft015-static-checks-1.7, -1.8): recon's static-checks-1.5 mirrored (R5, R9; cft015-static-checks-parity), then 1.6 facts only (R11; cft015-static-checks-1.6)
  assert.deepEqual(S.CHECKS.map((c) => c.id), ['S0', 'S1', 'S2', 'S3', 'S4', 'S5', 'S6', 'S7', 'S8', 'S9']);   // S8, S9: 1.8 (declared)
  assert.deepEqual(S.CHECKS[5], { id: 'S5', gate: S5G, cls: 'oversized-hook-target', roles: ['hook'], notice: 'an install script runs a file too large to read' });   // cls: recon's class name, carried by 1.4 (declared)
  assert.deepEqual(S.STATIC_GATES, S.CHECKS.map((c) => c.gate));
});

test('S5-1 a hook target over the kept-file cap is an S5 WARN (size from the header, body not read); S1 states it not checked and never fires on size', async () => {
  const S = await SC();
  const rows = S.staticRows({ manifest: HOOKED, packageJson: HOOKED, walk: walkOf([MAIN], [OVER]) });
  assert.equal(rows.length, 10);   // S8, S9: 1.8 (declared)
  const s5 = row(rows, 'S5'); assert.equal(s5.result, 'WARN');
  assert.equal(s5.detail, 'hook target install.js (2000000 B) is over the 1 MiB keep cap, body not read');
  const s1 = row(rows, 'S1'); assert.equal(s1.result, 'SKIP'); assert.equal(s1.detail, 'not checked: install.js over the kept-file cap (1048576 bytes)');
  assert.equal(row(rows, 'S3').result, 'SKIP', 'S3 still states the unread hook target');
});

test('S5-2 under the cap or no hook: a kept hook target and a target not kept beyond 6 files (size known) are ALLOW; no hook is ALLOW; a main over the cap is not S5', async () => {
  const S = await SC();
  const kept = row(S.staticRows({ manifest: HOOKED, packageJson: HOOKED, walk: walkOf([MAIN, file('install.js', 'x')]) }), 'S5');
  assert.equal(kept.result, 'ALLOW'); assert.equal(kept.detail, 'hook targets are within the 1 MiB keep cap (1 file sized)');
  const beyond = row(S.staticRows({ manifest: HOOKED, packageJson: HOOKED, walk: walkOf([MAIN], [{ path: 'install.js', reason: 'beyond 6 kept files', size: 10 }]) }), 'S5');
  assert.equal(beyond.result, 'ALLOW', beyond.detail);
  const none = row(S.staticRows({ manifest: PLAIN, packageJson: PLAIN, walk: walkOf([MAIN]) }), 'S5');
  assert.equal(none.result, 'ALLOW'); assert.equal(none.detail, 'no hook target');
  const main = row(S.staticRows({ manifest: PLAIN, packageJson: PLAIN, walk: walkOf([], [{ path: 'index.js', reason: 'over the kept-file cap (1048576 bytes)', size: 3000000 }]) }), 'S5');
  assert.equal(main.result, 'ALLOW');
  const bin = row(S.staticRows({ manifest: HOOKED, packageJson: HOOKED, walk: walkOf([MAIN, file('install.js', Buffer.concat([Buffer.from('\x7fELF'), Buffer.alloc(64)]))]) }), 'S5');
  assert.equal(bin.result, 'ALLOW', 'a binary hook target is still sized');
});

test('S5-3 not checked: a hook target with no size (absent) is the nothing-read SKIP; one named only by the tarball package.json is stated', async () => {
  const S = await SC();
  const absent = row(S.staticRows({ manifest: HOOKED, packageJson: HOOKED, walk: walkOf([MAIN], [{ path: 'install.js', reason: 'not in the archive' }]) }), 'S5');
  assert.equal(absent.result, 'SKIP'); assert.equal(absent.detail, `not checked: ${REASON} (install.js not in the archive)`);
  const tarOnly = row(S.staticRows({ manifest: PLAIN, packageJson: HOOKED, walk: walkOf([MAIN]) }), 'S5');
  assert.equal(tarOnly.result, 'SKIP'); assert.match(tarOnly.detail, /^not checked: install\.js named by the tarball package\.json only/);
});

// ---- (W) the real walker: the producer of notKept ----
function hdr(name, size) {
  const h = Buffer.alloc(512, 0);
  Buffer.from(name, 'utf8').copy(h, 0, 0, 100);
  h.write('0000644\0', 100); h.write('0000000\0', 108); h.write('0000000\0', 116);
  h.write(`${size.toString(8).padStart(11, '0')}\0`, 124, 'latin1');
  h.write('00000000000\0', 136); h.write('        ', 148); h.write('0', 156, 'latin1');
  h.write('ustar\0', 257, 'latin1'); h.write('00', 263, 'latin1');
  let sum = 0; for (let i = 0; i < 512; i += 1) sum += h[i];
  h.write(`${sum.toString(8).padStart(6, '0')}\0 `, 148, 'latin1');
  return h;
}
const entry = (name, content) => { const b = Buffer.isBuffer(content) ? content : Buffer.from(content); return [hdr(name, b.length), b, Buffer.alloc((512 - (b.length % 512)) % 512, 0)]; };
async function walkTar(parts, keep, opts = {}) {
  const w = createTarWalker({ keep, ...opts });
  const gz = zlib.gzipSync(Buffer.concat([...parts.flat(), Buffer.alloc(1024, 0)]));
  for (let i = 0; i < gz.length; i += 4096) w.write(gz.subarray(i, i + 4096));
  return w.end();
}

test('W1 walker: a target not kept for the size cap or the file count carries its header size; an absent target carries none', async () => {
  const big = Buffer.alloc(1536 * 1024, 0x61);
  const r = await walkTar([entry('package/package.json', JSON.stringify(HOOKED)), entry('package/install.js', big), entry('package/index.js', 'x')], ['install.js', 'index.js', 'lib/absent.js']);
  assert.equal(r.ok, true, r.reason);
  assert.deepEqual(r.notKept, [{ path: 'install.js', reason: 'over the kept-file cap (1048576 bytes)', size: 1536 * 1024 }, { path: 'lib/absent.js', reason: 'not in the archive' }]);
  const r2 = await walkTar([entry('package/package.json', JSON.stringify(HOOKED)), entry('package/a.js', 'aa'), entry('package/b.js', 'bbb')], ['a.js', 'b.js'], { maxKeep: 1 });
  assert.deepEqual(r2.notKept, [{ path: 'b.js', reason: 'beyond 1 kept files', size: 3 }]);
});

test('W2 end to end: the real walk of a package whose postinstall target is 1.5 MiB gives S5 WARN with the header size; S1 not checked', async () => {
  const S = await SC();
  const big = Buffer.from(`// ${'x'.repeat(1536 * 1024)}\n`);
  const walk = await walkTar([entry('package/package.json', JSON.stringify(HOOKED)), entry('package/install.js', big), entry('package/index.js', 'module.exports = 1;\n')], S.keepListFor(HOOKED).paths);
  const rows = S.staticRows({ manifest: HOOKED, packageJson: HOOKED, walk });
  assert.equal(row(rows, 'S5').result, 'WARN', row(rows, 'S5').detail);
  assert.equal(row(rows, 'S5').detail, `hook target install.js (${big.length} B) is over the 1 MiB keep cap, body not read`);
  assert.equal(row(rows, 'S1').result, 'SKIP');
});

test('R1 roles (declared: S5 NAMED by the operator ruling of 2026-10-15, cft015-s9): its WARN stays WARN, a named runner gate with recon\'s notice text', async () => {
  const RC = await import('../../gates/row-class.js');
  const POL = (await import('../../seed/v3/policy.js')).default;
  const N = await import('../../proxy/notice.js');
  assert.ok(!RC.CONTRIBUTING_GATES.has(S5G));
  assert.equal(RC.withRole({ gate: S5G, result: 'WARN', detail: 'd' }).result, 'WARN');
  assert.ok(POL.NAMED_RUNNER_GATES.includes(S5G));
  assert.equal(N.labelFor(S5G), 'an install script runs a file too large to read');
});

test('R2 every row-set shape is every check (eight since R2, R3; ten since 1.8): failed walk, unarmed, no manifest; staticSettled needs all of them', async () => {
  const S = await SC();
  const failed = S.staticRows({ manifest: HOOKED, packageJson: null, walk: { ok: false, reason: 'gunzip: unexpected end of file' } });
  assert.deepEqual(failed.map((r) => r.gate), S.STATIC_GATES); assert.equal(failed.length, 10);
  assert.equal(S.unarmedRows('x').length, 10); assert.equal(S.noManifestRows('x').length, 10);
  const rows = S.staticRows({ manifest: HOOKED, packageJson: HOOKED, walk: walkOf([MAIN, file('install.js', 'x')]) });
  assert.equal(S.staticSettled({ gates_fired: rows }), true);
  assert.equal(S.staticSettled({ gates_fired: rows.slice(0, 5) }), false, 'a record written before S5 is retried once');
});
