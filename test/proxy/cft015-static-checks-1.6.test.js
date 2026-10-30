// 0.1.5 static-checks-1.6 (operator ruling R11 2026-10-24, "Shadow first"): recon v6.14's facts-only bump mirrored. Every 1.5 section is
// unchanged; the new `facts` (rule 6 encoded runs with distinct characters and decoded magic, rule 7 an S5 target's base64 share and
// magic, 8a P2/P9-type hit lines under test/ __tests__/ fixtures/ vendor/ node_modules/ counted apart, 8d a write under an agent config
// dir, 8h no I/O surface) are computed and recorded, never read by a row outcome, an indicator, a gate, a class or a notice.
// The hand-off is recon's constants file (fixtures/cft015/static-checks-1.6-constants.json, byte for byte, sha256 below): its constants are
// compared with the module's exports by regex source and flags, and its 41 vectors (computed by recon's own functions) are run here.
// The proxy's half of the input contract (R11 (b)): an ARMED walk reads every regular file's first 2 MiB on the Linux view (the last
// duplicate wins) and streams a hook target over the keep cap through the base64 counter; the facts are stored beside the version's
// entry facts and shown by `why` and `report`. Failing first: written before the code. Tarballs are synthetic; nothing is run.
import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import zlib from 'node:zlib';
import { fileURLToPath } from 'node:url';
import Database from 'better-sqlite3';
import { createProxyServer } from '../../proxy/server.js';
import { createTarWalker } from '../../proxy/tar-walk.js';
import { openWitnessDB } from '../../witness/db.js';
import { resetDependencyCache } from '../../gates/dependency-cache.js';
import { forgetManifestHooks } from '../../proxy/manifest-check.js';

const SC = () => import('../../proxy/static-checks.js');
const CLI = fileURLToPath(new URL('../../cli/index.js', import.meta.url));
const FIXTURE = fileURLToPath(new URL('../fixtures/cft015/static-checks-1.6-constants.json', import.meta.url));
const HANDOFF_SHA256 = 'c4c1e0c03ebc3d7551beb648a43de37c0fabeda202999277559da3062d5bccb0';
const RAW = fs.readFileSync(FIXTURE);
const K = JSON.parse(RAW.toString('utf8'));
const F = K.facts;
const S5G = 'static:S5-oversized-hook-target';

// 1.7 widens 'http-request' and 'net-connect' with the bound-module forms; their 1.6 regex is kept as `literal` (cft015-static-checks-1.7)
const lit = (re) => re.literal ?? re;
const rx = (re) => ({ re: lit(re).source, flags: lit(re).flags });
const pairs = (list) => list.map(([name, re]) => ({ name, regex: lit(re).source, flags: lit(re).flags }));
const want = (list) => list.map((x) => ({ name: x.name, regex: x.regex, flags: x.flags ?? '' }));
const dataOf = (v) => (typeof v.data_base64 === 'string' ? Buffer.from(v.data_base64, 'base64') : Buffer.from(v.data_utf8 ?? '', 'utf8'));

// ------------------------------------------------------------------ (A) the hand-off and the 1.5 sections
test('C1 the hand-off is recon\'s file byte for byte (sha256), plain ASCII; the version string and the facts note are recon\'s', async () => {
  const S = await SC();
  assert.equal(createHash('sha256').update(RAW).digest('hex'), HANDOFF_SHA256);
  assert.ok(RAW.every((b) => b < 0x80), 'plain ASCII');
  assert.equal(K.static_checks_version, 'static-checks-1.6');
  assert.equal(S.STATIC_CHECKS_VERSION, 'static-checks-1.9', 'updated deliberately: 1.7 changes the two bound-form sinks only, 1.8 appends S8 and S9 (cft015-static-checks-1.7, -1.8)');
  assert.equal(S.FACTS_NOTE, F.note);
});

test('C2 every 1.5 section is unchanged: the eight checks, S0 1.4, the S6 and S7 vocabularies, the limits', async () => {
  const S = await SC();
  assert.deepEqual(S.CHECKS.slice(0, 8).map(({ id, gate, cls, roles, notice }) => ({ id, gate, cls, roles, notice })),   // S0-S7; 1.8 appends S8, S9 (declared)
    K.checks.map(({ id, gate, cls, roles, notice }) => ({ id, gate, cls, roles, notice })));
  assert.deepEqual([...S.SHELLS], K.s0.shells);
  assert.deepEqual({ regex: S.SHELL_C.source, flags: S.SHELL_C.flags }, { regex: K.s0.shell_c.regex, flags: K.s0.shell_c.flags });
  assert.deepEqual(pairs(S.NET_TOOLS), want(K.s0.net_tools));
  assert.deepEqual([...S.DNS_TOOLS], K.s0.dns_tools);
  assert.deepEqual(S.SEND_MARKERS.map(([name, re]) => ({ name, regex: re instanceof RegExp ? re.source : null })), K.s0.send_markers.map(({ name, regex }) => ({ name, regex: regex ?? null })));
  assert.deepEqual(pairs(S.API_NET_SINKS), want(K.s6.api_net_sinks));
  assert.deepEqual(pairs(S.HOST_IDENTITY), want(K.s6.host_identity));
  assert.deepEqual([...S.IDENTITY_ENV], K.s6.identity_env);
  assert.deepEqual(pairs(S.EXEC_SINKS), want(K.s6.exec_sinks));
  assert.deepEqual([...S.CAPABILITY_CLASSES], K.s7.capability_classes);
  assert.deepEqual(pairs(S.DECODE_MARKERS), want(K.s7.decode_markers));
  assert.deepEqual(pairs(S.CRED_SOURCES), want(K.s7.cred_sources));
  assert.deepEqual([...S.S7_NAMED_ARMS], K.s7.named_condition.arms);
  const L = K.limits;
  assert.deepEqual([S.LIMITS.maxKeep, S.LIMITS.maxKeepBytes, S.LIMITS.maxBin, S.LIMITS.maxHookTargets, S.LIMITS.s1MaxBytes, S.LIMITS.s2MinIdents, S.LIMITS.s2MinCharCodes,
    S.LIMITS.s2HexDensity, S.LIMITS.s2MinNumericHex, S.LIMITS.s4MinAddressFamilies, S.LIMITS.headBytes],
  [L.keepFiles, L.keepBytes, L.maxBin, L.maxHookTargets, L.s1MaxBytes, L.s2MinIdents, L.s2MinCharCodes, L.s2HexDensity, L.s2MinNumericHex, L.s4MinAddressFamilies, L.headBytes]);
});

test('C3 the facts constants are recon\'s: limits, decoded magic, rule 6 runs, 8a paths and P2-type, 8d dirs and writes, 8h classes and tokens', async () => {
  const S = await SC();
  assert.deepEqual({ ...S.FACTS_LIMITS }, { ...F.limits, distinctCharsBytes: 65536 });   // 1.8.1 adds the distinct-chars bound (cft016-static-checks-1.8.1)
  assert.deepEqual(S.DECODED_MAGIC.map(([name, hex_prefix]) => ({ name, hex_prefix })), F.decoded_magic);
  assert.deepEqual(rx(S.B64_RUN), F.rule6.b64_run);
  assert.deepEqual(rx(S.HEX_ESCAPE_RUN), F.rule6.hex_escape_run);
  assert.deepEqual(rx(S.EXCLUDED_PATH), F.s8a.excluded_path);
  assert.deepEqual(rx(S.DYNAMIC_CODE), F.s8a.dynamic_code_p2);
  assert.deepEqual(rx(S.RAW_IP_URL), F.s8a.raw_ip_url_p9);
  assert.deepEqual([...S.AGENT_CONFIG_NAMES], F.s8d.agent_names);
  assert.deepEqual(rx(S.AGENT_HOME_DIR), F.s8d.home_dir);
  assert.deepEqual(rx(S.AGENT_XDG_DIR), F.s8d.xdg_dir);
  assert.deepEqual(S.WRITE_MARKERS.map(([name, re]) => ({ name, re: re.source, flags: re.flags })), F.s8d.write_markers);
  assert.deepEqual({ name: S.SHELL_REDIRECT[0], ...rx(S.SHELL_REDIRECT[1]) }, F.s8d.shell_redirect);
  assert.deepEqual(rx(S.SHELL_SCRIPT), F.s8d.shell_script);
  assert.deepEqual([...S.IO_CLASSES], F.s8h.classes);
  assert.deepEqual(S.IO_TOKENS.map(([cls, name, re]) => ({ class: cls, name, re: lit(re).source, flags: lit(re).flags })), F.s8h.tokens);
});

// ------------------------------------------------------------------ (B) recon's 41 vectors
test('V1 rule 6: encodedRuns on recon\'s 10 vectors (kind, chars, distinct characters, decoded magic)', async () => {
  const S = await SC();
  assert.equal(F.vectors.encoded_runs.length, 10);
  for (const v of F.vectors.encoded_runs) assert.deepEqual(S.encodedRuns(v.text), v.expected, v.text.slice(0, 60));
});

test('V2 rule 7: the streamed base64 share on recon\'s 4 vectors, identical at chunk sizes 1, 7 and 401', async () => {
  const S = await SC();
  assert.equal(F.vectors.base64_share.length, 4);
  for (const v of F.vectors.base64_share) {
    const body = Buffer.from(v.body_utf8, 'utf8');
    for (const n of [1, 7, 401]) {
      const c = S.makeBase64Share();
      for (let i = 0; i < body.length; i += n) c.push(body.subarray(i, i + n));
      assert.deepEqual(c.end(), v.expected, `chunk ${n}: ${v.body_utf8.slice(0, 40)}`);
    }
  }
});

test('V3 memberFacts on recon\'s 17 member vectors (8a, 8d, 8h, rule 6, binary, beyond the window)', async () => {
  const S = await SC();
  assert.equal(F.vectors.member_facts.length, 17);
  // 1.8 adds six member facts for S8 and S9 (cft015-static-checks-1.8, declared): recon's 1.6 record once they are set aside
  const NEW18 = ['native', 'node_file', 'native_source', 'gyp_sources', 'xor_text', 'gyp_build'];
  const v16 = (m) => Object.fromEntries(Object.entries(m).filter(([k]) => !NEW18.includes(k)));
  for (const v of F.vectors.member_facts) assert.deepEqual(v16(S.memberFacts({ path: v.path, size: v.size, data: dataOf(v) })), v.expected, v.path);
});

test('V4 staticFacts on recon\'s 5 package vectors (no I/O surface, a binary member, an install hook, an archive not read in full, agent writes and the 8a split)', async () => {
  const S = await SC();
  assert.equal(F.vectors.static_facts.length, 5);
  const logo = F.vectors.member_facts.find((m) => m.path === 'logo.png');
  for (const v of F.vectors.static_facts) {
    const members = v.members.map((m) => { const d = dataOf(m); return S.memberFacts({ path: m.path, size: d.length, data: d }); });
    if (v.plus_member) members.push(S.memberFacts({ path: logo.path, size: logo.size, data: dataOf(logo) }));
    const got = S.staticFacts({ members, hooks: v.hooks, keepList: { roles: v.keep_list_roles }, archiveComplete: v.archive_complete });
    // recon's 1.6 vectors; the version string moved in 1.7, and 1.8.1 names the distinct-chars basis (cft016-static-checks-1.8.1)
    const want = { ...v.expected, version: S.STATIC_CHECKS_VERSION };
    if (want.encoded_runs) want.encoded_runs = { ...want.encoded_runs, distinct_chars_basis: 'distinct chars, first 64 KiB of each run' };
    assert.deepEqual(got, want, v.name);
  }
  assert.deepEqual(S.staticFacts({}), { version: 'static-checks-1.9', note: F.note, status: 'NOT_CHECKED', reason: 'no member facts supplied' });
});

test('V5 8d agentConfigWrite on recon\'s 5 vectors (the redirect only in a hook command or a shell script)', async () => {
  const S = await SC();
  assert.equal(F.vectors.agent_config_write.length, 5);
  for (const v of F.vectors.agent_config_write) assert.deepEqual(S.agentConfigWrite(v.text, { shell: v.shell }), v.expected, `${v.text} shell=${v.shell}`);
});

// ------------------------------------------------------------------ (C) the walker's half of the input contract
function hdr(name, size) {
  const h = Buffer.alloc(512, 0); Buffer.from(name, 'utf8').copy(h, 0, 0, 100);
  h.write('0000644\0', 100); h.write('0000000\0', 108); h.write('0000000\0', 116); h.write(`${size.toString(8).padStart(11, '0')}\0`, 124, 'latin1');
  h.write('00000000000\0', 136); h.write('        ', 148); h.write('0', 156, 'latin1'); h.write('ustar\0', 257, 'latin1'); h.write('00', 263, 'latin1');
  let sum = 0; for (let i = 0; i < 512; i += 1) sum += h[i]; h.write(`${sum.toString(8).padStart(6, '0')}\0 `, 148, 'latin1'); return h;
}
const pad = (b) => Buffer.concat([b, Buffer.alloc((512 - (b.length % 512)) % 512, 0)]);
const tarOf = (entries) => zlib.gzipSync(Buffer.concat([...entries.flatMap(([p, c]) => { const b = Buffer.from(c); return [hdr(`package/${p}`, b.length), pad(b)]; }), Buffer.alloc(1024, 0)]));
const tgz = (files) => tarOf(Object.entries(files));
const walkOf = async (buf, opts) => { const w = createTarWalker(opts); for (let i = 0; i < buf.length; i += 997) w.write(buf.subarray(i, i + 997)); return w.end(); };
const plainOf = (r) => JSON.parse(JSON.stringify(r, (k, v) => (v && v.type === 'Buffer' ? `buf:${v.data.length}` : v)));
const noMs = ({ memberMs, ...r }) => r;   // eslint-disable-line no-unused-vars -- the time the 1.6 work spent (T1), the only added key
// var w="AGFzbQ..." (recon's wasm base64 run of 544 characters) lengthened to 2,544, so its share of a 1.2 MiB body reads 0.002
const WASM = F.vectors.base64_share[0].body_utf8.split('\n')[0].replace('";', `${'A'.repeat(2000)}";`);
const FILL = `\n${'- '.repeat(600 * 1024)}\n`;                             // 1.2 MiB of non-alphabet bytes: over the 1 MiB keep cap

test('W1 onMember(path, size, window): every regular file on the Linux view with its header size and its first memberWindow bytes; without it the result is unchanged key for key', async () => {
  const PJ = '{"name":"p","version":"1.0.0"}';
  const buf = tarOf([['package.json', PJ], ['README.md', 'x'.repeat(300)], ['lib/index.js', 'module.exports = 1;\n'], ['empty.txt', ''], ['lib/index.js', 'module.exports = 2;\n']]);
  const seen = [];
  const a = await walkOf(buf, { onMember: (p, n, w) => seen.push([p, n, w.toString('utf8')]), memberWindow: 100 });
  const b = await walkOf(buf, {});
  assert.deepEqual(seen, [['package.json', PJ.length, PJ], ['README.md', 300, 'x'.repeat(100)], ['lib/index.js', 20, 'module.exports = 1;\n'], ['empty.txt', 0, ''], ['lib/index.js', 20, 'module.exports = 2;\n']],
    'every member in archive order (the caller keeps the last duplicate), each cut at the window');
  assert.deepEqual(plainOf(noMs(a)), plainOf(b));
  const c = await walkOf(buf, { keep: ['lib/index.js'] }); const d = await walkOf(buf, { keep: ['lib/index.js'], onMember: () => {}, memberWindow: 100 });
  assert.deepEqual(plainOf(noMs(d)), plainOf(c), 'with a keep list too');
  const e = await walkOf(buf, { onMember: () => { throw new Error('a member tally never fails the walk'); }, memberWindow: 100 });
  assert.equal(e.ok, true);
});

test('W2 a keep target over the keep cap is streamed whole through shareOf(): its not-kept entry carries the share; a kept target does not; without shareOf nothing changes', async () => {
  const S = await SC();
  const big = `${WASM}${FILL}`;
  const buf = tgz({ 'package.json': '{"name":"p","version":"1.0.0"}', 'install.js': big, 'index.js': 'module.exports = 1;\n' });
  const r = await walkOf(buf, { keep: ['install.js', 'index.js'], shareOf: S.makeBase64Share });
  const nk = r.notKept.find((x) => x.path === 'install.js');
  const want = S.makeBase64Share(); want.push(Buffer.from(big)); const w = want.end();
  assert.deepEqual(nk.base64, w); assert.equal(w.magic, 'wasm'); assert.ok(w.share > 0 && w.share < 0.01, String(w.share));
  assert.equal(nk.size, Buffer.byteLength(big)); assert.equal(r.files[0].path, 'index.js'); assert.equal('base64' in r.files[0], false);
  const plain = await walkOf(buf, { keep: ['install.js', 'index.js'] });
  assert.deepEqual(plainOf({ ...noMs(r), notKept: r.notKept.map(({ base64, ...x }) => x) }), plainOf(plain));   // eslint-disable-line no-unused-vars
});

// ------------------------------------------------------------------ (D) the proxy's facts of an armed walk
const MAN = (scripts, extra = {}) => ({ name: 'p', version: '1.1.0', main: 'index.js', ...(scripts ? { scripts } : {}), ...extra });
async function armedWalk(files, man, { members = true, share = true } = {}) {
  const S = await SC(); const kl = S.keepListFor(man); const ms = new Map();
  const buf = tgz({ 'package.json': JSON.stringify(man), ...files });
  const walk = await walkOf(buf, { keep: kl.paths, ...(members ? { onMember: (p, n, d) => ms.set(p, S.memberFacts({ path: p, size: n, data: d })), memberWindow: S.FACTS_LIMITS.windowBytes } : {}),
    ...(share ? { shareOf: S.makeBase64Share } : {}) });
  return { S, walk, members: members ? [...ms.values()] : undefined, man, pj: JSON.parse(walk.packageJson.toString('utf8')) };
}

test('F1 staticFactsOf: recon\'s block over the member facts with the hook commands S0 reads and the registry keep-list roles; rule 7 on the S5 target that fires', async () => {
  const { S, walk, members, man, pj } = await armedWalk({ 'install.js': `${WASM}${FILL}`, 'index.js': 'require("fs").writeFileSync(require("os").homedir() + "/.claude/x", "1");\n',
    'test/t.js': 'eval(x);\n' }, MAN({ postinstall: 'node install.js' }));
  const x = S.staticFactsOf({ manifest: man, packageJson: pj, walk, members });
  assert.equal(x.facts.version, 'static-checks-1.9'); assert.equal(x.facts.status, 'CHECKED'); assert.equal(x.facts.note, F.note);
  assert.deepEqual(Object.keys(x.facts), ['version', 'note', 'status', 'encoded_runs', 'excluded_paths', 'agent_config_writes', 'io_surface'], 'recon\'s block shape');
  assert.equal(x.facts.encoded_runs.by_magic.wasm, 1);
  assert.deepEqual(x.facts.excluded_paths.p2, { rest: 0, excluded: 1, rest_files: 0, excluded_files: 1 });
  assert.deepEqual(x.facts.agent_config_writes.listed, [{ source: 'file', path: 'index.js', roles: ['main'], dirs: ['.claude'], writes: ['fs-write'] }]);
  assert.equal(x.facts.io_surface.install_hooks, 1); assert.equal(x.facts.io_surface.no_io_surface, false);
  assert.equal(x.facts.io_surface.members, 4, 'package.json is a member, as in recon');
  assert.deepEqual(members.map((m) => m.path).sort(), ['index.js', 'install.js', 'package.json', 'test/t.js']);
  const c = S.makeBase64Share(); c.push(Buffer.from(`${WASM}${FILL}`)); const w = c.end();
  assert.deepEqual(x.s5, [{ path: 'install.js', roles: ['hook'], size: Buffer.byteLength(`${WASM}${FILL}`), fires: true, base64_share: w.share, base64_magic: 'wasm' }]);
});

test('F2 without the streamed body the S5 fields are recon\'s nulls and note; without member facts the block is NOT_CHECKED "no member facts supplied"; a refused walk likewise', async () => {
  const { S, walk, man, pj } = await armedWalk({ 'install.js': FILL, 'index.js': 'module.exports = 1;\n' }, MAN({ postinstall: 'node install.js' }), { members: false, share: false });
  const x = S.staticFactsOf({ manifest: man, packageJson: pj, walk, members: undefined });
  assert.deepEqual(x.facts, { version: 'static-checks-1.9', note: F.note, status: 'NOT_CHECKED', reason: 'no member facts supplied' });
  assert.deepEqual(x.s5, [{ path: 'install.js', roles: ['hook'], size: Buffer.byteLength(FILL), fires: true, base64_share: null, base64_magic: null, base64_note: 'body not streamed: base64 share not checked' }]);
  const refused = S.staticFactsOf({ manifest: man, packageJson: null, walk: { ok: false, reason: 'tar: truncated archive' }, members: [] });
  assert.equal(refused.facts.status, 'NOT_CHECKED'); assert.equal(refused.facts.reason, 'no member facts supplied'); assert.deepEqual(refused.s5, []);
  const t = S.createMemberTally({ max: 2 }); for (const p of ['a.js', 'b.js', 'c.js']) t.onMember(p, 1, Buffer.from('1'));
  assert.equal(t.result().over, true); assert.equal(S.createMemberTally().max, S.MAX_FACTS_MEMBERS);
  const u = S.createMemberTally({ max: 2 }); u.onMember('a.js', 1, Buffer.from('1')); u.onMember('a.js', 2, Buffer.from('22'));
  assert.deepEqual(u.result(), { over: false, members: [S.memberFacts({ path: 'a.js', size: 2, data: Buffer.from('22') })] }, 'the last duplicate wins');
  const capped = S.staticFactsOf({ manifest: man, packageJson: pj, walk, members: [], membersOver: true });
  assert.equal(capped.facts.status, 'NOT_CHECKED'); assert.equal(capped.facts.reason, `more than ${S.MAX_FACTS_MEMBERS} archive members: member facts not kept`);
});

test('F3 the facts change no row: the eight static rows of a walk are identical with and without the member facts and the streamed share', async () => {
  const files = { 'install.js': `${WASM}${FILL}`, 'index.js': 'fetch("http://10.0.0.1/x"); eval(y);\n', 'vendor/v.js': 'eval(z);\n' };
  const man = MAN({ postinstall: 'node install.js' });
  const a = await armedWalk(files, man); const b = await armedWalk(files, man, { members: false, share: false });
  const rows = (x) => x.S.staticRows({ manifest: man, packageJson: x.pj, walk: x.walk, armed: 'install-introduced', predecessor: null });
  assert.deepEqual(rows(a), rows(b));
  const s5 = rows(a).find((r) => r.gate === S5G);
  assert.equal(s5.result, 'WARN'); assert.ok(!/base64|share|magic/i.test(s5.detail), s5.detail);
});

// ------------------------------------------------------------------ (E) the store
function withDb(fn) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cft015-sc16-'));
  const db = openWitnessDB(path.join(dir, 'witness.db')); db.applySchema();
  try { return fn(db); } finally { db.close(); fs.rmSync(dir, { recursive: true, force: true }); }
}
const rec = (v) => ({ package_name: 'a', version: v, walk: 'read', static_checks_version: 'static-checks-1.6', files: [] });

test('D1 the store: a version\'s static facts written once beside its entry facts; read back; none without an entry facts row', () => withDb((db) => {
  db.recordEntryFacts(rec('1.0.0'));
  assert.equal(db.staticFactsFor('a', '1.0.0'), null);
  const x = { facts: { version: 'static-checks-1.6', status: 'NOT_CHECKED', reason: 'r' }, s5: [] };
  assert.equal(db.recordStaticFacts('a', '1.0.0', x), 1);
  assert.equal(db.recordStaticFacts('a', '1.0.0', { facts: {}, s5: [] }), 0, 'once per version');
  assert.deepEqual(db.staticFactsFor('a', '1.0.0'), x);
  assert.equal(db.recordStaticFacts('a', '9.9.9', x), 0, 'no entry facts row: nothing written');
}));

test('D2 a witness.db whose entry_fact_versions predates static_facts gains it on applySchema; a read-only open of it reads null', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cft015-sc16m-'));
  try {
    const p = path.join(dir, 'w.db'); const raw = new Database(p);
    raw.exec(`CREATE TABLE entry_fact_versions (id INTEGER PRIMARY KEY AUTOINCREMENT, package_name TEXT NOT NULL, version TEXT NOT NULL,
      served_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')), walk TEXT NOT NULL CHECK (walk IN ('read','refused')), reason TEXT,
      static_checks_version TEXT NOT NULL, facts_ms REAL, shape TEXT, shadow TEXT, UNIQUE (package_name, version));
      INSERT INTO entry_fact_versions (package_name, version, walk, static_checks_version) VALUES ('a', '0.9.0', 'read', 'static-checks-1.5');`);
    raw.close();
    const ro = openWitnessDB(p, { readonly: true });
    try { assert.equal(ro.staticFactsFor('a', '0.9.0'), null, 'an old table: no column, null, no throw'); } finally { ro.close(); }
    const db = openWitnessDB(p); db.applySchema();
    try {
      const cols = new Database(p, { readonly: true });
      try { assert.ok(cols.prepare('PRAGMA table_info(entry_fact_versions)').all().some((c) => c.name === 'static_facts')); } finally { cols.close(); }
      assert.equal(db.recordStaticFacts('a', '0.9.0', { facts: {}, s5: [] }), 1);
    } finally { db.close(); }
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

// ------------------------------------------------------------------ (F) end to end
const H = 3_600_000; const T0 = Date.parse('2026-03-01T00:00:00Z'); const at = (h) => new Date(T0 + h * H).toISOString();
// 1.1.0 adds an install hook 48 h after a hookless 1.0.0 -> install-introduced WARN (named) -> the walk is armed
const doc = (name, scripts) => ({ name, 'dist-tags': { latest: '1.1.0' }, time: { '1.0.0': at(0), '1.1.0': at(48) },
  versions: { '1.0.0': { name, version: '1.0.0', main: 'index.js' }, '1.1.0': { name, version: '1.1.0', main: 'index.js', ...(scripts ? { scripts } : {}) } } });
const Z = doc('z', { postinstall: 'node install.js' });
const Q = doc('q', null);                                                  // no hook: not armed
const DOCS = { '/z': Z, '/q': Q };
const TARBALLS = {
  '/z/-/z-1.1.0.tgz': tgz({ 'package.json': JSON.stringify(Z.versions['1.1.0']), 'install.js': `${WASM}${FILL}`, 'index.js': 'module.exports = 1;\n',
    'scripts/a.sh': 'mkdir -p ~/.cursor/rules && cp r.md ~/.cursor/rules/\n' }),
  '/q/-/q-1.1.0.tgz': tgz({ 'package.json': JSON.stringify(Q.versions['1.1.0']), 'index.js': 'module.exports = 1;\n' }),
};
async function withProxy(config, fn) {
  resetDependencyCache(); forgetManifestHooks();
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cft015-sc16e-'));
  const upstream = http.createServer((req, res) => {
    const u = decodeURIComponent(req.url.split('?')[0]);
    if (TARBALLS[u]) { res.writeHead(200, { 'content-type': 'application/octet-stream', 'content-length': String(TARBALLS[u].length) }); res.end(TARBALLS[u]); return; }
    if (DOCS[u]) { res.writeHead(200, { 'content-type': 'application/json' }); res.end(JSON.stringify(DOCS[u])); return; }
    res.writeHead(404, { 'content-type': 'application/json' }); res.end('{}');
  });
  await new Promise((r) => upstream.listen(0, '127.0.0.1', r));
  const dbPath = path.join(dir, 'witness.db');
  const proxy = createProxyServer({ port: 0, host: '127.0.0.1', upstream: `http://127.0.0.1:${upstream.address().port}`,
    witnessDbPath: dbPath, headersTimeoutMs: 10_000, bodyTimeoutMs: 20_000, ...config });
  await new Promise((r) => proxy.listen(0, '127.0.0.1', r));
  const base = `http://127.0.0.1:${proxy.address().port}`;
  try { return await fn({ base, proxy, dir, dbPath }); } finally {
    await new Promise((r) => proxy.close(r)); await new Promise((r) => upstream.close(r)); fs.rmSync(dir, { recursive: true, force: true });
    resetDependencyCache(); forgetManifestHooks();
  }
}
const get = (u) => new Promise((resolve, reject) => http.get(u, { agent: false }, (res) => {
  const chunks = []; res.on('data', (x) => chunks.push(x)); res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks) }));
}).on('error', reject));
const settle = () => new Promise((r) => setTimeout(r, 300));
async function eventually(fn, ms = 5000) { const until = Date.now() + ms; let v = fn(); while (!v && Date.now() < until) { await new Promise((r) => setTimeout(r, 50)); v = fn(); } return v; }
const runCli = (args, env) => new Promise((resolve) => {
  const c = spawn(process.execPath, [CLI, ...args], { env: { ...process.env, NO_COLOR: '1', CI: '', ...env } });
  let out = ''; c.stdout.on('data', (d) => { out += d; }); c.stderr.on('data', (d) => { out += d; }); c.on('close', (code) => resolve({ code, out }));
});

test('E1 an armed download stores its static-checks-1.6 facts once (rule 6 wasm run, rule 7 on S5, 8d the shell script, 8h present); the download, its rows and its notice are unchanged; one no row arms stores them too (since 0.1.6)', async () => {
  await withProxy({}, async ({ base, proxy }) => {
    await get(`${base}/z`); const t = await get(`${base}/z/-/z-1.1.0.tgz`);
    assert.equal(t.status, 200); assert.ok(t.body.equals(TARBALLS['/z/-/z-1.1.0.tgz']), 'served unchanged');
    const x = await eventually(() => proxy.witnessDb.staticFactsFor('z', '1.1.0'));
    assert.equal(x?.facts?.version, 'static-checks-1.9', JSON.stringify(x)); assert.equal(x.facts.status, 'CHECKED');
    assert.equal(x.facts.encoded_runs.by_magic.wasm, 1);
    assert.deepEqual(x.facts.agent_config_writes.listed, [{ source: 'file', path: 'scripts/a.sh', roles: ['module'], dirs: ['.cursor'], writes: ['shell-copy', 'shell-mkdir'] }]);
    assert.equal(x.facts.io_surface.no_io_surface, false);
    assert.equal(x.s5.length, 1); assert.equal(x.s5[0].path, 'install.js'); assert.equal(x.s5[0].base64_magic, 'wasm');
    const rows = proxy.witnessDb.getLatestDecision('z', '1.1.0').gates_fired;
    const s5 = rows.find((g) => g.gate === S5G);
    assert.equal(s5?.result, 'WARN'); assert.ok(!/base64|share|magic|static-checks-1\.[67]/.test(s5.detail), s5.detail);
    assert.ok(!rows.some((g) => /fact/i.test(String(g?.gate))), 'no runner row carries a fact');
    await get(`${base}/z/-/z-1.1.0.tgz`); await settle();
    assert.deepEqual(proxy.witnessDb.staticFactsFor('z', '1.1.0'), x, 'written once');
    await get(`${base}/q`); await get(`${base}/q/-/q-1.1.0.tgz`); await settle();
    // 0.1.6 every download is walked (deliberate change of expectation): S8 and S9 read the member facts, so every walk gathers them
    assert.equal((await eventually(() => proxy.witnessDb.staticFactsFor('q', '1.1.0')))?.facts?.status, 'CHECKED', 'every download: the member facts are read');
  });
});

test('E2 `why` prints the static-checks-1.6 facts under the recorded facts, marked record-only; --json carries them', async () => {
  await withProxy({}, async ({ base, proxy, dbPath, dir }) => {
    await get(`${base}/z`); await get(`${base}/z/-/z-1.1.0.tgz`);
    await eventually(() => proxy.witnessDb.staticFactsFor('z', '1.1.0')); await settle();
    const w = await runCli(['why', 'z@1.1.0'], { CHAINGATE_WITNESS_DB: dbPath, HOME: dir });
    assert.match(w.out, /Static check facts \(static-checks-1\.9; recorded only: no verdict, tier or notice depends on it/);
    assert.match(w.out, /encoded runs 1 \(wasm 1\)/);
    assert.match(w.out, /S5 install\.js \(\d+ B\): base64 share 0\.\d+, magic wasm/);
    assert.match(w.out, /agent config writes 1: scripts\/a\.sh \.cursor \(shell-copy, shell-mkdir\)/);
    assert.match(w.out, /I\/O surface present/);
    const block = w.out.slice(w.out.indexOf('  Static check facts')).split('\n'); const end = block.findIndex((l, i) => i > 0 && !l.startsWith('    '));
    assert.ok(block.slice(0, end).join('\n').split('').every((ch) => ch.charCodeAt(0) < 0x80), 'the facts block is plain ASCII');
    const j = await runCli(['why', 'z@1.1.0', '--json'], { CHAINGATE_WITNESS_DB: dbPath, HOME: dir });
    const parsed = JSON.parse(j.out.slice(j.out.indexOf('{')));
    assert.equal(parsed.static_facts?.facts?.version, 'static-checks-1.9');
  });
});

test('E3 `report` names the armed version\'s static facts in the record-only block; the facts change no exit code', async () => {
  await withProxy({}, async ({ base, proxy }) => {
    await get(`${base}/z`); await get(`${base}/z/-/z-1.1.0.tgz`);
    await eventually(() => proxy.witnessDb.staticFactsFor('z', '1.1.0')); await settle();
    const j = JSON.parse((await get(`${base}/_chaingate/report`)).body.toString('utf8'));
    const ev = j.installs.flatMap((i) => i.events).find((e) => e.kind === 'facts' && e.package === 'z' && e.version === '1.1.0');
    assert.equal(ev?.static_facts?.facts?.version, 'static-checks-1.9', JSON.stringify(ev));
    const { renderReport } = await import('../../cli/report-render.js');
    const text = renderReport(j, { source: 'proxy' }).text;
    assert.match(text, /z@1\.1\.0: .*static-checks-1\.9 facts: encoded runs 1 \(wasm 1\)/);
    const bare = { ...j, installs: j.installs.map((i) => ({ ...i, events: i.events.filter((e) => e.kind !== 'facts') })) };
    assert.equal(renderReport(j, { source: 'proxy' }).exit, renderReport(bare, { source: 'proxy' }).exit);
  });
});

// ------------------------------------------------------------------ (G) the time 1.6 adds to an armed walk (operator ruling R12 2026-10-25)
// As R8 measured the entry facts (facts_ms), an armed walk's 1.6 work is timed and stored beside them: the walker's member windows and
// onMember calls (the memberFacts calls) and its share counter's push/end calls (the base64 share) as `memberMs`, plus staticFactsOf,
// in milliseconds, as `static_facts_ms` on the version's entry_fact_versions row. proxy/static-checks.js is unchanged (R12), so recon's
// parity record stands. No bar is set on the number in 0.1.5 (the facts change no outcome); the first week gives it.
test('T1 the walker keeps the time its member windows, onMember calls and share counter spend as memberMs; without onMember or shareOf there is none', async () => {
  const S = await SC();
  const big = `${WASM}${FILL}`;
  const buf = tgz({ 'package.json': '{"name":"p","version":"1.0.0"}', 'install.js': big, 'index.js': 'module.exports = 1;\n' });
  const a = await walkOf(buf, { onMember: (p, n, d) => S.memberFacts({ path: p, size: n, data: d }), memberWindow: S.FACTS_LIMITS.windowBytes });
  assert.ok(Number.isFinite(a.memberMs) && a.memberMs > 0, String(a.memberMs));
  assert.equal(Number(a.memberMs.toFixed(3)), a.memberMs, 'milliseconds to three places, as facts_ms');
  const b = await walkOf(buf, { keep: ['install.js', 'index.js'], shareOf: S.makeBase64Share });
  assert.ok(Number.isFinite(b.memberMs) && b.memberMs > 0, `the share counter alone: ${b.memberMs}`);
  const c = await walkOf(buf, { keep: ['install.js', 'index.js'] }); const d = await walkOf(buf, {});
  assert.equal('memberMs' in c, false); assert.equal('memberMs' in d, false);
  const e = await walkOf(buf, { onMember: () => { throw new Error('x'); }, memberWindow: 10 });
  assert.equal(e.ok, true); assert.ok(Number.isFinite(e.memberMs), 'a throwing tally is still timed');
});

test('T2 the store: recordStaticFacts(p, v, x, ms) writes static_facts_ms with the facts, once; without ms it reads NULL; an old table gains the column', () => {
  withDb((db) => {
    db.recordEntryFacts(rec('1.0.0')); db.recordEntryFacts(rec('2.0.0'));
    const x = { facts: { version: 'static-checks-1.6', status: 'NOT_CHECKED', reason: 'r' }, s5: [] };
    assert.equal(db.recordStaticFacts('a', '1.0.0', x, 12.345), 1);
    assert.equal(db.recordStaticFacts('a', '1.0.0', x, 99), 0, 'once per version');
    const ms = (v) => db.db.prepare('SELECT static_facts_ms FROM entry_fact_versions WHERE package_name = ? AND version = ?').get('a', v).static_facts_ms;
    assert.equal(ms('1.0.0'), 12.345);
    assert.deepEqual(db.staticFactsFor('a', '1.0.0'), x, 'the stored block is the facts alone');
    assert.equal(db.recordStaticFacts('a', '2.0.0', x), 1); assert.equal(ms('2.0.0'), null);
  });
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cft015-sc16t-'));
  try {
    const p = path.join(dir, 'w.db'); const raw = new Database(p);
    raw.exec(`CREATE TABLE entry_fact_versions (id INTEGER PRIMARY KEY AUTOINCREMENT, package_name TEXT NOT NULL, version TEXT NOT NULL,
      served_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')), walk TEXT NOT NULL CHECK (walk IN ('read','refused')), reason TEXT,
      static_checks_version TEXT NOT NULL, facts_ms REAL, shape TEXT, shadow TEXT, static_facts TEXT, UNIQUE (package_name, version));
      INSERT INTO entry_fact_versions (package_name, version, walk, static_checks_version) VALUES ('a', '0.9.0', 'read', 'static-checks-1.6');`);
    raw.close();
    const db = openWitnessDB(p); db.applySchema();
    try { assert.equal(db.recordStaticFacts('a', '0.9.0', { facts: {}, s5: [] }, 1.5), 1); } finally { db.close(); }
    const r = new Database(p, { readonly: true });
    try { assert.equal(r.prepare('SELECT static_facts_ms FROM entry_fact_versions').get().static_facts_ms, 1.5); } finally { r.close(); }
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

test('T3 end to end: every walked version carries static_facts_ms beside facts_ms, read by the sqlite line; the facts block unchanged', async () => {
  await withProxy({}, async ({ base, proxy, dbPath }) => {
    await get(`${base}/z`); await get(`${base}/z/-/z-1.1.0.tgz`);
    const x = await eventually(() => proxy.witnessDb.staticFactsFor('z', '1.1.0'));
    assert.deepEqual(Object.keys(x).sort(), ['facts', 's5'], 'the block has no timing field');
    await get(`${base}/q`); await get(`${base}/q/-/q-1.1.0.tgz`); await settle();
    const r = new Database(dbPath, { readonly: true });
    try {
      const rows = r.prepare("SELECT package_name, version, facts_ms, static_facts_ms FROM entry_fact_versions WHERE package_name IN ('z', 'q')").all();
      const z = rows.find((w) => w.package_name === 'z'); const q = rows.find((w) => w.package_name === 'q');
      assert.ok(Number.isFinite(z?.static_facts_ms) && z.static_facts_ms > 0, JSON.stringify(rows));
      assert.ok(Number.isFinite(z.facts_ms), 'beside facts_ms');
      // 0.1.6 every download is walked (deliberate change of expectation)
      assert.ok(Number.isFinite(q?.static_facts_ms), JSON.stringify(rows));
    } finally { r.close(); }
  });
});

// ------------------------------------------------------------------ (H) the stored and shown facts in plain words (operator 2026-10-25)
// What the proxy stores and prints carries no internal wording. Recon's block in proxy/static-checks.js stays byte for byte (its two
// notes included); the proxy replaces those two notes with plain ones when it stores the facts, and its own heading note is plain.
const INTERNAL = /operator|ruling|recon|\bR11\b/i;
test('T4 publicStaticFacts gives the block with plain notes and nothing else changed; SHADOW_NOTE is plain; the module\'s own block is unchanged', async () => {
  const S = await SC(); const SF = await import('../../proxy/shadow-facts.js');
  assert.doesNotMatch(SF.SHADOW_NOTE, INTERNAL); assert.match(SF.SHADOW_NOTE, /no verdict, tier or notice depends on it/);
  const { walk, members, man, pj } = await armedWalk({ 'install.js': `${WASM}${FILL}`, 'index.js': 'module.exports = 1;\n', 'test/a.js': 'eval("1");\n' }, MAN({ postinstall: 'node install.js' }));
  const x = S.staticFactsOf({ manifest: man, packageJson: pj, walk, members });
  assert.equal(x.facts.note, S.FACTS_NOTE, 'the module\'s block is recon\'s, unchanged');
  const y = SF.publicStaticFacts(x);
  assert.doesNotMatch(JSON.stringify(y), INTERNAL, JSON.stringify(y).slice(0, 400));
  assert.match(y.facts.note, /recorded only/); assert.match(y.facts.excluded_paths.note, /dynamic code/);
  const strip = (o) => { const c = structuredClone(o); delete c.facts.note; if (c.facts.excluded_paths) delete c.facts.excluded_paths.note; return c; };
  assert.deepEqual(strip(y), strip(x));
  assert.equal(x.facts.note, S.FACTS_NOTE, 'the input is not changed in place');
  const nc = SF.publicStaticFacts(S.staticFactsOf({ manifest: man, packageJson: pj, walk, members: undefined }));
  assert.doesNotMatch(JSON.stringify(nc), INTERNAL); assert.equal(nc.facts.status, 'NOT_CHECKED');
  assert.equal(SF.publicStaticFacts(null), null);
});

test('T5 end to end: the stored static facts, `why` (text and --json) and the report carry no internal wording', async () => {
  await withProxy({}, async ({ base, proxy, dbPath, dir }) => {
    await get(`${base}/z`); await get(`${base}/z/-/z-1.1.0.tgz`);
    const x = await eventually(() => proxy.witnessDb.staticFactsFor('z', '1.1.0')); await settle();
    assert.doesNotMatch(JSON.stringify(x), INTERNAL);
    const w = await runCli(['why', 'z@1.1.0'], { CHAINGATE_WITNESS_DB: dbPath, HOME: dir });
    assert.match(w.out, /Static check facts/); assert.doesNotMatch(w.out, INTERNAL, w.out);
    const j = await runCli(['why', 'z@1.1.0', '--json'], { CHAINGATE_WITNESS_DB: dbPath, HOME: dir });
    assert.doesNotMatch(j.out, INTERNAL);
    const r = (await get(`${base}/_chaingate/report`)).body.toString('utf8');
    assert.doesNotMatch(r, INTERNAL);
    const { renderReport } = await import('../../cli/report-render.js');
    assert.doesNotMatch(renderReport(JSON.parse(r), { source: 'proxy' }).text, INTERNAL);
  });
});
