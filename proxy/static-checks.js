// 0.1.5 tarball static checks S0-S7 (design note §4, §5; S6 and S7 by operator rulings R2 and R3 2026-10-21). Pure functions over the registry manifest, the tarball package.json and the
// walker's kept bodies (tar-walk.js `keep`, step 1). Each check is a CONJUNCTION of two facts about ONE file (or one hook command),
// stated so a reviewer can confirm it by opening the tarball. A row is { gate, result: ALLOW | SKIP | WARN, detail }, the shape every
// gate writes; its detail is built from a closed vocabulary -- the marker NAMES that matched (never file content, never a host, never
// a command), the file's path sanitised and capped as MC's shownName, and the kept size. "Not checked" (SKIP) is stated per file and
// never read as absence; a WARN wins over not checked, which wins over ALLOW (as MC). No static row is ever a BLOCK.
// The marker constants are the ops recon tool's (chaingate-ops tools/recon/v6.6/static-checks.mjs) under the SAME version string, so a
// runtime row and a recon row read against each other; a change to any marker bumps STATIC_CHECKS_VERSION on both sides.
// The static-checks bump (operator rulings 2026-10-15; recon first, this file mirrors it): S0 adds hook-command exfiltration, S2 adds
// numeric hex, S3's sink is the exfil-host class only, and a file row that read nothing although its roles had a candidate says "no
// eligible file in the tarball". static-checks-1.2 (recon 7251caa; operator 2026-10-15, path (a); 1.1 was never shipped) adds S5,
// the oversized hook target as its own gate, judged by one fact: a hook target's size from the tar header.
// static-checks-1.3 is a WORDING-ONLY bump of 1.2 (operator 2026-10-15; contract 3.5, orchestrator verdict 20:25Z): S0's notice text
// says what 1.2's S0 catches (fetch-and-execute and hook-command exfiltration). Markers, thresholds, gates and roles are 1.2's, so
// every outcome is 1.2's. Recon's matching commit: chaingate-ops c135e35 (tools/recon/v6.7/static-checks.mjs), the same two strings.
//   S0 shell-fetch-in-hook        a preinstall/install/postinstall command carries a FETCH (curl, wget, Invoke-WebRequest, certutil
//                                 -urlcache, bitsadmin) AND an EXECUTE/DECODE (| sh, powershell -enc, base64 -d, eval, iex);
//                                 OR a NETWORK TOOL at a command position (curl, wget, nc, and nslookup/dig/host/ping with command
//                                 substitution only) AND a SENDS marker (command substitution, a data flag, a raw-IP or exfil-host URL)
//   S1 loader-in-hook-target      a kept hook target under 8 KiB with a NETWORK sink AND an EXECUTION sink
//   S2 obfuscated-entry           a kept main/bin target with >= 20 distinct `_0x[0-9a-f]{4,6}` identifiers AND a decode marker
//                                 (eval, Function, atob, a String.fromCharCode run of >= 50 codes, hex-escape density > 15 %,
//                                 >= 1,000 numeric 0x literals)
//   S3 secret-harvest-with-sink   a kept main/bin/hook target with a CREDENTIAL source AND an exfil-host sink (raw-IP and POST to
//                                 another literal host are recorded sinks, never firing)
//   S4 wallet-swap-hook           a kept main/bin target that OVERRIDES XMLHttpRequest.prototype.send / window.fetch /
//                                 window.ethereum.request AND carries >= 2 crypto-address regex families
//   S5 oversized-hook-target      a hook target over the 1 MiB kept-file cap (size from the tar header; the body is not read)
//   S6 network-beacon-in-hook-target  a kept hook target with an API network sink (url-literal is not one) AND a host-identity source
//                                 (os.hostname(), os.userInfo(), os.networkInterfaces() on os or require('os'), env-dump, or USER,
//                                 USERNAME, LOGNAME, HOSTNAME, COMPUTERNAME read from process.env; a bare process.env read is not one)
//                                 AND no execution sink in the same file
//   S7 entry-capability-gain      main or bin GAINS a capability (net, exec, decode, obf, cred; url-literal never) that the predecessor's
//                                 same-role files lacked (bin compared as the union); predecessor = the last version this proxy served
//                                 (witness.db entry facts, R4); none = not applicable; a refused or unread file = not checked, never a
//                                 clean delta; a role with no candidate file in an archive read in full is verified absent (review
//                                 verdict 2026-10-21) and compares as empty
// static-checks-1.4 (operator ruling R5 2026-10-21) is recon's tree v6.12 (chaingate-ops tools/recon/v6.12/static-checks.mjs) mirrored:
// S0 1.4 reads the quoted argument of sh|bash|dash|zsh -c one level deep and counts a network tool given by absolute path by its
// basename; S6 and S7 as above. Recon's constants, the S7 capability set and capabilityDelta are copied as they are; recon's
// entryFactsSummary is applied to the proxy's stored entry facts (entrySummaryOf).
// static-checks-1.5 (operator rulings R7, R9, R9a, R9b 2026-10-22) is recon's v6.13 mirrored: every 1.4 marker unchanged; S7 is an
// INDICATOR only when a role READ and non-empty on the predecessor and READ now gains a decode:* or obf:* class other than
// decode:Function, or an API network sink with an execution sink other than exec:Function (s7Named); every other gain is NONE and stays
// on the row as a fact with why it was not named.
// static-checks-1.6 (operator ruling R11 2026-10-24) is recon's v6.14 mirrored: every 1.5 constant unchanged, plus SHADOW FACTS (the
// triage noise-reduction rules 6, 7, 8a, 8d and 8h), recon's facts code as written (memberFacts, staticFacts, makeBase64Share and their
// constants). They are computed on an armed walk and stored beside the version's entry facts, never a row: no outcome, indicator,
// gate, class or notice reads them (staticFactsOf below; proxy/tar-walk.js reads the member windows and streams an over-cap hook target).
// static-checks-1.7 (operator 2026-10-26) is recon's v6.16 mirrored: the API network sinks 'http-request' and 'net-connect' also read a
// call on a NAME BOUND to the module (BOUND_CALLS, boundModuleCall): <id> = ...require(M)...; then <id>.f( (the beacon.cjs ternary
// `lib = c ? require('https') : require('http')`), require(M).f( direct, import <id> | * as <id> from M; then <id>.f(, and the
// destructured { f } / { f: local } = require(M) or import { f [as local] } from M; then a bare call. The 1.6 literal-receiver regexes
// stay and are tried first; the names stay (a call that moved from https.request( to lib.request( is not an S7 gain); url-literal stays
// excluded; every other constant, check, gate, role, notice and limit is unchanged. Each scan is linear (BOUND_LIMITS). Not read: a
// binding split across lines, a module held in an object property or passed to a function, a dynamic import(), and a name bound in
// one file and called in another.
// static-checks-1.8 (operator 2026-10-27; 0.1.5 held for it) is recon's v6.17 mirrored: two named checks appended after S7, S0-S7,
// every sink and every 1.6 fact unchanged.
//   S8 prebuilt-addon-dropper-in-hook  an install hook loads a shipped native module (a .node member with an ELF / PE / Mach-O head),
//                                      the tarball has no native source (no C/C++/... member, no binding.gyp naming a source), and a
//                                      member is text under a one-byte XOR (not UTF-8, under half printable, one key makes it at least
//                                      95 % printable; read over its first 1 MiB). The first two alone are a fact on the row.
//   S9 hidden-script-in-gyp-build      a binding.gyp or .gypi command expansion runs a package script with its standard output
//                                      discarded (npm builds a root binding.gyp even with no install hook).
// Both read the member facts of every archive member (memberFacts: native, node_file, native_source, gyp_sources, xor_text, gyp_build),
// which an armed walk already gathers (createMemberTally); without them, or past MAX_FACTS_MEMBERS, a row is SKIP "not checked", stated.
// Recon's block (S8_LIMITS through addonDropper) is copied as written; STATIC_LIMITS is recon's name for LIMITS. Stated limits: a body
// with a NUL in its first 8000 bytes is not read for XOR text; a multi-byte key or real encryption is not text under one key; a module
// loaded another way (a main or bin file, a dependency) is not a hook load.
// The keep list (keepListFor) comes from the REGISTRY manifest, known before the first byte: install-hook targets (a small hook
// grammar, node-resolution variants), main (default index.js), up to 4 bin targets; what is dropped is stated. The roles of a kept
// body (hook, main, bin) decide which checks read it; a body the tarball package.json alone names gets its role from that file.
import { createHash } from 'node:crypto';
import { posix } from 'node:path';
import { pyTruthy } from '../seed/v3/packument.js';
import { DEFAULTS as WALK } from './tar-walk.js';
import { classify } from '../witness/row-class.js';
import { NAMED_RUNNER_GATES, NAMED_ROWS } from '../seed/v3/policy.js';

export const STATIC_CHECKS_VERSION = 'static-checks-1.9';
/** The reason a file row states when its roles had a candidate on the keep list and no file was read (ruled 2026-10-14). */
export const NOTHING_READ = 'no eligible file in the tarball';
export const LIMITS = Object.freeze({ maxKeep: WALK.maxKeep, maxKeepBytes: WALK.maxKeepBytes, maxBin: 4, maxHookTargets: 3, s1MaxBytes: 8192,
  s2MinIdents: 20, s2MinCharCodes: 50, s2HexDensity: 0.15, s2MinNumericHex: 1000, s4MinAddressFamilies: 2, headBytes: 8000, detailChars: 400 });
/** recon's name for the same limits (headBytes 8000), so the static-checks-1.8 block below reads as written. */
const STATIC_LIMITS = LIMITS;
export const CHECKS = Object.freeze([
  { id: 'S0', gate: 'static:S0-shell-fetch-in-hook', cls: 'shell-fetch-in-hook', roles: null, notice: 'an install script downloads code to run or sends data to an outside host' },
  { id: 'S1', gate: 'static:S1-loader-in-hook-target', cls: 'loader-in-hook-target', roles: ['hook'], notice: 'an install script runs a small loader that fetches and executes' },
  { id: 'S2', gate: 'static:S2-obfuscated-entry', cls: 'obfuscated-entry', roles: ['main', 'bin'], notice: 'its entry file is obfuscated code' },
  { id: 'S3', gate: 'static:S3-secret-harvest-with-sink', cls: 'secret-harvest-with-sink', roles: ['main', 'bin', 'hook'], notice: 'its code reads credentials and sends them to an outside host' },
  { id: 'S4', gate: 'static:S4-wallet-swap-hook', cls: 'wallet-swap-hook', roles: ['main', 'bin'], notice: 'its code rewrites wallet addresses in web traffic' },
  { id: 'S5', gate: 'static:S5-oversized-hook-target', cls: 'oversized-hook-target', roles: ['hook'], notice: 'an install script runs a file too large to read' },
  { id: 'S6', gate: 'static:S6-network-beacon-in-hook-target', cls: 'network-beacon-in-hook-target', roles: ['hook'], notice: 'an install script sends details about this machine to the network' },   // R2; named as INDICATOR (R7 2026-10-22)
  { id: 'S7', gate: 'static:S7-entry-capability-gain', cls: 'entry-capability-gain', roles: ['main', 'bin'], notice: 'its entry file gained a capability its previous version did not have' },   // R3; named on the 1.5 condition (R9 2026-10-22)
  { id: 'S8', gate: 'static:S8-prebuilt-addon-dropper-in-hook', cls: 'prebuilt-addon-dropper-in-hook', roles: null, notice: 'an install script loads a prebuilt native module shipped without its source, next to an encoded file' },   // v6.17 (operator 2026-10-27)
  { id: 'S9', gate: 'static:S9-hidden-script-in-gyp-build', cls: 'hidden-script-in-gyp-build', roles: null, notice: 'its native build file runs a package script during install and hides the output' },   // v6.17 (operator 2026-10-27, step 0b)
]);
export const STATIC_GATES = Object.freeze(CHECKS.map((c) => c.gate));
/** Armed keep-list walks at once (design note §3 budget: ≤ 6 MiB each); beyond it a download gets the MC-only walk, stated and retried.
 *  Since 0.1.6 every download is walked, so the ceiling is npm's own default of 16 connections (about 96 MiB kept at most). */
export const MAX_ARMED_WALKS = 16;
/** 0.1.5 (R4): walks that keep only the main and bin bodies for the entry facts, at once (at most 6 x 1 MiB each); beyond it the
 *  version's facts are stored at a later download. */
export const MAX_FACTS_WALKS = 8;
/** 0.1.5 (#15): with the per-user `static_withhold` switch on, an armed download is held in memory up to this many bytes while the
 *  static checks read it (design note section 8 item 2); past it the download is served and recorded as today. With the ceiling
 *  above, at most MAX_ARMED_WALKS x 8 MiB are held at once. Since 0.1.6 every walked download is held while the switch is on. */
export const STATIC_WITHHOLD_CAP_BYTES = 8 * 1024 * 1024;
/**
 * 0.1.5 (#15): the static checks that withhold a held download: a static row whose result is WARN and whose gate the policy NAMES.
 * Rows are expected with their 1.2 role applied (`withRole`), so a contributing check's WARN is already a NOTE and never withholds.
 * A named row that is not a static check is served with its notice, as today. `named` defaults to the policy's named runner gates.
 */
export function withholdingChecks(rows, named = NAMED_RUNNER_GATES) {
  if (!Array.isArray(rows)) return [];
  const set = new Set(named);
  return [...new Set(rows.filter((r) => r && r.result === 'WARN' && STATIC_GATES.includes(r.gate) && set.has(r.gate)).map((r) => r.gate))].sort();
}
const INSTALL_HOOKS = ['preinstall', 'install', 'postinstall'];
const isObj = (x) => x !== null && typeof x === 'object' && !Array.isArray(x);
const names = (list, s) => list.filter(([, re]) => re.test(s)).map(([n]) => n);
/** 1.9 S6: is the match at idx inside the argument of a .update( call (a hash input)? */
export function insideUpdateArg(s, idx) {
  let depth = 0;
  for (let k = idx - 1; k >= 0 && k >= idx - 4000; k -= 1) { const c = s[k];
    if (c === ')') depth += 1;
    else if (c === '(') { if (depth === 0) return /\.\s*update\s*$/.test(s.slice(Math.max(0, k - 24), k)); depth -= 1; } }
  return false;
}
/** 1.9 S6: the host-identity sources with at least one use outside a hash's .update( argument (a hashed-only device id is not a raw source). */
export const hostIdentityNames = (s) => HOST_IDENTITY.filter(([, re]) => { const g = new RegExp(re.source, re.flags.includes('g') ? re.flags : `${re.flags}g`);
  for (const m of s.matchAll(g)) if (!insideUpdateArg(s, m.index)) return true; return false; }).map(([n]) => n);
// publisher text: control and bidi characters stripped, capped at 80 characters (as MC's shownName, G4 D-C1)
const UNSAFE = /[\u0000-\u001f\u007f-\u009f\u061c\u200b-\u200f\u202a-\u202e\u2060-\u2069\ufeff]/g;
export const shownName = (n) => { const x = String(n ?? '').replace(UNSAFE, ''); return x.length > 80 ? `${x.slice(0, 80)}…` : x; };
const clipDetail = (s) => (s.length > LIMITS.detailChars ? `${s.slice(0, LIMITS.detailChars - 1)}…` : s);

// ---- marker constants (closed vocabulary; names are what reaches a row) -- the recon v6.6 lists, verbatim ----
export const FETCH_MARKERS = [
  ['curl', /\bcurl(?:\.exe)?\b/i], ['wget', /\bwget(?:\.exe)?\b/i],
  ['Invoke-WebRequest', /Invoke-WebRequest|Invoke-RestMethod|\biwr\b|\birm\b/i],
  ['certutil-urlcache', /\bcertutil(?:\.exe)?\b[^|&;]{0,200}-urlcache/i],
  ['bitsadmin', /\bbitsadmin(?:\.exe)?\b|Start-BitsTransfer/i],
];
export const EXEC_MARKERS = [
  ['powershell-encoded', /\b(?:powershell|pwsh)(?:\.exe)?\b[^|&;]{0,200}\s-(?:e|ec|enc|encodedcommand)\b/i],
  ['Invoke-Expression', /Invoke-Expression|\biex\b/i],
  ['base64-decode', /\bbase64\b\s+(?:-\w+\s+)*(?:-d|-D|--decode)\b|\bcertutil(?:\.exe)?\b[^|&;]{0,200}-decode/i],
  ['pipe-to-shell', /(?<!\|)\|(?!\|)\s*(?:sudo\s+(?:-\S+\s+)*)?(?:ba|z|da|k|c|tc|fi)?sh\b(?!-)/],                      // a pipe, never the || operator
  ['pipe-to-interpreter', /(?<!\|)\|(?!\|)\s*(?:sudo\s+(?:-\S+\s+)*)?(?:node|bun|deno|python[23]?|perl|ruby)\b(?![-.])/],   // `|| node-gyp rebuild` is neither
  ['eval', /\beval\b/],
];
/** v6.16 static-checks-1.7: the bound-module call forms. Per sink: the modules (with or without node:) and the calls each one names. */
export const BOUND_CALLS = Object.freeze({
  'http-request': Object.freeze([Object.freeze({ mod: 'https?|http2', fns: 'request|get' })]),
  'net-connect': Object.freeze([Object.freeze({ mod: 'net', fns: 'connect|createConnection' }), Object.freeze({ mod: 'tls', fns: 'connect' }), Object.freeze({ mod: 'dgram', fns: 'createSocket' })]),
});
/** How far back from a require(M) / from M a binding is looked for (characters): an assignment, an import clause, a destructuring brace. */
export const BOUND_LIMITS = Object.freeze({ assignLookback: 160, importLookback: 240, braceChars: 200 });
const BID = String.raw`[A-Za-z_$][\w$]*`;
const ASSIGN = new RegExp(String.raw`(?<![\w$.])(${BID})\s*=(?![=>])`, 'g');
const DESTRUCTURE_TAIL = new RegExp(String.raw`\{([^{}]{0,${BOUND_LIMITS.braceChars}})\}\s*=\s*$`);
const BARE_CALL = new RegExp(String.raw`(?<![\w$.])(${BID})\s*\(`, 'g');
const FN_DECL_TAIL = /\bfunction\s*\*?\s*$/;
const boundSpec = ({ mod, fns }) => {
  const M = String.raw`['"\x60](?:node:)?(?:${mod})['"\x60]`;
  return { mod: new RegExp(M), direct: new RegExp(String.raw`\brequire\s*\(\s*${M}\s*\)\s*\.\s*(?:${fns})\s*\(`),
    req: new RegExp(String.raw`\brequire\s*\(\s*${M}\s*\)`, 'g'), from: new RegExp(String.raw`\bfrom\s*${M}`, 'g'),
    member: new RegExp(String.raw`(?<![\w$.])(${BID})\s*\.\s*(?:${fns})\s*\(`, 'g'), fn: new RegExp(String.raw`^(?:${fns})$`) };
};
/** The statement text before index i, back to ; { } or a line break, at most n characters. */
const stmtBefore = (s, i, n) => { let k = i - 1; const lo = Math.max(0, i - n); while (k >= lo && !';{}\n'.includes(s[k])) k -= 1; return s.slice(k + 1, i); };
/** The local names a destructuring list binds to the named calls: `f`, `f: local` (require) or `f as local` (import). */
const localsOf = (list, form, fn) => list.split(',').map((t) => t.trim()).flatMap((t) => {
  const m = form === 'import' ? new RegExp(String.raw`^(${BID})(?:\s+as\s+(${BID}))?$`).exec(t) : new RegExp(String.raw`^(${BID})\s*(?::\s*(${BID}))?\s*(?:=[\s\S]*)?$`).exec(t);
  return m && fn.test(m[1]) ? [m[2] ?? m[1]] : [];
});
/** v6.16 static-checks-1.7, pure and linear: does s call one of the named functions on a name bound to the module (BOUND_CALLS)? */
export function boundModuleCall(s, calls) {
  if (typeof s !== 'string') return false;
  for (const sp of calls.map(boundSpec)) {
    if (!sp.mod.test(s)) continue;
    if (sp.direct.test(s)) return true;
    const bound = new Set(); const locals = new Set();
    for (const m of s.matchAll(sp.req)) {
      const a = [...stmtBefore(s, m.index, BOUND_LIMITS.assignLookback).matchAll(ASSIGN)].pop(); if (a) bound.add(a[1]);
      const d = DESTRUCTURE_TAIL.exec(s.slice(Math.max(0, m.index - BOUND_LIMITS.braceChars - 40), m.index)); if (d) for (const n of localsOf(d[1], 'require', sp.fn)) locals.add(n);
    }
    for (const m of s.matchAll(sp.from)) {
      const seg = s.slice(Math.max(0, m.index - BOUND_LIMITS.importLookback), m.index); const k = seg.lastIndexOf('import');
      if (k < 0 || /[\w$]/.test(seg[k - 1] ?? '') || seg.slice(k).includes(';')) continue;
      const clause = seg.slice(k + 6);
      const ns = new RegExp(String.raw`\*\s*as\s+(${BID})`).exec(clause); if (ns) bound.add(ns[1]);
      const def = new RegExp(String.raw`^\s+(${BID})\s*(?:,|$)`).exec(clause); if (def) bound.add(def[1]);
      const br = /\{([^{}]*)\}/.exec(clause); if (br) for (const n of localsOf(br[1], 'import', sp.fn)) locals.add(n);
    }
    if (bound.size) for (const m of s.matchAll(sp.member)) if (bound.has(m[1])) return true;
    if (locals.size) for (const m of s.matchAll(BARE_CALL)) if (locals.has(m[1]) && !FN_DECL_TAIL.test(s.slice(Math.max(0, m.index - 16), m.index))) return true;
  }
  return false;
}
/** A sink that reads its 1.6 literal-receiver regex first, then the bound forms (names() and IO_TOKENS call test only). */
const sinkWithBound = (re, calls) => Object.freeze({ test: (s) => re.test(s) || boundModuleCall(s, calls), literal: re, bound: calls, toString: () => `${re} | bound` });
export const NET_SINKS = [
  ['http-request', sinkWithBound(/\b(?:https?|http2)\.(?:request|get)\s*\(/, BOUND_CALLS['http-request'])], ['fetch', /\bfetch\s*\(/],   // 1.7: + bound forms
  ['net-connect', sinkWithBound(/\bnet\.(?:connect|createConnection)\s*\(|\btls\.connect\s*\(|\bdgram\.createSocket\s*\(/, BOUND_CALLS['net-connect'])],   // 1.7: + bound forms
  ['websocket', /\bnew\s+WebSocket\s*\(/], ['xhr', /\bnew\s+XMLHttpRequest\s*\(/], ['axios', /\baxios(?:\.\w+)?\s*\(/],
  ['url-literal', /https?:\/\/[^\s'"`]{3,}/],
];
/** 1.4 (R2, R3): the API network sinks, i.e. NET_SINKS without url-literal (a URL string in a comment or README is not a call). */
export const API_NET_SINKS = NET_SINKS.filter(([n]) => n !== 'url-literal');
export const EXEC_SINKS = [
  ['child_process', /child_process|\b(?:execSync|spawnSync|execFileSync|execFile|spawn|fork)\s*\(/],
  ['eval', /\beval\s*\(/], ['Function', /(?:^|[^\w$.])(?:new\s+)?Function\s*\(/], ['vm', /\bvm\.(?:runIn(?:New|This)?Context|Script)\s*\(/],
];
export const DECODE_MARKERS = [['eval', /\beval\s*\(/], ['Function', /(?:^|[^\w$.])(?:new\s+)?Function\s*\(/], ['atob', /\batob\s*\(/]];
export const OBF_IDENT = /_0x[0-9a-f]{4,6}\b/g;
const HEX_ESCAPE = /\\x[0-9a-fA-F]{2}/g;
/** 1.2 S2: a numeric hex literal (0x1F), never an _0x identifier or a regex source like 0x[a-f]. */
const NUMERIC_HEX = /(?<![\w$.])0[xX][0-9a-fA-F]+\b/g;
const CHARCODE_RUN = new RegExp(`String\\.fromCharCode\\s*\\(\\s*(?:\\d{1,3}\\s*,\\s*){${LIMITS.s2MinCharCodes - 1},}\\d{1,3}`);
export const CRED_SOURCES = [
  ['npmrc', /\.npmrc\b/], ['ssh-key', /\.ssh\/|\bid_rsa\b|\bid_ed25519\b|\bid_ecdsa\b/],
  ['aws-credentials', /\.aws\/credentials|\bAWS_SECRET_ACCESS_KEY\b|\bAWS_ACCESS_KEY_ID\b/], ['git-credentials', /\.git-credentials\b/],
  ['token-env', /\b(?:NPM_TOKEN|GITHUB_TOKEN|GH_TOKEN|NODE_AUTH_TOKEN|NPM_AUTH_TOKEN|GITLAB_TOKEN|CI_JOB_TOKEN)\b/],
  ['env-dump', /JSON\.stringify\(\s*process\.env\s*\)|Object\.(?:keys|entries|values)\(\s*process\.env\s*\)|\.\.\.process\.env\b/],
  ['wallet-file', /wallet\.dat|Local Storage\/leveldb|\.config\/gcloud|\.kube\/config/],
];
/** 1.4 S6 (R2) host-identity sources: the os calls (receiver os or require('os')), the env-dump marker, the named identity variables.
 *  A bare process.env read (NODE_ENV, npm_config_*) is not a source. */
export const IDENTITY_ENV = Object.freeze(['USER', 'USERNAME', 'LOGNAME', 'HOSTNAME', 'COMPUTERNAME']);
const OS_RECV = String.raw`(?:\bos|\brequire\(\s*['"\x60](?:node:)?os['"\x60]\s*\))\s*\.\s*`;
const IDV = IDENTITY_ENV.join('|');
export const HOST_IDENTITY = [
  ['os.hostname', new RegExp(`${OS_RECV}hostname\\s*\\(`)], ['os.userInfo', new RegExp(`${OS_RECV}userInfo\\s*\\(`)],
  ['os.networkInterfaces', new RegExp(`${OS_RECV}networkInterfaces\\s*\\(`)],
  ['env-dump', CRED_SOURCES.find(([n]) => n === 'env-dump')[1]],
  ['identity-env', new RegExp(`\\bprocess\\.env(?:\\.(?:${IDV})\\b|\\[\\s*(['"\\x60])(?:${IDV})\\1\\s*\\])`)],
];
const apiNames = new Set(API_NET_SINKS.map(([n]) => n));
/** The API network sinks one file's facts carry (url-literal is never one; R2, R3). */
const apiNet = (F) => (Array.isArray(F?.net_sinks) ? F.net_sinks.filter((n) => apiNames.has(n)) : []);
export const EXFIL_HOSTS = /discord(?:app)?\.com\/api\/webhooks|api\.telegram\.org|hooks\.slack\.com|webhook\.site|\.pipedream\.net|\.ngrok(?:-free)?\.(?:io|app|dev)|\binteract\.sh\b|\boast\.(?:pro|live|site|fun|me)\b|burpcollaborator\.net|requestbin|pastebin\.com|transfer\.sh|\.requestcatcher\.com|\.free\.beeceptor\.com|\.hookbin\.com|\.pipedream\.com/i;
export const RAW_IP_URL = /\bhttps?:\/\/(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?\b/;
export const REGISTRY_HOSTS = Object.freeze(['registry.npmjs.org', 'registry.yarnpkg.com', 'registry.npmmirror.com', 'npmjs.com', 'www.npmjs.com', 'localhost', '127.0.0.1']);
const URL_HOST = /https?:\/\/([^\s'"`/:?#\\]+)/g;
const POST_MARKER = /method\s*[:=]\s*['"]POST['"]|\.post\s*\(|['"]POST['"]\s*,/i;
export const OVERRIDES = [
  ['xhr-send', /XMLHttpRequest\.prototype\.send\s*=/], ['window-fetch', /\b(?:window|globalThis|self)\.fetch\s*=/], ['ethereum-request', /\bethereum\.request\s*=/],
];
export const ADDRESS_FAMILIES = [
  ['evm', /0x\[(?:a-fA-F0-9|0-9a-fA-F|a-f0-9|0-9a-f|A-F0-9|0-9A-F|a-zA-Z0-9)\]\{40\}/],
  ['btc', /bc1\[[^\]]{1,60}\]\{|\[13\]\[[^\]]{1,60}\]\{2\d,3\d\}/],
  ['trx', /\bT\[[^\]]{1,40}\]\{33\}/],
  ['sol', /\[1-9A-HJ-NP-Za-km-z\]\{32,44\}|\[1-9A-HJ-NP-Za-km-z\]\{43,44\}/],
  ['ltc', /\[LM3\]\[[^\]]{1,40}\]\{26,33\}|ltc1\[[^\]]{1,60}\]\{/],
  ['xmr', /4\[0-9AB\]\[1-9A-HJ-NP-Za-km-z\]\{93\}/],
];

// ---- S0 over a hook command string ----
/** 1.2 S0 network tools, matched only at a command position (string start, or after ; & | ( ` or $( , optionally behind sudo/env). */
const CMD_POS = String.raw`(?:^|[;&|(\x60]|\$\()\s*(?:sudo\s+(?:-\S+\s+)*)?(?:env\s+(?:\w+=\S*\s+)*)?`;
// 1.4 S0: an absolute path in front of the tool counts (/usr/bin/curl, by its basename); a relative one does not (./node_modules/.bin/curl)
const ABS_PREFIX = String.raw`(?:(?:/[^\s/;&|()'"\x60]+)*/)?`;
const tool = (re) => new RegExp(`${CMD_POS}${ABS_PREFIX}(?:${re})(?:\\.exe)?(?=\\s|$|[;&|)])`, 'i');
export const NET_TOOLS = [['curl', tool('curl')], ['wget', tool('wget')], ['nc', tool('nc|ncat|netcat')], ['nslookup', tool('nslookup')],
  ['dig', tool('dig')], ['host', tool('host')], ['ping', tool('ping')]];
/** 1.2 S0: the DNS tools count only with command substitution (the DNS-exfiltration shape). */
export const DNS_TOOLS = Object.freeze(['nslookup', 'dig', 'host', 'ping']);
const ANY_URL = /https?:\/\/[^\s'"`]+/g;
/** 1.2 S0 "sends" markers: what makes a network tool in a hook carry data out. */
export const SEND_MARKERS = [
  ['command-substitution', /\$\(|`/],
  ['data-flag', /(?:^|\s)(?:--data(?:-[a-z]+)?|--form(?:-string)?|--upload-file|--post-data|--post-file)(?=[\s=]|$)|(?:^|\s)-[dFT](?=\s|[^\s-])/],
  ['raw-ip-url', RAW_IP_URL],
  ['exfil-host-url', { test: (s) => (s.match(ANY_URL) || []).some((u) => EXFIL_HOSTS.test(u)) }],
];
const sendsOf = (s) => SEND_MARKERS.filter(([, re]) => re.test(s)).map(([n]) => n);
/** 1.4 S0: the shells whose -c argument is read as a command (one level: the argument's own -c strings are not read again). */
export const SHELLS = Object.freeze(['sh', 'bash', 'dash', 'zsh']);
export const SHELL_C = new RegExp(`${CMD_POS}${ABS_PREFIX}(?:${SHELLS.join('|')})\\s+(?:-[a-zA-Z]+\\s+)*-[a-zA-Z]*c[a-zA-Z]*\\s+(?:'([^']*)'|"((?:[^"\\\\]|\\\\.)*)")`, 'g');
/** The quoted -c arguments of shells at a command position in one hook command (each read as a command string of its own). */
export function shellCArgs(s) { const out = []; if (typeof s !== 'string') return out; for (const m of s.matchAll(SHELL_C)) out.push(m[1] ?? m[2] ?? ''); return out; }
/** 1.9 S0: in a hook command that runs inline node code (node -e/--eval/-p/--print), the arguments of a console.* call are output, not
 *  a command: they are blanked before S0 reads the command, but only when they hold no call of their own
 *  (console.log(require('child_process').execSync(...)) still counts). Shell commands are unchanged (echo can be piped to sh). */
export const INLINE_NODE = /(?:^|[\s;&|(])node(?:\.exe)?\s+(?:--?[\w-]+(?:=\S+)?\s+)*?(?:-e|--eval|-p|--print)\b/;
export function blankConsoleOutput(s) {
  if (typeof s !== 'string' || !INLINE_NODE.test(s)) return s;
  let out = s;
  for (const m of s.matchAll(/\bconsole\s*\.\s*(?:log|error|warn|info|debug|trace)\s*\(/g)) {
    const start = m.index + m[0].length; let depth = 1; let q = null; let code = ''; let i = start;
    for (; i < s.length && depth > 0; i += 1) { const c = s[i];
      if (c === '\\') { i += 1; continue; }
      if (q) { if (c === q) q = null; continue; }
      if (c === "'" || c === '"' || c === '`') { q = c; continue; }
      if (c === '(') depth += 1; else if (c === ')') { depth -= 1; if (depth === 0) break; }
      code += c; }
    if (depth !== 0 || /[\w$)\]]\s*\(/.test(code)) continue;   // unbalanced, or a call inside the arguments: keep it
    out = out.slice(0, start) + ' '.repeat(i - start) + out.slice(i);
  }
  return out;
}
/** 1.9 S0 and S6: a node dns lookup/resolve call AND process or host data in one unit (an install hook command for S0, one hook target
 *  file for S6) is DNS exfiltration. A dns module bound to another name (const d = require('dns')) is not read. */
export const NODE_DNS_CALL = /\b(?:dns(?:\.promises)?|require\(\s*['"](?:node:)?dns(?:\/promises)?['"]\s*\)(?:\.promises)?)\s*\.\s*(?:lookup|lookupService|resolve(?:4|6|Any|Cname|Mx|Ns|Txt|Srv|Ptr|Soa|Naptr|Caa)?|reverse)\s*\(/;
export const DNS_DATA = /\bprocess\.(?:cwd\s*\(|env\b|argv\b)|\b(?:os|require\(\s*['"](?:node:)?os['"]\s*\))\s*\.\s*(?:hostname|userInfo|homedir|networkInterfaces)\s*\(|\b__dirname\b/;
export const dnsExfil = (s) => typeof s === 'string' && NODE_DNS_CALL.test(s) && DNS_DATA.test(s);
/** { fetch, exec, net_tools, sends, exfil, dns_exfil, fires } for one hook command; a non-string never throws and never fires. */
export function hookFetchExec(cmd) {
  const s = blankConsoleOutput(typeof cmd === 'string' ? cmd : '');   // 1.9: console output in inline node code is not a command
  const fetch = names(FETCH_MARKERS, s); const exec = names(EXEC_MARKERS, s);
  const net_tools = [...new Set([s, ...shellCArgs(s)].flatMap((x) => names(NET_TOOLS, x)))].sort((a, b) => NET_TOOLS.findIndex(([n]) => n === a) - NET_TOOLS.findIndex(([n]) => n === b)); const sends = sendsOf(s);   // 1.4: + the sh -c arguments
  // 1.2: hook-command exfiltration = a network tool at a command position AND a sends marker; the DNS tools only with command substitution
  const exfil = net_tools.some((t) => (DNS_TOOLS.includes(t) ? sends.includes('command-substitution') : sends.length > 0));
  const dns_exfil = dnsExfil(s);   // 1.9
  return { fetch, exec, net_tools, sends, exfil, dns_exfil, fires: (fetch.length > 0 && exec.length > 0) || exfil || dns_exfil };
}
/** The S0 detail for a fired hook: the 1.0 fetch-and-execute part, the bump's exfiltration part, or both (marker names only). */
const s0What = (r) => [r.fetch.length && r.exec.length ? `contains a fetch (${r.fetch.join(', ')}) and an execute (${r.exec.join(', ')})` : null,
  r.exfil ? `runs a network tool (${r.net_tools.join(', ')}) that sends (${r.sends.join(', ')})` : null,
  r.dns_exfil ? 'makes a DNS lookup carrying process or host data' : null].filter(Boolean).join(' and ');   // 1.9: the dns part

// ---- the keep list: what the registry manifest points npm at ----
const META = /[`$(){}<>*?![\]'"&#~\\]/;
const BUILTIN = new Set(['cd', 'echo', 'exit', 'true', 'false', 'test', ':', 'export', 'set']);
const NODEISH = new Set(['node', 'bun', 'deno']);
const INTERP = new Set(['node', 'bun', 'deno', 'sh', 'bash', 'zsh', 'python', 'python2', 'python3', 'tsx', 'ts-node', 'zx', 'perl', 'ruby', 'pwsh', 'powershell']);
const SUBCMD = { bun: new Set(['run', 'x']), deno: new Set(['run']) };
const PRELOAD = /^(?:-r|--require|--import|--loader|--experimental-loader)$/; const PRELOAD_EQ = /^(?:--require|--import|--loader|--experimental-loader)=(.+)$/;
const VALUE_FLAGS = new Set(['--stack-size', '--max-old-space-size', '--inspect-port', '--title', '-c', '--config', '--cwd']);
const MAX_SEGMENTS = 50;
/** Local code a hook command loads (the recon hook grammar's targets): [{ path, node }] and the reasons for what was not parsed. */
export function hookTargets(cmd) {
  const out = []; const dropped = [];
  const parts = String(cmd).split(/&&|\|\||;|\||&|\r?\n|\r/).map((s) => s.trim()).filter(Boolean);
  let cwd = '.'; let cwdUnknown = false;
  for (const s of parts.slice(0, MAX_SEGMENTS)) {
    if (META.test(s)) { dropped.push('unsupported hook syntax: quotes or shell syntax not parsed'); continue; }
    const tok = s.split(/\s+/); while (tok.length && /^[A-Za-z_][A-Za-z0-9_]*=/.test(tok[0])) tok.shift();
    const t0 = tok[0] ?? ''; const targets = [];
    if (t0 === 'cd') { const d = tok[1]; if (!d || d.startsWith('/') || d.startsWith('~')) cwdUnknown = true; else cwd = posix.join(cwd, d); continue; }
    if (BUILTIN.has(t0)) continue;
    if (INTERP.has(t0)) {
      const args = tok.slice(1); let script = null;
      for (let i = 0; i < args.length; i += 1) {
        const a = args[i];
        if (PRELOAD.test(a) && args[i + 1]) { targets.push(args[i + 1]); i += 1; continue; }
        const q = PRELOAD_EQ.exec(a); if (q) { targets.push(q[1]); continue; }
        if (a === '-m' && /^python/.test(t0)) { script = null; break; }
        if (/^-(e|p|-eval|-print|c)$/.test(a)) { script = null; break; }
        if (VALUE_FLAGS.has(a)) { i += 1; continue; } if (a.startsWith('-')) continue;
        if (SUBCMD[t0]?.has(a) && script === null) continue;
        script = a; break;
      }
      if (script) targets.unshift(script);
      for (const t of targets) out.push({ path: cwdUnknown ? null : posix.join(cwd, t), raw: t, node: NODEISH.has(t0), cwdUnknown });
      continue;
    }
    if (t0.includes('/')) out.push({ path: cwdUnknown ? null : posix.join(cwd, t0), raw: t0, node: false, cwdUnknown });
  }
  if (parts.length > MAX_SEGMENTS) dropped.push(`${parts.length - MAX_SEGMENTS} hook segment(s) beyond the grammar limit not parsed`);
  return { targets: out, dropped };
}
const norm = (p) => { const n = posix.normalize(String(p)).replace(/^\.\//, '').replace(/\/+$/, ''); return n === '.' ? '' : n; };
const outside = (n) => n === '' || n === '..' || n.startsWith('../') || n.startsWith('/') || n.includes('\0');
const variants = (n, node) => (node ? [n, `${n}.js`, `${n}.cjs`, `${n}.mjs`, `${n}/index.js`] : [n]);
/**
 * Candidate paths from a manifest (registry, or the tarball package.json): install-hook targets (node-resolution variants), then main
 * (default index.js), then up to 4 bin targets. { source, paths (priority order), roles: { path: [roles] }, hooks, dropped }. Bounded
 * (<= 3 hook targets x 5 variants + 5 main variants + 4 bin); never throws on a hostile manifest.
 */
export function keepListFor(man, source = 'registry manifest') {
  const roles = {}; const paths = []; const dropped = []; const hooks = []; const targets = [];
  const add = (p, role) => { if (!roles[p]) { roles[p] = []; paths.push(p); } if (!roles[p].includes(role)) roles[p].push(role); };
  const addTarget = (p, node, role) => { const vs = variants(p, node); for (const v of vs) add(v, role); targets.push({ path: p, variants: vs, role }); };
  const scripts = isObj(man) && isObj(man.scripts) ? man.scripts : {};
  let n = 0;
  for (const hook of INSTALL_HOOKS) {
    const cmd = scripts[hook]; if (typeof cmd !== 'string' || !pyTruthy(cmd)) continue;
    const g = hookTargets(cmd); const hookPaths = [];
    for (const r of g.dropped) dropped.push({ hook, reason: r });
    for (const t of g.targets) {
      if (t.cwdUnknown || t.path === null) { dropped.push({ hook, path: shownName(t.raw), reason: 'working directory unknown after an earlier segment' }); continue; }
      const p = norm(t.path); if (outside(p)) { dropped.push({ hook, path: shownName(t.raw), reason: 'target outside the package' }); continue; }
      if (n >= LIMITS.maxHookTargets) { dropped.push({ hook, path: shownName(p), reason: `hook targets beyond ${LIMITS.maxHookTargets}` }); continue; }
      n += 1; hookPaths.push(p); addTarget(p, t.node, 'hook');
    }
    hooks.push({ hook, cmd, targets: hookPaths });
  }
  const main = isObj(man) && typeof man.main === 'string' && !outside(norm(man.main)) ? norm(man.main) : 'index.js';
  addTarget(main, true, 'main');
  const bin = isObj(man) ? man.bin : undefined;
  const bins = typeof bin === 'string' ? [bin] : isObj(bin) ? Object.values(bin).filter((v) => typeof v === 'string') : [];
  let nb = 0;
  for (const b of bins) {
    const p = norm(b); if (outside(p)) { dropped.push({ path: shownName(b), reason: 'bin target outside the package' }); continue; }
    if (nb >= LIMITS.maxBin) { dropped.push({ path: shownName(p), reason: `bin targets beyond ${LIMITS.maxBin}` }); continue; }
    nb += 1; addTarget(p, false, 'bin');
  }
  return { source, version: STATIC_CHECKS_VERSION, paths, roles, hooks, targets, dropped };
}

// ---- per-file facts: counts and marker names only ----
/** Facts about one kept body { path, buf }. `binary` (a NUL in the first 8000 bytes) carries no text facts. Never throws. */
export function fileFacts(file) {
  const buf = Buffer.isBuffer(file?.buf) ? file.buf : Buffer.alloc(0);
  const base = { path: file?.path ?? '', size: buf.length };
  if (buf.subarray(0, LIMITS.headBytes).includes(0)) return { ...base, binary: true };
  const s = buf.toString('utf8');
  const idents = new Set(); for (const m of s.matchAll(OBF_IDENT)) idents.add(m[0]);
  let hex = 0; for (const m of s.matchAll(HEX_ESCAPE)) hex += m ? 1 : 0;
  const hexDensity = s.length ? (hex * 4) / s.length : 0;
  const decode = names(DECODE_MARKERS, s); if (CHARCODE_RUN.test(s)) decode.push('fromCharCode-run'); if (hexDensity > LIMITS.s2HexDensity) decode.push('hex-density');
  const numericHex = (s.match(NUMERIC_HEX) || []).length; if (numericHex >= LIMITS.s2MinNumericHex) decode.push('numeric-hex');
  const sinks = []; if (EXFIL_HOSTS.test(s)) sinks.push('exfil-host'); if (RAW_IP_URL.test(s)) sinks.push('raw-ip');
  const hosts = new Set(); for (const m of s.matchAll(URL_HOST)) hosts.add(m[1].toLowerCase());
  const foreign = [...hosts].filter((h) => !REGISTRY_HOSTS.includes(h) && !/^(?:\d{1,3}\.){3}\d{1,3}$/.test(h));
  if (foreign.length && POST_MARKER.test(s)) sinks.push('post-to-literal-host');
  return { ...base, binary: false, net_sinks: names(NET_SINKS, s), exec_sinks: names(EXEC_SINKS, s), obf_idents: idents.size, decode_markers: decode,
    hex_density: Number(hexDensity.toFixed(3)), numeric_hex: numericHex, cred_sources: names(CRED_SOURCES, s), sinks, overrides: names(OVERRIDES, s), address_families: names(ADDRESS_FAMILIES, s),
    host_identity: hostIdentityNames(s), dns_exfil: dnsExfil(s) };   // 1.4: host_identity (S6); 1.9: a use only inside a hash .update( does not count, and dns_exfil (S6)
}

// ---- 0.1.5 entry facts (operator ruling R4 2026-10-21): the main and bin facts of EVERY download, stored once per served version ----
const ENTRY_ROLES = Object.freeze(['main', 'bin']);
const entryTargets = (man) => keepListFor(man).targets.filter((t) => ENTRY_ROLES.includes(t.role));
/** The paths a download's walk keeps for the entry facts: the main target (node-resolution variants) and up to 4 bin targets. */
export function entryKeepFor(man) {
  return [...new Set(entryTargets(man).flatMap((t) => t.variants))];
}
/**
 * The entry facts of one finished walk, for witness.db: { walk: 'read' | 'refused', reason, files: [{ role, path, state, size_bytes,
 * sha256, facts, reason }] }. A target is 'read' (its kept body: size, sha256, the fileFacts summary without path or size), 'not-read'
 * (the walker's reason, the header size when known) or 'absent' (no variant in the archive). The manifest is the registry's when at
 * hand, else the tarball package.json. Never throws on a hostile manifest.
 */
export function entryFactsOf({ manifest, packageJson = null, walk }) {
  if (!walk || !walk.ok) return { walk: 'refused', reason: walk?.reason ?? 'the tarball was not walked', files: [] };
  const kept = new Map((Array.isArray(walk.files) ? walk.files : []).map((f) => [f.path, f]));
  const notKept = Array.isArray(walk.notKept) ? walk.notKept : [];
  const files = [];
  for (const t of entryTargets(manifest ?? packageJson)) {
    const hit = t.variants.map((v) => kept.get(v)).find(Boolean);
    if (hit) {
      const buf = Buffer.isBuffer(hit.buf) ? hit.buf : Buffer.alloc(0);
      const { path: _p, size: _s, ...facts } = fileFacts(hit);
      files.push({ role: t.role, path: hit.path, state: 'read', size_bytes: buf.length, sha256: createHash('sha256').update(buf).digest('hex'), facts, reason: null });
      continue;
    }
    const miss = notKept.find((x) => x && t.variants.includes(x.path) && !/^not in the archive/.test(String(x.reason)));
    if (!Array.isArray(walk.files)) files.push({ role: t.role, path: t.path, state: 'not-read', size_bytes: null, sha256: null, facts: null, reason: 'the walk kept no entry file' });
    else if (miss) files.push({ role: t.role, path: t.path, state: 'not-read', size_bytes: Number.isFinite(miss.size) ? miss.size : null, sha256: null, facts: null, reason: String(miss.reason) });
    else files.push({ role: t.role, path: t.path, state: 'absent', size_bytes: null, sha256: null, facts: null, reason: null });
  }
  return { walk: 'read', reason: null, files };
}

// ---- the rows ----
const hookDictOf = (man) => { const out = {}; const s = isObj(man) ? man.scripts : null; if (!isObj(s)) return out; for (const k of INSTALL_HOOKS) if (pyTruthy(s[k])) out[k] = s[k]; return out; };
const platSuffix = (plats) => (plats.length ? `; not checked for ${plats.join(', ')} (another entry installs there)` : '');
const plural = (n, w) => `${n} ${w}${n === 1 ? '' : 's'}`;
const ALLOW_TEXT = { S1: (n) => `hook targets carry no loader (${plural(n, 'file')} read)`, S2: (n) => `entry files carry no obfuscation marker pair (${plural(n, 'file')} read)`,
  S3: (n) => `files carry no credential source with a sink (${plural(n, 'file')} read)`, S4: (n) => `entry files carry no override with address regexes (${plural(n, 'file')} read)`,
  S6: (n) => `hook targets carry no network beacon (${plural(n, 'file')} read)` };
const NONE_TEXT = { S1: 'no hook target to read', S2: 'no entry file to read', S3: 'no file to read', S4: 'no entry file to read', S6: 'no hook target to read' };

// ---- S7 (R3), static-checks-1.4: recon's capability set and delta, copied; the summary built from the proxy's stored entry facts ----
/** The capability classes S7 compares (R3), as class:name over fileFacts; url-literal is never one. */
export const CAPABILITY_CLASSES = Object.freeze(['net', 'exec', 'decode', 'obf', 'cred']);
const S7_ROLES = ['main', 'bin'];
/** 1.5: the arms of S7's named condition (R9) and the class each one does not count (R9a, R9b). */
export const S7_NAMED_ARMS = Object.freeze(['decode-obf', 'net+exec']);
export const S7_DECODE_OBF_EXCLUDED = Object.freeze(['decode:Function']);   // R9a: the decode half of the Function pair a bundler adds
export const S7_EXEC_EXCLUDED = Object.freeze(['exec:Function']);           // R9b: not the execution sink of the net+exec arm
/** The gains of one role that meet the named condition (R9): { arms, named } (named sorted, unique). Pure; the caller checks the role is READ on both sides. */
export function s7Named(gains) {
  const g = Array.isArray(gains) ? gains.filter((x) => typeof x === 'string') : [];
  const dob = g.filter((x) => /^(?:decode|obf):/.test(x) && !S7_DECODE_OBF_EXCLUDED.includes(x));
  const net = g.filter((x) => x.startsWith('net:') && apiNames.has(x.slice(4))); const exec = g.filter((x) => x.startsWith('exec:') && !S7_EXEC_EXCLUDED.includes(x));
  const ne = net.length && exec.length ? [...net, ...exec] : [];
  return { arms: [...(dob.length ? ['decode-obf'] : []), ...(ne.length ? ['net+exec'] : [])], named: [...new Set([...dob, ...ne])].sort() };
}
/** The capabilities one text file's facts carry: net:<API sink>, exec:<sink>, decode:<marker>, obf:_0x-idents (>= the S2 identifier count), cred:<source>. */
export function capabilitiesOf(facts) {
  if (!facts || facts.binary) return [];
  return [...facts.net_sinks.filter((n) => apiNames.has(n)).map((n) => `net:${n}`), ...facts.exec_sinks.map((n) => `exec:${n}`), ...facts.decode_markers.map((n) => `decode:${n}`),
    ...(facts.obf_idents >= LIMITS.s2MinIdents ? ['obf:_0x-idents'] : []), ...facts.cred_sources.map((n) => `cred:${n}`)];
}
const clip = (x, n = 200) => { const t = String(x ?? '').replace(UNSAFE, ''); return t.length > n ? `${t.slice(0, n)}…` : t; };
/**
 * Recon's entryFactsSummary over the proxy's stored entry facts (entryFactsOf, or a witness.db predecessorEntryFacts record): per role
 * main/bin, READ (the files read and their capabilities, sorted, unique), NOT_CHECKED (a target not read, or binary) or ABSENT (no
 * candidate on the keep list: none declared; or none of its candidates in the archive: verified absent, only on an archive read in full,
 * review verdict 2026-10-21 condition 1). A refused archive has no summary. Pure.
 */
export function entrySummaryOf(entry, { archiveComplete = true } = {}) {
  const rows = Array.isArray(entry?.files) ? entry.files : [];
  const by_role = {};
  for (const role of S7_ROLES) {
    const caps = new Set(); const read = []; const nc = [];
    const mine = rows.filter((f) => f && f.role === role);
    for (const f of mine) {
      const p = shownName(f.path ?? '?');
      if (f.state === 'read' && f.facts && !f.facts.binary) { read.push(p); for (const c of capabilitiesOf(f.facts)) caps.add(c); continue; }
      if (f.state === 'read') { nc.push({ path: p, reason: `binary (a NUL in the first ${LIMITS.headBytes} bytes): not read as code` }); continue; }
      if (f.state === 'not-read') nc.push({ path: p, reason: clip(f.reason ?? 'not kept', 160) });
    }
    const candidate = mine.length > 0;
    if (candidate && !read.length && !nc.length && archiveComplete !== true) nc.push({ path: shownName(mine[0].path ?? '?'), reason: 'archive not read in full: absence not verified' });
    const absent = !read.length && !nc.length;
    by_role[role] = { status: nc.length ? 'NOT_CHECKED' : absent ? 'ABSENT' : 'READ', caps: [...caps].sort(), files: read, not_checked: nc,
      ...(absent ? { absent: candidate ? 'no candidate file in the tarball (verified absent)' : 'none declared (no candidate on the keep list)' } : {}) };
  }
  return { version: entry?.static_checks_version ?? STATIC_CHECKS_VERSION, archive_read_in_full: archiveComplete === true, by_role };
}
/**
 * S7 (R3), pure, recon's capabilityDelta: predecessor = { version, basis, summary }, or { version: null, basis } (cold start:
 * NOT_APPLICABLE), or { version, basis, status: 'NOT_CHECKED', reason } (checked first, so a NOT_CHECKED predecessor is never read as a
 * cold start); current = a summary, or { status: 'NOT_CHECKED', reason }. Per role: a gain is a capability the current role has and the
 * predecessor's same role lacked (a predecessor role ABSENT compares as empty). 1.5 (R9): a role's gains are named only when its
 * predecessor role was READ (predecessor_nonempty) and the current role is READ, by s7Named. Outcome: any named role INDICATOR, else any
 * role NOT_CHECKED NOT_CHECKED, else NONE; a gain not named stays on the row; coverage counts a verified-absent role as checked (condition 3).
 */
export function capabilityDelta({ predecessor, current } = {}) {
  const pred = predecessor && typeof predecessor === 'object' ? { version: predecessor.version ?? null, basis: predecessor.basis ?? null } : null;
  const empty = () => Object.fromEntries(S7_ROLES.map((r) => [r, { status: 'NOT_CHECKED', gains: [] }]));
  if (!pred) return { outcome: 'NOT_CHECKED', reason: 'no predecessor facts supplied', predecessor: null, by_role: empty() };
  if (predecessor.status === 'NOT_CHECKED') return { outcome: 'NOT_CHECKED', reason: `predecessor ${pred.version ?? '(not determined)'}: ${clip(predecessor.reason ?? 'not checked', 300)}`, predecessor: pred, by_role: empty() };
  if (pred.version === null) return { outcome: 'NOT_APPLICABLE', reason: clip(predecessor.reason ?? 'cold start: no predecessor', 200), predecessor: pred, by_role: empty() };
  if (!predecessor.summary?.by_role) return { outcome: 'NOT_CHECKED', reason: `predecessor ${pred.version}: no facts summary`, predecessor: pred, by_role: empty() };
  if (!current || current.status === 'NOT_CHECKED' || !current.by_role) return { outcome: 'NOT_CHECKED', reason: `current version: ${clip(current?.reason ?? 'no facts summary', 300)}`, predecessor: pred, by_role: empty() };
  const by_role = {}; let named = false; let nc = false;
  for (const role of S7_ROLES) {
    const p = predecessor.summary.by_role[role]; const c = current.by_role[role];
    if (!c || c.status === 'ABSENT') { by_role[role] = { status: 'ABSENT', gains: [], predecessor_nonempty: p?.status === 'READ', arms: [], named: [], note: `current ${role}: ${c?.absent ?? 'none'}`, ...(p?.status === 'ABSENT' ? { predecessor_note: `predecessor ${role}: ${p.absent}` } : {}) }; continue; }   // condition 2
    if (!p || p.status === 'NOT_CHECKED') { by_role[role] = { status: 'NOT_CHECKED', gains: [], predecessor_nonempty: false, arms: [], named: [], reason: 'the predecessor\'s same-role file was not read', not_checked: p?.not_checked ?? [] }; nc = true; continue; }
    const had = new Set(p.status === 'ABSENT' ? [] : p.caps); const gains = c.caps.filter((x) => !had.has(x));
    const nonempty = p.status === 'READ'; const s = nonempty && c.status === 'READ' ? s7Named(gains) : { arms: [], named: [] };   // 1.5 (R9)
    const notNamed = !nonempty ? `predecessor ${role} was not read and non-empty (${p.status === 'ABSENT' ? 'verified absent' : 'not read'}): a gain against it is a fact, not the named condition`
      : c.status !== 'READ' ? `current ${role} not read in full: no gain is named` : 'no decode or obf class other than decode:Function, and no API network sink with an execution sink other than exec:Function';
    by_role[role] = { status: c.status === 'READ' ? 'CHECKED' : 'NOT_CHECKED', gains, predecessor_nonempty: nonempty, arms: s.arms, named: s.named,
      ...(gains.length && !s.named.length ? { not_named: notNamed } : {}), ...(c.status !== 'READ' ? { not_checked: c.not_checked } : {}),
      ...(p.status === 'ABSENT' ? { predecessor_role: 'absent', predecessor_note: `predecessor ${role}: ${p.absent}` } : {}) };   // condition 2
    if (s.named.length) named = true; if (c.status !== 'READ') nc = true;
  }
  // condition 3: S7 counts a verified-absent role as checked, and says so beside the not-checked share
  const st = S7_ROLES.map((r) => by_role[r].status);
  const coverage = { roles: S7_ROLES.length, checked: st.filter((x) => x !== 'NOT_CHECKED').length, verified_absent: st.filter((x) => x === 'ABSENT').length, not_checked: st.filter((x) => x === 'NOT_CHECKED').length,
    note: 'S7 counts a verified-absent role as checked (an archive read in full holds no candidate file for it); the S1-S5 rows count nothing read as NOT_CHECKED' };
  return { outcome: named ? 'INDICATOR' : nc ? 'NOT_CHECKED' : 'NONE', predecessor: pred, by_role, coverage };
}
/** R3 runtime basis: the predecessor is the last version this proxy served (witness.db entry facts, R4). */
export const S7_BASIS = 'the version this proxy served before';
/** Since 0.1.6: stored entry facts S7 compares. 1.8.1 changes a fact field nothing decides on, and 1.9 changes S0 and S6 only (S7's
 *  capabilities read neither host_identity nor dns_exfil), so facts stored by 1.8 and 1.8.1 stay comparable. */
export const S7_COMPARABLE_VERSIONS = Object.freeze(['static-checks-1.8', 'static-checks-1.8.1', STATIC_CHECKS_VERSION]);
/** The predecessor argument of capabilityDelta from a witness.db predecessorEntryFacts record (null: cold start; 'unreadable': a storage error). */
function s7Predecessor(rec) {
  if (rec === 'unreadable') return { version: null, basis: S7_BASIS, status: 'NOT_CHECKED', reason: 'the stored entry facts of earlier versions could not be read' };
  if (!rec) return { version: null, basis: S7_BASIS, reason: 'no earlier version served by this proxy' };
  const version = shownName(rec.version);
  if (rec.walk !== 'read') return { version, basis: S7_BASIS, status: 'NOT_CHECKED', reason: `its archive was refused (${shownName(rec.reason ?? 'no reason stored')})` };
  if (typeof rec.static_checks_version === 'string' && !S7_COMPARABLE_VERSIONS.includes(rec.static_checks_version)) {
    return { version, basis: S7_BASIS, status: 'NOT_CHECKED', reason: `its facts were stored by ${shownName(rec.static_checks_version)}, not ${STATIC_CHECKS_VERSION}` };
  }
  return { version, basis: S7_BASIS, summary: entrySummaryOf(rec) };
}
/** The S7 row [result, detail] from capabilityDelta's result: the predecessor and its basis, the named gains with their arm (1.5), every
 *  other gain as a fact with why it was not named, the verified-absent notes (condition 2) and the coverage (condition 3). */
function s7Row(d) {
  if (d.outcome === 'NOT_APPLICABLE') return ['SKIP', `not applicable: ${d.reason}`];
  if (d.reason) return ['SKIP', `not checked: ${d.reason}`];
  const vs = `vs ${d.predecessor.version} (${d.predecessor.basis})`;
  const R = S7_ROLES.map((r) => [r, d.by_role[r]]);
  // condition 2: a role verified absent is said; the predecessor's note only when it differs from the current one (both none declared reads
  // once); an empty baseline with no gain is said here, one with gains is said in the gain's not-named reason
  const same = (x) => x.predecessor_note && x.predecessor_note.replace(/^predecessor /, '') === x.note.replace(/^current /, '');
  const notes = R.flatMap(([, x]) => (x.status === 'ABSENT' ? [x.note, same(x) ? null : x.predecessor_note] : !x.gains.length && x.predecessor_note ? [`against an empty baseline: ${x.predecessor_note}`] : []).filter(Boolean));
  // the row detail is capped (LIMITS.detailChars): the common not-named reason is said in short; capabilityDelta keeps recon's full text
  const why = (t) => (/^no decode or obf class other than/.test(t) ? 'no decode/obf gain other than decode:Function, no net+exec pair other than exec:Function' : t);
  const facts = R.filter(([, x]) => x.gains.length && !x.named.length).map(([r, x]) => `${r} gained ${x.gains.join(', ')} (not named: ${why(x.not_named)})`);
  const c = d.coverage; const cov = `roles checked ${c.checked} of ${c.roles} (${c.verified_absent} verified absent, counted as checked for S7), not checked ${c.not_checked}`;
  const tail = [...facts, ...notes, cov].join('; ');
  if (d.outcome === 'INDICATOR') {
    const g = R.filter(([, x]) => x.named.length).map(([r, x]) => `${r} gained ${x.gains.join(', ')} (${x.arms.join(', ')}: ${x.named.join(', ')})`).join('; ');
    return ['WARN', `${vs}: ${g}; ${tail}`];
  }
  if (d.outcome === 'NOT_CHECKED') {
    const why = R.filter(([, x]) => x.status === 'NOT_CHECKED').map(([r, x]) => {
      const side = x.reason ? 'predecessor' : 'current'; const n = (x.not_checked ?? [])[0];
      return n ? `${side} ${r} ${n.path} was not read (${n.reason})` : `${side} ${r} was not read`;
    });
    return ['SKIP', `not checked: ${why.join('; ')}; ${vs}; ${tail}`];
  }
  return ['ALLOW', `${facts.length ? 'no gain named' : 'no capability gained'} ${vs}; ${tail}`];
}
/** S7's outcome [result, detail] for a finished walk against the stored predecessor (witness.db predecessorEntryFacts, or null). */
function s7Outcome({ manifest, packageJson, walk, predecessor }) {
  const current = entrySummaryOf(entryFactsOf({ manifest: manifest ?? packageJson, walk }), { archiveComplete: Boolean(walk?.ok) });
  return s7Row(capabilityDelta({ predecessor: s7Predecessor(predecessor), current }));
}
const list = (xs) => xs.join(', ');
/** S8's or S9's outcome [result, detail] over the walk's member facts (recon's addonDropper and hiddenGypScript); paths and counts only. */
function memberRowOutcome(id, { hooks, files, members, membersOver }) {
  if (membersOver) return ['SKIP', `not checked: more than ${MAX_FACTS_MEMBERS} archive members: member facts not kept`];
  if (id === 'S8') {
    const { row: r, fires } = addonDropper({ hooks, files, members });
    if (r.outcome === 'NOT_CHECKED') return ['SKIP', `not checked: ${r.reason}`];
    if (r.reason === 'no install hook') return ['ALLOW', 'no install hook'];
    const mods = `${list(r.addons.slice(0, 3).map(shownName))}${r.addons_total > 3 ? ` and ${r.addons_total - 3} more` : ''}`;
    if (fires) {
      const x = r.xor_text[0];
      return ['WARN', `an install hook loads a shipped native module (${mods}; ${list(r.loads)}) and the tarball has no native source; ${shownName(x.path)} (${x.size} B) is text under a one-byte XOR${r.xor_text_total > 1 ? `; and ${r.xor_text_total - 1} more` : ''}`];
    }
    if (r.addon_without_source) return ['ALLOW', `an install hook loads a shipped native module with no native source (${mods}), and no member is text under a one-byte XOR`];
    return ['ALLOW', `no install hook loads a prebuilt native module shipped without its source (${plural(r.addons_total, 'native module')}, ${plural(r.native_source, 'native source file')})`];
  }
  const { row: r, fires } = hiddenGypScript({ members });
  if (r.outcome === 'NOT_CHECKED') return ['SKIP', `not checked: ${r.reason}`];
  if (fires) {
    const q = r.quiet_script[0];
    return ['WARN', `${shownName(q.path)} runs a package script in ${plural(q.count, 'command expansion')} with its output discarded${r.quiet_script_total > 1 ? `; and ${r.quiet_script_total - 1} more gyp file(s)` : ''}`];
  }
  return ['ALLOW', r.gyp_files ? `${plural(r.gyp_files, 'gyp file')}, ${plural(r.expansions, 'command expansion')}; none runs a package script with its output discarded` : 'no gyp file'];
}

/**
 * The ten rows (S0-S9) for a finished walk. `manifest`: the registry version manifest (what npm acts on; the keep list's source);
 * `packageJson`: the tarball's root package.json, parsed (Linux view), or null; `walk`: the walker result (step 1: `files`, `notKept`).
 * `predecessor`: S7's stored predecessor (witness.db predecessorEntryFacts), null on a cold start. Every row is { gate, result, detail }; the detail never carries publisher text beyond a sanitised path and fixed hook names.
 * `members`: the walk's member facts (createMemberTally's result), which S8 and S9 read; `membersOver`: more than MAX_FACTS_MEMBERS.
 */
export function staticRows({ manifest, packageJson = null, walk, armed = null, predecessor = null, members = undefined, membersOver = false }) {
  const suffix = typeof armed === 'string' && armed ? `; armed by ${armed}` : '';
  const row = (c, result, detail) => ({ gate: c.gate, result, detail: clipDetail(`${detail}${suffix}`) });
  if (!walk || !walk.ok) return CHECKS.map((c) => row(c, 'SKIP', `not checked: ${walk?.reason ?? 'the tarball was not walked'}`));
  if (!Array.isArray(walk.files)) return CHECKS.map((c) => row(c, 'SKIP', 'not checked: the tarball was not examined (keep list not armed)'));
  const klReg = keepListFor(manifest); const klTar = keepListFor(packageJson, 'tarball package.json');
  const roles = { ...klTar.roles };
  for (const [p, r] of Object.entries(klReg.roles)) roles[p] = [...new Set([...(roles[p] ?? []), ...r])];
  const primaryOf = {}; for (const t of [...klReg.targets, ...klTar.targets]) for (const v of t.variants) primaryOf[v] ??= t.path;
  const keptPaths = new Set(walk.files.map((f) => f.path));
  const keptPrimary = new Set([...keptPaths].map((p) => primaryOf[p] ?? p));
  const rows = [];
  // S0: the hook commands -- the registry manifest's, and those only the tarball package.json declares (MC says they differ)
  const reg = hookDictOf(manifest); const tar = hookDictOf(packageJson);
  const hooks = Object.entries(reg).map(([hook, cmd]) => ({ src: '', hook, cmd }));
  for (const [hook, cmd] of Object.entries(tar)) if (reg[hook] !== cmd) hooks.push({ src: 'tarball package.json ', hook, cmd });
  const fired = hooks.map((h) => ({ ...h, r: hookFetchExec(h.cmd) })).filter((h) => h.r.fires);
  if (fired.length) rows.push(row(CHECKS[0], 'WARN', `${fired[0].src}${fired[0].hook} command ${s0What(fired[0].r)}${fired.length > 1 ? `; and ${fired.length - 1} more hook(s)` : ''}`));
  else rows.push(row(CHECKS[0], 'ALLOW', hooks.length ? 'install hooks carry no fetch-and-execute' : 'no install hook'));
  // S1-S4: the kept bodies by role
  const facts = walk.files.map((f) => ({ f, facts: fileFacts(f), roles: roles[f.path] ?? [], shown: shownName(f.path), plats: Array.isArray(f.platformsNotChecked) ? f.platformsNotChecked : [] }));
  // what the walker did not keep, ONE statement per target (its node-resolution variants are the same target; a kept variant settles it);
  // a target only the tarball package.json names was never on the keep list: stated as such, never guessed
  const notKept = []; const stated = new Set();
  for (const x of Array.isArray(walk.notKept) ? walk.notKept : []) {
    if (!x || typeof x.path !== 'string' || !roles[x.path]) continue;
    const prim = primaryOf[x.path] ?? x.path;
    if (keptPrimary.has(prim) || stated.has(prim)) continue;
    if (/^not in the archive/.test(String(x.reason)) && x.path !== prim) continue;        // an absent variant is not news; the primary says it
    stated.add(prim); notKept.push(Number.isFinite(x.size) ? { path: prim, reason: x.reason, size: x.size } : { path: prim, reason: x.reason });
  }
  for (const t of klTar.targets) if (!klReg.roles[t.path] && !keptPrimary.has(t.path) && !stated.has(t.path)) { stated.add(t.path); notKept.push({ path: t.path, reason: 'named by the tarball package.json only (not kept)' }); }
  // nothing read (ruled 2026-10-14, per row): the reasons that mean no eligible file was there to read, as against a cap or a limit
  const absentOnly = (rs) => rs.length > 0 && rs.every((x) => /^not in the archive/.test(String(x.reason)));
  const candidateOf = (c) => klReg.paths.find((p) => klReg.roles[p].some((r) => c.roles.includes(r)) && primaryOf[p] === p);
  for (const c of CHECKS.slice(1)) {
    if (c.id === 'S8' || c.id === 'S9') {
      const [r, d] = memberRowOutcome(c.id, { hooks, files: walk.files.map((f) => ({ roles: roles[f.path] ?? [], data: f.buf })), members, membersOver });
      rows.push(row(c, r, d)); continue;
    }
    const mine = facts.filter((x) => c.roles.some((r) => x.roles.includes(r)));
    const unread = notKept.filter((x) => c.roles.some((r) => (roles[x.path] ?? []).includes(r)));
    const skipped = unread.map((x) => `${shownName(x.path)} ${x.reason}`);
    const hits = []; const platsRead = new Set(); let read = 0;
    if (c.id === 'S7') { const [r, d] = s7Outcome({ manifest, packageJson, walk, predecessor }); rows.push(row(c, r, d)); continue; }
    if (c.id === 'S5') {
      // S5 (1.2): one fact, a hook target's size: a kept body by its length (binary or not), a target not kept by its tar-header size;
      // over the 1 MiB kept-file cap fires; a target with no size (absent, or named only by the tarball package.json) is not checked
      const sized = [...mine.map((x) => ({ path: x.f.path, size: x.facts.size, plats: x.plats })), ...unread.filter((x) => Number.isFinite(x.size)).map((x) => ({ ...x, plats: [] }))];
      const noSize = unread.filter((x) => !Number.isFinite(x.size));
      for (const x of sized) { read += 1; for (const p of x.plats) platsRead.add(p); if (x.size > LIMITS.maxKeepBytes) hits.push({ detail: `hook target ${shownName(x.path)} (${x.size} B) is over the 1 MiB keep cap, body not read`, plats: x.plats }); }
      const cand = read || hits.length || (noSize.length && !absentOnly(noSize)) ? null : candidateOf(c);
      const sk = noSize.map((x) => `${shownName(x.path)} ${x.reason}`);
      if (hits.length) rows.push(row(c, 'WARN', `${hits[0].detail}${hits.length > 1 ? `; and ${hits.length - 1} more file(s)` : ''}${platSuffix(hits[0].plats)}`));
      else if (cand) rows.push(row(c, 'SKIP', `not checked: ${NOTHING_READ} (${sk.length ? `${sk[0]}${sk.length > 1 ? `; and ${sk.length - 1} more` : ''}` : shownName(cand)})`));
      else if (sk.length && !read) rows.push(row(c, 'SKIP', `not checked: ${sk[0]}${sk.length > 1 ? `; and ${sk.length - 1} more` : ''}`));
      else rows.push(row(c, 'ALLOW', `${read ? `hook targets are within the 1 MiB keep cap (${plural(read, 'file')} sized)` : 'no hook target'}${platSuffix([...platsRead])}`));
      continue;
    }
    for (const x of mine) {
      const F = x.facts;
      if (F.binary) { skipped.push(`${x.shown} is binary (a NUL in the first ${LIMITS.headBytes} bytes)`); continue; }
      if (c.id === 'S1' && F.size > LIMITS.s1MaxBytes) { skipped.push(`${x.shown} over 8 KiB (a loader stub is small)`); continue; }
      read += 1; for (const p of x.plats) platsRead.add(p);
      let detail = null;
      if (c.id === 'S1' && F.net_sinks.length && F.exec_sinks.length) detail = `hook target ${x.shown} (${F.size} B) has a network sink (${list(F.net_sinks)}) and an execution sink (${list(F.exec_sinks)})`;
      else if (c.id === 'S2' && F.obf_idents >= LIMITS.s2MinIdents && F.decode_markers.length) detail = `entry file ${x.shown} (${F.size} B) has ${F.obf_idents} _0x identifiers and a decode marker (${list(F.decode_markers)})`;
      else if (c.id === 'S3' && F.cred_sources.length && F.sinks.includes('exfil-host')) detail = `${x.shown} (${F.size} B) has a credential source (${list(F.cred_sources)}) and an outbound sink (${list(F.sinks)})`;
      else if (c.id === 'S4' && F.overrides.length && F.address_families.length >= LIMITS.s4MinAddressFamilies) detail = `entry file ${x.shown} (${F.size} B) has an override (${list(F.overrides)}) and ${F.address_families.length} address-regex families (${list(F.address_families)})`;
      else if (c.id === 'S6') {   // 1.9: or a dns call carrying process or host data (no execution-sink condition, as measured)
        const beacon = apiNet(F).length && F.host_identity.length && !F.exec_sinks.length;
        detail = [beacon ? `hook target ${x.shown} (${F.size} B) has a network API sink (${list(apiNet(F))}) and a host-identity source (${list(F.host_identity)}) and no execution sink` : null,
          F.dns_exfil ? `${beacon ? 'and it' : `hook target ${x.shown} (${F.size} B)`} makes a DNS lookup carrying process or host data` : null].filter(Boolean).join('; ') || null;
      }
      if (detail) hits.push({ detail, plats: x.plats });
    }
    const cand = read || hits.length || (skipped.length && !(skipped.length === unread.length && absentOnly(unread))) ? null : candidateOf(c);
    if (hits.length) rows.push(row(c, 'WARN', `${hits[0].detail}${hits.length > 1 ? `; and ${hits.length - 1} more file(s)` : ''}${platSuffix(hits[0].plats)}`));
    else if (cand) rows.push(row(c, 'SKIP', `not checked: ${NOTHING_READ} (${skipped.length ? `${skipped[0]}${skipped.length > 1 ? `; and ${skipped.length - 1} more` : ''}` : shownName(cand)})`));
    else if (skipped.length) rows.push(row(c, 'SKIP', `not checked: ${skipped[0]}${skipped.length > 1 ? `; and ${skipped.length - 1} more` : ''}`));
    else rows.push(row(c, 'ALLOW', `${read ? ALLOW_TEXT[c.id](read) : NONE_TEXT[c.id]}${platSuffix([...platsRead])}`));
  }
  return rows;
}

// ------------------------------------------------------------------ v6.17 static-checks-1.8: S8 (the native-addon dropper)
/** S8 bounds: the XOR read covers a member's first xorWindow bytes; a body under xorMinBytes is not read; the two printable shares. */
export const S8_LIMITS = Object.freeze({ xorWindow: 1 << 20, xorMinBytes: 64, xorMaxPrintableBefore: 0.5, xorMinPrintableAfter: 0.95, listed: 20 });
/** The heads of a native module (hex prefix): ELF, PE (MZ), Mach-O (both byte orders, 32 and 64 bit) and a fat Mach-O. */
export const NATIVE_MAGIC = Object.freeze([['elf', '7f454c46'], ['pe', '4d5a'], ['macho', 'cffaedfe'], ['macho', 'cefaedfe'], ['macho', 'feedfacf'], ['macho', 'feedface'], ['macho', 'cafebabe']].map((x) => Object.freeze(x)));
const NATIVE_BUF = NATIVE_MAGIC.map(([n, h]) => [n, Buffer.from(h, 'hex')]);
/** A native source file (what a module could be built from in the tarball). */
export const NATIVE_SOURCE = /\.(?:c|cc|cpp|cxx|c\+\+|h|hh|hpp|hxx|m|mm|rs|zig|go|s|asm)$/i;
export const BINDING_GYP = /(?:^|\/)binding\.gyp$/;
const GYP_SOURCES = /["']sources["']\s*:\s*\[\s*["']/;   // a non-empty sources list (gyp is a Python literal: either quote)
export const ADDON_FILE = /\.node$/i;
/** How an install hook loads a module (name, where it is read, regex): the hook command, or a kept hook target's text. */
export const ADDON_LOADS = Object.freeze([
  ['hook-names-node-file', 'command', /[\w-]\.node(?![\w-])/],
  ['hook-runs-node-gyp-build', 'command', /(?:^|[\s;&|(])node-gyp-build(?:-optional-packages)?(?=$|[\s;&|)])/],
  ['target-requires-node-file', 'hook-target', /\brequire\s*\([^)]*\.node['"`]|\bprocess\.dlopen\s*\(/],
  ['target-requires-node-gyp-build', 'hook-target', /\brequire\s*\(\s*['"`]node-gyp-build(?:-optional-packages)?['"`]\s*\)/],
].map((x) => Object.freeze(x)));
/** The native kind of a body's head, or null. */
export function nativeKind(buf) {
  if (!Buffer.isBuffer(buf)) return null;
  for (const [n, m] of NATIVE_BUF) if (buf.length >= m.length && buf.subarray(0, m.length).equals(m)) return n;
  return null;
}
const PRINTABLE = new Uint8Array(256); for (let b = 0x20; b < 0x7f; b += 1) PRINTABLE[b] = 1; PRINTABLE[9] = 1; PRINTABLE[10] = 1; PRINTABLE[13] = 1;
/** Text under a one-byte XOR, over the first xorWindow bytes (pure, bounded): null for a short body, a body with a NUL in its first 8000
 *  bytes, UTF-8 text, or a body at least half printable; else { printable_before, printable_after } when one key 1-255 makes it at least
 *  xorMinPrintableAfter printable, else null. Shares only: never the key, never a decoded byte. */
export function xorText(buf, { truncated = false } = {}) {
  const L = S8_LIMITS; if (!Buffer.isBuffer(buf)) return null;
  const b = buf.subarray(0, L.xorWindow); const n = b.length; if (n < L.xorMinBytes || b.subarray(0, STATIC_LIMITS.headBytes).includes(0)) return null;
  try { new TextDecoder('utf-8', { fatal: true }).decode(b, { stream: truncated || buf.length > n }); return null; } catch { /* not UTF-8: read on */ }
  const h = new Float64Array(256); for (let i = 0; i < n; i += 1) h[b[i]] += 1;
  let p0 = 0; for (let x = 0; x < 256; x += 1) if (PRINTABLE[x]) p0 += h[x];
  if (p0 / n >= L.xorMaxPrintableBefore) return null;
  let best = 0; for (let k = 1; k < 256; k += 1) { let p = 0; for (let x = 0; x < 256; x += 1) if (PRINTABLE[x ^ k]) p += h[x]; if (p > best) best = p; }
  return best / n >= L.xorMinPrintableAfter ? { printable_before: Number((p0 / n).toFixed(3)), printable_after: Number((best / n).toFixed(3)) } : null;
}
/** S9 bounds: at most maxExpansions command expansions read per gyp file, each at most expansionChars long. */
export const GYP_LIMITS = Object.freeze({ maxExpansions: 200, expansionChars: 2000 });
export const GYP_FILE = /(?:^|\/)(?:binding\.gyp|[^/]+\.gypi)$/;
/** S9: a command that discards its standard output (a 2> redirect alone is not one), and an interpreter given a package script file. */
export const GYP_QUIET = /(?<![2&\w])>{1,2}\s*(?:\/dev\/null|nul)\b|(?<!\w)1>{1,2}\s*(?:\/dev\/null|nul)\b|&>{1,2}\s*\/dev\/null/i;
export const GYP_SCRIPT = /(?:^|[\s;&|(])(?:env\s+)?(?:node|bun|deno|sh|bash|python3?|perl|ruby)\s+(?:-\S+\s+)*[\w@./-]+\.(?:c?js|mjs|ts|sh|py|pl|rb)(?![\w.])/;
/** The command expansions of a gyp text, in order (<!( and <!@(; balanced parentheses; bounded by GYP_LIMITS). Pure. */
export function gypExpansions(text) {
  const s = typeof text === 'string' ? text : ''; const out = []; let i = 0;
  while (out.length < GYP_LIMITS.maxExpansions && (i = s.indexOf('<!', i)) >= 0) {
    let j = i + 2; if (s[j] === '@') j += 1; if (s[j] !== '(') { i = j; continue; }
    let d = 0; let k = j; const end = Math.min(s.length, j + GYP_LIMITS.expansionChars);
    for (; k < end; k += 1) { if (s[k] === '(') d += 1; else if (s[k] === ')') { d -= 1; if (d === 0) break; } }
    out.push(s.slice(j + 1, k)); i = k + 1;
  }
  return out;
}
/** S9 fact of one gyp text: { expansions, quiet_script } (counts only; never the command). */
export function gypBuild(text) { const e = gypExpansions(text); return { expansions: e.length, quiet_script: e.filter((x) => GYP_QUIET.test(x) && GYP_SCRIPT.test(x)).length }; }
/** The six S8/S9 facts of one member (memberFacts carries them), each read from the full path. */
function s8MemberFacts(p, buf, truncated) {
  return { native: nativeKind(buf), node_file: ADDON_FILE.test(p), native_source: NATIVE_SOURCE.test(p), gyp_sources: BINDING_GYP.test(p) ? GYP_SOURCES.test(buf.toString('utf8')) : null, xor_text: xorText(buf, { truncated }),
    gyp_build: GYP_FILE.test(p) ? gypBuild(buf.toString('utf8')) : null };
}
/** S9, pure: members = memberFacts records. INDICATOR when a gyp file runs a package script with its output discarded; NONE otherwise;
 *  NOT_CHECKED without member facts. */
export function hiddenGypScript({ members = undefined } = {}) {
  if (!Array.isArray(members)) return { row: { outcome: 'NOT_CHECKED', reason: 'no member facts supplied' }, fires: false };
  const gs = members.filter((m) => m && typeof m === 'object' && m.gyp_build && typeof m.gyp_build === 'object');
  const quiet = gs.filter((m) => m.gyp_build.quiet_script > 0).map((m) => ({ path: String(m.path), count: m.gyp_build.quiet_script }));
  return { fires: quiet.length > 0, row: { outcome: quiet.length ? 'INDICATOR' : 'NONE', ...(gs.length ? {} : { reason: 'no gyp file' }), gyp_files: gs.length,
    expansions: gs.reduce((a, m) => a + (m.gyp_build.expansions || 0), 0), quiet_script: quiet.slice(0, S8_LIMITS.listed), quiet_script_total: quiet.length } };
}
/**
 * S8, pure: hooks as staticChecks (only the install hooks count), files = the kept bodies (their hook-role texts are read for a load),
 * members = memberFacts records (the 1.8 facts). Returns { row, fires }: the row states the loads, the shipped native modules, the native
 * source count, A (addon_without_source) and the XOR-text members; INDICATOR needs all three facts, NONE otherwise; NOT_CHECKED with
 * a hook and no member facts.
 */
export function addonDropper({ hooks = [], files = [], members = undefined } = {}) {
  const L = S8_LIMITS; const hs = (Array.isArray(hooks) ? hooks : []).filter((h) => h && INSTALL_HOOKS.includes(h.hook) && typeof h.cmd === 'string' && h.cmd);
  if (!hs.length) return { row: { outcome: 'NONE', reason: 'no install hook' }, fires: false };
  if (!Array.isArray(members)) return { row: { outcome: 'NOT_CHECKED', reason: 'no member facts supplied' }, fires: false };
  const ms = members.filter((m) => m && typeof m === 'object'); const loads = new Set();
  for (const [n, where, re] of ADDON_LOADS) {
    if (where === 'command' && hs.some((h) => re.test(h.cmd))) loads.add(n);
    if (where === 'hook-target' && (Array.isArray(files) ? files : []).some((f) => Array.isArray(f?.roles) && f.roles.includes('hook') && Buffer.isBuffer(f.data) && !f.data.subarray(0, STATIC_LIMITS.headBytes).includes(0) && re.test(f.data.toString('utf8')))) loads.add(n);
  }
  const addons = ms.filter((m) => m.node_file === true && m.native).map((m) => String(m.path));   // the full path is read in memberFacts (a row path is clipped)
  const source = ms.filter((m) => m.native_source === true || m.gyp_sources === true).length; const gyp = ms.filter((m) => typeof m.gyp_sources === 'boolean').length;
  const xor = ms.filter((m) => m.xor_text && m.node_file !== true).map((m) => ({ path: String(m.path), size: m.size, ...m.xor_text }));
  const a = loads.size > 0 && addons.length > 0 && source === 0; const fires = a && xor.length > 0;
  return { fires, row: { outcome: fires ? 'INDICATOR' : 'NONE', loads: ADDON_LOADS.map(([n]) => n).filter((n) => loads.has(n)), addons: addons.slice(0, L.listed), addons_total: addons.length,
    native_source: source, binding_gyp: gyp, addon_without_source: a, xor_text: xor.slice(0, L.listed), xor_text_total: xor.length } };
}

// ---- static-checks-1.6: shadow facts (operator ruling R11), recon v6.14's code as written (paths through factsClip, the head through LIMITS)
/** Facts only (R11): read from every member of the flagged archive (its first windowBytes, the pattern scan's window) and, for rule 7,
 *  from the whole body of a hook target. diversityRef is the consult's 16-character reference, counted, never a gate. */
export const FACTS_LIMITS = Object.freeze({ windowBytes: 2 << 20, b64MinRun: 400, hexEscapeMinRun: 60, magicBytes: 16, diversityRef: 16, listed: 20, distinctCharsBytes: 65536 });   // 1.8.1: distinctCharsBytes
export const FACTS_NOTE = 'shadow facts (operator ruling R11, 2026-10-24): no outcome, tier or notice depends on them; a fact is read against the file, never a verdict';
/** Rules 6 and 7: the magic numbers read at the start of decoded bytes (name, hex prefix). Anything else is null, never a guess. */
export const DECODED_MAGIC = Object.freeze([['wasm', '0061736d'], ['png', '89504e470d0a1a0a'], ['gzip', '1f8b'], ['woff', '774f4646'], ['woff2', '774f4632']].map((x) => Object.freeze(x)));
const MAGIC_BUF = DECODED_MAGIC.map(([n, h]) => [n, Buffer.from(h, 'hex')]);
export function magicOf(buf) {
  if (!Buffer.isBuffer(buf)) return null;
  for (const [n, m] of MAGIC_BUF) if (buf.length >= m.length && buf.subarray(0, m.length).equals(m)) return n;
  return null;
}
/** Rule 6: a base64 run (recon pattern P7) and a hex-escape run (P8's first alternative); a base64 run made only of lowercase hex digits
 *  is a hex run (P8's second alternative). Used with matchAll only. */
export const B64_RUN = /[A-Za-z0-9+/]{400,}={0,2}/g;
export const HEX_ESCAPE_RUN = /(?:\\x[0-9a-fA-F]{2}){60,}/g;
const B64_MAGIC_CHARS = Math.ceil(FACTS_LIMITS.magicBytes / 3) * 4;   // 24 base64 characters decode to the first 18 bytes
/** Rule 6, pure: every encoded run in a text, in text order: { kind: base64 | hex | hex-escape, chars (base64 padding included; a
 *  hex-escape run's hex digits), distinct_chars (padding and the \x framing excluded; 1.8.1: over at most the run's first distinctCharsBytes,
 *  64 KiB: base64 and hex alphabets saturate within a few hundred bytes), magic (of the decoded first bytes, or null) }. */
export function encodedRuns(text) {
  const s = typeof text === 'string' ? text : ''; const out = []; const M = FACTS_LIMITS.magicBytes;
  for (const m of s.matchAll(B64_RUN)) {
    const body = m[0].replace(/=+$/, ''); const hex = /^[0-9a-f]+$/.test(body);
    const head = hex ? Buffer.from(body.slice(0, M * 2), 'hex') : Buffer.from(body.slice(0, B64_MAGIC_CHARS), 'base64');
    out.push({ at: m.index, kind: hex ? 'hex' : 'base64', chars: m[0].length, distinct_chars: new Set(body.slice(0, FACTS_LIMITS.distinctCharsBytes)).size, magic: magicOf(head) });   // 1.8.1: first 64 KiB
  }
  for (const m of s.matchAll(HEX_ESCAPE_RUN)) {
    const digits = m[0].replace(/\\x/g, '');
    out.push({ at: m.index, kind: 'hex-escape', chars: digits.length, distinct_chars: new Set(digits.slice(0, FACTS_LIMITS.distinctCharsBytes)).size, magic: magicOf(Buffer.from(digits.slice(0, M * 2), 'hex')) });   // 1.8.1
  }
  return out.sort((a, b) => a.at - b.at).map(({ at, ...x }) => x);   // eslint-disable-line no-unused-vars
}
const B64_ALPHA = new Uint8Array(256); for (const c of 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/') B64_ALPHA[c.charCodeAt(0)] = 1;
/** Rule 7: a streaming counter over a whole body (an S5 target is over the keep cap, so its body is never kept): bytes in base64 runs
 *  of at least b64MinRun characters (P7's alphabet and up to two '=' after a run, so a hex run counts too) over all bytes, and the
 *  magic of the FIRST such run's decoded first bytes. Chunk boundaries never change the result. */
export function makeBase64Share() {
  const MIN = FACTS_LIMITS.b64MinRun; let bytes = 0; let b64 = 0; let run = 0; let eq = 0; let head = ''; let decided = false; let magic = null;
  const close = () => { if (run >= MIN) b64 += run + eq; run = 0; eq = 0; head = ''; };
  return {
    push(chunk) {
      const b = Buffer.isBuffer(chunk) ? chunk : Buffer.alloc(0); bytes += b.length;
      for (let i = 0; i < b.length; i += 1) {
        const c = b[i];
        if (B64_ALPHA[c]) {
          if (eq) close();
          run += 1; if (head.length < B64_MAGIC_CHARS) head += String.fromCharCode(c);
          if (run === MIN && !decided) { decided = true; magic = magicOf(Buffer.from(head, 'base64')); }
        } else if (c === 0x3d && run > 0 && eq < 2) eq += 1;
        else close();
      }
    },
    end() { close(); return { bytes, base64_bytes: b64, share: bytes ? Number((b64 / bytes).toFixed(3)) : 0, magic }; },
  };
}
/** 8a: the paths whose P2/P9-type hit lines are counted apart (the consult's five; at the start or after any separator). */
export const EXCLUDED_PATH = /(?:^|\/)(?:test|__tests__|fixtures|vendor|node_modules)\//;
/** 8a: P2-type = recon pattern P2 (dynamic code), P9-type = recon pattern P9 (RAW_IP_URL above, the same source). */
export const DYNAMIC_CODE = /\beval\s*\(|(?:^|[^\w$.])(?:new\s+)?Function\s*\(|\bvm\.runIn(?:New|This)?Context\s*\(|\bvm\.Script\s*\(/;
/** 8d: the agent names whose config dirs are read: ~/.<name>, and ~/.config/<name> (also as path.join parts). */
export const AGENT_CONFIG_NAMES = Object.freeze(['claude', 'cursor', 'codex', 'gemini', 'opencode', 'windsurf', 'github-copilot']);
const AGN = AGENT_CONFIG_NAMES.join('|');
export const AGENT_HOME_DIR = new RegExp(`(?:^|[\\\\/'"\`])\\.(${AGN})(?=[\\\\/'"\`]|$)`, 'gm');
export const AGENT_XDG_DIR = new RegExp(`\\.config(?:[\\\\/]|['"\`]\\s*,\\s*['"\`])(${AGN})(?=[\\\\/'"\`]|$)`, 'gm');
/** 8d: what writes. Every marker is read in every text member and hook command, except the shell redirect, read only in hook commands
 *  and shell scripts (in code a '>' is a comparison). */
export const WRITE_MARKERS = [
  ['fs-write', /\b(?:writeFileSync|writeFile|appendFileSync|appendFile|createWriteStream|copyFileSync|copyFile|cpSync|renameSync|symlinkSync|outputFileSync|outputFile|outputJsonSync|outputJson|writeJsonSync|writeJson)\s*\(/],
  ['fs-mkdir', /\b(?:mkdirSync|mkdir|mkdirp|ensureDirSync|ensureDir)\s*\(/],
  ['shell-copy', /(?:^|[\s;&|("'`])(?:cp|mv|ln|rsync)\s/m], ['shell-mkdir', /(?:^|[\s;&|("'`])mkdir\s/m], ['shell-tee', /(?:^|[\s;&|("'`])tee\s/m],
  ['ps-write', /\b(?:Copy-Item|New-Item|Set-Content|Add-Content|Out-File)\b/i],
];
export const SHELL_REDIRECT = ['shell-redirect', /(?<![=<>-])>>?\s*["']?(?:~|\$\{?HOME\}?|%USERPROFILE%|\$env:USERPROFILE)/];
export const SHELL_SCRIPT = /\.(?:sh|bash|zsh|ps1|cmd|bat)$/i;
const agentDirs = (s) => [...new Set([...[...s.matchAll(AGENT_HOME_DIR)].map((m) => `.${m[1]}`), ...[...s.matchAll(AGENT_XDG_DIR)].map((m) => `.config/${m[1]}`)])].sort();
const writesOf = (s, shell) => [...WRITE_MARKERS, ...(shell ? [SHELL_REDIRECT] : [])].filter(([, re]) => re.test(s)).map(([n]) => n);
/** 8d, pure: { dirs, writes } when a text both names an agent config dir and writes; else null. */
export function agentConfigWrite(s, { shell = false } = {}) {
  const t = typeof s === 'string' ? s : ''; const dirs = agentDirs(t); if (!dirs.length) return null;
  const writes = writesOf(t, shell); return writes.length ? { dirs, writes } : null;
}
/** 8h: the I/O token classes and their tokens (class, name, regex). A literal require of a file is not a token (that file is read too). */
export const IO_CLASSES = Object.freeze(['network', 'filesystem', 'process', 'env', 'exec', 'encoding']);
const MOD = (m) => new RegExp(`\\b(?:require|import)\\s*\\(\\s*['"\`](?:node:)?(?:${m})['"\`]|\\bfrom\\s*['"\`](?:node:)?(?:${m})['"\`]`);
export const IO_TOKENS = [
  ...API_NET_SINKS.map(([n, re]) => ['network', n, re]), ['network', 'net-module', MOD('https?|http2|net|dgram|tls|dns')], ['network', 'net-tool', /\b(?:curl|wget)\b/],
  ['filesystem', 'fs-call', /\b(?:readFileSync|writeFileSync|appendFileSync|readFile|writeFile|appendFile|createWriteStream|createReadStream|unlinkSync|unlink|rmSync|rmdirSync|chmodSync|chmod|renameSync|copyFileSync|readdirSync|symlinkSync)\s*\(|\bos\.homedir\s*\(/],
  ['filesystem', 'fs-module', MOD('fs|fs\\/promises')],
  ['process', 'process-object', /\bprocess\s*\.\s*(?!env\b)[A-Za-z_$]|\bprocess\s*\[/],
  ['env', 'env-read', /\bprocess\s*\.\s*env\b|\b(?:Deno|Bun)\.env\b|\bimport\.meta\.env\b/],
  ...EXEC_SINKS.map(([n, re]) => ['exec', n, re]), ['exec', 'dynamic-import', /\bimport\s*\(/], ['exec', 'dynamic-require', /\brequire\s*\(\s*(?!['"`\s])/],
  ['exec', 'wasm', /\bWebAssembly\s*\.\s*(?:instantiate|instantiateStreaming|compile|compileStreaming|Module|Instance)\b/], ['exec', 'worker', /\bnew\s+Worker\s*\(/],
  ['encoding', 'decode-call', /\batob\s*\(|\bbtoa\s*\(|\bBuffer\s*\.\s*from\s*\(|\bString\s*\.\s*fromCharCode\b|\bTextDecoder\b|\bunescape\s*\(|\bdecodeURIComponent\s*\(/],
  ['encoding', 'encoding-name', /['"`](?:base64|base64url|hex|latin1|binary)['"`]/], ['encoding', 'hex-escape', /\\x[0-9a-fA-F]{2}/],
];
const RUN_KINDS = ['base64', 'hex', 'hex-escape']; const MAGIC_NAMES = [...DECODED_MAGIC.map(([n]) => n), 'none'];
/**
 * The 1.6 facts of ONE archive member, pure: data = its first windowBytes (more is cut here); size = its full size. binary (a NUL in the
 * first 8000 bytes) -> nothing read; truncated = size beyond the window. Small and bounded: the caller keeps this record, never the bytes.
 */
export function memberFacts({ path, size, data } = {}) {
  const L = FACTS_LIMITS; const buf = Buffer.isBuffer(data) ? data.subarray(0, L.windowBytes) : Buffer.alloc(0); const n = Number.isFinite(size) ? size : buf.length;
  const p = typeof path === 'string' ? path : '?';
  const base = { path: factsClip(p), size: n, truncated: n > buf.length, excluded_path: EXCLUDED_PATH.test(p) };
  const none = { by_kind: Object.fromEntries(RUN_KINDS.map((k) => [k, 0])), by_magic: Object.fromEntries(MAGIC_NAMES.map((k) => [k, 0])), under_diversity_ref: 0 };
  const s8f = s8MemberFacts(p, buf, n > buf.length);   // v6.17 static-checks-1.8: the S8 facts (native, native_source, gyp_sources, xor_text)
  if (buf.subarray(0, LIMITS.headBytes).includes(0)) return { ...base, binary: true, io: [], io_tokens: [], p2_lines: 0, p9_lines: 0, runs_total: 0, run_counts: none, runs: [], agent: null, ...s8f };
  const s = buf.toString('utf8');
  let p2 = 0; let p9 = 0; for (const line of s.split('\n')) { if (DYNAMIC_CODE.test(line)) p2 += 1; if (RAW_IP_URL.test(line)) p9 += 1; }
  const runs = encodedRuns(s); const rc = none;
  for (const r of runs) { rc.by_kind[r.kind] += 1; rc.by_magic[r.magic ?? 'none'] += 1; if (r.distinct_chars < L.diversityRef) rc.under_diversity_ref += 1; }
  const toks = IO_TOKENS.filter(([, , re]) => re.test(s)); const io = new Set(toks.map(([c]) => c)); if (runs.length) io.add('encoding');
  return { ...base, binary: false, io: IO_CLASSES.filter((c) => io.has(c)), io_tokens: [...new Set([...toks.map(([, t]) => t), ...(runs.length ? ['encoded-run'] : [])])],
    p2_lines: p2, p9_lines: p9, runs_total: runs.length, run_counts: rc, runs: runs.slice(0, L.listed), agent: agentConfigWrite(s, { shell: SHELL_SCRIPT.test(p) }), ...s8f };
}
/**
 * The 1.6 facts block of one version, pure: members = memberFacts records of every member of the archive (the installed view), hooks =
 * the hook commands staticChecks reads, keepList for the roles of a writing file. No members -> NOT_CHECKED, stated.
 */
export function staticFacts({ members, hooks = [], keepList: kl = null, archiveComplete = false } = {}) {
  const L = FACTS_LIMITS; const v = { version: STATIC_CHECKS_VERSION, note: FACTS_NOTE };
  if (!Array.isArray(members)) return { ...v, status: 'NOT_CHECKED', reason: 'no member facts supplied' };
  const ms = members.filter((m) => m && typeof m === 'object'); const klRoles = kl && typeof kl.roles === 'object' && kl.roles ? kl.roles : {};
  const hs = (Array.isArray(hooks) ? hooks : []).filter((h) => h && typeof h.cmd === 'string' && h.cmd);
  // rule 6
  const er = { runs: 0, files: 0, by_kind: Object.fromEntries(RUN_KINDS.map((k) => [k, 0])), by_magic: Object.fromEntries(MAGIC_NAMES.map((k) => [k, 0])), under_diversity_ref: 0, diversity_ref: L.diversityRef, distinct_chars_basis: 'distinct chars, first 64 KiB of each run', listed: [] };   // 1.8.1
  for (const m of ms) {
    if (!m.runs_total) continue; er.files += 1; er.runs += m.runs_total; er.under_diversity_ref += m.run_counts?.under_diversity_ref ?? 0;
    for (const k of RUN_KINDS) er.by_kind[k] += m.run_counts?.by_kind?.[k] ?? 0; for (const k of MAGIC_NAMES) er.by_magic[k] += m.run_counts?.by_magic?.[k] ?? 0;
    for (const r of m.runs || []) if (er.listed.length < L.listed) er.listed.push({ path: m.path, ...r });
  }
  // 8a
  const side = (k) => { const rest = ms.filter((m) => !m.excluded_path); const ex = ms.filter((m) => m.excluded_path); const sum = (xs) => xs.reduce((a, m) => a + (m[k] || 0), 0);
    return { rest: sum(rest), excluded: sum(ex), rest_files: rest.filter((m) => m[k] > 0).length, excluded_files: ex.filter((m) => m[k] > 0).length }; };
  const excluded_paths = { pattern: EXCLUDED_PATH.source, p2: side('p2_lines'), p9: side('p9_lines'),
    listed: ms.filter((m) => m.excluded_path && (m.p2_lines || m.p9_lines)).slice(0, L.listed).map((m) => ({ path: m.path, p2: m.p2_lines, p9: m.p9_lines })),
    note: 'lines with a hit, over each member\'s read window: P2-type = recon pattern P2 (dynamic code), P9-type = recon pattern P9 (bare-IP URL)' };
  // 8d
  const aw = [...ms.filter((m) => m.agent).map((m) => ({ source: 'file', path: m.path, roles: Array.isArray(klRoles[m.path]) ? klRoles[m.path] : ['module'], dirs: m.agent.dirs, writes: m.agent.writes })),
    ...hs.map((h) => ({ h, a: agentConfigWrite(h.cmd, { shell: true }) })).filter((x) => x.a).map(({ h, a }) => ({ source: 'hook', hook: factsClip(h.hook ?? '?', 40), hook_source: h.source === 'tarball' ? 'tarball' : 'registry', dirs: a.dirs, writes: a.writes }))];
  const agent_config_writes = { count: aw.length, listed: aw.slice(0, L.listed) };
  // 8h
  const notRead = ms.filter((m) => m.binary || m.truncated); const classes = Object.fromEntries(IO_CLASSES.map((c) => [c, ms.filter((m) => (m.io || []).includes(c)).length]));
  const hookN = new Set(hs.filter((h) => INSTALL_HOOKS.includes(h.hook)).map((h) => h.hook)).size;
  const present = Object.values(classes).some((x) => x > 0) || hookN > 0;
  const bin = notRead.filter((m) => m.binary).length; const tr = notRead.length - bin; const why = [];
  if (archiveComplete !== true) why.push('archive not read in full'); if (!ms.length) why.push('no member read');
  if (notRead.length) why.push(`${notRead.length} member${notRead.length === 1 ? '' : 's'} not read as text (${bin} binary, ${tr} beyond the ${L.windowBytes >> 20} MiB read window)`);
  const status = present || !why.length ? 'CHECKED' : 'NOT_CHECKED';
  const io_surface = { status, no_io_surface: present ? false : why.length ? null : true, classes, tokens: [...new Set(ms.flatMap((m) => m.io_tokens || []))].sort(), install_hooks: hookN,
    members: ms.length, text_read: ms.length - notRead.length, not_read: notRead.length,
    not_read_listed: notRead.slice(0, L.listed).map((m) => ({ path: m.path, reason: m.binary ? 'binary (a NUL in the first 8000 bytes)' : `beyond the read window (${m.size} B)` })),
    ...(status === 'NOT_CHECKED' ? { reason: why.join('; ') } : {}),
    note: 'present = a token of any class in any member, or an install hook; NONE only when every member of an archive read in full was read as text' };
  return { ...v, status: 'CHECKED', encoded_runs: er, excluded_paths, agent_config_writes, io_surface };
}
/** Recon's clip (its pathChars cap, the cut and the length said), over a path with the proxy's control and bidi characters removed (UNSAFE, as shownName). */
const factsClip = (x, n = 200) => { const t = String(x ?? '').replace(UNSAFE, ''); return t.length > n ? `${t.slice(0, n)}…[${t.length} chars]` : t; };
/** Rule 7 on a FIRING S5 file entry, recon's fields (its staticChecks computes them inline): the streamed share, or why there is none. */
export const s5Base64Fields = (b) => (b && Number.isFinite(b.share) ? { base64_share: b.share, base64_magic: b.magic ?? null } : { base64_share: null, base64_magic: null, base64_note: 'body not streamed: base64 share not checked' });

// ---- the proxy's half of the 1.6 input contract (R11 (b)); facts only, never a row
/** The archive members whose facts one armed walk keeps (each a small memberFacts record, never the bytes); past it the block is NOT_CHECKED. */
export const MAX_FACTS_MEMBERS = 20000;
/** The member facts of one walk: onMember(path, size, window) from tar-walk.js (every regular file on the Linux view, its first
 *  FACTS_LIMITS.windowBytes); the installed view keeps the LAST duplicate of a path in the place of the first, as recon's tar.mjs. */
export function createMemberTally({ max = MAX_FACTS_MEMBERS } = {}) {
  const ms = new Map(); let over = false;
  return {
    max,
    onMember(path, size, data) {
      if (over) return;
      if (!ms.has(path) && ms.size >= max) { over = true; ms.clear(); return; }
      ms.set(path, memberFacts({ path, size, data }));
    },
    result() { return { over, members: over ? [] : [...ms.values()] }; },
  };
}
/**
 * The 1.6 facts of a finished ARMED walk, pure: { facts: recon's staticFacts block, s5: the S5 file entries that fire, each with recon's
 * rule 7 fields }. The hook commands are the ones S0 reads (the registry manifest's, then the tarball package.json's that differ); the
 * roles of a writing file are the registry keep list's, as recon's. Member facts count only from a walk read in full (recon reads them
 * from an archive it read in full); none supplied, or more than MAX_FACTS_MEMBERS, is NOT_CHECKED with the reason.
 */
export function staticFactsOf({ manifest, packageJson = null, walk, members, membersOver = false } = {}) {
  const ok = Boolean(walk?.ok) && Array.isArray(walk?.files);
  const klReg = keepListFor(manifest); const klTar = keepListFor(packageJson, 'tarball package.json');
  const reg = hookDictOf(manifest); const tar = hookDictOf(packageJson);
  const hooks = Object.entries(reg).map(([hook, cmd]) => ({ source: 'registry', hook, cmd }));
  for (const [hook, cmd] of Object.entries(tar)) if (reg[hook] !== cmd) hooks.push({ source: 'tarball', hook, cmd });
  const facts = ok && membersOver
    ? { version: STATIC_CHECKS_VERSION, note: FACTS_NOTE, status: 'NOT_CHECKED', reason: `more than ${MAX_FACTS_MEMBERS} archive members: member facts not kept` }
    : staticFacts({ members: ok && Array.isArray(members) ? members : undefined, hooks, keepList: klReg, archiveComplete: ok });
  // rule 7: a hook target over the keep cap (the S5 condition), once per target (its node-resolution variants are the same target)
  const primaryOf = {}; for (const t of [...klReg.targets, ...klTar.targets]) for (const v of t.variants) primaryOf[v] ??= t.path;
  const s5 = []; const seen = new Set();
  for (const x of ok && Array.isArray(walk.notKept) ? walk.notKept : []) {
    const roles = x && typeof x.path === 'string' ? klReg.roles[x.path] ?? klTar.roles[x.path] : null;
    if (!Array.isArray(roles) || !roles.includes('hook') || !(Number.isFinite(x.size) && x.size > LIMITS.maxKeepBytes)) continue;
    const prim = primaryOf[x.path] ?? x.path; if (seen.has(prim)) continue; seen.add(prim);
    s5.push({ path: shownName(prim), roles, size: x.size, fires: true, ...s5Base64Fields(x.base64) });
  }
  return { facts, s5 };
}

// ---- the trigger (operator ruling 2026-10-13, design note §3) and the retry rule ----
/**
 * Why a download's keep-list walk is armed, from the version's recorded rows: a NAMED WARN row (the runner's named gates, or a seed-v3
 * named row), the identity-break NOTE, the entry-path-change NOTE (ruling R1 2026-10-21), or the seed's coverage WARN (nothing in the finding was evaluated: the brand-new-package case).
 * Any other contributing row, or nothing, returns null. Pure; never throws on a malformed list.
 */
export function armedBy(results) {
  let cls; try { cls = classify(results); } catch { return null; }
  if (cls.named.length) return `named row${cls.named.length > 1 ? 's' : ''} ${cls.named.join(', ')}`;
  if (cls.contributing.includes('identity-break')) return 'identity-break';
  if (cls.contributing.includes('entry-path-change')) return 'entry-path-change';      // operator ruling R1 2026-10-21
  // since 0.1.6: a strict row the re-tier turned into a NOTE still arms the walk, so every re-tiered release is read
  if (cls.contributing.some((g) => NAMED_ROWS.includes(g))) return 'a strict row shown as a note (not new against its baseline)';
  if (cls.coverage.includes('seed-v3:coverage')) return 'seed coverage WARN (nothing in the finding was evaluated)';
  return null;
}
/** Since 0.1.6: every download is walked. The rows name what armed the walk, or "every download" when no recorded row did. */
export const walkReason = (results) => armedBy(results) ?? 'every download';
const RETRY_PREFIXES = ['not checked: not armed', 'not checked: no registry manifest at hand', 'not checked: walk budget exceeded'];
/** Since 0.1.6: the rows of a download that found no walk slot within static_walk_wait_ms; served unwalked, read at its next download. */
export const budgetRows = (waitedMs) => CHECKS.map((c) => ({ gate: c.gate, result: 'SKIP',
  detail: clipDetail(`not checked: walk budget exceeded (waited ${Number((Math.max(0, waitedMs) / 1000).toFixed(1))} s)`) }));
/** The ten rows of a walk that was not armed (or could not be: the concurrency ceiling), with the reason; retried when a later download is armed. */
export const unarmedRows = (why) => CHECKS.map((c) => ({ gate: c.gate, result: 'SKIP', detail: clipDetail(`not checked: not armed (${why})`) }));
/** The ten rows of an armed walk whose registry manifest was not at hand (no keep list); retried, as MC's own "not checked" is. */
export const noManifestRows = (armed) => CHECKS.map((c) => ({ gate: c.gate, result: 'SKIP', detail: clipDetail(`not checked: no registry manifest at hand; armed by ${armed}`) }));
/** Whether the record's static rows are FINAL: all ten present and none a retryable "not checked". A walked outcome, WARN, ALLOW or a
 *  SKIP for the tarball's own shape, is final: tarballs are immutable per version. */
export function staticSettled(latest) {
  const rows = Array.isArray(latest?.gates_fired) ? latest.gates_fired : [];
  const mine = STATIC_GATES.map((g) => rows.find((r) => r && r.gate === g));
  if (mine.some((r) => !r)) return false;
  return mine.every((r) => typeof r.detail === 'string' && !RETRY_PREFIXES.some((p) => r.detail.startsWith(p)));
}

export default { FACTS_LIMITS, FACTS_NOTE, DECODED_MAGIC, magicOf, B64_RUN, HEX_ESCAPE_RUN, encodedRuns, makeBase64Share, EXCLUDED_PATH, DYNAMIC_CODE,
  AGENT_CONFIG_NAMES, AGENT_HOME_DIR, AGENT_XDG_DIR, WRITE_MARKERS, SHELL_REDIRECT, SHELL_SCRIPT, agentConfigWrite, IO_CLASSES, IO_TOKENS, memberFacts, staticFacts,
  s5Base64Fields, MAX_FACTS_MEMBERS, createMemberTally, staticFactsOf, RAW_IP_URL, entryKeepFor, entryFactsOf, entrySummaryOf, capabilitiesOf, capabilityDelta, s7Named, S7_NAMED_ARMS, S7_DECODE_OBF_EXCLUDED, S7_EXEC_EXCLUDED, CAPABILITY_CLASSES, API_NET_SINKS, HOST_IDENTITY, IDENTITY_ENV, SHELLS, SHELL_C, shellCArgs, insideUpdateArg, hostIdentityNames, INLINE_NODE, blankConsoleOutput, NODE_DNS_CALL, DNS_DATA, dnsExfil, MAX_FACTS_WALKS, STATIC_CHECKS_VERSION, NOTHING_READ, LIMITS, CHECKS, STATIC_GATES, MAX_ARMED_WALKS, hookFetchExec, hookTargets, keepListFor, fileFacts, staticRows, shownName, armedBy, walkReason, budgetRows, unarmedRows, noManifestRows, staticSettled,
  S8_LIMITS, NATIVE_MAGIC, NATIVE_SOURCE, BINDING_GYP, ADDON_FILE, ADDON_LOADS, nativeKind, xorText, GYP_LIMITS, GYP_FILE, GYP_QUIET, GYP_SCRIPT, gypExpansions, gypBuild, hiddenGypScript, addonDropper };
