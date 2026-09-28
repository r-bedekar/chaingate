// U-01 A6/A11 — an in-process network guard, loaded with `node --import <this file>`.
//
// Every outbound path Node offers is replaced by one that RECORDS the attempt and THROWS: TCP and
// TLS sockets (which http, https, undici and fetch all use), fetch itself, DNS lookups and
// resolution, and UDP. If U01_NET_LOG names a file, each attempt is appended to it, so a test can
// assert the guard was never reached rather than merely that nothing failed.
//
// U01_ALLOW_LOOPBACK=1 lets TCP to 127.0.0.1 / ::1 / localhost through: the lifecycle qualification
// talks to a local proxy, and the operator permitted isolated loopback traffic for it. Nothing else
// is ever allowed.
//
// This is a PROCESS-LEVEL guard, not an OS one: this host refuses unprivileged network namespaces
// (`unshare -rn`: "write failed /proc/self/uid_map: Operation not permitted"). It covers the Node
// process and, through NODE_OPTIONS, the Node children it starts.
import net from 'node:net';
import tls from 'node:tls';
import dns from 'node:dns';
import dgram from 'node:dgram';
import fs from 'node:fs';

const LOG = process.env.U01_NET_LOG || null;
const ALLOW_LOOPBACK = process.env.U01_ALLOW_LOOPBACK === '1';
const LOOPBACK = new Set(['127.0.0.1', '::1', 'localhost', '::ffff:127.0.0.1']);

function record(kind, target) {
  const line = `${new Date().toISOString()} pid=${process.pid} ${kind} ${target}\n`;
  if (LOG) { try { fs.appendFileSync(LOG, line); } catch { /* the throw below still happens */ } }
  const err = new Error(`network access denied by U-01 guard: ${kind} ${target}`);
  err.code = 'U01_NETWORK_DENIED';
  return err;
}

function targetOf(args) {
  const a = args[0];
  if (a && typeof a === 'object') {
    if (a.path) return { host: 'unix', port: a.path, unix: true };
    return { host: a.host ?? 'localhost', port: a.port };
  }
  if (typeof a === 'string' && Number.isNaN(Number(a))) return { host: 'unix', port: a, unix: true };
  return { host: typeof args[1] === 'string' ? args[1] : 'localhost', port: a };
}

const origConnect = net.Socket.prototype.connect;
net.Socket.prototype.connect = function guardedConnect(...args) {
  const flat = Array.isArray(args[0]) ? args[0] : args;           // internal normalized-args form
  const t = targetOf(flat);
  if (t.unix || (ALLOW_LOOPBACK && LOOPBACK.has(String(t.host)))) return origConnect.apply(this, args);
  throw record('tcp', `${t.host}:${t.port}`);
};

const origTls = tls.connect;
tls.connect = function guardedTls(...args) {
  const t = targetOf(args);
  if (ALLOW_LOOPBACK && LOOPBACK.has(String(t.host))) return origTls.apply(this, args);
  throw record('tls', `${t.host}:${t.port}`);
};

const origFetch = globalThis.fetch;
globalThis.fetch = async function guardedFetch(input, init) {
  const url = typeof input === 'string' ? input : (input?.url ?? String(input));
  let host = '';
  try { host = new URL(url).hostname.replace(/^\[|\]$/g, ''); } catch { /* not a URL */ }
  // loopback fetch goes through, and its socket still passes the TCP guard above
  if (ALLOW_LOOPBACK && LOOPBACK.has(host)) return origFetch(input, init);
  throw record('fetch', url);
};

// Resolving an IP LITERAL is local (no query leaves the host), and the connect that follows is still
// guarded above, so literals go through the real resolver; `localhost` too when loopback is allowed.
// Every other name is denied.
const denyDns = (name, orig) => function guardedDns(host, ...rest) {
  if (net.isIP(String(host)) !== 0 || (ALLOW_LOOPBACK && String(host) === 'localhost')) {
    return orig.call(this, host, ...rest);
  }
  throw record(`dns.${name}`, String(host));
};
for (const fn of ['lookup', 'resolve', 'resolve4', 'resolve6', 'resolveAny', 'resolveCname', 'resolveMx',
  'resolveNs', 'resolveTxt', 'resolveSrv', 'reverse']) {
  if (typeof dns[fn] === 'function') dns[fn] = denyDns(fn, dns[fn]);
  if (dns.promises && typeof dns.promises[fn] === 'function') {
    const orig = dns.promises[fn];
    dns.promises[fn] = async (host, ...rest) => {
      if (net.isIP(String(host)) !== 0 || (ALLOW_LOOPBACK && String(host) === 'localhost')) return orig(host, ...rest);
      throw record(`dns.promises.${fn}`, String(host));
    };
  }
}

const origCreateSocket = dgram.createSocket;
dgram.createSocket = function guardedDgram() { throw record('udp', 'createSocket'); };
void origCreateSocket;

process.env.U01_NETWORK_GUARD = ALLOW_LOOPBACK ? 'loopback-only' : 'deny-all';
