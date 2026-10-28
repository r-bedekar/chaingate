import { request, Agent, interceptors, errors as undiciErrors } from 'undici';

// Upstream traffic goes through an Agent from the pinned undici. Without an explicit dispatcher,
// request() uses the process-wide global dispatcher, and on Node 22 importing `node:http` installs
// Node's own bundled undici there first, so the pinned version's HTTP/1.1 client would never run
// and its fixes (unterminated chunked bodies, header validation) would not apply.
//
// `pipelining: 0` disables keep-alive: every request is sent with `connection: close` on its own
// connection, which is closed after the response. An upstream can otherwise leave an unsolicited
// response on an idle socket for the next request to receive; on undici 6.28.1 we reproduced that
// on reused sockets (test/proxy/u031-upstream-hardening.test.js). Packuments, tarballs, background
// dependency lookups and the raw fallback all come through upstreamRequest() and share this Agent.
// The global dispatcher is left alone.
//
// Redirects are followed by undici's redirect interceptor, which reads each request's `maxRedirections`
// (undici 7 and later reject that option on a plain dispatcher). It drops `authorization` and cookies
// when a redirect leaves the origin, as the request option did in undici 6.
const upstreamAgent = new Agent({ pipelining: 0 }).compose(interceptors.redirect());

const RELAY_REQUEST_HEADERS = ['authorization', 'if-none-match', 'if-modified-since'];
const RELAY_RESPONSE_HEADERS = [
  'content-type',
  'content-length',
  'content-encoding',
  'etag',
  'last-modified',
  'cache-control',
  'vary',
  'npm-notice',
];

export class UpstreamTimeoutError extends Error {
  constructor(message) {
    super(message);
    this.name = 'UpstreamTimeoutError';
    this.code = 'UPSTREAM_TIMEOUT';
  }
}

export class UpstreamError extends Error {
  constructor(message, cause) {
    super(message);
    this.name = 'UpstreamError';
    this.code = 'UPSTREAM_UNREACHABLE';
    this.cause = cause;
  }
}

function buildUrl(upstream, encodedPath) {
  return new URL(encodedPath, upstream + '/').toString();
}

export function encodePackageName(rawName) {
  // Accept '@scope/name' OR '@scope%2Fname' on the way in; emit '@scope%2Fname'.
  const decoded = decodeURIComponent(rawName);
  if (decoded.startsWith('@')) {
    const slash = decoded.indexOf('/');
    if (slash === -1) return encodeURIComponent(decoded);
    const scope = decoded.slice(0, slash);
    const name = decoded.slice(slash + 1);
    return encodeURIComponent(scope) + '%2F' + encodeURIComponent(name);
  }
  return encodeURIComponent(decoded);
}

function pickRelayHeaders(src, allowed) {
  const out = {};
  if (!src) return out;
  for (const key of allowed) {
    const v = src[key] ?? src[key.toLowerCase()];
    if (v != null) out[key] = v;
  }
  return out;
}

// bounds: { headersTimeout, bodyTimeout, maxRedirections, signal } in place of the configured ones (the attestation fetch's tighter bounds)
async function upstreamRequest(url, { headers = {}, config, bounds = {} }) {
  try {
    return await request(url, {
      method: 'GET',
      headers: {
        'user-agent': 'chaingate-proxy/0.1 (+https://chaingate.dev)',
        accept: 'application/json',
        ...headers,
      },
      headersTimeout: config.headersTimeoutMs,
      bodyTimeout: config.bodyTimeoutMs,
      maxRedirections: 2,
      ...bounds,
      dispatcher: upstreamAgent,
    });
  } catch (err) {
    if (
      err instanceof undiciErrors.HeadersTimeoutError ||
      err instanceof undiciErrors.BodyTimeoutError ||
      err instanceof undiciErrors.ConnectTimeoutError
    ) {
      throw new UpstreamTimeoutError(`upstream timed out: ${err.message}`);
    }
    throw new UpstreamError(`upstream unreachable: ${err.message}`, err);
  }
}

export async function fetchPackument(rawName, { config, requestHeaders = {} } = {}) {
  const encoded = encodePackageName(rawName);
  const url = buildUrl(config.upstream, encoded);
  const relay = pickRelayHeaders(requestHeaders, RELAY_REQUEST_HEADERS);
  // Force identity encoding so the witness pipeline can parse the packument
  // JSON without decompressing. Localhost bandwidth savings from gzip are
  // negligible compared to the code simplification.
  relay['accept-encoding'] = 'identity';
  return upstreamRequest(url, { headers: relay, config });
}

export async function fetchTarball(rawName, filename, { config, requestHeaders = {} } = {}) {
  const encoded = encodePackageName(rawName);
  const safeFile = encodeURIComponent(filename);
  const url = buildUrl(config.upstream, `${encoded}/-/${safeFile}`);
  const relay = pickRelayHeaders(requestHeaders, RELAY_REQUEST_HEADERS);
  relay.accept = 'application/octet-stream, */*';
  return upstreamRequest(url, { headers: relay, config });
}

// The registry's attestation bundle of one version, for the repository claim recorded beside an armed version's facts. Bounded in
// time (the whole request) and bytes, no redirect followed, and no request header of the user's relayed (it is a public endpoint).
// Never throws: { ok: true, bytes } or { ok: false, reason }.
export async function fetchAttestationBundle(rawName, version, { config, timeoutMs, maxBytes }) {
  const name = decodeURIComponent(rawName);
  const spec = name.startsWith('@') ? `@${encodeURIComponent(name.slice(1))}` : encodeURIComponent(name);
  const url = buildUrl(config.upstream, `-/npm/v1/attestations/${spec}@${encodeURIComponent(version)}`);
  const ac = new AbortController();
  const timer = setTimeout(() => ac.abort(), timeoutMs);
  let res = null;
  try {
    res = await upstreamRequest(url, { headers: { 'accept-encoding': 'identity' }, config,
      bounds: { headersTimeout: timeoutMs, bodyTimeout: timeoutMs, maxRedirections: 0, signal: ac.signal } });
    res.body.on('error', () => { /* the body is dropped below; its abort is not an error of the proxy */ });
    if (res.statusCode !== 200) return { ok: false, reason: `HTTP ${res.statusCode}` };
    const len = Number(res.headers['content-length']);
    if (Number.isFinite(len) && len > maxBytes) return { ok: false, reason: `the bundle exceeds ${maxBytes} bytes` };
    const chunks = []; let total = 0;
    for await (const c of res.body) {
      total += c.length;
      if (total > maxBytes) return { ok: false, reason: `the bundle exceeds ${maxBytes} bytes` };
      chunks.push(c);
    }
    return { ok: true, bytes: Buffer.concat(chunks) };
  } catch (err) {
    if (ac.signal.aborted || err instanceof UpstreamTimeoutError || err instanceof undiciErrors.BodyTimeoutError) {
      return { ok: false, reason: `timeout after ${timeoutMs} ms` };
    }
    const msg = String(err?.message ?? err).slice(0, 160);
    return { ok: false, reason: err instanceof UpstreamError ? msg : `the bundle was not read: ${msg}` };
  } finally {
    clearTimeout(timer);
    try { if (res?.body && !res.body.destroyed) res.body.destroy(); } catch { /* already closed */ }
  }
}

export { RELAY_RESPONSE_HEADERS };
