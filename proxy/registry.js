import { request, errors as undiciErrors } from 'undici';

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

async function upstreamRequest(url, { headers = {}, config }) {
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

export { RELAY_RESPONSE_HEADERS };
