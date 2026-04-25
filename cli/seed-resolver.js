import { SEED_REPO, SEED_TAG_PATTERN, SEED_FILES } from './constants.js';

const GITHUB_API_BASE = 'https://api.github.com';

export class SeedResolutionError extends Error {
  constructor(message, kind) {
    super(message);
    this.name = 'SeedResolutionError';
    this.kind = kind; // 'no-releases' | 'rate-limit' | 'network' | 'malformed' | 'asset-mismatch'
  }
}

/**
 * Fetch all releases for the configured seed repo from GitHub's REST API.
 */
export async function fetchReleases({ fetchImpl = fetch } = {}) {
  const url = `${GITHUB_API_BASE}/repos/${SEED_REPO}/releases`;
  let resp;
  try {
    resp = await fetchImpl(url, {
      headers: {
        'Accept': 'application/vnd.github+json',
        'X-GitHub-Api-Version': '2022-11-28',
        'User-Agent': 'chaingate-cli',
      },
    });
  } catch (err) {
    throw new SeedResolutionError(
      `Network error contacting GitHub API: ${err.message}`,
      'network'
    );
  }

  if (resp.status === 403) {
    const remaining = resp.headers.get('x-ratelimit-remaining');
    const resetTs = resp.headers.get('x-ratelimit-reset');
    if (remaining === '0' && resetTs) {
      const resetSeconds = Number(resetTs) - Math.floor(Date.now() / 1000);
      const resetMinutes = Math.max(1, Math.ceil(resetSeconds / 60));
      throw new SeedResolutionError(
        `GitHub API rate limit exceeded. Try again in approximately ${resetMinutes} minute(s). ` +
        `(Unauthenticated requests are limited to 60/hour.)`,
        'rate-limit'
      );
    }
    throw new SeedResolutionError(
      `GitHub API returned 403 Forbidden. This may indicate rate limiting or a permission issue.`,
      'rate-limit'
    );
  }

  if (!resp.ok) {
    throw new SeedResolutionError(
      `GitHub API returned HTTP ${resp.status} for ${url}`,
      'network'
    );
  }

  let data;
  try {
    data = await resp.json();
  } catch (err) {
    throw new SeedResolutionError(
      `GitHub API returned malformed JSON: ${err.message}`,
      'malformed'
    );
  }

  if (!Array.isArray(data)) {
    throw new SeedResolutionError(
      `GitHub API returned unexpected shape (not an array)`,
      'malformed'
    );
  }

  return data;
}

/**
 * Filter releases by tag pattern, sort by published_at descending, return the most recent.
 */
export function pickLatestSeedRelease(releases) {
  const matching = releases.filter((r) => {
    if (!r || typeof r.tag_name !== 'string') return false;
    return SEED_TAG_PATTERN.test(r.tag_name);
  });

  if (matching.length === 0) {
    throw new SeedResolutionError(
      `No seed releases found in ${SEED_REPO}. Expected at least one release with tag matching ${SEED_TAG_PATTERN}. ` +
      `If you are setting up chaingate for the first time, check back when an initial seed bundle has been published.`,
      'no-releases'
    );
  }

  matching.sort((a, b) => {
    const ta = a.published_at ? Date.parse(a.published_at) : 0;
    const tb = b.published_at ? Date.parse(b.published_at) : 0;
    return tb - ta;
  });

  return matching[0];
}

/**
 * Extract download URLs for the SEED_FILES from a release object.
 */
export function extractAssetUrls(release) {
  if (!release || !Array.isArray(release.assets)) {
    throw new SeedResolutionError(
      `Release ${release?.tag_name ?? '<unknown>'} has no downloadable assets.`,
      'asset-mismatch'
    );
  }

  const byName = {};
  for (const asset of release.assets) {
    if (asset?.name && asset?.browser_download_url) {
      byName[asset.name] = asset.browser_download_url;
    }
  }

  const missing = SEED_FILES.filter((f) => !(f in byName));
  if (missing.length > 0) {
    throw new SeedResolutionError(
      `Release ${release.tag_name} is missing required asset(s): ${missing.join(', ')}. ` +
      `Available assets: ${Object.keys(byName).join(', ') || '(none)'}.`,
      'asset-mismatch'
    );
  }

  const urls = {};
  for (const f of SEED_FILES) urls[f] = byName[f];
  return urls;
}

/**
 * Resolve the latest seed release and return a map of asset filename → download URL.
 */
export async function resolveLatestSeedAssets(options = {}) {
  const releases = await fetchReleases(options);
  const release = pickLatestSeedRelease(releases);
  const urls = extractAssetUrls(release);
  return {
    tagName: release.tag_name,
    publishedAt: release.published_at,
    urls,
  };
}
