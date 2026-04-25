import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  fetchReleases,
  pickLatestSeedRelease,
  extractAssetUrls,
  resolveLatestSeedAssets,
  SeedResolutionError,
} from '../../cli/seed-resolver.js';
import { SEED_FILES } from '../../cli/constants.js';

function release({ tag, publishedAt = '2026-04-25T12:00:00Z', assets = null }) {
  return {
    tag_name: tag,
    published_at: publishedAt,
    assets: assets ?? SEED_FILES.map((name) => ({
      name,
      browser_download_url: `https://github.com/r-bedekar/chaingate/releases/download/${tag}/${name}`,
    })),
  };
}

function mockFetch(responseBody, { status = 200, headers = {} } = {}) {
  return async () => ({
    ok: status >= 200 && status < 300,
    status,
    headers: {
      get: (k) => headers[k.toLowerCase()] ?? headers[k] ?? null,
    },
    json: async () => responseBody,
  });
}

function mockFetchThrows(error) {
  return async () => { throw error; };
}

describe('pickLatestSeedRelease — happy path', () => {
  it('returns the only matching release when there is one', () => {
    const releases = [release({ tag: 'seed-v2.1' })];
    const picked = pickLatestSeedRelease(releases);
    assert.equal(picked.tag_name, 'seed-v2.1');
  });

  it('returns the most recent by published_at when multiple match', () => {
    const releases = [
      release({ tag: 'seed-v2',   publishedAt: '2026-04-20T00:00:00Z' }),
      release({ tag: 'seed-v2.1', publishedAt: '2026-04-25T00:00:00Z' }),
      release({ tag: 'seed-v1',   publishedAt: '2026-04-14T00:00:00Z' }),
    ];
    const picked = pickLatestSeedRelease(releases);
    assert.equal(picked.tag_name, 'seed-v2.1');
  });

  it('filters out non-seed tags (CLI releases, etc.)', () => {
    const releases = [
      release({ tag: 'v1.0.0',     publishedAt: '2026-05-01T00:00:00Z' }),
      release({ tag: 'seed-v2.1',  publishedAt: '2026-04-25T00:00:00Z' }),
      release({ tag: 'random-tag', publishedAt: '2026-05-02T00:00:00Z' }),
    ];
    const picked = pickLatestSeedRelease(releases);
    assert.equal(picked.tag_name, 'seed-v2.1');
  });
});

describe('pickLatestSeedRelease — edge cases', () => {
  it('throws SeedResolutionError(no-releases) when no releases match', () => {
    const releases = [
      release({ tag: 'v1.0.0' }),
      release({ tag: 'random-tag' }),
    ];
    assert.throws(
      () => pickLatestSeedRelease(releases),
      (err) => err instanceof SeedResolutionError && err.kind === 'no-releases'
    );
  });

  it('throws SeedResolutionError(no-releases) when releases array is empty', () => {
    assert.throws(
      () => pickLatestSeedRelease([]),
      (err) => err instanceof SeedResolutionError && err.kind === 'no-releases'
    );
  });
});

describe('fetchReleases — edge cases', () => {
  it('throws SeedResolutionError(rate-limit) on 403 with rate-limit headers', async () => {
    const resetTs = Math.floor(Date.now() / 1000) + 1800;
    const fetchImpl = mockFetch(
      { message: 'API rate limit exceeded' },
      { status: 403, headers: {
        'x-ratelimit-remaining': '0',
        'x-ratelimit-reset': String(resetTs),
      } }
    );
    await assert.rejects(
      fetchReleases({ fetchImpl }),
      (err) => err instanceof SeedResolutionError && err.kind === 'rate-limit'
    );
  });

  it('throws SeedResolutionError(network) on fetch throw', async () => {
    const fetchImpl = mockFetchThrows(new Error('ENOTFOUND'));
    await assert.rejects(
      fetchReleases({ fetchImpl }),
      (err) => err instanceof SeedResolutionError && err.kind === 'network'
    );
  });

  it('throws SeedResolutionError(malformed) when response is not an array', async () => {
    const fetchImpl = mockFetch({ not: 'an array' });
    await assert.rejects(
      fetchReleases({ fetchImpl }),
      (err) => err instanceof SeedResolutionError && err.kind === 'malformed'
    );
  });
});

describe('extractAssetUrls', () => {
  it('returns a map of filename → download URL for all SEED_FILES', () => {
    const r = release({ tag: 'seed-v2.1' });
    const urls = extractAssetUrls(r);
    for (const f of SEED_FILES) {
      assert.ok(urls[f], `missing URL for ${f}`);
      assert.match(urls[f], /^https:\/\/github\.com\/r-bedekar\/chaingate\/releases\/download\/seed-v2\.1\//);
    }
  });

  it('throws SeedResolutionError(asset-mismatch) when expected files are missing', () => {
    const r = release({
      tag: 'seed-v2.1',
      assets: [{ name: 'wrong-file.bin', browser_download_url: 'https://example.com/wrong-file.bin' }],
    });
    assert.throws(
      () => extractAssetUrls(r),
      (err) => err instanceof SeedResolutionError && err.kind === 'asset-mismatch'
    );
  });
});

describe('extractAssetUrls — release without assets array', () => {
  it('throws SeedResolutionError(asset-mismatch) when assets array is missing', () => {
    assert.throws(
      () => extractAssetUrls({ tag_name: 'seed-v2.1' }),
      (err) => err instanceof SeedResolutionError && err.kind === 'asset-mismatch'
    );
  });
});

describe('resolveLatestSeedAssets — integration', () => {
  it('end-to-end: fetches, picks latest, extracts URLs from a realistic API response', async () => {
    const apiResponse = [
      release({ tag: 'v0.1.0',     publishedAt: '2026-05-01T00:00:00Z',
                assets: [{ name: 'unrelated.tar.gz', browser_download_url: 'https://example.com/x' }] }),
      release({ tag: 'seed-v2.1',  publishedAt: '2026-04-25T12:35:16Z' }),
      release({ tag: 'seed-v2',    publishedAt: '2026-04-20T09:10:58Z' }),
      release({ tag: 'seed-v1',    publishedAt: '2026-04-14T19:00:37Z' }),
    ];
    const fetchImpl = mockFetch(apiResponse);
    const result = await resolveLatestSeedAssets({ fetchImpl });

    assert.equal(result.tagName, 'seed-v2.1');
    assert.equal(result.publishedAt, '2026-04-25T12:35:16Z');
    for (const f of SEED_FILES) {
      assert.ok(result.urls[f]);
      assert.match(result.urls[f], /seed-v2\.1/);
    }
  });
});
