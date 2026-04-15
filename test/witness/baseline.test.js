import { test } from 'node:test';
import assert from 'node:assert/strict';

import { parseVersion, parseVersionsFromPackument } from '../../witness/baseline.js';

function axiosVersion(overrides = {}) {
  return {
    name: 'axios',
    version: '1.7.9',
    description: 'promise-based http client',
    main: 'index.js',
    dependencies: {
      'follow-redirects': '^1.15.6',
      'form-data': '^4.0.0',
      'proxy-from-env': '^1.1.0',
    },
    devDependencies: { mocha: '^10.2.0' },
    _npmUser: { name: 'jasonsaayman', email: 'jasonsaayman@gmail.com' },
    _npmVersion: '10.9.2',
    maintainers: [
      { name: 'jasonsaayman', email: 'jasonsaayman@gmail.com', url: 'https://example' },
      { name: 'emilyemorehouse', email: 'emily@example.com' },
    ],
    dist: {
      shasum: 'f05076f19e0b9f60b8f1b7a8a7f5a0a00fedf22d',
      integrity: 'sha512-LhLcE7U6p8/IJhvZTZsiRBvkaHFULjCjfMCKpxRPxP6+Arx==',
      tarball: 'https://registry.npmjs.org/axios/-/axios-1.7.9.tgz',
      unpackedSize: 432109,
    },
    repository: { type: 'git', url: 'git+https://github.com/axios/axios.git' },
    gitHead: '9e0b9f60b8f1b7a8a7f5a0a00fedf22df05076f1',
    ...overrides,
  };
}

test('axios fixture → correct VersionMetadata shape', () => {
  const parsed = parseVersion('1.7.9', axiosVersion(), '2024-12-23T00:00:00.000Z');
  assert.equal(parsed.version, '1.7.9');
  assert.equal(parsed.published_at, '2024-12-23T00:00:00.000Z');
  assert.equal(parsed.content_hash, 'f05076f19e0b9f60b8f1b7a8a7f5a0a00fedf22d');
  assert.equal(parsed.content_hash_algo, 'sha1');
  assert.equal(parsed.integrity_hash, 'sha512-LhLcE7U6p8/IJhvZTZsiRBvkaHFULjCjfMCKpxRPxP6+Arx==');
  assert.equal(parsed.git_head, '9e0b9f60b8f1b7a8a7f5a0a00fedf22df05076f1');
  assert.equal(parsed.package_size_bytes, 432109);
  assert.equal(parsed.dependency_count, 3);
  assert.deepEqual(Object.keys(parsed.dependencies).sort(), [
    'follow-redirects', 'form-data', 'proxy-from-env',
  ]);
  assert.equal(parsed.dev_dependency_count, 1);
  assert.deepEqual(parsed.dev_dependencies, { mocha: '^10.2.0' });
  assert.equal(parsed.peer_dependencies, null);
  assert.equal(parsed.bundled_dependencies, null);
  assert.equal(parsed.publisher_name, 'jasonsaayman');
  assert.equal(parsed.publisher_email, 'jasonsaayman@gmail.com');
  assert.equal(parsed.publisher_tool, 'npm@10.9.2');
  assert.deepEqual(parsed.maintainers, [
    { name: 'jasonsaayman', email: 'jasonsaayman@gmail.com' },
    { name: 'emilyemorehouse', email: 'emily@example.com' },
  ]);
  assert.equal(parsed.publish_method, 'unknown');
  assert.equal(parsed.provenance_present, false);
  assert.equal(parsed.provenance_details, null);
  assert.equal(parsed.has_install_scripts, false);
  assert.equal(parsed.source_repo_url, 'git+https://github.com/axios/axios.git');
  assert.equal(parsed.license, null);
  assert.equal(parsed.files.length, 1);
  assert.equal(parsed.files[0].filename, 'axios-1.7.9.tgz');
  assert.equal(parsed.files[0].content_hash, 'f05076f19e0b9f60b8f1b7a8a7f5a0a00fedf22d');
});

test('scoped name survives intact', () => {
  const v = axiosVersion({
    name: '@babel/core',
    dist: {
      shasum: 'abc',
      tarball: 'https://registry.npmjs.org/@babel/core/-/core-7.24.0.tgz',
    },
  });
  const parsed = parseVersion('7.24.0', v, '2024-03-01T00:00:00.000Z');
  assert.equal(parsed.files[0].filename, 'core-7.24.0.tgz');
  assert.match(parsed.files[0].url, /@babel\/core\/-\/core-7\.24\.0\.tgz$/);
});

test('has_install_scripts: scripts.preinstall truthy → true', () => {
  const v = axiosVersion({ scripts: { preinstall: 'node setup.js' } });
  const parsed = parseVersion('1.7.9', v, null);
  assert.equal(parsed.has_install_scripts, true);
});

test('has_install_scripts: scripts.install truthy → true', () => {
  const v = axiosVersion({ scripts: { install: 'make' } });
  assert.equal(parseVersion('1.7.9', v, null).has_install_scripts, true);
});

test('has_install_scripts: scripts.postinstall truthy → true', () => {
  const v = axiosVersion({ scripts: { postinstall: 'echo done' } });
  assert.equal(parseVersion('1.7.9', v, null).has_install_scripts, true);
});

test('has_install_scripts: only test script → false', () => {
  const v = axiosVersion({ scripts: { test: 'mocha' } });
  assert.equal(parseVersion('1.7.9', v, null).has_install_scripts, false);
});

test('provenance: dist.attestations present → oidc + true', () => {
  const v = axiosVersion({
    dist: {
      ...axiosVersion().dist,
      attestations: { url: 'https://.../provenance', provenance: { /*...*/ } },
    },
  });
  const parsed = parseVersion('1.7.9', v, null);
  assert.equal(parsed.publish_method, 'oidc');
  assert.equal(parsed.provenance_present, true);
  assert.ok(parsed.provenance_details);
});

test('provenance: dist.signatures only → unknown (Python parity)', () => {
  const v = axiosVersion({
    dist: {
      ...axiosVersion().dist,
      signatures: [{ keyid: '...', sig: '...' }],
    },
  });
  const parsed = parseVersion('1.7.9', v, null);
  assert.equal(parsed.publish_method, 'unknown');
  assert.equal(parsed.provenance_present, false);
  assert.equal(parsed.provenance_details, null);
});

test('bundledDependencies as list is preserved', () => {
  const v = axiosVersion({ bundledDependencies: ['foo', 'bar'] });
  const parsed = parseVersion('1.7.9', v, null);
  assert.deepEqual(parsed.bundled_dependencies, ['foo', 'bar']);
  assert.equal(parsed.bundled_dependency_count, 2);
});

test('bundleDependencies (alt spelling) as dict preserved', () => {
  const v = axiosVersion({ bundleDependencies: { foo: '1.0', bar: '2.0' } });
  const parsed = parseVersion('1.7.9', v, null);
  assert.deepEqual(Object.keys(parsed.bundled_dependencies).sort(), ['bar', 'foo']);
  assert.equal(parsed.bundled_dependency_count, 2);
});

test('bundledDependencies=false → null (drop bool)', () => {
  const v = axiosVersion({ bundledDependencies: false });
  const parsed = parseVersion('1.7.9', v, null);
  assert.equal(parsed.bundled_dependencies, null);
  assert.equal(parsed.bundled_dependency_count, 0);
});

test('gitHead capped at 64 chars', () => {
  const v = axiosVersion({ gitHead: 'a'.repeat(200) });
  assert.equal(parseVersion('1.7.9', v, null).git_head.length, 64);
});

test('repository as string falls back to string URL', () => {
  const v = axiosVersion({ repository: 'https://github.com/foo/bar' });
  assert.equal(parseVersion('1.7.9', v, null).source_repo_url, 'https://github.com/foo/bar');
});

test('missing dist → content_hash null, empty files', () => {
  const v = axiosVersion();
  delete v.dist;
  const parsed = parseVersion('1.7.9', v, null);
  assert.equal(parsed.content_hash, null);
  assert.equal(parsed.integrity_hash, null);
  assert.equal(parsed.files.length, 0);
});

test('non-object version entry → null', () => {
  assert.equal(parseVersion('1.0.0', null, null), null);
  assert.equal(parseVersion('1.0.0', 'not an object', null), null);
});

test('parseVersionsFromPackument walks all versions in iteration order', () => {
  const packument = {
    name: 'axios',
    'dist-tags': { latest: '1.7.9' },
    versions: {
      '1.7.8': axiosVersion({ version: '1.7.8' }),
      '1.7.9': axiosVersion({ version: '1.7.9' }),
    },
    time: {
      '1.7.8': '2024-10-01T00:00:00.000Z',
      '1.7.9': '2024-12-23T00:00:00.000Z',
    },
  };
  const parsed = parseVersionsFromPackument(packument);
  assert.equal(parsed.length, 2);
  assert.equal(parsed[0].version, '1.7.8');
  assert.equal(parsed[0].published_at, '2024-10-01T00:00:00.000Z');
  assert.equal(parsed[1].version, '1.7.9');
});

test('parseVersionsFromPackument on empty packument → []', () => {
  assert.deepEqual(parseVersionsFromPackument({}), []);
  assert.deepEqual(parseVersionsFromPackument(null), []);
  assert.deepEqual(parseVersionsFromPackument({ versions: {} }), []);
});
