// Extracts normalized VersionMetadata from an npm packument.
//
// This parser must stay byte-for-byte equivalent to
// collector/sources/npm.py::_parse_single_version so seed baselines (written
// by the Python collector on the VPS) compare cleanly against proxy-observed
// baselines (written by this module at install time). Every field here
// mirrors a field in the Python parser. Don't add fields here without
// mirroring them there, and vice versa.

const MAINTAINER_FIELD_CAP = 200;
const GIT_HEAD_CAP = 64;
const PUBLISHER_TOOL_CAP = 80;
const URL_CAP = 500;
const FILENAME_CAP = 500;
const TARBALL_URL_CAP = 1000;

function isPlainObject(v) {
  return v != null && typeof v === 'object' && !Array.isArray(v);
}

function trim(value, limit) {
  if (typeof value !== 'string') return null;
  const s = value.trim();
  return s ? s.slice(0, limit) : null;
}

function normalizeMaintainers(value) {
  if (!Array.isArray(value) || value.length === 0) return null;
  const out = [];
  for (const m of value) {
    if (!isPlainObject(m)) continue;
    const entry = {};
    if (typeof m.name === 'string' && m.name) {
      entry.name = m.name.slice(0, MAINTAINER_FIELD_CAP);
    }
    if (typeof m.email === 'string' && m.email) {
      entry.email = m.email.slice(0, MAINTAINER_FIELD_CAP);
    }
    if (entry.name || entry.email) out.push(entry);
  }
  return out.length ? out : null;
}

function normalizeTool(npmVersion) {
  if (typeof npmVersion !== 'string') return null;
  const stripped = npmVersion.trim();
  if (!stripped) return null;
  return `npm@${stripped.slice(0, PUBLISHER_TOOL_CAP)}`;
}

function normalizeBundled(value) {
  if (Array.isArray(value) && value.length > 0) return value;
  if (isPlainObject(value) && Object.keys(value).length > 0) return value;
  return null;
}

function bundledCount(value) {
  if (Array.isArray(value)) return value.length;
  if (isPlainObject(value)) return Object.keys(value).length;
  return 0;
}

function extractRepoUrl(repo) {
  if (repo == null) return null;
  if (typeof repo === 'string') return repo.slice(0, URL_CAP);
  if (isPlainObject(repo) && typeof repo.url === 'string') {
    return repo.url.slice(0, URL_CAP);
  }
  return null;
}

function hasAnyInstallScript(scripts) {
  if (!isPlainObject(scripts)) return false;
  return Boolean(scripts.preinstall || scripts.install || scripts.postinstall);
}

function synthesizeFiles(dist, publishedAt) {
  const tarball = typeof dist.tarball === 'string' ? dist.tarball : null;
  if (!tarball) return [];
  const idx = tarball.lastIndexOf('/');
  const filename = idx >= 0 ? tarball.slice(idx + 1) : tarball;
  return [
    {
      filename: filename.slice(0, FILENAME_CAP),
      packagetype: 'tarball',
      content_hash: typeof dist.shasum === 'string' ? dist.shasum : null,
      content_hash_algo: typeof dist.shasum === 'string' ? 'sha1' : null,
      size_bytes: typeof dist.unpackedSize === 'number' ? dist.unpackedSize : null,
      uploaded_at: publishedAt ?? null,
      url: tarball.slice(0, TARBALL_URL_CAP),
    },
  ];
}

/**
 * Parse one (versionString, versionObject) pair from a packument.
 * @returns {object|null} VersionMetadata (same shape Python collector emits), or null
 */
export function parseVersion(versionStr, versionObj, publishedAt) {
  if (!isPlainObject(versionObj)) return null;
  const dist = isPlainObject(versionObj.dist) ? versionObj.dist : {};
  const dependencies = isPlainObject(versionObj.dependencies) ? versionObj.dependencies : {};
  const devDeps = isPlainObject(versionObj.devDependencies) ? versionObj.devDependencies : {};
  const peerDeps = isPlainObject(versionObj.peerDependencies) ? versionObj.peerDependencies : {};
  const optDeps = isPlainObject(versionObj.optionalDependencies)
    ? versionObj.optionalDependencies
    : {};
  const bundledRaw =
    versionObj.bundledDependencies ?? versionObj.bundleDependencies ?? null;
  const scripts = isPlainObject(versionObj.scripts) ? versionObj.scripts : {};
  const npmUser = isPlainObject(versionObj._npmUser) ? versionObj._npmUser : {};
  const maintainersRaw = versionObj.maintainers;
  const attestations = isPlainObject(dist.attestations) ? dist.attestations : null;

  const devDepsSaved = Object.keys(devDeps).length > 0 ? devDeps : null;
  const peerDepsSaved = Object.keys(peerDeps).length > 0 ? peerDeps : null;
  const optDepsSaved = Object.keys(optDeps).length > 0 ? optDeps : null;
  const bundledSaved = normalizeBundled(bundledRaw);

  return {
    version: versionStr,
    published_at: publishedAt ?? null,
    content_hash: typeof dist.shasum === 'string' ? dist.shasum : null,
    content_hash_algo: typeof dist.shasum === 'string' ? 'sha1' : null,
    integrity_hash: typeof dist.integrity === 'string' ? dist.integrity : null,
    git_head: trim(versionObj.gitHead, GIT_HEAD_CAP),
    package_size_bytes: typeof dist.unpackedSize === 'number' ? dist.unpackedSize : null,

    dependency_count: Object.keys(dependencies).length,
    dependencies,
    dev_dependencies: devDepsSaved,
    peer_dependencies: peerDepsSaved,
    optional_dependencies: optDepsSaved,
    bundled_dependencies: bundledSaved,
    dev_dependency_count: Object.keys(devDeps).length,
    peer_dependency_count: Object.keys(peerDeps).length,
    optional_dependency_count: Object.keys(optDeps).length,
    bundled_dependency_count: bundledCount(bundledRaw),

    publisher_name: typeof npmUser.name === 'string' ? npmUser.name : null,
    publisher_email: typeof npmUser.email === 'string' ? npmUser.email : null,
    publisher_tool: normalizeTool(versionObj._npmVersion),
    maintainers: normalizeMaintainers(maintainersRaw),

    publish_method: attestations ? 'oidc' : 'unknown',
    provenance_present: Boolean(attestations),
    provenance_details: attestations,

    has_install_scripts: hasAnyInstallScript(scripts),
    source_repo_url: extractRepoUrl(versionObj.repository),
    license: null, // V1 parity: Python collector doesn't extract npm license yet

    files: synthesizeFiles(dist, publishedAt ?? null),
  };
}

/**
 * Parse every version entry in a packument.
 * @returns {Array<object>} VersionMetadata objects in packument iteration order
 */
export function parseVersionsFromPackument(packument) {
  if (!isPlainObject(packument)) return [];
  const versions = isPlainObject(packument.versions) ? packument.versions : {};
  const times = isPlainObject(packument.time) ? packument.time : {};
  const out = [];
  for (const [versionStr, versionObj] of Object.entries(versions)) {
    const parsed = parseVersion(versionStr, versionObj, times[versionStr] ?? null);
    if (parsed) out.push(parsed);
  }
  return out;
}
