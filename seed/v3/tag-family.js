// The prerelease tag family (collector/drift_cooccurrence.py tag_family, pinned by lineage-tag-family-cases-0.2): one
// definition for the seed's rl2 placement (seed/v3/gate.js) and the install-time lineage predecessor
// (gates/lineage-predecessor.js). Since 0.1.6, with `platforms` (pinned by lineage-tag-family-cases-0.3): the family of a
// contract 1.3 seed, which adds the prerelease's platform tokens.
export const RELEASE_FAMILY = 'release';
// the npm holding text the forward stub predicate excludes (collector/stub_recognition.py HOLDING_DESCRIPTION; name-hold
// texts are NOT excluded, as there)
export const HOLDING_DESCRIPTION = 'security holding package';
// Python's `$` also matches before a final newline, hence `\n?`
const HEX_ID_RE = /^[0-9a-f]{7,40}\n?$/;
const FAMILY_RE = /^[A-Za-z]+/;
// closed: a new token is a new fixture version
export const PLATFORM_TOKENS = new Set([
  'aarch64', 'aix', 'amd64', 'android', 'arm', 'arm64', 'armhf', 'armv6', 'armv6l', 'armv7', 'armv7l', 'cygwin',
  'darwin', 'freebsd', 'glibc', 'gnu', 'gnueabihf', 'ia32', 'ios', 'linux', 'loong64', 'mac', 'macos', 'mingw', 'mips',
  'mips64el', 'mipsel', 'msvc', 'musl', 'musleabihf', 'netbsd', 'ohos', 'openbsd', 'osx', 'ppc', 'ppc64', 'ppc64le',
  'riscv64', 's390', 's390x', 'sunos', 'universal', 'wasm32', 'win', 'win32', 'win64', 'windows', 'x64', 'x86']);

/**
 * The prerelease tag family: build metadata dropped; no "-" is release; a commit-hash or numeric-first tag is num. With
 * `platforms`, then "@" and the prerelease's platform tokens (split on "." and "-", lower-cased, each once in order of first
 * appearance, joined by "-") when it has any; release never gains a suffix.
 */
export function tagFamily(version, { platforms = false } = {}) {
  const v = String(version ?? '').split('+')[0];
  const dash = v.indexOf('-');
  if (dash < 0) return RELEASE_FAMILY;
  const pre = v.slice(dash + 1);
  const first = pre.split('.')[0];
  let fam;
  if (HEX_ID_RE.test(first) && /[0-9]/.test(first)) fam = 'num';
  else { const m = FAMILY_RE.exec(pre); fam = m ? m[0].toLowerCase() : 'num'; }
  if (!platforms) return fam;
  const plat = [...new Set(pre.split(/[.-]/).map((t) => t.toLowerCase()).filter((t) => PLATFORM_TOKENS.has(t)))];
  return plat.length ? `${fam}@${plat.join('-')}` : fam;
}
