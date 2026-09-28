// CFT-04 — the registry-to-candidate adapter: raw packument fields -> normalised candidate fields.
//
// WHY THIS IS TESTED SEPARATELY. The 152,804-candidate fixture pack supplies candidate fields that are
// ALREADY normalised — the producer derived them. Passing that pack proves the evaluator agrees about
// findings; it proves nothing whatever about the adapter that turns a live packument into those fields.
// A reader that folded e-mail case differently, or hashed maintainers in a different canonical order,
// would still score 152,804/152,804 and be wrong on the first real release.
//
// So this module is exercised by fixed input -> normalised-value/digest vectors generated from the
// producer's own normalisation (collector/witness_norm.py, tools/seedgen/witness.py) — see
// make_vectors.py and vectors.json. Three of my first guesses were wrong and the vectors caught all
// three: the domain separator is a NEWLINE (not NUL), the kind labels are `email`/`tuple`, and Python
// uses casefold() rather than lower().
import { readFileSync } from 'node:fs';

import crypto from 'node:crypto';

const IDENTITY_DOMAIN_SEP = 'chaingate-seed-v3/identity/1';

const sha256Hex = (s) => crypto.createHash('sha256').update(s, 'utf8').digest('hex');
const md5Hex = (s) => crypto.createHash('md5').update(s, 'utf8').digest('hex');

/**
 * Domain-separated unkeyed digest, matching `witness._sha256`: the separator constant, then for EACH
 * part a newline followed by that part.  sha256(SEP + "\n" + p1 + "\n" + p2 + ...)
 */
function domainDigest(...parts) {
  let msg = IDENTITY_DOMAIN_SEP;
  for (const p of parts) msg += `\n${p}`;
  return sha256Hex(msg);
}

// Unicode semantics come from CPython, as generated tables — not from toLowerCase()/trim(), which
// disagree with Python in BOTH directions and produced wrong identity digests:
//   U+03C2 final sigma   casefold -> sigma      toLowerCase -> itself
//   U+13A0 Cherokee      casefold -> itself     toLowerCase -> the U+AB70 block
//   U+0085 NEL           str.strip() removes it   JS trim() does not
//   U+FEFF BOM           str.strip() keeps it     JS trim() removes it
// See make_unicode_tables.py.
const TABLES = JSON.parse(readFileSync(new URL('./unicode-tables.json', import.meta.url), 'utf8'));
const CASEFOLD = new Map(Object.entries(TABLES.casefold).map(([hex, to]) => [Number.parseInt(hex, 16), to]));
const LOWER = new Map(Object.entries(TABLES.lower).map(([hex, to]) => [Number.parseInt(hex, 16), to]));
const PY_SPACE = new Set(TABLES.python_whitespace.map((hex) => Number.parseInt(hex, 16)));
const PRINTABLE_RANGES = TABLES.printable_ranges;
const UNICODE_VERSION = TABLES.unicode_version;
const SIGMA_CASED = TABLES.final_sigma.cased_ranges;
const SIGMA_IGNORABLE = TABLES.final_sigma.case_ignorable_ranges;

/** Is `cp` inside one of these sorted, disjoint [lo, hi] ranges? Binary search. */
function inRanges(ranges, cp) {
  let lo = 0; let hi = ranges.length - 1;
  while (lo <= hi) {
    const mid = (lo + hi) >> 1;
    const [a, b] = ranges[mid];
    if (cp < a) hi = mid - 1;
    else if (cp > b) lo = mid + 1;
    else return true;
  }
  return false;
}

/** Python's str.isprintable(); repr() escapes everything this rejects. Ranges, binary-searched. */
const pyIsPrintable = (cp) => inRanges(PRINTABLE_RANGES, cp);

// str.lower() is NOT a per-character map. CPython's lower_ucs4() special-cases U+03A3 CAPITAL SIGMA
// and decides between U+03C2 FINAL SIGMA and U+03C3 SMALL SIGMA from the characters AROUND it, so
// Greek "OS" lowercases with a FINAL sigma and a table-only implementation hashes every word ending
// in sigma differently from the producer. The two context classes are generated from CPython by
// observation (see make_unicode_tables.py); `cased` there already means stop-and-cased, because the
// case-ignorable skip is applied first.
const CAPITAL_SIGMA = 0x03a3;
const SMALL_SIGMA = '\u03c3';
const FINAL_SIGMA = '\u03c2';

/** CPython handle_capital_sigma(): skip case-ignorable outward in both directions, then require a
 *  Cased character before and none after. */
function capitalSigmaAt(cps, i) {
  let j = i - 1;
  while (j >= 0 && inRanges(SIGMA_IGNORABLE, cps[j].codePointAt(0))) j -= 1;
  let final = j >= 0 && inRanges(SIGMA_CASED, cps[j].codePointAt(0));
  if (final) {
    let k = i + 1;
    while (k < cps.length && inRanges(SIGMA_IGNORABLE, cps[k].codePointAt(0))) k += 1;
    final = k === cps.length || !inRanges(SIGMA_CASED, cps[k].codePointAt(0));
  }
  return final ? FINAL_SIGMA : SMALL_SIGMA;
}

/** Python's str.lower(): the generated table, plus the one contextual rule. Not casefold, and not
 *  blindly toLowerCase. Iterates CODE POINTS, as CPython does. */
function pyLower(s) {
  const cps = Array.from(s);
  let out = '';
  for (let i = 0; i < cps.length; i += 1) {
    const cp = cps[i].codePointAt(0);
    if (cp === CAPITAL_SIGMA) { out += capitalSigmaAt(cps, i); continue; }
    const l = LOWER.get(cp);
    out += l === undefined ? cps[i] : l;
  }
  return out;
}

/** Python's str.split() with no argument: split on runs of PYTHON whitespace, drop empties.
 *  JS \s includes U+FEFF and excludes U+0085; Python's set is the other way round, so a script body
 *  containing either hashed differently on the two sides. */
function pySplitWhitespace(s) {
  const out = [];
  let cur = '';
  for (const ch of s) {
    if (PY_SPACE.has(ch.codePointAt(0))) {
      if (cur) { out.push(cur); cur = ''; }
    } else cur += ch;
  }
  if (cur) out.push(cur);
  return out;
}

/** Python's str.casefold(), by table. Never toLowerCase(). */
function casefold(s) {
  let out = '';
  for (const ch of s) {
    const folded = CASEFOLD.get(ch.codePointAt(0));
    out += folded === undefined ? ch : folded;
  }
  return out;
}

/** Python's str.strip() — its whitespace set, not JavaScript's. */
function pyStrip(s) {
  const cps = Array.from(s);
  let i = 0; let j = cps.length;
  while (i < j && PY_SPACE.has(cps[i].codePointAt(0))) i += 1;
  while (j > i && PY_SPACE.has(cps[j - 1].codePointAt(0))) j -= 1;
  return cps.slice(i, j).join('');
}

/** Compare by Unicode CODE POINT, the way Python orders strings. JavaScript's `<` compares UTF-16
 *  code units, so an astral character (U+10000 -> D800 DC00) sorts BEFORE U+E000 there and after it
 *  in Python — which silently reorders a maintainer set and changes its digest. */
function cmpCodePoints(a, b) {
  const x = Array.from(a); const y = Array.from(b);
  const n = Math.min(x.length, y.length);
  for (let i = 0; i < n; i += 1) {
    const d = x[i].codePointAt(0) - y[i].codePointAt(0);
    if (d !== 0) return d < 0 ? -1 : 1;
  }
  return x.length === y.length ? 0 : (x.length < y.length ? -1 : 1);
}

/** strip + casefold; empty / whitespace-only -> null (absent, i.e. incomparable). */
function normEmail(email) {
  if (typeof email !== 'string') return null;
  const e = casefold(pyStrip(email));
  return e || null;
}

function emailDomain(email) {
  const e = normEmail(email);
  if (!e || !e.includes('@')) return null;
  const d = pyStrip(e.slice(e.lastIndexOf('@') + 1));
  return d || null;
}

/** strip + casefold, matching `(publisher_name or "").strip().casefold()`. */
function normName(name) {
  return typeof name === 'string' ? casefold(pyStrip(name)) : '';
}

function identityDigest(publisherEmail) {
  const e = normEmail(publisherEmail);
  return e ? domainDigest('email', e) : null;
}

function tupleDigest(publisherName, publisherEmail) {
  const e = normEmail(publisherEmail);
  const n = normName(publisherName);
  if (!e && !n) return null;
  return domainDigest('tuple', n, e || '');
}

const isPlainObject = (m) => m !== null && typeof m === 'object' && !Array.isArray(m);

// Python's `json.dumps` defaults to ensure_ascii=True, so it escapes EVERY non-ASCII character as
// \uXXXX while JSON.stringify emits it raw. The maintainer digest hashes that JSON, so a maintainer
// named "Ünïcode" hashed differently on each side — a divergence on the MAIN path that the fixture
// pack could never expose, because its candidate digests are already normalised.
const JSON_ESC = { '"': '\\"', '\\': '\\\\', '\n': '\\n', '\r': '\\r', '\t': '\\t', '\b': '\\b', '\f': '\\f' };

function pyJsonString(str) {
  let out = '"';
  for (let i = 0; i < str.length; i += 1) {
    const ch = str[i];
    const code = str.charCodeAt(i);
    if (JSON_ESC[ch] !== undefined) out += JSON_ESC[ch];
    else if (code < 0x20 || code > 0x7e) out += `\\u${code.toString(16).padStart(4, '0')}`;
    else out += ch;
  }
  return `${out}"`;
}

/** json.dumps(value, separators=(",", ":")) for JSON-shaped values, ensure_ascii included. */
function pyJsonDumps(value) {
  if (value === null) return 'null';
  if (typeof value === 'boolean') return value ? 'true' : 'false';
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) throw new NonPortableInput(`non-finite number in canonical JSON: ${value}`);
    return Number.isInteger(value) ? String(value) : String(value);
  }
  if (typeof value === 'string') return pyJsonString(value);
  if (Array.isArray(value)) return `[${value.map(pyJsonDumps).join(',')}]`;
  throw new NonPortableInput(`unsupported value in canonical JSON: ${typeof value}`);
}

/** Python's str(): the string ITSELF for a string, repr() for everything else. */
function pyStr(v) { return typeof v === 'string' ? v : pyRepr(v); }

/** Python's repr() for JSON-shaped values — needed only by the maintainer fallback path. */
function pyRepr(v) {
  if (v === null) return 'None';
  if (typeof v === 'boolean') return v ? 'True' : 'False';
  if (typeof v === 'number') {
    // Unrepresentable, not merely awkward: JSON.parse gives the same Number for `1` and `1.0`, whose
    // Python reprs are '1' and '1.0'. Nothing downstream can recover which was written, so this
    // refuses by name rather than pick one and hash it.
    throw new NonPortableInput(
      `a number (${v}) in a repr-hashed maintainer set is ambiguous: Python distinguishes int 1 from `
      + 'float 1.0 and JavaScript does not, so the repr cannot be reproduced');
  }
  if (typeof v === 'string') {
    // Python prefers single quotes, switching to double only when the string has ' and no ".
    const useDouble = v.includes("'") && !v.includes('"');
    const q = useDouble ? '"' : "'";
    let out = q;
    for (const ch of v) {
      const code = ch.codePointAt(0);
      if (ch === '\\') out += '\\\\';
      else if (ch === q) out += `\\${q}`;
      else if (ch === '\n') out += '\\n';
      else if (ch === '\r') out += '\\r';
      else if (ch === '\t') out += '\\t';
      else if (!pyIsPrintable(code)) {
        // repr escapes every non-printable character: \xXX, \uXXXX or \UXXXXXXXX by width.
        if (code < 0x100) out += `\\x${code.toString(16).padStart(2, '0')}`;
        else if (code < 0x10000) out += `\\u${code.toString(16).padStart(4, '0')}`;
        else out += `\\U${code.toString(16).padStart(8, '0')}`;
      } else out += ch;
    }
    return out + q;
  }
  if (Array.isArray(v)) return `[${v.map(pyRepr).join(', ')}]`;
  if (isPlainObject(v)) {
    // JavaScript reorders integer-like own keys ahead of the rest, in ascending numeric order, while
    // a Python dict preserves insertion order — and after JSON.parse the original order is already
    // gone. `{'2': 'b', '1': 'a'}` therefore cannot be repr'd faithfully by any JS implementation.
    const keys = Object.keys(v);
    if (keys.some((k) => /^(0|[1-9][0-9]*)$/.test(k))) {
      throw new NonPortableInput(
        'a repr-hashed maintainer object has integer-like keys; JavaScript reorders those and the '
        + "original insertion order is unrecoverable, so Python's repr cannot be reproduced");
    }
    return `{${keys.map((k) => `${pyRepr(k)}: ${pyRepr(v[k])}`).join(', ')}}`;
  }
  throw new NonPortableInput(`unsupported value in repr: ${typeof v}`);
}

/**
 * Not portable in one corner, and it REFUSES there rather than diverging. When no entry carries a
 * string `name`, the producer falls back to md5 over `sorted(str(m) for m in maintainers)` — Python's
 * repr for a dict, which JavaScript cannot reproduce. For a list of STRINGS that repr IS the string,
 * so that case is implemented exactly; any other shape throws. Emitting a digest there would be worse
 * than refusing: it would silently disagree with the producer on identity.
 */
class NonPortableInput extends Error {
  constructor(message) { super(message); this.name = 'NonPortableInput'; }
}

/** [digest, count]. md5 over the sorted, normed (name, email) pairs; '' for empty/absent. */
function maintainersDigest(maintainers) {
  if (!Array.isArray(maintainers) || maintainers.length === 0) return ['', 0];
  const pairs = [];
  let count = 0;
  for (const m of maintainers) {
    if (isPlainObject(m) && (m.name || m.email)) count += 1;
    if (isPlainObject(m) && typeof m.name === 'string') {
      pairs.push([normName(m.name), normEmail(m.email) || '']);
    }
  }
  if (pairs.length === 0) {
    // The producer hashes md5(json.dumps(sorted(str(m) for m in maintainers))). `str` is Python's
    // repr, reproduced here for JSON-shaped values and REFUSED for anything whose repr this adapter
    // cannot derive (non-integer numbers, control characters) — refusing beats diverging on identity.
    const reprs = maintainers.map(pyStr).sort(cmpCodePoints);
    return [md5Hex(pyJsonDumps(reprs)), count];
  }
  pairs.sort((a, b) => cmpCodePoints(a[0], b[0]) || cmpCodePoints(a[1], b[1]));
  return [md5Hex(pyJsonDumps(pairs)), count];
}

/** [has_body, digest] over install+preinstall+postinstall, lowered, whitespace-collapsed, md5. */
function installBodyDigest(install, preinstall, postinstall) {
  const body = `${install || ''}${preinstall || ''}${postinstall || ''}`;
  // `" ".join(body.lower().split())` — Python's lower and Python's whitespace, not JavaScript's.
  const norm = pySplitWhitespace(pyLower(body)).join(' ');
  return norm ? [1, md5Hex(norm)] : [0, ''];
}

const FREE_WEBMAIL = new Set(['gmail.com', 'googlemail.com', 'yahoo.com', 'yahoo.co.uk', 'hotmail.com',
  'outlook.com', 'live.com', 'icloud.com', 'me.com', 'aol.com']);
const PRIVACY = new Set(['protonmail.com', 'protonmail.ch', 'protonmail.me', 'pm.me', 'proton.me',
  'tutanota.com', 'tutanota.de', 'tuta.io', 'guerrillamail.com']);
const MIN_VERIFIED_VERSIONS = 2;

/** Runtime precedence: unknown > privacy > free-webmail > verified-corporate > unverified. */
function providerClass(domain, domainVersionCount) {
  if (domain === null || domain === undefined) return 'unknown';
  if (PRIVACY.has(domain)) return 'privacy';
  if (FREE_WEBMAIL.has(domain)) return 'free-webmail';
  return domainVersionCount >= MIN_VERIFIED_VERSIONS ? 'verified-corporate' : 'unverified';
}

// Python's \d is the Unicode Nd category, so `v\u0663.0.0` (ARABIC-INDIC THREE) matches there and the
// ASCII-only JS \d returned '' — a different node_major for the same input.
const NODE_MAJOR_RE = /^v?(\p{Nd}+)/u;
function nodeMajor(publishedWithNodeVersion) {
  const m = NODE_MAJOR_RE.exec(publishedWithNodeVersion || '');
  return m ? m[1] : '';
}

export {
  IDENTITY_DOMAIN_SEP, sha256Hex, md5Hex, domainDigest, casefold, pyStrip, cmpCodePoints,
  UNICODE_VERSION,
  normEmail, emailDomain, normName, identityDigest, tupleDigest, maintainersDigest,
  pyLower, pySplitWhitespace, pyIsPrintable,
  pyJsonDumps, pyJsonString, pyRepr, pyStr,
  installBodyDigest, providerClass, nodeMajor,
  FREE_WEBMAIL, PRIVACY, MIN_VERIFIED_VERSIONS, NonPortableInput,
};


// A default export as well: the consumer is used both as `import R from` and
// `import { verify } from`, and the runtime package is ESM.
export default { IDENTITY_DOMAIN_SEP, sha256Hex, md5Hex, domainDigest, casefold, pyStrip,
  cmpCodePoints, UNICODE_VERSION, normEmail, emailDomain, normName, identityDigest, tupleDigest,
  maintainersDigest, pyLower, pySplitWhitespace, pyIsPrintable, pyJsonDumps, pyJsonString,
  pyRepr, pyStr, installBodyDigest, providerClass, nodeMajor, FREE_WEBMAIL, PRIVACY,
  MIN_VERIFIED_VERSIONS, NonPortableInput
};