// The seed LOGICAL digest, re-derived in JavaScript — mirrors `writer.logical_digest_of_db`.
//
// WHY IT EXISTS HERE. A fixture pack is bound to ONE seed. Checking only `corpus_snapshot_digest` and
// `rule_versions` is not that binding: two different builds of the same snapshot under the same rules
// share both, so a pack generated against a DIFFERENT seed passed parity. The manifest's
// `seed_logical_digest` is the exact identity, and a consumer that wants to trust the comparison has
// to RE-DERIVE it from the file rather than read it from the manifest that claims it.
//
// The digest is sha256 over, for each table in a fixed order, every row in primary-key order,
// serialised as json.dumps([table, [values...]], sort_keys=True, separators=(",",":"),
// ensure_ascii=False, default=bytes.hex), each followed by a newline.
import crypto from 'node:crypto';
import Database from 'better-sqlite3';

const TABLES_IN_DIGEST = ['packages', 'lineages', 'lineage_state', 'spine', 'events', 'dep_names',
  'known_malicious_pins', 'seed_metadata'];
const ORDER = {
  packages: 'id',
  lineages: 'id',
  lineage_state: 'lineage_id, grp',
  spine: 'lineage_id, ord',
  events: 'lineage_id, grp, ord',
  dep_names: 'package_id, name',
  known_malicious_pins: 'package_id, version, advisory_id',
  seed_metadata: 'key',
};

class NonPortableValue extends Error {
  constructor(message) { super(message); this.name = 'NonPortableValue'; }
}

// Python's json.dumps writes floats with repr(): shortest round-trip digits, but formatted by
// PYTHON's rules, which are not JavaScript's. Python switches to exponent notation outside
// 1e-4 <= |x| < 1e16 and always writes a fractional part; JavaScript switches outside
// 1e-6 <= |x| < 1e21 and drops ".0". So 1e16 is "1e+16" in Python and "10000000000000000" in JS, and
// 1001000.0 is "1001000.0" against "1001000". SQLite is dynamically typed and better-sqlite3 hands
// both integers and reals back as JS numbers, so the DECLARED column type decides which rule applies.
function pyFloat(v) {
  if (Number.isNaN(v)) throw new NonPortableValue('NaN in a REAL column: json.dumps would write NaN, which is not JSON');
  if (!Number.isFinite(v)) throw new NonPortableValue(`${v} in a REAL column: json.dumps would write Infinity, which is not JSON`);
  if (v === 0) return Object.is(v, -0) ? '-0.0' : '0.0';

  // toExponential() with no argument yields the minimal digits that uniquely identify the value —
  // the same shortest round-trip repr Python uses.
  const [mant, expStr] = v.toExponential().split('e');
  const exp = Number(expStr);
  const neg = mant.startsWith('-');
  const digits = mant.replace('-', '').replace('.', '');

  if (exp >= -4 && exp < 16) {                       // Python's fixed-notation window
    let out;
    if (exp >= digits.length - 1) {
      out = digits + '0'.repeat(exp - (digits.length - 1)) + '.0';
    } else if (exp >= 0) {
      out = `${digits.slice(0, exp + 1)}.${digits.slice(exp + 1)}`;
    } else {
      out = `0.${'0'.repeat(-exp - 1)}${digits}`;
    }
    return (neg ? '-' : '') + out;
  }
  // exponent notation: Python writes at least two exponent digits and an explicit sign
  const head = digits.length > 1 ? `${digits[0]}.${digits.slice(1)}` : digits[0];
  const sign = exp < 0 ? '-' : '+';
  const mag = String(Math.abs(exp)).padStart(2, '0');
  return `${neg ? '-' : ''}${head}e${sign}${mag}`;
}

// json.dumps(..., ensure_ascii=False): non-ASCII stays raw, so JSON.stringify agrees on strings.
function jsonValue(v, isReal) {
  if (v === null || v === undefined) return 'null';
  if (Buffer.isBuffer(v)) return JSON.stringify(v.toString('hex'));   // default=bytes.hex
  // Safe integers are ON for this connection, so a SQLite INTEGER arrives as a BigInt whenever it
  // does not fit a double. Python has unbounded ints and writes the exact value, so the BigInt is
  // serialised exactly rather than refused — refusing here would reject a seed Python digests fine.
  if (typeof v === 'bigint') return v.toString();
  if (typeof v === 'number') {
    if (isReal || !Number.isInteger(v)) return pyFloat(v);
    if (!Number.isSafeInteger(v)) {
      // Cannot happen with safe integers enabled; if it ever does, the value has already been
      // silently rounded by the driver and must not be digested as if it were exact.
      throw new NonPortableValue(`integer ${v} arrived as a rounded double; enable safe integers`);
    }
    return String(v);
  }
  if (typeof v === 'string') return JSON.stringify(v);
  throw new NonPortableValue(`unsupported column value of type ${typeof v}`);
}

/** sha256 over the canonical row serialisation. `db` may be a path or an open better-sqlite3 handle. */
function logicalDigestOfDb(dbOrPath) {
  const owned = typeof dbOrPath === 'string';
  const db = owned ? new Database(dbOrPath, { readonly: true, fileMustExist: true }) : dbOrPath;
  // Without this, better-sqlite3 silently rounds an INTEGER beyond 2^53-1 to a double — 9007199254740993
  // reads back as ...992 — and the digest would differ from Python's for a seed that is perfectly fine.
  db.defaultSafeIntegers(true);
  const h = crypto.createHash('sha256');
  try {
    for (const t of TABLES_IN_DIGEST) {
      const cols = db.prepare(`PRAGMA table_info(${t})`).all();
      const names = cols.map((c) => c.name);
      const real = new Set(cols.filter((c) => String(c.type).toUpperCase().includes('REAL')).map((c) => c.name));
      const stmt = db.prepare(`SELECT ${names.join(', ')} FROM ${t} ORDER BY ${ORDER[t]}`);
      stmt.raw(true);
      for (const row of stmt.iterate()) {
        const parts = row.map((v, i) => jsonValue(v, real.has(names[i])));
        h.update(`[${JSON.stringify(t)},[${parts.join(',')}]]\n`, 'utf8');
      }
    }
  } finally {
    if (owned) db.close(); else db.defaultSafeIntegers(false);   // leave a borrowed handle as found
  }
  return h.digest('hex');
}

export { logicalDigestOfDb, TABLES_IN_DIGEST, ORDER, pyFloat, jsonValue, NonPortableValue };


// A default export as well: the consumer is used both as `import R from` and
// `import { verify } from`, and the runtime package is ESM.
export default { logicalDigestOfDb, TABLES_IN_DIGEST, ORDER, pyFloat, jsonValue,
  NonPortableValue
};