// EXPERIMENTAL read layout `g10-rl1` (unpublished development runtime only). A seed MAY carry
// one DERIVED table beside its canonical relations, declared in seed_metadata (read_layout, read_layout_digest,
// read_layout_recipe). For every package with >= 1,000 lineages whose every lineage has exactly the five contract groups,
// one row holds the package's distinct verbatim initial_state texts (`dict`, first appearance: lineages by ord, groups by
// grp) and, per lineage in ord order, [lineage_id, index per group] (`idx`). The canonical relations are unchanged and stay
// authoritative: verify() re-derives the whole table from them (selection, every lineage, every group, verbatim text) and
// checks the declared digest and recipe; a declared layout that is missing, unknown, partial, corrupt or inconsistent
// refuses the seed. A seed without the declaration is read exactly as before (legacy reader behaviour).
import { createHash } from 'node:crypto';

const RL1 = 'g10-rl1';
const RL1_TABLE = 'lineage_initial_rl1';
const RL1_COLUMNS = ['package_id', 'n_lineages', 'groups', 'dict', 'idx'];
const RL1_GROUPS = Object.freeze(['deps', 'git', 'install', 'provenance', 'publisher']);   // grp (primary-key) order
const RL1_MIN_LINEAGES = 1000;
// byte-exact the producer's recipe text (tools/seedgen/read_layout.py RECIPE, json separators (',', ':'))
const RL1_RECIPE = '{"id":"g10-rl1","table":"lineage_initial_rl1","source":"lineage_state (verbatim initial_state text)",'
  + '"rule":"packages with >= 1000 lineages whose every lineage has exactly the groups [\'deps\', \'git\', \'install\', \'provenance\', \'publisher\']",'
  + '"encoding":"dict = distinct texts in first appearance (lineages by ord, groups by grp); idx = [[lineage_id, i_deps, i_git, i_install, i_provenance, i_publisher]] by lineage ord",'
  + '"json":"separators (\',\', \':\'), ensure_ascii False"}';
const RL1_KEYS = ['read_layout', 'read_layout_digest', 'read_layout_recipe'];

class ReadLayoutError extends Error {
  constructor(message) { super(`read layout ${RL1}: ${message}`); this.name = 'ReadLayoutError'; }
}

/** The declared contents digest: per row (by package_id), each field as 8-byte big-endian length + UTF-8 text. */
function contentDigest(rows) {
  const h = createHash('sha256');
  for (const r of [...rows].sort((a, b) => a.package_id - b.package_id)) {
    for (const k of RL1_COLUMNS) {
      const b = Buffer.from(String(r[k]), 'utf8'); const n = Buffer.alloc(8); n.writeBigUInt64BE(BigInt(b.length));
      h.update(n); h.update(b);
    }
  }
  return h.digest('hex');
}

/** Decodes one stored row against the package's lineage ids (ord order). Throws ReadLayoutError on any inconsistency. */
function decodeRow(d, lineageIds) {
  let groups; let texts; let idx;
  try { groups = JSON.parse(d.groups); texts = JSON.parse(d.dict); idx = JSON.parse(d.idx); } catch (e) {
    throw new ReadLayoutError(`package ${d.package_id}: undecodable row (${e.message})`);
  }
  if (!Array.isArray(groups) || groups.length !== RL1_GROUPS.length || groups.some((g, i) => g !== RL1_GROUPS[i])) {
    throw new ReadLayoutError(`package ${d.package_id}: groups ${JSON.stringify(groups)}`);
  }
  if (!Array.isArray(texts) || texts.some((t) => typeof t !== 'string')) throw new ReadLayoutError(`package ${d.package_id}: dict is not an array of texts`);
  if (!Array.isArray(idx) || d.n_lineages !== lineageIds.length || idx.length !== lineageIds.length) {
    throw new ReadLayoutError(`package ${d.package_id}: ${idx?.length} entries / n_lineages ${d.n_lineages} for ${lineageIds.length} lineages`);
  }
  for (let i = 0; i < idx.length; i += 1) {
    const x = idx[i];
    if (!Array.isArray(x) || x.length !== RL1_GROUPS.length + 1 || x[0] !== lineageIds[i]
      || x.slice(1).some((j) => !Number.isInteger(j) || j < 0 || j >= texts.length)) {
      throw new ReadLayoutError(`package ${d.package_id}: entry ${i} ${JSON.stringify(x)} (lineage ${lineageIds[i]})`);
    }
  }
  return { groups, texts, idx };
}

/** verify(): null when the seed declares no read layout (legacy), else true or the reason it is refused. */
// `partial` (since 0.1.6, a seed cache holding only some buckets): the rows held are checked against the rule and lineage_state,
// over the packages held; the whole-seed digest is not, since it covers buckets the cache does not hold (each held bucket's rows
// were checked against its own rl1_digest from the signed root).
function verifyReadLayout(db, raw, tables, { partial = false } = {}) {
  const declared = RL1_KEYS.filter((k) => k in raw);
  if (!declared.length) return null;
  if (declared.length !== RL1_KEYS.length) return `partial read-layout declaration (${declared.join(', ')})`;
  if (raw.read_layout !== RL1) return `unknown read layout ${JSON.stringify(raw.read_layout)}; this reader implements ${RL1}`;
  if (raw.read_layout_recipe !== RL1_RECIPE) return 'read_layout_recipe differs from this reader\'s g10-rl1 recipe';
  if (!tables.has(RL1_TABLE) && !partial) return `declared ${RL1} but table ${RL1_TABLE} is missing`;
  try {
    let rows = [];
    if (tables.has(RL1_TABLE)) {
      const cols = db.prepare(`PRAGMA table_info(${RL1_TABLE})`).all().map((r) => r.name);
      if (cols.join(',') !== RL1_COLUMNS.join(',')) return `${RL1_TABLE} columns ${JSON.stringify(cols)}`;
      rows = db.prepare(`SELECT ${RL1_COLUMNS.join(', ')} FROM ${RL1_TABLE} ORDER BY package_id`).all();
    }
    if (!partial && contentDigest(rows) !== raw.read_layout_digest) return 'read_layout_digest differs from the table contents';
    const want = db.prepare('SELECT package_id FROM lineages GROUP BY package_id HAVING count(*) >= ? ORDER BY package_id')
      .pluck().all(RL1_MIN_LINEAGES).filter((pid) => db.prepare(
        'SELECT count(*) FROM (SELECT l.id FROM lineages l LEFT JOIN lineage_state s ON s.lineage_id = l.id WHERE l.package_id = ? '
        + 'GROUP BY l.id HAVING count(s.grp) != 5 OR sum(s.grp IN (?,?,?,?,?)) != 5)').pluck().get(pid, ...RL1_GROUPS) === 0);
    const got = rows.map((r) => r.package_id);
    if (got.join(',') !== want.join(',')) return `selection ${JSON.stringify(got)} differs from the rule ${JSON.stringify(want)}`;
    const qL = db.prepare('SELECT id FROM lineages WHERE package_id = ? ORDER BY ord').pluck();
    const qS = db.prepare('SELECT s.grp, s.initial_state FROM lineages l JOIN lineage_state s ON s.lineage_id = l.id '
      + 'WHERE l.package_id = ? ORDER BY l.ord, s.grp').raw(true);
    for (const r of rows) {
      const { groups, texts, idx } = decodeRow(r, qL.all(r.package_id));
      const canon = qS.all(r.package_id);
      if (canon.length !== idx.length * groups.length) return `package ${r.package_id}: ${canon.length} canonical state rows`;
      let k = 0;
      for (const x of idx) {
        for (let g = 0; g < groups.length; g += 1, k += 1) {
          if (canon[k][0] !== groups[g] || canon[k][1] !== texts[x[g + 1]]) return `package ${r.package_id} lineage ${x[0]} ${groups[g]}: differs from lineage_state`;
        }
      }
    }
  } catch (e) { return e instanceof ReadLayoutError ? e.message : `${e.name}: ${e.message}`; }
  return true;
}

export { RL1, RL1_TABLE, RL1_COLUMNS, RL1_GROUPS, RL1_MIN_LINEAGES, RL1_RECIPE, RL1_KEYS, ReadLayoutError, contentDigest, decodeRow, verifyReadLayout };
export default { RL1, RL1_TABLE, RL1_COLUMNS, RL1_GROUPS, RL1_MIN_LINEAGES, RL1_RECIPE, RL1_KEYS, ReadLayoutError, contentDigest, decodeRow, verifyReadLayout };
