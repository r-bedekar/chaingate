// Portable v3 evaluator — an INDEPENDENT native JavaScript implementation of detection contract v1.
// It computes findings itself from the shipped seed representation; it never calls Python and never
// reads an expected answer. Mirrors tools/seedgen/checker.py.
import K from './contract.js';

const SEED_BINDING_KEYS = ['corpus_snapshot_digest', 'contract_version', 'schema_version', 'history_cutoff'];

/** Python's dict.get(): a key that is absent and a key that is null are the same thing here. */
function g(obj, key) {
  const v = obj === null || obj === undefined ? undefined : obj[key];
  return v === undefined ? null : v;
}
const EVENT_ONLY_KEYS = new Set(['tool_version', 'added', 'removed']);
function stripEventOnly(after) {
  const out = {};
  for (const [k, v] of Object.entries(after)) if (!EVENT_ONLY_KEYS.has(k)) out[k] = v;
  return out;
}

class LineageView {
  constructor(row) { Object.assign(this, row); }

  /** Group state in force at `ord` — initial state REPLACED by each event of that group at ord <= ord. */
  stateAt(grp, ord) {
    let st = { ...this.initial[grp] };
    for (const e of this.events) if (e.grp === grp && e.ord <= ord) st = stripEventOnly(e.after);
    return st;
  }

  /** [[start_ord, start_published_s, state]] for every segment of `grp`, in order. */
  segmentStarts(grp) {
    const out = [[0, this.first_published_s, { ...this.initial[grp] }]];
    const evs = this.events.filter((e) => e.grp === grp).sort((a, b) => a.ord - b.ord);
    for (const e of evs) out.push([e.ord, e.published_s, stripEventOnly(e.after)]);
    return out;
  }

  get minSpineOrd() {
    const ords = [...this.spine.keys()];
    return ords.length ? Math.min(...ords) : null;
  }
}

function loadSeedMeta(db) {
  const meta = {};
  for (const r of db.prepare('SELECT key, value FROM seed_metadata').all()) meta[r.key] = r.value;
  const out = {};
  for (const k of SEED_BINDING_KEYS) if (k in meta) out[k] = meta[k];
  if ('rule_versions' in meta) {
    try { out.rule_versions = JSON.parse(meta.rule_versions); } catch { out.rule_versions = meta.rule_versions; }
  }
  return out;
}

function loadPackage(db, packageName, seedMeta) {
  const row = db.prepare('SELECT id, package_name FROM packages WHERE package_name = ?').get(packageName);
  if (!row) return null;
  const pv = { package_id: row.id, package_name: row.package_name, lineages: new Map(), seed_meta: seedMeta };
  const lrows = db.prepare(
    'SELECT id, lineage_key, n_versions, first_published_s, last_published_s FROM lineages WHERE package_id = ? ORDER BY ord',
  ).all(pv.package_id);
  const qState = db.prepare('SELECT grp, initial_state FROM lineage_state WHERE lineage_id = ?');
  const qEvents = db.prepare(
    'SELECT grp, ord, version, published_s, after_state FROM events WHERE lineage_id = ? ORDER BY ord, grp');
  const qSpine = db.prepare(
    'SELECT ord, version, published_s, size_bytes, tool_key, shasum, capture_class FROM spine WHERE lineage_id = ? ORDER BY ord');
  for (const l of lrows) {
    const initial = {};
    for (const s of qState.all(l.id)) initial[s.grp] = JSON.parse(s.initial_state);
    const events = qEvents.all(l.id).map((e) => ({
      grp: e.grp, ord: e.ord, version: e.version, published_s: e.published_s, after: JSON.parse(e.after_state),
    }));
    const spine = new Map();
    for (const s of qSpine.all(l.id)) {
      spine.set(s.ord, {
        version: s.version, published_s: s.published_s, size_bytes: s.size_bytes, tool_key: s.tool_key,
        shasum: Buffer.isBuffer(s.shasum) ? s.shasum.toString('hex') : s.shasum, capture_class: s.capture_class,
      });
    }
    pv.lineages.set(l.id, new LineageView({
      lineage_id: l.id, lineage_key: l.lineage_key, n_versions: l.n_versions,
      first_published_s: l.first_published_s, last_published_s: l.last_published_s, initial, events, spine,
    }));
  }
  return pv;
}

// ---------------------------------------------------------------------------
// Channel-A (FU-2 lineage predecessor)
// ---------------------------------------------------------------------------
function channelA(pv, c) {
  const lv = pv.lineages.get(c.lineage_id) || null;
  const groups = {}; const constituents = {};
  let predVersion = null;

  if (lv === null) {
    for (const gname of K.CHANNEL_A_GROUPS) groups[gname] = K.unknown(K.UNCOVERED_PACKAGE);
    for (const cn of K.PUBLISHER_CONSTITUENTS) constituents[cn] = K.unknown(K.UNCOVERED_PACKAGE);
  } else {
    const ord = c.ord === null ? lv.n_versions : c.ord;       // a live candidate extends the tip
    const predOrd = ord - 1;
    if (predOrd < 0) {
      for (const gname of K.CHANNEL_A_GROUPS) groups[gname] = K.unknown(K.COLD_START);
      for (const cn of K.PUBLISHER_CONSTITUENTS) constituents[cn] = K.unknown(K.COLD_START);
    } else {
      const pub = lv.stateAt('publisher', predOrd);
      const prov = lv.stateAt('provenance', predOrd);
      const ins = lv.stateAt('install', predOrd);
      const git = lv.stateAt('git', predOrd);
      const srow = lv.spine.get(predOrd) || null;
      predVersion = srow ? srow.version : null;

      const pId = g(pub, 'identity_digest'); const cId = c.identity_digest;
      constituents.identity = (pId === null || cId === null)
        ? K.unknown(K.UNSUPPORTED_FIELD, { predecessor_identity_present: pId !== null, candidate_identity_present: cId !== null })
        : K.known(pId !== cId, { predecessor: pId.slice(0, 16), candidate: cId.slice(0, 16) });

      const pM = g(pub, 'maint_digest') || ''; const cM = c.maint_digest || '';
      constituents.maintainers = !pM
        ? K.unknown(K.UNSUPPORTED_FIELD, { predecessor_maint_digest_empty: true })
        : K.known(pM !== cM, { predecessor: pM.slice(0, 16), candidate: cM ? cM.slice(0, 16) : '', candidate_empty: !cM });

      const pName = g(pub, 'tool_name') || '';
      if (!pName || !c.tool_name) {
        constituents.tool_downgrade = K.known(false, { reason_note: 'tool name absent on one side: no break, no clear' });
      } else if (pName !== c.tool_name) {
        constituents.tool_downgrade = K.known(false, { predecessor_tool: pName, candidate_tool: c.tool_name });
      } else if (srow === null || srow.tool_key === null || srow.tool_key === undefined) {
        constituents.tool_downgrade = K.unknown(K.BEYOND_SPINE, { predecessor_ord: predOrd });
      } else {
        constituents.tool_downgrade = K.known(c.tool_key < srow.tool_key,
          { predecessor_tool_key: srow.tool_key, candidate_tool_key: c.tool_key });
      }
      groups.publisher = K.publisherGroup(constituents);

      groups.provenance = K.known(Boolean(g(prov, 'present')) && !c.provenance_present,
        { predecessor_present: Boolean(g(prov, 'present')), candidate_present: c.provenance_present });
      groups.install = K.known(!Boolean(g(ins, 'has_scripts')) && c.has_scripts,
        { predecessor_has_scripts: Boolean(g(ins, 'has_scripts')), candidate_has_scripts: c.has_scripts });
      groups.git = K.known(Boolean(g(git, 'head_present')) && !c.head_present, {
        predecessor_head_present: Boolean(g(git, 'head_present')), candidate_head_present: c.head_present,
        repo_digest_changed: g(git, 'repo_digest') !== c.repo_digest,
      });

      const psize = srow === null ? null : srow.size_bytes;
      if (srow === null || psize === null || psize === undefined || psize <= 0) {
        groups.size = K.unknown(srow === null ? K.BEYOND_SPINE : K.UNSUPPORTED_FIELD, { predecessor_ord: predOrd });
      } else if (c.size_bytes === null) {
        groups.size = K.unknown(K.UNSUPPORTED_FIELD, { candidate_size_missing: true });
      } else {
        groups.size = K.known(
          c.size_bytes >= psize * (1 + K.SIZE_BREAK_FRACTION) || c.size_bytes <= psize * (1 - K.SIZE_BREAK_FRACTION),
          { predecessor_size: psize, candidate_size: c.size_bytes },
        );
      }
    }
  }

  const agg = K.aggregate(groups, [['critical', K.CHANNEL_A_T]], K.CHANNEL_A_GROUPS.length);
  // install_body: RECORDED evidence, never a group, never in N.
  let bodyRecorded = null;
  const predOrd2 = lv === null ? null : (c.ord === null ? lv.n_versions : c.ord) - 1;
  if (lv !== null && predOrd2 !== null && predOrd2 >= 0) {
    const prevBody = g(lv.stateAt('install', predOrd2), 'body_digest') || '';
    bodyRecorded = {
      predecessor_body_digest: prevBody.slice(0, 16),
      candidate_body_digest: (c.body_digest || '').slice(0, 16),
      changed: Boolean(prevBody) && Boolean(c.body_digest) && prevBody !== c.body_digest,
      counts_toward_n: false,
    };
  }
  const groupsOut = {}; for (const [k, v] of Object.entries(groups)) groupsOut[k] = v.asDict();
  const consOut = {}; for (const [k, v] of Object.entries(constituents)) consOut[k] = v.asDict();
  return { predecessor_version: predVersion, groups: groupsOut, publisher_constituents: consOut,
    install_body: bodyRecorded, ...agg };
}

// ---------------------------------------------------------------------------
// DAC trajectory (package-wide, strictly prior)
// ---------------------------------------------------------------------------
function priorStates(pv, c, grp) {
  const prior = []; const ambiguous = [];
  for (const [lid, lv] of pv.lineages) {
    for (const [startOrd, startS, st] of lv.segmentStarts(grp)) {
      if (lid === c.lineage_id) {
        const candOrd = c.ord === null ? lv.n_versions : c.ord;
        if (startOrd < candOrd) prior.push(st);
      } else if (c.published_s === null || startS === null) {
        ambiguous.push(st);
      } else if (startS < c.published_s) {
        prior.push(st);
      } else if (startS === c.published_s) {
        ambiguous.push(st);
      }
    }
  }
  return [prior, ambiguous];
}

function hasPriorVersion(pv, c) {
  let certain = false; let ambiguous = false;
  for (const [lid, lv] of pv.lineages) {
    if (lid === c.lineage_id) {
      const candOrd = c.ord === null ? lv.n_versions : c.ord;
      if (candOrd > 0) certain = true;
    } else if (c.published_s === null) {
      ambiguous = true;
    } else if (lv.first_published_s < c.published_s) {
      certain = true;
    } else if (lv.first_published_s === c.published_s) {
      ambiguous = true;
    }
  }
  return [certain, ambiguous];
}

function everTrue(pv, c, grp, key) {
  const [prior, ambiguous] = priorStates(pv, c, grp);
  if (prior.some((st) => Boolean(g(st, key)))) return K.known(true);
  if (ambiguous.some((st) => Boolean(g(st, key)))) {
    return K.unknown(K.AMBIGUOUS_ORDER, { note: `a tie in stored publication time could add a prior ${grp}.${key}` });
  }
  return K.known(false);
}

function sizeReferenceCandidates(pv, c) {
  const visible = [];      // [published_s, lineage_id, ord, size]
  const equalTime = [];
  const bounds = [];
  for (const [lid, lv] of pv.lineages) {
    const own = lid === c.lineage_id;
    const candOrd = own ? (c.ord === null ? lv.n_versions : c.ord) : null;
    for (const [o, r] of lv.spine) {
      const size = r.size_bytes || 0;
      if (own) {
        if (o < candOrd && size > 0) visible.push([r.published_s, lid, o, size]);
        continue;
      }
      if (c.published_s === null || r.published_s === null) {
        if (size > 0) equalTime.push(size);
        continue;
      }
      if (r.published_s < c.published_s && size > 0) visible.push([r.published_s, lid, o, size]);
      else if (r.published_s === c.published_s && size > 0) equalTime.push(size);
    }
    const mso = lv.minSpineOrd;
    if (mso !== null && mso > 0) {
      let hidesPrior;
      if (own) hidesPrior = candOrd > 0;
      else if (c.published_s === null || lv.first_published_s === null) hidesPrior = true;
      else if (lv.first_published_s < c.published_s) hidesPrior = true;
      else hidesPrior = false;       // every version of this lineage is at or after the candidate
      if (hidesPrior) bounds.push(lv.spine.get(mso).published_s);
    }
  }
  if (!visible.length && !equalTime.length) {
    const [hasPrior] = hasPriorVersion(pv, c);
    if (!hasPrior) return [[], K.ZERO_HISTORY];
    return [[], bounds.length ? K.BEYOND_SPINE : K.UNSUPPORTED_FIELD];
  }
  const maxS = visible.length ? Math.max(...visible.map((r) => r[0])) : null;
  if (visible.length && bounds.length && maxS <= Math.max(...bounds)) return [[], K.BEYOND_SPINE];
  const sizes = [];
  if (visible.length) {
    const tied = visible.filter((r) => r[0] === maxS);
    if (new Set(tied.map((r) => r[1])).size > 1) {
      for (const r of tied) sizes.push(r[3]);               // different lineages, same stored second
    } else {
      sizes.push(tied.reduce((a, b) => (b[2] > a[2] ? b : a))[3]);   // same lineage: ord is authoritative
    }
  }
  sizes.push(...equalTime);
  return [[...new Set(sizes)].sort((a, b) => a - b), null];
}

function dac(pv, c) {
  const preds = {};
  let historyNote;
  if (c.published_s === null) {
    for (const p of K.DAC_PREDICATES) preds[p] = K.unknown(K.MISSING_PUBLICATION_TIME);
    historyNote = { prior_versions: null };
  } else {
    const [hasPrior, priorAmbiguous] = hasPriorVersion(pv, c);
    if (!hasPrior) {
      const reason = priorAmbiguous ? K.AMBIGUOUS_ORDER : K.ZERO_HISTORY;
      for (const p of K.DAC_PREDICATES) preds[p] = K.unknown(reason);
      historyNote = { prior_versions: 0, ambiguous: priorAmbiguous };
    } else {
      const everScripts = everTrue(pv, c, 'install', 'has_scripts');
      preds.install_introduced = everScripts.evaluable
        ? K.known(c.has_scripts && !everScripts.value) : K.unknown(everScripts.reason);
      const everProv = everTrue(pv, c, 'provenance', 'present');
      preds.prov_dropped = everProv.evaluable
        ? K.known(!c.provenance_present && Boolean(everProv.value)) : K.unknown(everProv.reason);

      const [priorSt, ambSt] = priorStates(pv, c, 'publisher');
      const priorTuples = new Set(priorSt.map((st) => g(st, 'tuple_digest')));
      const ambTuples = new Set(ambSt.map((st) => g(st, 'tuple_digest')));
      if (c.tuple_digest === null) {
        preds.first_pkg_appearance_new_publisher = K.unknown(K.UNSUPPORTED_FIELD, { candidate_tuple_missing: true });
      } else if (priorTuples.has(null)) {
        preds.first_pkg_appearance_new_publisher = K.unknown(K.UNSUPPORTED_FIELD, { prior_tuple_missing: true });
      } else if (priorTuples.has(c.tuple_digest)) {
        preds.first_pkg_appearance_new_publisher = K.known(false, { prior_tuple_count: priorTuples.size });
      } else if (ambTuples.has(c.tuple_digest)) {
        preds.first_pkg_appearance_new_publisher = K.unknown(K.AMBIGUOUS_ORDER);
      } else {
        preds.first_pkg_appearance_new_publisher = K.known(true, { prior_tuple_count: priorTuples.size });
      }

      const [sizes, why] = sizeReferenceCandidates(pv, c);
      if (why !== null) {
        preds.size_jump_5x = K.unknown(why);
      } else if (c.size_bytes === null) {
        preds.size_jump_5x = K.unknown(K.UNSUPPORTED_FIELD, { candidate_size_missing: true });
      } else {
        const outcomes = new Set(sizes.map((b) => c.size_bytes / b >= K.DAC_SIZE_JUMP_FACTOR));
        preds.size_jump_5x = outcomes.size === 1
          ? K.known([...outcomes][0], { reference_sizes: sizes, candidate_size: c.size_bytes })
          : K.unknown(K.AMBIGUOUS_ORDER, { reference_sizes: sizes, candidate_size: c.size_bytes });
      }
      historyNote = { prior_versions: '>=1', ambiguous: priorAmbiguous };
    }
  }
  const agg = K.aggregate(preds, [['surface', K.DAC_SURFACE_T], ['any', K.DAC_ANY_T]], K.DAC_PREDICATES.length);
  const out = {}; for (const [k, v] of Object.entries(preds)) out[k] = v.asDict();
  return { predicates: out, history: historyNote, ...agg };
}

/** The portable finding. No ALLOW/WARN/BLOCK: findings, evidence, counts and coverage only. */
function check(pv, c, seedMeta = null) {
  let ca; let dacOut;
  if (pv === null) {
    const na = {}; const nd = {}; const cons = {};
    for (const gname of K.CHANNEL_A_GROUPS) na[gname] = K.unknown(K.UNCOVERED_PACKAGE);
    for (const p of K.DAC_PREDICATES) nd[p] = K.unknown(K.UNCOVERED_PACKAGE);
    for (const cn of K.PUBLISHER_CONSTITUENTS) cons[cn] = K.unknown(K.UNCOVERED_PACKAGE).asDict();
    const ga = {}; for (const [k, v] of Object.entries(na)) ga[k] = v.asDict();
    const pa = {}; for (const [k, v] of Object.entries(nd)) pa[k] = v.asDict();
    ca = { predecessor_version: null, groups: ga, publisher_constituents: cons, install_body: null,
      ...K.aggregate(na, [['critical', K.CHANNEL_A_T]], K.CHANNEL_A_GROUPS.length) };
    dacOut = { predicates: pa, history: { prior_versions: null },
      ...K.aggregate(nd, [['surface', K.DAC_SURFACE_T], ['any', K.DAC_ANY_T]], K.DAC_PREDICATES.length) };
  } else {
    ca = channelA(pv, c); dacOut = dac(pv, c);
  }
  const binding = seedMeta !== null ? seedMeta : (pv !== null ? pv.seed_meta : {});
  return {
    contract_version: K.CONTRACT_VERSION,
    timestamp_precision: K.TIMESTAMP_PRECISION,
    candidate: { package: c.package_name, version: c.version, published_s: c.published_s,
      lineage_id: c.lineage_id, ord: c.ord, candidate_digest: c.identity_digest, provider_class: c.provider_class },
    corpus_context: 'unavailable',
    channel_a: ca,
    dac_trajectory: dacOut,
    seed: { ...binding },
  };
}

export { loadSeedMeta, loadPackage, check, channelA, dac, LineageView,
  priorStates, hasPriorVersion, everTrue, sizeReferenceCandidates, SEED_BINDING_KEYS };


// A default export as well: the consumer is used both as `import R from` and
// `import { verify } from`, and the runtime package is ESM.
export default { loadSeedMeta, loadPackage, check, channelA, dac, LineageView, priorStates,
  hasPriorVersion, everTrue, sizeReferenceCandidates, SEED_BINDING_KEYS
};