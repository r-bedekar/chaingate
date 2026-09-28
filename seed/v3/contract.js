// Detection contract v1 — shared vocabulary, mirrored from tools/seedgen/contract.py.
// NO detection logic and no database access lives here.
const CONTRACT_VERSION = 'cft-detection-contract-1.0';

const EVALUATED = 'EVALUATED';
const COLD_START = 'cold_start';
const ZERO_HISTORY = 'zero_history';
const BEYOND_SPINE = 'beyond_spine';
const AMBIGUOUS_ORDER = 'ambiguous_order';
const MISSING_PUBLICATION_TIME = 'missing_publication_time';
const UNCOVERED_PACKAGE = 'uncovered_package';
const STALE_SEED = 'stale_seed';
const UNSUPPORTED_FIELD = 'unsupported_field';
const REASONS = new Set([COLD_START, ZERO_HISTORY, BEYOND_SPINE, AMBIGUOUS_ORDER,
  MISSING_PUBLICATION_TIME, UNCOVERED_PACKAGE, STALE_SEED, UNSUPPORTED_FIELD]);

const CHANNEL_A_GROUPS = ['publisher', 'provenance', 'install', 'size', 'git'];   // M = 5
const PUBLISHER_CONSTITUENTS = ['identity', 'maintainers', 'tool_downgrade'];
const DAC_PREDICATES = ['install_introduced', 'size_jump_5x', 'prov_dropped',
  'first_pkg_appearance_new_publisher'];                                          // M = 4
const CHANNEL_A_T = 3;
const DAC_SURFACE_T = 2;
const DAC_ANY_T = 1;
const SIZE_BREAK_FRACTION = 0.50;
const DAC_SIZE_JUMP_FACTOR = 5.0;
const TIMESTAMP_PRECISION = 'unix_seconds_utc';

/** Tri-state outcome with its coverage. `value === null` means unevaluable. */
class Tri {
  constructor(value, coverage = EVALUATED, reason = null, evidence = {}) {
    this.value = value; this.coverage = coverage; this.reason = reason; this.evidence = evidence;
  }
  get evaluable() { return this.value !== null; }
  asDict() {
    const d = { value: this.value, coverage: this.coverage };
    if (this.reason) d.reason = this.reason;
    if (Object.keys(this.evidence).length) d.evidence = this.evidence;
    return d;
  }
}

function known(value, evidence = {}) { return new Tri(Boolean(value), EVALUATED, null, evidence); }
function unknown(reason, evidence = {}) {
  if (!REASONS.has(reason)) throw new Error(`unknown coverage reason: ${reason}`);
  return new Tri(null, 'NOT_EVALUATED', reason, evidence);
}

/** Deduped publisher witness, counted ONCE. Constituent coverage is retained by the caller. */
function publisherGroup(constituents) {
  const vals = PUBLISHER_CONSTITUENTS.map((c) => constituents[c].value);
  if (vals.some((v) => v === true)) {
    return known(true, { decided_by: PUBLISHER_CONSTITUENTS.filter((c) => constituents[c].value === true) });
  }
  if (vals.every((v) => v === false)) return known(false);
  const unresolved = PUBLISHER_CONSTITUENTS.filter((c) => constituents[c].value === null);
  const reasons = [...new Set(unresolved.map((c) => constituents[c].reason).filter(Boolean))].sort();
  return unknown(reasons.length === 1 ? reasons[0] : UNSUPPORTED_FIELD, { unresolved });
}

/** Tri-state aggregation. Retains [n_broke, n_broke + n_unevaluable] when indeterminate. */
function aggregate(items, thresholds, m) {
  const vals = Object.values(items);
  if (vals.length !== m) throw new Error(`aggregate: ${vals.length} items, M=${m}`);
  const nBroke = vals.filter((t) => t.value === true).length;
  const nEval = vals.filter((t) => t.value !== null).length;
  const nUneval = m - nEval;
  const out = thresholds.map(([name, t]) => {
    const lo = nBroke; const hi = nBroke + nUneval;
    let res; let det;
    if (nBroke >= t) { res = true; det = 'determinate'; }
    else if (hi < t) { res = false; det = 'determinate'; }
    else { res = null; det = 'indeterminate'; }
    return { name, threshold: t, threshold_result: res, threshold_determinacy: det, interval: [lo, hi] };
  });
  return { M: m, n_broke: nBroke, n_evaluable: nEval, n_unevaluable: nUneval, thresholds: out };
}

export {
  CONTRACT_VERSION, EVALUATED, COLD_START, ZERO_HISTORY, BEYOND_SPINE, AMBIGUOUS_ORDER,
  MISSING_PUBLICATION_TIME, UNCOVERED_PACKAGE, STALE_SEED, UNSUPPORTED_FIELD, REASONS,
  CHANNEL_A_GROUPS, PUBLISHER_CONSTITUENTS, DAC_PREDICATES, CHANNEL_A_T, DAC_SURFACE_T, DAC_ANY_T,
  SIZE_BREAK_FRACTION, DAC_SIZE_JUMP_FACTOR, TIMESTAMP_PRECISION,
  Tri, known, unknown, publisherGroup, aggregate,
};


// A default export as well: the consumer is used both as `import R from` and
// `import { verify } from`, and the runtime package is ESM.
export default { CONTRACT_VERSION, EVALUATED, COLD_START, ZERO_HISTORY, BEYOND_SPINE,
  AMBIGUOUS_ORDER, MISSING_PUBLICATION_TIME, UNCOVERED_PACKAGE, STALE_SEED, UNSUPPORTED_FIELD,
  REASONS, CHANNEL_A_GROUPS, PUBLISHER_CONSTITUENTS, DAC_PREDICATES, CHANNEL_A_T, DAC_SURFACE_T,
  DAC_ANY_T, SIZE_BREAK_FRACTION, DAC_SIZE_JUMP_FACTOR, TIMESTAMP_PRECISION, Tri, known,
  unknown, publisherGroup, aggregate
};