// Three conformance results, reported SEPARATELY because they prove different things and one number
// would let any of them hide inside another.
//
//   EVALUATOR PARITY   seed + already-normalised candidate fields -> findings. Says nothing about how
//                      those fields were produced.
//   NORMALISATION      raw values -> normalised values and digests, unit by unit, against vectors
//                      generated from the producer.
//   END-TO-END ADAPTER a real raw registry row -> a validated candidate, against the producer's own
//                      candidate_from_row over the SAME rows. This is the path a live consumer walks,
//                      and neither of the other two covers it.
//
// QUALIFICATION vs ordinary development: a CFT acceptance run must be handed the gated artifact. With
// `--qualify` (or CFT_QUALIFY=1) a missing CFT04_CANDIDATE is a FAILURE, not a skip. Optional skips
// are fine while developing; they are not fine when the result is used as qualification.

import { pathToFileURL, fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { existsSync, readFileSync } from 'node:fs';

import N from './normalize.js';
import PK from './packument.js';
import X from './normalize-extra.js';
import A from './adapter.js';
import P from './parity.js';
import R from './reader.js';
import L from './logical.js';

const DIRNAME = dirname(fileURLToPath(import.meta.url));
const readJson = (p) => JSON.parse(readFileSync(p, 'utf8'));

function normalisationConformance(vectorsPath = join(DIRNAME, 'vectors.json')) {
  const V = readJson(vectorsPath);
  const failures = [];
  let checked = 0;
  // A vector whose exact reproduction JavaScript cannot support must REFUSE by name. Counted
  // separately from agreements so the report never blurs "matched" with "correctly declined".
  let refusalsRequired = 0;
  let refusalsObserved = 0;
  const check = (group, label, got, want) => {
    checked += 1;
    if (JSON.stringify(got) !== JSON.stringify(want)) failures.push({ group, label, got, want });
  };
  const safe = (fn) => { try { return fn(); } catch (e) { return `THREW:${e.name}`; } };

  for (const v of V.norm_email) check('norm_email', JSON.stringify(v.in), N.normEmail(v.in), v.out);
  for (const v of V.norm_name) check('norm_name', JSON.stringify(v.in), N.normName(v.in), v.out);
  for (const v of V.email_domain) check('email_domain', JSON.stringify(v.in), N.emailDomain(v.in), v.out);
  for (const v of V.identity_digest) check('identity_digest', JSON.stringify(v.in), N.identityDigest(v.in), v.out);
  for (const v of V.tuple_digest) {
    check('tuple_digest', JSON.stringify([v.name, v.email]), N.tupleDigest(v.name, v.email), v.out);
  }
  for (const v of V.maintainers_digest) {
    // The generator marks which inputs a JavaScript consumer can reproduce at all. Where the producer
    // hashes a Python repr whose input JSON parsing has already flattened — a number, or integer-like
    // object keys — conformance requires an explicit, named REFUSAL rather than a matching digest,
    // because no JS implementation can produce one honestly.
    checked += 1;
    let got;
    try { got = N.maintainersDigest(v.in); } catch (e) { got = { refused: e.name }; }
    const representable = v.representable_in_js !== false;
    if (!representable) refusalsRequired += 1;
    const ok = representable
      ? JSON.stringify(got) === JSON.stringify(v.out)
      : (got && got.refused === 'NonPortableInput');
    if (!representable && ok) refusalsObserved += 1;
    if (!ok) {
      failures.push({
        group: 'maintainers_digest', label: JSON.stringify(v.in), got,
        want: representable ? v.out : 'an explicit NonPortableInput refusal',
      });
    }
  }
  for (const v of V.install_body_digest) {
    check('install_body_digest', JSON.stringify([v.install, v.preinstall, v.postinstall]),
      N.installBodyDigest(v.install, v.preinstall, v.postinstall), v.out);
  }
  // str.lower() as an operation, not only through the digests that consume it: it is CONTEXTUAL
  // around sigma, which a per-character table cannot express.
  for (const v of V.python_lower) {
    if (v.in === null) continue;
    check('python_lower', JSON.stringify(v.in), N.pyLower(v.in), v.out);
  }
  for (const v of V.node_major) check('node_major', JSON.stringify(v.in), N.nodeMajor(v.in), v.out);
  for (const v of V.provider_class) {
    check('provider_class', JSON.stringify([v.domain, v.count]), N.providerClass(v.domain, v.count), v.out);
  }
  for (const v of V.canonical_repo_url) check('canonical_repo_url', JSON.stringify(v.in), X.canonicalRepoUrl(v.in), v.out);
  for (const v of V.repo_digest) check('repo_digest', JSON.stringify(v.in), X.repoDigest(v.in), v.out);
  for (const v of V.parse_publisher_tool) {
    check('parse_publisher_tool', JSON.stringify(v.in), X.parsePublisherTool(v.in), v.out);
  }
  for (const v of V.resolve_publisher_email) {
    check('resolve_publisher_email', JSON.stringify([v.email, v.raw_metadata]),
      X.resolvePublisherEmail(v.email, v.raw_metadata), v.out);
  }
  for (const v of V.identity_digest_with_metadata) {
    check('identity_digest_with_metadata', JSON.stringify([v.email, v.raw_metadata]),
      X.identityDigestOf(v.email, v.raw_metadata), v.out);
  }
  // The float-repr vectors belong here too. They were only exercised by the unit tests, so a
  // qualification run reported 313 vectors while claiming the set was complete.
  for (const v of V.python_float_repr) {
    check('python_float_repr', v.in, safe(() => L.pyFloat(v.in === '-0.0' ? -0 : Number(v.in))), v.out);
  }
  return {
    result: failures.length === 0 ? 'PASS' : 'FAIL',
    what: 'raw values -> normalised values and digests (unit vectors)',
    ground_truth: 'generated from collector/witness_norm.py and tools/seedgen/witness.py',
    unicode_version: N.UNICODE_VERSION,
    vectors_checked: checked,
    vectors_compared: checked - refusalsRequired,
    refusals_required: refusalsRequired,
    refusals_observed: refusalsObserved,
    refusals_note: 'inputs whose Python repr JavaScript cannot reproduce after JSON parsing: a '
      + 'number (int 1 and float 1.0 become one Number) and integer-like object keys (JavaScript '
      + 'reorders them). These must refuse by name, not return a digest.',
    failure_count: failures.length,
    failures: failures.slice(0, 10),
  };
}

// The candidate contract is a FIXED field set. Comparing whichever keys an expectation happens to
// supply lets a truncated or empty expectation agree with anything, so both vector sets are compared
// against these names and an expectation that does not carry exactly them fails acceptance.
const ADAPTER_EXPECTED_FIELDS = [...R.CANDIDATE_REQUIRED].sort();
// The composed cases carry package_name alongside the row rather than inside the expectation.
const COMPOSED_EXPECTED_FIELDS = ADAPTER_EXPECTED_FIELDS.filter((k) => k !== 'package_name');

/** Does every case carry an expectation over EXACTLY `fields`? Names what is missing or unknown. */
function expectationsComplete(cases, key, fields) {
  const want = new Set(fields);
  for (const [i, c] of cases.entries()) {
    const exp = c[key];
    if (exp === null || typeof exp !== 'object' || Array.isArray(exp)) {
      return `case ${i} (${c.package_name}): ${key} is not an object`;
    }
    const have = Object.keys(exp);
    const missing = fields.filter((f) => !(f in exp));
    const unknown = have.filter((f) => !want.has(f)).sort();
    if (missing.length || unknown.length) {
      return `case ${i} (${c.package_name}): ${key} must carry exactly the ${fields.length} contract `
        + `fields; missing [${missing.join(', ')}], unknown [${unknown.join(', ')}]`;
    }
  }
  return true;
}

/** Compare the FIXED field set, absent === null on both sides. */
function diffExpected(got, expected, fields) {
  const diffs = [];
  for (const k of fields) {
    const a = got[k] === undefined ? null : got[k];
    const b = expected[k] === undefined ? null : expected[k];
    if (JSON.stringify(a) !== JSON.stringify(b)) diffs.push({ field: k, got: a, want: b });
  }
  return diffs;
}

/**
 * The identities a composed vector set claims to be bound to, ESTABLISHED rather than read.
 *
 * corpus_snapshot_digest alone is shared by every build of the same snapshot under the same rules, so
 * on its own it admits vectors generated against a DIFFERENT seed — the same hole the evaluator-parity
 * acceptance closes with an exact identity. The seed logical digest is RE-DERIVED from the file (a
 * seed cannot self-report it: it covers seed_metadata) and the fixtures digest is RECOMPUTED from
 * fixtures.jsonl. A manifest's or a vector file's own claim is never evidence for itself.
 */
function verifiedIdentities(seed, fixturesDir) {
  const out = { seed_logical_digest: null, fixtures_digest: null, established: {} };
  try {
    out.seed_logical_digest = L.logicalDigestOfDb(seed.db);
    out.established.seed_logical_digest = 're-derived from the seed file';
  } catch (e) {
    out.established.seed_logical_digest = `could not re-derive: ${e.name}: ${e.message}`;
  }
  const f = fixturesDir ? join(fixturesDir, 'fixtures.jsonl') : null;
  if (f && existsSync(f)) {
    out.fixtures_digest = R.sha256File(f);
    out.established.fixtures_digest = 'recomputed from fixtures.jsonl';
  } else {
    out.established.fixtures_digest = fixturesDir
      ? `no fixtures.jsonl under ${fixturesDir}` : 'no fixtures directory supplied';
  }
  return out;
}

function adapterConformance(vectorsPath = join(DIRNAME, 'e2e-vectors.json')) {
  const scope = 'producer EXTRACT row -> candidate (NOT a raw npm packument, and NOT a finding: '
    + 'lineage/ordinal are null and no seed is consulted)';
  if (!existsSync(vectorsPath)) {
    return { result: 'UNAVAILABLE', what: scope,
      detail: `no adapter vectors at ${vectorsPath}; generate with make_e2e_vectors.py` };
  }
  const V = readJson(vectorsPath);
  // Acceptance BEFORE comparison: an empty file used to return PASS 0/0, which is not a result.
  const accept = {};
  accept.schema = V.schema === 'adapter-vectors-1' ? true : `unexpected schema ${JSON.stringify(V.schema)}`;
  accept.cases_non_empty = Array.isArray(V.cases) && V.cases.length > 0 ? true
    : 'the vector file carries no cases; an empty pack is not a PASS';
  accept.domain_version_count_declared = Number.isInteger(V.domain_version_count) ? true
    : `domain_version_count must be declared, got ${JSON.stringify(V.domain_version_count)}`;
  accept.cases_well_formed = (V.cases || []).every(
    (c) => c && typeof c.package_name === 'string' && c.row && typeof c.row === 'object' && c.expected)
    ? true : 'a case is missing package_name, row or expected';
  accept.expectations_complete = accept.cases_well_formed === true
    ? expectationsComplete(V.cases, 'expected', ADAPTER_EXPECTED_FIELDS)
    : 'not checked: a case is malformed';
  if (Object.values(accept).some((v) => v !== true)) {
    return { result: 'FAIL', failure: 'acceptance', what: scope, acceptance: accept,
      cases: (V.cases || []).length, agreeing: 0, failure_count: 0, failures: [] };
  }
  const failures = [];
  for (const c of V.cases) {
    let got;
    try {
      got = A.candidateFromRawRow(c.row, {
        packageName: c.package_name, domainVersionCount: V.domain_version_count,
      });
    } catch (e) {
      failures.push({ package: c.package_name, error: `${e.name}: ${e.message}` });
      continue;
    }
    const diffs = diffExpected(got, c.expected, ADAPTER_EXPECTED_FIELDS);
    if (diffs.length) failures.push({ package: c.package_name, version: c.row.version, diffs: diffs.slice(0, 4) });
  }
  return {
    result: failures.length === 0 ? 'PASS' : 'FAIL',
    what: scope,
    ground_truth: "the producer's own oracle.candidate_from_row over the SAME real rows",
    acceptance: accept,
    compared_fields: ADAPTER_EXPECTED_FIELDS,
    rows_scanned: V.rows_scanned ?? null,
    cases: V.cases.length,
    agreeing: V.cases.length - failures.length,
    failure_count: failures.length,
    failures: failures.slice(0, 5),
  };
}

/**
 * The npm PACKUMENT path: real registry document -> observation row -> candidate.
 *
 * The adapter vectors start from a producer EXTRACT row, whose columns were already chosen, named and
 * normalised by the collector. A packument is the registry's own document and shares none of that
 * shape, so passing 400 extract rows says nothing about reading one. Ground truth is the PRODUCER's
 * own packument parser over REAL packuments (make_packument_vectors.py).
 */
function packumentConformance(vectorsPath = join(DIRNAME, 'packument-vectors.json'),
  fixturesDir = join(DIRNAME, 'packument-fixtures')) {
  const scope = 'real npm packument -> observation row -> candidate (NOT a finding: no seed is '
    + 'consulted and lineage/ordinal are null)';
  if (!existsSync(vectorsPath)) {
    return { result: 'UNAVAILABLE', what: scope,
      detail: `no packument vectors at ${vectorsPath}; generate with make_packument_vectors.py` };
  }
  const V = readJson(vectorsPath);
  const accept = {};
  accept.schema = V.schema === 'packument-vectors-1' ? true : `unexpected schema ${JSON.stringify(V.schema)}`;
  accept.cases_non_empty = Array.isArray(V.cases) && V.cases.length > 0 ? true
    : 'the vector file carries no cases; an empty pack is not a PASS';
  accept.row_fields_declared = Array.isArray(V.row_fields) && V.row_fields.length > 0 ? true
    : 'the vector file must declare the observation-row field set it was generated over';
  accept.fixtures_present = Array.isArray(V.fixtures) && V.fixtures.length > 0
    && V.fixtures.every((f) => existsSync(join(fixturesDir, f)))
    ? true : 'a declared packument fixture is missing';
  accept.domain_version_count_declared = Number.isInteger(V.domain_version_count) ? true
    : `domain_version_count must be declared, got ${JSON.stringify(V.domain_version_count)}`;
  accept.cases_well_formed = (V.cases || []).every(
    (c) => c && typeof c.package_name === 'string' && typeof c.version === 'string'
      && typeof c.fixture === 'string' && c.expected_row && c.expected_candidate)
    ? true : 'a case is missing package_name, version, fixture, expected_row or expected_candidate';
  // Real packuments alone do not exercise the divergence points; the adversarial half is required,
  // not optional, or this result would silently narrow to whatever the registry happened to contain.
  accept.adversarial_present = Array.isArray(V.adversarial) && V.adversarial.length >= 20 ? true
    : `the vector file must carry the adversarial manifests (got ${
      Array.isArray(V.adversarial) ? V.adversarial.length : 'none'})`;
  accept.adversarial_well_formed = (V.adversarial || []).every(
    (c) => c && typeof c.label === 'string' && c.manifest && typeof c.manifest === 'object'
      && (c.producer_parse_refused ? c.expected_row === null : Boolean(c.expected_row)))
    ? true : 'an adversarial case is missing its label, manifest, or expected row';
  // The fixed field sets, on both halves, for the same reason as everywhere else.
  accept.expected_rows_complete = accept.cases_well_formed === true
    ? expectationsComplete(V.cases, 'expected_row', V.row_fields) : 'not checked: a case is malformed';
  accept.expected_candidates_complete = accept.cases_well_formed === true
    ? expectationsComplete(V.cases, 'expected_candidate', ADAPTER_EXPECTED_FIELDS)
    : 'not checked: a case is malformed';
  if (Object.values(accept).some((v) => v !== true)) {
    return { result: 'FAIL', failure: 'acceptance', what: scope, acceptance: accept,
      cases: (V.cases || []).length, agreeing: 0, failure_count: 0, failures: [] };
  }

  // Read each fixture ONCE, through the document-level entry point, so the packument walk itself
  // (versions{} ordering, the separate time{} map, per-version refusals) is exercised and not only
  // the per-manifest mapping.
  const byPackage = new Map();
  const refusedVersions = [];
  let versionsSeen = 0;
  for (const f of V.fixtures) {
    const doc = readJson(join(fixturesDir, f));
    const parsed = PK.observationsFromPackument(doc);
    versionsSeen += parsed.versions_seen;
    for (const rr of parsed.refused) refusedVersions.push({ package: parsed.package_name, ...rr });
    byPackage.set(parsed.package_name, new Map(parsed.rows.map((r) => [r.version, r])));
  }

  const failures = [];

  // The ADVERSARIAL half: synthetic manifests sitting on the points where a JavaScript adapter and
  // the Python producer can silently disagree. Three stages, each with its own equivalence:
  //
  //   parse      the producer's PARSER refuses (a non-object _npmUser) -> so must this adapter
  //   row        exact field match, always
  //   candidate  the producer's candidate derivation refuses -> so must this consumer
  //
  // with ONE mechanical exception at the candidate stage: the producer's oracle does not enforce the
  // candidate contract, so it can emit a candidate whose values the declared CANDIDATE_SPEC rejects
  // (a float or out-of-range size_bytes). The consumer refusing there is correct, and the carve-out
  // is COMPUTED from the spec rather than listed by hand, so a new divergence cannot hide in it.
  const adversarial = Array.isArray(V.adversarial) ? V.adversarial : [];
  let advAgree = 0;
  const producerContractViolations = [];
  for (const c of adversarial) {
    let row = null; let rowRefusal = null;
    try {
      row = PK.observationFromManifest(c.version, c.manifest, c.published_at);
    } catch (e) { rowRefusal = `${e.name}: ${(e.reasons || [e.message]).join('; ')}`; }

    if (Boolean(c.producer_parse_refused) !== Boolean(rowRefusal)) {
      failures.push({ stage: 'adversarial:parse', label: c.label,
        producer: c.producer_parse_refused, js: rowRefusal });
      continue;
    }
    if (rowRefusal) { advAgree += 1; continue; }

    const rowDiffs = diffExpected(row, c.expected_row, V.row_fields);
    if (rowDiffs.length) {
      failures.push({ stage: 'adversarial:row', label: c.label, diffs: rowDiffs.slice(0, 4) });
      continue;
    }

    let cand = null; let candRefusal = null;
    try {
      cand = A.candidateFromRawRow(row, {
        packageName: c.package_name, domainVersionCount: V.domain_version_count });
    } catch (e) { candRefusal = `${e.name}: ${(e.reasons || [e.message]).join('; ')}`; }

    if (Boolean(c.producer_refused) !== Boolean(candRefusal)) {
      // the only permitted asymmetry, and only when the SPEC says so
      const violations = [];
      if (candRefusal && c.expected_candidate) {
        for (const [k, spec] of Object.entries(R.CANDIDATE_SPEC)) {
          const msg = R.validateField(k, c.expected_candidate[k], spec);
          if (msg) violations.push(msg);
        }
      }
      if (violations.length) {
        producerContractViolations.push({ label: c.label, js_refusal: candRefusal, violations });
        advAgree += 1;
      } else {
        failures.push({ stage: 'adversarial:candidate', label: c.label,
          producer: c.producer_refused, js: candRefusal });
      }
      continue;
    }
    if (candRefusal) { advAgree += 1; continue; }
    const candDiffs = diffExpected(cand, c.expected_candidate, ADAPTER_EXPECTED_FIELDS);
    if (candDiffs.length) {
      failures.push({ stage: 'adversarial:candidate', label: c.label, diffs: candDiffs.slice(0, 4) });
    } else { advAgree += 1; }
  }

  for (const c of V.cases) {
    const row = (byPackage.get(c.package_name) || new Map()).get(c.version);
    if (!row) {
      failures.push({ stage: 'packument', package: c.package_name, version: c.version,
        error: 'the packument walk produced no observation row for this version' });
      continue;
    }
    const rowDiffs = diffExpected(row, c.expected_row, V.row_fields);
    if (rowDiffs.length) {
      failures.push({ stage: 'row', package: c.package_name, version: c.version,
        diffs: rowDiffs.slice(0, 4) });
      continue;
    }
    let cand;
    try {
      cand = A.candidateFromRawRow(row, {
        packageName: c.package_name, domainVersionCount: V.domain_version_count });
    } catch (e) {
      failures.push({ stage: 'candidate', package: c.package_name, version: c.version,
        error: `${e.name}: ${(e.reasons || [e.message]).join('; ')}` });
      continue;
    }
    const cDiffs = diffExpected(cand, c.expected_candidate, ADAPTER_EXPECTED_FIELDS);
    if (cDiffs.length) {
      failures.push({ stage: 'candidate', package: c.package_name, version: c.version,
        diffs: cDiffs.slice(0, 4) });
    }
  }
  return {
    result: failures.length === 0 ? 'PASS' : 'FAIL',
    what: `${scope}; real packuments AND producer-generated adversarial manifests`,
    ground_truth: V.ground_truth || null,
    source: V.source || null,
    acceptance: accept,
    packages: V.fixtures.length,
    versions_in_fixtures: versionsSeen,
    cases: V.cases.length,
    adversarial_cases: adversarial.length,
    adversarial_agreeing: advAgree,
    // Reported, never hidden: inputs where the PRODUCER's oracle emits a candidate whose values its
    // own consumer contract rejects. The consumer refusing them is the contract working.
    producer_contract_violations: producerContractViolations,
    agreeing: V.cases.length + adversarial.length - failures.length,
    refused_versions: refusedVersions,
    compared_row_fields: V.row_fields,
    compared_candidate_fields: ADAPTER_EXPECTED_FIELDS,
    failure_count: failures.length,
    failures: failures.slice(0, 5),
  };
}

/**
 * The COMPOSED path: raw row -> candidate -> FINDING, with the lineage and ordinal the row actually
 * occupies and the producer's expected finding from the sealed pack. This is what the adapter vectors
 * do not show, because they stop at the candidate and carry null history.
 */
async function composedConformance(seed, opts = {}) {
  const {
    vectorsPath = join(DIRNAME, 'composed-vectors.json'),
    fixturesDir = null,
    verified = null,
  } = typeof opts === 'string' ? { vectorsPath: opts } : opts;
  const what = 'raw row -> candidate -> finding, against real package history';
  if (!existsSync(vectorsPath)) {
    return { result: 'UNAVAILABLE', what, detail: `no composed vectors at ${vectorsPath}` };
  }
  const V = readJson(vectorsPath);
  const accept = {};
  accept.schema = V.schema === 'composed-vectors-1' ? true : `unexpected schema ${JSON.stringify(V.schema)}`;
  accept.cases_non_empty = Array.isArray(V.cases) && V.cases.length > 0 ? true : 'no cases';
  accept.has_real_history = (V.cases || []).some((c) => c.lineage_id !== null && c.ord !== null) ? true
    : 'every case carries null lineage/ordinal, so no history is exercised';
  accept.cases_well_formed = (V.cases || []).every(
    (c) => c && typeof c.package_name === 'string' && c.row && typeof c.row === 'object'
      && c.expected_candidate && c.expected_finding) ? true
    : 'a case is missing package_name, row, expected_candidate or expected_finding';
  // An expectation that supplies no fields agrees with every candidate, and one that supplies a few
  // agrees with too many. Both halves are compared against the FIXED contract set.
  accept.expected_candidates_complete = accept.cases_well_formed === true
    ? expectationsComplete(V.cases, 'expected_candidate', COMPOSED_EXPECTED_FIELDS)
    : 'not checked: a case is malformed';
  accept.expected_findings_complete = accept.cases_well_formed === true
    ? ((V.cases.find((c) => !c.expected_finding.channel_a || !c.expected_finding.dac_trajectory)
      && 'a case expects no channel_a or no dac_trajectory') || true)
    : 'not checked: a case is malformed';

  // The expected findings come from ONE seed. corpus_snapshot_digest is necessary but NOT sufficient:
  // every build of that snapshot under the same rules shares it, so it admits vectors generated
  // against a different seed. The exact identities are checked against ESTABLISHED values.
  const ids = verified || verifiedIdentities(seed, fixturesDir);
  const bt = V.bound_to || {};
  accept.bound_to_declared = ['candidate_id', 'corpus_snapshot_digest', 'seed_logical_digest',
    'fixtures_digest'].filter((k) => !bt[k]).length === 0
    ? true : `bound_to must declare candidate_id, corpus_snapshot_digest, seed_logical_digest and `
      + `fixtures_digest; got [${Object.keys(bt).join(', ')}]`;
  accept.bound_to_this_seed = bt.corpus_snapshot_digest === seed.meta.corpus_snapshot_digest
    ? true : `vectors are bound to ${bt.corpus_snapshot_digest}, seed is ${seed.meta.corpus_snapshot_digest}`;
  accept.bound_to_seed_logical_digest = ids.seed_logical_digest === null
    ? `no verified seed identity: ${ids.established.seed_logical_digest}`
    : (ids.seed_logical_digest === bt.seed_logical_digest ? true
      : `vectors claim ${bt.seed_logical_digest}, ${ids.established.seed_logical_digest} gives ${ids.seed_logical_digest}`);
  accept.bound_to_fixtures_digest = ids.fixtures_digest === null
    ? `no verified fixtures identity: ${ids.established.fixtures_digest}`
    : (ids.fixtures_digest === bt.fixtures_digest ? true
      : `vectors claim ${bt.fixtures_digest}, ${ids.established.fixtures_digest} gives ${ids.fixtures_digest}`);

  if (Object.values(accept).some((v) => v !== true)) {
    return { result: 'FAIL', failure: 'acceptance', what, acceptance: accept,
      identities_established: ids.established, cases: (V.cases || []).length,
      agreeing: 0, failure_count: 0, failures: [] };
  }

  const failures = [];
  for (const c of V.cases) {
    try {
      const cand = A.candidateFromRawRow(c.row, {
        packageName: c.package_name, lineageId: c.lineage_id, ord: c.ord,
        domainVersionCount: V.domain_version_count,
      });
      // the candidate the producer derived from the same row, over the fixed contract field set
      for (const d of diffExpected(cand, c.expected_candidate, COMPOSED_EXPECTED_FIELDS)) {
        failures.push({ stage: 'candidate', package: c.package_name, ...d });
      }
      // and the finding that candidate produces against real history
      const got = P.canonical(seed.check(cand));
      const want = P.canonical({
        candidate: c.expected_finding.candidate || {},
        channel_a: c.expected_finding.channel_a,
        dac_trajectory: c.expected_finding.dac_trajectory,
      });
      if (!P.eq(want, got)) {
        const items = []; P.diff('', want, got, items);
        failures.push({ stage: 'finding', package: c.package_name, lineage_id: c.lineage_id,
          ord: c.ord, diffs: items.slice(0, 3) });
      }
    } catch (e) {
      failures.push({ stage: 'threw', package: c.package_name, error: `${e.name}: ${e.message}` });
    }
  }
  return {
    result: failures.length === 0 ? 'PASS' : 'FAIL',
    what,
    ground_truth: "the producer's expected findings from the sealed pack, over raw rows",
    acceptance: accept,
    identities_established: ids.established,
    compared_candidate_fields: COMPOSED_EXPECTED_FIELDS,
    bound_to: V.bound_to,
    cases: V.cases.length,
    agreeing: V.cases.length - failures.length,
    packages: new Set(V.cases.map((c) => c.package_name)).size,
    failure_count: failures.length,
    failures: failures.slice(0, 5),
  };
}

async function evaluatorParity(fixturesDir, seedPath, opts = {}) {
  const r = await P.run(fixturesDir, seedPath, { trust: R.TRUST_UNSIGNED_DEV, ...opts });
  return {
    result: r.status,
    what: 'seed + already-normalised candidate fields -> findings, evidence and coverage',
    candidates: r.candidates,
    agreeing: r.agreeing,
    disagreeing: r.disagreeing,
    acceptance: r.acceptance,
    exact_binding: r.acceptance ? r.acceptance.seed_logical_digest_rederived : undefined,
    // the identities this run established, for the composed check to be bound to the same artifacts
    verified: r.verified || null,
    items: (r.items || []).slice(0, 5),
  };
}

/** The candidate directory for a run. In qualification mode its absence is a failure, never a skip. */
function resolveCandidate() {
  const cand = process.env.CFT04_CANDIDATE || '';
  if (!cand) {
    return {
      ok: false,
      reason: 'CFT04_CANDIDATE is not set. A CFT acceptance run must be handed the gated candidate '
        + 'directory; skipping is only acceptable for ordinary developer tests.',
    };
  }
  const seed = join(cand, 'chaingate-seed.db');
  const fixtures = join(cand, 'fixtures');
  if (!existsSync(seed) || !existsSync(join(fixtures, 'fixtures.jsonl'))) {
    return { ok: false, reason: `CFT04_CANDIDATE does not contain chaingate-seed.db and fixtures/` };
  }
  return { ok: true, cand, seed, fixtures };
}

/** True when this run is being used as qualification rather than ordinary development. */
const isQualification = () => process.env.CFT_QUALIFY === '1' || process.argv.includes('--qualify');

export { normalisationConformance, adapterConformance, packumentConformance, composedConformance,
  evaluatorParity,
  resolveCandidate, isQualification, verifiedIdentities, expectationsComplete, diffExpected,
  ADAPTER_EXPECTED_FIELDS, COMPOSED_EXPECTED_FIELDS };
export default { normalisationConformance, adapterConformance, packumentConformance,
  composedConformance,
  evaluatorParity, resolveCandidate, isQualification, verifiedIdentities, expectationsComplete,
  diffExpected, ADAPTER_EXPECTED_FIELDS, COMPOSED_EXPECTED_FIELDS
};
// process.argv[1] is undefined under `node -e`, where pathToFileURL would throw — so importing
// this module for its exports must not depend on there being a script path.
const __isMain = Boolean(process.argv[1]) && import.meta.url === pathToFileURL(process.argv[1]).href;
if (__isMain) {
  const qualify = isQualification();
  const target = resolveCandidate();
  const emit = (name, body) => { console.log(`\n=== ${name} ===`); console.log(JSON.stringify(body, null, 2)); };
  const norm = normalisationConformance();
  const adapter = adapterConformance();
  const packument = packumentConformance();

  const finish = (par, composed) => {
    if (par) emit('EVALUATOR PARITY', par);
    emit('NORMALISATION CONFORMANCE', norm);
    emit('ADAPTER CONFORMANCE (extract row -> candidate)', adapter);
    emit('PACKUMENT CONFORMANCE (npm packument -> observation row -> candidate)', packument);
    if (composed) emit('COMPOSED CONFORMANCE (row -> candidate -> finding)', composed);
    console.log(`\n[conformance] evaluator_parity=${par ? par.result : 'NOT RUN'}`
      + `${par ? ` ${par.agreeing}/${par.candidates}` : ''} `
      + `normalisation=${norm.result} ${norm.vectors_compared}+${norm.refusals_observed}refused`
      + `/${norm.vectors_checked} `
      + `adapter=${adapter.result}${adapter.cases ? ` ${adapter.agreeing}/${adapter.cases}` : ''} `
      // `agreeing` spans BOTH halves, so printing it over `cases` alone read as "192/139".
      + `packument=${packument.result}`
      + `${packument.cases ? ` ${packument.cases}+${packument.adversarial_cases}adv`
        + `=${packument.agreeing}/${packument.cases + packument.adversarial_cases}` : ''} `
      + `composed=${composed ? composed.result : 'NOT RUN'}`
      + `${composed && composed.cases ? ` ${composed.agreeing}/${composed.cases}` : ''} `
      + `mode=${qualify ? 'QUALIFICATION' : 'development'}`);
    const allPass = Boolean(par) && par.result === 'PASS' && norm.result === 'PASS'
      && adapter.result === 'PASS' && packument.result === 'PASS'
      && Boolean(composed) && composed.result === 'PASS';
    if (qualify && !allPass) {
      console.error('[conformance] QUALIFICATION FAILED: every result must PASS, and the gated '
        + 'artifact is mandatory.');
      process.exit(3);
    }
    process.exit(allPass ? 0 : 3);
  };

  if (!target.ok) {
    if (qualify) {
      console.error(`\n[conformance] QUALIFICATION FAILED: ${target.reason}`);
      process.exit(4);
    }
    console.log(`\n[conformance] evaluator parity and composed NOT RUN: ${target.reason}`);
    finish(null, null);
  } else {
    const seed = R.openSeed(target.seed, { trust: R.TRUST_UNSIGNED_DEV });
    // Sequential, not concurrent: the composed vectors must be bound to the identities the parity run
    // ESTABLISHED, so that context is produced first and handed on rather than recomputed on trust.
    evaluatorParity(target.fixtures, target.seed)
      .then(async (par) => {
        const composed = await composedConformance(seed, {
          fixturesDir: target.fixtures, verified: par.verified,
        });
        seed.close();
        finish(par, composed);
      })
      .catch((e) => { try { seed.close(); } catch { /* already closed */ } console.error(e); process.exit(1); });
  }
}
