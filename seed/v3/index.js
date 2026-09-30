// ChainGate seed v3 — offline consumer: open, verify, check, why.
//
// The package entry point for reading a schema-v3 seed. It implements the CFT-04 runtime-consumption
// contract: compatibility is declared AND checked, trust is authenticated by default, the seed is
// opened read-only with no network access, `check` always re-evaluates, coverage is an outcome rather
// than an absence, and `why` is a pure function of the finding.
//
// No ALLOW / WARN / BLOCK is produced by the DETECTION path here. A finding carries evidence and
// coverage; mapping that to an action is policy, which is a separately versioned contract
// (`policy.js`, cft-policy-1.1) and is exported alongside rather than folded in. Nothing in the
// detection path imports it.

import contract from './contract.js';
import checker from './checker.js';
import reader from './reader.js';
import normalize from './normalize.js';
import logical from './logical.js';
import normalizeExtra from './normalize-extra.js';
import adapter from './adapter.js';
import packument from './packument.js';
import policy from './policy.js';
import gate from './gate.js';

// --- opening a seed -------------------------------------------------------------------------------
export const { openSeed, verify, Seed, SeedRefused } = reader;
export const { TRUST_AUTHENTICATED, TRUST_UNSIGNED_DEV, TRUST_MODES } = reader;

// --- supplying a candidate (facts are supplied, never invented) -------------------------------------
export const { candidateFromMapping, CandidateRejected, CANDIDATE_SPEC, CANDIDATE_REQUIRED } = reader;

// --- evaluation --------------------------------------------------------------------------------------
export const { check, loadPackage } = checker;

// --- identity of a seed --------------------------------------------------------------------------------
export const { logicalDigestOfDb } = logical;

// --- the registry-to-candidate adapter, and the shared vocabulary ----------------------------------------
// raw packument row -> validated candidate -> finding: the path a live consumer walks.
export const { candidateFromRawRow, evaluateRawRow, RawRowRejected } = adapter;
export const { canonicalRepoUrl, repoDigest, parsePublisherTool, resolvePublisherEmail } = normalizeExtra;

// --- the npm PACKUMENT adapter: the registry's own document -> explicit observation rows ---------------
// A separate layer from the extract-row adapter above: a packument has versions{}, a separate time{}
// map, nested dist{}, _npmUser and scripts{}, none of which an extract row has.
export const { observationsFromPackument, observationFromManifest, findingsFromPackument,
  PackumentRejected, PACKUMENT_ADAPTER_VERSION } = packument;

// --- POLICY: separately versioned, and the only place evidence becomes an action ------------------------
export const { decide, pinFor, OPEN_CHOICES, POLICY_CONTRACT_VERSION, PolicyConfigInvalid } = policy;

// --- the assembled installation path: packument -> row -> candidate -> finding -> policy -> GateResult ---
export const { createSeedV3Gate, placeInSeed, SEED_V3_GATE } = gate;

export { normalize, normalizeExtra, contract, adapter, packument, policy, gate };

export const SCHEMA_VERSION = 3;
export const CONTRACT_VERSION = contract.CONTRACT_VERSION;

export default {
  openSeed, verify, Seed, SeedRefused,
  TRUST_AUTHENTICATED, TRUST_UNSIGNED_DEV, TRUST_MODES,
  candidateFromMapping, CandidateRejected, CANDIDATE_SPEC, CANDIDATE_REQUIRED,
  check, loadPackage, logicalDigestOfDb,
  candidateFromRawRow, evaluateRawRow, RawRowRejected,
  canonicalRepoUrl, repoDigest, parsePublisherTool, resolvePublisherEmail,
  observationsFromPackument, observationFromManifest, findingsFromPackument, PackumentRejected,
  PACKUMENT_ADAPTER_VERSION,
  decide, pinFor, OPEN_CHOICES, POLICY_CONTRACT_VERSION, PolicyConfigInvalid,
  createSeedV3Gate, placeInSeed, SEED_V3_GATE,
  normalize, normalizeExtra, contract, adapter, packument, policy, gate,
  SCHEMA_VERSION, CONTRACT_VERSION,
};
