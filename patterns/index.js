// V2 pattern extraction — registry + contract validator.
//
// Patterns are deterministic, pure extractors over a package's observed
// history. Each pattern produces a structured feature set that the V2
// gates (Section 11 step 3) consume. Contract:
//
//   export default {
//     name:     string          // unique registry key
//     version:  positive int    // bump invalidates persisted pattern_cache
//     requires: string[]        // input fields the pattern reads
//     extract(input) → object   // deterministic, pure
//   }
//
// No external I/O inside extract(). No Date.now(), no process.env reads.
// Same input must always produce byte-identical output — this is the
// property that lets us cache pattern outputs and validate across
// machines. Determinism is enforced by the harness in
// test/patterns/*.test.js.
//
// Build order (V2_DESIGN §11): publisher → provenance → cadence →
// script → dep-structure. Only publisher is registered today.

import publisher from './publisher.js';

export const PATTERN_REGISTRY = Object.freeze({
  [publisher.name]: publisher,
});

export function validatePattern(mod) {
  if (!mod || typeof mod !== 'object') {
    throw new Error('pattern module must be a non-null object');
  }
  if (typeof mod.name !== 'string' || mod.name.length === 0) {
    throw new Error('pattern.name must be a non-empty string');
  }
  if (!Number.isInteger(mod.version) || mod.version < 1) {
    throw new Error(`pattern.version must be a positive integer (got ${mod.version})`);
  }
  if (!Array.isArray(mod.requires)) {
    throw new Error('pattern.requires must be an array of input field names');
  }
  if (typeof mod.extract !== 'function') {
    throw new Error('pattern.extract must be a function');
  }
  return true;
}
