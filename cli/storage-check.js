// U-05 gap-closure r2 (owner decision 6), Addendum 1 §B: the doctor check and status text for the RUNNING proxy's storage
// state. The state itself is computed by the proxy (proxy/storage-health.js) and read from /_chaingate/self; this module
// only words it. A positive in-memory count or FULL never passes. Persisted decisions are reported separately by
// `status` from the witness database; the in-memory count is never added to them.

function held(u) {
  const n = u?.count ?? 0;
  const sample = Array.isArray(u?.sample) && u.sample.length
    ? `; re-request: ${u.sample.slice(0, 5).join(', ')}${u.sample.length > 5 || n > u.sample.length ? ', …' : ''}` : '';
  return { n, text: `${n} BLOCK(s) held only in memory (not stored; a restart forgets them)`, sample };
}

function fullText(u) {
  return `the unstored-BLOCK record is FULL since ${u?.full_since ?? 'an unknown time'} (${u?.overflowed ?? 0} BLOCK(s) `
    + 'could not be remembered): tarballs without a stored BLOCK or an exact override are refused until the proxy restarts '
    + '(a resource-safety refusal, not a finding about any package)';
}

/** Words for one storage state, from a /_chaingate/self document. */
export function describeStorage(self) {
  const st = self?.storage; const u = self?.unstored_blocks;
  const f = st?.last_failure;
  const failing = `decision storage failing since ${st?.last_failure_at ?? 'an unknown time'}`
    + (f ? ` (stage ${f.stage}: ${f.message})` : '');
  const h = held(u);
  switch (st?.state) {
    case 'healthy': return 'decision writes are committing; no BLOCK is held only in memory';
    case 'recovered': return 'No BLOCK remains held only in memory: each was stored, or superseded by a later evaluated '
      + `decision under the approved rules. Decision writes have committed since ${st.last_ok_at} (${st.failure_count} `
      + `earlier storage failure(s)). This does not mean that every earlier BLOCK is stored or that future writes will succeed.`;
    case 'no_evidence': return 'no decision write has been attempted since the proxy started: write health is not yet established';
    case 'held': return `${h.text}; `
      + (st.last_outcome === 'ok' ? `decision writes have committed since ${st.last_ok_at}${h.sample}`
        : `no write-health evidence yet (no decision write attempted since start)${h.sample}`);
    case 'failing': return `${failing}; no BLOCK is held only in memory`;
    case 'failing_held': return `${failing}; ${h.text}${h.sample}`;
    case 'full_held': return `${fullText(u)}; ${h.text}${h.sample}`;
    case 'full_empty': return `${fullText(u)}. The record is now empty, but FULL stays until the proxy restarts: restart `
      + 'only after decision writes commit again; BLOCKs that could not be remembered are unknown until their packuments '
      + 'are observed again';
    default: return null;
  }
}

/**
 * The `witness-storage` doctor check. `pid` is readPidRecord's result (or null); `self` is the parsed /_chaingate/self
 * document, or null when it could not be read.
 */
export function witnessStorageCheck({ pid, self }) {
  const name = 'witness-storage';
  if (!pid || pid.state === 'dead' || pid.state === 'malformed') {
    return { name, pass: true, severity: 'skipped', state: 'not_running',
      detail: 'proxy not running: there is no in-memory decision state to report (anything a stopped proxy held only in memory is gone)' };
  }
  if (!self) {
    return { name, pass: false, severity: 'unverifiable', state: 'unreachable',
      detail: pid.state === 'indeterminate'
        ? `the operating system refused the liveness check for pid ${pid.pid} (${pid.code}); the proxy's storage state could not be read`
        : `pid ${pid.pid} is alive but /_chaingate/self did not answer; the storage state is unknown` };
  }
  const detail = describeStorage(self);
  if (!detail) {
    return { name, pass: false, severity: 'unverifiable', state: 'unreachable',
      detail: `the running proxy (version ${self.version ?? 'unknown'}) does not report storage health` };
  }
  const state = self.storage.state;
  if (state === 'healthy' || state === 'recovered') return { name, pass: true, state, detail };
  if (state === 'no_evidence') return { name, pass: true, severity: 'skipped', state, detail };
  return { name, pass: false, state, detail };
}
