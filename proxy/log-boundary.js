// U-05 gap-closure r2 (owner decision 6), A1: ONE logging boundary for the proxy, with a global output budget.
//
// Every line the proxy, the witness store, the gate runner, the dependency fetcher and the unstored-BLOCK record write goes
// through here. Two guarantees:
//   1. Logging can never change what the proxy does. A sink that throws is caught and counted; enforcement never waits
//      on, or branches on, a logging result. (A throwing logger used to be able to reject the request handler.)
//   2. Output is RATE-bounded. Event lines spend a token bucket (burst, refill per second); each line is cut to a byte
//      cap. Transition lines (a state that changed: storage failing or committing again, the record full) bypass the
//      bucket but are emitted only on a change and at most once per channel per minute. A summary line reports what was
//      suppressed, at most once a minute.
// What is NOT bounded: the size of the log file over unlimited time (proxy.log has no rotation), the proxy's start-up
// lines, and Node's own diagnostics. Rate-limited logs are not a complete per-decision record.

const DEFAULTS = Object.freeze({ burst: 300, perSecond: 1, lineBytes: 1024, summaryMs: 60_000 });

function clip(message, lineBytes, stats) {
  const s = typeof message === 'string' ? message : String(message);
  const bytes = Buffer.byteLength(s);
  if (bytes <= lineBytes) return s;
  stats.truncated += 1;
  const marker = (n) => `…[+${n} bytes]`;
  let keep = Buffer.from(s).subarray(0, Math.max(0, lineBytes - Buffer.byteLength(marker(bytes)))).toString('utf8');
  while (Buffer.byteLength(keep) + Buffer.byteLength(marker(bytes - Buffer.byteLength(keep))) > lineBytes) keep = keep.slice(0, -1);
  return keep + marker(bytes - Buffer.byteLength(keep));
}

/**
 * @param inner   the sink: { info?, warn?, error? }
 * @param opts    { burst, perSecond, lineBytes, summaryMs, now, stderr, timers, silentLevels }
 */
export function createLogBoundary(inner, opts = {}) {
  const o = { ...DEFAULTS, ...opts };
  const now = o.now ?? Date.now;
  const stderr = o.stderr ?? ((x) => process.stderr.write(x));
  const silent = new Set(o.silentLevels ?? []);
  const stats = { emitted: 0, suppressed: 0, truncated: 0, failures: 0, transitions: 0, transitions_suppressed: 0 };
  let tokens = o.burst;
  let last = now();
  let lastSummaryAt = now();
  let suppressedSinceSummary = 0;
  let lastFallbackAt = -Infinity;
  const channels = new Map();               // channel -> { value, at, pending: {value, message} | null }

  function fallback(err) {
    const t = now();
    if (t - lastFallbackAt < 60_000) return;
    lastFallbackAt = t;
    try {
      stderr(`[log] the proxy logger failed (${String(err?.message ?? err).slice(0, 120)}); further failures are counted, not printed\n`);
    } catch { /* nothing left to report to */ }
  }
  function write(level, line) {
    try {
      const fn = inner?.[level];
      if (typeof fn === 'function') fn.call(inner, line);
      stats.emitted += 1;
    } catch (err) {
      stats.failures += 1;
      fallback(err);
    }
  }
  function refill() {
    const t = now();
    if (t > last) { tokens = Math.min(o.burst, tokens + ((t - last) / 1000) * o.perSecond); last = t; }
  }
  function summary(force = false) {
    const t = now();
    if (suppressedSinceSummary > 0 && (force || t - lastSummaryAt >= o.summaryMs)) {
      const secs = Math.max(1, Math.round((t - lastSummaryAt) / 1000));
      const n = suppressedSinceSummary;
      suppressedSinceSummary = 0; lastSummaryAt = t;
      write('warn', `[log] suppressed ${n} line(s) in the last ${secs} s (log budget: ${o.burst} burst, ${o.perSecond}/s); `
        + 'rate-limited logs are not a complete per-decision record');
    } else if (suppressedSinceSummary === 0 && t - lastSummaryAt >= o.summaryMs) {
      lastSummaryAt = t;
    }
  }
  function flushPending() {
    const t = now();
    for (const [channel, c] of channels) {
      if (c.pending && t - c.at >= o.summaryMs) {
        const p = c.pending; c.pending = null;
        if (p.value !== c.value) { c.value = p.value; c.at = t; stats.transitions += 1; write('warn', p.line); }
      }
      void channel;
    }
  }
  function event(level, message) {
    if (silent.has(level)) return;
    let line;
    try { line = clip(message, o.lineBytes, stats); } catch { line = '[log] (unprintable message)'; }
    refill(); summary(); flushPending();
    if (tokens >= 1) { tokens -= 1; write(level, line); } else { stats.suppressed += 1; suppressedSinceSummary += 1; }
  }

  const boundary = {
    info: (m) => event('info', m),
    warn: (m) => event('warn', m),
    error: (m) => event('error', m),
    /** A state on `channel` changed to `value`: said once, when it changes, at most once per channel per minute. */
    transition(channel, value, message) {
      let line;
      try { line = clip(message, o.lineBytes, stats); } catch { line = `[log] ${channel}: ${value}`; }
      const t = now();
      const c = channels.get(channel);
      if (!c) { channels.set(channel, { value, at: t, pending: null }); stats.transitions += 1; write('warn', line); return; }
      if (c.value === value && !c.pending) return;
      if (t - c.at >= o.summaryMs) { c.value = value; c.at = t; c.pending = null; stats.transitions += 1; write('warn', line); return; }
      c.pending = { value, line };
      stats.transitions_suppressed += 1;
    },
    /** Periodic work: the suppression summary and pending transitions. Called by a timer, or by tests. */
    tick() { refill(); summary(); flushPending(); },
    stats() { return { ...stats, tokens: Math.floor(tokens) }; },
    close() { if (timer) clearInterval(timer); },
  };
  let timer = null;
  if (o.timers !== false) {
    timer = setInterval(() => { try { boundary.tick(); } catch { /* never throws out */ } }, o.summaryMs);
    timer.unref?.();
  }
  return boundary;
}
