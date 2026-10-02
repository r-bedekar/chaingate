// U-05 gap-closure r2, truthful stop, found by Windows CI (run 36982191770, S-1 and S-9): after the proxy is terminated,
// Windows keeps its listening socket for a moment, so the port still accepts while nothing answers there. `stop` called
// that STOPPED_PORT_TAKEN ("now answered by nothing is listening"), and `init --force` then refused to restart.
// The rule: only an IDENTIFIABLE answer on the port means it was taken; an unanswered port is waited out within the same
// bound. Written before the fix; the port probe and the self request are injected here (the `kill` seam's pattern).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

import { stopProxy } from '../../cli/proxy-control.js';

const PID = 424242;
function setup() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cg-stop-transient-'));
  const pidFile = path.join(dir, 'proxy.pid'); fs.writeFileSync(pidFile, `${PID}\n`);
  let dead = false;
  const kill = (pid, sig) => {                      // alive until SIGTERM, then gone
    if (sig === 'SIGTERM') { dead = true; return true; }
    if (dead) throw Object.assign(new Error('no such process'), { code: 'ESRCH' });
    return true;
  };
  return { dir, pidFile, kill, cleanup: () => fs.rmSync(dir, { recursive: true, force: true }) };
}
const owned = { ok: true, json: { service: 'chaingate-proxy', pid: PID, version: '0.1.3' } };
const nobody = { ok: false, why: 'nothing is listening' };

test('S-12 the pid is gone, the port still accepts for a moment and nobody answers there: STOPPED', async () => {
  const s = setup();
  try {
    let probes = 0; let selfCalls = 0;
    const r = await stopProxy(s.pidFile, { port: 1, kill: s.kill, pollMs: 10, waitMs: 3000,
      probePort: async () => { probes += 1; return probes <= 3; },
      self: async () => { selfCalls += 1; return selfCalls === 1 ? owned : nobody; } });
    assert.equal(r.outcome, 'stopped', r.detail);
    assert.equal(fs.existsSync(s.pidFile), false);
  } finally { s.cleanup(); }
});

test('S-13 the pid is gone and an identifiable listener answers on the port: STOPPED_PORT_TAKEN at once, naming it', async () => {
  const s = setup();
  try {
    let selfCalls = 0;
    const other = { ok: true, json: { service: 'something-else' } };
    const t0 = Date.now();
    const r = await stopProxy(s.pidFile, { port: 1, kill: s.kill, pollMs: 10, waitMs: 3000,
      probePort: async () => true, self: async () => { selfCalls += 1; return selfCalls === 1 ? owned : other; } });
    assert.equal(r.outcome, 'stopped_port_taken'); assert.match(r.detail, /something-else/);
    assert.ok(Date.now() - t0 < 1500, 'not held for the whole wait');
  } finally { s.cleanup(); }
});

test('S-14 the pid is gone and the port keeps accepting past the wait with nobody answering: STOPPED_PORT_TAKEN, saying so', async () => {
  const s = setup();
  try {
    let selfCalls = 0;
    const r = await stopProxy(s.pidFile, { port: 1, kill: s.kill, pollMs: 10, waitMs: 300,
      probePort: async () => true, self: async () => { selfCalls += 1; return selfCalls === 1 ? owned : nobody; } });
    assert.equal(r.outcome, 'stopped_port_taken');
    assert.match(r.detail, /still accepts connections and nothing identifies itself/);
  } finally { s.cleanup(); }
});
