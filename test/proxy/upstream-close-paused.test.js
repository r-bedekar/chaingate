// The registry closes the connection while the proxy has not yet passed the download on (a slow or departed npm
// client). undici 6 then stops the whole process with an uncatchable `assert(!this.paused)` from its socket end
// handler (upstream undici issue 5360, fixed in undici 8.4.1). The trigger is a paused body whose read buffer is
// empty when the end of the stream arrives; a 64 KiB body (the body stream's high-water mark) arriving in one read
// makes that deterministic on loopback. Each case runs the proxy's real upstream request path, with the pinned
// client, in a child process, since the crash cannot be caught in-process. The body read after the pause must be the
// upstream's, byte for byte.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const CHILD = join(dirname(fileURLToPath(import.meta.url)), '..', 'helpers', 'upstream-close-paused-child.mjs');
const KiB = 1024;

function runChild(args) {
  return new Promise((resolve) => {
    const c = spawn(process.execPath, [CHILD, ...args], { stdio: ['ignore', 'pipe', 'pipe'] });
    let out = ''; let err = '';
    c.stdout.on('data', (d) => { out += d; });
    c.stderr.on('data', (d) => { err += d; });
    const timer = setTimeout(() => c.kill('SIGKILL'), 30_000);
    c.on('close', (code, signal) => {
      clearTimeout(timer);
      const line = out.split('\n').find((l) => l.startsWith('RESULT '));
      resolve({ code, signal, stderr: err, result: line ? JSON.parse(line.slice(7)) : null });
    });
  });
}

for (const kind of ['tarball', 'packument']) {
  for (const size of [64 * KiB, 16 * KiB, 1024 * KiB]) {
    test(`upstream closes while the ${kind} body is unread (${size / KiB} KiB): the proxy process survives and the body is whole`, async () => {
      const r = await runChild([kind, String(size), '500']);
      assert.doesNotMatch(r.stderr, /AssertionError|paused/, 'the HTTP client does not crash on the upstream close');
      assert.equal(r.code, 0, `the child exits cleanly (signal ${r.signal}); stderr: ${r.stderr.slice(0, 400)}`);
      assert.deepEqual(r.result, { ok: true, status: 200, bytes: size, same: true });
    });
  }
}
