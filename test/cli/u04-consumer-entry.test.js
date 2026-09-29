// U-04 — the example CI consumer (examples/ci/chaingate-ci.mjs) must actually run when started from a
// path with a space or a non-ASCII character. Its old entry check compared against
// `new URL(import.meta.url).pathname`, which is percent-encoded (and /D:/... on Windows), so the
// consumer exited 0 WITHOUT checking anything: a CI gate that silently passes.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { copyFileSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..', '..');

test('the consumer runs (usage error, exit 2) from a path with a space and a non-ASCII character', () => {
  const dir = mkdtempSync(join(tmpdir(), 'chaingate ci zoë '));
  try {
    const script = join(dir, 'chaingate-ci.mjs');
    copyFileSync(join(ROOT, 'examples', 'ci', 'chaingate-ci.mjs'), script);
    const r = spawnSync(process.execPath, [script, '--definitely-not-an-option'], { encoding: 'utf8', timeout: 30_000 });
    assert.equal(r.status, 2, `it must run and reject the argument, not exit silently; stdout=${r.stdout} stderr=${r.stderr}`);
    assert.match(`${r.stdout}${r.stderr}`, /usage: chaingate-ci/);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
