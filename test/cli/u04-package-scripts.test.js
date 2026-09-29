// The published package must not declare lifecycle scripts that run when users install it. npm 11/12
// list these as unapproved install scripts and warn on every install (seen on the owner's Windows run
// with a `prepare` hook-setup script), and a consumer should never need to approve anything but
// better-sqlite3.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

const pkg = JSON.parse(readFileSync(new URL('../../package.json', import.meta.url), 'utf8'));
const INSTALL_LIFECYCLE = ['preinstall', 'install', 'postinstall', 'prepublish', 'preprepare', 'prepare', 'postprepare'];

test('package.json declares no install-time lifecycle scripts', () => {
  const present = INSTALL_LIFECYCLE.filter((k) => k in (pkg.scripts || {}));
  assert.deepEqual(present, []);
});

test('git hook setup stays available as an explicit script', () => {
  assert.equal(pkg.scripts.hooks, 'git config core.hooksPath .githooks');
});
