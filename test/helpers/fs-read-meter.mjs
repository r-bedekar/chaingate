// U-05 R2-2 (c) test seam, loaded with `--import` into a CHILD process only: records how many bytes were read through
// each open of each path, so a test can show that a sidecar was read at most cap + 1 bytes. It wraps the fs functions
// the runtime uses and syncs the named ESM exports, so it measures the code under test without changing it.
import fs from 'node:fs';
import { syncBuiltinESMExports } from 'node:module';

const out = process.env.U05_READ_METER_OUT;
const open = new Map();          // fd -> { path, n }
const accesses = [];             // { path, bytes, via }
const real = { openSync: fs.openSync, readSync: fs.readSync, closeSync: fs.closeSync, readFileSync: fs.readFileSync,
  writeFileSync: fs.writeFileSync };

fs.openSync = function openSync(p, ...a) {
  const fd = real.openSync.call(fs, p, ...a);
  open.set(fd, { path: String(p), n: 0 });
  return fd;
};
fs.readSync = function readSync(fd, ...a) {
  const n = real.readSync.call(fs, fd, ...a);
  const e = open.get(fd); if (e) e.n += n;
  return n;
};
fs.closeSync = function closeSync(fd) {
  const e = open.get(fd);
  if (e) { accesses.push({ path: e.path, bytes: e.n, via: 'fd' }); open.delete(fd); }
  return real.closeSync.call(fs, fd);
};
fs.readFileSync = function readFileSync(p, ...a) {
  const r = real.readFileSync.call(fs, p, ...a);
  const bytes = typeof r === 'string' ? Buffer.byteLength(r) : r.length;
  if (typeof p === 'number') { const e = open.get(p); if (e) e.n += bytes; } else accesses.push({ path: String(p), bytes, via: 'readFileSync' });
  return r;
};
syncBuiltinESMExports();

process.on('exit', () => {
  for (const e of open.values()) accesses.push({ path: e.path, bytes: e.n, via: 'fd-unclosed' });
  if (out) real.writeFileSync.call(fs, out, JSON.stringify(accesses));
});
