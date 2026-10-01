// U-05 R2-2 (b) child: take the seed-mutation lock for <base>, say HELD, and keep it until a line arrives on stdin (then
// release and exit) or until killed. `kill-self` as the second argument SIGKILLs this process while it holds the lock;
// `die-after:<ms>` does so after <ms>.
import fs from 'node:fs';
const [base, mode] = process.argv.slice(2);
const { acquireSeedMutationLock, releaseSeedMutationLock } = await import('../../cli/seed-mutation-lock.js');
const t = acquireSeedMutationLock(base);
fs.writeSync(1, 'HELD\n');
if (mode === 'kill-self') process.kill(process.pid, 'SIGKILL');
// `die-after:<ms>`: SIGKILL itself while holding, after <ms> (the waiting side may be blocked synchronously meanwhile)
if (mode && mode.startsWith('die-after:')) setTimeout(() => process.kill(process.pid, 'SIGKILL'), Number(mode.slice(10)));
const b = Buffer.alloc(1);
while (fs.readSync(0, b, 0, 1, null) === 1 && b[0] !== 0x0a) { /* hold */ }
releaseSeedMutationLock(t);
fs.writeSync(1, 'RELEASED\n');
