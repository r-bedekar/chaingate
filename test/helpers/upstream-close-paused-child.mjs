// Child for upstream-close-paused.test.js: the upstream sends a whole response with `connection: close` and closes its
// side at once, while the consumer of the proxy's upstream request has not read the body yet (a slow or departed npm
// client). After a pause the body is read to the end. Prints "RESULT <json>". A crash of the HTTP client in its socket
// end handler cannot be caught, so it ends this process, which the parent sees as the exit code and stderr.
//   node upstream-close-paused-child.mjs <tarball|packument> <bytes> <pauseMs>
import fs from 'node:fs';
import net from 'node:net';
import { fetchTarball, fetchPackument } from '../../proxy/registry.js';

const [kind, sizeArg, pauseArg] = process.argv.slice(2);
const size = Number(sizeArg); const pauseMs = Number(pauseArg);
const say = (o) => fs.writeSync(1, `RESULT ${JSON.stringify(o)}\n`);
const body = Buffer.alloc(size, 0x61);

const upstream = net.createServer((sock) => {
  sock.on('error', () => {});
  sock.once('data', () => {
    sock.write(`HTTP/1.1 200 OK\r\ncontent-type: application/octet-stream\r\ncontent-length: ${size}\r\nconnection: close\r\n\r\n`);
    sock.write(body);
    sock.end();
  });
});
await new Promise((resolve) => upstream.listen(0, '127.0.0.1', resolve));
const config = { upstream: `http://127.0.0.1:${upstream.address().port}`, headersTimeoutMs: 5_000, bodyTimeoutMs: 10_000 };

try {
  const res = kind === 'packument'
    ? await fetchPackument('p', { config })
    : await fetchTarball('p', 'p-1.0.0.tgz', { config });
  await new Promise((resolve) => setTimeout(resolve, pauseMs));
  let bytes = 0; let same = true;
  for await (const chunk of res.body) {
    for (let i = 0; i < chunk.length; i += 1) if (chunk[i] !== 0x61) { same = false; break; }
    bytes += chunk.length;
  }
  say({ ok: true, status: res.statusCode, bytes, same });
} catch (err) {
  say({ ok: false, name: err?.name ?? null, code: err?.code ?? null, message: String(err?.message ?? err).slice(0, 200) });
}
upstream.close();
