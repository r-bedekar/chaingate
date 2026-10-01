// U-05 R2-2 (c) child: run one verification entry point on a path and print its verdict as JSON. Used with the read
// meter (fs-read-meter.mjs) so the parent sees how many bytes each access read.
//   node u05-r22-verify-bundle.mjs bundle <bundle dir>
//   node u05-r22-verify-bundle.mjs persisted <sha256 path> <sig path> <base64 SPKI public key>
const [mode, a, b, key] = process.argv.slice(2);
try {
  if (mode === 'bundle') {
    const { verifyBundleDir } = await import('../../cli/seed-bundle.js');
    const v = verifyBundleDir(a);
    console.log(JSON.stringify({ ok: v.ok, why: v.why }));
  } else if (mode === 'persisted') {
    const { createPublicKey } = await import('node:crypto');
    const { verifyPersistedSignature } = await import('../../witness/seed_verify.js');
    const pubkey = createPublicKey({ key: Buffer.from(key, 'base64'), format: 'der', type: 'spki' });
    try { await verifyPersistedSignature(a, b, { pubkey }); console.log(JSON.stringify({ ok: true })); }
    catch (e) { console.log(JSON.stringify({ ok: false, code: e.code, why: e.message })); }
  } else throw new Error(`unknown mode ${mode}`);
} catch (e) {
  console.log(JSON.stringify({ ok: false, threw: `${e.name}: ${e.message}` }));
}
