// Since 0.1.6: reading the pins feed. A key manifest signed by the seed key names the pins keys; a cut is signed by the pins
// key valid at its own time; a newer cut is taken only when its chain reaches the kept cut with every link checked (no gaps);
// past 7 days or over 2,000 new versions a cut is held for --accept-cut. Keys here are fixture keys made per run.
// Written before the code.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import { createHash, generateKeyPairSync, sign as cryptoSign } from 'node:crypto';
import { openWitnessDB } from '../../witness/db.js';
import * as PF from '../../witness/pins-feed.js';
import { refreshPins, dirSource, urlSource } from '../../cli/pins-feed.js';

const { PINS_FEED_VERSION, KEY_MANIFEST_VERSION, PinsFeedRefused, verifyKeyManifest, parseCut, verifyCut, decideCut, keyIdOf,
  stampOf, storeRows, feedAge } = PF;

// ------------------------------------------------------------------------------------------------ a fixture publisher
const canon = (v) => (Array.isArray(v) ? `[${v.map(canon).join(',')}]`
  : v !== null && typeof v === 'object' ? `{${Object.keys(v).sort().map((k) => `${JSON.stringify(k)}:${canon(v[k])}`).join(',')}}`
    : JSON.stringify(v));
const sha = (b) => createHash('sha256').update(b).digest('hex');
const newKey = () => {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  const der = publicKey.export({ format: 'der', type: 'spki' });
  return { publicKey, privateKey, der, id: keyIdOf(der), spki: der.toString('base64') };
};
const SEED = newKey();
const PINS = newKey();
const H = 3600e3; const D = 24 * H;
const T0 = Date.parse('2026-10-29T10:00:00Z');
const iso = (ms) => new Date(ms).toISOString().replace(/\.\d{3}Z$/, 'Z');

function manifest(keys, seed = SEED) {
  const bytes = Buffer.from(canon({ key_manifest_version: KEY_MANIFEST_VERSION, keys }), 'ascii');
  return { bytes, sig: cryptoSign(null, bytes, seed.privateKey) };
}
const pinsEntry = (k = PINS, from = T0 - D, days = 90, role = 'pins') => ({ key_id: k.id, spki_b64: k.spki, role, valid_from: iso(from),
  valid_to: iso(from + days * D) });
const KEYS = verifyKeyManifest(manifest([pinsEntry()]).bytes, manifest([pinsEntry()]).sig, { seedKey: SEED.publicKey });

const row = (name, version, extra = {}) => ({ name, version, advisory_id: `MAL-2026-${name}-${version}`, also_advisories: [],
  record_id: sha(`${name}@${version}`), source: 'osv', evidence: { kind: 'advisory', advisory_id: `MAL-2026-${name}-${version}` },
  added_at: '2026-10-29T09:00:00Z', ...extra });
const capture = (name, version) => row(name, version, { advisory_id: `CHAINGATE-${sha(name).slice(0, 16)}`, source: 'chaingate-analyst',
  evidence: { kind: 'capture', sha256: sha(`tgz:${name}`), dist_integrity: `sha512-${'A+/b'.repeat(21)}AB==` } });

/** One cut: bytes, signature, parsed head, digest. `prev` is the previous cut or null. */
function cut(atMs, rows, prev = null, { key = PINS, head = {} } = {}) {
  const h = { feed_version: PINS_FEED_VERSION, cut_at: iso(atMs), count: rows.length, prev_cut_digest: prev ? prev.digest : null,
    prev_cut_at: prev ? prev.head.cut_at : null, pins_key_id: key.id, label_input_digest: sha('label'),
    label_input_metadata_cutoff: '2026-10-29T08:00:00Z', ...head };
  const sorted = [...rows].sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : a.version < b.version ? -1 : 1));
  const bytes = Buffer.from([h, ...sorted].map((o) => `${canon(o)}\n`).join(''), 'ascii');
  const digest = sha(bytes);
  return { bytes, sig: cryptoSign(null, Buffer.from(digest, 'ascii'), key.privateKey), head: h, digest };
}
const keptOf = (c) => ({ cut_at: c.head.cut_at, digest: c.digest, pairs: new Set(parseCut(c.bytes).rows.map((r) => `${r.name}@${r.version}`)) });
const loaderOf = (cuts) => async (stamp) => {
  const c = cuts.find((x) => stampOf(x.head.cut_at) === stamp);
  if (!c) throw new Error(`no dated copy ${stamp}`);
  return { bytes: c.bytes, sig: c.sig };
};
const refused = (p, re) => assert.rejects(p, (e) => e instanceof PinsFeedRefused && re.test(e.why));
const throwsRefused = (fn, re) => assert.throws(fn, (e) => e instanceof PinsFeedRefused && re.test(e.why));

function writeFeed(dir, man, latest, dated = []) {
  fs.mkdirSync(path.join(dir, 'cuts'), { recursive: true });
  fs.writeFileSync(path.join(dir, 'keys.json'), man.bytes); fs.writeFileSync(path.join(dir, 'keys.json.sig'), man.sig);
  fs.writeFileSync(path.join(dir, 'latest.jsonl'), latest.bytes); fs.writeFileSync(path.join(dir, 'latest.jsonl.sig'), latest.sig);
  for (const c of dated) {
    fs.writeFileSync(path.join(dir, 'cuts', `${stampOf(c.head.cut_at)}.jsonl`), c.bytes);
    fs.writeFileSync(path.join(dir, 'cuts', `${stampOf(c.head.cut_at)}.jsonl.sig`), c.sig);
  }
}
function withStore(fn) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'pins-feed-'));
  const db = openWitnessDB(path.join(dir, 'witness.db')); db.applySchema();
  return Promise.resolve().then(() => fn(db, dir)).finally(() => { db.close(); fs.rmSync(dir, { recursive: true, force: true }); });
}

// ------------------------------------------------------------------------------------------------ the key manifest
test('PF1 the key manifest: signed by the seed key, each key carrying its own id, at most 90 days, role pins', () => {
  assert.equal(KEYS.length, 1); assert.equal(KEYS[0].key_id, PINS.id);
  assert.match(PINS.id, /^ed25519:[0-9a-f]{16}$/);
  const m = manifest([pinsEntry()]);
  throwsRefused(() => verifyKeyManifest(m.bytes, m.sig, { seedKey: newKey().publicKey }), /does not verify against the seed key/);
  throwsRefused(() => verifyKeyManifest(m.bytes, Buffer.alloc(63), { seedKey: SEED.publicKey }), /not 64 bytes/);
  const lied = manifest([{ ...pinsEntry(), key_id: newKey().id }]);
  throwsRefused(() => verifyKeyManifest(lied.bytes, lied.sig, { seedKey: SEED.publicKey }), /does not match its public key/);
  const long = manifest([pinsEntry(PINS, T0, 91)]);
  throwsRefused(() => verifyKeyManifest(long.bytes, long.sig, { seedKey: SEED.publicKey }), /over 90 days/);
  const shards = manifest([pinsEntry(PINS, T0, 30, 'shards')]);
  throwsRefused(() => verifyKeyManifest(shards.bytes, shards.sig, { seedKey: SEED.publicKey }), /names no pins key/);
  // one list for both keys, as published: each reader takes its own role; any key over 90 days refuses the list for both
  const SHK = newKey();
  const both = manifest([pinsEntry(), pinsEntry(SHK, T0, 90, 'shards')]);
  assert.deepEqual(verifyKeyManifest(both.bytes, both.sig, { seedKey: SEED.publicKey }).map((k) => k.key_id), [PINS.id]);
  assert.deepEqual(verifyKeyManifest(both.bytes, both.sig, { seedKey: SEED.publicKey, role: 'shards' }).map((k) => k.key_id), [SHK.id]);
  const longShards = manifest([pinsEntry(), pinsEntry(SHK, T0, 91, 'shards')]);
  throwsRefused(() => verifyKeyManifest(longShards.bytes, longShards.sig, { seedKey: SEED.publicKey }), /over 90 days/);
  const other = Buffer.from(canon({ key_manifest_version: 'pins-keys-9', keys: [pinsEntry()] }));
  throwsRefused(() => verifyKeyManifest(other, cryptoSign(null, other, SEED.privateKey), { seedKey: SEED.publicKey }), /not pins-keys-1.0/);
});

// ------------------------------------------------------------------------------------------------ the cut format
test('PF2 a cut parses only as written: ASCII lines, the header fields, the count, sorted unique rows, evidence by source', () => {
  const c = cut(T0, [row('a', '1.0.0'), capture('b', '2.0.0')]);
  const p = parseCut(c.bytes);
  assert.equal(p.digest, c.digest); assert.equal(p.rows.length, 2); assert.equal(p.rows[1].evidence.kind, 'capture');
  const bad = (bytes, re) => throwsRefused(() => parseCut(Buffer.from(bytes)), re);
  const lines = c.bytes.toString('ascii').split('\n');
  bad(c.bytes.toString('ascii').slice(0, -1), /newline/);
  bad(c.bytes.toString('ascii').replace('"a"', '"\u00e4"'), /ASCII/);
  bad([lines[0], lines[1], ''].join('\n'), /counts 2 rows, the cut has 1/);
  bad([lines[0], lines[2], lines[1], ''].join('\n'), /not sorted/);
  bad([lines[0].replace('"count":2', '"count":3'), lines[1], lines[1], ''].join('\n'), /counts 3|not sorted|repeat/);
  bad(`${canon(Object.fromEntries(Object.entries(c.head).filter(([k]) => k !== 'prev_cut_at')))}\n${lines.slice(1).join('\n')}`, /header fields/);
  bad(`${canon({ ...c.head, feed_version: 'pins-feed-1.2' })}\n${lines.slice(1).join('\n')}`, /reads pins-feed/);
  bad(`${canon({ ...c.head, prev_cut_digest: sha('x') })}\n${lines.slice(1).join('\n')}`, /both name an earlier cut/);
  const one = (r) => `${canon({ ...c.head, count: 1 })}\n${canon(r)}\n`;
  bad(one({ ...row('a', '1.0.0'), source: 'npm' }), /unknown source/);
  bad(one({ ...row('a', '1.0.0'), source: 'chaingate-analyst' }), /does not fit its source/);
  bad(one({ ...capture('a', '1.0.0'), source: 'osv' }), /does not fit its source/);
  bad(one({ ...capture('a', '1.0.0'), evidence: { kind: 'capture', sha256: 'short', dist_integrity: null } }), /bad evidence/);
  bad(one({ ...row('a', '1.0.0'), extra: 1 }), /row fields/);
  const capEv = (di) => one({ ...capture('a', '1.0.0'), evidence: { kind: 'capture', sha256: sha('t'), dist_integrity: di } });
  assert.equal(parseCut(Buffer.from(capEv(capture('a', '1.0.0').evidence.dist_integrity))).rows.length, 1);
  for (const di of [null, 'sha1-abc=', 'sha512-short==', `sha256-${'A'.repeat(43)}=`]) bad(capEv(di), /bad evidence/);
});

test('PF3 a cut is checked against the pins key its header names, valid at the cut time, over the ASCII digest', () => {
  const c = cut(T0, [row('a', '1.0.0')]);
  assert.equal(verifyCut(parseCut(c.bytes), c.sig, KEYS).digest, c.digest);
  throwsRefused(() => verifyCut(parseCut(c.bytes), cut(T0, [row('b', '1.0.0')]).sig, KEYS), /does not verify/);
  const stranger = newKey(); const s = cut(T0, [row('a', '1.0.0')], null, { key: stranger });
  throwsRefused(() => verifyCut(parseCut(s.bytes), s.sig, KEYS), /no pins key ed25519:[0-9a-f]{16} is valid/);
  const late = cut(T0 + 95 * D, [row('a', '1.0.0')]);
  throwsRefused(() => verifyCut(parseCut(late.bytes), late.sig, KEYS), /is valid at/);
  // a raw-bytes signature (over the 32 digest bytes) is not the form
  const raw = cryptoSign(null, Buffer.from(c.digest, 'hex'), PINS.privateKey);
  throwsRefused(() => verifyCut(parseCut(c.bytes), raw, KEYS), /does not verify/);
});

// ------------------------------------------------------------------------------------------------ deciding
test('PF4 the first cut is taken; the same cut is "same"; an older or equal cut and a future cut are refused', async () => {
  const c1 = cut(T0, [row('a', '1.0.0')]); const c2 = cut(T0 + H, [row('a', '1.0.0')], c1);
  const loadCut = loaderOf([c1, c2]); const now = T0 + 2 * H;
  assert.equal((await decideCut({ latest: c1, kept: null, loadCut, keys: KEYS, now })).action, 'accept');
  assert.equal((await decideCut({ latest: c2, kept: keptOf(c2), loadCut, keys: KEYS, now })).action, 'same');
  await refused(decideCut({ latest: c1, kept: keptOf(c2), loadCut, keys: KEYS, now }), /not later than the kept cut/);
  const ahead = cut(now + H, [row('a', '1.0.0')], c2);
  await refused(decideCut({ latest: ahead, kept: keptOf(c2), loadCut, keys: KEYS, now }), /in the future/);
});

test('PF5 no gaps: a newer cut is taken only when its chain reaches the kept cut, every link checked', async () => {
  const F = rowsN(8, 'f');                                // filler, so one removal stays within the removal guard
  const c1 = cut(T0, [row('a', '1.0.0'), ...F]);
  const c2 = cut(T0 + H, [row('a', '1.0.0'), row('b', '1.0.0'), ...F], c1);
  const c3 = cut(T0 + 2 * H, [row('b', '1.0.0'), ...F], c2);
  const c4 = cut(T0 + 3 * H, [row('b', '1.0.0'), row('c', '1.0.0'), ...F], c3);
  const now = T0 + 4 * H; const kept = keptOf(c1);
  const next = await decideCut({ latest: c2, kept, loadCut: loaderOf([]), keys: KEYS, now });
  assert.deepEqual([next.action, next.walked], ['accept', 0], 'the next cut needs no walk');
  const walked = await decideCut({ latest: c4, kept, loadCut: loaderOf([c1, c2, c3, c4]), keys: KEYS, now });
  assert.deepEqual([walked.action, walked.walked], ['accept', 2]);
  // a missing dated copy refuses: never skipped
  await refused(decideCut({ latest: c4, kept, loadCut: loaderOf([c1, c2, c4]), keys: KEYS, now }), /cannot be read/);
  // a dated copy that is not the cut the next one names
  const c3b = cut(T0 + 2 * H, [row('z', '9.9.9'), ...F], c2);
  await refused(decideCut({ latest: c4, kept, loadCut: loaderOf([c1, c2, c3b]), keys: KEYS, now }), /is not the one/);
  // a link signed by a key the manifest does not name
  const c3s = { ...c3, sig: cut(T0 + 2 * H, [row('b', '1.0.0'), ...F], c2, { key: newKey() }).sig };
  await refused(decideCut({ latest: c4, kept, loadCut: loaderOf([c1, c2, c3s]), keys: KEYS, now }), /does not verify|no pins key/);
  // a fork: a chain that passes the kept cut's time without naming it
  const f2 = cut(T0 + H, [row('x', '1.0.0')], c1); const f3 = cut(T0 + 2 * H, [row('x', '1.0.0')], f2);
  const forkKept = keptOf(c2);
  await refused(decideCut({ latest: f3, kept: forkKept, loadCut: loaderOf([c1, f2]), keys: KEYS, now }), /does not lead back/);
  // a chain that starts over (prev null) is not a way past the kept cut
  const fresh = cut(T0 + 3 * H, [row('a', '1.0.0')]);
  await refused(decideCut({ latest: fresh, kept, loadCut: loaderOf([]), keys: KEYS, now }), /does not lead back/);
});

test('PF6 past 7 days, or over 2,000 new versions, a cut is HELD; --accept-cut with its digest takes it', async () => {
  const c1 = cut(T0, [row('a', '1.0.0')]);
  const far = cut(T0 + 8 * D, [row('a', '1.0.0')], { digest: sha('elsewhere'), head: { cut_at: iso(T0 + 8 * D - H) } });
  const now = T0 + 8 * D + H;
  const h = await decideCut({ latest: far, kept: keptOf(c1), loadCut: loaderOf([]), keys: KEYS, now });
  assert.equal(h.action, 'held'); assert.match(h.why, /more than 7 days/);
  const taken = await decideCut({ latest: far, kept: keptOf(c1), loadCut: loaderOf([]), keys: KEYS, now, accept: far.digest });
  assert.equal(taken.action, 'accept'); assert.match(taken.why, /--accept-cut/);
  const other = await decideCut({ latest: far, kept: keptOf(c1), loadCut: loaderOf([]), keys: KEYS, now, accept: sha('other') });
  assert.equal(other.action, 'held', 'only the named digest is taken');

  const many = [row('a', '1.0.0'), ...Array.from({ length: 2001 }, (_, i) => row(`w${String(i).padStart(5, '0')}`, '1.0.0'))];
  const flood = cut(T0 + H, many, c1);
  const fh = await decideCut({ latest: flood, kept: keptOf(c1), loadCut: loaderOf([]), keys: KEYS, now: T0 + 2 * H });
  assert.equal(fh.action, 'held'); assert.match(fh.why, /adds 2001 new versions/);
  const ok2000 = cut(T0 + H, many.slice(0, 2001), c1);
  assert.equal((await decideCut({ latest: ok2000, kept: keptOf(c1), loadCut: loaderOf([]), keys: KEYS, now: T0 + 2 * H })).action, 'accept');
  assert.equal((await decideCut({ latest: flood, kept: keptOf(c1), loadCut: loaderOf([]), keys: KEYS, now: T0 + 2 * H,
    accept: flood.digest })).action, 'accept');
});

test('PF7 feed age: fresh, old past 48 hours, stale past 7 days', () => {
  const k = { cut_at: iso(T0) };
  assert.equal(feedAge(null, T0).state, 'none');
  assert.equal(feedAge(k, T0 + 47 * H).state, 'fresh');
  assert.equal(feedAge(k, T0 + 49 * H).state, 'old');
  assert.equal(feedAge(k, T0 + 7 * D + H).state, 'stale');
});

// ------------------------------------------------------------------------------------------------ fetch and apply
test('PF8 refresh from a directory: accepted cuts land in the store, a refused or unreadable feed keeps the kept cut serving', async () => {
  await withStore(async (db, dir) => {
    const feed = path.join(dir, 'feed'); const man = manifest([pinsEntry()]);
    const F = rowsN(8, 'f');
    const c1 = cut(T0, [row('a', '1.0.0'), capture('b', '2.0.0'), ...F]);
    writeFeed(feed, man, c1, [c1]);
    const r1 = await refreshPins({ get: dirSource(feed), db, seedKey: SEED.publicKey, now: T0 + H });
    assert.equal(r1.outcome, 'accepted'); assert.equal(db.advisoryPinsFeed().digest, c1.digest);
    const pin = db.advisoryPinFor('b', '2.0.0');
    assert.equal(pin.source, 'chaingate-analyst'); assert.equal(JSON.parse(pin.evidence_json).kind, 'capture');
    assert.deepEqual(storeRows(parseCut(c1.bytes))[0].package_name, 'a');
    assert.equal((await refreshPins({ get: dirSource(feed), db, seedKey: SEED.publicKey, now: T0 + H })).outcome, 'same');

    // two cuts later, both dated copies present: walked and accepted; 'a' is no longer a pin
    const c2 = cut(T0 + H, [capture('b', '2.0.0'), ...F], c1); const c3 = cut(T0 + 2 * H, [capture('b', '2.0.0'), row('c', '3.0.0'), ...F], c2);
    writeFeed(feed, man, c3, [c2, c3]);
    const r3 = await refreshPins({ get: dirSource(feed), db, seedKey: SEED.publicKey, now: T0 + 3 * H });
    assert.deepEqual([r3.outcome, r3.walked], ['accepted', 1]);
    assert.equal(db.advisoryPinFor('a', '1.0.0'), null); assert.ok(db.advisoryPinFor('c', '3.0.0'));

    // a cut whose dated predecessor is gone: refused, recorded, c3 keeps serving
    const c4 = cut(T0 + 3 * H, [row('d', '4.0.0')], c3); const c5 = cut(T0 + 4 * H, [row('d', '4.0.0')], c4);
    writeFeed(feed, man, c5, []); fs.rmSync(path.join(feed, 'cuts', `${stampOf(c4.head.cut_at)}.jsonl`), { force: true });
    const r5 = await refreshPins({ get: dirSource(feed), db, seedKey: SEED.publicKey, now: T0 + 5 * H });
    assert.equal(r5.outcome, 'refused'); assert.match(r5.why, /cannot be read/);
    assert.equal(db.advisoryPinsFeed().digest, c3.digest); assert.ok(db.advisoryPinFor('c', '3.0.0'));
    assert.equal(db.advisoryPinsFetch().outcome, 'refused');

    // nothing there at all: failed, still c3
    const r6 = await refreshPins({ get: dirSource(path.join(dir, 'nowhere')), db, seedKey: SEED.publicKey, now: T0 + 5 * H });
    assert.equal(r6.outcome, 'failed'); assert.equal(db.advisoryPinsFeed().digest, c3.digest);

    // a manifest the seed key did not sign: refused
    writeFeed(feed, manifest([pinsEntry()], newKey()), c5, [c4, c5]);
    assert.equal((await refreshPins({ get: dirSource(feed), db, seedKey: SEED.publicKey, now: T0 + 5 * H })).outcome, 'refused');

    // held: recorded with its digest; --accept-cut takes exactly that digest
    const far = cut(T0 + 9 * D, [row('e', '5.0.0')], { digest: sha('x'), head: { cut_at: iso(T0 + 9 * D - H) } });
    writeFeed(feed, man, far, []);
    const held = await refreshPins({ get: dirSource(feed), db, seedKey: SEED.publicKey, now: T0 + 9 * D + H });
    assert.equal(held.outcome, 'held'); assert.equal(db.advisoryPinsFetch().held_digest, far.digest);
    assert.equal(db.advisoryPinsFeed().digest, c3.digest);
    const taken = await refreshPins({ get: dirSource(feed), db, seedKey: SEED.publicKey, now: T0 + 9 * D + H, accept: far.digest });
    assert.equal(taken.outcome, 'accepted'); assert.ok(db.advisoryPinFor('e', '5.0.0'));
  });
});

test('PF9 the replace happens only while the kept cut is the one the decision read', async () => {
  await withStore(async (db) => {
    const r = [{ package_name: 'a', version: '1.0.0', record_id: 'r', advisory_id: 'MAL-1', source: 'osv', evidence_json: null, added_at: null }];
    assert.equal(db.replaceAdvisoryPins({ cutAt: iso(T0), digest: 'a'.repeat(64), rows: r, expectDigest: null }), true);
    assert.equal(db.replaceAdvisoryPins({ cutAt: iso(T0 + H), digest: 'b'.repeat(64), rows: [], expectDigest: null }), false);
    assert.equal(db.advisoryPinsFeed().digest, 'a'.repeat(64));
    assert.equal(db.replaceAdvisoryPins({ cutAt: iso(T0 + H), digest: 'b'.repeat(64), rows: [], expectDigest: 'a'.repeat(64) }), true);
  });
});

test('PF10 fetching by URL: https only, plain GETs, no redirects, a size cap', async () => {
  assert.throws(() => urlSource('http://pins.example.org/pins/'), /https/);
  const seen = [];
  const big = Buffer.alloc(PF.PINS_LIMITS.manifestBytes + 1, 0x20);
  const srv = http.createServer((req, res) => {
    seen.push({ url: req.url, method: req.method, auth: req.headers.authorization ?? null, cookie: req.headers.cookie ?? null });
    if (req.url === '/pins/keys.json') { res.end(big); return; }
    if (req.url === '/pins/moved') { res.writeHead(302, { location: '/pins/latest.jsonl' }); res.end(); return; }
    res.writeHead(404); res.end();
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  try {
    const get = urlSource(`http://127.0.0.1:${srv.address().port}/pins`);
    await assert.rejects(get('keys.json'), /larger than/);
    await assert.rejects(get('latest.jsonl'), /HTTP 404/);
    await assert.rejects(get('moved'));
    assert.ok(seen.every((s) => s.method === 'GET' && s.auth === null && s.cookie === null));
  } finally { srv.close(); }
});

// ------------------------------------------------------------------------------------------------ config, proxy, CLI
import { validateConfig, ConfigUnreadable, DEFAULT_ADVISORY_FEED_URL } from '../../config-store.js';
import { createProxyServer } from '../../proxy/server.js';
import updatePins from '../../cli/commands/update-advisories.js';
import status from '../../cli/commands/status.js';
import doctor from '../../cli/commands/doctor.js';
import { describePinsFeed } from '../../cli/pins-feed.js';
import { buildSeed, docFor, after, LIVE } from '../seed-v3/u05-fixtures.mjs';

test('PF11 configuration: advisory_feed_url must be https; with it set the feed is on unless advisory_feed is false', () => {
  // since the first signed cut is live (operator 2026-10-29), an unset advisory_feed_url means the published feed (deliberate change
  // of expectation: it was off); advisory_feed: false turns it off, and a configured URL replaces it
  const DEFAULT = 'https://raw.githubusercontent.com/cgsec-labs/chaingate-pins/main/pins/';
  assert.equal(DEFAULT_ADVISORY_FEED_URL, DEFAULT);
  assert.deepEqual(validateConfig({}).pinsFeed, { url: DEFAULT, enabled: true });
  assert.deepEqual(validateConfig({ advisory_feed_url: null }).pinsFeed, { url: DEFAULT, enabled: true });
  assert.deepEqual(validateConfig({ advisory_feed: false }).pinsFeed, { url: DEFAULT, enabled: false });
  assert.deepEqual(validateConfig({ advisory_feed_url: 'https://pins.example.org/pins' }).pinsFeed, { url: 'https://pins.example.org/pins', enabled: true });
  assert.deepEqual(validateConfig({ advisory_feed_url: 'https://pins.example.org/pins', advisory_feed: false }).pinsFeed.enabled, false);
  for (const bad of [{ advisory_feed_url: 'http://pins.example.org/' }, { advisory_feed_url: 'https://u:p@pins.example.org/' },
    { advisory_feed_url: 'https://pins.example.org/?id=1' }, { advisory_feed_url: 7 }, { advisory_feed: 'yes' }]) {
    assert.throws(() => validateConfig(bad), ConfigUnreadable, JSON.stringify(bad));
  }
});

const listen = (srv) => new Promise((resolve) => { srv.listen(0, '127.0.0.1', () => resolve(`http://127.0.0.1:${srv.address().port}`)); });
const close = (srv) => new Promise((resolve) => { srv.close(() => resolve()); });
const hget = (url) => new Promise((resolve, reject) => {
  http.get(url, { agent: false }, (res) => {
    let b = ''; res.setEncoding('utf8'); res.on('data', (x) => { b += x; });
    res.on('end', () => { let json = null; try { json = JSON.parse(b); } catch { /* not JSON */ } resolve({ status: res.statusCode, headers: res.headers, json }); });
  }).on('error', reject);
});

test('PF12 the proxy fetches the feed when it starts: an accepted cut BLOCKs its version; a feed problem is one line and the kept cut serves', async () => {
  const s = buildSeed({ layout: '1.1' });
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'pins-feed-proxy-'));
  const doc = docFor('q', [['1.4.0', after(1)]]);
  const upstream = http.createServer((req, res) => {
    const url = decodeURIComponent(req.url);
    if (url.includes('/-/')) { res.writeHead(200, { 'content-type': 'application/octet-stream' }); res.end('tarball-bytes'); return; }
    if (url === '/q') { res.writeHead(200, { 'content-type': 'application/json' }); res.end(JSON.stringify(doc)); return; }
    res.writeHead(404, { 'content-type': 'application/json' }); res.end('{}');
  });
  const feed = path.join(dir, 'feed'); const now = Date.now();
  const c1 = cut(now - H, [capture('q', '1.4.0')]);
  writeFeed(feed, manifest([pinsEntry(PINS, now - D)]), c1, [c1]);
  const upstreamUrl = await listen(upstream);
  const lines = []; const realErr = console.error; console.error = (m) => { lines.push(String(m)); };
  const mk = (get) => createProxyServer({ port: 0, host: '127.0.0.1', upstream: upstreamUrl, witnessDbPath: path.join(dir, 'witness.db'),
    headersTimeoutMs: 5_000, bodyTimeoutMs: 15_000, seedV3Path: s.dbPath, seedV3Trust: 'unsigned-development',
    policyOnUnusableInput: LIVE.on_unusable_input, policyOnNoEvidence: LIVE.on_no_evidence, pinsFeedGet: get, pinsSeedKey: SEED.publicKey });
  let proxy = mk(dirSource(feed));
  try {
    const base = await listen(proxy);
    await proxy.refreshPinsFeed();                         // the start-up fetch is in flight or done; this waits for it
    assert.equal(proxy.witnessDb.advisoryPinsFeed().digest, c1.digest);
    const t = await hget(`${base}/q/-/q-1.4.0.tgz`);
    assert.equal(t.status, 403);
    assert.equal(t.headers['npm-notice'], 'chaingate: BLOCKED q@1.4.0: a ChainGate analyst record names this version. Details: chaingate why q@1.4.0');
    await close(proxy);
    // a restart against a feed that cannot be read: one warning line, the kept cut still BLOCKs
    lines.length = 0;
    proxy = mk(dirSource(path.join(dir, 'nowhere')));
    const base2 = await listen(proxy);
    await proxy.refreshPinsFeed();
    assert.equal(lines.filter((l) => l.startsWith('[advisories]')).length, 1, lines.join('\n'));
    assert.match(lines.find((l) => l.startsWith('[advisories]')), /advisory feed failed: .*the kept cut keeps serving/);
    assert.equal((await hget(`${base2}/q/-/q-1.4.0.tgz`)).status, 403);
  } finally {
    console.error = realErr; await close(proxy); await close(upstream); s.cleanup(); fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('PF13 without a seed or a feed URL the proxy fetches nothing', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'pins-feed-off-'));
  let calls = 0; const get = async () => { calls += 1; throw new Error('should not be called'); };
  const proxy = createProxyServer({ port: 0, host: '127.0.0.1', upstream: 'http://127.0.0.1:9', witnessDbPath: path.join(dir, 'witness.db'),
    headersTimeoutMs: 1_000, bodyTimeoutMs: 1_000, pinsFeedGet: get, pinsSeedKey: SEED.publicKey });
  try {
    await listen(proxy); assert.equal(await proxy.refreshPinsFeed(), null); assert.equal(calls, 0);
  } finally { await close(proxy); fs.rmSync(dir, { recursive: true, force: true }); }
});

async function inHome(fn) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'pins-feed-cli-'));
  const prev = process.env.CHAINGATE_HOME; process.env.CHAINGATE_HOME = dir;
  const out = []; const log = console.log; const err = console.error;
  console.log = (m = '') => { out.push(String(m)); }; console.error = (m = '') => { out.push(String(m)); };
  try {
    const db = openWitnessDB(path.join(dir, 'witness.db')); db.applySchema(); db.close();
    return await fn(dir, out);
  } finally {
    console.log = log; console.error = err;
    if (prev === undefined) delete process.env.CHAINGATE_HOME; else process.env.CHAINGATE_HOME = prev;
    fs.rmSync(dir, { recursive: true, force: true });
  }
}
// eslint-disable-next-line no-control-regex
const plain = (lines) => lines.join('\n').replace(/\x1b\[[0-9;]*m/g, '');

test('PF14 update-advisories: --file reads a directory; a held cut exits 2 and names its digest; --accept-cut takes exactly it', async () => {
  await inHome(async (dir, out) => {
    const feed = path.join(dir, 'feed'); const now = Date.now(); const man = manifest([pinsEntry(PINS, now - 10 * D)]);
    const c1 = cut(now - 9 * D, [row('a', '1.0.0')]);
    writeFeed(feed, man, c1, [c1]);
    assert.equal(await updatePins(['--file', feed], { seedKey: SEED.publicKey }), 0);
    assert.match(plain(out), /cut .* accepted: 1 versions/);
    assert.equal(await updatePins(['--file', feed], { seedKey: SEED.publicKey }), 0);
    assert.match(plain(out), /is current/);
    const far = cut(now - H, [row('b', '1.0.0')], { digest: sha('gone'), head: { cut_at: iso(now - 2 * H) } });
    writeFeed(feed, man, far, []);
    out.length = 0;
    assert.equal(await updatePins(['--file', feed], { seedKey: SEED.publicKey }), 2);
    assert.match(plain(out), new RegExp(`HELD: .*more than 7 days[\\s\\S]*update-advisories --accept-cut ${far.digest}`));
    assert.equal(await updatePins(['--file', feed, '--accept-cut', 'abc'], { seedKey: SEED.publicKey }), 1);
    assert.equal(await updatePins(['--file', feed, '--accept-cut', far.digest], { seedKey: SEED.publicKey }), 0);
    const db = openWitnessDB(path.join(dir, 'witness.db'), { readonly: true });
    try { assert.ok(db.advisoryPinFor('b', '1.0.0')); assert.equal(db.advisoryPinFor('a', '1.0.0'), null); } finally { db.close(); }
    out.length = 0;
    // since the default address (2026-10-29): a configuration with the feed turned off refuses without fetching
    fs.writeFileSync(path.join(dir, 'config.json'), JSON.stringify({ config_version: 1, advisory_feed: false }));
    assert.equal(await updatePins([]), 1, 'the feed turned off and no --file');
    assert.match(plain(out), /The advisory feed is off \("advisory_feed": false in the configuration\)/);
  });
});

test('PF15 status and doctor show the cut and its age; past 48 hours, stale, held or refused is a notice, never a failure', async () => {
  const now = T0 + 10 * D;
  const fresh = describePinsFeed({ url: 'https://p.example.org/', feed: { cut_at: iso(now - H), rows: 3 }, fetch: { outcome: 'same' }, now });
  assert.deepEqual([fresh.state, fresh.notice], ['fresh', false]); assert.match(fresh.text, /cut .* \(1 h old\), 3 versions/);
  const old = describePinsFeed({ url: 'https://p.example.org/', feed: { cut_at: iso(now - 50 * H), rows: 3 }, fetch: null, now });
  assert.deepEqual([old.state, old.notice], ['old', true]); assert.match(old.text, /older than 48 hours/);
  const stale = describePinsFeed({ url: 'https://p.example.org/', feed: { cut_at: iso(now - 8 * D), rows: 3 }, fetch: null, now });
  assert.deepEqual([stale.state, stale.notice], ['stale', true]); assert.match(stale.text, /STALE/);
  const held = describePinsFeed({ url: 'https://p.example.org/', feed: { cut_at: iso(now - H), rows: 3 },
    fetch: { outcome: 'held', why: 'too many', held_digest: 'f'.repeat(64), held_cut_at: iso(now) }, now });
  assert.ok(held.notice); assert.match(held.text, /--accept-cut f{64}/);
  assert.equal(describePinsFeed({ url: null, feed: null, fetch: null, now }).state, 'off');
  assert.ok(describePinsFeed({ url: 'https://p.example.org/', feed: null, fetch: null, now }).notice, 'configured, nothing accepted yet');

  await inHome(async (dir, out) => {
    const db = openWitnessDB(path.join(dir, 'witness.db')); db.applySchema();
    db.replaceAdvisoryPins({ cutAt: iso(Date.now() - 3 * D), digest: 'a'.repeat(64), rows: [] });
    db.close();
    fs.writeFileSync(path.join(dir, 'config.json'), JSON.stringify({ config_version: 1, advisory_feed_url: 'https://pins.example.org/pins' }));
    await status([]);
    assert.match(plain(out), /Advisory feed:\s+cut .* \(3 days old\), 0 versions; older than 48 hours/);
    out.length = 0;
    await status(['--json']);
    const j = JSON.parse(out.join('\n'));
    assert.equal(j.advisory_feed.state, 'old'); assert.equal(j.advisory_feed.url, 'https://pins.example.org/pins');
    out.length = 0;
    await doctor(['--json']);
    const pf = JSON.parse(out.join('\n')).find((c) => c.name === 'advisory-feed');
    assert.deepEqual([pf.pass, pf.severity], [false, 'notice']); assert.match(pf.detail, /older than 48 hours/);
  });
});

// ------------------------------------------------------------------------------------------------ the real key list
import { CHAINGATE_SEED_PUBKEY_B64 } from '../../witness/seed_verify.js';
import { createPublicKey } from 'node:crypto';
import { fileURLToPath } from 'node:url';

test('PF16 the published key list verifies against the seed key the runtime embeds, and names the pins key', async () => {
  const fx = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'fixtures', 'pins');
  const bytes = fs.readFileSync(path.join(fx, 'keys.json')); const sig = fs.readFileSync(path.join(fx, 'keys.json.sig'));
  assert.equal(sha(bytes), 'ea7ed9367afb5a96f3d326ee300533fc65186c7f25381cec9b2a15e1f018a4f4');
  const seedKey = createPublicKey({ key: Buffer.from(CHAINGATE_SEED_PUBKEY_B64, 'base64'), format: 'der', type: 'spki' });
  const keys = verifyKeyManifest(bytes, sig, { seedKey });
  assert.deepEqual(keys.map((k) => [k.key_id, iso(k.from), iso(k.to)]), [['ed25519:cbaa1978ce3adb68', '2026-10-29T10:00:00Z', '2027-01-27T10:00:00Z']]);
  throwsRefused(() => verifyKeyManifest(bytes, sig, { seedKey: SEED.publicKey }), /does not verify against the seed key/);
  // through the default trust path: a cut signed by any other key is refused under the real list
  await withStore(async (db, dir) => {
    const feed = path.join(dir, 'feed'); const c = cut(Date.parse('2026-10-30T10:00:00Z'), [row('a', '1.0.0')], null, { key: { ...PINS, id: 'ed25519:cbaa1978ce3adb68' } });
    writeFeed(feed, { bytes, sig }, c, [c]);
    const r = await refreshPins({ get: dirSource(feed), db, now: Date.parse('2026-10-30T11:00:00Z') });
    assert.equal(r.outcome, 'refused'); assert.match(r.why, /does not verify/);
    assert.equal(db.advisoryPinsFeed(), null);
  });
});

// ------------------------------------------------------------------------------------------------ the removal guard
const rowsN = (n, prefix = 'r') => Array.from({ length: n }, (_, i) => row(`${prefix}${String(i).padStart(4, '0')}`, '1.0.0'));

test('PF17 a cut removing more than 100 versions, or a quarter of those held (whichever is fewer), or emptying the feed, is HELD', async () => {
  const now = T0 + 2 * H; const go = (latest, kept, accept = null) => decideCut({ latest, kept: keptOf(kept), loadCut: loaderOf([]), keys: KEYS, now, accept });
  const big = cut(T0, rowsN(1000));
  assert.equal((await go(cut(T0 + H, rowsN(1000).slice(100), big), big)).action, 'accept', '100 removed of 1000: within');
  const h = await go(cut(T0 + H, rowsN(1000).slice(101), big), big);
  assert.equal(h.action, 'held'); assert.match(h.why, /removes 101 versions \(more than 100/);
  assert.equal(h.removed.length, 101);
  const small = cut(T0, rowsN(40));
  assert.equal((await go(cut(T0 + H, rowsN(40).slice(10), small), small)).action, 'accept', '10 of 40: a quarter');
  assert.match((await go(cut(T0 + H, rowsN(40).slice(11), small), small)).why, /removes 11 versions \(more than 10/);
  const empty = cut(T0 + H, [], small);
  assert.match((await go(empty, small)).why, /empty and would remove all 40/);
  assert.equal((await go(empty, small, empty.digest)).action, 'accept', '--accept-cut takes it');
  // an entry moved to another advisory (same name and version) is not a removal
  const moved = cut(T0 + H, rowsN(40).map((r) => ({ ...r, advisory_id: `GHSA-${r.name}`, also_advisories: [r.advisory_id] })), small);
  const m = await go(moved, small);
  assert.deepEqual([m.action, m.removed.length], ['accept', 0]);
});

test('PF18 a removal hold names, up to 20, the removed versions this proxy BLOCKed in the last 30 days', async () => {
  await withStore(async (db, dir) => {
    const feed = path.join(dir, 'feed'); const man = manifest([pinsEntry(PINS, T0 - D)]); const now = Date.now();
    const base = rowsN(200); const c1 = cut(now - 2 * H, base);
    writeFeed(feed, man, c1, [c1]);
    assert.equal((await refreshPins({ get: dirSource(feed), db, seedKey: SEED.publicKey, now })).outcome, 'accepted');
    for (let i = 0; i < 25; i++) db.insertGateDecision(`r${String(i).padStart(4, '0')}`, '1.0.0', 'BLOCK', []);
    db.insertGateDecision('r0199', '1.0.0', 'WARN', []);
    const c2 = cut(now - H, base.slice(0, 50), c1);       // removes r0050..r0199: 150 versions
    writeFeed(feed, man, c2, [c1, c2]);
    const r = await refreshPins({ get: dirSource(feed), db, seedKey: SEED.publicKey, now });
    assert.equal(r.outcome, 'held'); assert.match(r.why, /removes 150 versions/);
    assert.doesNotMatch(r.why, /BLOCKed/, 'none of the removed versions was blocked here');
    const c3 = cut(now - H + 60e3, base.slice(60), c1);   // removes r0000..r0059: 60 versions (more than 50), 25 blocked here
    writeFeed(feed, man, c3, [c1, c3]);
    const r3 = await refreshPins({ get: dirSource(feed), db, seedKey: SEED.publicKey, now: now + 120e3 });
    assert.equal(r3.outcome, 'held');
    assert.match(r3.why, /would lift 25 version\(s\) this proxy BLOCKed in the last 30 days: r0000@1\.0\.0, .* and 5 more/);
    assert.equal((r3.why.match(/r00\d\d@1\.0\.0/g) ?? []).length, 20);
    assert.equal(db.advisoryPinsFetch().why, r3.why);
  });
});

test('PF19 the newest cut is checked with its dated signature, so a cached old latest.jsonl.sig does not refuse it', async () => {
  await withStore(async (db, dir) => {
    const feed = path.join(dir, 'feed'); const man = manifest([pinsEntry()]);
    const c1 = cut(T0, rowsN(8)); const c2 = cut(T0 + H, rowsN(8).concat(row('z', '1.0.0')), c1);
    writeFeed(feed, man, c1, [c1]);
    assert.equal((await refreshPins({ get: dirSource(feed), db, seedKey: SEED.publicKey, now: T0 + 2 * H })).outcome, 'accepted');
    writeFeed(feed, man, c2, [c1, c2]);
    fs.writeFileSync(path.join(feed, 'latest.jsonl.sig'), c1.sig);          // a cache still serving the previous signature
    assert.equal((await refreshPins({ get: dirSource(feed), db, seedKey: SEED.publicKey, now: T0 + 2 * H })).outcome, 'accepted');
    assert.equal(db.advisoryPinsFeed().digest, c2.digest);
    // no dated signature yet: latest.jsonl.sig is used, and still verified
    const c3 = cut(T0 + 2 * H, rowsN(8), c2);
    writeFeed(feed, man, c3, [c3]); fs.rmSync(path.join(feed, 'cuts', `${stampOf(c3.head.cut_at)}.jsonl.sig`));
    assert.equal((await refreshPins({ get: dirSource(feed), db, seedKey: SEED.publicKey, now: T0 + 3 * H })).outcome, 'accepted');
    const c4 = cut(T0 + 3 * H, rowsN(8), c3);
    writeFeed(feed, man, c4, [c4]); fs.rmSync(path.join(feed, 'cuts', `${stampOf(c4.head.cut_at)}.jsonl.sig`));
    fs.writeFileSync(path.join(feed, 'latest.jsonl.sig'), c3.sig);
    const r4 = await refreshPins({ get: dirSource(feed), db, seedKey: SEED.publicKey, now: T0 + 4 * H });
    assert.equal(r4.outcome, 'refused'); assert.equal(db.advisoryPinsFeed().digest, c3.digest);
  });
});
