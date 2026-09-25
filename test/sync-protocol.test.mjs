import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  MAX_ALTERNATES,
  MAX_DATA_BYTES,
  ProtocolError,
  TS_WINDOW_MS,
  buildEnvelope,
  entryDigest,
  digestMap,
  mergeVaults,
  verifyEnvelope,
} from '../lib/sync-protocol.mjs';

const T0 = '2026-01-01T00:00:00.000Z';
const T1 = '2026-01-01T01:00:00.000Z';
const T2 = '2026-01-01T02:00:00.000Z';

function profile(credentials, savedAt, extra = {}) {
  return { credentials, oauthAccount: { emailAddress: 'a@example.com' }, savedAt, ...extra };
}

// --- digests ------------------------------------------------------------------

test('entryDigest ignores key order', () => {
  const a = entryDigest({ credentials: 'x', savedAt: T0, oauthAccount: { b: 1, a: 2 } });
  const b = entryDigest({ oauthAccount: { a: 2, b: 1 }, savedAt: T0, credentials: 'x' });
  assert.equal(a, b);
  assert.match(a, /^[0-9a-f]{64}$/);
});

test('entryDigest changes when credentials change', () => {
  assert.notEqual(entryDigest(profile('x', T0)), entryDigest(profile('y', T0)));
});

test('digestMap maps every name to its entry digest', () => {
  const profiles = { a: profile('x', T0), b: { deletedAt: T1 } };
  assert.deepEqual(digestMap(profiles), { a: entryDigest(profiles.a), b: entryDigest(profiles.b) });
});

// --- three-way merge ----------------------------------------------------------

test('merge: entry only on one side is taken from that side', () => {
  const local = { a: profile('x', T0) };
  const remote = { b: profile('y', T0) };
  const { merged, localChanges, remoteStale } = mergeVaults(local, remote, {});
  assert.deepEqual(Object.keys(merged).sort(), ['a', 'b']);
  assert.deepEqual(localChanges, { write: ['b'], delete: [] });
  assert.equal(remoteStale, true);
});

test('merge: identical entries need no changes', () => {
  const local = { a: profile('x', T0) };
  const remote = { a: profile('x', T0) };
  const r = mergeVaults(local, remote, digestMap(local));
  assert.deepEqual(r.localChanges, { write: [], delete: [] });
  assert.equal(r.remoteStale, false);
});

test('merge: only local changed since base -> local wins, push needed', () => {
  const base = { a: profile('x', T0) };
  const local = { a: profile('x2', T1) };
  const remote = { a: profile('x', T0) };
  const r = mergeVaults(local, remote, digestMap(base));
  assert.deepEqual(r.merged.a, local.a);
  assert.deepEqual(r.localChanges, { write: [], delete: [] });
  assert.equal(r.remoteStale, true);
});

test('merge: only remote changed since base -> remote wins, local write', () => {
  const base = { a: profile('x', T0) };
  const local = { a: profile('x', T0) };
  const remote = { a: profile('x2', T1) };
  const r = mergeVaults(local, remote, digestMap(base));
  assert.deepEqual(r.merged.a, remote.a);
  assert.deepEqual(r.localChanges, { write: ['a'], delete: [] });
  assert.equal(r.remoteStale, false);
});

test('merge: remote changed to an older savedAt still wins when local is unchanged (no clock comparison)', () => {
  const base = { a: profile('x', T1) };
  const local = { a: profile('x', T1) };
  const remote = { a: profile('older-but-only-change', T0) };
  const r = mergeVaults(local, remote, digestMap(base));
  assert.equal(r.merged.a.credentials, 'older-but-only-change');
});

test('merge: both changed with different credentials -> newer savedAt is primary, other becomes alternate', () => {
  const base = { a: profile('x', T0) };
  const local = { a: profile('L', T1, { machine: 'mbp' }) };
  const remote = { a: profile('R', T2, { machine: 'desk' }) };
  const r = mergeVaults(local, remote, digestMap(base));
  assert.equal(r.merged.a.credentials, 'R');
  assert.equal(r.merged.a.machine, 'desk');
  assert.deepEqual(r.merged.a.alternates, [{ credentials: 'L', savedAt: T1, machine: 'mbp' }]);
  assert.deepEqual(r.localChanges, { write: ['a'], delete: [] });
  assert.equal(r.remoteStale, true);
});

test('merge: both changed with identical credentials -> newer savedAt, no alternates', () => {
  const base = { a: profile('x', T0) };
  const local = { a: profile('same', T2) };
  const remote = { a: profile('same', T1) };
  const r = mergeVaults(local, remote, digestMap(base));
  assert.equal(r.merged.a.savedAt, T2);
  assert.equal(r.merged.a.alternates, undefined);
});

test('merge: alternates from both sides are carried, deduped, newest first, capped', () => {
  const base = { a: profile('x', T0) };
  const mk = (i) => ({ credentials: `alt${i}`, savedAt: `2025-12-0${i}T00:00:00.000Z` });
  const local = { a: profile('L', T1, { alternates: [mk(1), mk(2), mk(3)] }) };
  const remote = { a: profile('R', T2, { alternates: [mk(2), mk(4), mk(5)] }) };
  const r = mergeVaults(local, remote, digestMap(base));
  const creds = r.merged.a.alternates.map((x) => x.credentials);
  assert.equal(creds.length, MAX_ALTERNATES);
  assert.deepEqual(creds, ['L', 'alt5', 'alt4', 'alt3']);
});

test('merge: no base at all treats everything as both-changed (nothing dropped)', () => {
  const local = { a: profile('L', T1) };
  const remote = { a: profile('R', T0) };
  const r = mergeVaults(local, remote, null);
  assert.equal(r.merged.a.credentials, 'L');
  assert.deepEqual(r.merged.a.alternates, [{ credentials: 'R', savedAt: T0 }]);
});

test('merge: remote tombstone deletes an unchanged local profile', () => {
  const base = { a: profile('x', T0) };
  const local = { a: profile('x', T0) };
  const remote = { a: { deletedAt: T1 } };
  const r = mergeVaults(local, remote, digestMap(base));
  assert.deepEqual(r.merged.a, { deletedAt: T1 });
  assert.deepEqual(r.localChanges, { write: [], delete: ['a'] });
});

test('merge: re-login after a delete revives the profile when savedAt is newer than deletedAt', () => {
  const base = { a: profile('x', T0) };
  const local = { a: profile('fresh', T2) };
  const remote = { a: { deletedAt: T1 } };
  const r = mergeVaults(local, remote, digestMap(base));
  assert.equal(r.merged.a.credentials, 'fresh');
  assert.equal(r.remoteStale, true);
  assert.deepEqual(r.localChanges, { write: [], delete: [] });
});

test('merge: a delete newer than a changed profile wins', () => {
  const base = { a: profile('x', T0) };
  const local = { a: profile('changed', T1) };
  const remote = { a: { deletedAt: T2 } };
  const r = mergeVaults(local, remote, digestMap(base));
  assert.deepEqual(r.merged.a, { deletedAt: T2 });
  assert.deepEqual(r.localChanges.delete, ['a']);
});

test('merge: two tombstones keep the newer one', () => {
  const r = mergeVaults({ a: { deletedAt: T1 } }, { a: { deletedAt: T2 } }, {});
  assert.deepEqual(r.merged.a, { deletedAt: T2 });
  assert.deepEqual(r.localChanges, { write: [], delete: [] });
});

test('merge: local moved marker keeps the remote copy on the server without reviving it locally', () => {
  const local = { a: { movedAt: T1 } };
  const remote = { a: profile('x', T0) };
  const r = mergeVaults(local, remote, {});
  assert.deepEqual(r.merged.a, remote.a);
  assert.deepEqual(r.localChanges, { write: [], delete: [] });
  assert.equal(r.remoteStale, false);
});

test('merge: a remote copy newer than the local move revives the profile locally', () => {
  const local = { a: { movedAt: T1 } };
  const remote = { a: profile('x', T2) };
  const r = mergeVaults(local, remote, {});
  assert.deepEqual(r.localChanges, { write: ['a'], delete: [] });
});

test('merge: a local moved marker with nothing remote is not pushed', () => {
  const r = mergeVaults({ a: { movedAt: T1 } }, {}, {});
  assert.deepEqual(r.merged, {});
  assert.equal(r.remoteStale, false);
});

// --- envelope -----------------------------------------------------------------

const FPR = '071BC24AB653FEBB99E859EB46EC6DD922E6CD72';
const PUB = '-----BEGIN PGP PUBLIC KEY BLOCK-----\nabc\n-----END PGP PUBLIC KEY BLOCK-----\n';
const SIG = '-----BEGIN PGP SIGNATURE-----\nsig\n-----END PGP SIGNATURE-----\n';
const MSG = '-----BEGIN PGP MESSAGE-----\nenc\n-----END PGP MESSAGE-----\n';

const fakePgp = {
  fingerprint: FPR,
  exportPublicKey: () => PUB,
  sign: (text) => `${SIG}#${text.length}`,
};
const NOW = Date.parse('2026-06-01T12:00:00.000Z');
const okVerify = async ({ publicKey, payload, signature }) => {
  if (publicKey !== PUB || signature !== `${SIG}#${payload.length}`) throw new Error('bad signature');
  return { fingerprint: FPR };
};

async function rejects(fn, status, re) {
  await assert.rejects(fn, (err) => {
    assert.ok(err instanceof ProtocolError, `expected ProtocolError, got ${err?.stack ?? err}`);
    assert.equal(err.status, status);
    if (re) assert.match(err.message, re);
    return true;
  });
}

test('buildEnvelope signs the payload string verbatim and verifyEnvelope accepts it', async () => {
  const body = buildEnvelope({ op: 'put', vault: 'claude', baseVersion: 3, data: MSG }, fakePgp, NOW);
  assert.equal(body.publicKey, PUB);
  assert.equal(body.signature, fakePgp.sign(body.payload));
  const { fingerprint, payload } = await verifyEnvelope(body, 'claude', { verify: okVerify, now: NOW + 1000 });
  assert.equal(fingerprint, FPR);
  assert.deepEqual(payload, { v: 1, op: 'put', vault: 'claude', ts: new Date(NOW).toISOString(), baseVersion: 3, data: MSG });
});

test('get envelopes carry no data', () => {
  const body = buildEnvelope({ op: 'get', vault: 'kimi', baseVersion: 0 }, fakePgp, NOW);
  assert.equal(JSON.parse(body.payload).data, undefined);
});

test('verifyEnvelope rejects a body that is not an object of strings', async () => {
  await rejects(() => verifyEnvelope('nope', 'claude', { verify: okVerify, now: NOW }), 400);
  await rejects(() => verifyEnvelope({ publicKey: PUB, payload: 5, signature: SIG }, 'claude', { verify: okVerify, now: NOW }), 400);
});

test('verifyEnvelope rejects armor with the wrong header before calling verify', async () => {
  let called = false;
  const spy = async () => { called = true; return { fingerprint: FPR }; };
  const body = buildEnvelope({ op: 'get', vault: 'claude', baseVersion: 0 }, fakePgp, NOW);
  await rejects(() => verifyEnvelope({ ...body, publicKey: 'not a key' }, 'claude', { verify: spy, now: NOW }), 400);
  await rejects(() => verifyEnvelope({ ...body, signature: 'not a sig' }, 'claude', { verify: spy, now: NOW }), 400);
  assert.equal(called, false);
});

test('verifyEnvelope rejects oversized fields before calling verify', async () => {
  let called = false;
  const spy = async () => { called = true; return { fingerprint: FPR }; };
  const body = buildEnvelope({ op: 'put', vault: 'claude', baseVersion: 0, data: MSG + 'x'.repeat(MAX_DATA_BYTES) }, fakePgp, NOW);
  await rejects(() => verifyEnvelope(body, 'claude', { verify: spy, now: NOW }), 413);
  const bigKey = PUB + 'k'.repeat(64 * 1024);
  await rejects(() => verifyEnvelope({ ...body, publicKey: bigKey }, 'claude', { verify: spy, now: NOW }), 413);
  assert.equal(called, false);
});

test('verifyEnvelope maps a verify failure to 401', async () => {
  const body = buildEnvelope({ op: 'get', vault: 'claude', baseVersion: 0 }, fakePgp, NOW);
  await rejects(() => verifyEnvelope({ ...body, payload: body.payload + ' ' }, 'claude', { verify: okVerify, now: NOW }), 401);
});

test('verifyEnvelope rejects a stale or unparsable timestamp', async () => {
  const stale = buildEnvelope({ op: 'get', vault: 'claude', baseVersion: 0 }, fakePgp, NOW - TS_WINDOW_MS - 1);
  await rejects(() => verifyEnvelope(stale, 'claude', { verify: okVerify, now: NOW }), 401, /timestamp/);
  const future = buildEnvelope({ op: 'get', vault: 'claude', baseVersion: 0 }, fakePgp, NOW + TS_WINDOW_MS + 1);
  await rejects(() => verifyEnvelope(future, 'claude', { verify: okVerify, now: NOW }), 401, /timestamp/);
  const payload = JSON.stringify({ v: 1, op: 'get', vault: 'claude', ts: 'garbage', baseVersion: 0 });
  const nan = { publicKey: PUB, payload, signature: fakePgp.sign(payload) };
  await rejects(() => verifyEnvelope(nan, 'claude', { verify: okVerify, now: NOW }), 401, /timestamp/);
});

test('verifyEnvelope binds the signed vault name to the URL and whitelists names', async () => {
  const body = buildEnvelope({ op: 'get', vault: 'claude', baseVersion: 0 }, fakePgp, NOW);
  await rejects(() => verifyEnvelope(body, 'kimi', { verify: okVerify, now: NOW }), 400, /vault/);
  const odd = buildEnvelope({ op: 'get', vault: 'other', baseVersion: 0 }, fakePgp, NOW);
  await rejects(() => verifyEnvelope(odd, 'other', { verify: okVerify, now: NOW }), 400, /vault/);
});

test('verifyEnvelope rejects bad op, version, baseVersion and missing put data', async () => {
  const sign = (obj) => {
    const payload = JSON.stringify(obj);
    return { publicKey: PUB, payload, signature: fakePgp.sign(payload) };
  };
  const ts = new Date(NOW).toISOString();
  const opts = { verify: okVerify, now: NOW };
  await rejects(() => verifyEnvelope(sign({ v: 2, op: 'get', vault: 'claude', ts, baseVersion: 0 }), 'claude', opts), 400);
  await rejects(() => verifyEnvelope(sign({ v: 1, op: 'delete', vault: 'claude', ts, baseVersion: 0 }), 'claude', opts), 400);
  await rejects(() => verifyEnvelope(sign({ v: 1, op: 'get', vault: 'claude', ts, baseVersion: '0' }), 'claude', opts), 400);
  await rejects(() => verifyEnvelope(sign({ v: 1, op: 'get', vault: 'claude', ts, baseVersion: -1 }), 'claude', opts), 400);
  await rejects(() => verifyEnvelope(sign({ v: 1, op: 'put', vault: 'claude', ts, baseVersion: 0 }), 'claude', opts), 400, /data/);
  await rejects(() => verifyEnvelope(sign({ v: 1, op: 'put', vault: 'claude', ts, baseVersion: 0, data: 'plain' }), 'claude', opts), 400, /data/);
});
