import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';

import { MAX_BODY_BYTES, buildEnvelope } from '../lib/sync-protocol.mjs';
import { createSyncServer, createVaultStore, readServerConfig, writeServerConfig } from '../sync-server.mjs';

const FPR = '071BC24AB653FEBB99E859EB46EC6DD922E6CD72';
const FPR2 = 'CDB2F11FB986CD39AFE06723DB72CD76A6658CC8';
const PUB = '-----BEGIN PGP PUBLIC KEY BLOCK-----\nabc\n-----END PGP PUBLIC KEY BLOCK-----\n';
const SIG = '-----BEGIN PGP SIGNATURE-----\nsig\n-----END PGP SIGNATURE-----\n';
const MSG = (s = 'enc') => `-----BEGIN PGP MESSAGE-----\n${s}\n-----END PGP MESSAGE-----\n`;
const SECRET = 'a'.repeat(64);

function fakePgp(fpr = FPR) {
  return { fingerprint: fpr, exportPublicKey: () => `${PUB}#${fpr}`, sign: (text) => `${SIG}#${text.length}` };
}
// Accepts anything shaped like fakePgp's output and reads the fingerprint back
// out of the "public key", so tests can act as several users.
const fakeVerify = async ({ publicKey, payload, signature }) => {
  if (signature !== `${SIG}#${payload.length}`) throw new Error('bad signature');
  return { fingerprint: publicKey.split('#')[1] };
};

function dataDir(t) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ccsw-server-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  return dir;
}

async function startServer(t, opts = {}) {
  const dir = opts.dataDir ?? dataDir(t);
  const logs = [];
  const server = createSyncServer({ dataDir: dir, pathSecret: SECRET, verify: fakeVerify, log: (l) => logs.push(l), ...opts });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise((resolve) => {
    server.closeAllConnections();
    server.close(resolve);
  }));
  const base = `http://127.0.0.1:${server.address().port}`;
  return { server, base, dir, logs };
}

async function call(base, vault, envelope, { secret = SECRET, method = 'POST' } = {}) {
  const res = await fetch(`${base}/${secret}/v1/vaults/${vault}`, {
    method,
    headers: { 'content-type': 'application/json' },
    body: method === 'POST' ? JSON.stringify(envelope) : undefined,
  });
  const text = await res.text();
  return { status: res.status, body: text ? JSON.parse(text) : null, text };
}

// --- store ------------------------------------------------------------------------

test('store: get on a missing vault is version 0 with no data', (t) => {
  const store = createVaultStore(dataDir(t));
  assert.deepEqual(store.get(FPR, 'claude'), { version: 0, data: null });
  assert.equal(store.count(), 0);
});

test('store: put then get round-trips and bumps the version', (t) => {
  const store = createVaultStore(dataDir(t));
  assert.deepEqual(store.put(FPR, 'claude', 0, MSG()), { version: 1 });
  assert.deepEqual(store.get(FPR, 'claude'), { version: 1, data: MSG() });
  assert.deepEqual(store.put(FPR, 'claude', 1, MSG('two')), { version: 2 });
  assert.equal(store.get(FPR, 'claude').data, MSG('two'));
  assert.equal(store.count(), 1);
});

test('store: a stale baseVersion is a 409 carrying the current blob', (t) => {
  const store = createVaultStore(dataDir(t));
  store.put(FPR, 'claude', 0, MSG());
  assert.throws(() => store.put(FPR, 'claude', 0, MSG('late')), (err) => {
    assert.equal(err.status, 409);
    assert.deepEqual(err.extra, { version: 1, data: MSG() });
    return true;
  });
  assert.equal(store.get(FPR, 'claude').data, MSG());
});

test('store: files are private and survive a restart', (t) => {
  const dir = dataDir(t);
  createVaultStore(dir).put(FPR, 'claude', 0, MSG());
  createVaultStore(dir).put(FPR, 'kimi', 0, MSG());
  const file = path.join(dir, 'vaults', FPR, 'claude.json');
  assert.equal(fs.statSync(file).mode & 0o777, 0o600);
  assert.equal(fs.statSync(path.dirname(file)).mode & 0o777, 0o700);
  const again = createVaultStore(dir);
  assert.equal(again.count(), 2);
  assert.equal(again.get(FPR, 'claude').version, 1);
});

test('store: the global vault cap rejects new vaults but not updates', (t) => {
  const store = createVaultStore(dataDir(t), { maxVaults: 1 });
  store.put(FPR, 'claude', 0, MSG());
  assert.throws(() => store.put(FPR2, 'claude', 0, MSG()), (err) => err.status === 507);
  assert.throws(() => store.put(FPR, 'kimi', 0, MSG()), (err) => err.status === 507);
  assert.deepEqual(store.put(FPR, 'claude', 1, MSG('two')), { version: 2 });
});

test('store: rejects fingerprints and names that are not safe path segments', (t) => {
  const store = createVaultStore(dataDir(t));
  assert.throws(() => store.get('../etc', 'claude'), (err) => err.status === 400);
  assert.throws(() => store.get(FPR, '../x'), (err) => err.status === 400);
  assert.throws(() => store.put(FPR.toLowerCase(), 'claude', 0, MSG()), (err) => err.status === 400);
});

// --- HTTP -------------------------------------------------------------------------

test('http: get on an empty vault, put, get again', async (t) => {
  const { base, logs } = await startServer(t);
  const pgp = fakePgp();
  let r = await call(base, 'claude', buildEnvelope({ op: 'get', vault: 'claude', baseVersion: 0 }, pgp));
  assert.deepEqual(r, { status: 200, body: { version: 0, data: null }, text: r.text });
  r = await call(base, 'claude', buildEnvelope({ op: 'put', vault: 'claude', baseVersion: 0, data: MSG() }, pgp));
  assert.deepEqual(r.body, { version: 1 });
  r = await call(base, 'claude', buildEnvelope({ op: 'get', vault: 'claude', baseVersion: 0 }, pgp));
  assert.deepEqual(r.body, { version: 1, data: MSG() });
  assert.equal(logs.length, 3);
  assert.match(logs[1], /put 071BC24A 200 \d+ms/);
  assert.ok(!logs.join('\n').includes(MSG().trim()), 'log never contains vault data');
});

test('http: vaults are per fingerprint', async (t) => {
  const { base } = await startServer(t);
  await call(base, 'claude', buildEnvelope({ op: 'put', vault: 'claude', baseVersion: 0, data: MSG('mine') }, fakePgp(FPR)));
  const r = await call(base, 'claude', buildEnvelope({ op: 'get', vault: 'claude', baseVersion: 0 }, fakePgp(FPR2)));
  assert.deepEqual(r.body, { version: 0, data: null });
});

test('http: stale put answers 409 with the current blob', async (t) => {
  const { base } = await startServer(t);
  const pgp = fakePgp();
  await call(base, 'claude', buildEnvelope({ op: 'put', vault: 'claude', baseVersion: 0, data: MSG('one') }, pgp));
  const r = await call(base, 'claude', buildEnvelope({ op: 'put', vault: 'claude', baseVersion: 0, data: MSG('two') }, pgp));
  assert.equal(r.status, 409);
  assert.deepEqual(r.body, { error: 'version conflict', version: 1, data: MSG('one') });
});

test('http: concurrent puts on the same base serialize into one winner', async (t) => {
  const { base } = await startServer(t);
  const pgp = fakePgp();
  const results = await Promise.all([
    call(base, 'claude', buildEnvelope({ op: 'put', vault: 'claude', baseVersion: 0, data: MSG('a') }, pgp)),
    call(base, 'claude', buildEnvelope({ op: 'put', vault: 'claude', baseVersion: 0, data: MSG('b') }, pgp)),
  ]);
  assert.deepEqual(results.map((r) => r.status).sort(), [200, 409]);
});

test('http: unknown prefix, wrong method, unknown vault name and other paths are an empty 404', async (t) => {
  const { base, logs } = await startServer(t);
  const env = buildEnvelope({ op: 'get', vault: 'claude', baseVersion: 0 }, fakePgp());
  for (const [vault, opts] of [['claude', { secret: 'b'.repeat(64) }], ['claude', { method: 'GET' }], ['other', {}]]) {
    const r = await call(base, vault, env, opts);
    assert.equal(r.status, 404, `${vault} ${JSON.stringify(opts)}`);
    assert.equal(r.text, '');
  }
  const root = await fetch(`${base}/`);
  assert.equal(root.status, 404);
  assert.equal(await root.text(), '');
  assert.equal(logs.length, 0, 'probes are not logged');
});

test('http: bad signature is 401, malformed envelope is 400', async (t) => {
  const { base } = await startServer(t);
  const env = buildEnvelope({ op: 'get', vault: 'claude', baseVersion: 0 }, fakePgp());
  let r = await call(base, 'claude', { ...env, payload: env.payload + ' ' });
  assert.equal(r.status, 401);
  assert.match(r.body.error, /signature/);
  r = await call(base, 'claude', { nope: 1 });
  assert.equal(r.status, 400);
  const raw = await fetch(`${base}/${SECRET}/v1/vaults/claude`, { method: 'POST', body: '{not json' });
  assert.equal(raw.status, 400);
});

test('http: oversized vault data is 413 and an oversized body is cut off', async (t) => {
  const { base } = await startServer(t);
  const pgp = fakePgp();
  const big = buildEnvelope({ op: 'put', vault: 'claude', baseVersion: 0, data: MSG('x'.repeat(1024 * 1024)) }, pgp);
  const r = await call(base, 'claude', big);
  assert.equal(r.status, 413);
  await assert.rejects(
    fetch(`${base}/${SECRET}/v1/vaults/claude`, { method: 'POST', body: 'x'.repeat(MAX_BODY_BYTES + 1) }),
  );
});

test('http: vault cap answers 507', async (t) => {
  const { base } = await startServer(t, { maxVaults: 1 });
  await call(base, 'claude', buildEnvelope({ op: 'put', vault: 'claude', baseVersion: 0, data: MSG() }, fakePgp(FPR)));
  const r = await call(base, 'claude', buildEnvelope({ op: 'put', vault: 'claude', baseVersion: 0, data: MSG() }, fakePgp(FPR2)));
  assert.equal(r.status, 507);
});

test('http: slow clients are cut off by the request timeout', async (t) => {
  const { server, base } = await startServer(t, { requestTimeoutMs: 300 });
  const port = server.address().port;
  const closed = await new Promise((resolve) => {
    const sock = net.connect(port, '127.0.0.1', () => {
      sock.write(`POST /${SECRET}/v1/vaults/claude HTTP/1.1\r\nHost: x\r\nContent-Length: 100\r\n\r\n{"pub`);
    });
    sock.resume(); // a paused socket never reaches 'close'
    sock.on('close', () => resolve(true));
    sock.on('error', () => resolve(true));
    setTimeout(() => resolve(false), 3000);
  });
  assert.equal(closed, true);
  assert.equal(base.length > 0, true);
});

// --- config -----------------------------------------------------------------------

test('config: writeServerConfig creates a private file that readServerConfig returns', (t) => {
  const dir = dataDir(t);
  writeServerConfig(dir, { host: '127.0.0.1', port: 8787, pathSecret: SECRET });
  assert.equal(fs.statSync(path.join(dir, 'server.json')).mode & 0o777, 0o600);
  assert.deepEqual(readServerConfig(dir), { host: '127.0.0.1', port: 8787, pathSecret: SECRET });
  assert.equal(readServerConfig(path.join(dir, 'missing')), null);
});
