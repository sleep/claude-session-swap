// Two machines (A and B, each a sandboxed ccswitch home) syncing through one
// in-process ccswitch-server. PGP is faked so the tests run without gpg; the
// real gpg wrapper has its own suite.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

import {
  SyncError,
  UsageError,
  applyMerge,
  buildLocalVault,
  config,
  deleteProfileCmd,
  getActive,
  loadProfile,
  main,
  profileExists,
  readCredentials,
  readSyncConfig,
  saveProfile,
  setActive,
  syncEnabled,
  syncNow,
  writeCredentials,
  writeSyncConfig,
} from '../ccswitch.mjs';
import { createSyncServer } from '../sync-server.mjs';

const FPR = '071BC24AB653FEBB99E859EB46EC6DD922E6CD72';
const SECRET = 'a'.repeat(64);
const SIG = '-----BEGIN PGP SIGNATURE-----\nsig\n-----END PGP SIGNATURE-----\n';

// Same key on both machines, as in real life. "Encryption" is base64 so the
// tests can inspect what went over the wire.
function fakePgp(fingerprint = FPR) {
  return {
    fingerprint,
    exportPublicKey: () => `-----BEGIN PGP PUBLIC KEY BLOCK-----\n#${fingerprint}\n-----END PGP PUBLIC KEY BLOCK-----\n`,
    sign: (text) => `${SIG}#${text.length}`,
    encrypt: (text) => `-----BEGIN PGP MESSAGE-----\n${Buffer.from(text).toString('base64')}\n-----END PGP MESSAGE-----\n`,
    decrypt: (armored) => Buffer.from(armored.split('\n')[1], 'base64').toString('utf8'),
  };
}
const fakeVerify = async ({ publicKey, payload, signature }) => {
  if (signature !== `${SIG}#${payload.length}`) throw new Error('bad signature');
  return { fingerprint: publicKey.split('#')[1].split('\n')[0] };
};

async function server(t, opts = {}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ccsw-sync-srv-'));
  const srv = createSyncServer({ dataDir: dir, pathSecret: SECRET, verify: fakeVerify, log: () => {}, ...opts });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  t.after(() => new Promise((r) => { srv.closeAllConnections(); srv.close(r); }));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  return { url: `http://127.0.0.1:${srv.address().port}/${SECRET}`, dir, srv };
}

// A machine is a ccswitch home plus its own live credentials file.
function machine(t, name, serverUrl, { target = 'claude', enabled = true } = {}) {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), `ccsw-sync-${name}-`));
  t.after(() => fs.rmSync(home, { recursive: true, force: true }));
  const env = {
    CCSWITCH_HOME: path.join(home, 'profiles'),
    CCSWITCH_CLAUDE_JSON: path.join(home, 'claude.json'),
    CCSWITCH_CREDENTIALS_FILE: path.join(home, 'credentials.json'),
    CCSWITCH_CACHE_DIR: path.join(home, 'cache'),
    CCSWITCH_KEYCHAIN_SERVICE: `ccswitch-test-${process.pid}-${Math.random().toString(36).slice(2)}`,
    KCSWITCH_HOME: path.join(home, 'kimi-profiles'),
    KCSWITCH_KIMI_HOME: path.join(home, 'kimi-home'),
  };
  const use = () => Object.assign(process.env, env);
  use();
  const cfg = config(target);
  if (enabled) writeSyncConfig({ server: serverUrl, fingerprint: FPR, machine: name }, cfg);
  return { cfg, use, pgp: fakePgp() };
}

function captureErr(t) {
  const lines = [];
  const orig = console.error;
  console.error = (...a) => lines.push(a.join(' '));
  t.after(() => { console.error = orig; });
  return lines;
}
function captureLog(t) {
  const lines = [];
  const orig = console.log;
  console.log = (...a) => lines.push(a.join(' '));
  t.after(() => { console.log = orig; });
  return lines;
}

const FUTURE = Date.now() + 3600_000;
const creds = (tag, expiresAt = FUTURE) =>
  JSON.stringify({ claudeAiOauth: { accessToken: `at-${tag}`, refreshToken: `rt-${tag}`, expiresAt } });
const acct = (id) => ({ emailAddress: `${id}@example.com`, accountUuid: id });

// --- buildLocalVault / applyMerge ------------------------------------------------

test('buildLocalVault mirrors profiles, marks moved ones, and adds recorded tombstones', (t) => {
  const { cfg } = machine(t, 'a', 'http://unused');
  saveProfile('work', { credentials: creds('w'), oauthAccount: acct('u1'), savedAt: '2026-01-01T00:00:00.000Z', machine: 'a' }, cfg);
  saveProfile('gone', { credentials: creds('g'), oauthAccount: acct('u2'), movedAt: '2026-01-02T00:00:00.000Z' }, cfg);
  writeSyncConfig({ tombstones: { old: '2026-01-03T00:00:00.000Z', work: '2025-01-01T00:00:00.000Z' } }, cfg);
  const vault = buildLocalVault(cfg);
  assert.deepEqual(vault.work, { credentials: creds('w'), oauthAccount: acct('u1'), savedAt: '2026-01-01T00:00:00.000Z', machine: 'a' });
  assert.deepEqual(vault.gone, { movedAt: '2026-01-02T00:00:00.000Z' });
  assert.deepEqual(vault.old, { deletedAt: '2026-01-03T00:00:00.000Z', machine: 'a' });
});

test('buildLocalVault takes the live chain for the active profile and saves it back', (t) => {
  const { cfg } = machine(t, 'a', 'http://unused');
  saveProfile('work', { credentials: creds('stale'), oauthAccount: acct('u1'), savedAt: '2026-01-01T00:00:00.000Z' }, cfg);
  setActive('work', cfg);
  writeCredentials(creds('rotated'), cfg);
  fs.writeFileSync(cfg.claudeJson, JSON.stringify({ oauthAccount: acct('u1') }));
  const vault = buildLocalVault(cfg);
  assert.equal(vault.work.credentials, creds('rotated'));
  assert.equal(vault.work.machine, 'a');
  assert.ok(vault.work.savedAt > '2026-01-01T00:00:00.000Z');
  assert.equal(loadProfile('work', cfg).credentials, creds('rotated'));
});

test('buildLocalVault leaves the active profile alone when the live login is a different account', (t) => {
  const { cfg } = machine(t, 'a', 'http://unused');
  saveProfile('work', { credentials: creds('w'), oauthAccount: acct('u1'), savedAt: '2026-01-01T00:00:00.000Z' }, cfg);
  setActive('work', cfg);
  writeCredentials(creds('other'), cfg);
  fs.writeFileSync(cfg.claudeJson, JSON.stringify({ oauthAccount: acct('u9') }));
  assert.equal(buildLocalVault(cfg).work.credentials, creds('w'));
});

test('applyMerge writes, deletes, revives moved profiles, updates the live login and clears a deleted active pointer', (t) => {
  const { cfg } = machine(t, 'a', 'http://unused');
  saveProfile('work', { credentials: creds('old'), oauthAccount: acct('u1') }, cfg);
  saveProfile('bye', { credentials: creds('b'), oauthAccount: acct('u2') }, cfg);
  saveProfile('moved', { credentials: creds('m'), oauthAccount: acct('u3'), movedAt: '2026-01-01T00:00:00.000Z' }, cfg);
  setActive('work', cfg);
  writeCredentials(creds('old'), cfg);
  const merged = {
    work: { credentials: creds('new'), oauthAccount: acct('u1'), savedAt: '2026-02-01T00:00:00.000Z', machine: 'b' },
    bye: { deletedAt: '2026-02-01T00:00:00.000Z' },
    moved: { credentials: creds('m2'), oauthAccount: acct('u3'), savedAt: '2026-02-01T00:00:00.000Z' },
    fresh: { credentials: creds('f'), oauthAccount: acct('u4'), savedAt: '2026-02-01T00:00:00.000Z', alternates: [{ credentials: creds('f0'), savedAt: '2026-01-01T00:00:00.000Z' }] },
  };
  captureErr(t);
  applyMerge(merged, { write: ['work', 'moved', 'fresh'], delete: ['bye'] }, cfg);
  assert.equal(loadProfile('work', cfg).credentials, creds('new'));
  assert.equal(loadProfile('work', cfg).machine, 'b');
  assert.equal(readCredentials(cfg), creds('new'));
  assert.equal(profileExists('bye', cfg), false);
  assert.equal(loadProfile('moved', cfg).movedAt, undefined);
  assert.equal(loadProfile('fresh', cfg).alternates.length, 1);
  assert.deepEqual(readSyncConfig(cfg).tombstones, { bye: '2026-02-01T00:00:00.000Z' });
  assert.ok(fs.readdirSync(path.join(cfg.home, 'backups')).some((f) => f.includes('sync-pull')));

  applyMerge({ work: { deletedAt: '2026-03-01T00:00:00.000Z' } }, { write: [], delete: ['work'] }, cfg);
  assert.equal(getActive(cfg), null);
  assert.equal(profileExists('work', cfg), false);
});

// --- syncNow between two machines ----------------------------------------------

test('syncNow refuses to run without setup', async (t) => {
  const { cfg } = machine(t, 'a', 'http://unused', { enabled: false });
  assert.equal(syncEnabled(cfg), false);
  await assert.rejects(syncNow(cfg, { pgp: fakePgp() }), UsageError);
});

test('a profile saved on A appears on B, and the server holds only ciphertext', async (t) => {
  const { url, dir } = await server(t);
  const A = machine(t, 'a', url);
  saveProfile('work', { credentials: creds('w'), oauthAccount: acct('u1') }, A.cfg);
  const r1 = await syncNow(A.cfg, { pgp: A.pgp });
  assert.equal(r1.pushed, true);
  assert.equal(readSyncConfig(A.cfg).version, 1);
  const stored = JSON.parse(fs.readFileSync(path.join(dir, 'vaults', FPR, 'claude.json'), 'utf8'));
  assert.match(stored.data, /^-----BEGIN PGP MESSAGE-----/);
  assert.ok(!stored.data.includes('work') && !stored.data.includes('at-w'));

  const B = machine(t, 'b', url);
  const r2 = await syncNow(B.cfg, { pgp: B.pgp });
  assert.deepEqual(r2.pulled, ['work']);
  assert.equal(r2.pushed, false);
  assert.equal(loadProfile('work', B.cfg).credentials, creds('w'));
  assert.equal(loadProfile('work', B.cfg).machine, 'a');
  assert.equal(readSyncConfig(B.cfg).version, 1);
});

test('a chain rotated on A reaches B and replaces B\'s live login when that profile is active', async (t) => {
  const { url } = await server(t);
  const A = machine(t, 'a', url);
  saveProfile('work', { credentials: creds('v1'), oauthAccount: acct('u1') }, A.cfg);
  await syncNow(A.cfg, { pgp: A.pgp });
  const B = machine(t, 'b', url);
  await syncNow(B.cfg, { pgp: B.pgp });
  B.use();
  setActive('work', B.cfg);
  writeCredentials(creds('v1'), B.cfg);
  fs.writeFileSync(B.cfg.claudeJson, JSON.stringify({ oauthAccount: acct('u1') }));

  A.use();
  saveProfile('work', { credentials: creds('v2'), oauthAccount: acct('u1') }, A.cfg);
  const ra = await syncNow(A.cfg, { pgp: A.pgp });
  assert.equal(ra.pushed, true);

  B.use();
  captureErr(t);
  const rb = await syncNow(B.cfg, { pgp: B.pgp });
  assert.deepEqual(rb.pulled, ['work']);
  assert.equal(readCredentials(B.cfg), creds('v2'));
  assert.equal(loadProfile('work', B.cfg).credentials, creds('v2'));
});

test('a delete on B removes the profile on A', async (t) => {
  const { url } = await server(t);
  const A = machine(t, 'a', url);
  saveProfile('work', { credentials: creds('w'), oauthAccount: acct('u1') }, A.cfg);
  saveProfile('keep', { credentials: creds('k'), oauthAccount: acct('u2') }, A.cfg);
  await syncNow(A.cfg, { pgp: A.pgp });
  const B = machine(t, 'b', url);
  await syncNow(B.cfg, { pgp: B.pgp });
  B.use();
  captureLog(t);
  await deleteProfileCmd('work', { force: true }, B.cfg);
  assert.equal(typeof readSyncConfig(B.cfg).tombstones.work, 'string');
  await syncNow(B.cfg, { pgp: B.pgp });
  A.use();
  const ra = await syncNow(A.cfg, { pgp: A.pgp });
  assert.deepEqual(ra.deleted, ['work']);
  assert.equal(profileExists('work', A.cfg), false);
  assert.equal(profileExists('keep', A.cfg), true);
});

test('both machines refreshing the same profile ends with alternates, not a lost chain', async (t) => {
  const { url } = await server(t);
  const A = machine(t, 'a', url);
  saveProfile('work', { credentials: creds('base'), oauthAccount: acct('u1'), savedAt: '2026-01-01T00:00:00.000Z' }, A.cfg);
  await syncNow(A.cfg, { pgp: A.pgp });
  const B = machine(t, 'b', url);
  await syncNow(B.cfg, { pgp: B.pgp });

  A.use();
  saveProfile('work', { credentials: creds('fromA'), oauthAccount: acct('u1'), savedAt: '2026-01-02T00:00:00.000Z', machine: 'a' }, A.cfg);
  await syncNow(A.cfg, { pgp: A.pgp });
  B.use();
  saveProfile('work', { credentials: creds('fromB'), oauthAccount: acct('u1'), savedAt: '2026-01-03T00:00:00.000Z', machine: 'b' }, B.cfg);
  const rb = await syncNow(B.cfg, { pgp: B.pgp });
  assert.equal(rb.pushed, true);
  const onB = loadProfile('work', B.cfg);
  assert.equal(onB.credentials, creds('fromB'));
  assert.deepEqual(onB.alternates, [{ credentials: creds('fromA'), savedAt: '2026-01-02T00:00:00.000Z', machine: 'a' }]);

  A.use();
  await syncNow(A.cfg, { pgp: A.pgp });
  const onA = loadProfile('work', A.cfg);
  assert.equal(onA.credentials, creds('fromB'));
  assert.equal(onA.alternates.length, 1);
});

test('a version conflict during push is merged and retried', async (t) => {
  const { url } = await server(t);
  const A = machine(t, 'a', url);
  const B = machine(t, 'b', url);
  A.use();
  saveProfile('a-only', { credentials: creds('a'), oauthAccount: acct('u1') }, A.cfg);
  B.use();
  saveProfile('b-only', { credentials: creds('b'), oauthAccount: acct('u2') }, B.cfg);
  // B pushes first through a fetch that lets A's get run before B's put lands.
  let bPut;
  const gate = new Promise((r) => { bPut = r; });
  const slowFetch = async (u, init) => {
    if (JSON.parse(JSON.parse(init.body).payload).op === 'put') await gate;
    return fetch(u, init);
  };
  const pB = syncNow(B.cfg, { pgp: B.pgp, fetchImpl: slowFetch });
  await new Promise((r) => setTimeout(r, 50));
  A.use();
  const pA = syncNow(A.cfg, { pgp: A.pgp });
  await new Promise((r) => setTimeout(r, 50));
  bPut();
  const [rA, rB] = await Promise.all([pA, pB]);
  assert.ok(rA.pushed && rB.pushed);
  const versions = [readSyncConfig(A.cfg).version, readSyncConfig(B.cfg).version].sort();
  assert.deepEqual(versions, [1, 2]);
  const loser = versions[0] === readSyncConfig(A.cfg).version ? A : B;
  loser.use();
  await syncNow(loser.cfg, { pgp: loser.pgp });
  assert.ok(profileExists('a-only', loser.cfg) && profileExists('b-only', loser.cfg));
});

test('a server that serves an older vault than last seen is refused', async (t) => {
  const { url, dir } = await server(t);
  const A = machine(t, 'a', url);
  saveProfile('work', { credentials: creds('w'), oauthAccount: acct('u1') }, A.cfg);
  await syncNow(A.cfg, { pgp: A.pgp });
  saveProfile('work', { credentials: creds('w2'), oauthAccount: acct('u1') }, A.cfg);
  await syncNow(A.cfg, { pgp: A.pgp });
  assert.equal(readSyncConfig(A.cfg).version, 2);
  fs.rmSync(path.join(dir, 'vaults', FPR), { recursive: true });
  await assert.rejects(syncNow(A.cfg, { pgp: A.pgp }), (err) => err instanceof SyncError && /older/.test(err.message));
  assert.equal(loadProfile('work', A.cfg).credentials, creds('w2'));
});

test('a vault whose plaintext names another vault or version is refused', async (t) => {
  const { url } = await server(t);
  const A = machine(t, 'a', url);
  saveProfile('work', { credentials: creds('w'), oauthAccount: acct('u1') }, A.cfg);
  await syncNow(A.cfg, { pgp: A.pgp });
  const lying = { ...A.pgp, decrypt: (a) => A.pgp.decrypt(a).replace('"vault":"claude"', '"vault":"kimi"') };
  await assert.rejects(syncNow(A.cfg, { pgp: lying }), (err) => err instanceof SyncError && /kimi/.test(err.message));
  const stale = { ...A.pgp, decrypt: (a) => A.pgp.decrypt(a).replace('"version":1', '"version":7') };
  await assert.rejects(syncNow(A.cfg, { pgp: stale }), (err) => err instanceof SyncError && /version/.test(err.message));
});

test('an unreachable server, a wrong URL and a rejected signature give clear SyncErrors', async (t) => {
  const { url } = await server(t);
  const A = machine(t, 'a', url);
  saveProfile('work', { credentials: creds('w'), oauthAccount: acct('u1') }, A.cfg);
  writeSyncConfig({ server: 'http://127.0.0.1:1' }, A.cfg);
  await assert.rejects(syncNow(A.cfg, { pgp: A.pgp }), (err) => err instanceof SyncError && /could not reach/.test(err.message));
  writeSyncConfig({ server: url.replace(SECRET, 'b'.repeat(64)) }, A.cfg);
  await assert.rejects(syncNow(A.cfg, { pgp: A.pgp }), (err) => err instanceof SyncError && /URL/.test(err.message));
  writeSyncConfig({ server: url }, A.cfg);
  const badSigner = { ...A.pgp, sign: () => `${SIG}#0` };
  await assert.rejects(syncNow(A.cfg, { pgp: badSigner }), (err) => err instanceof SyncError && /signature/.test(err.message));
});

test('kimi profiles sync through their own vault', async (t) => {
  const { url, dir } = await server(t);
  const A = machine(t, 'a', url, { target: 'kimi' });
  const now = Math.floor(Date.now() / 1000);
  const kc = JSON.stringify({ access_token: 'at', refresh_token: 'rt', expires_at: now + 3600 });
  saveProfile('work', { credentials: kc, oauthAccount: { userId: 'u1' } }, A.cfg);
  await syncNow(A.cfg, { pgp: A.pgp });
  assert.ok(fs.existsSync(path.join(dir, 'vaults', FPR, 'kimi.json')));
  const B = machine(t, 'b', url, { target: 'kimi' });
  await syncNow(B.cfg, { pgp: B.pgp });
  assert.equal(loadProfile('work', B.cfg).credentials, kc);
});

// --- commands and auto-sync hooks -------------------------------------------------

import { syncSetup, syncStatus, withSyncLock } from '../ccswitch.mjs';

// Routes sync traffic to the real in-process server and everything else to a
// tiny fake provider, counting sync requests so debounce can be observed.
function routedFetch(t, serverUrl, provider = async () => ({ ok: true, status: 200, json: async () => ({}) })) {
  const real = globalThis.fetch;
  const state = { syncCalls: 0 };
  globalThis.fetch = async (url, init) => {
    if (String(url).startsWith(serverUrl)) {
      state.syncCalls++;
      return real(url, init);
    }
    return provider(url, init);
  };
  t.after(() => { globalThis.fetch = real; });
  return state;
}

test('main sync: pushes local profiles, reports, and a second run is a no-op', async (t) => {
  const { url } = await server(t);
  const A = machine(t, 'a', url);
  saveProfile('work', { credentials: creds('w'), oauthAccount: acct('u1') }, A.cfg);
  const lines = captureLog(t);
  assert.equal(await main(['sync'], { pgp: A.pgp }), 0);
  assert.match(lines.join('\n'), /pushed.*vault v1/);
  assert.equal(await main(['sync'], { pgp: A.pgp }), 0);
  assert.match(lines.join('\n'), /in sync.*v1/);
});

test('main: a command auto-pulls first and auto-pushes token changes afterwards', async (t) => {
  const { url } = await server(t);
  const A = machine(t, 'a', url);
  saveProfile('work', { credentials: creds('w'), oauthAccount: acct('u1') }, A.cfg);
  await syncNow(A.cfg, { pgp: A.pgp });
  const B = machine(t, 'b', url);
  B.use();
  routedFetch(t, url);
  captureLog(t);
  captureErr(t);
  assert.equal(await main(['usage'], { pgp: B.pgp }), 0); // pulled "work" before the usage table
  assert.equal(loadProfile('work', B.cfg).credentials, creds('w'));

  writeCredentials(creds('b-live'), B.cfg);
  fs.writeFileSync(B.cfg.claudeJson, JSON.stringify({ oauthAccount: acct('u2') }));
  writeSyncConfig({ lastSyncAt: new Date().toISOString() }, B.cfg); // fresh enough to skip the pre-pull
  assert.equal(await main(['save', 'home'], { pgp: B.pgp }), 0); // pushed afterwards
  A.use();
  const ra = await syncNow(A.cfg, { pgp: A.pgp });
  assert.deepEqual(ra.pulled, ['home']);
  assert.equal(loadProfile('home', A.cfg).credentials, creds('b-live'));
});

test('main: the pre-command pull is debounced, list never syncs, and --dry-run never talks to the server', async (t) => {
  const { url } = await server(t);
  const A = machine(t, 'a', url);
  saveProfile('work', { credentials: creds('w'), oauthAccount: acct('u1') }, A.cfg);
  const state = routedFetch(t, url);
  captureLog(t);
  captureErr(t);
  await main(['usage'], { pgp: A.pgp });
  const after = state.syncCalls;
  assert.ok(after >= 2, 'get + put');
  await main(['usage'], { pgp: A.pgp });
  assert.equal(state.syncCalls, after, 'second run inside the debounce window makes no sync request');
  writeSyncConfig({ lastSyncAt: '2020-01-01T00:00:00.000Z' }, A.cfg);
  await main(['list'], { pgp: A.pgp });
  assert.equal(state.syncCalls, after, 'list is read-only and never syncs');
  await main(['--dry-run', 'usage'], { pgp: A.pgp });
  assert.equal(state.syncCalls, after, 'dry-run makes no requests');
  await main(['usage'], { pgp: A.pgp });
  assert.ok(state.syncCalls > after, 'past the window it syncs again');
});

test('main: sync failures warn and the command still succeeds', async (t) => {
  const A = machine(t, 'a', 'http://127.0.0.1:1');
  saveProfile('work', { credentials: creds('w'), oauthAccount: acct('u1') }, A.cfg);
  routedFetch(t, 'http://127.0.0.1:1');
  const errs = captureErr(t);
  const lines = captureLog(t);
  assert.equal(await main(['usage'], { pgp: A.pgp }), 0);
  assert.match(errs.join('\n'), /sync: could not reach .*continuing with local profiles/);
  assert.match(lines.join('\n'), /work/);
  assert.equal(await main(['sync'], { pgp: A.pgp }), 1);
});

test('withSyncLock skips when another ccswitch holds a fresh lock and breaks a stale one', async (t) => {
  const A = machine(t, 'a', 'http://unused');
  const lock = path.join(A.cfg.home, 'sync.lock');
  fs.writeFileSync(lock, JSON.stringify({ pid: 1, at: new Date().toISOString() }));
  assert.equal(await withSyncLock(A.cfg, async () => 'ran'), null);
  fs.writeFileSync(lock, JSON.stringify({ pid: 1, at: '2020-01-01T00:00:00.000Z' }));
  assert.equal(await withSyncLock(A.cfg, async () => 'ran'), 'ran');
  assert.equal(fs.existsSync(lock), false);
  await assert.rejects(withSyncLock(A.cfg, async () => { throw new Error('boom'); }), /boom/);
  assert.equal(fs.existsSync(lock), false, 'lock released on failure');
});

test('main sync resolves pending candidate chains and pushes the winner', async (t) => {
  const { url } = await server(t);
  const A = machine(t, 'a', url);
  saveProfile(
    'work',
    { credentials: creds('new'), oauthAccount: acct('u1'), savedAt: '2026-01-02T00:00:00.000Z', machine: 'a',
      alternates: [{ credentials: creds('old'), savedAt: '2026-01-01T00:00:00.000Z', machine: 'b' }] },
    A.cfg,
  );
  routedFetch(t, url, async (u, init) => {
    if (u.includes('/oauth/usage')) {
      const ok = init.headers.Authorization === 'Bearer at-old';
      return { ok, status: ok ? 200 : 401, json: async () => ({}) };
    }
    return { ok: false, status: 400, json: async () => ({}) };
  });
  const errs = captureErr(t);
  captureLog(t);
  assert.equal(await main(['sync'], { pgp: A.pgp }), 0);
  assert.equal(loadProfile('work', A.cfg).alternates, undefined);
  assert.equal(loadProfile('work', A.cfg).credentials, creds('old'));
  assert.match(errs.join('\n'), /chain from b is live/);
  const B = machine(t, 'b', url);
  await syncNow(B.cfg, { pgp: B.pgp });
  assert.equal(loadProfile('work', B.cfg).credentials, creds('old'));
  assert.equal(loadProfile('work', B.cfg).alternates, undefined);
});

test('sync status and sync off', async (t) => {
  const { url } = await server(t);
  const A = machine(t, 'a', url);
  saveProfile('work', { credentials: creds('w'), oauthAccount: acct('u1'), alternates: [{ credentials: creds('x'), savedAt: '2026-01-01T00:00:00.000Z' }] }, A.cfg);
  const lines = captureLog(t);
  assert.equal(await main(['sync', 'status'], { pgp: A.pgp }), 0);
  const out = lines.join('\n');
  assert.match(out, new RegExp(url));
  assert.match(out, /071BC24A/);
  assert.match(out, /machine.*a/);
  assert.match(out, /never/);
  assert.match(out, /work/);
  assert.equal(await main(['sync', 'off'], { pgp: A.pgp }), 0);
  assert.equal(syncEnabled(A.cfg), false);
  assert.equal(profileExists('work', A.cfg), true);
  assert.equal(await main(['sync', 'status'], { pgp: A.pgp }), 0);
  assert.match(lines.join('\n'), /not set up/);
  await assert.rejects(main(['sync', 'bogus'], { pgp: A.pgp }), UsageError);
});

test('sync setup: picks a key, takes the URL, writes the config and runs the first sync', async (t) => {
  const { url } = await server(t);
  const A = machine(t, 'a', url, { enabled: false });
  saveProfile('work', { credentials: creds('w'), oauthAccount: acct('u1') }, A.cfg);
  const asked = [];
  const picked = [];
  const out = captureLog(t);
  const gpg = {
    findGpg: () => ({ bin: 'gpg', version: '2.5.0' }),
    listSecretKeys: () => [
      { fingerprint: 'DEAD'.repeat(10), uid: 'other <o@example.com>' },
      { fingerprint: FPR, uid: 'me <me@example.com>' },
    ],
    generateKey: () => { throw new Error('not expected'); },
    createPgp: ({ fingerprint }) => fakePgp(fingerprint),
  };
  const cfg = await syncSetup(A.cfg, {
    gpg,
    ask: async (q) => { asked.push(q); return q.includes('URL') ? url : ''; },
    pick: async (header, rows) => { picked.push(rows); return 1; },
  });
  assert.equal(cfg.fingerprint, FPR);
  assert.equal(cfg.server, url);
  assert.match(cfg.machine, /^[a-z0-9.-]+-[0-9a-f]{4}$/i);
  assert.deepEqual(picked[0].slice(0, 2).map((r) => r[0]), [`DEAD`.repeat(10).slice(-16), FPR.slice(-16)]);
  assert.match(picked[0][2][1], /generate/i);
  assert.equal(readSyncConfig(A.cfg).version, 1, 'first sync pushed the profile');
  assert.match(out.join('\n'), /pushed/);
});

test('sync setup: can generate a key, and refuses without gpg', async (t) => {
  const { url } = await server(t);
  const A = machine(t, 'a', url, { enabled: false });
  const generated = [];
  const gpg = {
    findGpg: () => ({ bin: 'gpg', version: '2.5.0' }),
    listSecretKeys: () => [],
    generateKey: (uid) => { generated.push(uid); return FPR; },
    createPgp: ({ fingerprint }) => fakePgp(fingerprint),
  };
  captureLog(t);
  const cfg = await syncSetup(A.cfg, {
    gpg,
    ask: async (q) => (q.includes('URL') ? url : q.includes('name') ? 'Me <me@example.com>' : ''),
    pick: async (header, rows) => rows.length - 1,
  });
  assert.deepEqual(generated, ['Me <me@example.com>']);
  assert.equal(cfg.fingerprint, FPR);

  const B = machine(t, 'b', url, { enabled: false });
  const errs = [];
  await assert.rejects(
    syncSetup(B.cfg, { gpg: { ...gpg, findGpg: () => null, ensureGpg: async ({ out }) => { out('install it'); throw new UsageError('gpg is not installed'); } }, ask: async () => '', pick: async () => 0, out: (l) => errs.push(l) }),
    /gpg is not installed/,
  );
});

test('help lists the sync commands', async (t) => {
  machine(t, 'a', 'http://unused', { enabled: false });
  const lines = captureLog(t);
  await main(['--help']);
  const out = lines.join('\n');
  for (const c of ['sync setup', 'sync status', 'sync off']) assert.ok(out.includes(c), c);
});
