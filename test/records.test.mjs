import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';

import { config, saveProfile, loadProfile, setActive, setPassphrase, setStoreEncryption, writeCredentials, writeUsageCache, readUsageCache, listProfileRecords, listProfilesWithUsage, liveIdentity, liveUsage, prepareRun, doctor, keychainServiceFor, materializeRunDir } from '../ccswitch.mjs';
import { sandbox, kimiSandbox, fakeClaudeBin, usageCreds, fakeSecurity, onDarwin, kimiCreds, captureLog } from './helpers.mjs';

// The plain-data API a program embedding ccswitch uses: records behind the
// tables, the live login, a pty-friendly run handle and the doctor report.
// Secrets never appear in any of them.

const okUsage = async () => ({
  ok: true,
  status: 200,
  json: async () => ({ five_hour: { utilization: 42, resets_at: '2030-01-01T00:00:00Z' }, seven_day: { utilization: 7, resets_at: null } }),
});

function assertNoSecrets(value) {
  assert.doesNotMatch(JSON.stringify(value), /at-|rt-|accessToken|refresh_token|access_token/);
}

test('listProfileRecords strips credentials and marks the active and moved profiles', (t) => {
  sandbox(t);
  const cfg = config();
  saveProfile('work', { credentials: usageCreds({ subscriptionType: 'max', expiresAt: 1700000000000 }), oauthAccount: { accountUuid: 'u-w', emailAddress: 'w@x.com', organizationRateLimitTier: 'default_claude_max_5x' } }, cfg);
  saveProfile('gone', { credentials: usageCreds(), oauthAccount: { emailAddress: 'g@x.com' }, movedAt: '2026-01-01T00:00:00.000Z' }, cfg);
  setActive('work', cfg);
  const out = listProfileRecords(cfg);
  assert.equal(out.target, 'claude');
  assert.equal(out.active, 'work');
  assert.deepEqual(out.profiles.map((p) => p.name), ['gone', 'work']);
  const work = out.profiles[1];
  assert.deepEqual(work, {
    name: 'work', active: true, moved: false, account: 'w@x.com', tier: 'default_claude_max_5x', accountId: 'u-w',
    subscriptionType: 'max', tokenExpiresAt: '2023-11-14T22:13:20.000Z', savedAt: loadProfile('work', cfg).savedAt,
  });
  assert.equal(out.profiles[0].moved, true);
  assertNoSecrets(out);
});

test('listProfilesWithUsage returns one record per profile with usage and state', async (t) => {
  sandbox(t);
  const cfg = config();
  saveProfile('work', { credentials: usageCreds(), oauthAccount: { emailAddress: 'w@x.com' } }, cfg);
  saveProfile('dead', { credentials: usageCreds({ accessToken: 'at-dead' }), oauthAccount: { emailAddress: 'd@x.com' } }, cfg);
  saveProfile('gone', { credentials: usageCreds(), oauthAccount: { emailAddress: 'g@x.com' }, movedAt: '2026-01-01T00:00:00.000Z' }, cfg);
  const fetchImpl = async (url, init) =>
    init.headers.Authorization === 'Bearer at-dead' ? { ok: false, status: 401, json: async () => ({}) } : okUsage();
  const out = await listProfilesWithUsage({}, cfg, fetchImpl);
  assert.equal(typeof out.fetchedAt, 'number');
  const by = Object.fromEntries(out.profiles.map((p) => [p.name, p]));
  assert.deepEqual(by.work.usage, { fiveHour: { utilization: 42, resetsAt: '2030-01-01T00:00:00Z' }, sevenDay: { utilization: 7, resetsAt: null }, fable: null });
  assert.deepEqual(by.work.state, { kind: 'ok' });
  assert.equal(by.work.cachedAt, null);
  assert.deepEqual(by.dead.state, { kind: 'dead' });
  assert.equal(by.dead.usage, null);
  assert.deepEqual(by.gone.state, { kind: 'moved' });
  assert.equal(by.gone.moved, true);
  assertNoSecrets(out);
  // The successful lookup was cached, exactly as the table command does.
  assert.equal(readUsageCache('work', cfg).usage.fiveHour.utilization, 42);
});

test('listProfilesWithUsage refresh:false answers from the cache without touching the network', async (t) => {
  sandbox(t);
  const cfg = config();
  saveProfile('work', { credentials: usageCreds({ expiresAt: 1 }), oauthAccount: { emailAddress: 'w@x.com' } }, cfg);
  saveProfile('new', { credentials: usageCreds(), oauthAccount: { emailAddress: 'n@x.com' } }, cfg);
  writeUsageCache('work', { fiveHour: { utilization: 11, resetsAt: null }, sevenDay: null, fable: null }, cfg, 1234);
  const out = await listProfilesWithUsage({ refresh: false }, cfg, async () => {
    throw new Error('network hit');
  });
  const by = Object.fromEntries(out.profiles.map((p) => [p.name, p]));
  assert.equal(by.work.usage.fiveHour.utilization, 11);
  assert.equal(by.work.cachedAt, 1234);
  assert.deepEqual(by.work.state, { kind: 'cached', at: 1234 });
  assert.deepEqual(by.new.state, { kind: 'error', message: 'no cached usage' });
  assert.equal(by.new.usage, null);
  // No refresh happened either: the expired snapshot is untouched.
  assert.equal(JSON.parse(loadProfile('work', cfg).credentials).claudeAiOauth.expiresAt, 1);
});

test('listProfilesWithUsage reports the kimi shape for a kimi store', async (t) => {
  kimiSandbox(t);
  const cfg = config('kimi');
  saveProfile('main', { credentials: kimiCreds({ sub: 'u-1' }), oauthAccount: { userId: 'u-1' } }, cfg);
  const fetchImpl = async (url) => {
    if (url.endsWith('/usages')) return { ok: true, status: 200, json: async () => ({ usage: { used: 3, limit: 10 } }) };
    if (url.endsWith('/me')) return { ok: true, status: 200, json: async () => ({ user_id: 'u-1', nickname: 'Shy', user_level_name: 'Pro' }) };
    throw new Error(`unexpected url ${url}`);
  };
  const out = await listProfilesWithUsage({}, cfg, fetchImpl);
  assert.equal(out.target, 'kimi');
  const [rec] = out.profiles;
  assert.equal(rec.usage.summary.utilization, 30);
  assert.equal(rec.usage.summary.label, '1w');
  assert.deepEqual(rec.usage.limits, []);
  assert.equal(rec.usage.booster, null);
  // /me enrichment lands in the record as well as in the profile.
  assert.equal(rec.account, 'Shy');
  assert.equal(rec.tier, 'Pro');
  assert.equal(rec.accountId, 'u-1');
  assert.equal(rec.subscriptionType, null);
  assertNoSecrets(out);
});

test('liveIdentity describes the live login and names the profile that owns it', (t) => {
  sandbox(t);
  const cfg = config();
  assert.deepEqual(liveIdentity(cfg), {
    loggedIn: false, account: null, tier: null, accountId: null, subscriptionType: null, rateLimitTier: null, tokenExpiresAt: null, profile: null,
  });
  writeCredentials(usageCreds({ subscriptionType: 'max', rateLimitTier: 'default_claude_max_20x', expiresAt: 1700000000000 }), cfg);
  fs.writeFileSync(cfg.claudeJson, JSON.stringify({ oauthAccount: { accountUuid: 'u-1', emailAddress: 'me@x.com', organizationRateLimitTier: 'default_claude_max_20x' } }));
  // Two profiles hold this account; the active one is the owner.
  saveProfile('copy', { credentials: null, oauthAccount: { accountUuid: 'u-1', emailAddress: 'me@x.com' } }, cfg);
  saveProfile('work', { credentials: null, oauthAccount: { accountUuid: 'u-1', emailAddress: 'me@x.com' } }, cfg);
  setActive('work', cfg);
  const id = liveIdentity(cfg);
  assert.deepEqual(id, {
    loggedIn: true, account: 'me@x.com', tier: 'default_claude_max_20x', accountId: 'u-1', subscriptionType: 'max',
    rateLimitTier: 'default_claude_max_20x', tokenExpiresAt: '2023-11-14T22:13:20.000Z', profile: 'work',
  });
  setActive(null, cfg);
  assert.equal(liveIdentity(cfg).profile, 'copy'); // first by name once no profile is active
  fs.writeFileSync(cfg.claudeJson, JSON.stringify({ oauthAccount: { accountUuid: 'u-9', emailAddress: 'other@x.com' } }));
  assert.equal(liveIdentity(cfg).profile, null); // logged in, but no profile holds this account
  assert.equal(liveIdentity(cfg).account, 'other@x.com');
});

test('liveIdentity on kimi borrows display fields from the matching profile', (t) => {
  kimiSandbox(t);
  const cfg = config('kimi');
  writeCredentials(kimiCreds({ sub: 'u-1' }), cfg);
  saveProfile('main', { credentials: null, oauthAccount: { userId: 'u-1', nickname: 'Shy', userLevelName: 'Pro' } }, cfg);
  const id = liveIdentity(cfg);
  assert.equal(id.account, 'Shy');
  assert.equal(id.tier, 'Pro');
  assert.equal(id.accountId, 'u-1');
  assert.equal(id.profile, 'main');
  assert.equal(id.subscriptionType, null);
});

test('liveUsage on kimi remembers the /me fields of a login no profile holds', async (t) => {
  kimiSandbox(t);
  const cfg = config('kimi');
  writeCredentials(kimiCreds({ sub: 'u-1' }), cfg);
  assert.equal(liveIdentity(cfg).account, 'u-1'); // nothing looked up yet
  const fetchImpl = async (url) => {
    if (url.endsWith('/usages')) return { ok: true, status: 200, json: async () => ({ usage: { limit: '100', remaining: '60' } }) };
    if (url.endsWith('/me')) return { ok: true, status: 200, json: async () => ({ user_id: 'u-1', nickname: 'Shy', email: 'shy@x.com', user_level_name: 'Pro' }) };
    throw new Error(`unexpected url ${url}`);
  };
  const out = await liveUsage({}, cfg, fetchImpl);
  assert.equal(out.usage.summary.utilization, 40);
  const id = liveIdentity(cfg);
  assert.equal(id.account, 'shy@x.com');
  assert.equal(id.tier, 'Pro');
  assert.equal(id.accountId, 'u-1');

  // A login to another account never inherits them.
  writeCredentials(kimiCreds({ sub: 'u-2' }), cfg);
  assert.equal(liveIdentity(cfg).account, 'u-2');
  assert.equal(liveIdentity(cfg).tier, null);
});

test('liveUsage refreshes an expired live token, persists it, and caches under .live', async (t) => {
  sandbox(t);
  const cfg = config();
  writeCredentials(JSON.stringify({ claudeAiOauth: { accessToken: 'at-old', refreshToken: 'rt-old', expiresAt: 1 } }), cfg);
  fs.writeFileSync(cfg.claudeJson, JSON.stringify({ oauthAccount: { accountUuid: 'u-1', emailAddress: 'me@x.com' } }));
  saveProfile('work', { credentials: '{"stale":true}', oauthAccount: { accountUuid: 'u-1', emailAddress: 'me@x.com' } }, cfg);
  setActive('work', cfg);
  const fetchImpl = async (url, init) => {
    if (url.includes('/oauth/token')) {
      return { ok: true, status: 200, json: async () => ({ access_token: 'at-new', refresh_token: 'rt-new', expires_in: 28800 }) };
    }
    assert.equal(init.headers.Authorization, 'Bearer at-new');
    return okUsage();
  };
  const out = await liveUsage({}, cfg, fetchImpl);
  assert.equal(out.usage.fiveHour.utilization, 42);
  assert.deepEqual(out.state, { kind: 'ok' });
  assert.equal(JSON.parse(fs.readFileSync(cfg.credentialsFile, 'utf8')).claudeAiOauth.refreshToken, 'rt-new');
  assert.equal(JSON.parse(loadProfile('work', cfg).credentials).claudeAiOauth.refreshToken, 'rt-new'); // active profile save-back
  assert.equal(readUsageCache('.live', cfg).usage.fiveHour.utilization, 42);

  const cached = await liveUsage({ refresh: false }, cfg, async () => {
    throw new Error('network hit');
  });
  assert.equal(cached.usage.fiveHour.utilization, 42);
  assert.equal(cached.state.kind, 'cached');

  // Without a live login there is nothing to ask about.
  fs.rmSync(cfg.credentialsFile);
  assert.deepEqual(await liveUsage({}, cfg, okUsage), { usage: null, cachedAt: null, state: { kind: 'dead' } });
});

test('prepareRun hands back what to spawn and finish() saves rotated tokens back', (t) => {
  const { home } = sandbox(t);
  t.after(() => { delete process.env.CCSWITCH_CLAUDE_BIN; });
  const bin = fakeClaudeBin(home, 'true\n');
  const cfg = config();
  saveProfile('work', { credentials: usageCreds({ expiresAt: 1000 }), oauthAccount: { emailAddress: 'w@x.com', organizationRateLimitTier: 'default_claude_max_5x' } }, cfg);

  const run = prepareRun('work', cfg);

  assert.equal(run.bin, bin);
  assert.equal(run.dir, path.join(cfg.home, 'dirs', 'work'));
  assert.deepEqual(run.env, { CLAUDE_CONFIG_DIR: run.dir });
  assert.deepEqual(run.profile, { name: 'work', account: 'w@x.com', tier: 'default_claude_max_5x' });
  assert.equal(JSON.parse(fs.readFileSync(path.join(run.dir, '.credentials.json'), 'utf8')).claudeAiOauth.accessToken, 'at-1');
  assertNoSecrets({ ...run, finish: undefined });

  // The session (whatever spawned it) rotated the chain in the run dir.
  fs.writeFileSync(path.join(run.dir, '.credentials.json'), usageCreds({ refreshToken: 'rt-rotated', expiresAt: 5000 }));
  assert.deepEqual(run.finish(), { savedBack: true });
  assert.equal(JSON.parse(loadProfile('work', cfg).credentials).claudeAiOauth.refreshToken, 'rt-rotated');
  assert.deepEqual(run.finish(), { savedBack: true }); // idempotent

  fs.rmSync(path.join(run.dir, '.credentials.json'));
  assert.deepEqual(run.finish(), { savedBack: false });
});

test('prepareRun on kimi points KIMI_CODE_HOME at the run dir', (t) => {
  kimiSandbox(t);
  const cfg = config('kimi');
  saveProfile('main', { credentials: kimiCreds({ sub: 'u-1' }), oauthAccount: { userId: 'u-1', nickname: 'Shy' } }, cfg);
  const run = prepareRun('main', cfg);
  assert.equal(run.bin, 'kimi');
  assert.deepEqual(run.env, { KIMI_CODE_HOME: run.dir });
  assert.equal(run.profile.account, 'Shy');
  assert.ok(fs.existsSync(path.join(run.dir, 'credentials', 'kimi-code.json')));
});

test('doctor reports the store, the live login and the tool binary without secrets', (t) => {
  const { home } = sandbox(t);
  t.after(() => { delete process.env.CCSWITCH_CLAUDE_BIN; });
  const bin = fakeClaudeBin(home, 'true\n');
  const cfg = config();
  let d = doctor(cfg);
  assert.equal(d.target, 'claude');
  assert.equal(d.platform, process.platform);
  assert.equal(d.node, process.version);
  assert.deepEqual(d.bin, { name: bin, found: bin });
  assert.deepEqual(d.store, { home: cfg.home, exists: false, encrypted: false, readable: true, profiles: [], active: null, runDirs: [] });
  assert.deepEqual(d.credentialsFile, { path: cfg.credentialsFile, present: false });
  assert.equal(d.live.loggedIn, false);

  saveProfile('work', { credentials: usageCreds(), oauthAccount: { accountUuid: 'u-1', emailAddress: 'w@x.com' } }, cfg);
  setActive('work', cfg);
  materializeRunDir('work', cfg);
  writeCredentials(usageCreds(), cfg);
  fs.writeFileSync(cfg.claudeJson, JSON.stringify({ oauthAccount: { accountUuid: 'u-1', emailAddress: 'w@x.com' } }));
  d = doctor(cfg);
  assert.deepEqual(d.store.profiles, ['work']);
  assert.deepEqual(d.store.runDirs, ['work']);
  assert.equal(d.store.active, 'work');
  assert.equal(d.credentialsFile.present, true);
  assert.equal(d.live.profile, 'work');
  assertNoSecrets(d);

  // A binary that is not on PATH is reported, not thrown.
  process.env.CCSWITCH_CLAUDE_BIN = 'definitely-not-a-real-binary';
  assert.deepEqual(doctor(config()).bin, { name: 'definitely-not-a-real-binary', found: null });
});

test('doctor reports a sealed store it cannot open as unreadable', (t) => {
  sandbox(t);
  t.after(() => setPassphrase(null));
  const cfg = config();
  saveProfile('work', { credentials: usageCreds(), oauthAccount: { emailAddress: 'w@x.com' } }, cfg);
  setPassphrase('pw');
  captureLog(t);
  setStoreEncryption(true, cfg);
  setPassphrase(null);
  const d = doctor(cfg);
  assert.equal(d.store.encrypted, true);
  assert.equal(d.store.readable, false);
  assert.equal(d.store.profiles, null);
  assert.equal(d.live.loggedIn, false);
});

test('doctor probes the Keychain by presence only and reports its lock state', onDarwin, (t) => {
  const { home } = sandbox(t);
  const kc = fakeSecurity(t, home);
  const cfg = config();
  saveProfile('work', { credentials: usageCreds(), oauthAccount: null }, cfg);
  const dir = materializeRunDir('work', cfg);
  kc.put(keychainServiceFor(dir, cfg), 'secret-item');
  kc.reset();
  const d = doctor(cfg);
  assert.deepEqual(d.keychain, {
    available: true,
    locked: false,
    lockProbeStatus: 0,
    defaultEntry: { service: cfg.keychainService, present: false },
    runDirEntries: [{ name: 'work', service: keychainServiceFor(dir, cfg), present: true }],
  });
  // Presence probes never pass -w (that would print the secret); the only
  // -w read is the live login's, which captureLive has always done. Nothing
  // is deleted, locked or unlocked.
  const calls = kc.calls();
  assert.ok(calls.includes(`find-generic-password -s ${keychainServiceFor(dir, cfg)}`));
  for (const call of calls) {
    assert.match(call, /^(find-generic-password|show-keychain-info) /);
    if (!call.includes(`-s ${cfg.keychainService} -w`)) assert.doesNotMatch(call, /(^| )-w( |$)/);
  }
  assert.doesNotMatch(JSON.stringify(d), /secret-item/);
  assert.equal(doctor(config('kimi')).keychain, null);
});

test('doctor reads exit 36 from show-keychain-info as a locked keychain', onDarwin, (t) => {
  const { home } = sandbox(t);
  fakeSecurity(t, home, { lockStatus: 36 });
  const d = doctor(config());
  assert.equal(d.keychain.locked, true);
  assert.equal(d.keychain.lockProbeStatus, 36);
});
