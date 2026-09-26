import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';

import { config, UsageError, readCredentials, writeCredentials, deleteCredentials, saveProfile, loadProfile, profileExists, getActive, setActive, writeBackup, captureLive, switchTo, tokenExpiry, formatList, deleteProfileCmd, login, saveCurrent, exportProfile, importProfile, materializeRunDir, runProfile, saveBackRunDir, setPassphrase, storeEncrypted, setStoreEncryption, isEncrypted, main, tokenExpired, refreshKimiCredentials, AuthDeadError, fetchKimiUsage, parseKimiUsage, kimiWindowLabel, fetchKimiUserInfo, enrichKimiIdentity, readKimiConnection, decodeJwtPayload, kimiIdentityFromCredentials, kimiUsageCmd, usageCmd, formatCents, defaultTarget } from '../ccswitch.mjs';

// Mirrors the claude suite's sandbox: all state goes to a temp dir, including
// the kimi home (so the real ~/.kimi-code login is never touched).
export function sandbox(t) {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'kcswitch-test-'));
  process.env.KCSWITCH_HOME = path.join(home, 'profiles-home');
  process.env.KCSWITCH_KIMI_HOME = path.join(home, 'kimi-home');
  process.env.CCSWITCH_CACHE_DIR = path.join(home, 'cache');
  for (const v of ['KIMI_CODE_HOME', 'KIMI_CODE_BASE_URL', 'KIMI_CODE_OAUTH_HOST', 'KIMI_OAUTH_HOST']) {
    delete process.env[v];
  }
  t.after(() => fs.rmSync(home, { recursive: true, force: true }));
  return { home };
}

const b64url = (o) => Buffer.from(JSON.stringify(o)).toString('base64url');

export function fakeJwt(payload) {
  return `${b64url({ alg: 'none', typ: 'JWT' })}.${b64url(payload)}.sig`;
}

// A kimi credentials payload in the on-disk wire shape (snake_case, unix
// seconds). expiresIn is relative to now; pass a negative value for expired.
export function kimiCreds({ sub = 'user-1', expiresIn = 3600, accessToken, refreshToken = 'rt-1', ...rest } = {}) {
  const now = Math.floor(Date.now() / 1000);
  return JSON.stringify({
    access_token: accessToken ?? fakeJwt({ sub, iat: now, exp: now + expiresIn }),
    refresh_token: refreshToken,
    expires_at: now + expiresIn,
    scope: 'kimi-code',
    token_type: 'Bearer',
    expires_in: expiresIn,
    ...rest,
  });
}

const AI_CONFIG_TOML = `default_model = "kimi-code/k3"

[providers."managed:kimi-code"]
type = "kimi"
base_url = "https://api.kimi.ai/coding/v1"

[providers."managed:kimi-code".oauth]
storage = "file"
oauthHost = "https://auth.kimi.ai"

[models."kimi-code/k3"]
provider = "managed:kimi-code"
`;

function writeKimiConfig(cfg, text = AI_CONFIG_TOML) {
  fs.mkdirSync(cfg.kimiHome, { recursive: true });
  fs.writeFileSync(path.join(cfg.kimiHome, 'config.toml'), text);
}

function seedTwoKimiProfiles(cfg) {
  saveProfile(
    'alpha',
    { credentials: kimiCreds({ sub: 'u-alpha', refreshToken: 'rt-a' }), oauthAccount: { userId: 'u-alpha', nickname: 'Alpha' } },
    cfg,
  );
  saveProfile('beta', { credentials: kimiCreds({ sub: 'u-beta', refreshToken: 'rt-b' }), oauthAccount: { userId: 'u-beta' } }, cfg);
  // Live state = alpha, but with a rotated token the profile file doesn't have yet.
  writeCredentials(kimiCreds({ sub: 'u-alpha', refreshToken: 'rt-a2' }), cfg);
  setActive('alpha', cfg);
}

function captureLog(t) {
  const lines = [];
  const orig = console.log;
  console.log = (...a) => lines.push(a.join(' '));
  t.after(() => {
    console.log = orig;
  });
  return lines;
}

// --- config & identity ----------------------------------------------------------

test('config("kimi") derives kimi paths and picks up env overrides', (t) => {
  const { home } = sandbox(t);
  const cfg = config('kimi');
  assert.equal(cfg.target, 'kimi');
  assert.equal(cfg.prog, 'ccswitch kimi');
  assert.equal(cfg.home, path.join(home, 'profiles-home'));
  assert.equal(cfg.kimiHome, path.join(home, 'kimi-home'));
  assert.equal(cfg.credentialsFile, path.join(home, 'kimi-home', 'credentials', 'kimi-code.json'));
  assert.equal(cfg.kimiBin, 'kimi');
  assert.equal(cfg.bin, 'kimi');
  assert.deepEqual(cfg.loginArgs, ['login']);
  assert.equal(cfg.runEnvVar, 'KIMI_CODE_HOME');
  assert.equal(cfg.procName, 'kimi');
  assert.equal(cfg.keychainService, undefined); // no Keychain on the kimi side
  assert.equal(cfg.claudeJson, undefined); // no identity file either
  assert.equal(config().target, 'claude'); // defaultTarget without the kcswitch bin name
  assert.equal(defaultTarget(), 'claude');
});

test('kimi credential store round-trips a payload, file only', (t) => {
  sandbox(t);
  const cfg = config('kimi');
  assert.equal(readCredentials(cfg), null);
  writeCredentials(kimiCreds({ refreshToken: 'rt-1' }), cfg);
  assert.equal(fs.statSync(cfg.credentialsFile).mode & 0o777, 0o600);
  assert.equal(JSON.parse(readCredentials(cfg)).refresh_token, 'rt-1');
  writeCredentials(kimiCreds({ refreshToken: 'rt-2' }), cfg); // upsert
  assert.equal(JSON.parse(readCredentials(cfg)).refresh_token, 'rt-2');
  deleteCredentials(cfg);
  assert.equal(readCredentials(cfg), null);
  deleteCredentials(cfg); // deleting a missing entry must not throw
});

test('kimiIdentityFromCredentials decodes the JWT sub and tolerates garbage', () => {
  assert.deepEqual(kimiIdentityFromCredentials(kimiCreds({ sub: 'u-42' })), { userId: 'u-42' });
  assert.equal(kimiIdentityFromCredentials(JSON.stringify({ access_token: 'opaque-token' })), null);
  assert.equal(kimiIdentityFromCredentials('not json'), null);
  assert.equal(kimiIdentityFromCredentials(null), null);
  assert.equal(kimiIdentityFromCredentials(JSON.stringify({})), null);
  assert.deepEqual(decodeJwtPayload(fakeJwt({ sub: 'x', exp: 1 })), { sub: 'x', exp: 1 });
  assert.equal(decodeJwtPayload('a.b'), null); // undecodable payload half
});

test('readKimiConnection parses config.toml, env overrides win', (t) => {
  sandbox(t);
  const cfg = config('kimi');
  // No config.toml: mainland-cn defaults.
  assert.deepEqual(readKimiConnection(cfg), {
    baseUrl: 'https://api.kimi.com/coding/v1',
    oauthHost: 'https://auth.kimi.com',
  });
  // A persisted global login in config.toml:
  writeKimiConfig(cfg);
  assert.deepEqual(readKimiConnection(cfg), {
    baseUrl: 'https://api.kimi.ai/coding/v1',
    oauthHost: 'https://auth.kimi.ai',
  });
  // Env overrides outrank the persisted login, as in kimi itself:
  process.env.KIMI_CODE_BASE_URL = 'https://example.com/v1';
  process.env.KIMI_CODE_OAUTH_HOST = 'https://auth.example.com';
  t.after(() => {
    delete process.env.KIMI_CODE_BASE_URL;
    delete process.env.KIMI_CODE_OAUTH_HOST;
  });
  assert.deepEqual(readKimiConnection(cfg), { baseUrl: 'https://example.com/v1', oauthHost: 'https://auth.example.com' });
});

test('captureLive derives kimi identity from the token JWT', (t) => {
  sandbox(t);
  const cfg = config('kimi');
  t.after(() => deleteCredentials(cfg));
  assert.deepEqual(captureLive(cfg), { credentials: null, oauthAccount: null });
  writeCredentials(kimiCreds({ sub: 'u-live' }), cfg);
  const live = captureLive(cfg);
  assert.deepEqual(live.oauthAccount, { userId: 'u-live' });
});

// --- Profiles & switching --------------------------------------------------------

test('saveProfile keeps kimi display fields across bare token save-backs', (t) => {
  sandbox(t);
  const cfg = config('kimi');
  saveProfile(
    'work',
    { credentials: kimiCreds(), oauthAccount: { userId: 'user-1', nickname: 'shy', baseUrl: 'https://api.kimi.com/coding/v1' } },
    cfg,
  );
  // A token save-back carries only the JWT-derived identity:
  saveProfile('work', { credentials: kimiCreds({ refreshToken: 'rt-2' }), oauthAccount: { userId: 'user-1' } }, cfg);
  const p = loadProfile('work', cfg);
  assert.equal(JSON.parse(p.credentials).refresh_token, 'rt-2');
  assert.equal(p.oauthAccount.nickname, 'shy'); // display fields preserved
  assert.equal(p.oauthAccount.baseUrl, 'https://api.kimi.com/coding/v1');
  // A different account overwrites wholesale, no stale fields survive:
  saveProfile('work', { credentials: kimiCreds({ sub: 'user-2' }), oauthAccount: { userId: 'user-2' } }, cfg);
  assert.equal(loadProfile('work', cfg).oauthAccount.nickname, undefined);
});

test('switchTo swaps kimi credentials, saves back, backs up', (t) => {
  sandbox(t);
  const cfg = config('kimi');
  t.after(() => deleteCredentials(cfg));
  seedTwoKimiProfiles(cfg);

  switchTo('beta', {}, cfg);

  assert.equal(JSON.parse(readCredentials(cfg)).refresh_token, 'rt-b');
  assert.equal(getActive(cfg), 'beta');
  // The rotated live token was saved back into the outgoing profile, and the
  // merge kept its cached display fields:
  const alpha = loadProfile('alpha', cfg);
  assert.equal(JSON.parse(alpha.credentials).refresh_token, 'rt-a2');
  assert.equal(alpha.oauthAccount.nickname, 'Alpha');
  // A backup of the pre-switch live state exists:
  const backups = fs.readdirSync(path.join(cfg.home, 'backups'));
  assert.equal(backups.length, 1);
  const backup = JSON.parse(fs.readFileSync(path.join(cfg.home, 'backups', backups[0]), 'utf8'));
  assert.equal(JSON.parse(backup.credentials).refresh_token, 'rt-a2');
});

test('switchTo kimi skips save-back when the live token belongs to another account', (t) => {
  sandbox(t);
  const cfg = config('kimi');
  t.after(() => deleteCredentials(cfg));
  seedTwoKimiProfiles(cfg);
  // Live token is suddenly a stranger's, e.g. a manual `kimi login` outside ccswitch:
  writeCredentials(kimiCreds({ sub: 'u-stranger', refreshToken: 'rt-stranger' }), cfg);

  switchTo('beta', {}, cfg);

  assert.equal(JSON.parse(loadProfile('alpha', cfg).credentials).refresh_token, 'rt-a'); // untouched
  assert.equal(JSON.parse(readCredentials(cfg)).refresh_token, 'rt-b'); // switch still completed
  assert.equal(getActive(cfg), 'beta');
});

test('saveCurrent kimi snapshots the live login and records region endpoints', (t) => {
  sandbox(t);
  const cfg = config('kimi');
  t.after(() => deleteCredentials(cfg));
  writeKimiConfig(cfg); // persisted global (.ai) login
  writeCredentials(kimiCreds({ sub: 'u-1' }), cfg);

  saveCurrent('work', {}, cfg);

  const p = loadProfile('work', cfg);
  assert.equal(p.oauthAccount.userId, 'u-1');
  assert.equal(p.oauthAccount.baseUrl, 'https://api.kimi.ai/coding/v1');
  assert.equal(p.oauthAccount.oauthHost, 'https://auth.kimi.ai');
  assert.equal(getActive(cfg), 'work');
  assert.match(formatList(cfg), /work +u-1/);
});

test('saveCurrent kimi fails without live credentials', (t) => {
  sandbox(t);
  const cfg = config('kimi');
  assert.throws(() => saveCurrent('work', {}, cfg), /no live Kimi Code login found.*ccswitch kimi login/);
});

test('formatList kimi shows nickname, level and moved marker', (t) => {
  sandbox(t);
  const cfg = config('kimi');
  saveProfile(
    'work',
    { credentials: kimiCreds(), oauthAccount: { userId: 'u-1', nickname: 'Shy', userLevelName: 'Pro' } },
    cfg,
  );
  saveProfile(
    'gone',
    { credentials: kimiCreds({ sub: 'u-2' }), oauthAccount: { userId: 'u-2' }, movedAt: '2026-01-01T00:00:00.000Z' },
    cfg,
  );
  const out = formatList(cfg);
  assert.match(out, /name +account +level +token expires +saved/);
  assert.match(out, /work +Shy +Pro/);
  assert.match(out, /gone +u-2 +- +moved/);
});

// --- Guided login ---------------------------------------------------------------

export function fakeKimiBin(home, script) {
  const bin = path.join(home, 'fake-kimi');
  fs.writeFileSync(bin, `#!/bin/sh\n${script}`, { mode: 0o755 });
  process.env.KCSWITCH_KIMI_BIN = bin;
  return bin;
}

test('login kimi captures a fresh account, with region hints and /me fields', async (t) => {
  const { home } = sandbox(t);
  t.after(() => {
    delete process.env.KCSWITCH_KIMI_BIN;
    delete process.env.KCSWITCH_TEST_OUT;
  });
  process.env.KCSWITCH_TEST_OUT = path.join(home, 'argv.txt');
  const fresh = kimiCreds({ sub: 'u-second', refreshToken: 'rt-fresh' });
  fakeKimiBin(
    home,
    `printf '%s' "$*" > "$KCSWITCH_TEST_OUT"\n` +
      `mkdir -p "$KCSWITCH_KIMI_HOME/credentials"\n` +
      `printf '%s' '${fresh}' > "$KCSWITCH_KIMI_HOME/credentials/kimi-code.json"\n` +
      `cat > "$KCSWITCH_KIMI_HOME/config.toml" <<'EOF'\n${AI_CONFIG_TOML}EOF\n`,
  );
  const cfg = config('kimi');
  t.after(() => deleteCredentials(cfg));
  seedTwoKimiProfiles(cfg); // live = alpha (rotated), active = alpha

  const meCalls = [];
  const fetchImpl = async (url, init) => {
    meCalls.push(url);
    assert.equal(url, 'https://api.kimi.ai/coding/v1/me'); // base_url from the fresh config.toml
    assert.equal(init.headers.Authorization, `Bearer ${JSON.parse(fresh).access_token}`);
    return { ok: true, status: 200, json: async () => ({ user_id: 'u-second', nickname: 'Second', email: 's@x.com', user_level_name: 'Pro' }) };
  };
  await login('second', { fetchImpl }, cfg);

  assert.equal(fs.readFileSync(process.env.KCSWITCH_TEST_OUT, 'utf8'), 'login'); // kimi login was invoked
  assert.equal(getActive(cfg), 'second');
  const p = loadProfile('second', cfg);
  assert.equal(JSON.parse(p.credentials).refresh_token, 'rt-fresh');
  assert.deepEqual(p.oauthAccount, {
    userId: 'u-second',
    nickname: 'Second',
    email: 's@x.com',
    userLevelName: 'Pro',
    baseUrl: 'https://api.kimi.ai/coding/v1',
    oauthHost: 'https://auth.kimi.ai',
  });
  assert.equal(meCalls.length, 1);
  // Outgoing live creds were stashed back into the previously active profile:
  assert.equal(JSON.parse(loadProfile('alpha', cfg).credentials).refresh_token, 'rt-a2');
});

test('login kimi passes --region through to kimi login', async (t) => {
  const { home } = sandbox(t);
  t.after(() => {
    delete process.env.KCSWITCH_KIMI_BIN;
    delete process.env.KCSWITCH_TEST_OUT;
  });
  process.env.KCSWITCH_TEST_OUT = path.join(home, 'argv.txt');
  fakeKimiBin(
    home,
    `printf '%s' "$*" > "$KCSWITCH_TEST_OUT"\n` +
      `mkdir -p "$KCSWITCH_KIMI_HOME/credentials"\n` +
      `printf '%s' '${kimiCreds({ sub: 'u-r' })}' > "$KCSWITCH_KIMI_HOME/credentials/kimi-code.json"\n`,
  );
  const cfg = config('kimi');
  t.after(() => deleteCredentials(cfg));

  const fetchImpl = async () => ({ ok: false, status: 404, json: async () => ({}) }); // /me unavailable
  await login('roaming', { region: 'global', fetchImpl }, cfg);

  assert.equal(fs.readFileSync(process.env.KCSWITCH_TEST_OUT, 'utf8'), 'login --region global');
  assert.equal(getActive(cfg), 'roaming');
  // /me failed: identity is just the JWT user id plus config.toml defaults.
  assert.deepEqual(loadProfile('roaming', cfg).oauthAccount, {
    userId: 'u-r',
    baseUrl: 'https://api.kimi.com/coding/v1',
    oauthHost: 'https://auth.kimi.com',
  });
});

test('aborted kimi login restores the previous account', async (t) => {
  const { home } = sandbox(t);
  t.after(() => delete process.env.KCSWITCH_KIMI_BIN);
  fakeKimiBin(home, 'exit 0\n'); // user quit without logging in
  const cfg = config('kimi');
  t.after(() => deleteCredentials(cfg));
  seedTwoKimiProfiles(cfg);

  await assert.rejects(() => login('second', { fetchImpl: fetch }, cfg), /no new credentials/);

  assert.equal(JSON.parse(readCredentials(cfg)).refresh_token, 'rt-a2');
  assert.equal(getActive(cfg), 'alpha');
  assert.equal(profileExists('second', cfg), false);
});

test('login kimi restores previous state when the kimi binary fails to spawn', async (t) => {
  const { home } = sandbox(t);
  process.env.KCSWITCH_KIMI_BIN = path.join(home, 'does-not-exist');
  t.after(() => delete process.env.KCSWITCH_KIMI_BIN);
  const cfg = config('kimi');
  t.after(() => deleteCredentials(cfg));
  seedTwoKimiProfiles(cfg);

  await assert.rejects(() => login('second', {}, cfg), /could not launch/);

  assert.equal(JSON.parse(readCredentials(cfg)).refresh_token, 'rt-a2');
  assert.equal(getActive(cfg), 'alpha');
  assert.equal(profileExists('second', cfg), false);
});

test('--region is rejected for the claude backend', async (t) => {
  const { home } = sandbox(t);
  process.env.CCSWITCH_HOME = path.join(home, 'claude-home'); // keep the claude store hermetic too
  await assert.rejects(() => main(['login', 'x', '--region', 'global']), /--region.*only valid/);
  delete process.env.CCSWITCH_HOME;
});

// --- Isolated run (KIMI_CODE_HOME) ----------------------------------------------

test('materializeRunDir kimi writes credentials and seeds a minimal config.toml', (t) => {
  sandbox(t);
  const cfg = config('kimi');
  saveProfile(
    'work',
    {
      credentials: kimiCreds(),
      oauthAccount: { userId: 'user-1', baseUrl: 'https://api.kimi.ai/coding/v1', oauthHost: 'https://auth.kimi.ai' },
    },
    cfg,
  );
  const dir = materializeRunDir('work', cfg);
  assert.equal(dir, path.join(cfg.home, 'dirs', 'work'));
  assert.equal(fs.statSync(dir).mode & 0o777, 0o700);
  const credFile = path.join(dir, 'credentials', 'kimi-code.json');
  assert.equal(JSON.parse(fs.readFileSync(credFile, 'utf8')).refresh_token, 'rt-1');
  assert.equal(fs.statSync(credFile).mode & 0o777, 0o600);
  const conf = fs.readFileSync(path.join(dir, 'config.toml'), 'utf8');
  assert.match(conf, /base_url = "https:\/\/api\.kimi\.ai\/coding\/v1"/);
  assert.match(conf, /oauthHost = "https:\/\/auth\.kimi\.ai"/);
  assert.match(conf, /storage = "file"/);
  // A user's own config.toml in the run dir is preserved across re-materialize:
  fs.writeFileSync(path.join(dir, 'config.toml'), '# customized\n');
  materializeRunDir('work', cfg);
  assert.equal(fs.readFileSync(path.join(dir, 'config.toml'), 'utf8'), '# customized\n');
});

test('runProfile kimi launches with KIMI_CODE_HOME and saves back rotated tokens', (t) => {
  const { home } = sandbox(t);
  t.after(() => {
    delete process.env.KCSWITCH_KIMI_BIN;
    delete process.env.KCSWITCH_TEST_OUT;
  });
  process.env.KCSWITCH_TEST_OUT = path.join(home, 'out.txt');
  // The fake session refreshes its token, as kimi does mid-session.
  fakeKimiBin(
    home,
    `printf '%s|%s' "$KIMI_CODE_HOME" "$*" > "$KCSWITCH_TEST_OUT"\n` +
      `printf '%s' '${kimiCreds({ sub: 'user-1', refreshToken: 'rt-rotated' })}' > "$KIMI_CODE_HOME/credentials/kimi-code.json"\n`,
  );
  const cfg = config('kimi');
  saveProfile('work', { credentials: kimiCreds({ refreshToken: 'rt-1' }), oauthAccount: { userId: 'user-1' } }, cfg);

  const code = runProfile('work', ['-p', 'hi'], cfg);

  assert.equal(code, 0);
  const [dir, argv] = fs.readFileSync(process.env.KCSWITCH_TEST_OUT, 'utf8').split('|');
  assert.equal(dir, path.join(cfg.home, 'dirs', 'work'));
  assert.equal(argv, '-p hi');
  assert.equal(JSON.parse(loadProfile('work', cfg).credentials).refresh_token, 'rt-rotated');
});

test('saveBackRunDir kimi skips a mismatched account and an empty run dir', (t) => {
  sandbox(t);
  const cfg = config('kimi');
  saveProfile('work', { credentials: kimiCreds({ refreshToken: 'rt-1' }), oauthAccount: { userId: 'user-1' } }, cfg);
  const dir = materializeRunDir('work', cfg);
  // A different account logged in inside the run session:
  fs.writeFileSync(path.join(dir, 'credentials', 'kimi-code.json'), kimiCreds({ sub: 'user-2', refreshToken: 'rt-x' }));
  saveBackRunDir('work', dir, cfg);
  assert.equal(JSON.parse(loadProfile('work', cfg).credentials).refresh_token, 'rt-1'); // untouched
  // Missing credentials file: no-op.
  fs.rmSync(path.join(dir, 'credentials', 'kimi-code.json'));
  saveBackRunDir('work', dir, cfg);
  assert.equal(JSON.parse(loadProfile('work', cfg).credentials).refresh_token, 'rt-1');
});

// --- Token refresh & usage --------------------------------------------------------

test('tokenExpired/tokenExpiry understand the kimi wire shape', () => {
  assert.equal(tokenExpired(kimiCreds({ expiresIn: 3600 })), false);
  assert.equal(tokenExpired(kimiCreds({ expiresIn: 120 })), true); // inside the 5-minute margin
  assert.equal(tokenExpired(kimiCreds({ expiresIn: -10 })), true);
  assert.match(tokenExpiry(kimiCreds({})), /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/);
  assert.equal(tokenExpiry(JSON.stringify({ access_token: 'x' })), '-');
});

test('refreshKimiCredentials posts the refresh form to the oauth host and rotates', async () => {
  const calls = [];
  const fetchImpl = async (url, init) => {
    calls.push({ url, init });
    return {
      ok: true,
      status: 200,
      json: async () => ({ access_token: fakeJwt({ sub: 'user-1' }), refresh_token: 'rt-new', expires_in: 900, scope: 'kimi-code', token_type: 'Bearer' }),
    };
  };
  const out = JSON.parse(await refreshKimiCredentials(kimiCreds({ refreshToken: 'rt-old' }), fetchImpl));
  assert.equal(calls[0].url, 'https://auth.kimi.com/api/oauth/token');
  assert.equal(calls[0].init.method, 'POST');
  const form = new URLSearchParams(calls[0].init.body);
  assert.equal(form.get('client_id'), '17e5f671-d194-4dfb-9706-5516cb48c098');
  assert.equal(form.get('grant_type'), 'refresh_token');
  assert.equal(form.get('refresh_token'), 'rt-old');
  assert.equal(out.refresh_token, 'rt-new');
  assert.equal(out.expires_in, 900);
  assert.ok(out.expires_at > Math.floor(Date.now() / 1000));

  // A persisted global login refreshes against auth.kimi.ai instead:
  await refreshKimiCredentials(kimiCreds({}), fetchImpl, { oauthHost: 'https://auth.kimi.ai' });
  assert.equal(calls[1].url, 'https://auth.kimi.ai/api/oauth/token');

  // A missing refresh_token in the response keeps the current one:
  const kept = JSON.parse(
    await refreshKimiCredentials(kimiCreds({ refreshToken: 'rt-keep' }), async () => ({
      ok: true,
      status: 200,
      json: async () => ({ access_token: 'at-x', expires_in: 900 }),
    })),
  );
  assert.equal(kept.refresh_token, 'rt-keep');
});

test('refreshKimiCredentials maps 401/403/invalid_grant to AuthDeadError, 500 to plain Error', async () => {
  const dead = (status, body = {}) => async () => ({ ok: false, status, json: async () => body });
  await assert.rejects(() => refreshKimiCredentials(kimiCreds({}), dead(401)), AuthDeadError);
  await assert.rejects(() => refreshKimiCredentials(kimiCreds({}), dead(403)), AuthDeadError);
  await assert.rejects(() => refreshKimiCredentials(kimiCreds({}), dead(400, { error: 'invalid_grant' })), AuthDeadError);
  await assert.rejects(() => refreshKimiCredentials(kimiCreds({}), dead(400, { error: 'bad_request' })), /token refresh failed/);
  await assert.rejects(() => refreshKimiCredentials(kimiCreds({}), dead(500)), /token refresh failed/);
  await assert.rejects(() => refreshKimiCredentials(JSON.stringify({ access_token: 'x' }), fetch), AuthDeadError);
});

test('parseKimiUsage parses the weekly summary, scoped limits and the booster wallet', () => {
  const usage = parseKimiUsage({
    usage: { used: 41, limit: 100, resetTime: '2026-09-15T00:00:00Z' },
    limits: [
      {
        name: 'RATE_LIMIT',
        window: { duration: 5, timeUnit: 'TIME_UNIT_HOUR' },
        detail: { used: 3, limit: 50, resetTime: '2026-09-11T22:00:00Z' },
      },
      { name: 'broken', window: null, detail: {} }, // no used/limit: dropped
    ],
    boosterWallet: {
      balance: { type: 'BOOSTER', amount: 950000000, amountLeft: 475000000 },
      monthlyChargeLimitEnabled: false,
    },
  });
  assert.equal(usage.summary.label, '1w'); // a windowless summary is the weekly quota
  assert.equal(usage.summary.utilization, 41);
  assert.equal(usage.summary.resetsAt, '2026-09-15T00:00:00Z');
  assert.equal(usage.limits.length, 1);
  assert.equal(usage.limits[0].name, 'RATE_LIMIT');
  assert.equal(usage.limits[0].label, '5h');
  assert.equal(usage.limits[0].utilization, 6);
  assert.deepEqual(usage.booster, { balanceCents: 475, totalCents: 950, currency: 'USD' });

  assert.deepEqual(parseKimiUsage(null), { summary: null, limits: [], booster: null });
  assert.deepEqual(parseKimiUsage({ usage: {}, boosterWallet: { balance: { type: 'OTHER', amount: 1 } } }), {
    summary: null,
    limits: [],
    booster: null,
  });
  assert.equal(kimiWindowLabel({ duration: 300, unit: 'minute' }), '5h'); // minutes collapse to hours
  assert.equal(kimiWindowLabel({ duration: 7, unit: 'day' }), '7d');
  assert.equal(kimiWindowLabel(null), null);
  assert.equal(formatCents(475, 'USD'), '$4.75');
  assert.equal(formatCents(950, 'CNY'), 'CNY 9.50');
});

test('fetchKimiUsage sends the bearer token and maps 401 to AuthDeadError', async () => {
  const token = fakeJwt({ sub: 'user-1' });
  const calls = [];
  const fetchImpl = async (url, init) => {
    calls.push({ url, init });
    return { ok: true, status: 200, json: async () => ({ usage: { used: 1, limit: 4, resetTime: null } }) };
  };
  const usage = await fetchKimiUsage(kimiCreds({ accessToken: token }), fetchImpl);
  assert.equal(calls[0].url, 'https://api.kimi.com/coding/v1/usages');
  assert.equal(calls[0].init.headers.Authorization, `Bearer ${token}`);
  assert.equal(usage.summary.utilization, 25);

  await fetchKimiUsage(kimiCreds({}), fetchImpl, { baseUrl: 'https://api.kimi.ai/coding/v1/' });
  assert.equal(calls[1].url, 'https://api.kimi.ai/coding/v1/usages'); // trailing slashes collapse

  await assert.rejects(
    () => fetchKimiUsage(kimiCreds({}), async () => ({ ok: false, status: 401, json: async () => ({}) })),
    AuthDeadError,
  );
  await assert.rejects(
    () => fetchKimiUsage(kimiCreds({}), async () => ({ ok: false, status: 500, json: async () => ({}) })),
    /usage request failed/,
  );
  await assert.rejects(() => fetchKimiUsage(JSON.stringify({ refresh_token: 'x' }), fetch), AuthDeadError);
});

test('fetchKimiUserInfo parses snake_case and degrades to null', async () => {
  const ok = await fetchKimiUserInfo('https://api.kimi.com/coding/v1', 'tok', async (url, init) => {
    assert.equal(url, 'https://api.kimi.com/coding/v1/me');
    assert.equal(init.headers.Authorization, 'Bearer tok');
    return { ok: true, status: 200, json: async () => ({ user_id: 'u-1', nickname: 'Shy', email: 's@x.com', user_level_name: 'Pro' }) };
  });
  assert.deepEqual(ok, { userId: 'u-1', nickname: 'Shy', email: 's@x.com', userLevelName: 'Pro' });
  assert.equal(await fetchKimiUserInfo('https://x', 'tok', async () => ({ ok: false, status: 401 })), null);
  assert.equal(await fetchKimiUserInfo('https://x', 'tok', async () => ({ ok: true, status: 200, json: async () => ({}) })), null);
  assert.equal(
    await fetchKimiUserInfo('https://x', 'tok', async () => {
      throw new Error('network down');
    }),
    null,
  );
});

test('enrichKimiIdentity merges connection hints and /me fields, never throws', async (t) => {
  sandbox(t);
  const cfg = config('kimi');
  writeKimiConfig(cfg); // .ai endpoints
  const out = await enrichKimiIdentity(kimiCreds({ sub: 'u-1' }), { userId: 'u-1' }, cfg, async () => ({
    ok: true,
    status: 200,
    json: async () => ({ user_id: 'u-1', nickname: 'Shy' }),
  }));
  assert.deepEqual(out, {
    userId: 'u-1',
    nickname: 'Shy',
    baseUrl: 'https://api.kimi.ai/coding/v1',
    oauthHost: 'https://auth.kimi.ai',
  });
  // /me down: still the connection hints plus the JWT identity.
  const degraded = await enrichKimiIdentity(kimiCreds({ sub: 'u-1' }), { userId: 'u-1' }, cfg, async () => {
    throw new Error('down');
  });
  assert.deepEqual(degraded, { userId: 'u-1', baseUrl: 'https://api.kimi.ai/coding/v1', oauthHost: 'https://auth.kimi.ai' });
  // Garbage credentials: no identity, but still the hints.
  assert.deepEqual(await enrichKimiIdentity('not json', null, cfg, fetch), {
    baseUrl: 'https://api.kimi.ai/coding/v1',
    oauthHost: 'https://auth.kimi.ai',
  });
});

test('kimiUsageCmd refreshes expired tokens, persists before the usage call, enriches from /me', async (t) => {
  sandbox(t);
  const cfg = config('kimi');
  saveProfile('work', { credentials: kimiCreds({ sub: 'u-1', expiresIn: -10, refreshToken: 'rt-old' }), oauthAccount: { userId: 'u-1' } }, cfg);
  const newToken = fakeJwt({ sub: 'u-1' });
  let persistedAtUsageTime = null;
  const fetchImpl = async (url, init) => {
    if (url.includes('/api/oauth/token')) {
      return { ok: true, status: 200, json: async () => ({ access_token: newToken, refresh_token: 'rt-new', expires_in: 900 }) };
    }
    if (url.endsWith('/usages')) {
      persistedAtUsageTime = JSON.parse(loadProfile('work', cfg).credentials).access_token;
      assert.equal(init.headers.Authorization, `Bearer ${newToken}`);
      return {
        ok: true,
        status: 200,
        json: async () => ({
          usage: { used: 63, limit: 100, resetTime: new Date(Date.now() + 86400000).toISOString() },
          limits: [
            {
              name: 'RATE_LIMIT',
              window: { duration: 5, timeUnit: 'TIME_UNIT_HOUR' },
              detail: { used: 10, limit: 50, resetTime: new Date(Date.now() + 3600000).toISOString() },
            },
          ],
          boosterWallet: { balance: { type: 'BOOSTER', amount: 950000000, amountLeft: 475000000 } },
        }),
      };
    }
    if (url.endsWith('/me')) {
      return { ok: true, status: 200, json: async () => ({ user_id: 'u-1', nickname: 'Shy', user_level_name: 'Pro' }) };
    }
    throw new Error(`unexpected url ${url}`);
  };
  const lines = captureLog(t);
  assert.equal(await usageCmd({}, cfg, fetchImpl), 0); // routes to the kimi implementation
  assert.equal(persistedAtUsageTime, newToken); // persist-before-use
  const out = lines.join('\n');
  assert.match(out, /name +account +week +resets +limits +booster +status/);
  assert.match(out, /63%/);
  assert.match(out, /5h .*20%/);
  assert.match(out, /\$4\.75/);
  assert.match(out, /✓/);
  // /me enrichment landed in the profile and the rendered row:
  assert.equal(loadProfile('work', cfg).oauthAccount.nickname, 'Shy');
  assert.match(out, /work +Shy/);
});

test('kimiUsageCmd uses live credentials for the active profile without refreshing', async (t) => {
  sandbox(t);
  const cfg = config('kimi');
  saveProfile('work', { credentials: kimiCreds({ sub: 'u-1', expiresIn: -10 }), oauthAccount: { userId: 'u-1', nickname: 'Shy' } }, cfg);
  setActive('work', cfg);
  writeCredentials(kimiCreds({ sub: 'u-1', refreshToken: 'rt-live' }), cfg); // live pair is fresh
  const urls = [];
  const fetchImpl = async (url, init) => {
    urls.push(url);
    if (url.endsWith('/usages')) return { ok: true, status: 200, json: async () => ({}) };
    if (url.endsWith('/me')) return { ok: false, status: 404 };
    throw new Error(`unexpected url ${url}`);
  };
  captureLog(t);
  assert.equal(await usageCmd({}, cfg, fetchImpl), 0);
  assert.deepEqual(urls.filter((u) => u.includes('/api/oauth/token')), []); // no refresh
  assert.deepEqual(urls, ['https://api.kimi.com/coding/v1/usages', 'https://api.kimi.com/coding/v1/me']);
});

test('kimiUsageCmd fails soft per profile and only exits 1 when all fail', async (t) => {
  sandbox(t);
  const cfg = config('kimi');
  saveProfile('good', { credentials: kimiCreds({ sub: 'u-g' }), oauthAccount: { userId: 'u-g', nickname: 'G' } }, cfg);
  saveProfile(
    'dead',
    { credentials: kimiCreds({ sub: 'u-d', expiresIn: -10, refreshToken: 'rt-dead' }), oauthAccount: { userId: 'u-d' } },
    cfg,
  );
  const fetchImpl = async (url) => {
    if (url.includes('/api/oauth/token')) return { ok: false, status: 400, json: async () => ({ error: 'invalid_grant' }) };
    if (url.endsWith('/usages')) return { ok: true, status: 200, json: async () => ({ usage: { used: 1, limit: 10 } }) };
    return { ok: false, status: 404 };
  };
  const lines = captureLog(t);
  assert.equal(await usageCmd({}, cfg, fetchImpl), 0);
  assert.match(lines.join('\n'), /✗/);
  saveProfile('gone', { credentials: kimiCreds({ sub: 'u-x' }), oauthAccount: { userId: 'u-x' }, movedAt: new Date().toISOString() }, cfg);
  lines.length = 0;
  assert.equal(await usageCmd({}, cfg, fetchImpl), 0);
  assert.match(lines.join('\n'), /→/);
});

test('kimiUsageCmd shows the last known usage on 429, in its own cache namespace', async (t) => {
  sandbox(t);
  const cfg = config('kimi');
  saveProfile('work', { credentials: kimiCreds({ sub: 'u-1' }), oauthAccount: { userId: 'u-1', nickname: 'Shy' } }, cfg);
  let status = 200;
  const fetchImpl = async (url) => {
    if (url.endsWith('/usages')) {
      return status === 200
        ? { ok: true, status, json: async () => ({ usage: { used: 3, limit: 10 } }) }
        : { ok: false, status, json: async () => ({}) };
    }
    return { ok: false, status: 404 };
  };
  process.env.NO_COLOR = '1';
  t.after(() => delete process.env.NO_COLOR);
  const lines = captureLog(t);
  assert.equal(await usageCmd({}, cfg, fetchImpl), 0);
  assert.notEqual(cfg.usageCacheDir, config('claude').usageCacheDir);
  status = 429;
  lines.length = 0;
  assert.equal(await usageCmd({}, cfg, fetchImpl), 0);
  assert.match(lines.join('\n'), /30%/);
  assert.match(lines.join('\n'), /◷ <1m/);
});

test('kimiUsageCmd --dry-run touches the network never', async (t) => {
  sandbox(t);
  const cfg = config('kimi');
  saveProfile('work', { credentials: kimiCreds({}), oauthAccount: { userId: 'u-1' } }, cfg);
  const lines = captureLog(t);
  assert.equal(
    await usageCmd({ dryRun: true }, cfg, async () => {
      throw new Error('network hit');
    }),
    0,
  );
  assert.match(lines.join('\n'), /\[dry-run\] would query usage for "work"/);
});

// --- Transfer & encryption (shared machinery, kimi store) -------------------------

test('export/import round-trips a kimi profile with its region hints', (t) => {
  const { home } = sandbox(t);
  const cfg = config('kimi');
  saveProfile(
    'work',
    { credentials: kimiCreds({ refreshToken: 'rt-w' }), oauthAccount: { userId: 'u-1', nickname: 'Shy', baseUrl: 'https://api.kimi.ai/coding/v1' } },
    cfg,
  );
  const file = path.join(home, 'w.json');
  exportProfile('work', file, {}, cfg);

  process.env.KCSWITCH_HOME = path.join(home, 'second-home');
  const cfg2 = config('kimi');
  importProfile('work', file, {}, cfg2);
  const p = loadProfile('work', cfg2);
  assert.equal(JSON.parse(p.credentials).refresh_token, 'rt-w');
  assert.equal(p.oauthAccount.nickname, 'Shy');
  assert.equal(p.oauthAccount.baseUrl, 'https://api.kimi.ai/coding/v1');
});

test('import keeps the live kimi chain when the file matches the live login', (t) => {
  const { home } = sandbox(t);
  const cfg = config('kimi');
  t.after(() => deleteCredentials(cfg));
  writeCredentials(kimiCreds({ sub: 'u-1', refreshToken: 'rt-live' }), cfg);
  const file = path.join(home, 'w.json');
  fs.writeFileSync(
    file,
    JSON.stringify({ credentials: kimiCreds({ sub: 'u-1', refreshToken: 'rt-remote' }), oauthAccount: { userId: 'u-1' } }),
  );
  importProfile('work', file, {}, cfg);
  assert.equal(JSON.parse(loadProfile('work', cfg).credentials).refresh_token, 'rt-live');
});

test('the kimi store encrypts and decrypts like the claude one', (t) => {
  sandbox(t);
  t.after(() => setPassphrase(null));
  const cfg = config('kimi');
  saveProfile('work', { credentials: kimiCreds({ refreshToken: 'rt-secret' }), oauthAccount: { userId: 'u-1', nickname: 'Shy' } }, cfg);
  writeBackup('test', { credentials: kimiCreds({ refreshToken: 'rt-backup' }) }, cfg);
  setPassphrase('pw');

  setStoreEncryption(true, cfg);

  assert.equal(storeEncrypted(cfg), true);
  const raw = fs.readFileSync(path.join(cfg.home, 'profiles', 'work.json'), 'utf8');
  assert.equal(isEncrypted(raw), true);
  assert.doesNotMatch(raw, /rt-secret/);
  assert.equal(JSON.parse(loadProfile('work', cfg).credentials).refresh_token, 'rt-secret');
  assert.match(formatList(cfg), /work +Shy/);

  setStoreEncryption(false, cfg);
  assert.match(fs.readFileSync(path.join(cfg.home, 'profiles', 'work.json'), 'utf8'), /rt-secret/);
});

// --- CLI routing ------------------------------------------------------------------

const CLI = new URL('../ccswitch.mjs', import.meta.url).pathname;

function runCli(args, env = {}) {
  return spawnSync(process.execPath, [CLI, ...args], {
    encoding: 'utf8',
    env: { ...process.env, ...env },
  });
}

function kimiEnv() {
  return {
    KCSWITCH_HOME: process.env.KCSWITCH_HOME,
    KCSWITCH_KIMI_HOME: process.env.KCSWITCH_KIMI_HOME,
  };
}

test('cli: kimi prefix routes list, switch and usage dry-run to the kimi store', (t) => {
  sandbox(t);
  const cfg = config('kimi');
  saveProfile('work', { credentials: kimiCreds({}), oauthAccount: { userId: 'u-1', nickname: 'Shy' } }, cfg);
  saveProfile('other', { credentials: kimiCreds({ sub: 'u-2' }), oauthAccount: { userId: 'u-2' } }, cfg);
  setActive('other', cfg);

  const list = runCli(['kimi', 'list'], kimiEnv());
  assert.equal(list.status, 0, list.stderr);
  assert.match(list.stdout, /\* +other +u-2/);
  assert.match(list.stdout, /work +Shy/);

  const sw = runCli(['kimi', 'work'], kimiEnv());
  assert.equal(sw.status, 0, sw.stderr);
  assert.match(sw.stdout, /switched to "work" \(Shy\)/);
  assert.equal(JSON.parse(readCredentials(cfg)).refresh_token, 'rt-1');

  const dry = runCli(['kimi', '--dry-run', 'usage'], kimiEnv());
  assert.equal(dry.status, 0, dry.stderr);
  assert.match(dry.stdout, /\[dry-run\] would query usage for "work"/);

  // 'work' is active now, so delete the other profile instead:
  const del = runCli(['kimi', 'delete', 'other', '--force'], kimiEnv());
  assert.equal(del.status, 0, del.stderr);
  assert.equal(profileExists('other', cfg), false);
  assert.equal(profileExists('work', cfg), true);
});

test('cli: kimi --help documents the kimi command set', (t) => {
  sandbox(t);
  const r = runCli(['kimi', '--help'], kimiEnv());
  assert.equal(r.status, 0);
  assert.match(r.stdout, /ccswitch kimi login/);
  assert.match(r.stdout, /KCSWITCH_\*/);
});

test('cli: the kcswitch bin name makes kimi the default target', (t) => {
  const { home } = sandbox(t);
  const cfg = config('kimi');
  saveProfile('work', { credentials: kimiCreds({}), oauthAccount: { userId: 'u-1', nickname: 'Shy' } }, cfg);
  const alias = path.join(home, 'kcswitch');
  fs.copyFileSync(CLI, alias);
  fs.chmodSync(alias, 0o755);
  const r = spawnSync(alias, ['list'], { encoding: 'utf8', env: { ...process.env, ...kimiEnv() } });
  assert.equal(r.status, 0, r.stderr);
  assert.match(r.stdout, /work +Shy/); // the kimi store, without any "kimi" argument
});

// Both bins are the same script; only argv[0] differs, so every message the
// kimi bin prints has to name itself rather than its sibling.
function kcBin(home) {
  const alias = path.join(home, 'kcswitch');
  fs.copyFileSync(CLI, alias);
  fs.chmodSync(alias, 0o755);
  return alias;
}

test('cli: kcswitch names itself in errors, not ccswitch', (t) => {
  const { home } = sandbox(t);
  const r = spawnSync(kcBin(home), ['Not-A-Name!'], { encoding: 'utf8', env: { ...process.env, ...kimiEnv() } });
  assert.equal(r.status, 1);
  assert.match(r.stderr, /^kcswitch: unknown command/);
  assert.match(r.stderr, /see kcswitch --help/);
  assert.doesNotMatch(r.stderr, /ccswitch/);
});

test('cli: kcswitch --help spells its own commands without the kimi prefix', (t) => {
  const { home } = sandbox(t);
  const r = spawnSync(kcBin(home), ['--help'], { encoding: 'utf8', env: { ...process.env, ...kimiEnv() } });
  assert.equal(r.status, 0, r.stderr);
  assert.match(r.stdout, /usage: kcswitch \[--dry-run\]/);
  assert.match(r.stdout, /\n  kcswitch login <name> /);
  assert.match(r.stdout, /kcswitch encrypt/);
  assert.doesNotMatch(r.stdout, /\n  ccswitch /); // no command line addressed to the other bin
});

test('cli: ccswitch kimi --help keeps the prefix in every command it prints', (t) => {
  sandbox(t);
  const r = runCli(['kimi', '--help'], kimiEnv());
  assert.equal(r.status, 0, r.stderr);
  assert.match(r.stdout, /usage: ccswitch kimi \[--dry-run\]/);
  assert.match(r.stdout, /\n  ccswitch kimi login <name> /);
});

test('cli: a kimi usage error reached through the prefix is prefixed ccswitch', (t) => {
  sandbox(t);
  const r = runCli(['kimi', 'Not-A-Name!'], kimiEnv());
  assert.equal(r.status, 1);
  assert.match(r.stderr, /^ccswitch: unknown command/);
});
