// Candidate chains: when two machines both refreshed the same profile, sync
// keeps both and the next use probes them newest-first to find the live one.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

import {
  config,
  getActive,
  loadProfile,
  main,
  readCredentials,
  resolveAlternates,
  saveProfile,
  setActive,
  usageCmd,
  writeCredentials,
} from '../ccswitch.mjs';

function sandbox(t) {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'ccswitch-alt-'));
  process.env.CCSWITCH_HOME = path.join(home, 'profiles-home');
  process.env.CCSWITCH_CLAUDE_JSON = path.join(home, 'claude.json');
  process.env.CCSWITCH_CACHE_DIR = path.join(home, 'cache');
  process.env.CCSWITCH_CREDENTIALS_FILE = path.join(home, 'credentials.json');
  process.env.CCSWITCH_KEYCHAIN_SERVICE = `ccswitch-test-${process.pid}-${Math.random().toString(36).slice(2)}`;
  process.env.KCSWITCH_HOME = path.join(home, 'kimi-profiles');
  process.env.KCSWITCH_KIMI_HOME = path.join(home, 'kimi-home');
  t.after(() => fs.rmSync(home, { recursive: true, force: true }));
  return { home };
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

const FUTURE = Date.now() + 3600_000; // fixed so equal tags yield byte-identical credentials
const creds = (tag, { expiresAt = FUTURE } = {}) =>
  JSON.stringify({ claudeAiOauth: { accessToken: `at-${tag}`, refreshToken: `rt-${tag}`, expiresAt } });
const tokenOf = (init) => init?.headers?.Authorization?.replace('Bearer ', '');

// A fake network whose behaviour is a table keyed by token: usage answers per
// access token, refresh answers per refresh token. Records every call.
function fakeNet({ usage = {}, refresh = {} } = {}) {
  const calls = [];
  const fetchImpl = async (url, init = {}) => {
    if (url.includes('/oauth/usage')) {
      const tok = tokenOf(init);
      calls.push(['usage', tok]);
      const status = usage[tok] ?? 401;
      if (status === 'boom') throw new Error('network down');
      return { ok: status === 200, status, json: async () => ({ five_hour: { utilization: 10, resets_at: null } }) };
    }
    if (url.includes('/oauth/token')) {
      const rt = JSON.parse(init.body).refresh_token;
      calls.push(['refresh', rt]);
      const r = refresh[rt];
      if (r === 'boom') throw new Error('network down');
      if (!r) return { ok: false, status: 400, json: async () => ({}) };
      return { ok: true, status: 200, json: async () => ({ access_token: r.access, refresh_token: r.refresh, expires_in: 3600 }) };
    }
    throw new Error(`unexpected url ${url}`);
  };
  return { fetchImpl, calls };
}

const T_OLD = '2026-01-01T00:00:00.000Z';
const T_NEW = '2026-01-02T00:00:00.000Z';

function conflicted(cfg, { newest = creds('new'), older = creds('old') } = {}) {
  saveProfile(
    'work',
    {
      credentials: newest,
      oauthAccount: { emailAddress: 'w@example.com', accountUuid: 'u1' },
      savedAt: T_NEW,
      machine: 'desk-1',
      alternates: [{ credentials: older, savedAt: T_OLD, machine: 'mbp-2' }],
    },
    cfg,
  );
  return loadProfile('work', cfg);
}

test('saveProfile persists machine and alternates, and drops alternates when absent', (t) => {
  sandbox(t);
  const cfg = config();
  const p = conflicted(cfg);
  assert.equal(p.machine, 'desk-1');
  assert.equal(p.alternates.length, 1);
  assert.equal(p.alternates[0].credentials, creds('old'));
  saveProfile('work', { credentials: p.credentials, oauthAccount: p.oauthAccount, machine: 'desk-1' }, cfg);
  assert.equal(loadProfile('work', cfg).alternates, undefined);
  saveProfile('work', { credentials: p.credentials, oauthAccount: p.oauthAccount, alternates: [] }, cfg);
  assert.equal(loadProfile('work', cfg).alternates, undefined);
});

test('resolveAlternates leaves a profile without alternates alone and makes no calls', async (t) => {
  sandbox(t);
  const cfg = config();
  saveProfile('work', { credentials: creds('only'), oauthAccount: null }, cfg);
  const net = fakeNet();
  const r = await resolveAlternates('work', loadProfile('work', cfg), cfg, net.fetchImpl);
  assert.equal(r.resolved, false);
  assert.equal(r.profile.credentials, creds('only'));
  assert.deepEqual(net.calls, []);
});

test('resolveAlternates keeps the newest chain when it answers, never touching the older one', async (t) => {
  sandbox(t);
  const cfg = config();
  const profile = conflicted(cfg);
  const net = fakeNet({ usage: { 'at-new': 200 } });
  const errs = captureErr(t);
  const r = await resolveAlternates('work', profile, cfg, net.fetchImpl);
  assert.equal(r.resolved, true);
  assert.equal(r.profile.credentials, creds('new'));
  assert.equal(r.profile.alternates, undefined);
  assert.deepEqual(net.calls, [['usage', 'at-new']]);
  const saved = loadProfile('work', cfg);
  assert.equal(saved.alternates, undefined);
  assert.equal(saved.credentials, creds('new'));
  assert.ok(fs.readdirSync(path.join(cfg.home, 'backups')).some((f) => f.includes('resolve-work')));
  assert.match(errs.join('\n'), /"work".*desk-1.*mbp-2.*desk-1/);
});

test('resolveAlternates falls through to the older chain when the newest is dead, then stops', async (t) => {
  sandbox(t);
  const cfg = config();
  const profile = conflicted(cfg);
  const net = fakeNet({ usage: { 'at-new': 401, 'at-old': 200 }, refresh: {} });
  captureErr(t);
  const r = await resolveAlternates('work', profile, cfg, net.fetchImpl);
  assert.equal(r.profile.credentials, creds('old'));
  assert.deepEqual(net.calls, [['usage', 'at-new'], ['refresh', 'rt-new'], ['usage', 'at-old']]);
  assert.equal(loadProfile('work', cfg).alternates, undefined);
});

test('resolveAlternates refreshes an expired newest chain and persists the rotated tokens', async (t) => {
  sandbox(t);
  const cfg = config();
  const profile = conflicted(cfg, { newest: creds('new', { expiresAt: Date.now() - 1000 }) });
  const net = fakeNet({ refresh: { 'rt-new': { access: 'at-new2', refresh: 'rt-new2' } } });
  captureErr(t);
  const r = await resolveAlternates('work', profile, cfg, net.fetchImpl);
  assert.deepEqual(net.calls, [['refresh', 'rt-new']]);
  const saved = JSON.parse(loadProfile('work', cfg).credentials).claudeAiOauth;
  assert.equal(saved.accessToken, 'at-new2');
  assert.equal(saved.refreshToken, 'rt-new2');
  assert.equal(r.profile.alternates, undefined);
});

test('resolveAlternates treats a 429 on usage as proof the chain is live', async (t) => {
  sandbox(t);
  const cfg = config();
  const profile = conflicted(cfg);
  const net = fakeNet({ usage: { 'at-new': 429 } });
  captureErr(t);
  const r = await resolveAlternates('work', profile, cfg, net.fetchImpl);
  assert.equal(r.profile.credentials, creds('new'));
  assert.deepEqual(net.calls, [['usage', 'at-new']]);
});

test('resolveAlternates drops every candidate when all are dead and says so', async (t) => {
  sandbox(t);
  const cfg = config();
  const profile = conflicted(cfg);
  const net = fakeNet();
  const errs = captureErr(t);
  const r = await resolveAlternates('work', profile, cfg, net.fetchImpl);
  assert.equal(r.resolved, true);
  assert.equal(r.live, false);
  assert.equal(r.profile.credentials, creds('new'));
  assert.equal(loadProfile('work', cfg).alternates, undefined);
  assert.match(errs.join('\n'), /logged out/);
});

test('resolveAlternates keeps everything when the network fails mid-probe', async (t) => {
  sandbox(t);
  const cfg = config();
  const profile = conflicted(cfg);
  const net = fakeNet({ usage: { 'at-new': 'boom' } });
  const errs = captureErr(t);
  const r = await resolveAlternates('work', profile, cfg, net.fetchImpl);
  assert.equal(r.resolved, false);
  assert.equal(loadProfile('work', cfg).alternates.length, 1);
  assert.match(errs.join('\n'), /network down/);
});

test('resolveAlternates rewrites the live credentials when the profile is active', async (t) => {
  sandbox(t);
  const cfg = config();
  const profile = conflicted(cfg);
  setActive('work', cfg);
  writeCredentials(creds('new'), cfg);
  const net = fakeNet({ usage: { 'at-new': 401, 'at-old': 200 } });
  captureErr(t);
  await resolveAlternates('work', profile, cfg, net.fetchImpl);
  assert.equal(readCredentials(cfg), creds('old'));
});

test('resolveAlternates works for kimi via its own endpoints', async (t) => {
  sandbox(t);
  const cfg = config('kimi');
  const now = Math.floor(Date.now() / 1000);
  const kc = (tag) => JSON.stringify({ access_token: `at-${tag}`, refresh_token: `rt-${tag}`, expires_at: now + 3600 });
  saveProfile(
    'work',
    { credentials: kc('new'), oauthAccount: { userId: 'u1' }, savedAt: T_NEW, alternates: [{ credentials: kc('old'), savedAt: T_OLD }] },
    cfg,
  );
  const calls = [];
  const fetchImpl = async (url, init = {}) => {
    calls.push(url);
    if (url.endsWith('/usages')) {
      return tokenOf(init) === 'at-old' ? { ok: true, status: 200, json: async () => ({}) } : { ok: false, status: 401, json: async () => ({}) };
    }
    if (url.endsWith('/api/oauth/token')) return { ok: false, status: 401, json: async () => ({ error: 'invalid_grant' }) };
    throw new Error(`unexpected url ${url}`);
  };
  captureErr(t);
  const r = await resolveAlternates('work', loadProfile('work', cfg), cfg, fetchImpl);
  assert.equal(r.profile.credentials, kc('old'));
  assert.deepEqual(calls.map((u) => u.split('/').pop()), ['usages', 'token', 'usages']);
});

test('usageCmd resolves a conflicted profile before reporting on it', async (t) => {
  sandbox(t);
  const cfg = config();
  conflicted(cfg);
  const net = fakeNet({ usage: { 'at-new': 401, 'at-old': 200 } });
  captureErr(t);
  const lines = captureLog(t);
  assert.equal(await usageCmd({}, cfg, net.fetchImpl), 0);
  assert.match(lines.join('\n'), /work .* ok/);
  assert.equal(loadProfile('work', cfg).credentials, creds('old'));
});

test('main switches to the chain that survives probing', async (t) => {
  sandbox(t);
  const cfg = config();
  conflicted(cfg);
  saveProfile('other', { credentials: creds('other'), oauthAccount: { emailAddress: 'o@example.com', accountUuid: 'u2' } }, cfg);
  setActive('other', cfg);
  writeCredentials(creds('other'), cfg);
  const net = fakeNet({ usage: { 'at-new': 401, 'at-old': 200 } });
  const orig = globalThis.fetch;
  globalThis.fetch = net.fetchImpl;
  t.after(() => { globalThis.fetch = orig; });
  captureErr(t);
  captureLog(t);
  assert.equal(await main(['work']), 0);
  assert.equal(getActive(cfg), 'work');
  assert.equal(readCredentials(cfg), creds('old'));
});

test('resolveAlternates probes the live chain first when the active profile was rotated by the tool', async (t) => {
  sandbox(t);
  const cfg = config();
  const profile = conflicted(cfg);
  setActive('work', cfg);
  writeCredentials(creds('live'), cfg);
  fs.writeFileSync(cfg.claudeJson, JSON.stringify({ oauthAccount: { emailAddress: 'w@example.com', accountUuid: 'u1' } }));
  const net = fakeNet({ usage: { 'at-live': 200, 'at-new': 200 } });
  captureErr(t);
  const r = await resolveAlternates('work', profile, cfg, net.fetchImpl);
  assert.deepEqual(net.calls, [['usage', 'at-live']]);
  assert.equal(r.profile.credentials, creds('live'));
  assert.equal(readCredentials(cfg), creds('live'));
});
