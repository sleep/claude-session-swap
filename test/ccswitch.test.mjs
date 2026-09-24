import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';

import { config, validateName, ensureHome, UsageError, readCredentials, writeCredentials, deleteCredentials, readClaudeJson, updateOauthAccount, saveProfile, loadProfile, profileExists, listProfiles, deleteProfileFile, getActive, setActive, writeBackup, captureLive, switchTo, tokenExpiry, formatList, deleteProfileCmd, login, saveCurrent, exportProfile, importProfile, exportAll, importAll, materializeRunDir, runProfile, saveBackRunDir, encryptText, decryptText, isEncrypted, setPassphrase, storeEncrypted, setStoreEncryption, main, tokenExpired, refreshCredentials, AuthDeadError, fetchUsage, parseUsage, formatBar, formatResetIn, renderTable, usageCmd, shouldUseColor, parseFableLimit, CancelledError, asCancel, reportFatal, progName, defaultTarget, RateLimitedError, readUsageCache, formatAgo } from '../ccswitch.mjs';

// Every test calls sandbox(t) first: all ccswitch state goes to a temp dir,
// including the credentials file, so the suite runs on any platform and the
// real login is never touched. The keychain service name is randomized so
// the darwin migration/eviction path never sees a real entry.
export function sandbox(t) {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'ccswitch-test-'));
  process.env.CCSWITCH_HOME = path.join(home, 'profiles-home');
  process.env.CCSWITCH_CLAUDE_JSON = path.join(home, 'claude.json');
  process.env.CCSWITCH_CACHE_DIR = path.join(home, 'cache');
  process.env.CCSWITCH_CREDENTIALS_FILE = path.join(home, 'credentials.json');
  process.env.CCSWITCH_KEYCHAIN_SERVICE =
    `ccswitch-test-${process.pid}-${Math.random().toString(36).slice(2)}`;
  t.after(() => fs.rmSync(home, { recursive: true, force: true }));
  return { home };
}

test('config picks up env overrides', (t) => {
  const { home } = sandbox(t);
  const cfg = config();
  assert.equal(cfg.home, path.join(home, 'profiles-home'));
  assert.equal(cfg.claudeJson, path.join(home, 'claude.json'));
  assert.match(cfg.keychainService, /^ccswitch-test-/);
  assert.equal(cfg.claudeBin, 'claude');
  assert.equal(cfg.credentialsFile, path.join(home, 'credentials.json'));
});

test('validateName accepts kebab-case, rejects everything else', () => {
  assert.equal(validateName('work-2'), 'work-2');
  for (const bad of ['Work', 'a b', '../evil', '', 'é', 'a.b']) {
    assert.throws(() => validateName(bad), UsageError);
  }
});

test('ensureHome creates 0700 directories', (t) => {
  sandbox(t);
  const cfg = config();
  ensureHome(cfg);
  for (const dir of ['', 'profiles', 'backups', 'dirs']) {
    const st = fs.statSync(path.join(cfg.home, dir));
    assert.ok(st.isDirectory());
    assert.equal(st.mode & 0o777, 0o700);
  }
});

test('file credential store round-trips a payload', (t) => {
  sandbox(t);
  const cfg = config();
  assert.equal(readCredentials(cfg), null);
  writeCredentials('{"claudeAiOauth":{"accessToken":"tok-1"}}', cfg);
  assert.equal(readCredentials(cfg), '{"claudeAiOauth":{"accessToken":"tok-1"}}');
  assert.equal(fs.statSync(cfg.credentialsFile).mode & 0o777, 0o600);
  writeCredentials('{"claudeAiOauth":{"accessToken":"tok-2"}}', cfg); // upsert
  assert.equal(readCredentials(cfg), '{"claudeAiOauth":{"accessToken":"tok-2"}}');
  deleteCredentials(cfg);
  assert.equal(readCredentials(cfg), null);
  deleteCredentials(cfg); // deleting a missing entry must not throw
});

test('updateOauthAccount replaces only that key, atomically', (t) => {
  sandbox(t);
  const cfg = config();
  fs.writeFileSync(
    cfg.claudeJson,
    JSON.stringify({ foo: 1, oauthAccount: { emailAddress: 'old@x.com' }, bar: { baz: 2 } }),
  );
  updateOauthAccount({ emailAddress: 'new@x.com' }, cfg);
  const after = JSON.parse(fs.readFileSync(cfg.claudeJson, 'utf8'));
  assert.deepEqual(after, { foo: 1, oauthAccount: { emailAddress: 'new@x.com' }, bar: { baz: 2 } });
  assert.equal(fs.statSync(cfg.claudeJson).mode & 0o777, 0o600);

  updateOauthAccount(null, cfg);
  assert.deepEqual(JSON.parse(fs.readFileSync(cfg.claudeJson, 'utf8')), { foo: 1, bar: { baz: 2 } });
});

test('readClaudeJson: missing file is {}, garbage file throws', (t) => {
  sandbox(t);
  const cfg = config();
  assert.deepEqual(readClaudeJson(cfg), {});
  fs.writeFileSync(cfg.claudeJson, 'not json {');
  assert.throws(() => readClaudeJson(cfg), /not valid JSON/);
});

test('profile save/load/list/delete round-trip', (t) => {
  sandbox(t);
  const cfg = config();
  assert.deepEqual(listProfiles(cfg), []);
  saveProfile('work', { credentials: '{"a":1}', oauthAccount: { emailAddress: 'w@x.com' } }, cfg);
  saveProfile('home', { credentials: '{"b":2}', oauthAccount: { emailAddress: 'h@x.com' } }, cfg);

  const p = loadProfile('work', cfg);
  assert.equal(p.credentials, '{"a":1}');
  assert.equal(p.oauthAccount.emailAddress, 'w@x.com');
  assert.ok(p.savedAt);
  const file = path.join(cfg.home, 'profiles', 'work.json');
  assert.equal(fs.statSync(file).mode & 0o777, 0o600);

  assert.deepEqual(listProfiles(cfg).map((x) => x.name), ['home', 'work']);
  assert.equal(profileExists('work', cfg), true);
  deleteProfileFile('work', cfg);
  assert.equal(profileExists('work', cfg), false);
  assert.throws(() => loadProfile('work', cfg), UsageError);
  assert.throws(() => deleteProfileFile('work', cfg), UsageError);
  assert.throws(() => profileExists('../evil', cfg), UsageError);
});

test('active state and backups', (t) => {
  sandbox(t);
  const cfg = config();
  assert.equal(getActive(cfg), null);
  setActive('work', cfg);
  assert.equal(getActive(cfg), 'work');
  setActive(null, cfg);
  assert.equal(getActive(cfg), null);

  const file = writeBackup('switch-to-work', { credentials: 'x', oauthAccount: null }, cfg);
  assert.ok(file.includes(`${path.sep}backups${path.sep}`));
  assert.match(path.basename(file), /switch-to-work\.json$/);
  assert.equal(fs.statSync(file).mode & 0o777, 0o600);
  assert.deepEqual(JSON.parse(fs.readFileSync(file, 'utf8')), { credentials: 'x', oauthAccount: null });
});

function seedTwoProfiles(cfg) {
  saveProfile('alpha', { credentials: '{"tok":"alpha"}', oauthAccount: { emailAddress: 'alpha@x.com' } }, cfg);
  saveProfile('beta', { credentials: '{"tok":"beta"}', oauthAccount: { emailAddress: 'beta@x.com' } }, cfg);
  // Live state = alpha, but with a refreshed token the profile file doesn't have yet.
  writeCredentials('{"tok":"alpha-refreshed"}', cfg);
  fs.writeFileSync(
    cfg.claudeJson,
    JSON.stringify({ oauthAccount: { emailAddress: 'alpha@x.com' }, unrelated: [1, 2, 3] }),
  );
  setActive('alpha', cfg);
}

test('switchTo swaps keychain + oauthAccount, saves back, backs up', (t) => {
  sandbox(t);
  const cfg = config();
  t.after(() => deleteCredentials(cfg));
  seedTwoProfiles(cfg);

  switchTo('beta', {}, cfg);

  assert.equal(readCredentials(cfg), '{"tok":"beta"}');
  const cj = JSON.parse(fs.readFileSync(cfg.claudeJson, 'utf8'));
  assert.equal(cj.oauthAccount.emailAddress, 'beta@x.com');
  assert.deepEqual(cj.unrelated, [1, 2, 3]); // untouched
  assert.equal(getActive(cfg), 'beta');
  // Refreshed live token was saved back into the outgoing profile:
  assert.equal(loadProfile('alpha', cfg).credentials, '{"tok":"alpha-refreshed"}');
  // A backup of the pre-switch live state exists:
  const backups = fs.readdirSync(path.join(cfg.home, 'backups'));
  assert.equal(backups.length, 1);
  const backup = JSON.parse(fs.readFileSync(path.join(cfg.home, 'backups', backups[0]), 'utf8'));
  assert.equal(backup.credentials, '{"tok":"alpha-refreshed"}');
});

test('switchTo --dry-run mutates nothing', (t) => {
  sandbox(t);
  const cfg = config();
  t.after(() => deleteCredentials(cfg));
  seedTwoProfiles(cfg);

  switchTo('beta', { dryRun: true }, cfg);

  assert.equal(readCredentials(cfg), '{"tok":"alpha-refreshed"}');
  assert.equal(JSON.parse(fs.readFileSync(cfg.claudeJson, 'utf8')).oauthAccount.emailAddress, 'alpha@x.com');
  assert.equal(getActive(cfg), 'alpha');
  assert.ok(!fs.existsSync(path.join(cfg.home, 'backups')) || fs.readdirSync(path.join(cfg.home, 'backups')).length === 0);
});

test('switchTo to a missing profile fails before touching anything', (t) => {
  sandbox(t);
  const cfg = config();
  t.after(() => deleteCredentials(cfg));
  seedTwoProfiles(cfg);
  assert.throws(() => switchTo('nope', {}, cfg), UsageError);
  assert.equal(readCredentials(cfg), '{"tok":"alpha-refreshed"}');
  assert.equal(getActive(cfg), 'alpha');
});

test('switchTo to the already-active profile keeps the live token', (t) => {
  sandbox(t);
  const cfg = config();
  t.after(() => deleteCredentials(cfg));
  seedTwoProfiles(cfg); // live keychain = {"tok":"alpha-refreshed"}, active = alpha

  switchTo('alpha', {}, cfg);

  assert.equal(readCredentials(cfg), '{"tok":"alpha-refreshed"}'); // NOT reverted to {"tok":"alpha"}
  assert.equal(loadProfile('alpha', cfg).credentials, '{"tok":"alpha-refreshed"}'); // save-back still happened
  assert.equal(getActive(cfg), 'alpha');
});

test('switchTo skips save-back when live identity does not match active profile', (t) => {
  sandbox(t);
  const cfg = config();
  t.after(() => deleteCredentials(cfg));
  seedTwoProfiles(cfg); // live keychain = {"tok":"alpha-refreshed"}, active = alpha
  // Live oauthAccount no longer matches the alpha profile, e.g. because the
  // user ran `claude /login` manually outside ccswitch.
  fs.writeFileSync(
    cfg.claudeJson,
    JSON.stringify({ oauthAccount: { emailAddress: 'stranger@x.com' }, unrelated: [1, 2, 3] }),
  );

  switchTo('beta', {}, cfg);

  assert.equal(loadProfile('alpha', cfg).credentials, '{"tok":"alpha"}'); // save-back was skipped
  assert.equal(readCredentials(cfg), '{"tok":"beta"}'); // the switch itself still completed
  assert.equal(getActive(cfg), 'beta');
});

test('switchTo to self restores a wiped keychain', (t) => {
  sandbox(t);
  const cfg = config();
  t.after(() => deleteCredentials(cfg));
  seedTwoProfiles(cfg);
  const stored = loadProfile('alpha', cfg).credentials;
  deleteCredentials(cfg);

  switchTo('alpha', {}, cfg);

  assert.equal(readCredentials(cfg), stored);
  assert.equal(getActive(cfg), 'alpha');
});

test('saveCurrent snapshots the live login and marks it active', (t) => {
  sandbox(t);
  const cfg = config();
  t.after(() => deleteCredentials(cfg));
  writeCredentials('{"tok":"live"}', cfg);
  fs.writeFileSync(cfg.claudeJson, JSON.stringify({ oauthAccount: { emailAddress: 'me@x.com' } }));

  saveCurrent('personal', {}, cfg);

  assert.equal(loadProfile('personal', cfg).credentials, '{"tok":"live"}');
  assert.equal(loadProfile('personal', cfg).oauthAccount.emailAddress, 'me@x.com');
  assert.equal(getActive(cfg), 'personal');
  // Live state was only read, never written:
  assert.equal(readCredentials(cfg), '{"tok":"live"}');
});

test('saveCurrent leaves the active pointer on a matching profile', (t) => {
  sandbox(t);
  const cfg = config();
  t.after(() => deleteCredentials(cfg));
  seedTwoProfiles(cfg); // live login = alpha's account, active = alpha

  saveCurrent('alpha-copy', {}, cfg);

  assert.equal(loadProfile('alpha-copy', cfg).credentials, '{"tok":"alpha-refreshed"}');
  assert.equal(getActive(cfg), 'alpha'); // not stolen by the copy
});

test('saveCurrent fails without live credentials', (t) => {
  sandbox(t);
  const cfg = config();
  assert.throws(() => saveCurrent('personal', {}, cfg), /no live Claude Code login/);
  assert.equal(profileExists('personal', cfg), false);
});

test('saveCurrent refuses to overwrite without --force, --dry-run mutates nothing', (t) => {
  sandbox(t);
  const cfg = config();
  saveProfile('personal', { credentials: '{"tok":"old"}', oauthAccount: null }, cfg);
  assert.throws(() => saveCurrent('personal', {}, cfg), /already exists/);
  saveCurrent('personal', { dryRun: true, force: true }, cfg); // returns before touching the keychain
  assert.equal(loadProfile('personal', cfg).credentials, '{"tok":"old"}');
  assert.equal(getActive(cfg), null);
});

test('tokenExpiry parses expiresAt, tolerates garbage', () => {
  assert.equal(tokenExpiry('{"claudeAiOauth":{"expiresAt":1893456000000}}'), '2030-01-01T00:00:00.000Z');
  assert.equal(tokenExpiry('{"claudeAiOauth":{}}'), '-');
  assert.equal(tokenExpiry('not json'), '-');
  assert.equal(tokenExpiry(null), '-');
});

test('formatList marks the active profile and preserves unknowns', (t) => {
  sandbox(t);
  const cfg = config();
  assert.match(formatList(cfg), /no profiles yet/);
  saveProfile('work', { credentials: '{"claudeAiOauth":{"expiresAt":1893456000000}}', oauthAccount: { emailAddress: 'w@x.com', organizationRateLimitTier: 'default_claude_max_5x' } }, cfg);
  saveProfile('spare', { credentials: null, oauthAccount: null }, cfg);
  setActive('work', cfg);
  const out = formatList(cfg);
  assert.match(out, /\* {2}work +w@x\.com +default_claude_max_5x +2030-01-01T00:00:00\.000Z/);
  assert.match(out, /^ {3}spare +- +-/m);
});

test('deleteProfileCmd refuses the active profile, force-deletes others', async (t) => {
  sandbox(t);
  const cfg = config();
  saveProfile('work', { credentials: 'x', oauthAccount: null }, cfg);
  saveProfile('old', { credentials: 'y', oauthAccount: null }, cfg);
  setActive('work', cfg);
  await assert.rejects(() => deleteProfileCmd('work', { force: true }, cfg), UsageError);
  await deleteProfileCmd('old', { force: true }, cfg);
  assert.equal(profileExists('old', cfg), false);
});

test('deleteProfileCmd backs up before deleting', async (t) => {
  sandbox(t);
  const cfg = config();
  saveProfile('old', { credentials: 'y', oauthAccount: { emailAddress: 'old@x.com' } }, cfg);

  await deleteProfileCmd('old', { force: true }, cfg);

  assert.equal(profileExists('old', cfg), false);
  const backups = fs.readdirSync(path.join(cfg.home, 'backups'));
  const match = backups.find((f) => /delete-old\.json$/.test(f));
  assert.ok(match, `expected a delete-old backup, got: ${backups.join(', ')}`);
  const backup = JSON.parse(fs.readFileSync(path.join(cfg.home, 'backups', match), 'utf8'));
  assert.equal(backup.credentials, 'y');
});

export function fakeClaudeBin(home, script) {
  const bin = path.join(home, 'fake-claude');
  fs.writeFileSync(bin, `#!/bin/sh\n${script}`, { mode: 0o755 });
  process.env.CCSWITCH_CLAUDE_BIN = bin;
  return bin;
}

test('login captures a fresh account as a new profile', async (t) => {
  const { home } = sandbox(t);
  t.after(() => { delete process.env.CCSWITCH_CLAUDE_BIN; });
  fakeClaudeBin(
    home,
    `printf '%s' '{"tok":"fresh"}' > "$CCSWITCH_CREDENTIALS_FILE"\n` +
      `printf '%s' '{"oauthAccount":{"emailAddress":"second@x.com"}}' > "$CCSWITCH_CLAUDE_JSON"\n`,
  );
  const cfg = config();
  t.after(() => deleteCredentials(cfg));
  seedTwoProfiles(cfg); // live = alpha (refreshed), active = alpha

  await login('second', {}, cfg);

  assert.equal(getActive(cfg), 'second');
  assert.equal(loadProfile('second', cfg).credentials, '{"tok":"fresh"}');
  assert.equal(loadProfile('second', cfg).oauthAccount.emailAddress, 'second@x.com');
  // Outgoing live creds were stashed back into the active profile:
  assert.equal(loadProfile('alpha', cfg).credentials, '{"tok":"alpha-refreshed"}');
  assert.equal(readCredentials(cfg), '{"tok":"fresh"}');
});

test('aborted login restores the previous account', async (t) => {
  const { home } = sandbox(t);
  t.after(() => { delete process.env.CCSWITCH_CLAUDE_BIN; });
  fakeClaudeBin(home, 'exit 0\n'); // user quit without logging in
  const cfg = config();
  t.after(() => deleteCredentials(cfg));
  seedTwoProfiles(cfg);

  await assert.rejects(() => login('second', {}, cfg), /no new credentials/);

  assert.equal(readCredentials(cfg), '{"tok":"alpha-refreshed"}');
  assert.equal(JSON.parse(fs.readFileSync(cfg.claudeJson, 'utf8')).oauthAccount.emailAddress, 'alpha@x.com');
  assert.equal(getActive(cfg), 'alpha');
  assert.equal(profileExists('second', cfg), false);
});

test('login refuses an existing profile name without --force', async (t) => {
  sandbox(t);
  const cfg = config();
  saveProfile('work', { credentials: 'x', oauthAccount: null }, cfg);
  await assert.rejects(() => login('work', {}, cfg), /already exists.*--force/);
});

test('login --force re-logs into an existing profile and backs it up first', async (t) => {
  const { home } = sandbox(t);
  t.after(() => { delete process.env.CCSWITCH_CLAUDE_BIN; });
  fakeClaudeBin(
    home,
    `printf '%s' '{"tok":"fresh"}' > "$CCSWITCH_CREDENTIALS_FILE"\n` +
      `printf '%s' '{"oauthAccount":{"emailAddress":"beta@x.com"}}' > "$CCSWITCH_CLAUDE_JSON"\n`,
  );
  const cfg = config();
  t.after(() => deleteCredentials(cfg));
  seedTwoProfiles(cfg); // live = alpha (refreshed), active = alpha

  await login('beta', { force: true }, cfg);

  assert.equal(getActive(cfg), 'beta');
  assert.equal(loadProfile('beta', cfg).credentials, '{"tok":"fresh"}');
  // Outgoing live creds were stashed back into the previously active profile:
  assert.equal(loadProfile('alpha', cfg).credentials, '{"tok":"alpha-refreshed"}');
  // The replaced profile was backed up before being overwritten:
  const backups = fs.readdirSync(path.join(cfg.home, 'backups'));
  const match = backups.find((f) => /login-replace-beta\.json$/.test(f));
  assert.ok(match, `expected a login-replace-beta backup, got: ${backups.join(', ')}`);
  const backup = JSON.parse(fs.readFileSync(path.join(cfg.home, 'backups', match), 'utf8'));
  assert.equal(backup.credentials, '{"tok":"beta"}');
});

test('login revives a moved profile without --force and clears the tombstone', async (t) => {
  const { home } = sandbox(t);
  t.after(() => { delete process.env.CCSWITCH_CLAUDE_BIN; });
  fakeClaudeBin(
    home,
    `printf '%s' '{"tok":"fresh"}' > "$CCSWITCH_CREDENTIALS_FILE"\n` +
      `printf '%s' '{"oauthAccount":{"emailAddress":"work@x.com"}}' > "$CCSWITCH_CLAUDE_JSON"\n`,
  );
  const cfg = config();
  t.after(() => deleteCredentials(cfg));
  saveProfile(
    'work',
    { credentials: '{"tok":"stale"}', oauthAccount: { emailAddress: 'work@x.com' }, movedAt: '2026-01-01T00:00:00.000Z' },
    cfg,
  );

  await login('work', {}, cfg);

  const revived = loadProfile('work', cfg);
  assert.equal(revived.credentials, '{"tok":"fresh"}');
  assert.equal(revived.movedAt, undefined);
  assert.equal(getActive(cfg), 'work');
});

test('login restores previous state when claudeBin fails to spawn', async (t) => {
  const { home } = sandbox(t);
  process.env.CCSWITCH_CLAUDE_BIN = path.join(home, 'does-not-exist');
  t.after(() => { delete process.env.CCSWITCH_CLAUDE_BIN; });
  const cfg = config();
  t.after(() => deleteCredentials(cfg));
  seedTwoProfiles(cfg); // live = alpha (refreshed), active = alpha

  await assert.rejects(() => login('second', {}, cfg), /could not launch/);

  assert.equal(readCredentials(cfg), '{"tok":"alpha-refreshed"}');
  assert.equal(getActive(cfg), 'alpha');
  assert.equal(profileExists('second', cfg), false);
});

test('export writes a plaintext file that import round-trips into a profile', (t) => {
  const { home } = sandbox(t);
  const cfg = config();
  saveProfile('work', { credentials: '{"tok":"w"}', oauthAccount: { emailAddress: 'w@x.com' } }, cfg);
  const out = path.join(home, 'work.ccswitch.json');

  const written = exportProfile('work', out, {}, cfg);
  assert.equal(written, out);
  assert.equal(fs.statSync(out).mode & 0o777, 0o600);
  const dumped = JSON.parse(fs.readFileSync(out, 'utf8'));
  assert.equal(dumped.credentials, '{"tok":"w"}'); // token is present, plaintext
  assert.equal(dumped.oauthAccount.emailAddress, 'w@x.com');

  importProfile('work-copy', out, {}, cfg);
  const copy = loadProfile('work-copy', cfg);
  assert.equal(copy.credentials, '{"tok":"w"}');
  assert.equal(copy.oauthAccount.emailAddress, 'w@x.com');
});

test('export defaults the path to <name>.ccswitch.json', (t) => {
  sandbox(t);
  const cfg = config();
  saveProfile('work', { credentials: '{"tok":"w"}', oauthAccount: null }, cfg);
  const out = exportProfile('work', undefined, { dryRun: true }, cfg);
  assert.equal(out, 'work.ccswitch.json');
});

test('export refuses a missing profile and refuses to clobber without --force', (t) => {
  const { home } = sandbox(t);
  const cfg = config();
  assert.throws(() => exportProfile('nope', path.join(home, 'x.json'), {}, cfg), UsageError);

  saveProfile('work', { credentials: 'x', oauthAccount: null }, cfg);
  const out = path.join(home, 'work.json');
  fs.writeFileSync(out, 'preexisting');
  assert.throws(() => exportProfile('work', out, {}, cfg), /already exists/);
  exportProfile('work', out, { force: true }, cfg); // --force overwrites
  assert.equal(JSON.parse(fs.readFileSync(out, 'utf8')).credentials, 'x');
});

test('import validates the file and guards existing profiles', (t) => {
  const { home } = sandbox(t);
  const cfg = config();
  const missing = path.join(home, 'gone.json');
  assert.throws(() => importProfile('a', missing, {}, cfg), /no file to import/);

  const bad = path.join(home, 'bad.json');
  fs.writeFileSync(bad, 'not json {');
  assert.throws(() => importProfile('a', bad, {}, cfg), /not valid JSON/);

  const wrong = path.join(home, 'wrong.json');
  fs.writeFileSync(wrong, JSON.stringify({ oauthAccount: null }));
  assert.throws(() => importProfile('a', wrong, {}, cfg), /not a ccswitch export/);

  const good = path.join(home, 'good.json');
  fs.writeFileSync(good, JSON.stringify({ credentials: '{"tok":"g"}', oauthAccount: null }));
  saveProfile('a', { credentials: 'old', oauthAccount: null }, cfg);
  assert.throws(() => importProfile('a', good, {}, cfg), /already exists/);
  importProfile('a', good, { force: true }, cfg); // --force overwrites
  assert.equal(loadProfile('a', cfg).credentials, '{"tok":"g"}');
});

test('import --dry-run writes no profile', (t) => {
  const { home } = sandbox(t);
  const cfg = config();
  const good = path.join(home, 'good.json');
  fs.writeFileSync(good, JSON.stringify({ credentials: '{"tok":"g"}', oauthAccount: null }));
  importProfile('a', good, { dryRun: true }, cfg);
  assert.equal(profileExists('a', cfg), false);
});

test('cli: export then import round-trips across a fresh store', (t) => {
  const { home } = sandbox(t);
  const cfg = config();
  saveProfile('work', { credentials: '{"tok":"w"}', oauthAccount: { emailAddress: 'w@x.com' } }, cfg);
  const file = path.join(home, 'moved.json');
  const env = {
    CCSWITCH_HOME: process.env.CCSWITCH_HOME,
    CCSWITCH_CLAUDE_JSON: process.env.CCSWITCH_CLAUDE_JSON,
    CCSWITCH_KEYCHAIN_SERVICE: process.env.CCSWITCH_KEYCHAIN_SERVICE,
  };
  const exp = runCli(['export', 'work', file], env);
  assert.equal(exp.status, 0);
  assert.match(exp.stdout, /exported "work"/);

  const imp = runCli(['import', 'work-2', file], env);
  assert.equal(imp.status, 0);
  assert.equal(loadProfile('work-2', cfg).credentials, '{"tok":"w"}');
});

test('export-all/import-all round-trips the whole store', (t) => {
  const { home } = sandbox(t);
  const cfg = config();
  saveProfile('work', { credentials: '{"tok":"w"}', oauthAccount: { emailAddress: 'w@x.com' }, savedAt: '2026-01-01T00:00:00.000Z' }, cfg);
  saveProfile('personal', { credentials: '{"tok":"p"}', oauthAccount: null }, cfg);
  setActive('work', cfg);
  const out = path.join(home, 'all.json');

  exportAll(out, {}, cfg);
  assert.equal(fs.statSync(out).mode & 0o777, 0o600);
  const dumped = JSON.parse(fs.readFileSync(out, 'utf8'));
  assert.equal(dumped.ccswitchExport, 1);
  assert.equal(dumped.active, 'work');
  assert.deepEqual(Object.keys(dumped.profiles).sort(), ['personal', 'work']);

  // Import into a fresh store:
  process.env.CCSWITCH_HOME = path.join(home, 'second-home');
  const cfg2 = config();
  importAll(out, {}, cfg2);
  assert.equal(loadProfile('work', cfg2).credentials, '{"tok":"w"}');
  assert.equal(loadProfile('work', cfg2).savedAt, '2026-01-01T00:00:00.000Z'); // preserved, not re-stamped
  assert.equal(loadProfile('personal', cfg2).credentials, '{"tok":"p"}');
  assert.equal(getActive(cfg2), 'work'); // adopted: fresh machine had no active profile
});

test('import-all merges: skips existing profiles without --force, keeps local active', (t) => {
  const { home } = sandbox(t);
  const cfg = config();
  saveProfile('work', { credentials: '{"tok":"local"}', oauthAccount: null }, cfg);
  setActive('work', cfg);
  const out = path.join(home, 'all.json');
  fs.writeFileSync(out, JSON.stringify({
    ccswitchExport: 1,
    active: 'other',
    profiles: {
      work: { credentials: '{"tok":"remote"}', oauthAccount: null },
      other: { credentials: '{"tok":"o"}', oauthAccount: null },
    },
  }));

  importAll(out, {}, cfg);
  assert.equal(loadProfile('work', cfg).credentials, '{"tok":"local"}'); // skipped
  assert.equal(loadProfile('other', cfg).credentials, '{"tok":"o"}'); // added
  assert.equal(getActive(cfg), 'work'); // local active pointer kept

  importAll(out, { force: true }, cfg);
  assert.equal(loadProfile('work', cfg).credentials, '{"tok":"remote"}'); // --force overwrites
});

test('export-all/import-all validate inputs and honor --dry-run', (t) => {
  const { home } = sandbox(t);
  const cfg = config();
  assert.throws(() => exportAll(path.join(home, 'x.json'), {}, cfg), /no profiles to export/);

  saveProfile('work', { credentials: 'x', oauthAccount: null }, cfg);
  const out = path.join(home, 'all.json');
  exportAll(out, { dryRun: true }, cfg);
  assert.equal(fs.existsSync(out), false);
  fs.writeFileSync(out, 'preexisting');
  assert.throws(() => exportAll(out, {}, cfg), /already exists/);

  assert.throws(() => importAll(path.join(home, 'gone.json'), {}, cfg), /no file to import/);
  const bad = path.join(home, 'bad.json');
  fs.writeFileSync(bad, JSON.stringify({ profiles: {} })); // missing marker
  assert.throws(() => importAll(bad, {}, cfg), /not a ccswitch full export/);
  const evil = path.join(home, 'evil.json');
  fs.writeFileSync(evil, JSON.stringify({ ccswitchExport: 1, profiles: { '../evil': { credentials: 'x' }, ok: { credentials: 'y' } } }));
  assert.throws(() => importAll(evil, {}, cfg), UsageError);
  assert.equal(profileExists('ok', cfg), false); // nothing written when any name is invalid

  const good = path.join(home, 'good.json');
  fs.writeFileSync(good, JSON.stringify({ ccswitchExport: 1, profiles: { fresh: { credentials: 'z' } } }));
  importAll(good, { dryRun: true }, cfg);
  assert.equal(profileExists('fresh', cfg), false);
});

test('materializeRunDir writes credentials and identity, preserves extras', (t) => {
  sandbox(t);
  const cfg = config();
  fs.writeFileSync(cfg.claudeJson, JSON.stringify({ hasCompletedOnboarding: true, theme: 'dark', unrelated: 1 }));
  saveProfile('work', { credentials: '{"tok":"w"}', oauthAccount: { emailAddress: 'w@x.com' } }, cfg);
  const dir = materializeRunDir('work', cfg);
  // Onboarding flags are seeded from the global config so claude doesn't
  // replay first-run setup; unrelated global keys are not copied.
  const seeded = JSON.parse(fs.readFileSync(path.join(dir, '.claude.json'), 'utf8'));
  assert.equal(seeded.hasCompletedOnboarding, true);
  assert.equal(seeded.theme, 'dark');
  assert.equal(seeded.unrelated, undefined);
  assert.equal(dir, path.join(cfg.home, 'dirs', 'work'));
  assert.equal(fs.statSync(dir).mode & 0o777, 0o700);
  assert.equal(fs.readFileSync(path.join(dir, '.credentials.json'), 'utf8'), '{"tok":"w"}');
  assert.equal(fs.statSync(path.join(dir, '.credentials.json')).mode & 0o777, 0o600);
  // A later re-run preserves keys claude added to the materialized .claude.json:
  fs.writeFileSync(path.join(dir, '.claude.json'), JSON.stringify({ oauthAccount: { emailAddress: 'stale@x.com' }, theme: 'dark' }));
  materializeRunDir('work', cfg);
  const cj = JSON.parse(fs.readFileSync(path.join(dir, '.claude.json'), 'utf8'));
  assert.equal(cj.oauthAccount.emailAddress, 'w@x.com');
  assert.equal(cj.theme, 'dark');
});

test('runProfile launches claude with CLAUDE_CONFIG_DIR set', (t) => {
  const { home } = sandbox(t);
  t.after(() => { delete process.env.CCSWITCH_CLAUDE_BIN; delete process.env.CCSWITCH_TEST_OUT; });
  process.env.CCSWITCH_TEST_OUT = path.join(home, 'out.txt');
  fakeClaudeBin(home, 'printf "%s|%s" "$CLAUDE_CONFIG_DIR" "$*" > "$CCSWITCH_TEST_OUT"\n');
  const cfg = config();
  saveProfile('work', { credentials: '{"tok":"w"}', oauthAccount: null }, cfg);

  const code = runProfile('work', ['--continue'], cfg);

  assert.equal(code, 0);
  const [dir, argv] = fs.readFileSync(process.env.CCSWITCH_TEST_OUT, 'utf8').split('|');
  assert.equal(dir, path.join(cfg.home, 'dirs', 'work'));
  assert.equal(argv, '--continue');
});

test('runProfile saves refreshed run-dir credentials back into the profile', (t) => {
  const { home } = sandbox(t);
  t.after(() => { delete process.env.CCSWITCH_CLAUDE_BIN; });
  // The fake session refreshes its token, as claude does on expiry.
  fakeClaudeBin(home, `printf '%s' '{"tok":"w-refreshed"}' > "$CLAUDE_CONFIG_DIR/.credentials.json"\n`);
  const cfg = config();
  saveProfile('work', { credentials: '{"tok":"w"}', oauthAccount: { emailAddress: 'w@x.com' } }, cfg);

  runProfile('work', [], cfg);

  assert.equal(loadProfile('work', cfg).credentials, '{"tok":"w-refreshed"}');
});

test('saveBackRunDir skips a mismatched account and an empty run dir', (t) => {
  sandbox(t);
  const cfg = config();
  saveProfile('work', { credentials: '{"tok":"w"}', oauthAccount: { emailAddress: 'w@x.com' } }, cfg);
  const dir = materializeRunDir('work', cfg);
  // A different account logged in inside the run session:
  fs.writeFileSync(path.join(dir, '.claude.json'), JSON.stringify({ oauthAccount: { emailAddress: 'other@x.com' } }));
  fs.writeFileSync(path.join(dir, '.credentials.json'), '{"tok":"other"}');
  saveBackRunDir('work', dir, cfg);
  assert.equal(loadProfile('work', cfg).credentials, '{"tok":"w"}'); // untouched

  // Missing credentials file: no-op.
  fs.rmSync(path.join(dir, '.credentials.json'));
  saveBackRunDir('work', dir, cfg);
  assert.equal(loadProfile('work', cfg).credentials, '{"tok":"w"}');
});

test('encryptText/decryptText round-trip; wrong passphrase and tampering fail', () => {
  const sealed = encryptText('{"secret":"tok"}', 'pw');
  assert.equal(isEncrypted(sealed), true);
  assert.doesNotMatch(sealed, /tok/);
  assert.equal(decryptText(sealed, 'pw'), '{"secret":"tok"}');
  assert.throws(() => decryptText(sealed, 'nope'), /wrong passphrase/);
  const tampered = JSON.parse(sealed);
  tampered.data = Buffer.from('xx').toString('base64');
  assert.throws(() => decryptText(tampered, 'pw'), /wrong passphrase|corrupted/);
});

test('encrypting the store seals profiles and backups; decrypt restores plaintext', (t) => {
  sandbox(t);
  t.after(() => setPassphrase(null));
  const cfg = config();
  saveProfile('work', { credentials: '{"tok":"secret-w"}', oauthAccount: { emailAddress: 'w@x.com' } }, cfg);
  writeBackup('test', { credentials: '{"tok":"secret-b"}' }, cfg);
  setPassphrase('pw');

  setStoreEncryption(true, cfg);

  assert.equal(storeEncrypted(cfg), true);
  const rawProfile = fs.readFileSync(path.join(cfg.home, 'profiles', 'work.json'), 'utf8');
  assert.equal(isEncrypted(rawProfile), true);
  assert.doesNotMatch(rawProfile, /secret-w/); // no plaintext token on disk
  const backupFile = fs.readdirSync(path.join(cfg.home, 'backups'))[0];
  assert.doesNotMatch(fs.readFileSync(path.join(cfg.home, 'backups', backupFile), 'utf8'), /secret-b/);
  // Reads still work transparently, including new writes:
  assert.equal(loadProfile('work', cfg).credentials, '{"tok":"secret-w"}');
  saveProfile('new', { credentials: '{"tok":"secret-n"}', oauthAccount: null }, cfg);
  assert.doesNotMatch(fs.readFileSync(path.join(cfg.home, 'profiles', 'new.json'), 'utf8'), /secret-n/);
  assert.match(formatList(cfg), /work +w@x\.com/);
  assert.throws(() => setStoreEncryption(true, cfg), /already encrypted/);

  setStoreEncryption(false, cfg);
  assert.equal(storeEncrypted(cfg), false);
  assert.match(fs.readFileSync(path.join(cfg.home, 'profiles', 'work.json'), 'utf8'), /secret-w/);
  assert.equal(loadProfile('new', cfg).credentials, '{"tok":"secret-n"}');
});

test('reading an encrypted store without a passphrase fails cleanly', (t) => {
  sandbox(t);
  t.after(() => setPassphrase(null));
  const cfg = config();
  saveProfile('work', { credentials: '{"tok":"w"}', oauthAccount: null }, cfg);
  setPassphrase('pw');
  setStoreEncryption(true, cfg);
  setPassphrase(null);
  assert.throws(() => loadProfile('work', cfg), /set CCSWITCH_PASSPHRASE/);
  setPassphrase('wrong');
  assert.throws(() => loadProfile('work', cfg), /wrong passphrase/);
});

test('encrypted store produces encrypted exports that import back', (t) => {
  const { home } = sandbox(t);
  t.after(() => setPassphrase(null));
  const cfg = config();
  saveProfile('work', { credentials: '{"tok":"secret-w"}', oauthAccount: null }, cfg);
  setPassphrase('pw');
  setStoreEncryption(true, cfg);

  const one = exportProfile('work', path.join(home, 'one.json'), {}, cfg);
  assert.equal(isEncrypted(fs.readFileSync(one, 'utf8')), true);
  importProfile('work-copy', one, {}, cfg);
  assert.equal(loadProfile('work-copy', cfg).credentials, '{"tok":"secret-w"}');

  const all = exportAll(path.join(home, 'all.json'), {}, cfg);
  assert.equal(isEncrypted(fs.readFileSync(all, 'utf8')), true);
  // Import into a fresh plaintext store, same passphrase for the file:
  process.env.CCSWITCH_HOME = path.join(home, 'second-home');
  const cfg2 = config();
  importAll(all, {}, cfg2);
  assert.equal(loadProfile('work', cfg2).credentials, '{"tok":"secret-w"}');
  assert.equal(isEncrypted(fs.readFileSync(path.join(cfg2.home, 'profiles', 'work.json'), 'utf8')), false); // target store is plaintext
});

test('cli: encrypt via CCSWITCH_PASSPHRASE, list works, decrypt restores', (t) => {
  sandbox(t);
  const cfg = config();
  saveProfile('work', { credentials: '{"tok":"secret-w"}', oauthAccount: { emailAddress: 'w@x.com' } }, cfg);
  const env = {
    CCSWITCH_HOME: process.env.CCSWITCH_HOME,
    CCSWITCH_CLAUDE_JSON: process.env.CCSWITCH_CLAUDE_JSON,
    CCSWITCH_KEYCHAIN_SERVICE: process.env.CCSWITCH_KEYCHAIN_SERVICE,
    CCSWITCH_PASSPHRASE: 'pw',
  };
  const enc = runCli(['encrypt'], env);
  assert.equal(enc.status, 0, enc.stderr);
  assert.equal(isEncrypted(fs.readFileSync(path.join(cfg.home, 'profiles', 'work.json'), 'utf8')), true);

  const list = runCli(['list'], env);
  assert.equal(list.status, 0, list.stderr);
  assert.match(list.stdout, /work +w@x\.com/);

  const noPw = runCli(['list'], { ...env, CCSWITCH_PASSPHRASE: '' });
  assert.equal(noPw.status, 1);
  assert.match(noPw.stderr, /CCSWITCH_PASSPHRASE/);

  const dec = runCli(['decrypt'], env);
  assert.equal(dec.status, 0, dec.stderr);
  assert.match(fs.readFileSync(path.join(cfg.home, 'profiles', 'work.json'), 'utf8'), /secret-w/);
});

const CLI = new URL('../ccswitch.mjs', import.meta.url).pathname;

function runCli(args, env = {}, input) {
  return spawnSync(process.execPath, [CLI, ...args], {
    encoding: 'utf8',
    env: { ...process.env, ...env },
    input,
  });
}

test('cli: --help prints usage and exits 0', (t) => {
  sandbox(t);
  const r = runCli(['--help']);
  assert.equal(r.status, 0);
  assert.match(r.stdout, /usage: ccswitch/i);
  assert.match(r.stdout, /login <name>/);
});

test('cli: list works end to end', (t) => {
  sandbox(t);
  const cfg = config();
  saveProfile('work', { credentials: null, oauthAccount: { emailAddress: 'w@x.com' } }, cfg);
  const r = runCli(['list'], {
    CCSWITCH_HOME: process.env.CCSWITCH_HOME,
    CCSWITCH_CLAUDE_JSON: process.env.CCSWITCH_CLAUDE_JSON,
    CCSWITCH_KEYCHAIN_SERVICE: process.env.CCSWITCH_KEYCHAIN_SERVICE,
  });
  assert.equal(r.status, 0);
  assert.match(r.stdout, /work +w@x\.com/);
});

test('cli: bare invocation falls back to a numbered prompt when stdin is not a TTY', (t) => {
  sandbox(t);
  const cfg = config();
  saveProfile('work', { credentials: null, oauthAccount: { emailAddress: 'w@x.com' } }, cfg);
  saveProfile('home', { credentials: null, oauthAccount: { emailAddress: 'h@x.com' } }, cfg);
  // --dry-run so the picker skips the network usage fetch entirely (a piped,
  // non-TTY stdin can't drive the arrow-key picker either way).
  // Profiles list alphabetically: 1) home, 2) work.
  const r = runCli(['--dry-run'], {}, '1\n');
  assert.equal(r.status, 0, r.stderr);
  assert.match(r.stdout, /#\s+name\s+account/);
  assert.match(r.stdout, /1\s+home\s+h@x\.com/);
  assert.match(r.stdout, /would .*activate "home"/);
});

test('cli: bare invocation rejects an out-of-range selection', (t) => {
  sandbox(t);
  const cfg = config();
  saveProfile('work', { credentials: null, oauthAccount: { emailAddress: 'w@x.com' } }, cfg);
  const r = runCli(['--dry-run'], {}, '9\n');
  assert.equal(r.status, 1);
  assert.match(r.stderr, /invalid selection/);
});

test('cli: unknown command errors cleanly without a stack trace', (t) => {
  sandbox(t);
  const r = runCli(['Not-A-Name!']);
  assert.equal(r.status, 1);
  assert.match(r.stderr, /^ccswitch: unknown command/);
  assert.doesNotMatch(r.stderr, /at .*\(.*\)/); // no stack frames for usage errors
});

test('cli: run passes args after -- to claude', (t) => {
  const { home } = sandbox(t);
  t.after(() => { delete process.env.CCSWITCH_CLAUDE_BIN; delete process.env.CCSWITCH_TEST_OUT; });
  process.env.CCSWITCH_TEST_OUT = path.join(home, 'out.txt');
  fakeClaudeBin(home, 'printf "%s" "$*" > "$CCSWITCH_TEST_OUT"\n');
  const cfg = config();
  saveProfile('work', { credentials: '{"tok":"w"}', oauthAccount: null }, cfg);
  const r = runCli(['run', 'work', '--', '--model', 'opus'], {
    CCSWITCH_HOME: process.env.CCSWITCH_HOME,
    CCSWITCH_CLAUDE_JSON: process.env.CCSWITCH_CLAUDE_JSON,
    CCSWITCH_KEYCHAIN_SERVICE: process.env.CCSWITCH_KEYCHAIN_SERVICE,
    CCSWITCH_CLAUDE_BIN: process.env.CCSWITCH_CLAUDE_BIN,
    CCSWITCH_TEST_OUT: process.env.CCSWITCH_TEST_OUT,
  });
  assert.equal(r.status, 0);
  assert.equal(fs.readFileSync(process.env.CCSWITCH_TEST_OUT, 'utf8'), '--model opus');
});

test('cli: --dry-run after -- passes through to claude untouched', (t) => {
  const { home } = sandbox(t);
  t.after(() => { delete process.env.CCSWITCH_CLAUDE_BIN; delete process.env.CCSWITCH_TEST_OUT; });
  process.env.CCSWITCH_TEST_OUT = path.join(home, 'out.txt');
  fakeClaudeBin(home, 'printf "%s" "$*" > "$CCSWITCH_TEST_OUT"\n');
  const cfg = config();
  saveProfile('work', { credentials: '{"tok":"w"}', oauthAccount: null }, cfg);
  const r = runCli(['run', 'work', '--', '--dry-run', '--model', 'opus'], {
    CCSWITCH_HOME: process.env.CCSWITCH_HOME,
    CCSWITCH_CLAUDE_JSON: process.env.CCSWITCH_CLAUDE_JSON,
    CCSWITCH_KEYCHAIN_SERVICE: process.env.CCSWITCH_KEYCHAIN_SERVICE,
    CCSWITCH_CLAUDE_BIN: process.env.CCSWITCH_CLAUDE_BIN,
    CCSWITCH_TEST_OUT: process.env.CCSWITCH_TEST_OUT,
  });
  assert.equal(r.status, 0);
  assert.equal(fs.readFileSync(process.env.CCSWITCH_TEST_OUT, 'utf8'), '--dry-run --model opus');
});

test('cli: delete --dry-run deletes nothing', (t) => {
  sandbox(t);
  const cfg = config();
  saveProfile('old', { credentials: 'y', oauthAccount: null }, cfg);
  const r = runCli(['delete', 'old', '--dry-run', '--force'], {
    CCSWITCH_HOME: process.env.CCSWITCH_HOME,
    CCSWITCH_CLAUDE_JSON: process.env.CCSWITCH_CLAUDE_JSON,
    CCSWITCH_KEYCHAIN_SERVICE: process.env.CCSWITCH_KEYCHAIN_SERVICE,
  });
  assert.equal(r.status, 0);
  assert.match(r.stdout, /\[dry-run\] would delete profile "old"/);
  assert.equal(profileExists('old', cfg), true);
});

// --- usage command ---------------------------------------------------------------

const usageCreds = (o) =>
  JSON.stringify({ claudeAiOauth: { accessToken: 'at-1', refreshToken: 'rt-1', expiresAt: Date.now() + 60 * 60 * 1000, ...o } });

function captureLog(t) {
  const lines = [];
  const orig = console.log;
  console.log = (...a) => lines.push(a.join(' '));
  t.after(() => { console.log = orig; });
  return lines;
}

test('tokenExpired honors the 5-minute margin and fails closed', () => {
  assert.equal(tokenExpired(usageCreds()), false);
  assert.equal(tokenExpired(usageCreds({ expiresAt: Date.now() + 2 * 60 * 1000 })), true); // inside margin
  assert.equal(tokenExpired(usageCreds({ expiresAt: Date.now() - 1000 })), true);
  assert.equal(tokenExpired(usageCreds({ expiresAt: undefined })), true);
  assert.equal(tokenExpired('not json'), true);
  assert.equal(tokenExpired(null), true);
});

test('refreshCredentials rotates the pair and preserves other fields', async () => {
  const calls = [];
  const fetchImpl = async (url, init) => {
    calls.push({ url, body: JSON.parse(init.body) });
    return { ok: true, status: 200, json: async () => ({ access_token: 'at-2', refresh_token: 'rt-2', expires_in: 28800 }) };
  };
  const before = JSON.stringify({
    claudeAiOauth: { accessToken: 'at-1', refreshToken: 'rt-1', expiresAt: 1, scopes: ['user:inference'], subscriptionType: 'max' },
  });
  const after = JSON.parse(await refreshCredentials(before, fetchImpl));
  assert.equal(calls[0].body.grant_type, 'refresh_token');
  assert.equal(calls[0].body.refresh_token, 'rt-1');
  assert.equal(after.claudeAiOauth.accessToken, 'at-2');
  assert.equal(after.claudeAiOauth.refreshToken, 'rt-2');
  assert.ok(after.claudeAiOauth.expiresAt > Date.now());
  assert.deepEqual(after.claudeAiOauth.scopes, ['user:inference']);
  assert.equal(after.claudeAiOauth.subscriptionType, 'max');
});

test('refreshCredentials maps 400/401 to AuthDeadError, 500 to plain Error', async () => {
  const respond = (status) => async () => ({ ok: false, status, json: async () => ({}) });
  await assert.rejects(refreshCredentials(usageCreds(), respond(400)), AuthDeadError);
  await assert.rejects(refreshCredentials(usageCreds(), respond(401)), AuthDeadError);
  await assert.rejects(refreshCredentials(usageCreds(), respond(500)), (e) => !(e instanceof AuthDeadError));
  await assert.rejects(refreshCredentials('{}', async () => {}), AuthDeadError); // no refresh token
});

test('fetchUsage sends bearer + beta headers and parses windows', async () => {
  let seen;
  const fetchImpl = async (url, init) => {
    seen = { url, headers: init.headers };
    return {
      ok: true,
      status: 200,
      json: async () => ({
        five_hour: { utilization: 58, resets_at: '2026-07-18T20:00:00Z' },
        seven_day: { utilization: 84.4, resets_at: '2026-07-24T00:00:00Z' },
        seven_day_opus: null, // superseded: present but never populated
        limits: [
          { kind: 'weekly_all', percent: 84, resets_at: '2026-07-24T00:00:00Z', scope: null },
          {
            kind: 'weekly_scoped',
            percent: 49,
            resets_at: '2026-07-22T00:00:00Z',
            scope: { model: { id: null, display_name: 'Fable' }, surface: null },
          },
        ],
        extra_field: true,
      }),
    };
  };
  const u = await fetchUsage(usageCreds(), fetchImpl);
  assert.equal(seen.headers.Authorization, 'Bearer at-1');
  assert.equal(seen.headers['anthropic-beta'], 'oauth-2025-04-20');
  assert.equal(u.fiveHour.utilization, 58);
  assert.equal(u.sevenDay.resetsAt, '2026-07-24T00:00:00Z');
  assert.equal(u.fable.utilization, 49);
});

test('fetchUsage maps 401/403 to AuthDeadError; parseUsage tolerates gaps', async () => {
  await assert.rejects(fetchUsage(usageCreds(), async () => ({ ok: false, status: 401 })), AuthDeadError);
  await assert.rejects(fetchUsage(usageCreds(), async () => ({ ok: false, status: 500 })), (e) => !(e instanceof AuthDeadError));
  assert.deepEqual(parseUsage({}), { fiveHour: null, sevenDay: null, fable: null });
  assert.deepEqual(parseUsage({ five_hour: { utilization: 'x' } }), {
    fiveHour: { utilization: null, resetsAt: null },
    sevenDay: null,
    fable: null,
  });
});

test('parseFableLimit picks the Fable-scoped limit and nothing else', () => {
  const fable = { percent: 49, resets_at: '2026-07-22T00:00:00Z', scope: { model: { display_name: 'Fable' } } };
  assert.deepEqual(parseFableLimit({ limits: [fable] }), { utilization: 49, resetsAt: '2026-07-22T00:00:00Z' });
  assert.deepEqual(parseFableLimit({ limits: [{ ...fable, scope: { model: { display_name: 'FABLE' } } }] }).utilization, 49);
  assert.equal(parseFableLimit({}), null);
  assert.equal(parseFableLimit({ limits: null }), null);
  // An unscoped or differently-scoped limit must never be read as Fable.
  assert.equal(parseFableLimit({ limits: [{ kind: 'weekly_all', percent: 84, scope: null }] }), null);
  assert.equal(
    parseFableLimit({ limits: [{ kind: 'weekly_scoped', percent: 84, scope: { surface: { display_name: 'Code' } } }] }),
    null,
  );
  // Present but unpopulated: the row renders a dash rather than a bogus 0%.
  assert.deepEqual(parseFableLimit({ limits: [{ ...fable, percent: null, resets_at: null }] }), {
    utilization: null,
    resetsAt: null,
  });
});

test('formatBar renders fixed-width bars, clamps, and colors by threshold', () => {
  assert.equal(formatBar(null), '-');
  assert.equal(formatBar(0), '        0%');
  assert.equal(formatBar(58), '██▉    58%');
  assert.equal(formatBar(100), '█████ 100%');
  assert.equal(formatBar(250), '█████ 100%'); // clamped
  assert.match(formatBar(58, { color: true }), /^\x1b\[32m/); // green < 60
  assert.match(formatBar(70, { color: true }), /^\x1b\[33m/); // yellow 60–85
  assert.match(formatBar(90, { color: true }), /^\x1b\[31m/); // red > 85
});

test('shouldUseColor defaults on, TTY or not, unless NO_COLOR/FORCE_COLOR=0 opts out', () => {
  assert.equal(shouldUseColor({}), true);
  assert.equal(shouldUseColor({ NO_COLOR: '1' }), false);
  assert.equal(shouldUseColor({ FORCE_COLOR: '0' }), false);
  assert.equal(shouldUseColor({ NO_COLOR: '1', FORCE_COLOR: '1' }), false); // NO_COLOR wins
  assert.equal(shouldUseColor({ FORCE_COLOR: '1' }), true);
});

test('formatResetIn picks the right granularity', () => {
  const now = Date.UTC(2026, 6, 18, 12, 0, 0);
  const at = (ms) => new Date(now + ms).toISOString();
  assert.equal(formatResetIn(null), '-');
  assert.equal(formatResetIn(at(-1000), now), 'now');
  assert.equal(formatResetIn(at(12 * 60000), now), 'in 12m');
  assert.equal(formatResetIn(at((3 * 60 + 27) * 60000), now), 'in 3h27m');
  assert.equal(formatResetIn(at((5 * 24 + 23) * 3600000), now), 'in 5d23h');
});

test('renderTable aligns columns ignoring ANSI escapes', () => {
  const out = renderTable(['a', 'b'], [['\x1b[32mxx\x1b[0m', 'y'], ['zzz', 'w']]);
  // Compare visible positions: escape sequences occupy string indices but no columns.
  const lines = out.split('\n').map((l) => l.replace(/\x1b\[[0-9;]*m/g, ''));
  assert.equal(lines[1].indexOf('y'), lines[2].indexOf('w'));
});

test('renderTable clips rows to maxWidth without splitting escapes', () => {
  const out = renderTable(['a', 'status'], [['\x1b[31mxx\x1b[0m', 'a long status message']], 12);
  for (const line of out.split('\n')) assert.ok(line.replace(/\x1b\[[0-9;]*m/g, '').length <= 12);
  const row = out.split('\n')[1];
  assert.equal(row.replace(/\x1b\[[0-9;]*m/g, ''), 'xx  a long s');
  assert.ok(row.endsWith('\x1b[0m'));
});

test('usageCmd refreshes expired tokens and persists before the usage call', async (t) => {
  sandbox(t);
  const cfg = config();
  const expired = JSON.stringify({ claudeAiOauth: { accessToken: 'at-old', refreshToken: 'rt-old', expiresAt: 1 } });
  saveProfile('work', { credentials: expired, oauthAccount: { emailAddress: 'w@x.com' } }, cfg);
  let persistedAtUsageTime = null;
  const fetchImpl = async (url, init) => {
    if (url.includes('/oauth/token')) {
      return { ok: true, status: 200, json: async () => ({ access_token: 'at-new', refresh_token: 'rt-new', expires_in: 28800 }) };
    }
    persistedAtUsageTime = JSON.parse(loadProfile('work', cfg).credentials).claudeAiOauth.accessToken;
    assert.equal(init.headers.Authorization, 'Bearer at-new');
    return { ok: true, status: 200, json: async () => ({ five_hour: { utilization: 10, resets_at: null } }) };
  };
  const lines = captureLog(t);
  assert.equal(await usageCmd({}, cfg, fetchImpl), 0);
  assert.equal(persistedAtUsageTime, 'at-new'); // persist-before-use
  assert.match(lines.join('\n'), /ok \(refreshed\)/);
});

test('usageCmd uses live credentials for the active profile without refreshing', async (t) => {
  sandbox(t);
  const cfg = config();
  const stale = JSON.stringify({ claudeAiOauth: { accessToken: 'at-stale', refreshToken: 'rt-1', expiresAt: 1 } });
  saveProfile('work', { credentials: stale, oauthAccount: { emailAddress: 'w@x.com' } }, cfg);
  setActive('work', cfg);
  writeCredentials(
    JSON.stringify({ claudeAiOauth: { accessToken: 'at-live', refreshToken: 'rt-2', expiresAt: Date.now() + 3600000 } }),
    cfg,
  );
  const urls = [];
  const fetchImpl = async (url, init) => {
    urls.push(url);
    assert.equal(init.headers.Authorization, 'Bearer at-live');
    return { ok: true, status: 200, json: async () => ({}) };
  };
  captureLog(t);
  assert.equal(await usageCmd({}, cfg, fetchImpl), 0);
  assert.equal(urls.length, 1); // usage only, no token refresh
});

test('fetchUsage maps 429 to RateLimitedError', async () => {
  await assert.rejects(fetchUsage(usageCreds(), async () => ({ ok: false, status: 429 })), RateLimitedError);
});

test('usageCmd caches usage and shows the last known value on 429', async (t) => {
  sandbox(t);
  const cfg = config();
  saveProfile('work', { credentials: usageCreds(), oauthAccount: { emailAddress: 'w@x.com' } }, cfg);
  let status = 200;
  const fetchImpl = async () =>
    status === 200
      ? { ok: true, status, json: async () => ({ five_hour: { utilization: 42, resets_at: null } }) }
      : { ok: false, status, json: async () => ({}) };
  process.env.NO_COLOR = '1';
  t.after(() => delete process.env.NO_COLOR);
  const lines = captureLog(t);

  assert.equal(await usageCmd({}, cfg, fetchImpl), 0);
  const cached = readUsageCache('work', cfg);
  assert.equal(cached.usage.fiveHour.utilization, 42);
  assert.equal(fs.statSync(path.join(cfg.usageCacheDir, 'work.json')).mode & 0o777, 0o600);

  status = 429;
  lines.length = 0;
  assert.equal(await usageCmd({}, cfg, fetchImpl), 0);
  assert.match(lines.join('\n'), /42%/);
  assert.match(lines.join('\n'), /rate limited, cached just now/);

  // Other failures never fall back: stale numbers would hide a real problem.
  status = 500;
  lines.length = 0;
  assert.equal(await usageCmd({}, cfg, fetchImpl), 1);
  assert.match(lines.join('\n'), /error: usage request failed \(HTTP 500\)/);
  assert.doesNotMatch(lines.join('\n'), /42%/);
});

test('usageCmd reports a 429 as an error when nothing is cached yet', async (t) => {
  sandbox(t);
  const cfg = config();
  saveProfile('work', { credentials: usageCreds(), oauthAccount: {} }, cfg);
  const lines = captureLog(t);
  assert.equal(await usageCmd({}, cfg, async () => ({ ok: false, status: 429 })), 1);
  assert.match(lines.join('\n'), /error: usage request failed \(HTTP 429\)/);
});

test('deleting a profile drops its cached usage', (t) => {
  sandbox(t);
  const cfg = config();
  saveProfile('work', { credentials: usageCreds(), oauthAccount: {} }, cfg);
  fs.mkdirSync(cfg.usageCacheDir, { recursive: true });
  fs.writeFileSync(path.join(cfg.usageCacheDir, 'work.json'), '{}');
  deleteProfileFile('work', cfg);
  assert.equal(fs.existsSync(path.join(cfg.usageCacheDir, 'work.json')), false);
});

test('formatAgo renders coarse relative times', () => {
  const now = 10 * 86400000;
  assert.equal(formatAgo(now - 10000, now), 'just now');
  assert.equal(formatAgo(now - 5 * 60000, now), '5m ago');
  assert.equal(formatAgo(now - 125 * 60000, now), '2h05m ago');
  assert.equal(formatAgo(now - 26 * 3600000, now), '1d02h ago');
});

test('usageCmd fails soft per profile and only exits 1 when all fail', async (t) => {
  sandbox(t);
  const cfg = config();
  const good = JSON.stringify({ claudeAiOauth: { accessToken: 'at-ok', refreshToken: 'rt', expiresAt: Date.now() + 3600000 } });
  const dead = JSON.stringify({ claudeAiOauth: { accessToken: 'at-dead', refreshToken: 'rt-dead', expiresAt: 1 } });
  saveProfile('good', { credentials: good, oauthAccount: {} }, cfg);
  saveProfile('dead', { credentials: dead, oauthAccount: {} }, cfg);
  const fetchImpl = async (url) => {
    if (url.includes('/oauth/token')) return { ok: false, status: 400, json: async () => ({}) };
    return { ok: true, status: 200, json: async () => ({}) };
  };
  const lines = captureLog(t);
  assert.equal(await usageCmd({}, cfg, fetchImpl), 0);
  assert.match(lines.join('\n'), /logged out/);
  deleteProfileFile('good', cfg);
  assert.equal(await usageCmd({}, cfg, fetchImpl), 1);
});

test('usageCmd renders the fable window and keeps every row column-aligned', async (t) => {
  sandbox(t);
  // Column positions are checked by raw string index below, so ANSI color
  // codes (on by default even off a TTY) would throw the count off.
  process.env.NO_COLOR = '1';
  t.after(() => delete process.env.NO_COLOR);
  const cfg = config();
  const creds = () =>
    JSON.stringify({ claudeAiOauth: { accessToken: 'at', refreshToken: 'rt', expiresAt: Date.now() + 3600000 } });
  saveProfile('premium', { credentials: creds(), oauthAccount: { emailAddress: 'p@x.com' } }, cfg);
  saveProfile('plain', { credentials: creds(), oauthAccount: { emailAddress: 'q@x.com' } }, cfg);
  saveProfile('gone', { credentials: creds(), oauthAccount: { emailAddress: 'r@x.com' }, movedAt: new Date().toISOString() }, cfg);
  const bodies = {
    premium: {
      five_hour: { utilization: 10, resets_at: null },
      seven_day: { utilization: 20, resets_at: null },
      limits: [{ kind: 'weekly_scoped', percent: 49, resets_at: null, scope: { model: { display_name: 'Fable' } } }],
    },
    plain: {
      five_hour: { utilization: 10, resets_at: null },
      seven_day: { utilization: 20, resets_at: null },
      limits: [{ kind: 'weekly_all', percent: 20, resets_at: null, scope: null }],
    },
  };
  let nth = 0;
  const lines = captureLog(t);
  assert.equal(
    await usageCmd({}, cfg, async () => ({
      ok: true,
      status: 200,
      json: async () => bodies[['plain', 'premium'][nth++]], // 'gone' is moved: never queried
    })),
    0,
  );
  const out = lines.join('\n').split('\n');
  assert.match(out[0], /7d\s+resets\s+fable\s+resets\s+status/);
  assert.match(out.find((l) => /premium/.test(l)), / 49%/);
  // A moved profile builds its row by hand: check it still has the full column
  // count, or `status` slides silently under the `fable` header.
  const statusCol = out[0].indexOf('status');
  assert.equal(out.find((l) => /premium/.test(l)).indexOf('ok'), statusCol);
  assert.equal(out.find((l) => /gone/.test(l)).indexOf('moved to'), statusCol);
});

test('usageCmd --dry-run touches the network never', async (t) => {
  sandbox(t);
  const cfg = config();
  saveProfile('work', { credentials: usageCreds(), oauthAccount: {} }, cfg);
  const lines = captureLog(t);
  assert.equal(
    await usageCmd({ dryRun: true }, cfg, async () => {
      throw new Error('network hit');
    }),
    0,
  );
  assert.match(lines.join('\n'), /\[dry-run\]/);
});

test('main routes "usage" (dry-run) and help mentions it', async (t) => {
  sandbox(t);
  const cfg = config();
  saveProfile('work', { credentials: usageCreds(), oauthAccount: {} }, cfg);
  const lines = captureLog(t);
  assert.equal(await main(['--dry-run', 'usage']), 0);
  assert.match(lines.join('\n'), /would query usage for "work"/);
  lines.length = 0;
  await main(['--help']);
  assert.match(lines.join('\n'), /ccswitch usage/);
});

// --- Multi-machine chain safety ---------------------------------------------------
// OAuth refresh tokens rotate on every refresh, so a chain is only usable from
// one machine. These tests pin the guardrails that keep two machines from
// revoking each other's logins.

test('export-all ships the live token chain for the active profile, not the stale snapshot', (t) => {
  const { home } = sandbox(t);
  const cfg = config();
  t.after(() => deleteCredentials(cfg));
  seedTwoProfiles(cfg); // live = alpha-refreshed, alpha profile file = stale
  captureLog(t);
  const out = path.join(home, 'all.json');
  exportAll(out, {}, cfg);
  const dumped = JSON.parse(fs.readFileSync(out, 'utf8'));
  assert.equal(dumped.profiles.alpha.credentials, '{"tok":"alpha-refreshed"}');
  assert.equal(dumped.profiles.beta.credentials, '{"tok":"beta"}');
});

test('export ships the live token chain when exporting the active profile', (t) => {
  const { home } = sandbox(t);
  const cfg = config();
  t.after(() => deleteCredentials(cfg));
  seedTwoProfiles(cfg);
  captureLog(t);
  const out = exportProfile('alpha', path.join(home, 'alpha.json'), {}, cfg);
  assert.equal(JSON.parse(fs.readFileSync(out, 'utf8')).credentials, '{"tok":"alpha-refreshed"}');
});

test('export-all --move retires the exported profiles on this machine', (t) => {
  const { home } = sandbox(t);
  const cfg = config();
  t.after(() => deleteCredentials(cfg));
  seedTwoProfiles(cfg); // active = alpha, live login present
  captureLog(t);
  const out = path.join(home, 'all.json');
  exportAll(out, { move: true }, cfg);
  assert.ok(loadProfile('alpha', cfg).movedAt);
  assert.ok(loadProfile('beta', cfg).movedAt);
  assert.throws(() => switchTo('beta', {}, cfg), /moved/);
  assert.throws(() => materializeRunDir('beta', cfg), /moved/);
  // The active profile's chain was the live login: moving it logs this machine out.
  assert.equal(readCredentials(cfg), null);
  assert.equal(readClaudeJson(cfg).oauthAccount, undefined);
  assert.equal(getActive(cfg), null);
});

test('export --move retires the profile locally', (t) => {
  const { home } = sandbox(t);
  const cfg = config();
  t.after(() => deleteCredentials(cfg));
  seedTwoProfiles(cfg);
  captureLog(t);
  exportProfile('beta', path.join(home, 'beta.json'), { move: true }, cfg);
  assert.ok(loadProfile('beta', cfg).movedAt);
  assert.throws(() => switchTo('beta', {}, cfg), /moved/);
});

test('a moved profile shows as moved in usage and is never refreshed', async (t) => {
  sandbox(t);
  const cfg = config();
  saveProfile(
    'gone',
    {
      credentials: JSON.stringify({ claudeAiOauth: { accessToken: 'at', refreshToken: 'rt', expiresAt: 1 } }),
      oauthAccount: { emailAddress: 'g@x.com' },
      movedAt: '2026-01-01T00:00:00.000Z',
    },
    cfg,
  );
  const lines = captureLog(t);
  assert.equal(
    await usageCmd({}, cfg, async () => {
      throw new Error('network hit');
    }),
    1,
  );
  assert.match(lines.join('\n'), /moved to another machine/);
});

test('import-all keeps the live chain when an imported profile matches the live login', (t) => {
  const { home } = sandbox(t);
  const cfg = config();
  t.after(() => deleteCredentials(cfg));
  writeCredentials('{"tok":"mine-live"}', cfg);
  fs.writeFileSync(cfg.claudeJson, JSON.stringify({ oauthAccount: { accountUuid: 'u-1', emailAddress: 'me@x.com' } }));
  const out = path.join(home, 'all.json');
  fs.writeFileSync(
    out,
    JSON.stringify({
      ccswitchExport: 1,
      active: null,
      profiles: {
        mine: { credentials: '{"tok":"foreign-copy"}', oauthAccount: { accountUuid: 'u-1', emailAddress: 'me@x.com' } },
        other: { credentials: '{"tok":"o"}', oauthAccount: { accountUuid: 'u-2' } },
      },
    }),
  );
  captureLog(t);
  importAll(out, {}, cfg);
  assert.equal(loadProfile('mine', cfg).credentials, '{"tok":"mine-live"}'); // this machine's own chain wins
  assert.equal(loadProfile('other', cfg).credentials, '{"tok":"o"}');
});

test('import keeps the live chain when the file matches the live login', (t) => {
  const { home } = sandbox(t);
  const cfg = config();
  t.after(() => deleteCredentials(cfg));
  writeCredentials('{"tok":"mine-live"}', cfg);
  fs.writeFileSync(cfg.claudeJson, JSON.stringify({ oauthAccount: { accountUuid: 'u-1' } }));
  const file = path.join(home, 'one.json');
  fs.writeFileSync(file, JSON.stringify({ credentials: '{"tok":"foreign-copy"}', oauthAccount: { accountUuid: 'u-1' } }));
  captureLog(t);
  importProfile('mine', file, {}, cfg);
  assert.equal(loadProfile('mine', cfg).credentials, '{"tok":"mine-live"}');
});

test('import-all restores a moved profile without --force', (t) => {
  const { home } = sandbox(t);
  const cfg = config();
  saveProfile('work', { credentials: '{"tok":"dead"}', oauthAccount: null, movedAt: '2026-01-01T00:00:00.000Z' }, cfg);
  const out = path.join(home, 'all.json');
  fs.writeFileSync(
    out,
    JSON.stringify({ ccswitchExport: 1, profiles: { work: { credentials: '{"tok":"fresh"}', oauthAccount: null } } }),
  );
  captureLog(t);
  importAll(out, {}, cfg);
  const p = loadProfile('work', cfg);
  assert.equal(p.credentials, '{"tok":"fresh"}');
  assert.equal(p.movedAt, undefined);
});

test('main routes export-all --move', async (t) => {
  const { home } = sandbox(t);
  const cfg = config();
  t.after(() => deleteCredentials(cfg));
  saveProfile('work', { credentials: '{"tok":"w"}', oauthAccount: null }, cfg);
  const out = path.join(home, 'all.json');
  captureLog(t);
  assert.equal(await main(['export-all', out, '--move']), 0);
  assert.ok(loadProfile('work', cfg).movedAt);
});

function captureErr(t) {
  const lines = [];
  const orig = console.error;
  console.error = (...a) => lines.push(a.join(' '));
  t.after(() => { console.error = orig; });
  return lines;
}

test('asCancel turns a readline Ctrl+C abort into a cancel and passes everything else through', () => {
  // What readline/promises actually rejects a pending question with on Ctrl+C.
  const ctrlC = Object.assign(new Error('Aborted with Ctrl+C'), { name: 'AbortError', code: 'ABORT_ERR' });
  assert.ok(asCancel(ctrlC) instanceof CancelledError);
  // DOMException-shaped aborts carry a numeric .code, so the name is the fallback.
  assert.ok(asCancel(new DOMException('Aborted', 'AbortError')) instanceof CancelledError);
  const real = new Error('disk on fire');
  assert.equal(asCancel(real), real);
  assert.equal(asCancel(new UsageError('nope')) instanceof CancelledError, false);
});

test('reportFatal exits 130 on a cancel and never prints a stack trace for it', (t) => {
  const lines = captureErr(t);
  assert.equal(reportFatal(new CancelledError()), 130); // 128 + SIGINT
  assert.equal(lines.join('\n').trim(), 'aborted');
  assert.doesNotMatch(lines.join('\n'), /at .*\(.*\)/);
});

test('reportFatal keeps usage errors terse and real failures debuggable', (t) => {
  const lines = captureErr(t);
  assert.equal(reportFatal(new UsageError('no profile named "x"')), 1);
  assert.equal(lines.at(-1), 'ccswitch: no profile named "x"');
  assert.doesNotMatch(lines.at(-1), /at .*\(.*\)/);
  assert.equal(reportFatal(new Error('disk on fire')), 1);
  assert.match(lines.at(-1), /at .*\(.*\)/); // unexpected failures keep their stack
});

// The two bins are the same file; argv[1] is the only thing telling them apart.
function asBin(t, name) {
  const orig = process.argv[1];
  t.after(() => { process.argv[1] = orig; });
  process.argv[1] = path.join('/usr/local/bin', name);
}

test('progName follows the invoked bin name, and the target follows it', (t) => {
  asBin(t, 'kcswitch');
  assert.equal(progName(), 'kcswitch');
  assert.equal(defaultTarget(), 'kimi');
  process.argv[1] = '/usr/local/bin/ccswitch';
  assert.equal(progName(), 'ccswitch');
  assert.equal(defaultTarget(), 'claude');
});

test('cfg.prog is the command a user would retype, cfg.progBin the bin alone', (t) => {
  sandbox(t);
  asBin(t, 'ccswitch');
  assert.equal(config('claude').prog, 'ccswitch');
  assert.equal(config('claude').progBin, 'ccswitch');
  assert.equal(config('kimi').prog, 'ccswitch kimi'); // reached via the prefix
  assert.equal(config('kimi').progBin, 'ccswitch');
  process.argv[1] = '/usr/local/bin/kcswitch';
  assert.equal(config('kimi').prog, 'kcswitch'); // no prefix needed under this bin
  assert.equal(config('kimi').progBin, 'kcswitch');
});

test('reportFatal names the bin the user actually invoked', (t) => {
  const lines = captureErr(t);
  asBin(t, 'kcswitch');
  assert.equal(reportFatal(new UsageError('no profile named "x"')), 1);
  assert.equal(lines.at(-1), 'kcswitch: no profile named "x"');
  process.argv[1] = '/usr/local/bin/ccswitch';
  reportFatal(new UsageError('no profile named "x"'));
  assert.equal(lines.at(-1), 'ccswitch: no profile named "x"');
});

test('cli: ccswitch still names itself ccswitch', (t) => {
  sandbox(t);
  const r = runCli(['Not-A-Name!']);
  assert.match(r.stderr, /^ccswitch: unknown command/);
  assert.match(r.stderr, /see ccswitch --help/);
  const help = runCli(['--help']);
  assert.match(help.stdout, /usage: ccswitch \[--dry-run\]/);
  assert.match(help.stdout, /\n  ccswitch list /);
});
