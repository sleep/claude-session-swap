import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';

import { config, validateName, ensureHome, UsageError, readCredentials, writeCredentials, deleteCredentials, readKeychain, writeKeychain, deleteKeychain, readClaudeJson, updateOauthAccount, saveProfile, loadProfile, profileExists, listProfiles, deleteProfileFile, getActive, setActive, writeBackup, captureLive, switchTo, tokenExpiry, formatList, deleteProfileCmd, login, saveCurrent, exportProfile, importProfile, materializeRunDir, runProfile, main } from '../ccswitch.mjs';

// Every test calls sandbox(t) first: all ccswitch state goes to a temp dir,
// and the credential store is forced to a temp file so the suite runs on any
// platform and the real login (Keychain or ~/.claude/.credentials.json) is
// never touched. The macOS Keychain adapter has its own darwin-only test.
export function sandbox(t) {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'ccswitch-test-'));
  process.env.CCSWITCH_HOME = path.join(home, 'profiles-home');
  process.env.CCSWITCH_CLAUDE_JSON = path.join(home, 'claude.json');
  process.env.CCSWITCH_CRED_STORE = 'file';
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
  assert.equal(cfg.credStore, 'file');
  assert.equal(cfg.credentialsFile, path.join(home, 'credentials.json'));
});

test('config defaults the credential store by platform', (t) => {
  sandbox(t);
  delete process.env.CCSWITCH_CRED_STORE;
  t.after(() => { process.env.CCSWITCH_CRED_STORE = 'file'; });
  const cfg = config();
  assert.equal(cfg.credStore, process.platform === 'darwin' ? 'keychain' : 'file');
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

test('keychain adapter round-trips a payload', { skip: process.platform !== 'darwin' && 'macOS only' }, (t) => {
  sandbox(t);
  const cfg = config();
  t.after(() => deleteKeychain(cfg));
  assert.equal(readKeychain(cfg), null);
  writeKeychain('{"claudeAiOauth":{"accessToken":"tok-1"}}', cfg);
  assert.equal(readKeychain(cfg), '{"claudeAiOauth":{"accessToken":"tok-1"}}');
  writeKeychain('{"claudeAiOauth":{"accessToken":"tok-2"}}', cfg); // upsert
  assert.equal(readKeychain(cfg), '{"claudeAiOauth":{"accessToken":"tok-2"}}');
  deleteKeychain(cfg);
  assert.equal(readKeychain(cfg), null);
  deleteKeychain(cfg); // deleting a missing entry must not throw
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

test('login refuses an existing profile name', async (t) => {
  sandbox(t);
  const cfg = config();
  saveProfile('work', { credentials: 'x', oauthAccount: null }, cfg);
  await assert.rejects(() => login('work', {}, cfg), UsageError);
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

test('materializeRunDir writes credentials and identity, preserves extras', (t) => {
  sandbox(t);
  const cfg = config();
  saveProfile('work', { credentials: '{"tok":"w"}', oauthAccount: { emailAddress: 'w@x.com' } }, cfg);
  const dir = materializeRunDir('work', cfg);
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

const CLI = new URL('../ccswitch.mjs', import.meta.url).pathname;

function runCli(args, env = {}) {
  return spawnSync(process.execPath, [CLI, ...args], {
    encoding: 'utf8',
    env: { ...process.env, ...env },
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
