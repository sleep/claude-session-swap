#!/usr/bin/env node
// ccswitch — manage multiple Claude Code subscription accounts.
// Credentials live in ~/.claude/.credentials.json on every platform. On
// macOS, Claude Code itself prefers the Keychain, so a lingering Keychain
// entry is read as the freshest copy and evicted on every write — after
// which Claude Code falls back to the credentials file.
// Zero dependencies by design: this tool handles OAuth refresh tokens, so
// every third-party package would be supply-chain attack surface.
import { spawnSync } from 'node:child_process';
import crypto from 'node:crypto';
import fs from 'node:fs';
import { Writable } from 'node:stream';
import os from 'node:os';
import path from 'node:path';
import readline from 'node:readline/promises';
import { pathToFileURL } from 'node:url';

export class UsageError extends Error {}

export function config() {
  return {
    home: process.env.CCSWITCH_HOME || path.join(os.homedir(), '.claude-profiles'),
    credentialsFile:
      process.env.CCSWITCH_CREDENTIALS_FILE || path.join(os.homedir(), '.claude', '.credentials.json'),
    keychainService: process.env.CCSWITCH_KEYCHAIN_SERVICE || 'Claude Code-credentials',
    claudeJson: process.env.CCSWITCH_CLAUDE_JSON || path.join(os.homedir(), '.claude.json'),
    claudeBin: process.env.CCSWITCH_CLAUDE_BIN || 'claude',
  };
}

export function validateName(name) {
  if (typeof name !== 'string' || !/^[a-z0-9-]+$/.test(name)) {
    throw new UsageError(
      `invalid profile name ${JSON.stringify(name)}: use lowercase letters, digits and hyphens`,
    );
  }
  return name;
}

export function ensureHome(cfg = config()) {
  for (const dir of ['', 'profiles', 'backups', 'dirs']) {
    fs.mkdirSync(path.join(cfg.home, dir), { recursive: true, mode: 0o700 });
  }
}

// --- Keychain migration & eviction (macOS only) --------------------------------
// ccswitch no longer stores anything in the Keychain. But Claude Code itself
// prefers the Keychain on macOS, so: a lingering entry is treated as the
// freshest copy on read (claude refreshes tokens into it), and every ccswitch
// write evicts the entry so claude falls back to the credentials file.

export function readKeychainEntry(cfg = config()) {
  if (process.platform !== 'darwin') return null;
  const r = spawnSync('security', ['find-generic-password', '-s', cfg.keychainService, '-w'], {
    encoding: 'utf8',
  });
  if (r.error) return null; // `security` unavailable: nothing to migrate
  if (r.status === 0) return r.stdout.replace(/\n$/, '');
  return null; // absent (44) or unreadable: fall back to the file
}

export function evictKeychainEntry(cfg = config()) {
  if (process.platform !== 'darwin') return;
  const r = spawnSync('security', ['delete-generic-password', '-s', cfg.keychainService], { encoding: 'utf8' });
  if (r.error) return;
  if (r.status === 0 || r.status === 44) return; // deleted, or already absent
  throw new Error(`security delete-generic-password failed: ${r.stderr.trim()}`);
}

// --- File credential store (all platforms) --------------------------------------
// Claude Code keeps the same payload as a 0600 file at ~/.claude/.credentials.json.

function readCredentialsFile(cfg) {
  try {
    return fs.readFileSync(cfg.credentialsFile, 'utf8');
  } catch (err) {
    if (err.code === 'ENOENT') return null;
    throw err;
  }
}

function writeCredentialsFile(payload, cfg) {
  fs.mkdirSync(path.dirname(cfg.credentialsFile), { recursive: true, mode: 0o700 });
  const tmp = `${cfg.credentialsFile}.ccswitch-${process.pid}.tmp`;
  fs.writeFileSync(tmp, payload, { mode: 0o600 });
  fs.renameSync(tmp, cfg.credentialsFile);
}

function deleteCredentialsFile(cfg) {
  fs.rmSync(cfg.credentialsFile, { force: true });
}

// --- Store-agnostic credential access -------------------------------------------

export function readCredentials(cfg = config()) {
  return readKeychainEntry(cfg) ?? readCredentialsFile(cfg);
}

export function writeCredentials(payload, cfg = config()) {
  writeCredentialsFile(payload, cfg);
  evictKeychainEntry(cfg);
}

export function deleteCredentials(cfg = config()) {
  deleteCredentialsFile(cfg);
  evictKeychainEntry(cfg);
}

// --- ~/.claude.json surgical updates ------------------------------------------
// ~/.claude.json holds ~95 unrelated keys (projects, history, settings); only
// the oauthAccount key may ever be touched, and never non-atomically.

export function readClaudeJson(cfg = config()) {
  let raw;
  try {
    raw = fs.readFileSync(cfg.claudeJson, 'utf8');
  } catch (err) {
    if (err.code === 'ENOENT') return {};
    throw err;
  }
  try {
    return JSON.parse(raw);
  } catch {
    throw new Error(`${cfg.claudeJson} is not valid JSON; refusing to touch it`);
  }
}

export function updateOauthAccount(oauthAccount, cfg = config()) {
  const data = readClaudeJson(cfg);
  if (oauthAccount === null) delete data.oauthAccount;
  else data.oauthAccount = oauthAccount;
  const tmp = `${cfg.claudeJson}.ccswitch-${process.pid}.tmp`;
  fs.writeFileSync(tmp, JSON.stringify(data, null, 2), { mode: 0o600 });
  fs.renameSync(tmp, cfg.claudeJson);
}

// --- Encryption at rest (opt-in) -------------------------------------------------
// scrypt-derived key + AES-256-GCM via node:crypto, keeping the zero-dependency
// design. Applies to profiles, backups and exports — never to the live
// ~/.claude/.credentials.json, which Claude Code must read as plaintext.

const SCRYPT = { N: 1 << 15, r: 8, p: 1, maxmem: 128 * 1024 * 1024 };

export function encryptText(plain, passphrase) {
  const salt = crypto.randomBytes(16);
  const key = crypto.scryptSync(passphrase, salt, 32, SCRYPT);
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const data = Buffer.concat([cipher.update(plain, 'utf8'), cipher.final()]);
  return JSON.stringify(
    {
      ccswitchEncrypted: 1,
      kdf: 'scrypt',
      N: SCRYPT.N,
      r: SCRYPT.r,
      p: SCRYPT.p,
      salt: salt.toString('base64'),
      iv: iv.toString('base64'),
      tag: cipher.getAuthTag().toString('base64'),
      data: data.toString('base64'),
    },
    null,
    2,
  );
}

export function decryptText(raw, passphrase) {
  const env_ = typeof raw === 'string' ? JSON.parse(raw) : raw;
  const key = crypto.scryptSync(passphrase, Buffer.from(env_.salt, 'base64'), 32, {
    N: env_.N, r: env_.r, p: env_.p, maxmem: SCRYPT.maxmem,
  });
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, Buffer.from(env_.iv, 'base64'));
  decipher.setAuthTag(Buffer.from(env_.tag, 'base64'));
  try {
    return Buffer.concat([decipher.update(Buffer.from(env_.data, 'base64')), decipher.final()]).toString('utf8');
  } catch {
    throw new UsageError('wrong passphrase (or corrupted encrypted file)');
  }
}

export function isEncrypted(raw) {
  try {
    return JSON.parse(raw)?.ccswitchEncrypted === 1;
  } catch {
    return false;
  }
}

// The passphrase is resolved once per invocation (CCSWITCH_PASSPHRASE, or an
// interactive prompt in main) and cached so the sync file helpers can use it.
let passphraseCache = null;

export function setPassphrase(p) {
  passphraseCache = p;
}

function mustPassphrase() {
  const p = passphraseCache ?? process.env.CCSWITCH_PASSPHRASE;
  if (!p) throw new UsageError('this store is encrypted; set CCSWITCH_PASSPHRASE or run interactively');
  return p;
}

async function promptHidden(question) {
  process.stdout.write(question);
  const muted = new Writable({ write(chunk, enc, cb) { cb(); } });
  const rl = readline.createInterface({ input: process.stdin, output: muted, terminal: true });
  try {
    const answer = await rl.question('');
    process.stdout.write('\n');
    return answer.trim();
  } finally {
    rl.close();
  }
}

export async function requirePassphrase({ confirm = false } = {}) {
  const preset = passphraseCache ?? process.env.CCSWITCH_PASSPHRASE;
  if (preset) {
    passphraseCache = preset;
    return preset;
  }
  if (!process.stdin.isTTY) {
    throw new UsageError('this store is encrypted; set CCSWITCH_PASSPHRASE or run interactively');
  }
  const p = await promptHidden('Passphrase: ');
  if (!p) throw new UsageError('empty passphrase');
  if (confirm && (await promptHidden('Repeat passphrase: ')) !== p) {
    throw new UsageError('passphrases do not match');
  }
  passphraseCache = p;
  return p;
}

// Wrap/unwrap a JSON body according to the store's encryption flag.
function sealBody(body, cfg) {
  return storeEncrypted(cfg) ? encryptText(body, mustPassphrase()) : body;
}

function openBody(raw) {
  return isEncrypted(raw) ? decryptText(raw, mustPassphrase()) : raw;
}

// --- Profile store -------------------------------------------------------------

function profilePath(name, cfg) {
  return path.join(cfg.home, 'profiles', `${name}.json`);
}

export function saveProfile(name, { credentials, oauthAccount, savedAt }, cfg = config()) {
  validateName(name);
  ensureHome(cfg);
  const body = JSON.stringify({ credentials, oauthAccount, savedAt: savedAt ?? new Date().toISOString() }, null, 2);
  fs.writeFileSync(profilePath(name, cfg), sealBody(body, cfg), { mode: 0o600 });
}

export function loadProfile(name, cfg = config()) {
  validateName(name);
  try {
    return JSON.parse(openBody(fs.readFileSync(profilePath(name, cfg), 'utf8')));
  } catch (err) {
    if (err.code === 'ENOENT') {
      throw new UsageError(`no profile named "${name}" (run "ccswitch list")`);
    }
    throw err;
  }
}

export function profileExists(name, cfg = config()) {
  validateName(name);
  return fs.existsSync(profilePath(name, cfg));
}

export function listProfiles(cfg = config()) {
  let files;
  try {
    files = fs.readdirSync(path.join(cfg.home, 'profiles'));
  } catch (err) {
    if (err.code === 'ENOENT') return [];
    throw err;
  }
  return files
    .filter((f) => f.endsWith('.json'))
    .sort()
    .map((f) => ({
      name: f.slice(0, -'.json'.length),
      ...JSON.parse(openBody(fs.readFileSync(path.join(cfg.home, 'profiles', f), 'utf8'))),
    }));
}

export function deleteProfileFile(name, cfg = config()) {
  validateName(name);
  if (!profileExists(name, cfg)) throw new UsageError(`no profile named "${name}"`);
  fs.rmSync(profilePath(name, cfg));
  fs.rmSync(path.join(cfg.home, 'dirs', name), { recursive: true, force: true });
}

function readState(cfg) {
  try {
    return JSON.parse(fs.readFileSync(path.join(cfg.home, 'state.json'), 'utf8'));
  } catch (err) {
    if (err.code === 'ENOENT') return {};
    throw err;
  }
}

function writeState(patch, cfg) {
  ensureHome(cfg);
  fs.writeFileSync(path.join(cfg.home, 'state.json'), JSON.stringify({ ...readState(cfg), ...patch }, null, 2), {
    mode: 0o600,
  });
}

export function getActive(cfg = config()) {
  return readState(cfg).active ?? null;
}

export function setActive(name, cfg = config()) {
  writeState({ active: name }, cfg);
}

export function storeEncrypted(cfg = config()) {
  return readState(cfg).encrypted === true;
}

export function writeBackup(reason, payload, cfg = config()) {
  ensureHome(cfg);
  const stamp = new Date().toISOString().replace(/[:.]/g, '-');
  const file = path.join(cfg.home, 'backups', `${stamp}-${reason}.json`);
  fs.writeFileSync(file, sealBody(JSON.stringify(payload, null, 2), cfg), { mode: 0o600 });
  return file;
}

// --- Core operations -------------------------------------------------------------

export function captureLive(cfg = config()) {
  return {
    credentials: readCredentials(cfg),
    oauthAccount: readClaudeJson(cfg).oauthAccount ?? null,
  };
}

// Missing identity on either side proves nothing; only a definite
// mismatch blocks the save-back.
function sameAccount(a, b) {
  const ka = a?.accountUuid ?? a?.emailAddress;
  const kb = b?.accountUuid ?? b?.emailAddress;
  return !ka || !kb || ka === kb;
}

export function warnIfClaudeRunning() {
  const r = spawnSync('pgrep', ['-x', 'claude'], { encoding: 'utf8' });
  if (r.status === 0) {
    console.error(
      'warning: claude is currently running; open sessions keep the old account and may rewrite the credentials when their token refreshes',
    );
  }
}

export function switchTo(name, { dryRun = false } = {}, cfg = config()) {
  const profile = loadProfile(name, cfg);
  const active = getActive(cfg);
  const email = profile.oauthAccount?.emailAddress ?? 'unknown email';
  if (dryRun) {
    console.log(
      `[dry-run] would back up live credentials, ` +
        `${active ? `save them to profile "${active}", ` : ''}then activate "${name}" (${email})`,
    );
    return;
  }
  const live = captureLive(cfg);
  writeBackup(`switch-to-${name}`, live, cfg);
  let savedBack = false;
  if (active && live.credentials) {
    if (profileExists(active, cfg) && sameAccount(live.oauthAccount, loadProfile(active, cfg).oauthAccount)) {
      saveProfile(active, { credentials: live.credentials, oauthAccount: live.oauthAccount }, cfg);
      savedBack = true;
    } else {
      console.error(
        `warning: the live login doesn't match profile "${active}", so its saved credentials were left untouched`,
      );
    }
  }
  if (active === name && live.credentials) {
    console.log(
      savedBack
        ? `"${name}" is already active; refreshed its saved credentials`
        : `"${name}" is already active`,
    );
    return;
  }
  writeCredentials(profile.credentials, cfg);
  updateOauthAccount(profile.oauthAccount, cfg);
  setActive(name, cfg);
  warnIfClaudeRunning();
  console.log(`switched to "${name}" (${email})`);
}

// --- list / delete ----------------------------------------------------------------

export function tokenExpiry(credentials) {
  try {
    const expiresAt = JSON.parse(credentials)?.claudeAiOauth?.expiresAt;
    return expiresAt ? new Date(expiresAt).toISOString() : '-';
  } catch {
    return '-';
  }
}

export function formatList(cfg = config()) {
  const profiles = listProfiles(cfg);
  if (profiles.length === 0) return 'no profiles yet — save your current login with "ccswitch save <name>"';
  const active = getActive(cfg);
  const header = [' ', 'name', 'email', 'tier', 'token expires', 'saved'];
  const rows = profiles.map((p) => [
    p.name === active ? '*' : ' ',
    p.name,
    p.oauthAccount?.emailAddress ?? '-',
    p.oauthAccount?.organizationRateLimitTier ?? '-',
    tokenExpiry(p.credentials),
    p.savedAt ?? '-',
  ]);
  const widths = header.map((h, i) => Math.max(h.length, ...rows.map((r) => String(r[i]).length)));
  return [header, ...rows]
    .map((r) => r.map((c, i) => String(c).padEnd(widths[i])).join('  ').trimEnd())
    .join('\n');
}

async function promptLine(question) {
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  try {
    return (await rl.question(question)).trim();
  } finally {
    rl.close();
  }
}

export async function deleteProfileCmd(name, { force = false, dryRun = false } = {}, cfg = config()) {
  validateName(name);
  if (getActive(cfg) === name) {
    throw new UsageError(`"${name}" is the active profile; switch away before deleting`);
  }
  if (!profileExists(name, cfg)) throw new UsageError(`no profile named "${name}"`);
  if (dryRun) {
    console.log(`[dry-run] would delete profile "${name}"`);
    return;
  }
  if (!force) {
    const answer = await promptLine(`Delete profile "${name}" and its stored tokens? [y/N] `);
    if (answer.toLowerCase() !== 'y') {
      console.log('aborted');
      return;
    }
  }
  writeBackup(`delete-${name}`, loadProfile(name, cfg), cfg);
  deleteProfileFile(name, cfg);
  console.log(`deleted "${name}"`);
}

// --- Save the live login as a profile ----------------------------------------------

export function saveCurrent(name, { force = false, dryRun = false } = {}, cfg = config()) {
  validateName(name);
  if (profileExists(name, cfg) && !force) {
    throw new UsageError(`profile "${name}" already exists; pass --force to overwrite`);
  }
  if (dryRun) {
    console.log(`[dry-run] would save the current login as profile "${name}"`);
    return;
  }
  const live = captureLive(cfg);
  if (!live.credentials) {
    throw new UsageError('no live Claude Code login found — use "ccswitch login <name>" instead');
  }
  saveProfile(name, live, cfg);
  const active = getActive(cfg);
  if (active && active !== name && profileExists(active, cfg) && sameAccount(live.oauthAccount, loadProfile(active, cfg).oauthAccount)) {
    // The live login already belongs to the active profile; taking over the
    // active pointer would break token save-back for it on the next switch.
    console.error(`note: "${active}" stays the active profile; "${name}" holds a copy of the same login`);
  } else {
    setActive(name, cfg);
  }
  console.log(`saved current login as "${name}" (${live.oauthAccount?.emailAddress ?? 'unknown email'})`);
}

// --- Guided login -----------------------------------------------------------------

export async function login(name, { dryRun = false } = {}, cfg = config()) {
  validateName(name);
  if (profileExists(name, cfg)) {
    throw new UsageError(`profile "${name}" already exists; use "ccswitch ${name}" or delete it first`);
  }
  if (dryRun) {
    console.log(
      `[dry-run] would stash current credentials, launch ${cfg.claudeBin} for login, and save the new account as "${name}"`,
    );
    return;
  }
  ensureHome(cfg);
  const live = captureLive(cfg);
  const active = getActive(cfg);
  writeBackup(`login-${name}`, live, cfg);
  if (live.credentials) {
    if (active) {
      if (profileExists(active, cfg) && sameAccount(live.oauthAccount, loadProfile(active, cfg).oauthAccount)) {
        saveProfile(active, live, cfg);
      } else {
        console.error(
          `warning: the live login doesn't match profile "${active}", so its saved credentials were left untouched`,
        );
      }
    } else {
      const stashName = await promptLine('Current login is not a saved profile. Name to save it under (empty to discard): ');
      if (stashName) {
        validateName(stashName);
        if (profileExists(stashName, cfg) || stashName === name) {
          throw new UsageError(
            `profile "${stashName}" already exists or is reserved for the new login "${name}"; pick another name`,
          );
        }
        saveProfile(stashName, live, cfg);
      }
    }
  }
  deleteCredentials(cfg);
  updateOauthAccount(null, cfg);
  setActive(null, cfg);
  const restore = () => {
    if (live.credentials) {
      writeCredentials(live.credentials, cfg);
      updateOauthAccount(live.oauthAccount, cfg);
      setActive(active, cfg);
    }
  };
  console.log('Launching Claude Code — complete the login it offers, then exit (/exit) to continue.');
  const r = spawnSync(cfg.claudeBin, ['/login'], { stdio: 'inherit' });
  if (r.error) {
    restore();
    throw new Error(`could not launch ${cfg.claudeBin}: ${r.error.message}; previous state restored`);
  }
  const fresh = captureLive(cfg);
  if (!fresh.credentials) {
    restore();
    throw new Error('no new credentials found after login; previous state restored');
  }
  saveProfile(name, fresh, cfg);
  setActive(name, cfg);
  console.log(`logged in and saved profile "${name}" (${fresh.oauthAccount?.emailAddress ?? 'unknown email'})`);
}

// --- Import / export (plaintext transfer between machines) ---------------------
// Profiles already live as plaintext JSON, so moving a session to another
// machine is just copying that file out and back in. These commands never
// touch the Keychain, so unlike switch/login they work on any platform.

function transferPath(name, given) {
  return given ?? `${name}.ccswitch.json`;
}

export function exportProfile(name, dest, { force = false, dryRun = false } = {}, cfg = config()) {
  const profile = loadProfile(name, cfg); // throws UsageError if the profile is missing
  const out = transferPath(name, dest);
  if (dryRun) {
    console.log(`[dry-run] would write profile "${name}" to ${out}`);
    return out;
  }
  if (fs.existsSync(out) && !force) {
    throw new UsageError(`${out} already exists; pass --force to overwrite`);
  }
  const body = JSON.stringify(
    { credentials: profile.credentials, oauthAccount: profile.oauthAccount, savedAt: profile.savedAt ?? null },
    null,
    2,
  );
  fs.writeFileSync(out, sealBody(body, cfg), { mode: 0o600 });
  console.log(
    storeEncrypted(cfg)
      ? `exported "${name}" to ${out} (encrypted with your store passphrase)`
      : `exported "${name}" to ${out} (plaintext — it holds live tokens, so guard it)`,
  );
  return out;
}

export function importProfile(name, src, { force = false, dryRun = false } = {}, cfg = config()) {
  validateName(name);
  const from = transferPath(name, src);
  let raw;
  try {
    raw = fs.readFileSync(from, 'utf8');
  } catch (err) {
    if (err.code === 'ENOENT') throw new UsageError(`no file to import at ${from}`);
    throw err;
  }
  let parsed;
  try {
    parsed = JSON.parse(openBody(raw));
  } catch (err) {
    if (err instanceof UsageError) throw err;
    throw new UsageError(`${from} is not valid JSON`);
  }
  if (!parsed || typeof parsed !== 'object' || !('credentials' in parsed)) {
    throw new UsageError(`${from} is not a ccswitch export (missing "credentials")`);
  }
  if (profileExists(name, cfg) && !force) {
    throw new UsageError(`profile "${name}" already exists; pass --force to overwrite`);
  }
  if (dryRun) {
    console.log(`[dry-run] would import ${from} as profile "${name}"`);
    return;
  }
  saveProfile(name, { credentials: parsed.credentials ?? null, oauthAccount: parsed.oauthAccount ?? null }, cfg);
  console.log(`imported profile "${name}" from ${from} (${parsed.oauthAccount?.emailAddress ?? 'unknown email'})`);
}

// --- Encrypt / decrypt the store (migration) ------------------------------------

export function setStoreEncryption(enabled, cfg = config()) {
  if (storeEncrypted(cfg) === enabled) {
    throw new UsageError(`store is already ${enabled ? 'encrypted' : 'decrypted'}`);
  }
  if (enabled) mustPassphrase(); // fail before flipping the flag, not mid-rewrite
  // Read everything while the current flag still matches the on-disk format.
  const profiles = listProfiles(cfg);
  const backupsDir = path.join(cfg.home, 'backups');
  let backups = [];
  try {
    backups = fs
      .readdirSync(backupsDir)
      .filter((f) => f.endsWith('.json'))
      .map((f) => ({ file: path.join(backupsDir, f), body: openBody(fs.readFileSync(path.join(backupsDir, f), 'utf8')) }));
  } catch (err) {
    if (err.code !== 'ENOENT') throw err;
  }
  writeState({ encrypted: enabled }, cfg);
  for (const p of profiles) saveProfile(p.name, p, cfg);
  for (const b of backups) fs.writeFileSync(b.file, enabled ? encryptText(b.body, mustPassphrase()) : b.body, { mode: 0o600 });
  console.log(
    `${enabled ? 'encrypted' : 'decrypted'} ${profiles.length} profile(s) and ${backups.length} backup(s) in ${cfg.home}`,
  );
}

// --- Whole-store export / import ------------------------------------------------
// Bundles every profile plus the active pointer into one plaintext file, for
// moving the whole store between machines. Backups and run dirs stay local:
// backups are point-in-time recovery data, run dirs are regenerated on demand.

export function exportAll(dest, { force = false, dryRun = false } = {}, cfg = config()) {
  const out = dest ?? 'ccswitch-all.ccswitch.json';
  const profiles = {};
  for (const p of listProfiles(cfg)) {
    profiles[p.name] = { credentials: p.credentials ?? null, oauthAccount: p.oauthAccount ?? null, savedAt: p.savedAt ?? null };
  }
  if (Object.keys(profiles).length === 0) {
    throw new UsageError('no profiles to export — save one with "ccswitch save <name>" first');
  }
  if (dryRun) {
    console.log(`[dry-run] would write ${Object.keys(profiles).length} profile(s) to ${out}`);
    return out;
  }
  if (fs.existsSync(out) && !force) {
    throw new UsageError(`${out} already exists; pass --force to overwrite`);
  }
  const body = JSON.stringify(
    { ccswitchExport: 1, exportedAt: new Date().toISOString(), active: getActive(cfg), profiles },
    null,
    2,
  );
  fs.writeFileSync(out, sealBody(body, cfg), { mode: 0o600 });
  console.log(
    storeEncrypted(cfg)
      ? `exported ${Object.keys(profiles).length} profile(s) to ${out} (encrypted with your store passphrase)`
      : `exported ${Object.keys(profiles).length} profile(s) to ${out} (plaintext — it holds live tokens, so guard it)`,
  );
  return out;
}

export function importAll(src, { force = false, dryRun = false } = {}, cfg = config()) {
  const from = src ?? 'ccswitch-all.ccswitch.json';
  let raw;
  try {
    raw = fs.readFileSync(from, 'utf8');
  } catch (err) {
    if (err.code === 'ENOENT') throw new UsageError(`no file to import at ${from}`);
    throw err;
  }
  let parsed;
  try {
    parsed = JSON.parse(openBody(raw));
  } catch (err) {
    if (err instanceof UsageError) throw err;
    throw new UsageError(`${from} is not valid JSON`);
  }
  if (parsed?.ccswitchExport !== 1 || typeof parsed.profiles !== 'object' || parsed.profiles === null) {
    throw new UsageError(`${from} is not a ccswitch full export (missing "ccswitchExport"/"profiles")`);
  }
  const names = Object.keys(parsed.profiles);
  for (const name of names) validateName(name); // reject the whole file before writing anything
  if (dryRun) {
    console.log(`[dry-run] would import ${names.length} profile(s) from ${from}: ${names.join(', ')}`);
    return;
  }
  let imported = 0;
  for (const name of names) {
    if (profileExists(name, cfg) && !force) {
      console.error(`skipping "${name}": profile already exists (pass --force to overwrite)`);
      continue;
    }
    const p = parsed.profiles[name];
    saveProfile(name, { credentials: p.credentials ?? null, oauthAccount: p.oauthAccount ?? null, savedAt: p.savedAt ?? undefined }, cfg);
    imported++;
  }
  // Adopt the exported active pointer only on a machine with no active profile,
  // and only if that profile actually made it across.
  if (!getActive(cfg) && parsed.active && profileExists(parsed.active, cfg)) {
    setActive(parsed.active, cfg);
  }
  console.log(`imported ${imported} of ${names.length} profile(s) from ${from}`);
}

// --- Isolated run (no global mutation) -----------------------------------------

export function materializeRunDir(name, cfg = config()) {
  const profile = loadProfile(name, cfg);
  const dir = path.join(cfg.home, 'dirs', name);
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  fs.writeFileSync(path.join(dir, '.credentials.json'), profile.credentials ?? '', { mode: 0o600 });
  const cjPath = path.join(dir, '.claude.json');
  let cj = {};
  if (fs.existsSync(cjPath)) cj = JSON.parse(fs.readFileSync(cjPath, 'utf8'));
  // A bare .claude.json makes claude replay first-run onboarding (theme
  // picker etc.); seed those flags from the user's global config once.
  const global_ = readClaudeJson(cfg);
  for (const key of ['hasCompletedOnboarding', 'theme']) {
    if (cj[key] === undefined && global_[key] !== undefined) cj[key] = global_[key];
  }
  if (cj.hasCompletedOnboarding === undefined) cj.hasCompletedOnboarding = true;
  cj.oauthAccount = profile.oauthAccount;
  fs.writeFileSync(cjPath, JSON.stringify(cj, null, 2), { mode: 0o600 });
  return dir;
}

// OAuth refresh tokens are single-use: once the session refreshes, the
// profile's snapshot is dead. Persist whatever the session left in the run
// dir back into the profile, or the next run starts from a revoked token.
export function saveBackRunDir(name, dir, cfg = config()) {
  let credentials;
  try {
    credentials = fs.readFileSync(path.join(dir, '.credentials.json'), 'utf8');
  } catch {
    return;
  }
  if (!credentials) return;
  let oauthAccount = null;
  try {
    oauthAccount = JSON.parse(fs.readFileSync(path.join(dir, '.claude.json'), 'utf8')).oauthAccount ?? null;
  } catch {}
  const profile = loadProfile(name, cfg);
  if (!sameAccount(oauthAccount, profile.oauthAccount)) {
    console.error(
      `warning: the run session's login doesn't match profile "${name}"; its saved credentials were left untouched`,
    );
    return;
  }
  saveProfile(name, { credentials, oauthAccount: oauthAccount ?? profile.oauthAccount }, cfg);
}

export function runProfile(name, claudeArgs, cfg = config()) {
  const dir = materializeRunDir(name, cfg);
  const r = spawnSync(cfg.claudeBin, claudeArgs, {
    stdio: 'inherit',
    env: { ...process.env, CLAUDE_CONFIG_DIR: dir },
  });
  if (r.error) throw r.error;
  saveBackRunDir(name, dir, cfg);
  return r.status ?? 1;
}

// --- Usage across accounts -------------------------------------------------------
// First (and only) network code in ccswitch: quota lookups and token refresh
// against Anthropic's OAuth endpoints, via built-in fetch. fetchImpl is a
// parameter (like cfg) so tests inject a fake without any mocking library.

const OAUTH_CLIENT_ID = '9d1c250a-e61b-44d9-88ed-5944d1962f5e'; // Claude Code's public client id
const TOKEN_URL = 'https://console.anthropic.com/v1/oauth/token';
const USAGE_URL = 'https://api.anthropic.com/api/oauth/usage';
const EXPIRY_MARGIN_MS = 5 * 60 * 1000;

// A dead chain (revoked/rotated-away refresh token) is a user-fixable state,
// distinct from transient network/server failures.
export class AuthDeadError extends Error {}

export function tokenExpired(credentials, now = Date.now()) {
  try {
    const expiresAt = JSON.parse(credentials)?.claudeAiOauth?.expiresAt;
    if (!expiresAt) return true;
    return new Date(expiresAt).getTime() - EXPIRY_MARGIN_MS <= now;
  } catch {
    return true;
  }
}

export async function refreshCredentials(credentials, fetchImpl = fetch) {
  const parsed = JSON.parse(credentials);
  const oauth = parsed?.claudeAiOauth;
  if (!oauth?.refreshToken) throw new AuthDeadError('no refresh token stored');
  const res = await fetchImpl(TOKEN_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ grant_type: 'refresh_token', refresh_token: oauth.refreshToken, client_id: OAUTH_CLIENT_ID }),
  });
  if (res.status === 400 || res.status === 401 || res.status === 403) {
    throw new AuthDeadError(`refresh rejected (HTTP ${res.status})`);
  }
  if (!res.ok) throw new Error(`token refresh failed (HTTP ${res.status})`);
  const body = await res.json();
  parsed.claudeAiOauth = {
    ...oauth,
    accessToken: body.access_token,
    refreshToken: body.refresh_token ?? oauth.refreshToken,
    expiresAt: Date.now() + (body.expires_in ?? 0) * 1000,
  };
  return JSON.stringify(parsed);
}

export function parseUsage(body) {
  const win = (o) =>
    o && typeof o === 'object'
      ? {
          utilization: typeof o.utilization === 'number' ? o.utilization : null,
          resetsAt: typeof o.resets_at === 'string' ? o.resets_at : null,
        }
      : null;
  return { fiveHour: win(body?.five_hour), sevenDay: win(body?.seven_day) };
}

export async function fetchUsage(credentials, fetchImpl = fetch) {
  const token = JSON.parse(credentials)?.claudeAiOauth?.accessToken;
  if (!token) throw new AuthDeadError('no access token stored');
  const res = await fetchImpl(USAGE_URL, {
    headers: { Authorization: `Bearer ${token}`, 'anthropic-beta': 'oauth-2025-04-20' },
  });
  if (res.status === 401 || res.status === 403) throw new AuthDeadError(`token rejected (HTTP ${res.status})`);
  if (!res.ok) throw new Error(`usage request failed (HTTP ${res.status})`);
  return parseUsage(await res.json());
}

const BAR_WIDTH = 5;
const EIGHTHS = '▏▎▍▌▋▊▉█';

export function formatBar(utilization, { color = false } = {}) {
  if (utilization == null) return '-';
  const pct = Math.max(0, Math.min(100, utilization));
  const eighths = Math.round((pct / 100) * BAR_WIDTH * 8);
  const bar = (EIGHTHS[7].repeat(Math.floor(eighths / 8)) + (eighths % 8 ? EIGHTHS[(eighths % 8) - 1] : '')).padEnd(BAR_WIDTH);
  const label = `${String(Math.round(pct)).padStart(3)}%`;
  if (!color) return `${bar} ${label}`;
  const code = pct > 85 ? 31 : pct >= 60 ? 33 : 32;
  return `\x1b[${code}m${bar}\x1b[0m ${label}`;
}

export function formatResetIn(resetsAt, now = Date.now()) {
  if (!resetsAt) return '-';
  const ms = new Date(resetsAt).getTime() - now;
  if (!Number.isFinite(ms)) return '-';
  if (ms <= 0) return 'now';
  const mins = Math.round(ms / 60000);
  const d = Math.floor(mins / 1440);
  const h = Math.floor((mins % 1440) / 60);
  const m = mins % 60;
  if (d > 0) return `in ${d}d${String(h).padStart(2, '0')}h`;
  if (h > 0) return `in ${h}h${String(m).padStart(2, '0')}m`;
  return `in ${m}m`;
}

// Colored cells contain ANSI escapes, which occupy string length but no
// terminal columns — alignment must measure visible width only.
const visibleWidth = (s) => String(s).replace(/\x1b\[[0-9;]*m/g, '').length;

export function renderTable(header, rows) {
  const widths = header.map((h, i) => Math.max(visibleWidth(h), ...rows.map((r) => visibleWidth(r[i]))));
  return [header, ...rows]
    .map((r) => r.map((c, i) => String(c) + ' '.repeat(widths[i] - visibleWidth(c))).join('  ').trimEnd())
    .join('\n');
}

export async function usageCmd({ dryRun = false } = {}, cfg = config(), fetchImpl = fetch) {
  const profiles = listProfiles(cfg);
  if (profiles.length === 0) {
    console.log('no profiles yet — save your current login with "ccswitch save <name>"');
    return 0;
  }
  const active = getActive(cfg);
  if (dryRun) {
    for (const p of profiles) {
      const credentials = p.name === active ? (readCredentials(cfg) ?? p.credentials) : p.credentials;
      console.log(
        `[dry-run] would query usage for "${p.name}"${tokenExpired(credentials) ? ' (needs token refresh first)' : ''}`,
      );
    }
    return 0;
  }
  const color = process.stdout.isTTY === true;
  const rows = [];
  let succeeded = 0;
  for (const p of profiles) {
    const isActive = p.name === active;
    let credentials = isActive ? (readCredentials(cfg) ?? p.credentials) : p.credentials;
    let status = 'ok';
    let usage = null;
    try {
      if (!credentials) throw new AuthDeadError('no credentials stored');
      if (tokenExpired(credentials)) {
        credentials = await refreshCredentials(credentials, fetchImpl);
        // Persist-before-use: the rotated chain reaches disk before anything
        // can go wrong with the usage call (or the process).
        saveProfile(p.name, { credentials, oauthAccount: p.oauthAccount }, cfg);
        if (isActive) writeCredentials(credentials, cfg);
        status = 'ok (refreshed)';
      }
      usage = await fetchUsage(credentials, fetchImpl);
      succeeded++;
    } catch (err) {
      status = err instanceof AuthDeadError ? `logged out — run "ccswitch login ${p.name}"` : `error: ${err.message}`;
    }
    rows.push([
      isActive ? '*' : ' ',
      p.name,
      p.oauthAccount?.emailAddress ?? '-',
      usage ? formatBar(usage.fiveHour?.utilization ?? null, { color }) : '-',
      usage ? formatResetIn(usage.fiveHour?.resetsAt ?? null) : '-',
      usage ? formatBar(usage.sevenDay?.utilization ?? null, { color }) : '-',
      usage ? formatResetIn(usage.sevenDay?.resetsAt ?? null) : '-',
      status,
    ]);
  }
  console.log(renderTable([' ', 'name', 'email', '5h', 'resets', '7d', 'resets', 'status'], rows));
  return succeeded > 0 ? 0 : 1;
}

// --- CLI --------------------------------------------------------------------------

const HELP = `usage: ccswitch [--dry-run] <command>

  ccswitch                      pick a profile interactively and switch to it
  ccswitch <name>               switch to profile <name>
  ccswitch switch <name>        same as above
  ccswitch login <name>         log a new account in and save it as <name>
  ccswitch save <name>          save the current login as <name> (--force overwrites)
  ccswitch run <name> -- [...]  one-off claude session as <name> (no global switch)
  ccswitch list                 show saved profiles
  ccswitch usage                show 5h/7d quota for every profile (refreshes expired tokens)
  ccswitch delete <name>        delete a profile (--force skips confirmation)
  ccswitch export <name> [file] write a profile to a plaintext file (default <name>.ccswitch.json)
  ccswitch import <name> [file] load a profile from such a file (--force overwrites)
  ccswitch export-all [file]    write ALL profiles + active pointer to one file (default ccswitch-all.ccswitch.json)
  ccswitch import-all [file]    merge such a file into this machine (--force overwrites existing profiles)
  ccswitch encrypt              encrypt profiles, backups and future exports with a passphrase
  ccswitch decrypt              turn passphrase encryption back off (rewrites the store as plaintext)

To use an account on a second machine, run "ccswitch login" there — each
machine gets its own token chain. Export/import moves a login; two machines
sharing one exported chain will log each other out on refresh.

State lives in ~/.claude-profiles. Every mutation writes a backup there first.
Unencrypted stores keep tokens in plaintext; run "ccswitch encrypt" to protect
them at rest. CCSWITCH_PASSPHRASE skips the interactive passphrase prompt.`;

function requireName(name) {
  if (!name) throw new UsageError('missing profile name (see ccswitch --help)');
  return name;
}

async function pickProfile(cfg) {
  const profiles = listProfiles(cfg);
  if (profiles.length === 0) {
    throw new UsageError('no profiles yet — save your current login with "ccswitch save <name>"');
  }
  const active = getActive(cfg);
  for (const [i, p] of profiles.entries()) {
    console.log(`${i + 1}) ${p.name === active ? '*' : ' '} ${p.name} (${p.oauthAccount?.emailAddress ?? '-'})`);
  }
  const answer = await promptLine('Switch to: ');
  const idx = Number(answer) - 1;
  if (!Number.isInteger(idx) || idx < 0 || idx >= profiles.length) {
    throw new UsageError(`invalid selection ${JSON.stringify(answer)}`);
  }
  return profiles[idx].name;
}

export async function main(argv = process.argv.slice(2)) {
  const sep = argv.indexOf('--');
  const head = sep === -1 ? argv : argv.slice(0, sep);
  const tail = sep === -1 ? [] : argv.slice(sep + 1);
  const dryRun = head.includes('--dry-run');
  const args = head.filter((a) => a !== '--dry-run');
  const [cmd, ...rest] = args;
  const cfg = config();

  if (cmd === '--help' || cmd === '-h' || cmd === 'help') {
    console.log(HELP);
    return 0;
  }
  // Resolve the passphrase up front whenever this invocation will need to
  // open sealed data: an encrypted store, or an encrypted import file.
  const fileIsEncrypted = (p) => {
    try {
      return isEncrypted(fs.readFileSync(p, 'utf8'));
    } catch {
      return false;
    }
  };
  const pos = rest.filter((a) => a !== '--force');
  const importSrc =
    cmd === 'import' ? (pos[1] ?? (pos[0] ? `${pos[0]}.ccswitch.json` : null))
    : cmd === 'import-all' ? (pos[0] ?? 'ccswitch-all.ccswitch.json')
    : null;
  if (storeEncrypted(cfg) || (importSrc && fileIsEncrypted(importSrc))) {
    await requirePassphrase();
  }
  if (!cmd) {
    switchTo(await pickProfile(cfg), { dryRun }, cfg);
    return 0;
  }
  switch (cmd) {
    case 'login':
      await login(requireName(rest[0]), { dryRun }, cfg);
      return 0;
    case 'save':
      saveCurrent(requireName(rest.find((a) => a !== '--force')), { force: rest.includes('--force'), dryRun }, cfg);
      return 0;
    case 'switch':
      switchTo(requireName(rest[0]), { dryRun }, cfg);
      return 0;
    case 'list':
      console.log(formatList(cfg));
      return 0;
    case 'usage':
      return usageCmd({ dryRun }, cfg);
    case 'delete':
      await deleteProfileCmd(requireName(rest[0]), { force: rest.includes('--force'), dryRun }, cfg);
      return 0;
    case 'export': {
      const pos = rest.filter((a) => a !== '--force');
      exportProfile(requireName(pos[0]), pos[1], { force: rest.includes('--force'), dryRun }, cfg);
      return 0;
    }
    case 'import': {
      const pos = rest.filter((a) => a !== '--force');
      importProfile(requireName(pos[0]), pos[1], { force: rest.includes('--force'), dryRun }, cfg);
      return 0;
    }
    case 'export-all': {
      const pos = rest.filter((a) => a !== '--force');
      exportAll(pos[0], { force: rest.includes('--force'), dryRun }, cfg);
      return 0;
    }
    case 'import-all': {
      const pos = rest.filter((a) => a !== '--force');
      importAll(pos[0], { force: rest.includes('--force'), dryRun }, cfg);
      return 0;
    }
    case 'encrypt': {
      if (storeEncrypted(cfg)) throw new UsageError('store is already encrypted');
      if (dryRun) {
        console.log('[dry-run] would encrypt all profiles and backups with a passphrase');
        return 0;
      }
      await requirePassphrase({ confirm: true });
      setStoreEncryption(true, cfg);
      return 0;
    }
    case 'decrypt': {
      if (!storeEncrypted(cfg)) throw new UsageError('store is not encrypted');
      if (dryRun) {
        console.log('[dry-run] would rewrite all profiles and backups as plaintext');
        return 0;
      }
      setStoreEncryption(false, cfg);
      return 0;
    }
    case 'run': {
      requireName(rest[0]);
      if (dryRun) {
        console.log(`[dry-run] would launch ${cfg.claudeBin} with CLAUDE_CONFIG_DIR for "${rest[0]}"`);
        return 0;
      }
      return runProfile(rest[0], tail, cfg);
    }
    default:
      if (/^[a-z0-9-]+$/.test(cmd)) {
        switchTo(cmd, { dryRun }, cfg); // shorthand: ccswitch <name>
        return 0;
      }
      throw new UsageError(`unknown command ${JSON.stringify(cmd)} (see ccswitch --help)`);
  }
}

const invokedDirectly = (() => {
  if (!process.argv[1]) return false;
  try {
    return import.meta.url === pathToFileURL(fs.realpathSync(process.argv[1])).href;
  } catch {
    return false;
  }
})();

if (invokedDirectly) {
  main()
    .then((code) => process.exit(code ?? 0))
    .catch((err) => {
      console.error(`ccswitch: ${err instanceof UsageError ? err.message : (err.stack ?? err.message)}`);
      process.exit(1);
    });
}
