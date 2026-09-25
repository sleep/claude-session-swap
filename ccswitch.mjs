#!/usr/bin/env node
// ccswitch — manage multiple Claude Code and Kimi Code subscription accounts.
// Claude credentials live in ~/.claude/.credentials.json on every platform. On
// macOS, Claude Code itself prefers the Keychain, so a lingering Keychain
// entry is read as the freshest copy and evicted on every write — after
// which Claude Code falls back to the credentials file.
// Kimi credentials live at <KIMI_CODE_HOME>/credentials/kimi-code.json
// (file-only, every platform); a leading "kimi" in the command line selects
// that backend, as does running under the "kcswitch" bin name.
// Zero dependencies by design: this tool handles OAuth refresh tokens, so
// every third-party package would be supply-chain attack surface.
import { spawnSync } from 'node:child_process';
import crypto from 'node:crypto';
import fs from 'node:fs';
import { Writable } from 'node:stream';
import os from 'node:os';
import path from 'node:path';
import readline from 'node:readline/promises';
import { emitKeypressEvents } from 'node:readline';
import { pathToFileURL } from 'node:url';

import { GpgError, createPgp, ensureGpg, findGpg, generateKey, listSecretKeys } from './lib/gpg.mjs';
import { buildEnvelope, canonicalJson, digestMap, mergeVaults } from './lib/sync-protocol.mjs';

export class UsageError extends Error {}

// Sync trouble is reported and then ignored: the local store keeps working.
export class SyncError extends Error {}

// A prompt the user walked away from, as opposed to something going wrong.
export class CancelledError extends Error {}

// readline/promises does not let Ctrl+C at a prompt raise SIGINT: it rejects the
// pending question with an AbortError instead. Left alone that reads as a crash,
// so translate it into a cancel. Node's AbortError carries code ABORT_ERR while a
// DOMException-shaped one carries a numeric code, hence the two checks.
export function asCancel(err) {
  if (err?.code === 'ABORT_ERR' || err?.name === 'AbortError') {
    return new CancelledError('cancelled at a prompt');
  }
  return err;
}

// The same script ships under two bin names; argv[0] is all that separates them.
// Exact match only: anything looser would also catch lookalike paths (test
// files, editor backups) and silently flip the backend.
export function progName() {
  return path.basename(process.argv[1] ?? '') === 'kcswitch' ? 'kcswitch' : 'ccswitch';
}

// Installed under the "kcswitch" bin name, the tool defaults to kimi.
export function defaultTarget() {
  return progName() === 'kcswitch' ? 'kimi' : 'claude';
}

// Last-known usage per profile lives outside the profile store: it is
// disposable, holds no secrets, and should not ride along in backups/exports.
function usageCacheRoot() {
  if (process.env.CCSWITCH_CACHE_DIR) return path.join(process.env.CCSWITCH_CACHE_DIR, 'usage');
  const base = process.env.XDG_CACHE_HOME || path.join(os.homedir(), '.cache');
  return path.join(base, 'ccswitch', 'usage');
}

export function config(target = defaultTarget()) {
  if (target === 'kimi') {
    const kimiHome =
      process.env.KCSWITCH_KIMI_HOME || process.env.KIMI_CODE_HOME || path.join(os.homedir(), '.kimi-code');
    const bin = process.env.KCSWITCH_KIMI_BIN || 'kimi';
    return {
      target: 'kimi',
      progBin: progName(),
      // Under the kcswitch bin the kimi store needs no prefix; under ccswitch it does.
      prog: progName() === 'kcswitch' ? 'kcswitch' : 'ccswitch kimi',
      toolName: 'Kimi Code',
      home: process.env.KCSWITCH_HOME || path.join(os.homedir(), '.kimi-profiles'),
      usageCacheDir: path.join(usageCacheRoot(), 'kimi'),
      credentialsFile:
        process.env.KCSWITCH_CREDENTIALS_FILE || path.join(kimiHome, 'credentials', 'kimi-code.json'),
      kimiHome,
      kimiBin: bin,
      bin,
      loginArgs: ['login'],
      runEnvVar: 'KIMI_CODE_HOME',
      procName: 'kimi',
    };
  }
  const bin = process.env.CCSWITCH_CLAUDE_BIN || 'claude';
  return {
    target: 'claude',
    progBin: progName(),
    prog: progName(),
    toolName: 'Claude Code',
    home: process.env.CCSWITCH_HOME || path.join(os.homedir(), '.claude-profiles'),
    usageCacheDir: path.join(usageCacheRoot(), 'claude'),
    credentialsFile:
      process.env.CCSWITCH_CREDENTIALS_FILE || path.join(os.homedir(), '.claude', '.credentials.json'),
    keychainService: process.env.CCSWITCH_KEYCHAIN_SERVICE || 'Claude Code-credentials',
    claudeJson: process.env.CCSWITCH_CLAUDE_JSON || path.join(os.homedir(), '.claude.json'),
    claudeBin: bin,
    bin,
    loginArgs: ['/login'],
    runEnvVar: 'CLAUDE_CONFIG_DIR',
    procName: 'claude',
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
  if (!cfg.keychainService) return null; // kimi: file-only credential store
  if (process.platform !== 'darwin') return null;
  const r = spawnSync('security', ['find-generic-password', '-s', cfg.keychainService, '-w'], {
    encoding: 'utf8',
  });
  if (r.error) return null; // `security` unavailable: nothing to migrate
  if (r.status === 0) return r.stdout.replace(/\n$/, '');
  return null; // absent (44) or unreadable: fall back to the file
}

export function evictKeychainEntry(cfg = config()) {
  if (!cfg.keychainService) return; // kimi: no Keychain involvement
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
// Kimi has no such identity file — its access-token JWT carries the account —
// so both functions degrade to no-ops for a kimi cfg.

export function readClaudeJson(cfg = config()) {
  if (!cfg.claudeJson) return {};
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
  if (!cfg.claudeJson) return; // kimi: identity lives in the token, not a file
  const data = readClaudeJson(cfg);
  if (oauthAccount === null) delete data.oauthAccount;
  else data.oauthAccount = oauthAccount;
  const tmp = `${cfg.claudeJson}.ccswitch-${process.pid}.tmp`;
  fs.writeFileSync(tmp, JSON.stringify(data, null, 2), { mode: 0o600 });
  fs.renameSync(tmp, cfg.claudeJson);
}

// --- Kimi Code backend ----------------------------------------------------------
// Kimi Code keeps a single login at <KIMI_CODE_HOME>/credentials/kimi-code.json
// ({access_token, refresh_token, expires_at, scope, token_type, expires_in},
// expires_at in unix seconds). The access token is a JWT whose `sub` is the
// account's user id — the only on-disk identity, since kimi has no
// ~/.claude.json-style account record. Display fields (nickname, email, level)
// come from best-effort GETs to <baseUrl>/me and are cached in the profile.

const KIMI_CLIENT_ID = '17e5f671-d194-4dfb-9706-5516cb48c098'; // kimi-code's public client id
const KIMI_DEFAULT_OAUTH_HOST = 'https://auth.kimi.com';
const KIMI_DEFAULT_BASE_URL = 'https://api.kimi.com/coding/v1';

export function decodeJwtPayload(token) {
  try {
    const part = String(token).split('.')[1];
    if (!part) return null;
    return JSON.parse(Buffer.from(part, 'base64url').toString('utf8'));
  } catch {
    return null;
  }
}

export function kimiIdentityFromCredentials(credentials) {
  try {
    const userId = decodeJwtPayload(JSON.parse(credentials)?.access_token)?.sub;
    return typeof userId === 'string' && userId ? { userId } : null;
  } catch {
    return null;
  }
}

// Region/endpoint hints, mirroring kimi's own resolution order: env override,
// then the persisted login in config.toml's managed-provider section, then the
// mainland-cn default. Parsed with regexes to stay zero-dependency; anything
// unreadable just falls through to the defaults.
export function readKimiConnection(cfg = config('kimi')) {
  let text = '';
  try {
    text = fs.readFileSync(path.join(cfg.kimiHome, 'config.toml'), 'utf8');
  } catch {}
  const sectionBody = (header) => {
    const m = new RegExp(`^\\[${header.replace(/[."[\]]/g, (c) => `\\${c}`)}\\][ \\t]*$`, 'm').exec(text);
    if (!m) return '';
    const rest = text.slice(m.index + m[0].length);
    const next = rest.search(/^\[/m);
    return next === -1 ? rest : rest.slice(0, next);
  };
  const str = (body, key) =>
    new RegExp(`^\\s*${key}\\s*=\\s*"([^"]+)"`, 'm').exec(body)?.[1] ?? null;
  const provider = sectionBody('providers."managed:kimi-code"');
  const oauth = sectionBody('providers."managed:kimi-code".oauth');
  return {
    baseUrl: process.env.KIMI_CODE_BASE_URL ?? str(provider, 'base_url') ?? KIMI_DEFAULT_BASE_URL,
    oauthHost:
      process.env.KIMI_CODE_OAUTH_HOST ?? process.env.KIMI_OAUTH_HOST ?? str(oauth, 'oauthHost') ?? KIMI_DEFAULT_OAUTH_HOST,
  };
}

// Account/level cells for list and usage, across both identity shapes.
function displayAccount(oauthAccount) {
  return oauthAccount?.emailAddress ?? oauthAccount?.nickname ?? oauthAccount?.email ?? oauthAccount?.userId ?? null;
}

function displayTier(oauthAccount) {
  return oauthAccount?.organizationRateLimitTier ?? oauthAccount?.userLevelName ?? null;
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
  const p = passphraseCache ?? process.env.CCSWITCH_PASSPHRASE ?? process.env.KCSWITCH_PASSPHRASE;
  if (!p) throw new UsageError('this store is encrypted; set CCSWITCH_PASSPHRASE/KCSWITCH_PASSPHRASE or run interactively');
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
  } catch (err) {
    throw asCancel(err);
  } finally {
    rl.close();
  }
}

export async function requirePassphrase({ confirm = false } = {}) {
  const preset = passphraseCache ?? process.env.CCSWITCH_PASSPHRASE ?? process.env.KCSWITCH_PASSPHRASE;
  if (preset) {
    passphraseCache = preset;
    return preset;
  }
  if (!process.stdin.isTTY) {
    throw new UsageError('this store is encrypted; set CCSWITCH_PASSPHRASE/KCSWITCH_PASSPHRASE or run interactively');
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

function quietLoadProfile(name, cfg) {
  try {
    return JSON.parse(openBody(fs.readFileSync(profilePath(name, cfg), 'utf8')));
  } catch {
    return null;
  }
}

export function saveProfile(name, { credentials, oauthAccount, savedAt, movedAt, machine, alternates }, cfg = config()) {
  validateName(name);
  ensureHome(cfg);
  // Kimi display fields (nickname, email, level) arrive via best-effort /me
  // lookups; a bare token save-back for the same account must not drop them.
  if (oauthAccount?.userId) {
    const prev = quietLoadProfile(name, cfg);
    if (prev?.oauthAccount?.userId === oauthAccount.userId) {
      oauthAccount = {
        ...prev.oauthAccount,
        ...Object.fromEntries(Object.entries(oauthAccount).filter(([, v]) => v != null)),
      };
    }
  }
  // machine and alternates come from sync: which machine last saved this
  // chain, and rival chains from a double refresh awaiting a probe.
  const body = JSON.stringify(
    {
      credentials,
      oauthAccount,
      savedAt: savedAt ?? new Date().toISOString(),
      ...(movedAt ? { movedAt } : {}),
      ...(machine ? { machine } : {}),
      ...(Array.isArray(alternates) && alternates.length > 0 ? { alternates } : {}),
    },
    null,
    2,
  );
  fs.writeFileSync(profilePath(name, cfg), sealBody(body, cfg), { mode: 0o600 });
}

export function loadProfile(name, cfg = config()) {
  validateName(name);
  try {
    return JSON.parse(openBody(fs.readFileSync(profilePath(name, cfg), 'utf8')));
  } catch (err) {
    if (err.code === 'ENOENT') {
      throw new UsageError(`no profile named "${name}" (run "${cfg.prog} list")`);
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
  fs.rmSync(path.join(cfg.usageCacheDir, `${name}.json`), { force: true });
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

// Sync settings live beside state.json: server URL, signing key, this
// machine's label, and the bookkeeping the three-way merge needs.
export function readSyncConfig(cfg = config()) {
  try {
    return JSON.parse(fs.readFileSync(path.join(cfg.home, 'sync.json'), 'utf8'));
  } catch (err) {
    if (err.code === 'ENOENT') return null;
    throw err;
  }
}

export function writeSyncConfig(patch, cfg = config(), { replace = false } = {}) {
  ensureHome(cfg);
  const next = replace ? patch : { ...(readSyncConfig(cfg) ?? {}), ...patch };
  fs.writeFileSync(path.join(cfg.home, 'sync.json'), JSON.stringify(next, null, 2), { mode: 0o600 });
  return next;
}

export function localMachine(cfg = config()) {
  return readSyncConfig(cfg)?.machine ?? null;
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
  const credentials = readCredentials(cfg);
  if (cfg.target === 'kimi') {
    return { credentials, oauthAccount: kimiIdentityFromCredentials(credentials) };
  }
  return {
    credentials,
    oauthAccount: readClaudeJson(cfg).oauthAccount ?? null,
  };
}

// Identity keys by backend shape: claude's oauthAccount carries
// accountUuid/emailAddress, kimi's carries userId (from the token JWT) plus
// email from /me lookups. No backend's shape has another's keys.
function identityKey(a) {
  return a?.accountUuid ?? a?.userId ?? a?.emailAddress ?? a?.email ?? null;
}

// Missing identity on either side proves nothing; only a definite
// mismatch blocks the save-back.
function sameAccount(a, b) {
  const ka = identityKey(a);
  const kb = identityKey(b);
  return !ka || !kb || ka === kb;
}

// Import needs the opposite bias: only a definite identity match may let the
// machine's own live chain override incoming credentials.
function definitelySameAccount(a, b) {
  const ka = identityKey(a);
  const kb = identityKey(b);
  return !!ka && !!kb && ka === kb;
}

// Token chains rotate on refresh, so a chain moved to another machine must
// never be used from here again: replaying it revokes the account everywhere.
function assertNotMoved(name, profile, cfg = config()) {
  if (profile.movedAt) {
    throw new UsageError(
      `profile "${name}" was moved to another machine on ${profile.movedAt}; ` +
        `run "${cfg.prog} login ${name}" for a fresh chain here, or import it back`,
    );
  }
}

export function warnIfToolRunning(cfg = config()) {
  const r = spawnSync('pgrep', ['-x', cfg.procName], { encoding: 'utf8' });
  if (r.status === 0) {
    console.error(
      `warning: ${cfg.procName} is currently running; open sessions keep the old account and may rewrite the credentials when their token refreshes`,
    );
  }
}

export function warnIfClaudeRunning() {
  warnIfToolRunning(config());
}

export function switchTo(name, { dryRun = false } = {}, cfg = config()) {
  const profile = loadProfile(name, cfg);
  assertNotMoved(name, profile, cfg);
  const active = getActive(cfg);
  const email = displayAccount(profile.oauthAccount) ?? 'unknown email';
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
  warnIfToolRunning(cfg);
  console.log(`switched to "${name}" (${email})`);
}

// --- list / delete ----------------------------------------------------------------

// Claude stores expiresAt in milliseconds under claudeAiOauth; kimi stores
// expires_at in unix seconds at the top level.
function expiryMs(parsed) {
  const claude = parsed?.claudeAiOauth?.expiresAt;
  if (claude) return claude;
  const kimi = parsed?.expires_at;
  return typeof kimi === 'number' ? kimi * 1000 : null;
}

export function tokenExpiry(credentials) {
  try {
    const ms = expiryMs(JSON.parse(credentials));
    return ms ? new Date(ms).toISOString() : '-';
  } catch {
    return '-';
  }
}

export function formatList(cfg = config()) {
  const profiles = listProfiles(cfg);
  if (profiles.length === 0) return `no profiles yet — save your current login with "${cfg.prog} save <name>"`;
  const active = getActive(cfg);
  const header =
    cfg.target === 'kimi'
      ? [' ', 'name', 'account', 'level', 'token expires', 'saved']
      : [' ', 'name', 'email', 'tier', 'token expires', 'saved'];
  const rows = profiles.map((p) => [
    p.name === active ? '*' : ' ',
    p.name,
    displayAccount(p.oauthAccount) ?? '-',
    displayTier(p.oauthAccount) ?? '-',
    p.movedAt ? 'moved' : tokenExpiry(p.credentials),
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
  } catch (err) {
    throw asCancel(err);
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
  recordTombstone(name, cfg);
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
    throw new UsageError(`no live ${cfg.toolName} login found — use "${cfg.prog} login <name>" instead`);
  }
  if (cfg.target === 'kimi') {
    // Record the region endpoints this login resolves to, so later refreshes
    // and usage lookups hit the right deployment.
    live.oauthAccount = { ...readKimiConnection(cfg), ...(live.oauthAccount ?? {}) };
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
  console.log(`saved current login as "${name}" (${displayAccount(live.oauthAccount) ?? 'unknown email'})`);
}

// --- Guided login -----------------------------------------------------------------

export async function login(name, { force = false, dryRun = false, region = null, fetchImpl = fetch } = {}, cfg = config()) {
  validateName(name);
  // A moved profile is just a tombstone, so logging back into it needs no --force.
  const existing = profileExists(name, cfg) ? loadProfile(name, cfg) : null;
  if (existing && !existing.movedAt && !force) {
    throw new UsageError(
      `profile "${name}" already exists; use "${cfg.prog} ${name}" to switch to it, or pass --force to re-login and replace it`,
    );
  }
  if (dryRun) {
    console.log(
      `[dry-run] would stash current credentials, launch ${cfg.bin} for login, and save the new account as "${name}"`,
    );
    return;
  }
  ensureHome(cfg);
  const live = captureLive(cfg);
  const active = getActive(cfg);
  writeBackup(`login-${name}`, live, cfg);
  if (existing) writeBackup(`login-replace-${name}`, existing, cfg);
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
  console.log(
    cfg.target === 'kimi'
      ? 'Launching Kimi Code — complete the device-code login it offers, then exit to continue.'
      : 'Launching Claude Code — complete the login it offers, then exit (/exit) to continue.',
  );
  const r = spawnSync(cfg.bin, [...cfg.loginArgs, ...(region ? ['--region', region] : [])], { stdio: 'inherit' });
  if (r.error) {
    restore();
    throw new Error(`could not launch ${cfg.bin}: ${r.error.message}; previous state restored`);
  }
  const fresh = captureLive(cfg);
  if (!fresh.credentials) {
    restore();
    throw new Error('no new credentials found after login; previous state restored');
  }
  if (cfg.target === 'kimi') {
    // Best-effort: region endpoints from config.toml, nickname/email from /me.
    fresh.oauthAccount = await enrichKimiIdentity(fresh.credentials, fresh.oauthAccount, cfg, fetchImpl);
  }
  saveProfile(name, fresh, cfg);
  setActive(name, cfg);
  console.log(`logged in and saved profile "${name}" (${displayAccount(fresh.oauthAccount) ?? 'unknown email'})`);
}

// --- Import / export (plaintext transfer between machines) ---------------------
// Profiles already live as plaintext JSON, so moving a session to another
// machine is just copying that file out and back in. These commands never
// touch the Keychain, so unlike switch/login they work on any platform.

function transferPath(name, given) {
  return given ?? `${name}.ccswitch.json`;
}

export function exportProfile(name, dest, { force = false, move = false, dryRun = false } = {}, cfg = config()) {
  const profile = loadProfile(name, cfg); // throws UsageError if the profile is missing
  assertNotMoved(name, profile, cfg); // its chain already lives elsewhere; exporting it would ship a dead chain
  const out = transferPath(name, dest);
  if (dryRun) {
    console.log(`[dry-run] would write profile "${name}" to ${out}${move ? ' and retire it on this machine' : ''}`);
    return out;
  }
  if (fs.existsSync(out) && !force) {
    throw new UsageError(`${out} already exists; pass --force to overwrite`);
  }
  // The active profile's freshest chain is the live one: claude refreshes it
  // in place, and the profile file only catches up on the next switch.
  let credentials = profile.credentials;
  let tookLive = false;
  if (name === getActive(cfg)) {
    const live = captureLive(cfg);
    if (live.credentials && sameAccount(live.oauthAccount, profile.oauthAccount)) {
      credentials = live.credentials;
      tookLive = true;
    }
  }
  const body = JSON.stringify(
    { credentials, oauthAccount: profile.oauthAccount, savedAt: profile.savedAt ?? null },
    null,
    2,
  );
  fs.writeFileSync(out, sealBody(body, cfg), { mode: 0o600 });
  console.log(
    storeEncrypted(cfg)
      ? `exported "${name}" to ${out} (encrypted with your store passphrase)`
      : `exported "${name}" to ${out} (plaintext - it holds live tokens, so guard it)`,
  );
  if (move) {
    retireProfiles([{ name, credentials, oauthAccount: profile.oauthAccount, savedAt: profile.savedAt, tookLive }], cfg);
  } else {
    console.error(
      'note: the exported chain stays active on this machine; pass --move if another machine will take it over (one chain used from two machines logs both out)',
    );
  }
  return out;
}

// Mark exported profiles as moved so this machine never refreshes their
// chains again; when the live login went with the export, log it out here.
function retireProfiles(entries, cfg) {
  const movedAt = new Date().toISOString();
  const active = getActive(cfg);
  for (const e of entries) {
    saveProfile(e.name, { credentials: e.credentials, oauthAccount: e.oauthAccount, savedAt: e.savedAt ?? undefined, movedAt }, cfg);
  }
  const activeEntry = entries.find((e) => e.name === active);
  if (activeEntry?.tookLive) {
    deleteCredentials(cfg);
    updateOauthAccount(null, cfg);
    setActive(null, cfg);
    console.error(`this machine is now logged out of "${active}": its token chain moved with the export`);
  }
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
  // A moved profile is just a tombstone, so restoring over it needs no --force.
  if (profileExists(name, cfg) && !loadProfile(name, cfg).movedAt && !force) {
    throw new UsageError(`profile "${name}" already exists; pass --force to overwrite`);
  }
  if (dryRun) {
    console.log(`[dry-run] would import ${from} as profile "${name}"`);
    return;
  }
  saveProfile(name, { credentials: adoptLiveChain(name, parsed, cfg), oauthAccount: parsed.oauthAccount ?? null }, cfg);
  console.log(`imported profile "${name}" from ${from} (${parsed.oauthAccount?.emailAddress ?? 'unknown email'})`);
}

// If the imported account is already logged in on this machine, its local
// chain is the one that stays valid here; the imported copy still rotates on
// the source machine, and using it from two machines revokes it everywhere.
function adoptLiveChain(name, incoming, cfg) {
  const live = captureLive(cfg);
  if (live.credentials && definitelySameAccount(live.oauthAccount, incoming.oauthAccount)) {
    console.error(`"${name}" is the login already active on this machine; keeping the local token chain`);
    return live.credentials;
  }
  return incoming.credentials ?? null;
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

export function exportAll(dest, { force = false, move = false, dryRun = false } = {}, cfg = config()) {
  const out = dest ?? 'ccswitch-all.ccswitch.json';
  const active = getActive(cfg);
  const live = captureLive(cfg);
  const profiles = {};
  const entries = [];
  for (const p of listProfiles(cfg)) {
    if (p.movedAt) {
      console.error(`skipping "${p.name}": its chain already moved to another machine`);
      continue;
    }
    // The active profile's freshest chain is the live one: claude refreshes
    // it in place, and the profile file only catches up on the next switch.
    const tookLive = p.name === active && !!live.credentials && sameAccount(live.oauthAccount, p.oauthAccount);
    const credentials = tookLive ? live.credentials : (p.credentials ?? null);
    profiles[p.name] = { credentials, oauthAccount: p.oauthAccount ?? null, savedAt: p.savedAt ?? null };
    entries.push({ name: p.name, credentials, oauthAccount: p.oauthAccount ?? null, savedAt: p.savedAt, tookLive });
  }
  if (entries.length === 0) {
    throw new UsageError(`no profiles to export — save one with "${cfg.prog} save <name>" first`);
  }
  if (dryRun) {
    console.log(`[dry-run] would write ${entries.length} profile(s) to ${out}${move ? ' and retire them on this machine' : ''}`);
    return out;
  }
  if (fs.existsSync(out) && !force) {
    throw new UsageError(`${out} already exists; pass --force to overwrite`);
  }
  const body = JSON.stringify(
    { ccswitchExport: 1, exportedAt: new Date().toISOString(), active, profiles },
    null,
    2,
  );
  fs.writeFileSync(out, sealBody(body, cfg), { mode: 0o600 });
  console.log(
    storeEncrypted(cfg)
      ? `exported ${entries.length} profile(s) to ${out} (encrypted with your store passphrase)`
      : `exported ${entries.length} profile(s) to ${out} (plaintext - it holds live tokens, so guard it)`,
  );
  if (move) {
    retireProfiles(entries, cfg);
  } else {
    console.error(
      'note: the exported chains stay active on this machine; pass --move if another machine will take them over (one chain used from two machines logs both out)',
    );
  }
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
    // A moved profile is just a tombstone, so restoring over it needs no --force.
    if (profileExists(name, cfg) && !loadProfile(name, cfg).movedAt && !force) {
      console.error(`skipping "${name}": profile already exists (pass --force to overwrite)`);
      continue;
    }
    const p = parsed.profiles[name];
    saveProfile(name, { credentials: adoptLiveChain(name, p, cfg), oauthAccount: p.oauthAccount ?? null, savedAt: p.savedAt ?? undefined }, cfg);
    imported++;
  }
  // Adopt the exported active pointer only on a machine with no active profile,
  // and only if that profile actually made it across.
  if (!getActive(cfg) && parsed.active && profileExists(parsed.active, cfg)) {
    setActive(parsed.active, cfg);
  }
  console.log(`imported ${imported} of ${names.length} profile(s) from ${from}`);
}

// --- Sync client ---------------------------------------------------------------------
// Profiles are mirrored into a vault on a ccswitch-server so every machine
// holds the newest chain for each account. The vault is signed and encrypted
// with the user's own OpenPGP key (lib/gpg.mjs) and the server sees only
// ciphertext. Merging is three-way against `base`, the digests each entry had
// after the last sync (lib/sync-protocol.mjs); a double refresh keeps both
// chains as alternates for resolveAlternates to probe.

const SYNC_TIMEOUT_MS = 10_000;

export function syncEnabled(cfg = config()) {
  const sc = readSyncConfig(cfg);
  return !!(sc?.server && sc?.fingerprint);
}

// A delete only reaches other machines as a tombstone in the vault, so it is
// remembered here until it has been pushed (and kept so a stale copy of the
// profile arriving later still loses to it).
export function recordTombstone(name, cfg = config()) {
  if (!syncEnabled(cfg)) return;
  const sc = readSyncConfig(cfg);
  writeSyncConfig({ tombstones: { ...(sc.tombstones ?? {}), [name]: new Date().toISOString() } }, cfg);
}

export function buildLocalVault(cfg = config()) {
  const sc = readSyncConfig(cfg) ?? {};
  const active = getActive(cfg);
  const live = captureLive(cfg);
  const profiles = {};
  for (const p of listProfiles(cfg)) {
    if (p.movedAt) {
      profiles[p.name] = { movedAt: p.movedAt };
      continue;
    }
    let { credentials = null, savedAt = null, machine = null } = p;
    if (p.name === active && live.credentials && live.credentials !== p.credentials && sameAccount(live.oauthAccount, p.oauthAccount)) {
      // The tool refreshed the live chain since the profile was written: that
      // chain is the one to share, and saving it back keeps the profile, the
      // vault and the next run's base digest in agreement.
      credentials = live.credentials;
      savedAt = new Date().toISOString();
      machine = sc.machine ?? machine;
      saveProfile(p.name, { ...p, credentials, oauthAccount: live.oauthAccount ?? p.oauthAccount, savedAt, machine }, cfg);
    }
    // A profile with no label was saved on this machine (save/login write
    // none), so it is labelled here rather than travelling anonymously.
    machine ??= sc.machine ?? null;
    const entry = { credentials, oauthAccount: p.oauthAccount ?? null, savedAt };
    if (machine) entry.machine = machine;
    if (p.alternates?.length) entry.alternates = p.alternates;
    profiles[p.name] = entry;
  }
  for (const [name, deletedAt] of Object.entries(sc.tombstones ?? {})) {
    if (!profiles[name]) profiles[name] = { deletedAt, ...(sc.machine ? { machine: sc.machine } : {}) };
  }
  return profiles;
}

export function applyMerge(merged, { write, delete: del }, cfg = config()) {
  if (write.length === 0 && del.length === 0) return;
  writeBackup('sync-pull', Object.fromEntries([...write, ...del].map((n) => [n, quietLoadProfile(n, cfg)])), cfg);
  const active = getActive(cfg);
  const tombstones = { ...(readSyncConfig(cfg)?.tombstones ?? {}) };
  for (const name of write) {
    const e = merged[name];
    saveProfile(
      name,
      { credentials: e.credentials, oauthAccount: e.oauthAccount ?? null, savedAt: e.savedAt ?? undefined, machine: e.machine, alternates: e.alternates },
      cfg,
    );
    delete tombstones[name];
    if (name === active && e.credentials && readCredentials(cfg) !== e.credentials) {
      writeCredentials(e.credentials, cfg);
      updateOauthAccount(e.oauthAccount ?? null, cfg);
      warnIfToolRunning(cfg);
    }
  }
  for (const name of del) {
    if (profileExists(name, cfg)) deleteProfileFile(name, cfg);
    // The live login stays; only the pointer goes, so the next switch cannot
    // save the live chain back under a name that no longer exists.
    if (name === active) setActive(null, cfg);
    tombstones[name] = merged[name].deletedAt;
  }
  writeSyncConfig({ tombstones }, cfg);
}

async function syncRequest(op, { baseVersion, data }, cfg, { pgp, fetchImpl, now }) {
  const sc = readSyncConfig(cfg);
  let body;
  try {
    body = buildEnvelope({ op, vault: cfg.target, baseVersion, data }, pgp, now());
  } catch (err) {
    throw new SyncError(`gpg could not sign the request: ${err.message}`);
  }
  let res;
  try {
    res = await fetchImpl(`${sc.server.replace(/\/+$/, '')}/v1/vaults/${cfg.target}`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(SYNC_TIMEOUT_MS),
    });
  } catch (err) {
    throw new SyncError(`could not reach ${sc.server}: ${err.cause?.message ?? err.message}`);
  }
  const text = await res.text();
  let json = null;
  try {
    json = JSON.parse(text);
  } catch {}
  if (res.status === 404) throw new SyncError('server answered 404: wrong sync URL (the secret path must match the server)');
  if (res.status === 401) throw new SyncError(`server rejected the signature (${json?.error ?? 'no detail'})`);
  if (res.status === 409) return { status: 409, version: json.version, data: json.data };
  if (!res.ok) throw new SyncError(`server error HTTP ${res.status}: ${json?.error ?? text.slice(0, 200)}`);
  return { status: 200, ...json };
}

// The plaintext names its own vault and version so a server (or anyone on
// the wire) cannot hand back a different vault or an older copy unnoticed.
function openVault(data, version, cfg, pgp) {
  let text;
  try {
    text = pgp.decrypt(data);
  } catch (err) {
    throw new SyncError(`could not decrypt the vault: ${err.message}`);
  }
  let v;
  try {
    v = JSON.parse(text);
  } catch {
    throw new SyncError('vault is not JSON');
  }
  if (v?.ccswitchVault !== 1 || !v.profiles || typeof v.profiles !== 'object') throw new SyncError('vault has an unknown format');
  if (v.vault !== cfg.target) throw new SyncError(`server returned the "${v.vault}" vault instead of "${cfg.target}"`);
  if (v.version !== version) throw new SyncError(`vault version mismatch (blob says ${v.version}, server says ${version}); refusing it`);
  for (const name of Object.keys(v.profiles)) validateName(name);
  return v.profiles;
}

function sealVault(profiles, version, cfg, pgp) {
  try {
    return pgp.encrypt(JSON.stringify({ ccswitchVault: 1, vault: cfg.target, version, profiles }));
  } catch (err) {
    throw new SyncError(`gpg could not encrypt the vault: ${err.message}`);
  }
}

export function localSyncPending(cfg = config()) {
  const sc = readSyncConfig(cfg);
  return canonicalJson(digestMap(buildLocalVault(cfg))) !== canonicalJson(sc?.base ?? {});
}

export async function syncNow(cfg = config(), { pgp = null, fetchImpl = fetch, now = Date.now } = {}) {
  const sc = readSyncConfig(cfg);
  if (!sc?.server || !sc?.fingerprint) throw new UsageError(`sync is not set up; run "${cfg.prog} sync setup"`);
  pgp ??= createPgp({ fingerprint: sc.fingerprint });
  const deps = { pgp, fetchImpl, now };
  const summary = { pulled: [], deleted: [], pushed: false, version: sc.version ?? 0 };
  let local = buildLocalVault(cfg);
  const got = await syncRequest('get', { baseVersion: 0 }, cfg, deps);
  const known = sc.version ?? 0;
  if (got.version < known || (got.data === null && known > 0)) {
    throw new SyncError(`server returned an older vault (version ${got.version}, last seen ${known}); refusing to roll back`);
  }
  let version = got.version;
  let remote = got.data === null ? {} : openVault(got.data, version, cfg, pgp);
  const finish = (v, merged) => {
    writeSyncConfig({ version: v, lastSyncAt: new Date(now()).toISOString(), base: digestMap(merged) }, cfg);
    summary.version = v;
    return summary;
  };
  for (let attempt = 0; ; attempt++) {
    const { merged, localChanges, remoteStale } = mergeVaults(local, remote, sc.base ?? null);
    applyMerge(merged, localChanges, cfg);
    summary.pulled.push(...localChanges.write);
    summary.deleted.push(...localChanges.delete);
    if (!remoteStale) return finish(version, merged);
    const put = await syncRequest('put', { baseVersion: version, data: sealVault(merged, version + 1, cfg, pgp) }, cfg, deps);
    if (put.status === 200) {
      summary.pushed = true;
      return finish(put.version, merged);
    }
    if (attempt >= 2) throw new SyncError('the vault kept changing on the server; try again');
    version = put.version;
    remote = put.data === null ? {} : openVault(put.data, version, cfg, pgp);
    local = merged;
  }
}

// --- Isolated run (no global mutation) -----------------------------------------

export function materializeRunDir(name, cfg = config()) {
  const profile = loadProfile(name, cfg);
  assertNotMoved(name, profile, cfg);
  const dir = path.join(cfg.home, 'dirs', name);
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  if (cfg.target === 'kimi') {
    // The run dir is a whole KIMI_CODE_HOME: credentials plus a minimal
    // config.toml that pins the region endpoints. The user's own config.toml
    // is never copied — it can hold API keys for other providers.
    const credDir = path.join(dir, 'credentials');
    fs.mkdirSync(credDir, { recursive: true, mode: 0o700 });
    fs.writeFileSync(path.join(credDir, 'kimi-code.json'), profile.credentials ?? '', { mode: 0o600 });
    const confPath = path.join(dir, 'config.toml');
    if (!fs.existsSync(confPath)) {
      const conn = readKimiConnection(cfg);
      const baseUrl = profile.oauthAccount?.baseUrl ?? conn.baseUrl;
      const oauthHost = profile.oauthAccount?.oauthHost ?? conn.oauthHost;
      fs.writeFileSync(
        confPath,
        `[providers."managed:kimi-code"]\ntype = "kimi"\nbase_url = "${baseUrl}"\n\n` +
          `[providers."managed:kimi-code".oauth]\nstorage = "file"\noauthHost = "${oauthHost}"\n`,
        { mode: 0o600 },
      );
    }
    return dir;
  }
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
  const credFile =
    cfg.target === 'kimi' ? path.join(dir, 'credentials', 'kimi-code.json') : path.join(dir, '.credentials.json');
  let credentials;
  try {
    credentials = fs.readFileSync(credFile, 'utf8');
  } catch {
    return;
  }
  if (!credentials) return;
  let oauthAccount = null;
  if (cfg.target === 'kimi') {
    oauthAccount = kimiIdentityFromCredentials(credentials);
  } else {
    try {
      oauthAccount = JSON.parse(fs.readFileSync(path.join(dir, '.claude.json'), 'utf8')).oauthAccount ?? null;
    } catch {}
  }
  const profile = loadProfile(name, cfg);
  if (!sameAccount(oauthAccount, profile.oauthAccount)) {
    console.error(
      `warning: the run session's login doesn't match profile "${name}"; its saved credentials were left untouched`,
    );
    return;
  }
  saveProfile(name, { credentials, oauthAccount: oauthAccount ?? profile.oauthAccount }, cfg);
}

export function runProfile(name, toolArgs, cfg = config()) {
  const dir = materializeRunDir(name, cfg);
  const r = spawnSync(cfg.bin, toolArgs, {
    stdio: 'inherit',
    env: { ...process.env, [cfg.runEnvVar]: dir },
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

// A 429 from the usage endpoint says nothing about the account itself, so the
// rows fall back to the last usage that did come through (see readUsageCache).
export class RateLimitedError extends Error {}

export function writeUsageCache(name, usage, cfg = config(), now = Date.now()) {
  fs.mkdirSync(cfg.usageCacheDir, { recursive: true, mode: 0o700 });
  const file = path.join(cfg.usageCacheDir, `${name}.json`);
  const tmp = `${file}.${process.pid}.tmp`;
  fs.writeFileSync(tmp, JSON.stringify({ fetchedAt: now, usage }), { mode: 0o600 });
  fs.renameSync(tmp, file);
}

// Missing or unreadable cache is just "nothing known yet", never an error:
// the caller already has a real failure to report.
export function readUsageCache(name, cfg = config()) {
  try {
    const rec = JSON.parse(fs.readFileSync(path.join(cfg.usageCacheDir, `${name}.json`), 'utf8'));
    if (typeof rec?.fetchedAt !== 'number' || !rec.usage) return null;
    return rec;
  } catch {
    return null;
  }
}

export function formatAgo(ms, now = Date.now()) {
  const mins = Math.max(0, Math.round((now - ms) / 60000));
  if (mins < 1) return 'just now';
  if (mins < 60) return `${mins}m ago`;
  const h = Math.floor(mins / 60);
  if (h < 24) return `${h}h${String(mins % 60).padStart(2, '0')}m ago`;
  return `${Math.floor(h / 24)}d${String(h % 24).padStart(2, '0')}h ago`;
}

// Shared by both row builders: fetch, cache on success, fall back on 429.
async function usageWithCache(name, cfg, fetchFn) {
  try {
    const usage = await fetchFn();
    try {
      writeUsageCache(name, usage, cfg);
    } catch {
      // An unwritable cache dir only costs the 429 fallback, not this row.
    }
    return { usage, stale: null };
  } catch (err) {
    if (!(err instanceof RateLimitedError)) throw err;
    const cached = readUsageCache(name, cfg);
    if (!cached) throw err;
    return { usage: cached.usage, stale: `rate limited, cached ${formatAgo(cached.fetchedAt)}` };
  }
}

export function tokenExpired(credentials, now = Date.now()) {
  try {
    const ms = expiryMs(JSON.parse(credentials));
    if (!ms) return true;
    return ms - EXPIRY_MARGIN_MS <= now;
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

// Fable's weekly cap does not arrive as a top-level window like five_hour and
// seven_day do. It is an entry in `limits`, scoped to the model, and it reports
// `percent` where the windows report `utilization`. Matching on the model's
// display name rather than on kind === 'weekly_scoped' keeps this from picking
// up a scoped limit belonging to some other model or surface.
const FABLE_MODEL = 'fable';

export function parseFableLimit(body) {
  const limits = Array.isArray(body?.limits) ? body.limits : [];
  const limit = limits.find((l) => l?.scope?.model?.display_name?.toLowerCase() === FABLE_MODEL);
  if (!limit) return null;
  return {
    utilization: typeof limit.percent === 'number' ? limit.percent : null,
    resetsAt: typeof limit.resets_at === 'string' ? limit.resets_at : null,
  };
}

export function parseUsage(body) {
  const win = (o) =>
    o && typeof o === 'object'
      ? {
          utilization: typeof o.utilization === 'number' ? o.utilization : null,
          resetsAt: typeof o.resets_at === 'string' ? o.resets_at : null,
        }
      : null;
  return { fiveHour: win(body?.five_hour), sevenDay: win(body?.seven_day), fable: parseFableLimit(body) };
}

export async function fetchUsage(credentials, fetchImpl = fetch) {
  const token = JSON.parse(credentials)?.claudeAiOauth?.accessToken;
  if (!token) throw new AuthDeadError('no access token stored');
  const res = await fetchImpl(USAGE_URL, {
    headers: { Authorization: `Bearer ${token}`, 'anthropic-beta': 'oauth-2025-04-20' },
  });
  if (res.status === 401 || res.status === 403) throw new AuthDeadError(`token rejected (HTTP ${res.status})`);
  if (res.status === 429) throw new RateLimitedError('usage request failed (HTTP 429)');
  if (!res.ok) throw new Error(`usage request failed (HTTP ${res.status})`);
  return parseUsage(await res.json());
}

// --- Kimi usage / refresh / profile lookups ------------------------------------
// Mirrors of the claude functions above against kimi's endpoints: refresh via
// <oauthHost>/api/oauth/token (form-encoded, like kimi itself), quota via
// GET <baseUrl>/usages, account display fields via GET <baseUrl>/me.

export async function refreshKimiCredentials(credentials, fetchImpl = fetch, { oauthHost } = {}) {
  const parsed = JSON.parse(credentials);
  if (!parsed?.refresh_token) throw new AuthDeadError('no refresh token stored');
  const host = (oauthHost ?? process.env.KIMI_CODE_OAUTH_HOST ?? process.env.KIMI_OAUTH_HOST ?? KIMI_DEFAULT_OAUTH_HOST).replace(
    /\/+$/,
    '',
  );
  const res = await fetchImpl(`${host}/api/oauth/token`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded', Accept: 'application/json' },
    body: new URLSearchParams({
      client_id: KIMI_CLIENT_ID,
      grant_type: 'refresh_token',
      refresh_token: parsed.refresh_token,
    }).toString(),
  });
  const body = await res.json().catch(() => ({}));
  // kimi itself treats 401/403 and invalid_grant as terminal for the chain.
  if (res.status === 401 || res.status === 403 || body?.error === 'invalid_grant') {
    throw new AuthDeadError(`refresh rejected (HTTP ${res.status})`);
  }
  if (!res.ok) throw new Error(`token refresh failed (HTTP ${res.status})`);
  if (typeof body?.access_token !== 'string') throw new Error('token refresh returned no access_token');
  const expiresIn = Number(body.expires_in);
  return JSON.stringify({
    ...parsed,
    access_token: body.access_token,
    refresh_token: typeof body.refresh_token === 'string' ? body.refresh_token : parsed.refresh_token,
    expires_at: Math.floor(Date.now() / 1000) + (Number.isFinite(expiresIn) ? expiresIn : 0),
    ...(typeof body.scope === 'string' ? { scope: body.scope } : {}),
    ...(typeof body.token_type === 'string' ? { token_type: body.token_type } : {}),
    ...(Number.isFinite(expiresIn) ? { expires_in: expiresIn } : {}),
  });
}

const toIntOrNull = (v) => {
  const n = typeof v === 'number' ? v : typeof v === 'string' ? Number(v) : NaN;
  return Number.isFinite(n) ? Math.trunc(n) : null;
};

const KIMI_TIME_UNITS = { TIME_UNIT_MINUTE: 'minute', TIME_UNIT_HOUR: 'hour', TIME_UNIT_DAY: 'day', TIME_UNIT_WEEK: 'week' };

function kimiWindowFrom(raw) {
  const duration = toIntOrNull(raw?.duration);
  const unit = KIMI_TIME_UNITS[raw?.timeUnit] ?? null;
  return duration !== null && unit ? { duration, unit } : null;
}

export function kimiWindowLabel(window) {
  if (!window) return null;
  let { duration, unit } = window;
  if (unit === 'minute' && duration >= 60 && duration % 60 === 0) {
    duration /= 60;
    unit = 'hour';
  }
  const suffix = { minute: 'm', hour: 'h', day: 'd', week: 'w' }[unit];
  return suffix ? `${duration}${suffix}` : null;
}

function kimiUsageRow(raw, { name = null, window = null } = {}) {
  if (!raw || typeof raw !== 'object') return null;
  const used = toIntOrNull(raw.used);
  const limit = toIntOrNull(raw.limit);
  if (used === null && limit === null) return null;
  const w = window ?? kimiWindowFrom(raw.window);
  return {
    name: name ?? (typeof raw.name === 'string' && raw.name ? raw.name : null),
    label: kimiWindowLabel(w),
    used: used ?? 0,
    limit: limit ?? 0,
    utilization: limit ? ((used ?? 0) / limit) * 100 : null,
    resetsAt: typeof raw.resetTime === 'string' && raw.resetTime ? raw.resetTime : null,
  };
}

// The booster wallet reports fixed-point amounts: 1e6 units = 1 cent.
const KIMI_FIXED_POINT_CENTS = 1e6;

function parseKimiBooster(raw) {
  const balance = raw?.balance;
  if (balance?.type !== 'BOOSTER') return null;
  const total = toIntOrNull(balance.amount);
  if (total === null || total <= 0) return null;
  const left = toIntOrNull(balance.amountLeft) ?? 0;
  const currency = raw?.monthlyChargeLimit?.currency || raw?.monthlyUsed?.currency || 'USD';
  return {
    balanceCents: Math.round(left / KIMI_FIXED_POINT_CENTS),
    totalCents: Math.round(total / KIMI_FIXED_POINT_CENTS),
    currency,
  };
}

export function parseKimiUsage(body) {
  const rec = body && typeof body === 'object' ? body : {};
  let summary = kimiUsageRow(rec.usage);
  // kimi treats a windowless summary as the weekly quota.
  if (summary && !summary.label) summary = { ...summary, label: '1w' };
  const limits = [];
  if (Array.isArray(rec.limits)) {
    for (const item of rec.limits) {
      const row = kimiUsageRow(item?.detail, {
        name: typeof item?.name === 'string' && item.name ? item.name : null,
        window: kimiWindowFrom(item?.window),
      });
      if (row) limits.push(row);
    }
  }
  return { summary, limits, booster: parseKimiBooster(rec.boosterWallet) };
}

export async function fetchKimiUsage(credentials, fetchImpl = fetch, { baseUrl } = {}) {
  const token = JSON.parse(credentials)?.access_token;
  if (!token) throw new AuthDeadError('no access token stored');
  const base = (baseUrl ?? process.env.KIMI_CODE_BASE_URL ?? KIMI_DEFAULT_BASE_URL).replace(/\/+$/, '');
  const res = await fetchImpl(`${base}/usages`, {
    headers: { Authorization: `Bearer ${token}`, Accept: 'application/json' },
  });
  if (res.status === 401 || res.status === 403) throw new AuthDeadError(`token rejected (HTTP ${res.status})`);
  if (res.status === 429) throw new RateLimitedError('usage request failed (HTTP 429)');
  if (!res.ok) throw new Error(`usage request failed (HTTP ${res.status})`);
  return parseKimiUsage(await res.json());
}

// /me answers in snake_case; anything unusable degrades to null (callers
// treat the lookup as strictly best-effort).
export async function fetchKimiUserInfo(baseUrl, accessToken, fetchImpl = fetch) {
  try {
    const res = await fetchImpl(`${String(baseUrl).replace(/\/+$/, '')}/me`, {
      headers: { Authorization: `Bearer ${accessToken}`, Accept: 'application/json' },
      signal: AbortSignal.timeout(8000),
    });
    if (!res.ok) return null;
    const body = await res.json();
    const str = (v) => (typeof v === 'string' && v ? v : null);
    if (!str(body?.user_id)) return null;
    return {
      userId: body.user_id,
      nickname: str(body.nickname),
      email: str(body.email),
      userLevelName: str(body.user_level_name),
    };
  } catch {
    return null;
  }
}

// Fill in everything a kimi profile likes to carry: region endpoints from
// config.toml/env, display fields from /me. Never throws — the login must not
// fail just because the profile lookup did.
export async function enrichKimiIdentity(credentials, identity, cfg = config('kimi'), fetchImpl = fetch) {
  const conn = readKimiConnection(cfg);
  const out = { ...conn, ...(identity ?? {}) };
  let accessToken = null;
  try {
    accessToken = JSON.parse(credentials)?.access_token ?? null;
  } catch {}
  if (!accessToken) return out;
  const me = await fetchKimiUserInfo(conn.baseUrl, accessToken, fetchImpl);
  if (me) {
    out.userId = out.userId ?? me.userId;
    if (me.nickname) out.nickname = me.nickname;
    if (me.email) out.email = me.email;
    if (me.userLevelName) out.userLevelName = me.userLevelName;
  }
  return out;
}

export function formatCents(cents, currency) {
  const amount = (cents / 100).toFixed(2);
  return currency === 'USD' ? `$${amount}` : `${currency} ${amount}`;
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

// Cut a line to `max` visible columns without splitting an escape sequence,
// resetting attributes so a clipped color can't bleed into the next line.
function clipLine(line, max) {
  if (visibleWidth(line) <= max) return line;
  let out = '';
  let cols = 0;
  for (const tok of line.match(/\x1b\[[0-9;]*m|[^\x1b]/g) ?? []) {
    if (tok.startsWith('\x1b')) out += tok;
    else if (cols < max) {
      out += tok;
      cols++;
    }
  }
  return out.includes('\x1b') ? out + '\x1b[0m' : out;
}

// `maxWidth` keeps each row to one terminal line: overflow is cut off rather
// than wrapped, so a narrow terminal loses the tail of the status column.
export function renderTable(header, rows, maxWidth = Infinity) {
  const widths = header.map((h, i) => Math.max(visibleWidth(h), ...rows.map((r) => visibleWidth(r[i]))));
  return [header, ...rows]
    .map((r) => clipLine(r.map((c, i) => String(c) + ' '.repeat(widths[i] - visibleWidth(c))).join('  ').trimEnd(), maxWidth))
    .join('\n');
}

const terminalWidth = () => (process.stdout.isTTY && process.stdout.columns) || Infinity;

// Color defaults on, TTY or not: usage is routinely piped through wrappers
// like `watch --color`, which render any ANSI we emit even though our own
// stdout is a pipe there. NO_COLOR (or FORCE_COLOR=0) opts back out, per the
// standard CLI convention, for callers that want plain text.
export function shouldUseColor(env = process.env) {
  if (env.NO_COLOR) return false;
  if (env.FORCE_COLOR === '0') return false;
  return true;
}

const CLAUDE_USAGE_HEADER = [' ', 'name', 'email', '5h', 'resets', '7d', 'resets', 'fable', 'resets', 'status'];

// Shared by usageCmd (prints the table as-is) and pickProfile (adds a "#"
// column and prompts for a selection), so the picker's per-account limits
// stay driven by the exact same fetch/refresh/error logic as `usage`.
async function claudeUsageRows(profiles, active, cfg, fetchImpl, color) {
  const rows = [];
  let succeeded = 0;
  for (let p of profiles) {
    const isActive = p.name === active;
    if (p.alternates?.length && !p.movedAt) {
      p = { name: p.name, ...(await resolveAlternates(p.name, p, cfg, fetchImpl)).profile };
    }
    if (p.movedAt) {
      // The chain rotates on another machine now; refreshing it from here
      // would revoke it there.
      rows.push([
        isActive ? '*' : ' ', p.name, p.oauthAccount?.emailAddress ?? '-', '-', '-', '-', '-', '-', '-',
        'moved to another machine',
      ]);
      continue;
    }
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
      const got = await usageWithCache(p.name, cfg, () => fetchUsage(credentials, fetchImpl));
      usage = got.usage;
      if (got.stale) status = got.stale;
      succeeded++;
    } catch (err) {
      status = err instanceof AuthDeadError ? 'logged out' : `error: ${err.message}`;
    }
    rows.push([
      isActive ? '*' : ' ',
      p.name,
      p.oauthAccount?.emailAddress ?? '-',
      usage ? formatBar(usage.fiveHour?.utilization ?? null, { color }) : '-',
      usage ? formatResetIn(usage.fiveHour?.resetsAt ?? null) : '-',
      usage ? formatBar(usage.sevenDay?.utilization ?? null, { color }) : '-',
      usage ? formatResetIn(usage.sevenDay?.resetsAt ?? null) : '-',
      usage ? formatBar(usage.fable?.utilization ?? null, { color }) : '-',
      usage ? formatResetIn(usage.fable?.resetsAt ?? null) : '-',
      status,
    ]);
  }
  return { header: CLAUDE_USAGE_HEADER, rows, succeeded };
}

export async function usageCmd({ dryRun = false } = {}, cfg = config(), fetchImpl = fetch) {
  if (cfg.target === 'kimi') return kimiUsageCmd({ dryRun }, cfg, fetchImpl);
  const profiles = listProfiles(cfg);
  if (profiles.length === 0) {
    console.log(`no profiles yet — save your current login with "${cfg.prog} save <name>"`);
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
  const { header, rows, succeeded } = await claudeUsageRows(profiles, active, cfg, fetchImpl, shouldUseColor());
  console.log(renderTable(header, rows, terminalWidth()));
  return succeeded > 0 ? 0 : 1;
}

const KIMI_USAGE_HEADER = [' ', 'name', 'account', 'week', 'resets', 'limits', 'booster', 'status'];

// Kimi's /usages shape differs from claude's: a weekly summary row, extra
// scoped limit windows, and a booster wallet balance. Columns follow suit.
// Shared by kimiUsageCmd and pickProfile, same reason as claudeUsageRows above.
async function kimiUsageRows(profiles, active, cfg, fetchImpl, color) {
  const rows = [];
  let succeeded = 0;
  for (let p of profiles) {
    const isActive = p.name === active;
    if (p.alternates?.length && !p.movedAt) {
      p = { name: p.name, ...(await resolveAlternates(p.name, p, cfg, fetchImpl)).profile };
    }
    let account = displayAccount(p.oauthAccount) ?? '-';
    if (p.movedAt) {
      // The chain rotates on another machine now; refreshing it from here
      // would revoke it there.
      rows.push([
        isActive ? '*' : ' ', p.name, account, '-', '-', '-', '-',
        'moved to another machine',
      ]);
      continue;
    }
    let credentials = isActive ? (readCredentials(cfg) ?? p.credentials) : p.credentials;
    let oauthAccount = p.oauthAccount;
    let status = 'ok';
    let usage = null;
    try {
      if (!credentials) throw new AuthDeadError('no credentials stored');
      if (tokenExpired(credentials)) {
        credentials = await refreshKimiCredentials(credentials, fetchImpl, { oauthHost: oauthAccount?.oauthHost });
        // Persist-before-use: the rotated chain reaches disk before anything
        // can go wrong with the usage call (or the process).
        saveProfile(p.name, { credentials, oauthAccount }, cfg);
        if (isActive) writeCredentials(credentials, cfg);
        status = 'ok (refreshed)';
      }
      const baseUrl = oauthAccount?.baseUrl ?? readKimiConnection(cfg).baseUrl;
      const got = await usageWithCache(p.name, cfg, () => fetchKimiUsage(credentials, fetchImpl, { baseUrl }));
      usage = got.usage;
      if (got.stale) status = got.stale;
      succeeded++;
      // Best-effort: cache the account's display fields into the profile so
      // list/usage show a nickname instead of a bare user id.
      const me = await fetchKimiUserInfo(baseUrl, JSON.parse(credentials).accessToken, fetchImpl);
      if (me) {
        const add = {};
        if (!oauthAccount?.nickname && me.nickname) add.nickname = me.nickname;
        if (!oauthAccount?.email && me.email) add.email = me.email;
        if (!oauthAccount?.userLevelName && me.userLevelName) add.userLevelName = me.userLevelName;
        if (Object.keys(add).length > 0 || !oauthAccount?.userId) {
          oauthAccount = { ...oauthAccount, userId: oauthAccount?.userId ?? me.userId, ...add };
          saveProfile(p.name, { credentials, oauthAccount }, cfg);
          account = displayAccount(oauthAccount) ?? account;
        }
      }
    } catch (err) {
      status = err instanceof AuthDeadError ? 'logged out' : `error: ${err.message}`;
    }
    rows.push([
      isActive ? '*' : ' ',
      p.name,
      account,
      usage?.summary ? formatBar(usage.summary.utilization, { color }) : '-',
      usage?.summary ? formatResetIn(usage.summary.resetsAt) : '-',
      usage
        ? usage.limits.length
          ? usage.limits
              .map((l) => `${l.label ?? l.name} ${formatBar(l.utilization, { color })} ${formatResetIn(l.resetsAt)}`)
              .join('  ')
          : '-'
        : '-',
      usage?.booster ? formatCents(usage.booster.balanceCents, usage.booster.currency) : '-',
      status,
    ]);
  }
  return { header: KIMI_USAGE_HEADER, rows, succeeded };
}

export async function kimiUsageCmd({ dryRun = false } = {}, cfg = config('kimi'), fetchImpl = fetch) {
  const profiles = listProfiles(cfg);
  if (profiles.length === 0) {
    console.log(`no profiles yet — save your current login with "${cfg.prog} save <name>"`);
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
  const { header, rows, succeeded } = await kimiUsageRows(profiles, active, cfg, fetchImpl, shouldUseColor());
  console.log(renderTable(header, rows, terminalWidth()));
  return succeeded > 0 ? 0 : 1;
}

// --- Candidate chains -------------------------------------------------------------
// Two machines that both refreshed the same profile between syncs each hold a
// chain the other does not know about. Sync keeps both (see mergeVaults) and
// the next use asks the provider which one still works. Probing goes newest
// first and stops at the first live chain: refreshing a superseded token after
// a newer one already worked is what trips reuse detection and revokes the
// whole family, so the older candidates are only ever touched once the newer
// ones are known to be dead.

async function probeChain(credentials, oauthAccount, cfg, fetchImpl) {
  const kimi = cfg.target === 'kimi';
  const conn = kimi ? readKimiConnection(cfg) : null;
  if (!tokenExpired(credentials)) {
    try {
      if (kimi) await fetchKimiUsage(credentials, fetchImpl, { baseUrl: oauthAccount?.baseUrl ?? conn.baseUrl });
      else await fetchUsage(credentials, fetchImpl);
      return { live: true, credentials };
    } catch (err) {
      // 429 means the token was accepted and only the quota endpoint balked.
      if (err instanceof RateLimitedError) return { live: true, credentials };
      if (!(err instanceof AuthDeadError)) throw err;
    }
  }
  try {
    const fresh = kimi
      ? await refreshKimiCredentials(credentials, fetchImpl, { oauthHost: oauthAccount?.oauthHost ?? conn.oauthHost })
      : await refreshCredentials(credentials, fetchImpl);
    return { live: true, credentials: fresh };
  } catch (err) {
    if (err instanceof AuthDeadError) return { live: false };
    throw err;
  }
}

export async function resolveAlternates(name, profile, cfg = config(), fetchImpl = fetch) {
  const alternates = Array.isArray(profile.alternates) ? profile.alternates : [];
  if (alternates.length === 0) return { profile, resolved: false, live: null };
  const candidates = [{ credentials: profile.credentials, savedAt: profile.savedAt, machine: profile.machine }, ...alternates]
    .filter((c) => typeof c.credentials === 'string')
    .sort((a, b) => (Date.parse(b.savedAt) || 0) - (Date.parse(a.savedAt) || 0));
  const label = (c) => c.machine ?? 'an unknown machine';
  let winner = null;
  try {
    for (const c of candidates) {
      const r = await probeChain(c.credentials, profile.oauthAccount, cfg, fetchImpl);
      if (r.live) {
        winner = { ...c, credentials: r.credentials };
        break;
      }
    }
  } catch (err) {
    // Network trouble proves nothing about any chain; leave them all in place.
    console.error(`"${name}": could not test its candidate chains (${err.message}); keeping all of them for now`);
    return { profile, resolved: false, live: null };
  }
  writeBackup(`resolve-${name}`, profile, cfg);
  const kept = winner ?? candidates[0];
  saveProfile(
    name,
    {
      credentials: kept.credentials,
      oauthAccount: profile.oauthAccount ?? null,
      machine: localMachine(cfg) ?? kept.machine,
      ...(profile.movedAt ? { movedAt: profile.movedAt } : {}),
    },
    cfg,
  );
  if (getActive(cfg) === name && readCredentials(cfg) !== kept.credentials) writeCredentials(kept.credentials, cfg);
  if (winner) {
    const machines = [...new Set(candidates.map(label))].join(' and ');
    console.error(`"${name}": refreshed on both ${machines}; chain from ${label(kept)} is live`);
  } else {
    console.error(`"${name}": every candidate chain is logged out; run "${cfg.prog} login ${name} --force" for a fresh one`);
  }
  return { profile: loadProfile(name, cfg), resolved: true, live: !!winner };
}

// switch/run read the profile synchronously, so main settles any pending
// candidates first; the usage row builders do it inline since they are
// already talking to the provider.
async function resolvePending(name, cfg, fetchImpl = fetch) {
  if (!profileExists(name, cfg)) return;
  const profile = loadProfile(name, cfg);
  if (profile.alternates?.length) await resolveAlternates(name, profile, cfg, fetchImpl);
}

// --- Sync commands and auto-sync ------------------------------------------------------

const SYNC_LOCK_STALE_MS = 60_000;
// Statusline scripts call "usage" every few seconds; one pull a minute is
// plenty, and pushes only happen when something actually changed.
const SYNC_DEBOUNCE_MS = 60_000;
// Read-only or explicitly local commands never sync.
const SYNC_SKIP = new Set(['sync', 'list', 'encrypt', 'decrypt', 'export', 'export-all', 'import', 'import-all']);

// Two ccswitch processes syncing the same home at once would race on
// sync.json and the profiles; the second one just skips its sync.
export async function withSyncLock(cfg, fn) {
  ensureHome(cfg);
  const file = path.join(cfg.home, 'sync.lock');
  const acquire = () => {
    try {
      fs.writeFileSync(file, JSON.stringify({ pid: process.pid, at: new Date().toISOString() }), { flag: 'wx', mode: 0o600 });
      return true;
    } catch (err) {
      if (err.code !== 'EEXIST') throw err;
      return false;
    }
  };
  if (!acquire()) {
    let at = 0;
    try {
      at = Date.parse(JSON.parse(fs.readFileSync(file, 'utf8')).at) || 0;
    } catch {}
    if (Date.now() - at < SYNC_LOCK_STALE_MS) return null;
    fs.rmSync(file, { force: true }); // a crashed sync left it behind
    if (!acquire()) return null;
  }
  try {
    return await fn();
  } finally {
    fs.rmSync(file, { force: true });
  }
}

function describeSync(summary) {
  const parts = [];
  if (summary.pulled.length) parts.push(`pulled ${summary.pulled.join(', ')}`);
  if (summary.deleted.length) parts.push(`deleted ${summary.deleted.join(', ')}`);
  if (summary.pushed) parts.push('pushed local changes');
  return parts.length ? `synced: ${parts.join('; ')} (vault v${summary.version})` : `already in sync (vault v${summary.version})`;
}

async function autoSync(cfg, deps) {
  try {
    const r = await withSyncLock(cfg, () => syncNow(cfg, deps));
    if (r === null) console.error('sync: another ccswitch is syncing; skipped');
    return true;
  } catch (err) {
    console.error(`sync: ${err.message}; continuing with local profiles`);
    return false;
  }
}

async function syncBefore(cfg, deps) {
  const last = Date.parse(readSyncConfig(cfg)?.lastSyncAt ?? '') || 0;
  if (Date.now() - last < SYNC_DEBOUNCE_MS) return true;
  return autoSync(cfg, deps);
}

async function syncAfter(cfg, deps) {
  let pending;
  try {
    pending = localSyncPending(cfg);
  } catch (err) {
    console.error(`sync: ${err.message}; local changes were not pushed`);
    return;
  }
  if (pending) await autoSync(cfg, deps);
}

export function syncStatus(cfg = config()) {
  const sc = readSyncConfig(cfg);
  if (!sc?.server || !sc?.fingerprint) return `sync: not set up on this machine (run "${cfg.prog} sync setup")`;
  const pending = listProfiles(cfg)
    .filter((p) => p.alternates?.length && !p.movedAt)
    .map((p) => `${p.name} (${p.alternates.length + 1} candidate chains)`);
  const gpg = findGpg();
  return [
    `server:    ${sc.server}`,
    `key:       ${sc.fingerprint}`,
    `machine:   ${sc.machine ?? '-'}`,
    `vault:     ${cfg.target} v${sc.version ?? 0}`,
    `last sync: ${sc.lastSyncAt ?? 'never'}`,
    `pending:   ${pending.length ? pending.join(', ') : 'none'}`,
    `gpg:       ${gpg ? `${gpg.version} (${gpg.bin})` : 'not found'}`,
  ].join('\n');
}

export async function syncSetup(cfg = config(), deps = {}) {
  const g = { findGpg, listSecretKeys, generateKey, createPgp, ensureGpg, ...(deps.gpg ?? {}) };
  const ask = deps.ask ?? promptLine;
  const pick = deps.pick ?? pickIndex;
  const out = deps.out ?? console.log;
  if (!g.findGpg()) {
    try {
      await g.ensureGpg({ rl: { question: ask }, out });
    } catch (err) {
      throw new UsageError(err.message);
    }
  }
  const existing = readSyncConfig(cfg) ?? {};
  const keys = g.listSecretKeys();
  const rows = [...keys.map((k) => [k.fingerprint.slice(-16), k.uid ?? '-']), ['(new)', 'generate a new key for sync']];
  out(keys.length ? 'Which gpg key identifies you to the sync server?' : 'No gpg secret keys found; a new one can be generated.');
  const idx = await pick(['key', 'identity'], rows, Math.max(0, keys.findIndex((k) => k.fingerprint === existing.fingerprint)));
  let fingerprint;
  if (idx === keys.length) {
    const uid = await ask('Your name and email for the new key (e.g. "Me <me@example.com>"): ');
    if (!uid) throw new UsageError('a name is needed to generate a key');
    fingerprint = g.generateKey(uid);
    out(`generated key ${fingerprint}`);
  } else {
    fingerprint = keys[idx].fingerprint;
  }
  const server = (await ask(`Sync server URL${existing.server ? ` [${existing.server}]` : ''}: `)) || existing.server;
  if (!/^https?:\/\/\S+$/.test(server ?? '')) throw new UsageError('the sync server URL must start with http:// or https://');
  const machine =
    existing.machine ?? `${os.hostname().split('.')[0].slice(0, 12).toLowerCase() || 'machine'}-${crypto.randomBytes(2).toString('hex')}`;
  // A different server or key means a different vault: the merge base and
  // version belong to the old one and must not be carried over.
  const changed = existing.server !== server || existing.fingerprint !== fingerprint;
  const next = changed
    ? { server, fingerprint, machine, version: 0, lastSyncAt: null, base: {}, tombstones: existing.tombstones ?? {} }
    : { ...existing, machine };
  writeSyncConfig(next, cfg, { replace: true });
  out(`sync configured: ${server}\n  key ${fingerprint} (this machine is "${machine}")`);
  const pgp = deps.pgp ?? g.createPgp({ fingerprint });
  try {
    const summary = await withSyncLock(cfg, () => syncNow(cfg, { pgp, fetchImpl: deps.fetchImpl ?? fetch }));
    if (summary) out(describeSync(summary));
  } catch (err) {
    if (err instanceof SyncError) {
      throw new UsageError(`${err.message}\nthe settings were saved; fix the problem and run "${cfg.prog} sync"`);
    }
    throw err;
  }
  return readSyncConfig(cfg);
}

async function syncCmd(sub, cfg, deps) {
  if (sub === 'setup') {
    await syncSetup(cfg, deps);
    return 0;
  }
  if (sub === 'status') {
    console.log(syncStatus(cfg));
    return 0;
  }
  if (sub === 'off') {
    fs.rmSync(path.join(cfg.home, 'sync.json'), { force: true });
    console.log('sync is off on this machine; local profiles and the server vault are untouched');
    return 0;
  }
  if (sub !== undefined) throw new UsageError(`unknown sync command ${JSON.stringify(sub)} (setup, status, off, or none)`);
  if (!syncEnabled(cfg)) throw new UsageError(`sync is not set up; run "${cfg.prog} sync setup"`);
  try {
    let summary = await withSyncLock(cfg, () => syncNow(cfg, deps));
    if (summary === null) throw new SyncError('another ccswitch is syncing right now; try again in a moment');
    // Candidate chains left by a double refresh get settled here rather than
    // on the next switch, and the winner goes straight back to the server.
    let resolved = 0;
    for (const p of listProfiles(cfg)) {
      if (p.alternates?.length && !p.movedAt && (await resolveAlternates(p.name, p, cfg, deps.fetchImpl)).resolved) resolved++;
    }
    if (resolved > 0) summary = (await withSyncLock(cfg, () => syncNow(cfg, deps))) ?? summary;
    console.log(describeSync(summary));
    return 0;
  } catch (err) {
    if (err instanceof SyncError) {
      console.error(`sync: ${err.message}`);
      return 1;
    }
    throw err;
  }
}

// --- CLI --------------------------------------------------------------------------

// Every command line is rendered from this table so the invocation column stays
// aligned whichever name it is printed under ("kcswitch" and "ccswitch" are the
// same width, "ccswitch kimi" is not).
const COMMANDS = [
  ['', 'show QUOTA for every profile, then pick one interactively to switch to'],
  ['<name>', 'switch to profile <name>'],
  ['switch <name>', 'same as above'],
  ['login <name>', 'log a new account in and save it as <name> (--force re-logs into an existing profile)'],
  ['save <name>', 'save the current login as <name> (--force overwrites)'],
  ['run <name> -- [...]', 'one-off BIN session as <name> (no global switch)'],
  ['list', 'show saved profiles'],
  ['usage', 'show QUOTA for every profile (refreshes expired tokens)'],
  ['delete <name>', 'delete a profile (--force skips confirmation)'],
  ['export <name> [file]', 'write a profile to a plaintext file (--move retires it here)'],
  ['import <name> [file]', 'load a profile from such a file (--force overwrites)'],
  ['export-all [file]', 'write ALL profiles + active pointer to one file (--move retires them here)'],
  ['import-all [file]', 'merge such a file into this machine (--force overwrites existing profiles)'],
  ['encrypt', 'encrypt profiles, backups and future exports with a passphrase'],
  ['decrypt', 'turn passphrase encryption back off (rewrites the store as plaintext)'],
  ['sync', 'pull the newest token chains from your sync server and push local changes'],
  ['sync setup', 'connect this machine to a ccswitch-server using your gpg key'],
  ['sync status', 'show the sync server, key, vault version and unresolved chains'],
  ['sync off', 'stop syncing on this machine (keeps local profiles and the vault)'],
];

function help(cfg) {
  const invocations = COMMANDS.map(([args]) => `  ${cfg.prog}${args && ' '}${args}`);
  const width = Math.max(...invocations.map((i) => i.length));
  const quota = cfg.target === 'kimi' ? 'the quota window' : '5h/7d/fable quota';
  const table = COMMANDS.map(([, desc], i) =>
    `${invocations[i].padEnd(width)}  ${desc.replace('BIN', cfg.bin).replace('QUOTA', quota)}`,
  ).join('\n');

  // Both backends are reachable from either bin, so each help text points at the
  // other one rather than pretending its own store is all there is.
  const crossRef =
    cfg.target === 'kimi'
      ? `This is the Kimi Code store: state lives in ~/.kimi-profiles, the live login
is ~/.kimi-code/credentials/kimi-code.json, and "run" isolates via
KIMI_CODE_HOME. "${cfg.prog} login <name>" runs "kimi login" (pass --region
global for kimi.ai accounts; mainland-cn is the default). Claude Code accounts
live under the sibling "ccswitch" bin. KCSWITCH_* env vars mirror the CCSWITCH_*
ones; CCSWITCH_PASSPHRASE and KCSWITCH_PASSPHRASE both work for either store.`
      : `Kimi Code accounts: prefix any command with "kimi" — "ccswitch kimi save work",
"ccswitch kimi work", "ccswitch kimi run work -- -p ...", "ccswitch kimi usage",
and so on through the whole command set. "ccswitch kimi login <name>" runs
"kimi login" (pass --region global for kimi.ai accounts; mainland-cn is the
default). Kimi state lives in ~/.kimi-profiles, the live login is
~/.kimi-code/credentials/kimi-code.json, and "run" isolates via KIMI_CODE_HOME.
Installed under the "kcswitch" bin name, the tool targets kimi without the
prefix. (A claude profile literally named "kimi" stays reachable via
"ccswitch switch kimi".) KCSWITCH_* env vars mirror the CCSWITCH_* ones;
CCSWITCH_PASSPHRASE and KCSWITCH_PASSPHRASE both work for either store.`;

  const store = cfg.target === 'kimi' ? '~/.kimi-profiles' : '~/.claude-profiles';
  return `usage: ${cfg.prog} [--dry-run] <command>

${table}

${crossRef}

Tokens rotate on every refresh, so a chain copied by hand works from ONE
machine only; a chain used from two machines gets the account logged out
everywhere. To share accounts across machines run "${cfg.prog} sync setup" on
each: profiles are mirrored through a ccswitch-server as a vault encrypted with
your own gpg key, every command pulls the newest chains first, and a chain
refreshed on two machines at once is kept twice and tested on the next use.
Without sync, use "export-all --move" / "import-all" to migrate: --move retires
the source copies so this machine cannot revoke the moved chains later.

State lives in ${store}. Every mutation writes a backup there first.
Unencrypted stores keep tokens in plaintext; run "${cfg.prog} encrypt" to protect
them at rest. CCSWITCH_PASSPHRASE skips the interactive passphrase prompt.`;
}

function requireName(name, cfg) {
  if (!name) throw new UsageError(`missing profile name (see ${cfg.progBin} --help)`);
  return name;
}

// Arrow keys / wasd / vim keys move the highlight, enter selects. Falls back
// to a numbered prompt when stdin or stdout isn't a TTY (piped, redirected,
// or a non-interactive CI shell can't do raw-mode keypress reading at all).
async function pickIndex(header, rows, initialIdx) {
  const n = rows.length;
  if (!process.stdin.isTTY || !process.stdout.isTTY) {
    const numbered = rows.map((r, i) => [String(i + 1), ...r]);
    console.log(renderTable(['#', ...header], numbered, terminalWidth()));
    const answer = await promptLine('Switch to: ');
    const idx = Number(answer) - 1;
    if (!Number.isInteger(idx) || idx < 0 || idx >= n) {
      throw new UsageError(`invalid selection ${JSON.stringify(answer)}`);
    }
    return idx;
  }

  const width = terminalWidth();
  // Reserve the 2-column gutter the pointer prints into so a full-width row
  // plus pointer doesn't wrap and throw off the cursor-up redraw math below.
  const rowWidth = Number.isFinite(width) ? Math.max(10, width - 2) : width;
  const [headerLine, ...rowLines] = renderTable(header, rows, rowWidth).split('\n');
  const color = shouldUseColor();
  const pointer = color ? '\x1b[36m❯\x1b[39m ' : '> ';
  const gutter = '  ';

  console.log(`${gutter}${headerLine}`);

  let idx = Math.min(Math.max(initialIdx, 0), n - 1);
  const draw = (first) => {
    if (!first) process.stdout.write(`\x1b[${n}A`);
    for (let i = 0; i < n; i++) {
      process.stdout.write(`\x1b[2K${i === idx ? pointer : gutter}${rowLines[i]}\n`);
    }
  };
  draw(true);

  process.stdout.write('\x1b[?25l'); // hide the cursor while the list is live
  try {
    return await new Promise((resolve, reject) => {
      const finish = (settle, value) => {
        process.stdin.removeListener('keypress', onKeypress);
        process.stdin.setRawMode(false);
        process.stdin.pause();
        settle(value);
      };
      const onKeypress = (str, key = {}) => {
        if (key.ctrl && key.name === 'c') return finish(reject, new CancelledError('cancelled at a prompt'));
        if (key.name === 'escape' || key.name === 'q') return finish(reject, new CancelledError('cancelled at a prompt'));
        if (key.name === 'return' || key.name === 'enter') return finish(resolve, idx);
        if (key.name === 'up' || key.name === 'k' || key.name === 'w') {
          idx = (idx - 1 + n) % n;
          draw(false);
        } else if (key.name === 'down' || key.name === 'j' || key.name === 's') {
          idx = (idx + 1) % n;
          draw(false);
        }
      };
      emitKeypressEvents(process.stdin);
      process.stdin.setRawMode(true);
      process.stdin.resume();
      process.stdin.on('keypress', onKeypress);
    });
  } finally {
    process.stdout.write('\x1b[?25h'); // always restore the cursor, cancel or not
  }
}

async function pickProfile(cfg, { dryRun = false } = {}, fetchImpl = fetch) {
  const profiles = listProfiles(cfg);
  if (profiles.length === 0) {
    throw new UsageError(`no profiles yet — save your current login with "${cfg.prog} save <name>"`);
  }
  const active = getActive(cfg);
  const activeIdx = Math.max(0, profiles.findIndex((p) => p.name === active));
  let header, rows;
  if (dryRun) {
    // Fetching limits refreshes expired tokens, a real write; skip it so
    // --dry-run stays a true no-op and show the plain name list instead.
    header = [' ', 'name', 'account'];
    rows = profiles.map((p) => [p.name === active ? '*' : ' ', p.name, displayAccount(p.oauthAccount) ?? '-']);
  } else {
    const rowsFn = cfg.target === 'kimi' ? kimiUsageRows : claudeUsageRows;
    ({ header, rows } = await rowsFn(profiles, active, cfg, fetchImpl, shouldUseColor()));
  }
  const idx = await pickIndex(header, rows, activeIdx);
  return profiles[idx].name;
}

export async function main(argv = process.argv.slice(2), deps = {}) {
  const sep = argv.indexOf('--');
  const head = sep === -1 ? argv : argv.slice(0, sep);
  const tail = sep === -1 ? [] : argv.slice(sep + 1);
  const dryRun = head.includes('--dry-run');
  const args = head.filter((a) => a !== '--dry-run');
  // A leading "kimi" selects the Kimi Code backend; without it the target is
  // claude, unless the tool is running under its "kcswitch" bin name.
  const target = args[0] === 'kimi' ? 'kimi' : defaultTarget();
  if (args[0] === 'kimi') args.shift();
  const [cmd, ...rest] = args;
  const cfg = config(target);

  if (cmd === '--help' || cmd === '-h' || cmd === 'help') {
    console.log(help(cfg));
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
  const syncDeps = { pgp: deps.pgp ?? null, fetchImpl: deps.fetchImpl ?? fetch };
  if (cmd === 'sync') return syncCmd(rest[0], cfg, syncDeps);
  // Every other command runs between a pull (so it sees the newest chains)
  // and a push (so what it changed reaches the other machines). Neither can
  // fail the command itself. Dry runs never touch the network.
  const auto = syncEnabled(cfg) && !dryRun && !SYNC_SKIP.has(cmd ?? '');
  const pulled = auto ? await syncBefore(cfg, syncDeps) : false;
  try {
    return await dispatch();
  } finally {
    if (auto && pulled) await syncAfter(cfg, syncDeps);
  }

  async function dispatch() {
  if (!cmd) {
    const picked = await pickProfile(cfg, { dryRun });
    if (!dryRun) await resolvePending(picked, cfg);
    switchTo(picked, { dryRun }, cfg);
    return 0;
  }
  switch (cmd) {
    case 'login': {
      const ri = rest.indexOf('--region');
      const region = ri === -1 ? null : (rest[ri + 1] ?? null);
      if (ri !== -1 && (target !== 'kimi' || !region)) {
        throw new UsageError(`--region <mainland-cn|global> is only valid as "${config('kimi').prog} login <name> --region <region>"`);
      }
      const name = rest.find((a, i) => a !== '--force' && a !== '--region' && (ri === -1 || i !== ri + 1));
      await login(requireName(name, cfg), { force: rest.includes('--force'), dryRun, region }, cfg);
      return 0;
    }
    case 'save':
      saveCurrent(requireName(rest.find((a) => a !== '--force'), cfg), { force: rest.includes('--force'), dryRun }, cfg);
      return 0;
    case 'switch':
      requireName(rest[0], cfg);
      if (!dryRun) await resolvePending(rest[0], cfg);
      switchTo(rest[0], { dryRun }, cfg);
      return 0;
    case 'list':
      console.log(formatList(cfg));
      return 0;
    case 'usage':
      return usageCmd({ dryRun }, cfg);
    case 'delete':
      await deleteProfileCmd(requireName(rest[0], cfg), { force: rest.includes('--force'), dryRun }, cfg);
      return 0;
    case 'export': {
      const pos = rest.filter((a) => a !== '--force' && a !== '--move');
      exportProfile(requireName(pos[0], cfg), pos[1], { force: rest.includes('--force'), move: rest.includes('--move'), dryRun }, cfg);
      return 0;
    }
    case 'import': {
      const pos = rest.filter((a) => a !== '--force');
      importProfile(requireName(pos[0], cfg), pos[1], { force: rest.includes('--force'), dryRun }, cfg);
      return 0;
    }
    case 'export-all': {
      const pos = rest.filter((a) => a !== '--force' && a !== '--move');
      exportAll(pos[0], { force: rest.includes('--force'), move: rest.includes('--move'), dryRun }, cfg);
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
      requireName(rest[0], cfg);
      if (dryRun) {
        console.log(`[dry-run] would launch ${cfg.bin} with ${cfg.runEnvVar} for "${rest[0]}"`);
        return 0;
      }
      await resolvePending(rest[0], cfg);
      return runProfile(rest[0], tail, cfg);
    }
    default:
      if (/^[a-z0-9-]+$/.test(cmd)) {
        if (!dryRun) await resolvePending(cmd, cfg);
        switchTo(cmd, { dryRun }, cfg); // shorthand: ccswitch <name>
        return 0;
      }
      throw new UsageError(`unknown command ${JSON.stringify(cmd)} (see ${cfg.progBin} --help)`);
  }
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

// Returns the exit status so the failure paths stay testable without spawning.
export function reportFatal(err) {
  if (err instanceof CancelledError) {
    // The prompt left the cursor mid-line; the newline keeps "aborted" off it.
    console.error('\naborted');
    return 130; // 128 + SIGINT, so callers can tell a cancel from a failure
  }
  console.error(`${progName()}: ${err instanceof UsageError || err instanceof SyncError || err instanceof GpgError ? err.message : (err.stack ?? err.message)}`);
  return 1;
}

if (invokedDirectly) {
  main()
    .then((code) => process.exit(code ?? 0))
    .catch((err) => process.exit(reportFatal(err)));
}
