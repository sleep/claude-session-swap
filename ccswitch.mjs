#!/usr/bin/env node
// ccswitch — manage multiple Claude Code subscription accounts on macOS.
// Zero dependencies by design: this tool handles OAuth refresh tokens, so
// every third-party package would be supply-chain attack surface.
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import readline from 'node:readline/promises';
import { pathToFileURL } from 'node:url';

export class UsageError extends Error {}

export function config() {
  return {
    home: process.env.CCSWITCH_HOME || path.join(os.homedir(), '.claude-profiles'),
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

// --- Keychain adapter (macOS `security` CLI) ---------------------------------

export function readKeychain(cfg = config()) {
  const r = spawnSync('security', ['find-generic-password', '-s', cfg.keychainService, '-w'], {
    encoding: 'utf8',
  });
  if (r.error) throw r.error;
  if (r.status === 0) return r.stdout.replace(/\n$/, '');
  if (r.status === 44) return null; // errSecItemNotFound: no entry, not a failure
  throw new Error(`security find-generic-password failed: ${r.stderr.trim()}`);
}

export function writeKeychain(payload, cfg = config()) {
  // `security` only accepts the secret via argv (-w); it is briefly visible
  // in the process list, matching how other keychain CLIs behave locally.
  const r = spawnSync(
    'security',
    ['add-generic-password', '-U', '-s', cfg.keychainService, '-a', os.userInfo().username, '-w', payload],
    { encoding: 'utf8' },
  );
  if (r.error) throw r.error;
  if (r.status !== 0) throw new Error(`security add-generic-password failed: ${r.stderr.trim()}`);
}

export function deleteKeychain(cfg = config()) {
  const r = spawnSync('security', ['delete-generic-password', '-s', cfg.keychainService], { encoding: 'utf8' });
  if (r.error) throw r.error;
  if (r.status === 0 || r.status === 44) return; // deleted, or already absent
  throw new Error(`security delete-generic-password failed: ${r.stderr.trim()}`);
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

// --- Profile store -------------------------------------------------------------

function profilePath(name, cfg) {
  return path.join(cfg.home, 'profiles', `${name}.json`);
}

export function saveProfile(name, { credentials, oauthAccount }, cfg = config()) {
  validateName(name);
  ensureHome(cfg);
  const body = JSON.stringify({ credentials, oauthAccount, savedAt: new Date().toISOString() }, null, 2);
  fs.writeFileSync(profilePath(name, cfg), body, { mode: 0o600 });
}

export function loadProfile(name, cfg = config()) {
  validateName(name);
  try {
    return JSON.parse(fs.readFileSync(profilePath(name, cfg), 'utf8'));
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
      ...JSON.parse(fs.readFileSync(path.join(cfg.home, 'profiles', f), 'utf8')),
    }));
}

export function deleteProfileFile(name, cfg = config()) {
  validateName(name);
  if (!profileExists(name, cfg)) throw new UsageError(`no profile named "${name}"`);
  fs.rmSync(profilePath(name, cfg));
  fs.rmSync(path.join(cfg.home, 'dirs', name), { recursive: true, force: true });
}

export function getActive(cfg = config()) {
  try {
    return JSON.parse(fs.readFileSync(path.join(cfg.home, 'state.json'), 'utf8')).active ?? null;
  } catch (err) {
    if (err.code === 'ENOENT') return null;
    throw err;
  }
}

export function setActive(name, cfg = config()) {
  ensureHome(cfg);
  fs.writeFileSync(path.join(cfg.home, 'state.json'), JSON.stringify({ active: name }, null, 2), {
    mode: 0o600,
  });
}

export function writeBackup(reason, payload, cfg = config()) {
  ensureHome(cfg);
  const stamp = new Date().toISOString().replace(/[:.]/g, '-');
  const file = path.join(cfg.home, 'backups', `${stamp}-${reason}.json`);
  fs.writeFileSync(file, JSON.stringify(payload, null, 2), { mode: 0o600 });
  return file;
}

// --- Core operations -------------------------------------------------------------

export function captureLive(cfg = config()) {
  return {
    credentials: readKeychain(cfg),
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
      'warning: claude is currently running; open sessions keep the old account and may rewrite the Keychain when their token refreshes',
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
  writeKeychain(profile.credentials, cfg);
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
  if (profiles.length === 0) return 'no profiles yet — add one with "ccswitch login <name>"';
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
  deleteKeychain(cfg);
  updateOauthAccount(null, cfg);
  setActive(null, cfg);
  const restore = () => {
    if (live.credentials) {
      writeKeychain(live.credentials, cfg);
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
  fs.writeFileSync(out, body, { mode: 0o600 });
  console.log(`exported "${name}" to ${out} (plaintext — it holds live tokens, so guard it)`);
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
    parsed = JSON.parse(raw);
  } catch {
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

// --- Isolated run (no global mutation) -----------------------------------------

export function materializeRunDir(name, cfg = config()) {
  const profile = loadProfile(name, cfg);
  const dir = path.join(cfg.home, 'dirs', name);
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  fs.writeFileSync(path.join(dir, '.credentials.json'), profile.credentials ?? '', { mode: 0o600 });
  const cjPath = path.join(dir, '.claude.json');
  let cj = {};
  if (fs.existsSync(cjPath)) cj = JSON.parse(fs.readFileSync(cjPath, 'utf8'));
  cj.oauthAccount = profile.oauthAccount;
  fs.writeFileSync(cjPath, JSON.stringify(cj, null, 2), { mode: 0o600 });
  return dir;
}

export function runProfile(name, claudeArgs, cfg = config()) {
  const dir = materializeRunDir(name, cfg);
  const r = spawnSync(cfg.claudeBin, claudeArgs, {
    stdio: 'inherit',
    env: { ...process.env, CLAUDE_CONFIG_DIR: dir },
  });
  if (r.error) throw r.error;
  return r.status ?? 1;
}

// --- CLI --------------------------------------------------------------------------

const HELP = `usage: ccswitch [--dry-run] <command>

  ccswitch                      pick a profile interactively and switch to it
  ccswitch <name>               switch to profile <name>
  ccswitch switch <name>        same as above
  ccswitch login <name>         log a new account in and save it as <name>
  ccswitch run <name> -- [...]  one-off claude session as <name> (no global switch)
  ccswitch list                 show saved profiles
  ccswitch delete <name>        delete a profile (--force skips confirmation)
  ccswitch export <name> [file] write a profile to a plaintext file (default <name>.ccswitch.json)
  ccswitch import <name> [file] load a profile from such a file (--force overwrites)

State lives in ~/.claude-profiles. Every mutation writes a backup there first.
Exported files hold tokens in plaintext; move them over a trusted channel.`;

function requireName(name) {
  if (!name) throw new UsageError('missing profile name (see ccswitch --help)');
  return name;
}

async function pickProfile(cfg) {
  const profiles = listProfiles(cfg);
  if (profiles.length === 0) {
    throw new UsageError('no profiles yet — add one with "ccswitch login <name>"');
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
  if (!cmd) {
    switchTo(await pickProfile(cfg), { dryRun }, cfg);
    return 0;
  }
  switch (cmd) {
    case 'login':
      await login(requireName(rest[0]), { dryRun }, cfg);
      return 0;
    case 'switch':
      switchTo(requireName(rest[0]), { dryRun }, cfg);
      return 0;
    case 'list':
      console.log(formatList(cfg));
      return 0;
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
