import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';

// Shared by every suite. Nothing here touches the real ~/.claude,
// ~/.kimi-code, profile stores or the login keychain.

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

// Mirrors sandbox for the kimi store: all state goes to a temp dir, including
// the kimi home (so the real ~/.kimi-code login is never touched).
export function kimiSandbox(t) {
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

// A claude credentials payload with a token pair valid for an hour.
export const usageCreds = (o) =>
  JSON.stringify({ claudeAiOauth: { accessToken: 'at-1', refreshToken: 'rt-1', expiresAt: Date.now() + 60 * 60 * 1000, ...o } });

export function captureLog(t) {
  const lines = [];
  const orig = console.log;
  console.log = (...a) => lines.push(a.join(' '));
  t.after(() => { console.log = orig; });
  return lines;
}

export function captureErr(t) {
  const lines = [];
  const orig = console.error;
  console.error = (...a) => lines.push(a.join(' '));
  t.after(() => { console.error = orig; });
  return lines;
}

export function fakeClaudeBin(home, script) {
  const bin = path.join(home, 'fake-claude');
  fs.writeFileSync(bin, `#!/bin/sh\n${script}`, { mode: 0o755 });
  process.env.CCSWITCH_CLAUDE_BIN = bin;
  return bin;
}

export function fakeKimiBin(home, script) {
  const bin = path.join(home, 'fake-kimi');
  fs.writeFileSync(bin, `#!/bin/sh\n${script}`, { mode: 0o755 });
  process.env.KCSWITCH_KIMI_BIN = bin;
  return bin;
}

// A stand-in `security` on PATH, backed by one file per service name under
// the sandbox, so the darwin Keychain paths run against a store the test
// controls and the real login keychain is never read, written or unlocked.
export function fakeSecurity(t, home, { lockStatus = 0 } = {}) {
  const bin = path.join(home, 'fake-bin');
  const store = path.join(home, 'keychain');
  const log = path.join(home, 'security.log');
  fs.mkdirSync(bin);
  fs.mkdirSync(store);
  fs.writeFileSync(
    path.join(bin, 'security'),
    `#!/bin/sh
echo "$*" >> "${log}"
cmd=$1; shift
svc=""; want=""
while [ $# -gt 0 ]; do case "$1" in -s) svc=$2; shift;; -w) want=1;; esac; shift; done
case "$cmd" in
  find-generic-password)
    if [ -f "${store}/$svc" ]; then [ -n "$want" ] && cat "${store}/$svc"; exit 0; fi
    echo "security: SecKeychainSearchCopyNext: The specified item could not be found in the keychain." >&2; exit 44;;
  delete-generic-password)
    if [ -f "${store}/$svc" ]; then rm "${store}/$svc"; exit 0; fi
    exit 44;;
  show-keychain-info)
    [ ${lockStatus} -eq 0 ] || echo "security: SecKeychainCopySettings: User interaction is not allowed." >&2
    exit ${lockStatus};;
esac
exit 1
`,
    { mode: 0o755 },
  );
  const origPath = process.env.PATH;
  process.env.PATH = `${bin}${path.delimiter}${origPath}`;
  t.after(() => { process.env.PATH = origPath; });
  return {
    store,
    put: (service, text) => fs.writeFileSync(path.join(store, service), text),
    has: (service) => fs.existsSync(path.join(store, service)),
    calls: () => (fs.existsSync(log) ? fs.readFileSync(log, 'utf8').trim().split('\n') : []),
    reset: () => fs.rmSync(log, { force: true }),
  };
}

export const onDarwin = { skip: process.platform !== 'darwin' && 'Keychain paths only run on macOS' };

// Spawns the CLI as a user would, in a fresh process.
export const CLI = new URL('../ccswitch.mjs', import.meta.url).pathname;

export function runCli(args, env = {}, input) {
  return spawnSync(process.execPath, [CLI, ...args], {
    encoding: 'utf8',
    env: { ...process.env, ...env },
    input,
  });
}

