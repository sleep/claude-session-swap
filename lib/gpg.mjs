// OpenPGP via the user's installed gpg. ccswitch stays dependency-free, and
// gpg is what already holds the user's keys and agent (hardware tokens
// included), so it is shelled out to the same way `security` is for the
// macOS Keychain. Every result is read from gpg's machine-readable status
// lines, never from its exit code: gpg happily exits 0 after writing
// plaintext for an unsigned or wrongly-signed message.
import { spawn, spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

export class GpgError extends Error {}

const BASE_ARGS = ['--batch', '--no-tty'];
const FPR_RE = /^[0-9A-F]{40}([0-9A-F]{24})?$/;

function gpgBinFrom(env) {
  return env.CCSWITCH_GPG_BIN || null;
}

function run(args, { gpgBin, env = process.env, input } = {}) {
  const bin = gpgBin ?? gpgBinFrom(env) ?? 'gpg';
  const r = spawnSync(bin, [...BASE_ARGS, ...args], { env, input, encoding: 'utf8', maxBuffer: 16 * 1024 * 1024 });
  if (r.error) throw new GpgError(`could not run ${bin}: ${r.error.message}`);
  return r;
}

function statusLines(text) {
  return text.split('\n').filter((l) => l.startsWith('[GNUPG:] ')).map((l) => l.slice('[GNUPG:] '.length).split(' '));
}

export function findGpg({ env = process.env } = {}) {
  const candidates = gpgBinFrom(env) ? [gpgBinFrom(env)] : ['gpg', 'gpg2'];
  for (const bin of candidates) {
    const r = spawnSync(bin, ['--version'], { env, encoding: 'utf8' });
    if (r.error || r.status !== 0) continue;
    const m = /\(GnuPG\)\s+(\d+\.\d+\.\d+)/.exec(r.stdout);
    if (!m) continue;
    const [major, minor] = m[1].split('.').map(Number);
    // Older gpg verified an inline-signed "signature" file and ignored the
    // data file, which would turn the server's verify into a no-op.
    if (major < 2 || (major === 2 && minor < 2)) continue;
    return { bin, version: m[1] };
  }
  return null;
}

export function installHint(platform = process.platform) {
  if (platform === 'darwin') return 'macOS: brew install gnupg';
  if (platform === 'linux') {
    return [
      'Debian/Ubuntu: sudo apt install gnupg',
      'Fedora: sudo dnf install gnupg2',
      'Arch: sudo pacman -S gnupg',
    ].join('\n');
  }
  return 'install GnuPG 2.2 or newer from https://gnupg.org/download/';
}

// `--with-colons` listing: a `sec` line opens each secret key, the first `fpr`
// after it is the primary fingerprint, and the first `uid` names it. `ssb`
// subkeys have their own `fpr` lines which must not be mistaken for a key.
export function parseSecretKeys(text) {
  const keys = [];
  let current = null;
  for (const line of text.split('\n')) {
    const f = line.split(':');
    if (f[0] === 'sec') {
      current = { fingerprint: null, uid: null, created: Number(f[5]) || null, expires: Number(f[6]) || null };
      keys.push(current);
    } else if (f[0] === 'ssb') {
      current = null;
    } else if (f[0] === 'fpr' && current && !current.fingerprint) {
      current.fingerprint = f[9];
    } else if (f[0] === 'uid' && current && !current.uid) {
      current.uid = f[9];
    }
  }
  return keys.filter((k) => k.fingerprint);
}

export function listSecretKeys(opts = {}) {
  const r = run(['--list-secret-keys', '--with-colons'], opts);
  if (r.status !== 0) throw new GpgError(`could not list secret keys: ${r.stderr.trim()}`);
  return parseSecretKeys(r.stdout);
}

// Ed25519 signing primary plus a cv25519 encryption subkey. `passphrase` is
// for tests and scripted setups; interactive use lets pinentry ask.
export function generateKey(uid, { passphrase = null, ...opts } = {}) {
  const pass = passphrase === null ? [] : ['--pinentry-mode', 'loopback', '--passphrase', passphrase];
  const gen = run([...pass, '--quiet', '--quick-generate-key', uid, 'ed25519', 'sign', '0'], opts);
  if (gen.status !== 0) throw new GpgError(`key generation failed: ${gen.stderr.trim()}`);
  const fingerprint = listSecretKeys(opts).find((k) => k.uid === uid)?.fingerprint;
  if (!fingerprint) throw new GpgError('key generation reported success but the key is not listed');
  const sub = run([...pass, '--quiet', '--quick-add-key', fingerprint, 'cv25519', 'encr', '0'], opts);
  if (sub.status !== 0) throw new GpgError(`adding the encryption subkey failed: ${sub.stderr.trim()}`);
  return fingerprint;
}

function primaryFromValidsig(fields) {
  // VALIDSIG <sig-fpr> <date> <ts> <expiry> <ver> <res> <pk-algo> <hash> <class> <primary-fpr>
  const primary = fields[10] ?? fields[1];
  return FPR_RE.test(primary) ? primary : null;
}

const SIG_FAILURES = new Set(['BADSIG', 'ERRSIG', 'EXPSIG', 'EXPKEYSIG', 'REVKEYSIG', 'NO_PUBKEY']);

export function createPgp({ fingerprint, gpgBin, env = process.env }) {
  if (!FPR_RE.test(fingerprint)) throw new GpgError(`not a key fingerprint: ${fingerprint}`);
  const opts = { gpgBin, env };
  return {
    fingerprint,
    exportPublicKey() {
      const r = run(['--armor', '--export', fingerprint], opts);
      if (r.status !== 0 || !r.stdout.startsWith('-----BEGIN PGP PUBLIC KEY BLOCK-----')) {
        throw new GpgError(`could not export public key ${fingerprint}: ${r.stderr.trim()}`);
      }
      return r.stdout;
    },
    sign(text) {
      const r = run(['--detach-sign', '--armor', '--local-user', fingerprint], { ...opts, input: text });
      if (r.status !== 0) throw new GpgError(`signing failed: ${r.stderr.trim()}`);
      return r.stdout;
    },
    encrypt(text) {
      const r = run(
        ['--sign', '--encrypt', '--armor', '--trust-model', 'always', '--local-user', fingerprint, '--recipient', fingerprint],
        { ...opts, input: text },
      );
      if (r.status !== 0) throw new GpgError(`encryption failed: ${r.stderr.trim()}`);
      return r.stdout;
    },
    // Anyone holding the public key can encrypt to it, so a readable message
    // proves nothing about its origin: only our own signature does.
    decrypt(armored) {
      const r = run(['--decrypt', '--status-fd', '2', '--max-output', String(4 * 1024 * 1024)], { ...opts, input: armored });
      const status = statusLines(r.stderr);
      const has = (tag) => status.some((s) => s[0] === tag);
      if (!has('DECRYPTION_OKAY')) throw new GpgError(`decryption failed: ${r.stderr.split('\n').find((l) => l.startsWith('gpg:'))?.trim() ?? 'no DECRYPTION_OKAY'}`);
      if (status.some((s) => SIG_FAILURES.has(s[0]))) throw new GpgError('vault was not signed by your key (bad signature)');
      const valid = status.find((s) => s[0] === 'VALIDSIG');
      if (!has('GOODSIG') || !valid || primaryFromValidsig(valid) !== fingerprint) {
        throw new GpgError('vault was not signed by your key');
      }
      return r.stdout;
    },
  };
}

function runAsync(bin, args, { env, timeoutMs }) {
  return new Promise((resolve, reject) => {
    const child = spawn(bin, args, { env, stdio: ['ignore', 'pipe', 'pipe'], timeout: timeoutMs });
    let stdout = '';
    let stderr = '';
    child.stdout.setEncoding('utf8').on('data', (d) => { stdout += d; });
    child.stderr.setEncoding('utf8').on('data', (d) => { stderr += d; });
    child.on('error', (err) => reject(new GpgError(`could not run ${bin}: ${err.message}`)));
    child.on('close', (status, signal) => resolve({ status, signal, stdout, stderr }));
  });
}

// Server side: verify a detached signature using nothing but the key the
// client presented. A throwaway homedir per request keeps one caller's key
// from ever vouching for another's, and --no-autostart keeps gpg from
// spawning an agent (with its unix sockets) into a directory about to be
// removed.
export async function verifyDetached({ publicKey, payload, signature }, { gpgBin, env = process.env, tmpRoot = os.tmpdir(), timeoutMs = 5000 } = {}) {
  const bin = gpgBin ?? gpgBinFrom(env) ?? 'gpg';
  const home = fs.mkdtempSync(path.join(tmpRoot, 'ccsync-'));
  fs.chmodSync(home, 0o700);
  try {
    const common = [...BASE_ARGS, '--homedir', home, '--no-autostart', '--no-auto-key-retrieve', '--no-auto-key-locate', '--trust-model', 'always', '--status-fd', '1'];
    const keyFile = path.join(home, 'key.asc');
    const payloadFile = path.join(home, 'payload');
    const sigFile = path.join(home, 'sig.asc');
    fs.writeFileSync(keyFile, publicKey, { mode: 0o600 });
    fs.writeFileSync(payloadFile, payload, { mode: 0o600 });
    fs.writeFileSync(sigFile, signature, { mode: 0o600 });

    const imp = await runAsync(bin, [...common, '--import', keyFile], { env, timeoutMs });
    const impStatus = statusLines(imp.stdout);
    const imported = impStatus.filter((s) => s[0] === 'IMPORT_OK').map((s) => s[2]);
    const res = impStatus.find((s) => s[0] === 'IMPORT_RES');
    if (imported.length !== 1 || !res || res[1] !== '1' || !FPR_RE.test(imported[0])) {
      throw new GpgError('public key block must contain exactly one key');
    }
    const expected = imported[0];

    const ver = await runAsync(bin, [...common, '--verify', sigFile, payloadFile], { env, timeoutMs });
    const status = statusLines(ver.stdout);
    if (ver.signal) throw new GpgError(`gpg verify timed out`);
    if (status.some((s) => SIG_FAILURES.has(s[0]))) throw new GpgError('bad signature');
    const count = (tag) => status.filter((s) => s[0] === tag).length;
    if (count('NEWSIG') !== 1 || count('GOODSIG') !== 1 || count('VALIDSIG') !== 1) {
      throw new GpgError('expected exactly one valid signature');
    }
    const primary = primaryFromValidsig(status.find((s) => s[0] === 'VALIDSIG'));
    if (primary !== expected) throw new GpgError('signature was not made by the presented key');
    return { fingerprint: primary };
  } finally {
    fs.rmSync(home, { recursive: true, force: true });
  }
}
