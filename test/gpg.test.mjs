// Exercises the real gpg binary in throwaway keyrings. Skipped entirely when
// gpg is not installed so the rest of the suite stays runnable anywhere.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

import {
  BASE_ARGS,
  GpgError,
  createPgp,
  findGpg,
  generateKey,
  installHint,
  listSecretKeys,
  parseSecretKeys,
  verifyDetached,
} from '../lib/gpg.mjs';

const gpg = findGpg();
const skip = gpg ? false : 'gpg not installed';

// Keyrings live under os.tmpdir(): gpg-agent's socket path must stay short
// enough for a unix socket, which a deep temp path is not.
function keyring(t) {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'ccsw-gpg-'));
  fs.chmodSync(home, 0o700);
  const env = { ...process.env, GNUPGHOME: home };
  t.after(() => {
    spawnSync('gpgconf', ['--homedir', home, '--kill', 'all'], { env });
    fs.rmSync(home, { recursive: true, force: true });
  });
  return env;
}

const COLONS = `sec:u:255:22:46EC6DD922E6CD72:1790293623:::u:::scESC:::+::ed25519:::0:
fpr:::::::::071BC24AB653FEBB99E859EB46EC6DD922E6CD72:
grp:::::::::C5D0465CCD3C4A09FF373372263D903DC1A1D3AC:
uid:u::::1790293623::23143DC9A25554773DE2806129371CAF0453F2C3::probe <probe@example.invalid>::::::::::0:
ssb:u:255:18:64B70D91045CAC37:1790293623::::::e:::+::cv25519::
fpr:::::::::6F246618C4BC8FED7DCC02FD64B70D91045CAC37:
sec:u:255:22:1111111111111111:1790293700:1800000000::u:::scESC:::+::ed25519:::0:
fpr:::::::::2222222222222222222222222222222222222222:
uid:u::::1790293700::AAAA::second <s@example.invalid>::::::::::0:
`;

test('parseSecretKeys reads primary fingerprints and uids, skipping subkeys', () => {
  assert.deepEqual(parseSecretKeys(COLONS), [
    { fingerprint: '071BC24AB653FEBB99E859EB46EC6DD922E6CD72', uid: 'probe <probe@example.invalid>', created: 1790293623, expires: null },
    { fingerprint: '2222222222222222222222222222222222222222', uid: 'second <s@example.invalid>', created: 1790293700, expires: 1800000000 },
  ]);
});

test('installHint names a package manager command per platform', () => {
  assert.match(installHint('darwin'), /brew install gnupg/);
  assert.match(installHint('linux'), /apt|dnf|pacman/);
});

test('findGpg reports a bin and a version', { skip }, () => {
  assert.equal(typeof gpg.bin, 'string');
  assert.match(gpg.version, /^\d+\.\d+/);
});

test('findGpg returns null for a missing binary', () => {
  assert.equal(findGpg({ env: { ...process.env, CCSWITCH_GPG_BIN: '/nonexistent/gpg-xyz' } }), null);
});

test('generateKey creates a signing+encryption key that listSecretKeys reports', { skip }, (t) => {
  const env = keyring(t);
  const fpr = generateKey('alice <alice@example.invalid>', { env, passphrase: '' });
  assert.match(fpr, /^[0-9A-F]{40}$/);
  const keys = listSecretKeys({ env });
  assert.equal(keys.length, 1);
  assert.equal(keys[0].fingerprint, fpr);
  assert.equal(keys[0].uid, 'alice <alice@example.invalid>');
});

test('sign then verifyDetached round-trips and names the primary fingerprint', { skip }, async (t) => {
  const env = keyring(t);
  const fpr = generateKey('alice <alice@example.invalid>', { env, passphrase: '' });
  const pgp = createPgp({ fingerprint: fpr, env });
  const payload = '{"op":"get","vault":"claude"}';
  const publicKey = pgp.exportPublicKey();
  assert.match(publicKey, /^-----BEGIN PGP PUBLIC KEY BLOCK-----/);
  const signature = pgp.sign(payload);
  assert.match(signature, /^-----BEGIN PGP SIGNATURE-----/);
  const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'ccsw-verify-'));
  t.after(() => fs.rmSync(tmpRoot, { recursive: true, force: true }));
  const result = await verifyDetached({ publicKey, payload, signature }, { tmpRoot });
  assert.deepEqual(result, { fingerprint: fpr });
  assert.deepEqual(fs.readdirSync(tmpRoot), [], 'temp homedir is removed after verify');
});

test('verifyDetached rejects a tampered payload', { skip }, async (t) => {
  const env = keyring(t);
  const fpr = generateKey('alice <alice@example.invalid>', { env, passphrase: '' });
  const pgp = createPgp({ fingerprint: fpr, env });
  const signature = pgp.sign('original');
  await assert.rejects(
    verifyDetached({ publicKey: pgp.exportPublicKey(), payload: 'tampered', signature }, {}),
    (err) => err instanceof GpgError && /BADSIG|signature/.test(err.message),
  );
});

test('verifyDetached rejects a signature made by a key other than the presented one', { skip }, async (t) => {
  const env = keyring(t);
  const alice = generateKey('alice <alice@example.invalid>', { env, passphrase: '' });
  const mallory = generateKey('mallory <m@example.invalid>', { env, passphrase: '' });
  const signature = createPgp({ fingerprint: mallory, env }).sign('payload');
  const publicKey = createPgp({ fingerprint: alice, env }).exportPublicKey();
  await assert.rejects(verifyDetached({ publicKey, payload: 'payload', signature }, {}), GpgError);
});

test('verifyDetached rejects a public key block holding more than one key', { skip }, async (t) => {
  const env = keyring(t);
  const alice = generateKey('alice <alice@example.invalid>', { env, passphrase: '' });
  generateKey('bob <bob@example.invalid>', { env, passphrase: '' });
  const both = spawnSync(gpg.bin, ['--batch', '--armor', '--export'], { env, encoding: 'utf8' }).stdout;
  const signature = createPgp({ fingerprint: alice, env }).sign('payload');
  await assert.rejects(
    verifyDetached({ publicKey: both, payload: 'payload', signature }, {}),
    (err) => err instanceof GpgError && /one key/.test(err.message),
  );
});

test('encrypt then decrypt round-trips for the owner', { skip }, (t) => {
  const env = keyring(t);
  const fpr = generateKey('alice <alice@example.invalid>', { env, passphrase: '' });
  const pgp = createPgp({ fingerprint: fpr, env });
  const armored = pgp.encrypt('{"ccswitchVault":1}');
  assert.match(armored, /^-----BEGIN PGP MESSAGE-----/);
  assert.equal(pgp.decrypt(armored), '{"ccswitchVault":1}');
});

test('decrypt rejects a message that is encrypted to us but not signed', { skip }, (t) => {
  const env = keyring(t);
  const fpr = generateKey('alice <alice@example.invalid>', { env, passphrase: '' });
  const unsigned = spawnSync(
    gpg.bin,
    ['--batch', '--quiet', '--trust-model', 'always', '--recipient', fpr, '--encrypt', '--armor'],
    { env, input: 'sneaky', encoding: 'utf8' },
  ).stdout;
  assert.throws(() => createPgp({ fingerprint: fpr, env }).decrypt(unsigned), (err) => err instanceof GpgError && /signed/.test(err.message));
});

test('decrypt rejects a message signed by another key even though we can read it', { skip }, (t) => {
  const env = keyring(t);
  const alice = generateKey('alice <alice@example.invalid>', { env, passphrase: '' });
  const mallory = generateKey('mallory <m@example.invalid>', { env, passphrase: '' });
  const forged = spawnSync(
    gpg.bin,
    ['--batch', '--quiet', '--pinentry-mode', 'loopback', '--passphrase', '', '--trust-model', 'always',
      '--local-user', mallory, '--recipient', alice, '--sign', '--encrypt', '--armor'],
    { env, input: '{"ccswitchVault":1,"profiles":{"evil":{}}}', encoding: 'utf8' },
  ).stdout;
  assert.throws(() => createPgp({ fingerprint: alice, env }).decrypt(forged), (err) => err instanceof GpgError && /signed/.test(err.message));
});

test('decrypt rejects garbage', { skip }, (t) => {
  const env = keyring(t);
  const fpr = generateKey('alice <alice@example.invalid>', { env, passphrase: '' });
  assert.throws(() => createPgp({ fingerprint: fpr, env }).decrypt('-----BEGIN PGP MESSAGE-----\nnope\n-----END PGP MESSAGE-----\n'), GpgError);
});

test('client calls never auto-fetch keys and fail fast instead of prompting when not interactive', { skip }, (t) => {
  const env = keyring(t);
  const fpr = generateKey('alice <alice@example.invalid>', { env, passphrase: 'secret' });
  const pgp = createPgp({ fingerprint: fpr, env, interactive: false });
  const started = Date.now();
  assert.throws(() => pgp.sign('x'), GpgError);
  assert.ok(Date.now() - started < 5000, 'no pinentry wait');
  assert.ok(BASE_ARGS.includes('--no-auto-key-retrieve') && BASE_ARGS.includes('--no-auto-key-locate'));
});
