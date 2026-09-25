#!/usr/bin/env node
// ccswitch-server: the sync server ccswitch clients push their PGP-encrypted
// profile vaults to. It never sees a token: each vault is an opaque blob
// signed and encrypted by the owner's OpenPGP key, and the owner's public key
// (verified against the request signature) is the only identity there is.
// Every route lives under a random path prefix, so probes see nothing but
// 404s; a full disk compromise yields public keys and ciphertext.
// Zero dependencies, same as ccswitch itself.
import crypto from 'node:crypto';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import readline from 'node:readline/promises';
import { pathToFileURL } from 'node:url';

import { GpgMissingError, ensureGpg, findGpg, installHint, verifyDetached } from './lib/gpg.mjs';

export { ensureGpg };
import { MAX_BODY_BYTES, MAX_VAULTS, ProtocolError, VAULT_NAMES, verifyEnvelope } from './lib/sync-protocol.mjs';

const FPR_RE = /^[0-9A-F]{40}([0-9A-F]{24})?$/;

// --- vault store ----------------------------------------------------------------
// <dataDir>/vaults/<fingerprint>/<vault>.json = {version, data, updatedAt}.
// Writes are tmp+rename so a crash never leaves a half-written vault, and the
// vault count is kept in memory so the global cap is one comparison.

export function createVaultStore(dataDir, { maxVaults = MAX_VAULTS } = {}) {
  const root = path.join(dataDir, 'vaults');
  fs.mkdirSync(root, { recursive: true, mode: 0o700 });
  let count = 0;
  for (const fpr of fs.readdirSync(root)) {
    if (!FPR_RE.test(fpr)) continue;
    count += fs.readdirSync(path.join(root, fpr)).filter((f) => f.endsWith('.json')).length;
  }

  function file(fpr, name) {
    if (typeof fpr !== 'string' || !FPR_RE.test(fpr)) throw new ProtocolError(400, 'bad fingerprint');
    if (!VAULT_NAMES.includes(name)) throw new ProtocolError(400, 'unknown vault');
    return path.join(root, fpr, `${name}.json`);
  }

  function read(fpr, name) {
    try {
      const rec = JSON.parse(fs.readFileSync(file(fpr, name), 'utf8'));
      if (!Number.isSafeInteger(rec.version) || typeof rec.data !== 'string') return null;
      return rec;
    } catch (err) {
      if (err.code === 'ENOENT') return null;
      throw err;
    }
  }

  return {
    count: () => count,
    get(fpr, name) {
      const rec = read(fpr, name);
      return rec ? { version: rec.version, data: rec.data } : { version: 0, data: null };
    },
    put(fpr, name, baseVersion, data) {
      const target = file(fpr, name);
      const current = read(fpr, name);
      const version = current?.version ?? 0;
      if (baseVersion !== version) {
        throw new ProtocolError(409, 'version conflict', { version, data: current?.data ?? null });
      }
      if (!current && count >= maxVaults) throw new ProtocolError(507, 'server is full');
      fs.mkdirSync(path.dirname(target), { recursive: true, mode: 0o700 });
      const tmp = `${target}.${process.pid}.tmp`;
      fs.writeFileSync(tmp, JSON.stringify({ version: version + 1, data, updatedAt: new Date().toISOString() }), { mode: 0o600 });
      fs.renameSync(tmp, target);
      if (!current) count++;
      return { version: version + 1 };
    },
  };
}

// --- HTTP ---------------------------------------------------------------------------

function readBody(req, limit) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    req.on('data', (chunk) => {
      size += chunk.length;
      if (size > limit) {
        // Chunked bodies carry no Content-Length, so the only honest limit is
        // counting what actually arrives and dropping the socket past it.
        req.destroy();
        reject(new ProtocolError(413, 'body too large'));
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    req.on('error', reject);
  });
}

// Serialises work per key so two concurrent puts on the same vault see each
// other's version, and caps how many gpg verifications run at once so a flood
// of junk envelopes cannot starve legitimate ones.
function limiter(concurrency) {
  let active = 0;
  const queue = [];
  const next = () => {
    if (active >= concurrency || queue.length === 0) return;
    active++;
    const { fn, resolve, reject } = queue.shift();
    fn().then(resolve, reject).finally(() => {
      active--;
      next();
    });
  };
  return (fn) => new Promise((resolve, reject) => {
    queue.push({ fn, resolve, reject });
    next();
  });
}

function perKeyLock() {
  const chains = new Map();
  return (key, fn) => {
    const prev = chains.get(key) ?? Promise.resolve();
    const run = prev.then(fn, fn);
    const settled = run.then(
      () => {},
      () => {},
    );
    chains.set(key, settled);
    settled.then(() => {
      if (chains.get(key) === settled) chains.delete(key);
    });
    return run;
  };
}

export function createSyncServer({
  dataDir,
  pathSecret,
  verify = null,
  now = Date.now,
  maxVaults = MAX_VAULTS,
  log = (line) => console.log(line),
  gpgConcurrency = 2,
  requestTimeoutMs = 15000,
  gpgBin = undefined,
} = {}) {
  if (typeof pathSecret !== 'string' || pathSecret.length < 32) throw new Error('pathSecret must be at least 32 characters');
  const store = createVaultStore(dataDir, { maxVaults });
  const tmpRoot = path.join(dataDir, 'tmp');
  fs.rmSync(tmpRoot, { recursive: true, force: true }); // sweep verify dirs a crash left behind
  fs.mkdirSync(tmpRoot, { recursive: true, mode: 0o700 });
  const verifyFn = verify ?? ((env) => verifyDetached(env, { gpgBin, tmpRoot }));
  const gpgSlot = limiter(gpgConcurrency);
  const withLock = perKeyLock();
  const route = new RegExp(`^/${pathSecret}/v1/vaults/(${VAULT_NAMES.join('|')})$`);

  const server = http.createServer({
    requestTimeout: requestTimeoutMs,
    headersTimeout: Math.min(requestTimeoutMs, 10000),
    // Timeouts are only enforced on this interval, so it must be shorter
    // than the timeouts themselves to mean anything.
    connectionsCheckingInterval: Math.max(100, Math.floor(requestTimeoutMs / 3)),
  }, async (req, res) => {
    const started = Date.now();
    const m = req.method === 'POST' ? route.exec(req.url ?? '') : null;
    if (!m) {
      // Indistinguishable from a host with nothing on it: no body, no log.
      res.writeHead(404).end();
      return;
    }
    const vault = m[1];
    let status = 500;
    let body = { error: 'internal error' };
    let who = '-';
    let op = '-';
    try {
      const raw = await readBody(req, MAX_BODY_BYTES);
      let envelope;
      try {
        envelope = JSON.parse(raw);
      } catch {
        throw new ProtocolError(400, 'body is not JSON');
      }
      const { fingerprint, payload } = await verifyEnvelope(envelope, vault, {
        verify: (env) => gpgSlot(() => verifyFn(env)),
        now: now(),
      });
      who = fingerprint.slice(0, 8);
      op = payload.op;
      body = await withLock(`${fingerprint}/${vault}`, async () =>
        payload.op === 'get' ? store.get(fingerprint, vault) : store.put(fingerprint, vault, payload.baseVersion, payload.data),
      );
      status = 200;
    } catch (err) {
      if (err instanceof ProtocolError) {
        status = err.status;
        body = { error: err.message, ...(err.extra ?? {}) };
      } else {
        status = 500;
        body = { error: 'internal error' };
        log(`${new Date().toISOString()} error ${err.stack ?? err.message}`);
      }
    }
    // A consumed request stream reads as destroyed, so the socket is what
    // says whether there is still anyone to answer (the 413 path drops it).
    if (!res.destroyed && !res.socket?.destroyed) {
      res.writeHead(status, { 'content-type': 'application/json' }).end(JSON.stringify(body));
    }
    log(`${new Date().toISOString()} ${op} ${who} ${status} ${Date.now() - started}ms`);
  });
  return server;
}

// --- config ---------------------------------------------------------------------------

export function defaultDataDir(env = process.env) {
  return env.CCSWITCH_SERVER_DIR || path.join(os.homedir(), '.ccswitch-server');
}

export function readServerConfig(dataDir) {
  try {
    return JSON.parse(fs.readFileSync(path.join(dataDir, 'server.json'), 'utf8'));
  } catch (err) {
    if (err.code === 'ENOENT') return null;
    throw err;
  }
}

export function writeServerConfig(dataDir, cfg) {
  fs.mkdirSync(dataDir, { recursive: true, mode: 0o700 });
  fs.writeFileSync(path.join(dataDir, 'server.json'), JSON.stringify(cfg, null, 2), { mode: 0o600 });
}

export function newPathSecret() {
  return crypto.randomBytes(32).toString('hex');
}

export function baseUrl({ host, port, pathSecret, publicUrl }) {
  if (publicUrl) return `${publicUrl.replace(/\/+$/, '')}/${pathSecret}`;
  const h = host === '0.0.0.0' || host === '::' ? os.hostname() : host;
  return `http://${h.includes(':') ? `[${h}]` : h}:${port}/${pathSecret}`;
}

// --- CLI ------------------------------------------------------------------------------

export class UsageError extends Error {}

async function ask(rl, question, fallback) {
  const a = (await rl.question(`${question}${fallback !== undefined ? ` [${fallback}]` : ''}: `)).trim();
  return a || fallback;
}

export async function setup(dataDir, { rl, out = console.log } = {}) {
  const own = !rl;
  rl ??= readline.createInterface({ input: process.stdin, output: process.stdout });
  try {
    try {
      await ensureGpg({ rl, out });
    } catch (err) {
      if (err instanceof GpgMissingError) throw new UsageError(err.message);
      throw err;
    }
    const existing = readServerConfig(dataDir);
    if (existing) {
      const again = (await rl.question(`${dataDir} is already set up. Reconfigure (keeps vaults and URL)? [y/N] `)).trim().toLowerCase();
      if (again !== 'y' && again !== 'yes') throw new UsageError('setup cancelled');
    }
    out('Bind to 127.0.0.1 and put a TLS reverse proxy in front for anything beyond localhost;');
    out('0.0.0.0 exposes the server directly.');
    const host = await ask(rl, 'Listen host', existing?.host ?? '127.0.0.1');
    const port = Number(await ask(rl, 'Listen port', String(existing?.port ?? 8787)));
    if (!Number.isInteger(port) || port < 1 || port > 65535) throw new UsageError(`invalid port ${port}`);
    const publicUrl = (await ask(rl, 'Public URL clients reach this server at (empty = http://host:port)', existing?.publicUrl ?? '')) || undefined;
    const cfg = { host, port, pathSecret: existing?.pathSecret ?? newPathSecret(), ...(publicUrl ? { publicUrl } : {}) };
    writeServerConfig(dataDir, cfg);
    createVaultStore(dataDir);
    out(`\nwrote ${path.join(dataDir, 'server.json')}`);
    out(`\nClient sync URL (treat it as a secret, it is the only thing keeping strangers out):\n  ${baseUrl(cfg)}`);
    out(`\nStart with: ccswitch-server start${dataDir === defaultDataDir() ? '' : ` --data-dir ${dataDir}`}`);
    return cfg;
  } finally {
    if (own) rl.close();
  }
}

function requireConfig(dataDir) {
  const cfg = readServerConfig(dataDir);
  if (!cfg) throw new UsageError(`no server configured in ${dataDir}; run "ccswitch-server setup" first`);
  return cfg;
}

const HELP = `usage: ccswitch-server [--data-dir <dir>] <command>

  setup        interactive first-time configuration (checks gpg, picks host/port, mints the secret URL)
  start        run the server (default)
  url          print the client sync URL again
  rotate-url   mint a new secret path; every client must run "ccswitch sync setup" again

Data lives in ~/.ccswitch-server (or CCSWITCH_SERVER_DIR / --data-dir). Vaults are
PGP ciphertext keyed by the owner's public key fingerprint; the server holds no
tokens and no private keys. Limits: ${MAX_VAULTS} vaults, 1 MiB each.`;

export async function main(argv = process.argv.slice(2)) {
  const args = [...argv];
  let dataDir = defaultDataDir();
  const di = args.indexOf('--data-dir');
  if (di !== -1) {
    dataDir = args[di + 1];
    if (!dataDir) throw new UsageError('--data-dir needs a path');
    args.splice(di, 2);
  }
  const cmd = args[0] ?? 'start';
  switch (cmd) {
    case 'help':
    case '-h':
    case '--help':
      console.log(HELP);
      return 0;
    case 'setup':
      await setup(dataDir);
      return 0;
    case 'url':
      console.log(baseUrl(requireConfig(dataDir)));
      return 0;
    case 'rotate-url': {
      const cfg = { ...requireConfig(dataDir), pathSecret: newPathSecret() };
      writeServerConfig(dataDir, cfg);
      console.log(baseUrl(cfg));
      return 0;
    }
    case 'start': {
      const cfg = requireConfig(dataDir);
      if (!findGpg()) throw new UsageError(`gpg not found\n${installHint()}`);
      const server = createSyncServer({ dataDir, pathSecret: cfg.pathSecret });
      await new Promise((resolve, reject) => {
        server.once('error', reject);
        server.listen(cfg.port, cfg.host, resolve);
      });
      console.log(`ccswitch-server listening on ${cfg.host}:${cfg.port}; client URL: ${baseUrl(cfg)}`);
      await new Promise((resolve) => {
        const stop = () => server.close(resolve);
        process.once('SIGINT', stop);
        process.once('SIGTERM', stop);
      });
      return 0;
    }
    default:
      throw new UsageError(`unknown command ${JSON.stringify(cmd)} (see ccswitch-server --help)`);
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
  main().then(
    (code) => process.exit(code),
    (err) => {
      console.error(`ccswitch-server: ${err instanceof UsageError || err instanceof GpgMissingError ? err.message : (err.stack ?? err.message)}`);
      process.exit(1);
    },
  );
}
