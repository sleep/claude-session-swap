// Sync protocol: the pure part shared by the ccswitch client and the sync
// server. No I/O here; signing, verifying, encrypting and decrypting are
// injected so this module is testable without gpg and reusable on both ends.
//
// Wire format: an envelope {publicKey, payload, signature} where payload is a
// JSON string signed byte-for-byte by the user's OpenPGP key. The server
// verifies the string first and parses it only afterwards, so there is no
// canonicalisation step to get wrong. The signed payload binds the operation,
// the vault name, a timestamp and the version the client is building on, so a
// captured request cannot be replayed against another vault or a later state.
import crypto from 'node:crypto';

export const PROTOCOL_VERSION = 1;
export const MAX_DATA_BYTES = 1024 * 1024; // one encrypted vault
export const MAX_BODY_BYTES = 2 * 1024 * 1024; // whole request body
export const MAX_PUBKEY_BYTES = 64 * 1024;
export const MAX_SIGNATURE_BYTES = 8 * 1024;
export const MAX_VAULTS = 1024; // global cap on the server
export const TS_WINDOW_MS = 5 * 60 * 1000;
export const VAULT_NAMES = ['claude', 'kimi']; // one vault per backend
export const MAX_ALTERNATES = 4;

const PUBKEY_HEADER = '-----BEGIN PGP PUBLIC KEY BLOCK-----';
const SIGNATURE_HEADER = '-----BEGIN PGP SIGNATURE-----';
const MESSAGE_HEADER = '-----BEGIN PGP MESSAGE-----';

// Carries the HTTP status the server should answer with, plus an optional
// body (the 409 path returns the current vault so the client can merge
// without a second round trip).
export class ProtocolError extends Error {
  constructor(status, message, extra = null) {
    super(message);
    this.status = status;
    this.extra = extra;
  }
}

// --- digests -------------------------------------------------------------------

export function canonicalJson(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (value && typeof value === 'object') {
    const keys = Object.keys(value).filter((k) => value[k] !== undefined).sort();
    return `{${keys.map((k) => `${JSON.stringify(k)}:${canonicalJson(value[k])}`).join(',')}}`;
  }
  return JSON.stringify(value);
}

export function entryDigest(entry) {
  return crypto.createHash('sha256').update(canonicalJson(entry)).digest('hex');
}

export function digestMap(profiles) {
  return Object.fromEntries(Object.entries(profiles).map(([name, entry]) => [name, entryDigest(entry)]));
}

// --- envelope --------------------------------------------------------------------

export function buildEnvelope({ op, vault, baseVersion, data }, pgp, now = Date.now()) {
  const payload = JSON.stringify({
    v: PROTOCOL_VERSION,
    op,
    vault,
    ts: new Date(now).toISOString(),
    baseVersion,
    ...(data == null ? {} : { data }),
  });
  return { publicKey: pgp.exportPublicKey(), payload, signature: pgp.sign(payload) };
}

function bad(message) {
  return new ProtocolError(400, message);
}

// Everything cheap runs before the signature check: gpg is the expensive step,
// and junk should never reach it.
export async function verifyEnvelope(body, urlVault, { verify, now = Date.now() }) {
  if (!body || typeof body !== 'object') throw bad('envelope must be an object');
  const { publicKey, payload, signature } = body;
  for (const [k, v] of Object.entries({ publicKey, payload, signature })) {
    if (typeof v !== 'string') throw bad(`${k} must be a string`);
  }
  if (Buffer.byteLength(publicKey) > MAX_PUBKEY_BYTES) throw new ProtocolError(413, 'public key too large');
  if (Buffer.byteLength(signature) > MAX_SIGNATURE_BYTES) throw new ProtocolError(413, 'signature too large');
  if (Buffer.byteLength(payload) > MAX_DATA_BYTES + 4096) throw new ProtocolError(413, 'payload too large');
  if (!publicKey.startsWith(PUBKEY_HEADER)) throw bad('publicKey is not an armored public key');
  if (!signature.startsWith(SIGNATURE_HEADER)) throw bad('signature is not an armored signature');
  if (!VAULT_NAMES.includes(urlVault)) throw bad('unknown vault');

  let parsed;
  try {
    parsed = JSON.parse(payload);
  } catch {
    throw bad('payload is not JSON');
  }
  if (!parsed || typeof parsed !== 'object') throw bad('payload must be an object');
  if (parsed.v !== PROTOCOL_VERSION) throw bad('unsupported protocol version');
  if (parsed.op !== 'get' && parsed.op !== 'put') throw bad('unknown op');
  if (parsed.vault !== urlVault) throw bad('signed vault name does not match the request');
  if (!Number.isSafeInteger(parsed.baseVersion) || parsed.baseVersion < 0) throw bad('baseVersion must be a non-negative integer');
  if (parsed.op === 'put') {
    if (typeof parsed.data !== 'string' || !parsed.data.startsWith(MESSAGE_HEADER)) throw bad('put data must be an armored PGP message');
    if (Buffer.byteLength(parsed.data) > MAX_DATA_BYTES) throw new ProtocolError(413, 'vault data too large');
  } else if (parsed.data !== undefined) {
    throw bad('get carries no data');
  }
  // Date.parse of garbage is NaN, and NaN compares false against everything,
  // so the finiteness check is what actually enforces the window.
  const ts = typeof parsed.ts === 'string' ? Date.parse(parsed.ts) : NaN;
  if (!Number.isFinite(ts) || Math.abs(now - ts) > TS_WINDOW_MS) throw new ProtocolError(401, 'timestamp outside the accepted window');

  let fingerprint;
  try {
    ({ fingerprint } = await verify({ publicKey, payload, signature }));
  } catch (err) {
    throw new ProtocolError(401, `signature rejected: ${err.message}`);
  }
  return { fingerprint, payload: parsed };
}

// --- three-way merge -------------------------------------------------------------
// Entries are profiles {credentials, oauthAccount, savedAt, machine?,
// alternates?}, deletion tombstones {deletedAt, machine?}, or, on the local
// side only, a moved marker {movedAt} for a profile whose chain was handed to
// another machine with export --move. `base` maps names to the digest each
// entry had after the last successful sync, so a side that still matches its
// base did not change and the other side wins outright. Only when both sides
// changed is any timestamp consulted, and even then a lost chain is never
// dropped: it becomes an alternate for the next use to probe.

const isTombstone = (e) => !!e && typeof e.deletedAt === 'string';
const isMoved = (e) => !!e && typeof e.movedAt === 'string';
const when = (iso) => (typeof iso === 'string' ? Date.parse(iso) : NaN) || 0;

function alternateOf(entry) {
  const alt = { credentials: entry.credentials, savedAt: entry.savedAt };
  if (entry.machine) alt.machine = entry.machine;
  return alt;
}

function conflictProfiles(a, b) {
  const [primary, other] = when(a.savedAt) >= when(b.savedAt) ? [a, b] : [b, a];
  if (primary.credentials === other.credentials) {
    const { alternates: _a, ...rest } = primary;
    const alternates = dedupeAlternates([...(a.alternates ?? []), ...(b.alternates ?? [])], primary.credentials);
    return alternates.length ? { ...rest, alternates } : rest;
  }
  const alternates = dedupeAlternates(
    [alternateOf(other), ...(a.alternates ?? []), ...(b.alternates ?? [])],
    primary.credentials,
  );
  const { alternates: _p, ...rest } = primary;
  return { ...rest, alternates };
}

function dedupeAlternates(list, primaryCredentials) {
  const seen = new Set([primaryCredentials]);
  const out = [];
  for (const alt of list.slice().sort((x, y) => when(y.savedAt) - when(x.savedAt))) {
    if (!alt?.credentials || seen.has(alt.credentials)) continue;
    seen.add(alt.credentials);
    out.push(alt);
  }
  return out.slice(0, MAX_ALTERNATES);
}

function resolveBothChanged(local, remote) {
  if (isTombstone(local) && isTombstone(remote)) return when(remote.deletedAt) > when(local.deletedAt) ? remote : local;
  if (isTombstone(local)) return when(remote.savedAt) > when(local.deletedAt) ? remote : local;
  if (isTombstone(remote)) return when(local.savedAt) > when(remote.deletedAt) ? local : remote;
  return conflictProfiles(local, remote);
}

export function mergeVaults(local, remote, base) {
  const merged = {};
  const localChanges = { write: [], delete: [] };
  let remoteStale = false;
  const names = [...new Set([...Object.keys(local), ...Object.keys(remote)])].sort();
  for (const name of names) {
    const L = local[name];
    const R = remote[name];
    let result;
    if (isMoved(L)) {
      // The server copy stays for the other machines; it only comes back
      // here if it was saved after the move (someone re-logged it in).
      if (!R) continue;
      result = R;
      if (isTombstone(R)) localChanges.delete.push(name);
      else if (when(R.savedAt) > when(L.movedAt)) localChanges.write.push(name);
      merged[name] = result;
      continue;
    }
    if (!L || !R) {
      result = L ?? R;
    } else if (entryDigest(L) === entryDigest(R)) {
      result = L;
    } else {
      const baseDigest = base ? base[name] : undefined;
      const localChanged = baseDigest === undefined || entryDigest(L) !== baseDigest;
      const remoteChanged = baseDigest === undefined || entryDigest(R) !== baseDigest;
      if (localChanged && !remoteChanged) result = L;
      else if (remoteChanged && !localChanged) result = R;
      else result = resolveBothChanged(L, R);
    }
    merged[name] = result;
    if (!L || entryDigest(result) !== entryDigest(L)) {
      if (isTombstone(result)) {
        if (L && !isTombstone(L)) localChanges.delete.push(name);
      } else {
        localChanges.write.push(name);
      }
    }
    if (!R || entryDigest(result) !== entryDigest(R)) remoteStale = true;
  }
  return { merged, localChanges, remoteStale };
}
