import { inspect } from 'node:util';
import { url as inspectorUrl } from 'node:inspector';
import { requestJson, UpstreamError } from './upstream.mjs';
const LOCKED = 'vault locked: re-authorize to unlock';
export const DEFAULT_VAULT_TTL = 8 * 3600;
export const DEFAULT_VAULT_IDLE = 1800;
const MAX_TIMER = 2 ** 31 - 1;
export class VaultLockedError extends Error {
  constructor() { super(LOCKED); this.code = 'VAULT_LOCKED'; }
}
// A decrypted private key. Redacted from inspect/JSON/string conversion so a stray log or
// error serializer cannot print it; zeroed when its session is dropped.
export class SecretKey {
  #bytes;
  constructor(pem) { this.#bytes = Buffer.from(pem, 'utf8'); }
  use() { if (!this.#bytes) throw new VaultLockedError(); return this.#bytes; }
  wipe() { this.#bytes?.fill(0); this.#bytes = null; }
  toJSON() { return '[redacted]'; }
  toString() { return '[redacted]'; }
  [inspect.custom]() { return 'SecretKey [redacted]'; }
}
const PEM = /^-----BEGIN (?:OPENSSH |RSA |EC |)PRIVATE KEY-----\r?\n[A-Za-z0-9+/=\r\n]+-----END (?:OPENSSH |RSA |EC |)PRIVATE KEY-----\r?\n?$/;
const KEY_ID = /^[A-Za-z0-9_-]{22}$/;
// Unlocked vault keys per OAuth grant, held only in this process's memory. Nothing here is ever
// written to the store, logs or errors; a restart, revoke, absolute TTL or idle timeout drops it.
export class VaultSessions {
  #grants = new Map();
  constructor({ ttlSeconds = DEFAULT_VAULT_TTL, idleSeconds = DEFAULT_VAULT_IDLE, now = Date.now } = {}) {
    if (!Number.isInteger(ttlSeconds) || ttlSeconds < 60 || ttlSeconds > 30 * 86400) throw new Error('MCP_VAULT_TTL_SECONDS must be an integer between 60 and 2592000');
    if (!Number.isInteger(idleSeconds) || idleSeconds < 60 || idleSeconds > ttlSeconds) throw new Error('MCP_VAULT_IDLE_SECONDS must be an integer between 60 and the TTL');
    this.ttl = ttlSeconds * 1000; this.idle = idleSeconds * 1000; this.now = now;
  }
  #deadline(session) { return session.pendingUntil ?? Math.min(session.expiry, session.lastUsed + this.idle); }
  // One timer per grant at the nearer of absolute expiry and idle deadline; re-armed when use moved it.
  #arm(grantId, session) {
    clearTimeout(session.timer);
    session.timer = setTimeout(() => {
      if (this.#grants.get(grantId) !== session) return;
      if (this.#deadline(session) <= this.now()) this.drop(grantId); else this.#arm(grantId, session);
      // setTimeout overflows above 2^31-1 ms (fires at once, then spins); a capped timer just re-arms.
    }, Math.min(MAX_TIMER, Math.max(0, this.#deadline(session) - this.now())));
    session.timer.unref();
  }
  // grantExpiry is the grant/refresh-token life; the vault never outlives it. With pendingMs the keys
  // stay unusable until activate() (the authorization code is redeemed) and drop when that window ends.
  put(grantId, keys, grantExpiry, { pendingMs } = {}) {
    this.drop(grantId);
    const hosts = new Map();
    for (const { host, keyId, pem } of keys) hosts.set(host, { keyId, key: new SecretKey(pem) });
    const session = { hosts, expiry: Math.min(this.now() + this.ttl, grantExpiry), lastUsed: this.now(), timer: null, pendingUntil: pendingMs ? this.now() + pendingMs : null };
    this.#grants.set(grantId, session); this.#arm(grantId, session);
    return session.expiry;
  }
  // Every tool call on the grant counts as use and pushes the idle deadline out.
  #live(grantId) {
    const session = this.#grants.get(grantId);
    if (!session) return null;
    if (this.#deadline(session) <= this.now()) { this.drop(grantId); return null; }
    if (session.pendingUntil) return null;
    session.lastUsed = this.now();
    return session;
  }
  activate(grantId) {
    const session = this.#grants.get(grantId);
    if (!session?.pendingUntil) return;
    if (session.pendingUntil <= this.now()) { this.drop(grantId); return; }
    session.pendingUntil = null; session.lastUsed = this.now(); this.#arm(grantId, session);
  }
  key(grantId, host) {
    const entry = this.#live(grantId)?.hosts.get(host);
    if (!entry) throw new VaultLockedError();
    return entry.key;
  }
  status(grantId) {
    const session = this.#live(grantId);
    return session ? { hosts: [...session.hosts.keys()], expiresAt: new Date(session.expiry).toISOString(), idleExpiresAt: new Date(this.#deadline(session)).toISOString() } : null;
  }
  drop(grantId) {
    const session = this.#grants.get(grantId);
    if (!session) return;
    clearTimeout(session.timer);
    for (const { key } of session.hosts.values()) key.wipe();
    this.#grants.delete(grantId);
  }
  dropAll() { for (const id of [...this.#grants.keys()]) this.drop(id); }
  get size() { return this.#grants.size; }
  [inspect.custom]() { return `VaultSessions [${this.#grants.size} grants, redacted]`; }
}
// Unlocked keys live in this process's heap, so with the vault on the process must not be
// debuggable or heap-dumpable: no inspector flags, no heap snapshots, and no SIGUSR1 inspector.
const UNSAFE_FLAG = /^--(?:inspect(?:-brk|-wait|-port|-publish-uid)?|debug-port|heapsnapshot-signal|heapsnapshot-near-heap-limit|heap-prof|expose-internals)(?:=|$)/;
export function assertVaultProcessSafe({ execArgv = process.execArgv, nodeOptions = process.env.NODE_OPTIONS || '', inspectorOpen = !!inspectorUrl() } = {}) {
  const flags = [...execArgv, ...nodeOptions.split(/\s+/).filter(Boolean)];
  const unsafe = flags.filter(flag => UNSAFE_FLAG.test(flag)).map(flag => flag.split('=')[0]);
  if (unsafe.length || inspectorOpen) throw new Error(`MCP_VAULT=on refuses to run with a debugger or heap snapshots enabled (${unsafe.join(', ') || 'inspector open'})`);
  if (!flags.includes('--disable-sigusr1')) throw new Error('MCP_VAULT=on requires node --disable-sigusr1, so a signal cannot open the inspector on unlocked keys');
}
// The unlock page holds the passphrase, which opens the whole vault. Any other code on the same origin
// (another service under a path prefix, or an XSS there) could script that page, so vault mode needs
// a bare origin that the operator confirms serves nothing else. A process cannot see its neighbours,
// so this fails closed without that confirmation.
export function assertDedicatedVaultOrigin(issuer, confirmed) {
  const url = new URL(issuer);
  if (url.pathname !== '/' && url.pathname !== '') throw new Error('MCP_VAULT=on needs MCP_ISSUER to be a bare origin with no service path');
  if (confirmed !== url.origin) throw new Error(`MCP_VAULT=on needs a dedicated origin: set MCP_VAULT_DEDICATED_ORIGIN=${url.origin} to confirm nothing else is served there`);
}
// Validates what the consent page posts: only configured hosts, private-key PEMs, bounded size.
export function validateUnlock(keys, allowedHosts) {
  if (!Array.isArray(keys) || keys.length < 1 || keys.length > 20) throw new Error('invalid_vault_keys');
  const seen = new Set();
  for (const k of keys) {
    if (!k || typeof k.host !== 'string' || !allowedHosts.includes(k.host) || seen.has(k.host) || typeof k.keyId !== 'string' || !KEY_ID.test(k.keyId) || typeof k.pem !== 'string' || k.pem.length > 16384 || !PEM.test(k.pem)) throw new Error('invalid_vault_keys');
    seen.add(k.host);
  }
  return keys.map(({ host, keyId, pem }) => ({ host, keyId, pem }));
}
// Proxies the consent page's vault reads and phase-2 verify through the CLI-bearer sync routes with
// the user's own device session (W2 contract). The server only ever handles ciphertext and AUTH.
export const VAULT_SLOT = /^(?:vault|vk-[A-Za-z0-9_-]{22})$/;
const retryMs = error => Number.isFinite(error.retryAfter) ? Math.max(0, error.retryAfter) * 1000 : 60000;
export function vaultSource({ base, fetcher }) {
  return {
    // VaultSlotTransport.pull, plus {kind:'gated'} while the phase-2 read gate hides a slot.
    async pull({ token }, slot) {
      if (typeof slot !== 'string' || !VAULT_SLOT.test(slot)) throw new Error('invalid_slot');
      try {
        const raw = await requestJson(base, `/cli/settings/${slot}`, { token, fetcher });
        if (typeof raw?.data !== 'string' || raw.data.length > 16384 || !Number.isInteger(raw.version)) throw new UpstreamError(502, 'invalid_vault');
        return { kind: 'ok', version: raw.version, data: raw.data };
      } catch (error) {
        if (error instanceof UpstreamError && error.status === 404) return { kind: 'absent' };
        if (error instanceof UpstreamError && error.code === 'vault_verify_required') return { kind: 'gated' };
        throw error;
      }
    },
    // VaultServerVerifier.status: public KDF parameters for the gated order (core shape).
    async status({ token }) {
      try {
        const raw = await requestJson(base, '/cli/vault/status', { token, fetcher });
        if (!Number.isInteger(raw?.epoch) || typeof raw.hasVerifier !== 'boolean') return { kind: 'unavailable' };
        return { kind: 'ok', epoch: raw.epoch, hasVerifier: raw.hasVerifier, retryAfterMs: Number.isFinite(raw.retryAfter) ? raw.retryAfter * 1000 : 0, ...(raw.kdf && typeof raw.kdf === 'object' ? { kdf: raw.kdf } : {}) };
      } catch (error) { if (error instanceof UpstreamError) return { kind: 'unavailable' }; throw error; }
    },
    // VaultServerVerifier.verify, mapped 1:1 from the W2 responses.
    async verify({ token }, auth) {
      if (typeof auth !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(auth)) throw new Error('invalid_request');
      try { await requestJson(base, '/cli/vault/verify', { method: 'POST', body: { auth }, token, fetcher }); return { kind: 'ok' }; }
      catch (error) {
        if (!(error instanceof UpstreamError)) return { kind: 'unavailable' };
        if (error.code === 'wrong_passphrase') return { kind: 'wrong', retryAfterMs: retryMs(error) };
        if (error.status === 429) return { kind: 'locked', retryAfterMs: retryMs(error) };
        if (error.code === 'no_verifier') return { kind: 'noVerifier' };
        if (error.status === 404 || error.status === 503 || error.code === 'verifier_stale') return { kind: 'unavailable' };
        throw error;
      }
    },
  };
}
