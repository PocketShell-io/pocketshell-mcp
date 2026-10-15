import { inspect } from 'node:util';
import { requestJson, UpstreamError } from './upstream.mjs';
const LOCKED = 'vault locked: re-authorize to unlock';
export const DEFAULT_VAULT_TTL = 8 * 3600;
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
// written to the store, logs or errors; a restart, revoke or TTL expiry drops it.
export class VaultSessions {
  #grants = new Map();
  constructor({ ttlSeconds = DEFAULT_VAULT_TTL, now = Date.now } = {}) {
    if (!Number.isInteger(ttlSeconds) || ttlSeconds < 60 || ttlSeconds > 30 * 86400) throw new Error('MCP_VAULT_TTL_SECONDS must be an integer between 60 and 2592000');
    this.ttl = ttlSeconds * 1000; this.now = now;
  }
  // grantExpiry is the grant/refresh-token life; the vault never outlives it.
  put(grantId, keys, grantExpiry) {
    this.drop(grantId);
    const hosts = new Map();
    for (const { host, keyId, pem } of keys) hosts.set(host, { keyId, key: new SecretKey(pem) });
    const expiry = Math.min(this.now() + this.ttl, grantExpiry);
    const timer = setTimeout(() => this.drop(grantId), Math.max(0, expiry - this.now())); timer.unref();
    this.#grants.set(grantId, { hosts, expiry, timer });
    return expiry;
  }
  #live(grantId) {
    const session = this.#grants.get(grantId);
    if (session && session.expiry <= this.now()) { this.drop(grantId); return null; }
    return session || null;
  }
  key(grantId, host) {
    const entry = this.#live(grantId)?.hosts.get(host);
    if (!entry) throw new VaultLockedError();
    return entry.key;
  }
  status(grantId) {
    const session = this.#live(grantId);
    return session ? { hosts: [...session.hosts.keys()], expiresAt: new Date(session.expiry).toISOString() } : null;
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
    // Public KDF parameters for the gated order; null when phase 2 is not deployed.
    async status({ token }) {
      try { const raw = await requestJson(base, '/cli/vault/status', { token, fetcher }); return raw?.kdf && typeof raw.kdf === 'object' ? { kdf: raw.kdf } : {}; }
      catch (error) { if (error instanceof UpstreamError && [404, 503].includes(error.status)) return {}; throw error; }
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
