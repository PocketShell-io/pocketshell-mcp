// Interim read-only KeyVaultStore for the consent page, using the names of @pocketshell/core's
// keyVault API (W1) so the swap to core is an import change. The format is design section 3:
// Argon2id (injected, hash-wasm), HKDF-SHA256 (empty salt), AES-256-GCM with bound AAD.
// Runs in browsers and Node 24 (WebCrypto). Delete once core's keyVault is published.
const encoder = new TextEncoder();
const PREFIX = 'pocketshell-vault/v1/';
const CHECK = 'pocketshell-vault-check-v1';
export const VAULT_HEADER_SLOT = 'vault';
export const vaultKeySlot = keyId => `vk-${keyId}`;
class Corrupt extends Error {}
export function fromB64u(value) {
  if (typeof value !== 'string' || !/^[A-Za-z0-9_-]*$/.test(value)) throw new Corrupt();
  const text = atob(value.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - value.length % 4) % 4));
  return Uint8Array.from(text, c => c.charCodeAt(0));
}
export function toB64u(bytes) {
  let text = '';
  for (const b of bytes) text += String.fromCharCode(b);
  return btoa(text).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
const sized = (value, length) => { const bytes = fromB64u(value); if (bytes.length !== length) throw new Corrupt(); return bytes; };
const aead = sealed => { if (!sealed || typeof sealed !== 'object') throw new Corrupt(); return { iv: sized(sealed.n, 12), ct: fromB64u(sealed.ct) }; };
// Unlock uses the stored parameters; bounds only stop a hostile header exhausting the browser.
function parseKdf(k) {
  if (k?.alg !== 'argon2id' || !Number.isInteger(k.m) || k.m < 8192 || k.m > 1048576 || !Number.isInteger(k.t) || k.t < 1 || k.t > 16 || !Number.isInteger(k.p) || k.p < 1 || k.p > 8) throw new Corrupt();
  sized(k.salt, 16); return k;
}
function parseHeader(data) {
  let header;
  try { header = JSON.parse(data); } catch { throw new Corrupt(); }
  if (header?.v !== 1 || typeof header.vaultId !== 'string' || !Number.isInteger(header.epoch)) throw new Corrupt();
  parseKdf(header.kdf); sized(header.vaultId, 16); aead(header.wrappedDek); aead(header.check); aead(header.index);
  return header;
}
async function hkdf(subtle, master, label) {
  const base = await subtle.importKey('raw', master, 'HKDF', false, ['deriveBits']);
  return new Uint8Array(await subtle.deriveBits({ name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(0), info: encoder.encode(PREFIX + label) }, base, 256));
}
async function open(subtle, key, sealed, aad) {
  const { iv, ct } = aead(sealed);
  return new Uint8Array(await subtle.decrypt({ name: 'AES-GCM', iv, additionalData: encoder.encode(aad) }, key, ct));
}
export async function derivePassphraseKeys(passphrase, kdf, { argon2id, subtle = globalThis.crypto.subtle }) {
  const master = await argon2id({ password: passphrase.normalize('NFKC'), salt: fromB64u(kdf.salt), parallelism: kdf.p, iterations: kdf.t, memorySize: kdf.m, hashLength: 32, outputType: 'binary' });
  try {
    const kek = await subtle.importKey('raw', await hkdf(subtle, master, 'kek'), 'AES-GCM', false, ['decrypt']);
    return { kek, auth: await hkdf(subtle, master, 'auth') };
  } finally { master.fill(0); }
}
export const vaultBackoffMs = failures => failures < 3 ? 0 : Math.min(30000, 1000 * 2 ** (failures - 3));
export class KeyVaultStore {
  #transport; #verifier; #argon2id; #subtle; #now; #dek = null; #index = null; #failures = 0; #notBefore = 0;
  constructor({ transport, verifier, argon2id, subtle = globalThis.crypto.subtle, now = Date.now }) {
    this.#transport = transport; this.#verifier = verifier; this.#argon2id = argon2id; this.#subtle = subtle; this.#now = now;
    this.state = 'locked'; this.vaultId = null; this.epoch = null;
  }
  backoffRemainingMs() { return Math.max(0, this.#notBefore - this.#now()); }
  lock() { this.#dek = null; this.#index = null; this.state = 'locked'; }
  #wrong(retryAfterMs = 0) {
    this.#failures++; this.#notBefore = this.#now() + Math.max(retryAfterMs, vaultBackoffMs(this.#failures));
    return { kind: 'wrongPassphrase', retryAfterMs: this.backoffRemainingMs() };
  }
  async #verify(auth) {
    if (!this.#verifier) return null;
    const answer = await this.#verifier.verify(auth);
    if (answer.kind === 'wrong') return this.#wrong(answer.retryAfterMs);
    if (answer.kind === 'locked') return { kind: 'rateLimited', retryAfterMs: answer.retryAfterMs };
    return null; // ok, noVerifier, unavailable: the local check value decides.
  }
  // Ungated: read header, check locally, then verify (the server may gate vk-* reads on it).
  // Gated (phase 2 hides the header): status -> Argon2id -> AUTH -> verify -> read header -> check.
  async unlock(passphrase) {
    if (this.backoffRemainingMs()) return { kind: 'backoff', retryAfterMs: this.backoffRemainingMs() };
    try {
      let pulled = await this.#transport.pull(VAULT_HEADER_SLOT), keys = null, gatedSalt = null;
      if (pulled.kind === 'absent') return { kind: 'noVault' };
      if (pulled.kind === 'gated') {
        const kdf = (await this.#verifier?.status())?.kdf;
        if (!kdf) return { kind: 'error', message: 'vault status unavailable' };
        gatedSalt = parseKdf(kdf).salt;
        keys = await derivePassphraseKeys(passphrase, kdf, { argon2id: this.#argon2id, subtle: this.#subtle });
        const answer = await this.#verify(keys.auth); if (answer) return answer;
        pulled = await this.#transport.pull(VAULT_HEADER_SLOT);
      }
      if (pulled.kind === 'absent') return { kind: 'noVault' };
      if (pulled.kind !== 'ok') return { kind: 'error', message: pulled.message || 'vault unavailable' };
      const header = parseHeader(pulled.data);
      if (gatedSalt && header.kdf.salt !== gatedSalt) return { kind: 'corrupt' };
      keys ||= await derivePassphraseKeys(passphrase, header.kdf, { argon2id: this.#argon2id, subtle: this.#subtle });
      try {
        if (new TextDecoder().decode(await open(this.#subtle, keys.kek, header.check, `${PREFIX}check|${header.vaultId}`)) !== CHECK) throw new Error();
      } catch { return this.#wrong(); }
      if (!gatedSalt) { const answer = await this.#verify(keys.auth); if (answer) return answer; }
      keys.auth.fill(0);
      const raw = await open(this.#subtle, keys.kek, header.wrappedDek, `${PREFIX}dek|${header.vaultId}`);
      const dek = await this.#subtle.importKey('raw', raw, 'AES-GCM', false, ['decrypt']); raw.fill(0);
      const index = JSON.parse(new TextDecoder().decode(await open(this.#subtle, dek, header.index, `${PREFIX}index|${header.vaultId}`)));
      if (!index || !Array.isArray(index.keys) || !index.hosts || typeof index.hosts !== 'object') return { kind: 'corrupt' };
      delete index.sync; // The account sync passphrase is not needed here.
      this.#dek = dek; this.#index = index; this.vaultId = header.vaultId; this.epoch = header.epoch; this.state = 'unlocked'; this.#failures = 0;
      return { kind: 'ok' };
    } catch (error) { return error instanceof Corrupt || error?.name === 'OperationError' || error instanceof SyntaxError ? { kind: 'corrupt' } : { kind: 'error', message: 'vault unavailable' }; }
  }
  getKey(keyId) { return this.#index?.keys.find(k => k.keyId === keyId) || null; }
  getHostBinding(hostAlias) { return this.#index && Object.hasOwn(this.#index.hosts, hostAlias) ? this.#index.hosts[hostAlias] : null; }
  async decryptKeyForHost(hostAlias) {
    if (this.state !== 'unlocked') return { kind: 'locked' };
    const binding = this.getHostBinding(hostAlias);
    return binding ? this.decryptKey(binding.keyId) : { kind: 'unbound' };
  }
  async decryptKey(keyId) {
    if (this.state !== 'unlocked') return { kind: 'locked' };
    const entry = this.getKey(keyId);
    if (!entry) return { kind: 'missingKey', keyId };
    try {
      const pulled = await this.#transport.pull(vaultKeySlot(keyId));
      if (pulled.kind === 'absent') return { kind: 'missingKey', keyId };
      if (pulled.kind !== 'ok') return { kind: 'error', message: pulled.message || 'vault unavailable' };
      const blob = JSON.parse(pulled.data);
      if (blob?.v !== 1 || blob.vaultId !== this.vaultId || blob.keyId !== keyId) return { kind: 'corrupt' };
      const bytes = await open(this.#subtle, this.#dek, { n: blob.n, ct: blob.ct }, `${PREFIX}key|${this.vaultId}|${keyId}`);
      const text = new TextDecoder().decode(bytes); bytes.fill(0);
      return entry.type === 'password' ? { kind: 'password', password: text } : { kind: 'key', pem: text };
    } catch { return { kind: 'corrupt' }; }
  }
}
// Which MCP-configured hosts this vault can unlock. Bindings are keyed by account host alias.
export function hostChoices(store, hostNames) {
  return hostNames.map(name => {
    const binding = store.getHostBinding(name);
    const key = binding && store.getKey(binding.keyId);
    if (!key) return { name, available: false, reason: 'no vault key bound to this host' };
    if (key.type === 'password') return { name, available: false, reason: 'password login is not available over MCP' };
    return { name, available: true, keyId: key.keyId, keyName: typeof key.name === 'string' ? key.name : key.keyId, fingerprint: typeof key.fingerprint === 'string' ? key.fingerprint : '' };
  });
}
