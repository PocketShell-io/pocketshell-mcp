// Test-only vault writer for the section-3 format. Production never creates vaults (web only).
import { webcrypto, randomBytes, createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { argon2id } from 'hash-wasm';
import { toB64u } from '../src/browser/vault-format.js';
const { subtle } = webcrypto;
const enc = new TextEncoder();
const P = 'pocketshell-vault/v1/';
async function seal(key, plaintext, aad) {
  const iv = randomBytes(12);
  const ct = new Uint8Array(await subtle.encrypt({ name: 'AES-GCM', iv, additionalData: enc.encode(aad) }, key, typeof plaintext === 'string' ? enc.encode(plaintext) : plaintext));
  return { n: toB64u(iv), ct: toB64u(ct) };
}
async function hkdf(master, label) {
  const base = await subtle.importKey('raw', master, 'HKDF', false, ['deriveBits']);
  return new Uint8Array(await subtle.deriveBits({ name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(0), info: enc.encode(P + label) }, base, 256));
}
export function throwawayKey() {
  const dir = mkdtempSync(join(tmpdir(), 'vk-'));
  try {
    execFileSync('ssh-keygen', ['-q', '-t', 'ed25519', '-N', '', '-C', 'throwaway', '-f', join(dir, 'k')]);
    const publicKey = readFileSync(join(dir, 'k.pub'), 'utf8').trim();
    const wire = Buffer.from(publicKey.split(' ')[1], 'base64');
    return { pem: readFileSync(join(dir, 'k'), 'utf8'), publicKey, keyId: toB64u(createHash('sha256').update(wire).digest().subarray(0, 16)) };
  } finally { rmSync(dir, { recursive: true, force: true }); }
}
// keys: [{keyId, pem, type?, password?}], hosts: {alias: keyId}
export async function makeVault(passphrase, { keys, hosts, kdf = { m: 8192, t: 1, p: 1 } }) {
  const vaultId = toB64u(randomBytes(16)), salt = randomBytes(16);
  const master = await argon2id({ password: passphrase.normalize('NFKC'), salt, parallelism: kdf.p, iterations: kdf.t, memorySize: kdf.m, hashLength: 32, outputType: 'binary' });
  const kek = await subtle.importKey('raw', await hkdf(master, 'kek'), 'AES-GCM', false, ['encrypt']);
  const rawDek = randomBytes(32);
  const dek = await subtle.importKey('raw', rawDek, 'AES-GCM', false, ['encrypt']);
  const index = { keys: keys.map(k => ({ keyId: k.keyId, name: `key-${k.keyId.slice(0, 4)}`, type: k.type || 'ssh-ed25519', fingerprint: 'SHA256:synthetic', createdAt: new Date().toISOString() })), hosts: Object.fromEntries(Object.entries(hosts).map(([alias, keyId]) => [alias, { keyId, gatewayAuth: 'managed' }])), sync: { passphrase: 'synthetic sync passphrase' } };
  const header = { v: 1, vaultId, kdf: { alg: 'argon2id', ...kdf, salt: toB64u(salt) }, wrappedDek: await seal(kek, rawDek, `${P}dek|${vaultId}`), check: await seal(kek, 'pocketshell-vault-check-v1', `${P}check|${vaultId}`), index: await seal(dek, JSON.stringify(index), `${P}index|${vaultId}`), epoch: 1, updatedAt: new Date().toISOString() };
  const slots = { vault: JSON.stringify(header) };
  for (const k of keys) slots[`vk-${k.keyId}`] = JSON.stringify({ v: 1, vaultId, keyId: k.keyId, ...await seal(dek, k.type === 'password' ? k.password : k.pem, `${P}key|${vaultId}|${k.keyId}`) });
  return { header: slots.vault, slots, auth: toB64u(await hkdf(master, 'auth')) };
}
