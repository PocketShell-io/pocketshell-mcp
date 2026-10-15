// Test vaults are created with @pocketshell/core's own KeyVaultStore (the pinned vendor bundle),
// exactly as the web app does; this file holds no crypto. Keys are freshly generated throwaways.
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { KeyVaultStore, vaultKeyIdForPublicKey } from '../vendor/key-vault.mjs';
export const memoryTransport = (slots, gate = { open: true }) => ({
  pull: async slot => !gate.open && /^(vault|vk-)/.test(slot) ? { kind: 'gated' } : slots[slot] ? { kind: 'ok', version: 1, data: slots[slot] } : { kind: 'absent' },
  push: async (slot, data) => { slots[slot] = data; return { kind: 'ok', version: 1 }; },
  delete: async slot => { delete slots[slot]; },
  list: async () => Object.keys(slots).map(slot => ({ slot, version: 1 })),
});
export function throwawayKey() {
  const dir = mkdtempSync(join(tmpdir(), 'vk-'));
  try {
    execFileSync('ssh-keygen', ['-q', '-t', 'ed25519', '-N', '', '-C', 'throwaway', '-f', join(dir, 'k')]);
    const publicKey = readFileSync(join(dir, 'k.pub'), 'utf8').trim();
    return { pem: readFileSync(join(dir, 'k'), 'utf8'), publicKey };
  } finally { rmSync(dir, { recursive: true, force: true }); }
}
// keys: [{pem} | {password}] with host aliases to bind; returns the slots plus each key's keyId.
export async function makeVault(passphrase, { keys, kdf = { m: 32768, t: 1, p: 1 } }) {
  const slots = {};
  const store = new KeyVaultStore({ transport: memoryTransport(slots), kdf });
  const created = await store.createVault(passphrase, { syncPassphrase: 'synthetic sync passphrase' });
  if (created.kind !== 'ok') throw new Error(`createVault: ${created.kind}`);
  for (const key of keys) {
    const added = key.password ? await store.addPassword(key.password, `${key.host} password`) : await store.addKey(key.pem, `key for ${key.host}`);
    if (added.kind !== 'ok') throw new Error(`add: ${added.kind}`);
    key.keyId = added.entry.keyId;
    const bound = await store.bindHost(key.host, key.keyId, 'managed');
    if (bound.kind !== 'ok') throw new Error(`bind: ${bound.kind}`);
  }
  store.lock();
  return { slots, header: slots.vault };
}
export { KeyVaultStore, vaultKeyIdForPublicKey };
