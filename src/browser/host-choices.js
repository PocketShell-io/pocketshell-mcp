// Which MCP-configured hosts an unlocked vault can serve. Bindings are keyed by account host alias.
// Works on @pocketshell/core's KeyVaultStore (getHostBinding/getKey); no crypto here.
export function hostChoices(store, hostNames) {
  return hostNames.map(name => {
    const binding = store.getHostBinding(name);
    const key = binding && store.getKey(binding.keyId);
    if (!key) return { name, available: false, reason: 'no vault key bound to this host' };
    if (key.type === 'password') return { name, available: false, reason: 'password login is not available over MCP' };
    return { name, available: true, keyId: key.keyId, keyName: typeof key.name === 'string' ? key.name : key.keyId, fingerprint: typeof key.fingerprint === 'string' ? key.fingerprint : '' };
  });
}
// AUTH goes to the verifier as base64url without padding (W2 contract).
export function toB64u(bytes) {
  let text = '';
  for (const b of bytes) text += String.fromCharCode(b);
  return btoa(text).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
// The consent page reads ciphertext through the connector's transaction-bound proxies; it never writes.
export function proxyTransport(post) {
  const readOnly = async () => ({ kind: 'error', message: 'read-only vault access' });
  return {
    transport: { pull: slot => post('pull', { slot }), push: readOnly, delete: async () => { throw new Error('read-only vault access'); }, list: async () => [] },
    verifier: { verify: auth => post('verify', { auth: toB64u(auth) }), status: () => post('status') },
  };
}
