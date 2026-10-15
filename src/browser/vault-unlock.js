// Consent-page vault unlock. The passphrase, master key and DEK never leave this page.
// Only the private keys of hosts the user ticks are sent, over TLS, to bind to this grant.
// The connector proxies ciphertext reads and the phase-2 verifier with the user's own session.
import { KeyVaultStore } from './key-vault.js';
import { hostChoices, proxyTransport } from './host-choices.js';
const data = JSON.parse(document.getElementById('vault-data').textContent);
const $ = id => document.getElementById(id);
const status = text => { $('vault-status').textContent = text; };
const post = async (path, body = {}) => {
  const response = await fetch(`${data.prefix}/oauth/vault/${path}`, { method: 'POST', credentials: 'same-origin', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ csrf: data.csrf, ...body }) });
  const result = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(result.error || 'request_failed');
  return result;
};
const store = new KeyVaultStore(proxyTransport(post));
const seconds = ms => Math.max(1, Math.ceil(ms / 1000));
$('vault-unlock').addEventListener('submit', async event => {
  event.preventDefault();
  const field = $('vault-passphrase'), button = $('vault-unlock-button');
  button.disabled = true; status('Unlocking…');
  const result = await store.unlock(field.value).catch(() => ({ kind: 'error' }));
  button.disabled = false;
  if (result.kind === 'ok') { field.value = ''; $('vault-unlock').hidden = true; status(''); return renderHosts(hostChoices(store, data.hosts)); }
  status({
    wrongPassphrase: "That passphrase didn't unlock your vault." + (result.retryAfterMs ? ` Try again in ${seconds(result.retryAfterMs)} s.` : ''),
    backoff: `Wait ${seconds(result.retryAfterMs || 0)} s before trying again.`,
    rateLimited: `Too many attempts. Try again in ${seconds(result.retryAfterMs || 60000)} s.`,
    noVault: 'This account has no key vault yet. Set one up on the web, or continue without keys.',
    unsupportedVersion: 'Your vault was saved by a newer PocketShell version than this connector supports. Ask the operator to update it, or continue without keys.',
  }[result.kind] || 'The vault could not be read. Continue without keys, or try again later.');
});
function renderHosts(choices) {
  const list = $('vault-hosts');
  list.replaceChildren();
  for (const choice of choices) {
    const label = document.createElement('label');
    const box = document.createElement('input');
    box.type = 'checkbox'; box.value = choice.name; box.disabled = !choice.available;
    label.append(box, ` ${choice.name}`, choice.available ? ` (key ${choice.keyName}${choice.fingerprint ? ', ' + choice.fingerprint : ''})` : ` (${choice.reason})`);
    const row = document.createElement('p'); row.append(label); list.append(row);
  }
  $('vault-select').hidden = false;
}
$('vault-select').addEventListener('submit', async event => {
  event.preventDefault();
  const picked = [...document.querySelectorAll('#vault-hosts input:checked')].map(box => box.value);
  if (!picked.length) return status('Tick at least one host, or continue without keys.');
  const button = $('vault-select-button'); button.disabled = true; status('Decrypting the selected keys…');
  try {
    const keys = [];
    for (const host of picked) {
      const result = await store.decryptKeyForHost(host);
      if (result.kind !== 'key') throw new Error(result.kind);
      keys.push({ host, keyId: store.getHostBinding(host).keyId, pem: result.pem });
    }
    const { location } = await post('finish', { keys });
    keys.length = 0; store.lock();
    status('Unlocked. Returning to your client…');
    window.location.assign(location);
  } catch {
    status('Unlock failed. Continue without keys, or start the connection again.');
    button.disabled = false;
  }
});
