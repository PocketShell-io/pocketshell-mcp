import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { once } from 'node:events';
import { randomBytes, createHash } from 'node:crypto';
import { inspect } from 'node:util';
import { mkdtemp, writeFile, readdir, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { readFileSync } from 'node:fs';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import { Store, secret } from '../src/store.mjs';
import { createApp } from '../src/app.mjs';
import { UpstreamError } from '../src/upstream.mjs';
import { pocketTools, executePsc } from '../src/pocketshell.mjs';
import { VaultSessions, VaultLockedError, vaultSource, validateUnlock, assertVaultProcessSafe } from '../src/vault.mjs';
import { hostChoices, proxyTransport, toB64u } from '../src/browser/host-choices.js';
import { makeVault, throwawayKey, memoryTransport, KeyVaultStore, vaultKeyIdForPublicKey } from './vault-fixture.mjs';
const identity = { id: 'synthetic-account', email: 'operator@example.com' };
const passphrase = 'correct horse battery staple';
const body = pem => pem.split('\n').filter(l => l && !l.startsWith('-----')).join('');

test('the pinned core bundle reproduces core known-answer vectors', async () => {
  // Built by scripts/build-client.mjs next to vendor/key-vault.mjs from the same core commit.
  const kat = JSON.parse(readFileSync(new URL('../vendor/vault-v1-vectors.json', import.meta.url), 'utf8'));
  const slots = { vault: kat.headerSlotData, [`vk-${kat.sshKey.keyId}`]: kat.sshKey.slotData, [`vk-${kat.password.keyId}`]: kat.password.slotData };
  const verified = [];
  const store = new KeyVaultStore({ transport: memoryTransport(slots), verifier: { verify: async auth => { verified.push(toB64u(auth)); return { kind: 'ok' }; } } });
  assert.equal((await store.unlock(kat.passphrase)).kind, 'ok');
  assert.deepEqual(verified, [kat.authB64url]);
  assert.deepEqual(await store.decryptKey(kat.sshKey.keyId), { kind: 'key', pem: kat.sshKey.plaintext });
  assert.deepEqual(await store.decryptKey(kat.password.keyId), { kind: 'password', password: kat.password.plaintext });
  assert.equal((await new KeyVaultStore({ transport: memoryTransport(slots) }).unlock(kat.normalizedPassphrase)).kind, 'ok');
});

test('core vault: wrong passphrase, server answers, AAD binding and host choices', async () => {
  const a = throwawayKey(), b = throwawayKey();
  const alpha = { host: 'alpha', pem: a.pem }, beta = { host: 'beta', pem: b.pem }, legacy = { host: 'legacy', password: 'synthetic' };
  const v = await makeVault(passphrase, { keys: [alpha, beta, legacy] });
  assert.equal(alpha.keyId, (await vaultKeyIdForPublicKey(a.publicKey)));
  const verified = [];
  const store = new KeyVaultStore({ transport: memoryTransport(v.slots), verifier: { verify: async auth => { verified.push(toB64u(auth)); return { kind: 'unavailable' }; } } });
  assert.equal((await store.unlock('wrong passphrase')).kind, 'wrongPassphrase');
  assert.equal((await store.unlock(passphrase)).kind, 'ok');
  // Core reports every attempt's AUTH to the verifier, so the server-side failure budget applies.
  assert.equal(verified.length, 2); assert.notEqual(verified[0], verified[1]);
  assert.deepEqual(await store.decryptKeyForHost('alpha'), { kind: 'key', pem: a.pem });
  assert.deepEqual(await store.decryptKeyForHost('legacy'), { kind: 'password', password: 'synthetic' });
  assert.equal((await store.decryptKeyForHost('nowhere')).kind, 'unbound');
  // A blob moved into another key's slot fails its key ID / AAD binding.
  const swapped = new KeyVaultStore({ transport: memoryTransport({ ...v.slots, [`vk-${beta.keyId}`]: v.slots[`vk-${alpha.keyId}`] }) });
  assert.equal((await swapped.unlock(passphrase)).kind, 'ok');
  assert.notEqual((await swapped.decryptKeyForHost('beta')).kind, 'key');
  const choices = hostChoices(store, ['alpha', 'legacy', 'unbound', 'constructor']);
  assert.deepEqual(choices.map(c => [c.name, c.available]), [['alpha', true], ['legacy', false], ['unbound', false], ['constructor', false]]);
  assert.match(choices[1].reason, /password/);
  assert.equal((await new KeyVaultStore({ transport: memoryTransport({}) }).unlock(passphrase)).kind, 'noVault');
  // Ungated, core's local check value is authoritative over a verifier 'wrong'; a lockout still stops unlock.
  for (const [answer, kind] of [[{ kind: 'wrong', retryAfterMs: 5000 }, 'ok'], [{ kind: 'locked', retryAfterMs: 900000 }, 'rateLimited']]) {
    const r = await new KeyVaultStore({ transport: memoryTransport(v.slots), verifier: { verify: async () => answer } }).unlock(passphrase);
    assert.equal(r.kind, kind);
  }
});

test('gated order through the proxy transport: KDF from status, verify, then the header', async () => {
  const a = throwawayKey();
  const alpha = { host: 'alpha', pem: a.pem };
  const v = await makeVault(passphrase, { keys: [alpha] });
  const gate = { open: false }, calls = [], transport = memoryTransport(v.slots, gate);
  // The AUTH a correct passphrase yields, as the server-side verifier would know it.
  const probe = [];
  await new KeyVaultStore({ transport: memoryTransport(v.slots), verifier: { verify: async auth => { probe.push(toB64u(auth)); return { kind: 'ok' }; } } }).unlock(passphrase);
  // What the connector's endpoints return, here without HTTP.
  const post = async (path, body = {}) => {
    calls.push(path);
    if (path === 'pull') return transport.pull(body.slot);
    if (path === 'status') return { kind: 'ok', epoch: 1, hasVerifier: true, retryAfterMs: 0, kdf: JSON.parse(v.header).kdf };
    if (body.auth !== probe[0]) return { kind: 'wrong', retryAfterMs: 0 };
    gate.open = true; return { kind: 'ok' };
  };
  const store = new KeyVaultStore(proxyTransport(post));
  assert.equal((await store.unlock('wrong passphrase')).kind, 'wrongPassphrase');
  assert.equal(gate.open, false);
  assert.equal((await store.unlock(passphrase)).kind, 'ok');
  assert.equal(gate.open, true);
  assert.ok(calls.indexOf('verify') < calls.lastIndexOf('pull'));
  assert.deepEqual(await store.decryptKeyForHost('alpha'), { kind: 'key', pem: a.pem });
});

test('vault sessions expire at TTL, never outlive the grant, wipe on drop and redact', () => {
  let now = 1_000_000;
  const sessions = new VaultSessions({ ttlSeconds: 3600, idleSeconds: 3600, now: () => now });
  const { pem } = throwawayKey();
  const expiry = sessions.put('g1', [{ host: 'alpha', keyId: 'a'.repeat(22), pem }], now + 86400000);
  assert.equal(expiry, now + 3600000);
  const key = sessions.key('g1', 'alpha');
  assert.equal(key.use().toString(), pem);
  for (const view of [inspect(key), JSON.stringify({ key }), String(key), inspect(sessions), `${key}`]) assert.ok(!view.includes(body(pem).slice(0, 24)), view);
  assert.throws(() => sessions.key('g1', 'beta'), VaultLockedError);
  now += 3600000;
  assert.throws(() => sessions.key('g1', 'alpha'), e => e instanceof VaultLockedError && e.message === 'vault locked: re-authorize to unlock');
  assert.throws(() => key.use(), VaultLockedError);
  assert.equal(sessions.size, 0);
  // The refresh-token / grant life caps the TTL.
  sessions.put('g2', [{ host: 'alpha', keyId: 'a'.repeat(22), pem }], now + 60000);
  assert.equal(sessions.status('g2').expiresAt, new Date(now + 60000).toISOString());
  now += 60000; assert.equal(sessions.status('g2'), null);
  assert.throws(() => new VaultSessions({ ttlSeconds: 10 }), /TTL/);
  assert.throws(() => new VaultSessions({ ttlSeconds: 600, idleSeconds: 900 }), /IDLE/);
  // Restart: a fresh process has no sessions.
  assert.throws(() => new VaultSessions().key('g1', 'alpha'), VaultLockedError);
});

test('idle timeout drops keys without a tool call; use extends it up to the absolute TTL', () => {
  let now = 1_000_000;
  const sessions = new VaultSessions({ ttlSeconds: 3600, idleSeconds: 600, now: () => now });
  const { pem } = throwawayKey();
  sessions.put('g', [{ host: 'alpha', keyId: 'a'.repeat(22), pem }], now + 86400000);
  for (let i = 0; i < 5; i++) { now += 599000; sessions.key('g', 'alpha'); }
  assert.equal(sessions.status('g').idleExpiresAt, new Date(now + 600000).toISOString());
  now += 600000;
  assert.throws(() => sessions.key('g', 'alpha'), VaultLockedError);
  assert.equal(sessions.size, 0);
  // Continuous use still ends at the absolute TTL.
  sessions.put('h', [{ host: 'alpha', keyId: 'a'.repeat(22), pem }], now + 86400000);
  const end = now + 3600000;
  while (now + 500000 < end) { now += 500000; sessions.key('h', 'alpha'); }
  now = end; assert.throws(() => sessions.key('h', 'alpha'), VaultLockedError);
});

test('the idle timer drops a grant by itself and re-arms after use', t => {
  t.mock.timers.enable({ apis: ['setTimeout', 'Date'], now: 1_000_000 });
  const sessions = new VaultSessions({ ttlSeconds: 3600, idleSeconds: 600 });
  sessions.put('r', [{ host: 'alpha', keyId: 'a'.repeat(22), pem: throwawayKey().pem }], Date.now() + 86400000);
  t.mock.timers.tick(500000); sessions.key('r', 'alpha');
  t.mock.timers.tick(200000); // the original deadline passes; the timer re-arms for the later one
  assert.equal(sessions.size, 1);
  t.mock.timers.tick(400000);
  assert.equal(sessions.size, 0);
});

test('vault mode refuses a debuggable or heap-dumpable process', () => {
  const safe = { execArgv: ['--disable-sigusr1'], nodeOptions: '', inspectorOpen: false };
  assertVaultProcessSafe(safe);
  for (const change of [{ execArgv: ['--disable-sigusr1', '--inspect=0.0.0.0:9229'] }, { execArgv: ['--disable-sigusr1', '--inspect-brk'] }, { nodeOptions: '--heapsnapshot-signal=SIGUSR2' }, { nodeOptions: '--max-old-space-size=512 --heapsnapshot-near-heap-limit=3' }, { inspectorOpen: true }]) assert.throws(() => assertVaultProcessSafe({ ...safe, ...change }), /refuses/);
  assert.throws(() => assertVaultProcessSafe({ ...safe, execArgv: [] }), /disable-sigusr1/);
  assertVaultProcessSafe({ ...safe, execArgv: [], nodeOptions: '--disable-sigusr1 --max-old-space-size=512' });
});

test('a 30-day TTL does not overflow the timer into a spin', t => {
  t.mock.timers.enable({ apis: ['setTimeout', 'Date'], now: 1_000_000 });
  const sessions = new VaultSessions({ ttlSeconds: 30 * 86400, idleSeconds: 30 * 86400 });
  sessions.put('g', [{ host: 'alpha', keyId: 'a'.repeat(22), pem: throwawayKey().pem }], Date.now() + 31 * 86400000);
  t.mock.timers.tick(1000);
  assert.equal(sessions.size, 1);
  t.mock.timers.tick(2 ** 31); // the capped timer fires and re-arms
  assert.equal(sessions.size, 1);
  t.mock.timers.tick(30 * 86400000);
  assert.equal(sessions.size, 0);
});

test('unlock payload is scoped to configured hosts and private-key PEMs', async () => {
  const { pem, publicKey } = throwawayKey(); const keyId = (await vaultKeyIdForPublicKey(publicKey));
  assert.deepEqual(validateUnlock([{ host: 'alpha', keyId, pem, extra: 1 }], ['alpha']), [{ host: 'alpha', keyId, pem }]);
  for (const bad of [[{ host: 'beta', keyId, pem }], [{ host: 'alpha', keyId, pem: 'not a key' }], [{ host: 'alpha', keyId: 'x', pem }], [], [{ host: 'alpha', keyId, pem }, { host: 'alpha', keyId, pem }]]) assert.throws(() => validateUnlock(bad, ['alpha']), /invalid_vault_keys/);
});

test('vault source proxies slots and maps the W2 verifier 1:1', async () => {
  const seen = [];
  const fetcher = async (url, init) => {
    const path = new URL(url).pathname; seen.push([init.method, path, init.headers.Authorization]);
    if (path === '/cli/settings/vault') return Response.json({ slot: 'vault', version: 3, data: '{"v":1}' });
    if (path === `/cli/settings/vk-${'B'.repeat(22)}`) return Response.json({ error: 'vault_verify_required' }, { status: 403 });
    return Response.json({ error: 'not_found' }, { status: 404 });
  };
  const source = vaultSource({ base: 'https://broker.example.com', fetcher });
  const cred = { token: 'psc_synthetic' };
  assert.deepEqual(await source.pull(cred, 'vault'), { kind: 'ok', version: 3, data: '{"v":1}' });
  assert.deepEqual(await source.pull(cred, `vk-${'A'.repeat(22)}`), { kind: 'absent' });
  assert.deepEqual(await source.pull(cred, `vk-${'B'.repeat(22)}`), { kind: 'gated' });
  for (const bad of ['main', 'keys', '../vault', 'vk-short', undefined]) await assert.rejects(() => source.pull(cred, bad), /invalid_slot/);
  assert.deepEqual(await source.status(cred), { kind: 'unavailable' });
  assert.deepEqual(seen[0], ['GET', '/cli/settings/vault', 'Bearer psc_synthetic']);
  const answer = (status, body) => vaultSource({ base: 'https://broker.example.com', fetcher: async () => Response.json(body, { status }) }).verify(cred, 'A'.repeat(43));
  assert.deepEqual(await answer(200, { ok: true, epoch: 1 }), { kind: 'ok' });
  assert.deepEqual(await answer(401, { error: 'wrong_passphrase', retryAfter: 4, attemptsRemaining: 2 }), { kind: 'wrong', retryAfterMs: 4000 });
  assert.deepEqual(await answer(429, { error: 'too_many_attempts', retryAfter: 900 }), { kind: 'locked', retryAfterMs: 900000 });
  assert.deepEqual(await answer(429, { error: 'rate_limited', retryAfter: 30 }), { kind: 'locked', retryAfterMs: 30000 });
  assert.deepEqual(await answer(404, { error: 'no_verifier' }), { kind: 'noVerifier' });
  for (const [status, error] of [[404, 'not_found'], [503, 'vault_not_configured'], [409, 'verifier_stale']]) assert.deepEqual(await answer(status, { error }), { kind: 'unavailable' });
  await assert.rejects(() => source.verify(cred, 'short'), /invalid_request/);
  assert.deepEqual(await vaultSource({ base: 'https://broker.example.com', fetcher: async () => Response.json({ epoch: 2, hasVerifier: true, retryAfter: 30, kdf: { alg: 'argon2id' } }) }).status(cred), { kind: 'ok', epoch: 2, hasVerifier: true, retryAfterMs: 30000, kdf: { alg: 'argon2id' } });
});

async function harness(t, { ttlSeconds = 28800 } = {}) {
  const alpha = { host: 'alpha', ...throwawayKey() }, beta = { host: 'beta', ...throwawayKey() };
  const v = await makeVault(passphrase, { keys: [alpha, beta] });
  const store = new Store(':memory:', randomBytes(32).toString('hex'));
  const credential = { token: secret(), tokenId: 'synthetic', expiry: Date.now() + 86400000, identity };
  store.put('profile', identity.id, { hosts: [{ name: 'alpha', deviceId: 'device-alpha', user: 'u' }, { name: 'beta', deviceId: 'device-beta', user: 'u' }], pins: 'synthetic' }, Date.now() + 86400000);
  let now = Date.now(); const clock = () => now;
  const sessions = new VaultSessions({ ttlSeconds, idleSeconds: Math.min(1800, ttlSeconds), now: clock });
  const verified = [];
  const source = { pull: async (_c, slot) => v.slots[slot] ? { kind: 'ok', version: 1, data: v.slots[slot] } : { kind: 'absent' }, status: async () => ({ kind: 'unavailable' }), verify: async (_c, auth) => { verified.push(auth); return { kind: 'ok' }; } };
  const vault = { sessions, source, hosts: c => store.get('profile', c.identity.id)?.hosts.map(h => h.name) || [], resetUrl: 'https://web.example.com/keys?reset=1' };
  const executed = [], revoked = [];
  const upstream = { kind: 'pocketshell', base: 'https://broker.example.com', gatewayOrigin: 'https://gateway.example.com',
    start: async () => ({ userCode: 'BCDF-GHJK', deviceCode: secret(), approval: 'https://approval.example.com/device', expiry: Date.now() + 600000, interval: 1 }),
    poll: async () => credential, identity: async () => identity, revoke: async c => { revoked.push(c.token); }, devices: async () => [{ id: 'device-alpha', idValid: true, presence: { online: true } }] };
  const tools = pocketTools({ store, upstream, vault: sessions, execute: async (argv, options) => { executed.push(options.vaultKey.use().toString()); return { ok: true }; } });
  let app; const server = createServer((req, res) => app(req, res)); server.listen(0, 'localhost'); await once(server, 'listening');
  const issuer = `http://localhost:${server.address().port}`;
  app = createApp({ store, issuer, upstream, tools, vault, allowedEmails: [identity.email], redirectUris: [] });
  t.after(() => { sessions.dropAll(); server.closeAllConnections(); server.close(); store.close(); });
  const call = (path, data, headers = {}, form = false) => fetch(issuer + path, { redirect: 'manual', ...(data ? { method: 'POST', headers: { 'content-type': form ? 'application/x-www-form-urlencoded' : 'application/json', origin: issuer, ...headers }, body: form ? new URLSearchParams(data) : JSON.stringify(data) } : { headers }) });
  const client = await (await call('/oauth/register', { redirect_uris: ['http://localhost:9999/cb'], token_endpoint_auth_method: 'none' })).json();
  const verifier = secret();
  async function consent({ readOnly = false } = {}) {
    const auth = await call('/oauth/authorize?' + new URLSearchParams({ response_type: 'code', client_id: client.client_id, redirect_uri: 'http://localhost:9999/cb', code_challenge_method: 'S256', code_challenge: createHash('sha256').update(verifier).digest('base64url'), resource: issuer + '/mcp' }));
    const cookie = auth.headers.get('set-cookie').split(';')[0];
    const csrf = /name="csrf" value="([^"]+)"/.exec(await auth.text())[1];
    assert.equal((await call('/oauth/start', { csrf, ...(readOnly ? { read_only: '1' } : {}) }, { cookie }, true)).status, 200);
    const unlock = await call('/oauth/complete', { csrf }, { cookie });
    return { cookie, csrf, unlock };
  }
  async function exchange(location) {
    const code = new URL(location).searchParams.get('code');
    return (await call('/oauth/token', { grant_type: 'authorization_code', client_id: client.client_id, redirect_uri: 'http://localhost:9999/cb', code, code_verifier: verifier, resource: issuer + '/mcp' })).json();
  }
  async function browserUnlock({ cookie, csrf }, hosts) {
    // What vault-unlock.js does: the same KeyVaultStore, talking to the connector's proxy endpoints.
    const post = async (path, data = {}) => (await call('/oauth/vault/' + path, { csrf, ...data }, { cookie })).json();
    const store = new KeyVaultStore(proxyTransport(post));
    assert.equal((await store.unlock(passphrase)).kind, 'ok');
    const keys = [];
    for (const c of hostChoices(store, hosts).filter(c => c.available)) keys.push({ host: c.name, keyId: c.keyId, pem: (await store.decryptKeyForHost(c.name)).pem });
    return call('/oauth/vault/finish', { csrf, keys }, { cookie });
  }
  const mcp = async token => {
    const c = new Client({ name: 'vault-test', version: '1' });
    await c.connect(new StreamableHTTPClientTransport(new URL(issuer + '/mcp'), { requestInit: { headers: { Authorization: `Bearer ${token}` } } }));
    t.after(() => c.close()); return c;
  };
  return { app, credential, revoked, alpha, beta, v, store, sessions, call, consent, exchange, browserUnlock, mcp, executed, client, verified, advance: ms => { now += ms; } };
}

test('consent unlock binds only ticked hosts to the grant; locked hosts and revoke give a clear tool error', async t => {
  const h = await harness(t);
  const flow = await h.consent();
  assert.equal(flow.unlock.status, 200);
  assert.match(flow.unlock.headers.get('content-security-policy'), /script-src 'self' 'wasm-unsafe-eval'; connect-src 'self'/);
  // Browsers apply form-action to the 303 that follows a form POST, and send Origin: null under no-referrer.
  assert.match(flow.unlock.headers.get('content-security-policy'), /form-action 'self' http:\/\/localhost:9999;/);
  assert.equal(flow.unlock.headers.get('referrer-policy'), 'same-origin');
  const html = await flow.unlock.text();
  assert.ok(!html.includes('sync passphrase') && !html.includes(body(h.alpha.pem).slice(0, 24)));
  assert.match(html, /href="https:\/\/web\.example\.com\/keys\?reset=1"/);
  for (const asset of ['vault-unlock.js', 'host-choices.js', 'key-vault.js']) {
    const r = await h.call('/oauth/vault/' + asset); assert.equal(r.status, 200); assert.match(r.headers.get('content-type'), /javascript/);
    assert.match(r.headers.get('content-security-policy'), /default-src 'none'/);
  }
  // CSRF and phase are enforced on the unlock endpoints.
  assert.equal((await h.call('/oauth/vault/finish', { csrf: 'wrong', keys: [] }, { cookie: flow.cookie })).status, 400);
  assert.equal((await h.call('/oauth/vault/pull', { csrf: flow.csrf, slot: 'vault' }, { cookie: flow.cookie, origin: 'https://evil.example.com' })).status, 403);
  assert.equal((await h.call('/oauth/vault/pull', { csrf: flow.csrf, slot: 'main' }, { cookie: flow.cookie })).status, 400);
  // A key for a host that is not configured for this account is refused.
  assert.equal((await h.call('/oauth/vault/finish', { csrf: flow.csrf, keys: [{ host: 'gamma', keyId: h.alpha.keyId, pem: h.alpha.pem }] }, { cookie: flow.cookie })).status, 400);
  const finish = await h.browserUnlock(flow, ['alpha']);
  assert.equal(finish.status, 200);
  assert.equal(h.verified.length, 1);
  const tokens = await h.exchange((await finish.json()).location);
  assert.ok(tokens.access_token);
  const client = await h.mcp(tokens.access_token);
  const ok = await client.callTool({ name: 'status', arguments: { host: 'alpha', session: 's1' } });
  assert.notEqual(ok.isError, true);
  assert.deepEqual(h.executed, [h.alpha.pem]);
  const listed = await client.callTool({ name: 'hosts', arguments: {} });
  assert.equal(listed.structuredContent.hosts[0].unlocked, true); assert.ok(listed.structuredContent.vault.expiresAt);
  // Host scoping: beta's key exists in the vault but was not ticked.
  const beta = await client.callTool({ name: 'status', arguments: { host: 'beta', session: 's1' } });
  assert.equal(beta.isError, true); assert.equal(beta.content[0].text, 'vault locked: re-authorize to unlock');
  // Revoke drops the in-memory keys immediately.
  assert.equal(h.sessions.size, 1);
  await h.call('/oauth/revoke', { token: tokens.refresh_token, client_id: h.client.client_id });
  assert.equal(h.sessions.size, 0);
});

test('TTL expiry locks tools; skipping unlock issues a working grant with no keys; refresh reuse drops keys', async t => {
  const h = await harness(t, { ttlSeconds: 600 });
  const flow = await h.consent(); await flow.unlock.text();
  const tokens = await h.exchange((await (await h.browserUnlock(flow, ['alpha', 'beta'])).json()).location);
  const client = await h.mcp(tokens.access_token);
  assert.notEqual((await client.callTool({ name: 'ls', arguments: { host: 'beta' } })).isError, true);
  h.advance(600000);
  const expired = await client.callTool({ name: 'ls', arguments: { host: 'beta' } });
  assert.equal(expired.content[0].text, 'vault locked: re-authorize to unlock');
  // Skip (plain form, no script): grant works, SSH tools report locked.
  const skipFlow = await h.consent(); await skipFlow.unlock.text();
  const skipped = await h.call('/oauth/vault/finish', { csrf: skipFlow.csrf }, { cookie: skipFlow.cookie }, true);
  assert.equal(skipped.status, 303);
  const skipTokens = await h.exchange(skipped.headers.get('location'));
  const locked = await (await h.mcp(skipTokens.access_token)).callTool({ name: 'ls', arguments: { host: 'alpha' } });
  assert.equal(locked.content[0].text, 'vault locked: re-authorize to unlock');
  // Refresh-token reuse revokes the grant and its keys.
  const again = await h.consent(); await again.unlock.text();
  const t3 = await h.exchange((await (await h.browserUnlock(again, ['alpha'])).json()).location);
  assert.equal(h.sessions.size, 1);
  const { resource } = await (await h.call('/.well-known/oauth-protected-resource/mcp')).json();
  const refresh = { grant_type: 'refresh_token', client_id: h.client.client_id, resource, refresh_token: t3.refresh_token };
  assert.equal((await h.call('/oauth/token', refresh)).status, 200);
  assert.equal((await h.call('/oauth/token', refresh)).status, 400);
  assert.equal(h.sessions.size, 0);
});

test('the unlock step gets a fresh window, and an abandoned one revokes its upstream session', async t => {
  const h = await harness(t);
  const flow = await h.consent(); await flow.unlock.text();
  assert.match(flow.unlock.headers.get('set-cookie'), /Max-Age=600/);
  const [row] = h.store.db.prepare("SELECT id,value FROM records WHERE kind='transaction'").all();
  assert.ok(h.store.open('transaction', row.id, row.value).expiry > Date.now() + 590000);
  await h.app.sweepAbandoned();
  assert.deepEqual(h.revoked, []);
  h.store.db.prepare("UPDATE records SET expiry=0 WHERE kind='transaction'").run();
  await h.app.sweepAbandoned();
  assert.deepEqual(h.revoked, [h.credential.token]);
  assert.equal(h.store.db.prepare("SELECT count(*) AS n FROM records WHERE kind='transaction'").get().n, 0);
  // A finished unlock leaves nothing to sweep.
  const done = await h.consent(); await done.unlock.text();
  await h.browserUnlock(done, ['alpha']);
  h.store.db.prepare("UPDATE records SET expiry=0 WHERE kind='transaction'").run();
  await h.app.sweepAbandoned();
  assert.equal(h.revoked.length, 1);
});

test('a read-only grant is offered and allowed only read tools, even with keys unlocked', async t => {
  const h = await harness(t);
  const flow = await h.consent({ readOnly: true }); await flow.unlock.text();
  const tokens = await h.exchange((await (await h.browserUnlock(flow, ['alpha'])).json()).location);
  const client = await h.mcp(tokens.access_token);
  assert.deepEqual((await client.listTools()).tools.map(x => x.name).sort(), ['capture', 'hosts', 'ls', 'status']);
  const refused = await client.callTool({ name: 'send', arguments: { host: 'alpha', session: 's', text: 'rm -rf ~' } });
  assert.equal(refused.isError, true);
  assert.notEqual((await client.callTool({ name: 'capture', arguments: { host: 'alpha', session: 's' } })).isError, true);
  assert.equal(h.executed.length, 1);
  // A normal grant still lists every tool.
  const full = await h.consent(); await full.unlock.text();
  const fullTokens = await h.exchange((await (await h.browserUnlock(full, ['alpha'])).json()).location);
  assert.equal((await (await h.mcp(fullTokens.access_token)).listTools()).tools.length, 7);
});

test('no key material reaches logs, error text or the persistent store', async t => {
  const written = [];
  const originals = { out: process.stdout.write, err: process.stderr.write, log: console.log, error: console.error, warn: console.warn, info: console.info, debug: console.debug };
  const capture = chunk => { written.push(String(chunk)); return true; };
  process.stdout.write = capture; process.stderr.write = capture;
  for (const m of ['log', 'error', 'warn', 'info', 'debug']) console[m] = (...a) => written.push(a.map(x => typeof x === 'string' ? x : inspect(x, { depth: 8 })).join(' '));
  let h, results = [];
  try {
    h = await harness(t);
    const flow = await h.consent(); await flow.unlock.text();
    const tokens = await h.exchange((await (await h.browserUnlock(flow, ['alpha'])).json()).location);
    const client = await h.mcp(tokens.access_token);
    results.push(await client.callTool({ name: 'status', arguments: { host: 'beta', session: 's' } }));
    results.push(await client.callTool({ name: 'hosts', arguments: {} }));
    // Force an internal failure on the unlocked host: the generic error must not echo the key.
    const failing = pocketTools({ store: h.store, upstream: { base: 'https://broker.example.com', gatewayOrigin: 'https://gateway.example.com' }, vault: h.sessions, execute: async (_a, o) => { throw new Error('boom ' + o.vaultKey); } });
    await failing.call('ls', { host: 'alpha' }, { identity }, { grantId: [...h.store.db.prepare("SELECT id FROM records WHERE kind='grant'").all()][0].id }).catch(e => results.push({ text: e.message }));
    console.log('sessions', h.sessions, 'executed count', h.executed.length);
  } finally { process.stdout.write = originals.out; process.stderr.write = originals.err; for (const m of ['log', 'error', 'warn', 'info', 'debug']) console[m] = originals[m]; }
  const needle = body(h.alpha.pem).slice(0, 24);
  const haystack = written.join('\n') + JSON.stringify(results);
  assert.ok(haystack.includes('SecretKey [redacted]') || haystack.includes('[redacted]'));
  assert.ok(!haystack.includes(needle), 'key material leaked into logs or tool errors');
  // Persistent store: decrypt every record; none may hold a private key.
  for (const row of h.store.db.prepare('SELECT kind,id,value FROM records').all()) assert.ok(!JSON.stringify(h.store.open(row.kind, row.id, row.value)).includes('PRIVATE KEY'), row.kind);
});

test('executePsc loads a vault key into a private ssh-agent and writes only the public key', async t => {
  const root = await mkdtemp(join(tmpdir(), 'mcp-agent-')); t.after(() => rm(root, { recursive: true, force: true }));
  const entrypoint = join(root, 'fixture.mjs'), runtimeRoot = join(root, 'run');
  // The fake psc reports what ssh would see: the -i file and the agent's identities.
  await writeFile(entrypoint, `import {readFileSync,readdirSync,statSync} from 'node:fs';import {execFileSync} from 'node:child_process';import {join} from 'node:path';const dir=process.env.XDG_CONFIG_HOME;const hosts=JSON.parse(readFileSync(join(dir,'pocketshell-tui-client/hosts.json'),'utf8'));const files=[];const walk=d=>{for(const n of readdirSync(d)){const p=join(d,n);const s=statSync(p);if(s.isDirectory())walk(p);else if(s.isFile())files.push(readFileSync(p,'utf8'));}};walk(dir);console.log(JSON.stringify({identity:readFileSync(hosts.hosts[0].gateway.identityFile,'utf8'),agent:execFileSync('ssh-add',['-L']).toString(),privateOnDisk:files.some(f=>f.includes('PRIVATE KEY')),sockMode:statSync(process.env.SSH_AUTH_SOCK).isSocket()}));`);
  const key = throwawayKey(); key.keyId = (await vaultKeyIdForPublicKey(key.publicKey));
  const sessions = new VaultSessions(); t.after(() => sessions.dropAll());
  sessions.put('g', [{ host: 'alpha', keyId: key.keyId, pem: key.pem }], Date.now() + 60000);
  const result = await executePsc([], { profile: { hosts: [{ name: 'alpha', deviceId: 'device-alpha', user: 'u' }], pins: 'synthetic' }, credential: { token: secret(), tokenId: 's', expiry: Date.now() + 10000, identity }, broker: 'https://broker.example.com', gateway: 'https://gateway.example.com', runtimeRoot, stdin: '', entrypoint, vaultKey: sessions.key('g', 'alpha') });
  const pub = key.publicKey.split(' ').slice(0, 2).join(' ');
  assert.equal(result.identity.trim(), pub);
  assert.ok(result.agent.startsWith(pub));
  assert.equal(result.privateOnDisk, false); assert.equal(result.sockMode, true);
  assert.deepEqual(await readdir(runtimeRoot), []);
});
