// Real HTTPS + MCP Inspector against the multiplexed gateway (catalog plus all
// tools per CLI: pocketshell, dataops). Upstream account approval
// is a synthetic fixture; this does not claim an account-level ChatGPT, Claude
// or Grok Bot acceptance test.
import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:https';
import { once } from 'node:events';
import { execFile as execFileCallback, execFileSync } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdtemp, readFile, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { createHash, randomBytes } from 'node:crypto';
import { Store, secret } from '../src/store.mjs';
import { createApp } from '../src/app.mjs';
import { gatewayTools } from '../src/registry.mjs';
import { pocketRegistration, dataopsRegistration } from '../src/adapters.mjs';
import { pocketTools } from '../src/pocketshell.mjs';
const execFile = promisify(execFileCallback);
const inspector = resolve('node_modules/@modelcontextprotocol/inspector/clients/cli/build/index.js');
test('gateway: real TLS, DCR/PKCE/device bridge and MCP Inspector discovery/calls for all backends', async t => {
  const dir = await mkdtemp(join(tmpdir(), 'mcp-inspector-gateway-'));
  const keyFile = join(dir, 'key.pem'), certFile = join(dir, 'cert.pem');
  execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', keyFile, '-out', certFile, '-days', '1', '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost'], { stdio: 'ignore' });
  const store = new Store(':memory:', randomBytes(32).toString('hex'));
  let app;
  const server = createServer({ key: await readFile(keyFile), cert: await readFile(certFile) }, (req, res) => app(req, res));
  server.listen(0, 'localhost'); await once(server, 'listening');
  const issuer = `https://localhost:${server.address().port}`;
  const identity = { id: 'synthetic-account', email: 'operator@example.com' };
  const credential = () => ({ token: secret(), tokenId: 'synthetic', expiry: Date.now() + 86400000, identity });
  const device = {
    start: async () => ({ deviceCode: secret(), userCode: 'BCDF-GHJK', approval: 'https://approval.example.com/device', expiry: Date.now() + 600000, interval: 1 }),
    poll: async () => credential(), identity: async () => identity, revoke: async () => {},
  };
  const seen = [];
  const pscProfile = { hosts: [{ name: 'hetzner-host', deviceId: 'dev-1', user: 'alexey' }] };
  store.put('profile', identity.id, pscProfile, Date.now() + 86400000);
  const pTools = pocketTools({
    store,
    upstream: { base: 'https://broker.example.com', gatewayOrigin: 'https://gateway.example.com', devices: async () => [{ id: 'dev-1', presence: 'online', idValid: true }] },
    execute: async (...args) => { seen.push(['pocketshell', ...args]); return { ok: true }; }
  });

  const tools = gatewayTools([
    pocketRegistration(pTools),
    dataopsRegistration({ entrypoint: join(dir, 'dataops.mjs'), upstream: { base: 'https://portal.example.com' }, runtimeRoot: dir, run: async options => { seen.push(['dataops', ...options.argv]); return { tasks: [] }; } }),
  ]);
  app = createApp({
    store,
    issuer,
    upstream: { ...device, kind: 'gateway' },
    tools,
    connections: [
      { name: 'dataops', auth: device }
    ],
    allowedEmails: [identity.email],
    redirectUris: []
  });
  t.after(async () => { server.closeAllConnections(); server.close(); store.close(); await rm(dir, { recursive: true, force: true }); });
  // Trust only this generated test certificate for the HTTP driver; TLS verification stays enabled.
  const { Agent, fetch: tlsFetch } = await import('undici'); const dispatcher = new Agent({ connect: { ca: await readFile(certFile) } }); t.after(() => dispatcher.close());
  const call = (path, body, headers = {}) => tlsFetch(issuer + path, { dispatcher, redirect: 'manual', ...(body ? { method: 'POST', body: JSON.stringify(body), headers: { 'content-type': 'application/json', ...headers } } : { headers }) });
  const unauthorized = await call('/mcp', {}); assert.equal(unauthorized.status, 401);
  const metadata = await (await call('/.well-known/oauth-protected-resource/mcp')).json(); assert.deepEqual(metadata.authorization_servers, [issuer]);
  const registration = await call('/oauth/register', { client_name: 'Inspector synthetic fixture', redirect_uris: ['http://localhost:9999/callback'], token_endpoint_auth_method: 'none' }); assert.equal(registration.status, 201); const client = await registration.json();
  const verifier = secret();
  const authorize = await call('/oauth/authorize?' + new URLSearchParams({ response_type: 'code', client_id: client.client_id, redirect_uri: client.redirect_uris[0], code_challenge_method: 'S256', code_challenge: createHash('sha256').update(verifier).digest('base64url'), resource: issuer + '/mcp' }));
  assert.equal(authorize.status, 200); const cookie = authorize.headers.get('set-cookie').split(';')[0]; const csrf = /name="csrf" value="([^"]+)"/.exec(await authorize.text())[1]; const browser = { cookie, origin: issuer };
  assert.equal((await call('/oauth/start', { csrf }, browser)).status, 200);
  assert.equal((await call('/oauth/complete', { csrf }, browser)).status, 200);
  assert.equal((await call('/oauth/link/start', { csrf, cli: 'dataops' }, browser)).status, 200);
  assert.equal((await call('/oauth/link/complete', { csrf, cli: 'dataops' }, browser)).status, 200);
  const done = await call('/oauth/link/finish', { csrf }, browser); assert.equal(done.status, 303);
  const redirect = new URL(done.headers.get('location'));
  const exchange = await call('/oauth/token', { grant_type: 'authorization_code', client_id: client.client_id, redirect_uri: client.redirect_uris[0], code: redirect.searchParams.get('code'), code_verifier: verifier, resource: issuer + '/mcp' }); assert.equal(exchange.status, 200); const token = await exchange.json();
  const config = join(dir, 'inspector.json'); await writeFile(config, JSON.stringify({ mcpServers: { fixture: { type: 'http', url: issuer + '/mcp', headers: { Authorization: `Bearer ${token.access_token}` } } } }), { mode: 0o600 });
  const run = async args => {
    try { return await execFile(process.execPath, [inspector, '--config', config, '--server', 'fixture', ...args], { env: { ...process.env, NODE_EXTRA_CA_CERTS: certFile }, timeout: 20000, maxBuffer: 1024 * 1024 }); }
    catch { assert.fail('Inspector process failed; raw diagnostics suppressed to protect credentials'); }
  };
  const listed = await run(['--method', 'tools/list']); const discovered = JSON.parse(listed.stdout); const names = (discovered.tools || discovered).map(x => x.name).sort();
  assert.deepEqual(names, ['catalog', 'dataops', 'pocketshell']);
  const dataopsToolDef = (discovered.tools || discovered).find(x => x.name === 'dataops');
  assert.ok(JSON.stringify(dataopsToolDef.inputSchema).includes('argv'));

  // 1. Catalog tool call via Inspector
  const catalog = JSON.parse((await run(['--method', 'tools/call', '--tool-name', 'catalog'])).stdout);
  assert.equal(catalog.isError || false, false);
  assert.deepEqual(JSON.parse(catalog.content[0].text).clis.map(x => x.name), ['pocketshell', 'dataops']);

  // 2. PocketShell read-only tool call via Inspector
  const psCall = JSON.parse((await run(['--method', 'tools/call', '--tool-name', 'pocketshell', '--tool-args-json', JSON.stringify({ argv: ['hosts'] })])).stdout);
  assert.equal(psCall.isError || false, false);
  assert.deepEqual(JSON.parse(psCall.content[0].text), { hosts: [{ id: 'dev-1', presence: 'online', configured: true, name: 'hetzner-host' }] });

  // 3. DataOps read-only tool call via Inspector
  const doCall = JSON.parse((await run(['--method', 'tools/call', '--tool-name', 'dataops', '--tool-args-json', JSON.stringify({ argv: ['tasks', 'list', '--mine'] })])).stdout);
  assert.equal(doCall.isError || false, false);
  assert.deepEqual(JSON.parse(doCall.content[0].text), { tasks: [] });
  assert.deepEqual(seen.find(x => x[0] === 'dataops'), ['dataops', 'tasks', 'list', '--mine', '--json']);

});
