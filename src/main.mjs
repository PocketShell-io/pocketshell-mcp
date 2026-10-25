import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { Store } from './store.mjs';
import { pocketUpstream, dataopsUpstream } from './upstream.mjs';
import { pocketTools } from './pocketshell.mjs';
import { gatewayTools } from './registry.mjs';
import { pocketRegistration, dataopsRegistration } from './adapters.mjs';
import { loadCliRegistrations } from './plugins.mjs';
import { executePsc } from './pocketshell.mjs';
import { createApp } from './app.mjs';
import { VaultSessions, vaultSource, DEFAULT_VAULT_TTL, DEFAULT_VAULT_IDLE, assertVaultProcessSafe, assertDedicatedVaultOrigin } from './vault.mjs';
process.umask(0o077);
const kind = 'gateway';
if (process.env.MCP_SERVICE && !['gateway','pocketshell'].includes(process.env.MCP_SERVICE)) throw new Error('Use one gateway and register this CLI instead of running a separate service');
const state = process.env.MCP_STATE_DIR || '/var/lib/pocketshell-mcp';
const storageKey = process.env.MCP_STORAGE_KEY_FILE ? readFileSync(process.env.MCP_STORAGE_KEY_FILE, 'utf8').trim() : process.env.MCP_STORAGE_KEY;
const store = new Store(join(state, 'oauth.sqlite'), storageKey);
const remoteConfig = { base: process.env.MCP_UPSTREAM_ORIGIN, webOrigin: process.env.MCP_WEB_ORIGIN, gatewayOrigin: process.env.MCP_GATEWAY_ORIGIN };
const remote = pocketUpstream({ ...remoteConfig, core: await import('../vendor/client-core.mjs') });
// Opt-in: SSH keys come from the user's vault, unlocked at consent and held only in memory.
const vaultEnabled = ['1', 'on', 'true'].includes((process.env.MCP_VAULT || '').toLowerCase());
if (vaultEnabled) { assertVaultProcessSafe(); assertDedicatedVaultOrigin(process.env.MCP_ISSUER, process.env.MCP_VAULT_DEDICATED_ORIGIN); }
const sessions = vaultEnabled ? new VaultSessions({ ttlSeconds: Number(process.env.MCP_VAULT_TTL_SECONDS || DEFAULT_VAULT_TTL), idleSeconds: Number(process.env.MCP_VAULT_IDLE_SECONDS || DEFAULT_VAULT_IDLE) }) : null;
const vault = sessions && { sessions, source: vaultSource({ base: remote.base }), hosts: credential => store.get('profile', credential.identity.id)?.hosts.map(h => h.name) || [], resetUrl: new URL('/keys?reset=1', remoteConfig.webOrigin).href };
const runtimeRoot = process.env.MCP_RUNTIME_DIR || '/run/pocketshell-mcp';
const registrations = [pocketRegistration(pocketTools({store,upstream:remote,vault:sessions,runtimeRoot,
  execute:(args,options)=>executePsc(args,{...options,sandbox:true})}))];
const connections = [];
if (process.env.MCP_DATAOPS_ORIGIN) {
  const dataops = dataopsUpstream({base:process.env.MCP_DATAOPS_ORIGIN,webOrigin:process.env.MCP_DATAOPS_WEB_ORIGIN || process.env.MCP_DATAOPS_ORIGIN});
  const dataopsReg = dataopsRegistration({entrypoint:process.env.MCP_DATAOPS_ENTRYPOINT || new URL('../vendor/dataops.mjs',import.meta.url).pathname,upstream:dataops,runtimeRoot});
  registrations.push(dataopsReg);
  connections.push({name:'dataops',auth:dataops,title:'DataOps',description:dataopsReg.manifest.description});
}
for (const registration of loadCliRegistrations(process.env.MCP_CLI_CONFIG_FILE, {runtimeRoot})) {
  const name = registration.manifest.namespace;
  const title = name.charAt(0).toUpperCase() + name.slice(1);
  registrations.push(registration);
  connections.push({name,auth:registration.auth,title,description:registration.manifest.description});
}
const tools = gatewayTools(registrations);
const app = createApp({ store, upstream: {...remote,kind:'gateway'}, tools, connections, vault, issuer: process.env.MCP_ISSUER,
  allowedEmails: (process.env.MCP_ALLOWED_EMAILS || '').split(',').map(x=>x.trim().toLowerCase()).filter(Boolean),
  redirectUris: (process.env.MCP_REDIRECT_URIS || '').split(',').map(x=>x.trim()).filter(Boolean),
});
const server = app.listen(Number(process.env.PORT || 8080), process.env.MCP_BIND || 'localhost', () => console.log(`${kind} MCP listening`));
const timer = setInterval(() => { app.sweepAbandoned().catch(() => {}).finally(() => { try { store.prune({ except: app.sweptKinds }); } catch {} }); }, 60000); timer.unref();
for (const signal of ['SIGTERM', 'SIGINT']) process.on(signal, () => { sessions?.dropAll(); server.close(() => { clearInterval(timer); store.close(); process.exit(0); }); });
