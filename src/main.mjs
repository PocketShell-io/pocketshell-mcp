import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { Store } from './store.mjs';
import { pocketUpstream, dataopsUpstream } from './upstream.mjs';
import { pocketTools } from './pocketshell.mjs';
import { dataopsTools } from './dataops.mjs';
import { createApp } from './app.mjs';
import { VaultSessions, vaultSource, DEFAULT_VAULT_TTL } from './vault.mjs';
process.umask(0o077);
const kind = process.env.MCP_SERVICE || 'pocketshell';
if (!['pocketshell','dataops'].includes(kind)) throw new Error('Unknown MCP_SERVICE');
const state = process.env.MCP_STATE_DIR || '/var/lib/pocketshell-mcp';
const storageKey = process.env.MCP_STORAGE_KEY_FILE ? readFileSync(process.env.MCP_STORAGE_KEY_FILE, 'utf8').trim() : process.env.MCP_STORAGE_KEY;
const store = new Store(join(state, 'oauth.sqlite'), storageKey);
const remoteConfig = { base: process.env.MCP_UPSTREAM_ORIGIN, webOrigin: process.env.MCP_WEB_ORIGIN, gatewayOrigin: process.env.MCP_GATEWAY_ORIGIN };
const remote = kind === 'pocketshell'
  ? pocketUpstream({ ...remoteConfig, core: await import('../vendor/client-core.mjs') })
  : dataopsUpstream(remoteConfig);
// Opt-in: SSH keys come from the user's vault, unlocked at consent and held only in memory.
const vaultEnabled = kind === 'pocketshell' && ['1', 'on', 'true'].includes((process.env.MCP_VAULT || '').toLowerCase());
const sessions = vaultEnabled ? new VaultSessions({ ttlSeconds: Number(process.env.MCP_VAULT_TTL_SECONDS || DEFAULT_VAULT_TTL) }) : null;
const vault = sessions && { sessions, source: vaultSource({ base: remote.base }), hosts: credential => store.get('profile', credential.identity.id)?.hosts.map(h => h.name) || [], resetUrl: new URL('/keys?reset=1', remoteConfig.webOrigin).href };
const tools = kind === 'pocketshell' ? pocketTools({ store, upstream: remote, vault: sessions }) : dataopsTools({ upstream: remote });
const app = createApp({ store, upstream: remote, tools, vault, issuer: process.env.MCP_ISSUER,
  allowedEmails: (process.env.MCP_ALLOWED_EMAILS || '').split(',').map(x=>x.trim().toLowerCase()).filter(Boolean),
  redirectUris: (process.env.MCP_REDIRECT_URIS || '').split(',').map(x=>x.trim()).filter(Boolean),
});
const server = app.listen(Number(process.env.PORT || 8080), process.env.MCP_BIND || 'localhost', () => console.log(`${kind} MCP listening`));
const timer = setInterval(() => store.prune(), 60000); timer.unref();
for (const signal of ['SIGTERM', 'SIGINT']) process.on(signal, () => { sessions?.dropAll(); server.close(() => { clearInterval(timer); store.close(); process.exit(0); }); });
