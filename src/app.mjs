import express from 'express';
import rateLimit from 'express-rate-limit';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { installOAuth, validRedirect } from './oauth.mjs';
export function createApp(config) {
  const { issuer, tools, upstream } = config;
  const parsed = new URL(issuer);
  if ((parsed.protocol !== 'https:' && !(parsed.protocol === 'http:' && ['localhost'].includes(parsed.hostname))) || parsed.username || parsed.password || parsed.search || parsed.hash || !/^\/(?:[A-Za-z0-9_-]+)?$/.test(parsed.pathname)) throw new Error('MCP_ISSUER must be HTTPS with an optional single service path (HTTP only on loopback)');
  if (!config.allowedEmails.length) throw new Error('An explicit account allowlist is required');
  for (const uri of config.redirectUris) {
    if (!validRedirect(uri)) throw new Error('Callback must use HTTPS or HTTP loopback without credentials or fragment');
  }
  const app = express(); const service = express.Router(); const prefix = parsed.pathname.replace(/\/$/, ''); app.disable('x-powered-by');
  // Trust exactly the local reverse proxy, not arbitrary forwarded IPs.
  app.set('trust proxy', 'loopback');
  app.use((req, res, next) => {
    // same-origin, not no-referrer: browsers send `Origin: null` on form POSTs under no-referrer,
    // which the consent CSRF origin check would reject. Cross-origin requests still get no referrer.
    res.set({ 'Cache-Control':'no-store', 'Referrer-Policy':'same-origin', 'X-Content-Type-Options':'nosniff', 'X-Frame-Options':'DENY', 'Content-Security-Policy': "default-src 'none'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'" });
    if (req.headers.origin && req.headers.origin !== parsed.origin) return res.status(403).json({ error: 'invalid_origin' });
    // Reject DNS rebinding / attacker-controlled Host; proxy preserves public Host.
    if (req.headers.host !== parsed.host) return res.status(400).json({ error: 'invalid_host' });
    next();
  });
  app.use(express.json({ limit: '128kb' })); app.use(express.urlencoded({ extended: false, limit: '16kb' }));
  app.get('/health', (_req, res) => res.json({ status: 'ok', service: upstream.kind }));
  const oauth = installOAuth(service, { ...config, rootApp: app });
  const limiter = rateLimit({ windowMs: 60000, limit: 120, standardHeaders: 'draft-8', legacyHeaders: false });
  let active = 0;
  service.all('/mcp', limiter, oauth.authenticate, async (req, res) => {
    if (req.method !== 'POST') return res.status(405).set('Allow','POST').json({ error: 'method_not_allowed' });
    if (active >= 8) return res.status(429).json({ error: 'busy' });
    active++;
    const server = new McpServer({ name: `${upstream.kind}-mcp`, version: '0.1.0' });
    for (const tool of tools.definitions) server.registerTool(tool.name, {
      description: tool.description, inputSchema: tool.schema,
      annotations: { readOnlyHint: !!tool.read, destructiveHint: !!tool.destructive, idempotentHint: !!tool.read, openWorldHint: true },
      _meta: { securitySchemes: [{ type: 'oauth2', scopes: ['mcp:tools'] }] },
    }, async args => {
      try {
        const result = await tools.call(tool.name, args, req.credential);
        const content = JSON.stringify(result);
        if (Buffer.byteLength(content) > 1024 * 1024) throw new Error('Response too large');
        return { content: [{ type: 'text', text: content }], structuredContent: result && typeof result === 'object' && !Array.isArray(result) ? result : { result } };
      } catch {
        return { isError: true, content: [{ type: 'text', text: 'Operation failed. Check the resource, permissions and connection configuration; retry reads before repeating a write.' }] };
      }
    });
    const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined, enableJsonResponse: true });
    try {
      await server.connect(transport); await transport.handleRequest(req, res, req.body);
    } catch { if (!res.headersSent) res.status(500).json({ error: 'server_error' }); }
    finally { active--; await transport.close(); await server.close(); }
  });
  app.use(prefix || '/', service);
  app.use((_req, res) => res.status(404).json({ error:'not_found' }));
  app.use((_error, _req, res, _next) => { if (!res.headersSent) res.status(400).json({ error:'invalid_request' }); });
  return app;
}
