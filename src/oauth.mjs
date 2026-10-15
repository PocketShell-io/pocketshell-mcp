import { createHash, timingSafeEqual } from 'node:crypto';
import rateLimit from 'express-rate-limit';
import { digest, secret } from './store.mjs';
import { UpstreamError } from './upstream.mjs';
import { isIP } from 'node:net';
export function validRedirect(value) {
  try {
    const u = new URL(value);
    const host = u.hostname.replace(/^\[|\]$/g, '');
    const loopback = host === 'localhost' || (isIP(host) === 4 && Number(host.split('.')[0]) === 127) || host === `${':'.repeat(2)}1`;
    return !u.username && !u.password && !u.hash && (u.protocol === 'https:' || (u.protocol === 'http:' && loopback));
  } catch { return false; }
}
const DAY = 86400000;
// Consent forms end in a 303 to the client's callback, and CSP form-action also governs that redirect,
// so each transaction page allows exactly its own validated callback origin.
const consentCsp = tx => `default-src 'none'; form-action 'self' ${new URL(tx.redirect).origin}; frame-ancestors 'none'; base-uri 'none'`;
const equal = (a, b) => typeof a === 'string' && typeof b === 'string' && Buffer.byteLength(a) === Buffer.byteLength(b) && timingSafeEqual(Buffer.from(a), Buffer.from(b));
const html = value => String(value).replace(/[&<>"']/g, x => ({ '&':'&amp;', '<':'&lt;', '>':'&gt;', '"':'&quot;', "'":'&#39;' })[x]);
const fail = (res, code = 'invalid_request', status = 400) => res.status(status).json({ error: code });

export function installOAuth(app, { store, issuer, upstream, allowedEmails, redirectUris, rootApp = app }) {
  const resource = `${issuer}/mcp`;
  const issuerUrl = new URL(issuer);
  const origin = issuerUrl.origin;
  const prefix = issuerUrl.pathname.replace(/\/$/, '');
  const metadataUrl = `${origin}/.well-known/oauth-protected-resource${prefix}/mcp`;
  const redirectAllowed = uri => validRedirect(uri) && (!redirectUris.length || redirectUris.includes(uri));
  const cookieName = `mcp_tx_${digest(issuer).slice(0, 8)}`;
  const scope = 'mcp:tools';
  const limiter = rateLimit({ windowMs: 60000, limit: 60, standardHeaders: 'draft-8', legacyHeaders: false });
  app.use('/oauth', limiter);
  rootApp.get([`/.well-known/oauth-protected-resource${prefix}`, `/.well-known/oauth-protected-resource${prefix}/mcp`], (_req, res) => res.json({ resource, authorization_servers: [issuer], scopes_supported: [scope], bearer_methods_supported: ['header'] }));
  rootApp.get(`/.well-known/oauth-authorization-server${prefix}`, (_req, res) => res.json({ issuer, authorization_endpoint: `${issuer}/oauth/authorize`, token_endpoint: `${issuer}/oauth/token`, registration_endpoint: `${issuer}/oauth/register`, revocation_endpoint: `${issuer}/oauth/revoke`, scopes_supported: [scope], response_types_supported: ['code'], grant_types_supported: ['authorization_code', 'refresh_token'], code_challenge_methods_supported: ['S256'], token_endpoint_auth_methods_supported: ['none'], authorization_response_iss_parameter_supported: true }));
  const challenge = (res) => res.set('WWW-Authenticate', `Bearer resource_metadata="${metadataUrl}", scope="${scope}"`).status(401).json({ error: 'invalid_token' });
  const page = (res, body, tx = null) => (tx ? res.set('Content-Security-Policy', consentCsp(tx)) : res).type('html').send(`<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>${upstream.kind} connection</title><body><main><h1>Connect ${html(upstream.kind)}</h1>${body}</main></body></html>`);
  const transaction = req => {
    const cookies = Object.fromEntries((req.headers.cookie || '').split(';').map(x => x.trim().split('=')));
    return cookies[cookieName] && store.get('transaction', digest(cookies[cookieName]));
  };
  function csrf(req) {
    const tx = transaction(req);
    return tx && req.get('origin') === origin && equal(req.body?.csrf, tx.csrf) ? tx : null;
  }
  function saveTx(tx) { store.put('transaction', tx.id, tx, tx.expiry); }
  app.post('/oauth/register', (req, res) => {
    const b = req.body;
    // DCR clients are untrusted. Validate redirect syntax, then require explicit browser consent.
    // Operators can optionally restrict callbacks further; no client brand is hardcoded.
    if (!b || !Array.isArray(b.redirect_uris) || b.redirect_uris.length < 1 || b.redirect_uris.length > 10 || b.redirect_uris.some(uri => !redirectAllowed(uri)) || !['none', undefined].includes(b.token_endpoint_auth_method) || (b.grant_types && (!Array.isArray(b.grant_types) || b.grant_types.some(x => !['authorization_code','refresh_token'].includes(x)))) || (b.response_types && JSON.stringify(b.response_types) !== '["code"]')) return fail(res, 'invalid_client_metadata');
    const client = { client_id: secret(), client_name: String(b.client_name || 'MCP client').slice(0, 80), redirect_uris: b.redirect_uris, token_endpoint_auth_method: 'none', grant_types: ['authorization_code','refresh_token'], response_types: ['code'] };
    // Keep client registration stable across all token lifetimes (no expiry/rotation policy).
    store.put('client', client.client_id, client, 8640000000000000);
    res.status(201).json(client);
  });
  app.get('/oauth/authorize', (req, res) => {
    const q = req.query;
    const client = typeof q.client_id === 'string' && store.get('client', q.client_id);
    if (!client || typeof q.redirect_uri !== 'string' || !client.redirect_uris.includes(q.redirect_uri) || !redirectAllowed(q.redirect_uri)) return fail(res);
    if (q.response_type !== 'code' || q.code_challenge_method !== 'S256' || typeof q.code_challenge !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(q.code_challenge) || q.resource !== resource || (q.scope !== undefined && q.scope !== scope) || (q.state !== undefined && (typeof q.state !== 'string' || q.state.length > 2048))) return fail(res);
    const nonce = secret();
    const tx = { id: digest(nonce), csrf: secret(), clientId: client.client_id, redirect: q.redirect_uri, state: q.state, challenge: q.code_challenge, resource, scope, expiry: Date.now() + 600000, phase: 'consent' };
    saveTx(tx);
    res.cookie(cookieName, nonce, { httpOnly: true, secure: issuer.startsWith('https:'), sameSite: 'lax', path: `${prefix}/oauth`, maxAge: 600000 });
    page(res, `<p>Client: ${html(client.client_name)}</p><p>Return address: ${html(tx.redirect)}</p><p>This grants all ${html(upstream.kind)} tools, including changes and destructive operations, within your existing account permissions. Approve only a connection you just started.</p><form method="post" action="${prefix}/oauth/start"><input type="hidden" name="csrf" value="${tx.csrf}"><button>Continue to device approval</button></form>`);
  });
  app.post('/oauth/start', async (req, res) => {
    const tx = csrf(req);
    if (!tx || tx.phase !== 'consent') return fail(res);
    // Persist before awaiting to prevent concurrent starts for the same browser transaction.
    tx.phase = 'starting'; saveTx(tx);
    try {
      tx.device = await upstream.start(`${upstream.kind} MCP (${new URL(tx.redirect).hostname})`);
      tx.expiry = Math.min(tx.expiry, tx.device.expiry); tx.nextPoll = 0; tx.phase = 'pending'; saveTx(tx);
      page(res, `<p>Approve code <strong>${html(tx.device.userCode)}</strong> in ${html(upstream.kind)}.</p><p><a href="${html(tx.device.approval)}" target="_blank" rel="noopener noreferrer">Open device approval</a></p><p>After approving, return here and continue. No token needs to be copied.</p><form method="post" action="${prefix}/oauth/complete"><input type="hidden" name="csrf" value="${tx.csrf}"><button>Finish connection</button></form>`, tx);
    } catch { store.delete('transaction', tx.id); fail(res, 'temporarily_unavailable', 503); }
  });
  app.post('/oauth/complete', async (req, res) => {
    const tx = csrf(req);
    if (!tx || tx.phase !== 'pending') return fail(res);
    if (Date.now() < tx.nextPoll) return fail(res, 'slow_down', 429);
    tx.nextPoll = Date.now() + tx.device.interval * 1000; tx.phase = 'polling'; saveTx(tx);
    try {
      const credential = await upstream.poll(tx.device.deviceCode);
      if (!allowedEmails.includes(credential.identity.email)) {
        await upstream.revoke(credential).catch(() => {}); store.delete('transaction', tx.id); return fail(res, 'access_denied', 403);
      }
      const code = secret();
      const grantId = secret();
      store.transaction(() => {
        store.put('grant', grantId, { credential, clientId: tx.clientId, resource, scope, revoked: false }, Math.min(credential.expiry, Date.now() + 30 * DAY));
        store.put('code', digest(code), { grantId, clientId: tx.clientId, redirect: tx.redirect, challenge: tx.challenge, resource }, Date.now() + 60000);
        store.delete('transaction', tx.id);
      });
      const target = new URL(tx.redirect); target.searchParams.set('code', code); if (tx.state !== undefined) target.searchParams.set('state', tx.state); target.searchParams.set('iss', issuer);
      res.clearCookie(cookieName, { path: `${prefix}/oauth` }); res.redirect(303, target.href);
    } catch (error) {
      if (error instanceof UpstreamError && ['authorization_pending', 'slow_down'].includes(error.code)) {
        if (error.code === 'slow_down') tx.device.interval = Math.min(60, tx.device.interval + 5);
        tx.phase = 'pending'; tx.nextPoll = Date.now() + tx.device.interval * 1000; saveTx(tx);
        return page(res, `<p>Approval is still pending. Wait ${tx.device.interval} seconds, approve in the other tab, then continue.</p><form method="post" action="${prefix}/oauth/complete"><input type="hidden" name="csrf" value="${tx.csrf}"><button>Check approval</button></form>`, tx);
      }
      store.delete('transaction', tx.id); return fail(res, 'access_denied', 403);
    }
  });
  function mint(grantId, grant) {
    const access = secret(); const refresh = secret();
    const expiry = Math.min(grant.credential.expiry, Date.now() + 30 * DAY);
    store.put('access', digest(access), { grantId, clientId: grant.clientId, resource, scope }, Math.min(expiry, Date.now() + 3600000));
    store.put('refresh', digest(refresh), { grantId, clientId: grant.clientId, resource }, expiry);
    return { access_token: access, token_type: 'Bearer', expires_in: Math.floor((Math.min(expiry, Date.now() + 3600000) - Date.now()) / 1000), refresh_token: refresh, scope };
  }
  app.post('/oauth/token', (req, res) => {
    const b = req.body || {};
    if (!store.get('client', b.client_id)) return fail(res, 'invalid_client', 401);
    if (b.resource !== resource || (b.scope !== undefined && b.scope !== scope)) return fail(res, 'invalid_target');
    const result = store.transaction(() => {
      if (b.grant_type === 'authorization_code') {
        const key = typeof b.code === 'string' ? digest(b.code) : '';
        const code = store.get('code', key);
        if (!code || code.clientId !== b.client_id || code.redirect !== b.redirect_uri || typeof b.code_verifier !== 'string' || !/^[A-Za-z0-9._~-]{43,128}$/.test(b.code_verifier) || !equal(code.challenge, createHash('sha256').update(b.code_verifier).digest('base64url'))) return null;
        const grant = store.get('grant', code.grantId);
        if (!grant || grant.revoked) return null;
        store.delete('code', key); return mint(code.grantId, grant);
      }
      if (b.grant_type === 'refresh_token') {
        const key = typeof b.refresh_token === 'string' ? digest(b.refresh_token) : '';
        const token = store.get('refresh', key);
        if (!token || token.clientId !== b.client_id) return null;
        const grant = store.get('grant', token.grantId);
        if (!grant || grant.revoked) return null;
        if (token.used) { grant.revoked = true; store.put('grant', token.grantId, grant, grant.credential.expiry); return null; }
        store.put('refresh', key, { ...token, used: true }, grant.credential.expiry);
        return mint(token.grantId, grant);
      }
      return null;
    });
    if (!result) return fail(res, 'invalid_grant');
    res.json(result);
  });
  app.post('/oauth/revoke', async (req, res) => {
    const b = req.body || {};
    const key = typeof b.token === 'string' ? digest(b.token) : '';
    const token = store.get('refresh', key) || store.get('access', key);
    if (token && token.clientId === b.client_id) {
      const grant = store.get('grant', token.grantId);
      if (grant) {
        grant.revoked = true; store.put('grant', token.grantId, grant, grant.credential.expiry);
        await upstream.revoke(grant.credential).catch(() => {});
      }
    }
    res.json({});
  });
  return {
    resource,
    async authenticate(req, res, next) {
      const bearer = /^Bearer ([A-Za-z0-9_-]{43})$/.exec(req.get('authorization') || '')?.[1];
      const token = bearer && store.get('access', digest(bearer));
      const grant = token && store.get('grant', token.grantId);
      if (!grant || grant.revoked || token.resource !== resource || token.scope !== scope || grant.credential.expiry <= Date.now()) return challenge(res);
      try {
        // Live validation makes upstream logout / device-session revocation effective immediately.
        const identity = await upstream.identity(grant.credential);
        if (identity.id !== grant.credential.identity.id || !allowedEmails.includes(identity.email)) return challenge(res);
        req.credential = grant.credential; next();
      } catch (error) {
        if (error instanceof UpstreamError && [401,403].includes(error.status)) return challenge(res);
        return fail(res, 'temporarily_unavailable', 503);
      }
    },
  };
}
