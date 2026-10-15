import { digest } from './store.mjs';
export class UpstreamError extends Error {
  constructor(status, code = 'upstream_failed') { super(code); this.status = status; this.code = code; }
}
export async function requestJson(base, path, { method = 'GET', body, token, fetcher = fetch, allowText = false } = {}) {
  const target = new URL(path, base);
  if (target.origin !== new URL(base).origin || target.username || target.password) throw new Error('Cross-origin upstream URL refused');
  const response = await fetcher(target, { method, redirect: 'manual', signal: AbortSignal.timeout(15000),
    headers: { Accept: 'application/json', ...(body !== undefined ? { 'Content-Type': 'application/json' } : {}), ...(token ? { Authorization: `Bearer ${token}` } : {}) },
    ...(body !== undefined ? { body: JSON.stringify(body) } : {}) });
  const reader = response.body?.getReader();
  let size = 0; const parts = [];
  if (reader) for (;;) {
    const { done, value } = await reader.read(); if (done) break;
    size += value.byteLength;
    if (size > 1024 * 1024) { await reader.cancel(); throw new UpstreamError(502, 'upstream_response_too_large'); }
    parts.push(Buffer.from(value));
  }
  let data;
  try { data = size ? JSON.parse(Buffer.concat(parts).toString()) : {}; }
  catch {
    if (allowText && response.ok) data = { text: Buffer.concat(parts).toString('utf8'), contentType: response.headers.get('content-type') || 'text/plain' };
    else throw new UpstreamError(502, 'invalid_upstream_response');
  }
  if (!response.ok) throw Object.assign(new UpstreamError(response.status, /^[a-z_]{1,64}$/.test(data?.error) ? data.error : 'upstream_failed'), Number.isFinite(data?.retryAfter) ? { retryAfter: data.retryAfter } : {});
  return data;
}
function origins(base, webOrigin, gatewayOrigin) {
  for (const origin of [base, webOrigin, gatewayOrigin].filter(Boolean)) {
    const u = new URL(origin);
    if (u.protocol !== 'https:' || u.origin !== origin) throw new Error('Service origins must be bare HTTPS origins');
  }
  if (!base || !webOrigin) throw new Error('Explicit upstream and web origins are required');
}

// PocketShell protocol, parsing, transport and trust are owned by the psc core.
// This adapter only maps those results into the connector OAuth bridge.
export function pocketUpstream({ core, base, webOrigin, gatewayOrigin, fetcher } = {}) {
  origins(base, webOrigin, gatewayOrigin);
  if (!core || !gatewayOrigin) throw new Error('Shared client core and gateway origin are required');
  base = core.validateBrokerUrl(base);
  const http = fetcher ? { fetch: fetcher } : { transport: { kind: 'direct' } };
  const endpoint = core.resolveEndpoint(gatewayOrigin.replace(/^https:/, 'wss:'));
  async function session(token) {
    try { return await core.getSession(base, token, http); }
    catch (error) { if (error.code === 'NOT_LOGGED_IN') throw new UpstreamError(401, 'invalid_identity'); throw error; }
  }
  return {
    kind: 'pocketshell', base, gatewayOrigin,
    async start(label) {
      const raw = await core.startDevice(base, label, http);
      const pending = core.pendingDeviceLogin(raw, webOrigin);
      return { deviceCode: raw.deviceCode, userCode: pending.userCode, approval: pending.verificationUriComplete || pending.verificationUri,
        expiry: Date.now() + raw.expiresIn * 1000, interval: raw.interval };
    },
    async poll(deviceCode) {
      const response = await core.pollDevice(base, deviceCode, http);
      if (response.status !== 200) throw new UpstreamError(response.status, core.errorCode(response) || 'upstream_failed');
      const raw = core.parseDeviceToken(response.data);
      try {
        const info = await session(raw.accessToken);
        if (info.tokenId !== raw.tokenId) throw new UpstreamError(401, 'invalid_identity');
        return { token: raw.accessToken, expiry: info.expiresAt * 1000, tokenId: raw.tokenId,
          identity: { id: digest(`pocketshell:${info.email.toLowerCase()}`), email: info.email.toLowerCase() } };
      } catch (error) { await core.logout(base, raw.accessToken, http).catch(() => {}); throw error; }
    },
    async identity({ token }) {
      const info = await session(token);
      return { id: digest(`pocketshell:${info.email.toLowerCase()}`), email: info.email.toLowerCase() };
    },
    async revoke({ token }) { await core.logout(base, token, http); },
    async devices({ token }) {
      const gateway = await core.mintGatewayToken(base, token, http);
      return core.fetchDevices(endpoint, gateway.token);
    },
  };
}

export function dataopsUpstream({ base, webOrigin, fetcher } = {}) {
  origins(base, webOrigin);
  // The portal's work API is under /work/api, as in the dataops CLI.
  const call = (path, options) => requestJson(base, path.startsWith('/api/') ? `/work${path}` : path, { ...options, fetcher });
  return {
    kind: 'dataops', base, call,
    async start(label) {
      const raw = await call('/api/auth/device', { method: 'POST', body: { label } });
      if (typeof raw.deviceCode !== 'string' || raw.deviceCode.length < 16 || typeof raw.userCode !== 'string' || !/^[A-Z0-9]{4}-[A-Z0-9]{4}$/.test(raw.userCode) || !Number.isInteger(raw.expiresIn) || raw.expiresIn < 1 || raw.expiresIn > 3600) throw new UpstreamError(502, 'invalid_device_response');
      const approval = new URL('/device', webOrigin); approval.searchParams.set('userCode', raw.userCode);
      return { deviceCode: raw.deviceCode, userCode: raw.userCode, approval: approval.href,
        expiry: Date.now() + raw.expiresIn * 1000, interval: Math.max(1, Math.min(60, Number(raw.interval) || 5)) };
    },
    async poll(deviceCode) {
      const raw = await call('/api/auth/device/token', { method: 'POST', body: { deviceCode } });
      const expiry = Date.parse(raw.expiresAt);
      if (typeof raw.token !== 'string' || raw.token.length < 20 || !Number.isFinite(expiry) || expiry <= Date.now()) throw new UpstreamError(502, 'invalid_token_response');
      const credential = { token: raw.token, tokenId: raw.tokenId, expiry };
      try { return { ...credential, identity: await this.identity(credential) }; }
      catch (error) { await this.revoke(credential).catch(() => {}); throw error; }
    },
    async identity({ token }) {
      const raw = await call('/api/me', { token }); const email = raw.user?.email;
      if (typeof email !== 'string' || !email.includes('@')) throw new UpstreamError(401, 'invalid_identity');
      return { id: digest(`dataops:${email.toLowerCase()}`), email: email.toLowerCase() };
    },
    async revoke(credential) {
      if (credential.tokenId) await call(`/api/tokens/${encodeURIComponent(credential.tokenId)}`, { method: 'DELETE', token: credential.token });
    },
  };
}
