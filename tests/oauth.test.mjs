import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes, createHash } from 'node:crypto';
import { once } from 'node:events';
import express from 'express';
import { Store, digest, secret } from '../src/store.mjs';
import { installOAuth, validRedirect } from '../src/oauth.mjs';
import { UpstreamError } from '../src/upstream.mjs';
const issuer = 'https://mcp.example.com';
const callback = 'https://assistant.example.com/callback';
const identity = { id: 'test-account', email: 'operator@example.com' };
async function fixture(t) {
  const store = new Store(':memory:', randomBytes(32).toString('hex'));
  let approved = false, revoked = false;
  const credential = { token: secret(), tokenId: 'synthetic', expiry: Date.now()+86400000, identity };
  const upstream = { kind: 'test', start: async()=> ({ userCode:'BCDF-GHJK', deviceCode:secret(), approval:'https://approval.example.com/device', expiry:Date.now()+600000, interval:1 }), poll:async()=> { if (!approved) throw new UpstreamError(400,'authorization_pending'); return credential; }, identity:async()=>identity, revoke:async()=>{revoked=true;} };
  const app = express(); app.use(express.json()); app.use(express.urlencoded({extended:false}));
  app.use((_req,res,next)=>{res.set('Cache-Control','no-store');next();});
  installOAuth(app,{store,issuer,upstream,allowedEmails:[identity.email],redirectUris:[]});
  const server = app.listen(0, 'localhost'); await once(server,'listening');
  t.after(()=>{server.closeAllConnections();server.close();store.close();});
  const base = `http://localhost:${server.address().port}`;
  const call = (path,body,headers={})=>fetch(base+path,{redirect:'manual',...(body?{method:'POST',headers:{'content-type':'application/json',...headers},body:JSON.stringify(body)}:{headers})});
  const reg = await call('/oauth/register',{redirect_uris:[callback],client_name:'Synthetic client',token_endpoint_auth_method:'none'});
  assert.equal(reg.status,201); const client = await reg.json();
  const verifier = secret(); const challenge = createHash('sha256').update(verifier).digest('base64url');
  const params = {client_id:client.client_id,redirect_uri:callback,response_type:'code',code_challenge_method:'S256',code_challenge:challenge,resource:issuer+'/mcp',state:secret()};
  async function login() {
    const auth = await call('/oauth/authorize?'+new URLSearchParams(params)); assert.equal(auth.status,200);
    const cookie = auth.headers.get('set-cookie').split(';')[0];
    const csrf = /name="csrf" value="([^"]+)"/.exec(await auth.text())[1];
    const headers = {cookie,origin:issuer};
    const start = await call('/oauth/start',{csrf},headers); assert.equal(start.status,200);
    // Browsers apply form-action to the 303 after the next form POST, so the callback origin must be allowed.
    assert.match(start.headers.get('content-security-policy'),/form-action 'self' https:\/\/assistant\.example\.com;/);
    approved = true;
    const finish = await call('/oauth/complete',{csrf},headers); assert.equal(finish.status,303);
    const target = new URL(finish.headers.get('location')); assert.equal(target.searchParams.get('state'),params.state); assert.equal(target.searchParams.get('iss'),issuer);
    return {code:target.searchParams.get('code'),cookie,csrf};
  }
  const tokenBody = code => ({grant_type:'authorization_code',client_id:client.client_id,redirect_uri:callback,resource:issuer+'/mcp',code_verifier:verifier,code});
  return {store,call,client,login,tokenBody,params,credential,get revoked(){return revoked;}};
}
test('discovery advertises public-client DCR, S256 PKCE, resource and issuer', async t=>{
 const f=await fixture(t); const meta=await (await f.call('/.well-known/oauth-authorization-server')).json();
 assert.deepEqual(meta.code_challenge_methods_supported,['S256']);assert.deepEqual(meta.token_endpoint_auth_methods_supported,['none']);assert.equal(meta.issuer,issuer);
 const resource=await (await f.call('/.well-known/oauth-protected-resource/mcp')).json();assert.equal(resource.resource,issuer+'/mcp');
});
test('device approval becomes a single-use code, never an upstream token',async t=>{
 const f=await fixture(t);const {code}=await f.login();
 const response=await f.call('/oauth/token',f.tokenBody(code));assert.equal(response.status,200);const tokens=await response.json();
 assert.notEqual(tokens.access_token,f.credential.token);assert.ok(tokens.refresh_token);assert.equal(response.headers.get('cache-control'),'no-store');
 assert.equal((await f.call('/oauth/token',f.tokenBody(code))).status,400);
});
test('PKCE, redirect, audience and client binding reject substitution',async t=>{
 const f=await fixture(t);const {code}=await f.login();
 for(const change of [{code_verifier:secret()},{redirect_uri:callback+'/other'},{resource:'https://other.example.com/mcp'},{client_id:secret()}]) assert.ok((await f.call('/oauth/token',{...f.tokenBody(code),...change})).status>=400);
 assert.equal((await f.call('/oauth/token',f.tokenBody(code))).status,200);
});
test('refresh rotates and reuse revokes the entire grant',async t=>{
 const f=await fixture(t);const {code}=await f.login();const initial=await (await f.call('/oauth/token',f.tokenBody(code))).json();
 const body={grant_type:'refresh_token',client_id:f.client.client_id,resource:issuer+'/mcp',refresh_token:initial.refresh_token};
 const next=await (await f.call('/oauth/token',body)).json();assert.notEqual(next.refresh_token,initial.refresh_token);
 assert.equal((await f.call('/oauth/token',body)).status,400);
 assert.equal((await f.call('/oauth/token',{...body,refresh_token:next.refresh_token})).status,400);
 const access=f.store.get('access',digest(next.access_token));assert.equal(f.store.get('grant',access.grantId).revoked,true);
});
test('browser consent requires same-origin POST and transaction CSRF',async t=>{
 const f=await fixture(t);const auth=await f.call('/oauth/authorize?'+new URLSearchParams(f.params));const cookie=auth.headers.get('set-cookie').split(';')[0];
 assert.equal((await f.call('/oauth/start',{csrf:'wrong'},{cookie,origin:issuer})).status,400);
 assert.equal((await f.call('/oauth/start',{csrf:'wrong'},{cookie,origin:'https://other.example.com'})).status,400);
});
test('DCR supports generic HTTPS and loopback clients, rejects unsafe redirect schemes',async t=>{
 const f=await fixture(t);
 for(const uri of ['https://generic.example.com/oauth','http://localhost:9876/callback']) assert.equal((await f.call('/oauth/register',{redirect_uris:[uri],token_endpoint_auth_method:'none'})).status,201);
 for(const uri of ['javascript:alert(1)','https://user:password@example.com/oauth','http://external.example.com/callback','https://example.com/#fragment']) assert.equal((await f.call('/oauth/register',{redirect_uris:[uri]})).status,400);
 assert.equal(validRedirect('not a url'),false);
});
