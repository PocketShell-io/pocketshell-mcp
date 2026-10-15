import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { once } from 'node:events';
import { randomBytes } from 'node:crypto';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import { z } from 'zod';
import { Store, secret, digest } from '../src/store.mjs';
import { createApp } from '../src/app.mjs';
import { UpstreamError } from '../src/upstream.mjs';

test('standard SDK completes real HTTP initialization, discovery, tool calls and revocation rejection',async t=>{
 const store=new Store(':memory:',randomBytes(32).toString('hex'));let valid=true;
 const identity={id:'synthetic-account',email:'operator@example.com'};
 let app; const server=createServer((req,res)=>app(req,res)); server.listen(0,'localhost');await once(server,'listening');
 const issuer=`http://localhost:${server.address().port}`;const resource=issuer+'/mcp';const token=secret();
 store.put('access',digest(token),{grantId:'test',clientId:'test',resource,scope:'mcp:tools'},Date.now()+60000);
 store.put('grant','test',{credential:{token:secret(),identity,expiry:Date.now()+60000},revoked:false},Date.now()+60000);
 app=createApp({store,issuer,allowedEmails:[identity.email],redirectUris:[],upstream:{kind:'test',identity:async()=>{if(!valid)throw new UpstreamError(401);return identity;}},tools:{definitions:[{name:'echo',description:'Echo synthetic test data',schema:z.object({value:z.string()}),read:true}],call:async(_name,args)=>({echo:args.value})}});
 t.after(()=>{server.closeAllConnections();server.close();store.close();});
 const base=issuer;
 const raw=(path,init={})=>fetch(base+path,{...init,headers:init.headers});
 // no-referrer would make browsers send Origin: null on consent form POSTs, failing the CSRF origin check.
 assert.equal((await raw('/health')).headers.get('referrer-policy'),'same-origin');
 const denied=await raw('/mcp',{method:'POST'});assert.equal(denied.status,401);assert.match(denied.headers.get('www-authenticate'),/resource_metadata=/);

 assert.equal((await raw('/health',{headers:{Origin:'https://other.example.com'}})).status,403);
 const client=new Client({name:'generic-test-client',version:'1'});
 const transport=new StreamableHTTPClientTransport(new URL(base+'/mcp'),{requestInit:{headers:{Authorization:`Bearer ${token}`}}});
 await client.connect(transport);t.after(()=>client.close());
 const {tools}=await client.listTools();assert.equal(tools[0].name,'echo');assert.equal(tools[0].annotations.readOnlyHint,true);
 const result=await client.callTool({name:'echo',arguments:{value:'synthetic'}});assert.deepEqual(result.structuredContent,{echo:'synthetic'});
 const invalid=await client.callTool({name:'echo',arguments:{value:42}});assert.equal(invalid.isError,true);
 valid=false;
 assert.equal((await raw('/mcp',{method:'POST',headers:{Authorization:`Bearer ${token}`,'Content-Type':'application/json'},body:JSON.stringify({jsonrpc:'2.0',method:'tools/list',id:10})})).status,401);
});
