import { readFileSync } from 'node:fs';
import { z } from 'zod';
import { cliRegistration } from './adapters.mjs';
import { createAuth, httpsOrigin, envName } from './auth.mjs';
export { registerAuthType } from './auth.mjs';
// Operator-only JSON config. Each `auth` block is validated by its registered auth type.
const pluginSchema=z.strictObject({
 manifestFile:z.string(),command:z.string(),prefix:z.array(z.string()).default([]),mounts:z.array(z.string()).default([]),
 origin:httpsOrigin,originEnv:envName,
 auth:z.looseObject({type:z.string()})
});
export function loadCliRegistrations(path,{runtimeRoot}) {
 if(!path)return [];
 return z.array(pluginSchema).max(16).parse(JSON.parse(readFileSync(path,'utf8'))).map(config=>{
  const manifest=JSON.parse(readFileSync(config.manifestFile,'utf8'));
  const {auth,materialize}=createAuth(config.auth,{origin:config.origin});
  return cliRegistration({manifest,command:config.command,prefix:config.prefix,mounts:config.mounts,runtimeRoot,auth,environment:{[config.originEnv]:config.origin},credentials:materialize});
 });
}
