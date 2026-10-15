// Check tracked source. Real deployment values belong only in private runtime config.
import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
const files=execFileSync('git',['ls-files','-z'],{encoding:'utf8'}).split('\0').filter(Boolean);
const source=files.filter(x=>x!=='package-lock.json' && !x.startsWith('.github/'));
const hosts=new Set(['github.com','registry.npmjs.org','developers.openai.com','learn.chatgpt.com','docs.x.ai','forum.cursor.com','support.claude.com','code.claude.com','cursor.com','modelcontextprotocol.io']);
let failed=false;
for(const file of source) {
 const body=readFileSync(file,'utf8');
 const found=[];
 if(/(?:vendor\/(?:(?:psc|client-core|key-vault)\.mjs|vault-v1-vectors\.json)|\.env)$/.test(file)) found.push('generated runtime or private configuration is tracked');
 if(/-----BEGIN (?:OPENSSH |RSA |EC )?PRIVATE KEY-----[\r\n]+[A-Za-z0-9+/]{20}/.test(body)) found.push('private key material');
 if(/\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/.test(body)) found.push('cloud credential');
 for(const match of body.matchAll(/[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g)) if(!match[0].endsWith('@example.com') && !match[0].endsWith('@users.noreply.github.com') && !match[0].startsWith('mcp@')) found.push('non-placeholder email');
 for(const match of body.matchAll(/(?:https?|wss?):\/\/(?:[^/\s:]+:[^/@\s]+@)?([A-Za-z0-9.-]+)/g)) {
   const host=match[1];
   if(!hosts.has(host) && host!=='localhost' && host!=='example.com' && !host.endsWith('.example.com')) found.push('non-placeholder service address');
 }
 if(found.length){ console.error(`${file}: ${[...new Set(found)].join(', ')}`); failed=true; }
}
if(failed) process.exit(1);
console.log('Tracked-source public-boundary checks passed.');
