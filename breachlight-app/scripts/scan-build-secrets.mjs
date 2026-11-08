import { readdirSync,readFileSync } from 'node:fs';
import { loadConfig } from '../server/config.mjs';
const c=loadConfig();
const secrets=[c.hfToken,c.databaseUrl,c.databaseUrl?decodeURIComponent(new URL(c.databaseUrl).password):''].filter(Boolean);
function walk(path){return readdirSync(path,{withFileTypes:true}).flatMap(e=>e.isDirectory()?walk(path+'/'+e.name):[path+'/'+e.name]);}
const files=['dist','public','.openai'].flatMap(walk);let hits=0;
for(const f of files){const data=readFileSync(f);if(secrets.some(s=>data.includes(Buffer.from(s)))){console.error('Secret detected in artifact:',f);hits++;}}
console.log(hits?'Secret scan failed.':`Passed: no configured credential values in ${files.length} build/public/hosting files.`);process.exitCode=hits?1:0;
