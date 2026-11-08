import test from 'node:test';
import assert from 'node:assert/strict';
import { Readable } from 'node:stream';
import { createHandler } from './app.mjs';
const config={apiKey:'',workspaceId:'test',hfToken:'',hfModel:'ibm-granite/granite-4.2-8b:deepinfra',hfEndpoint:''};
async function request(handler,path,method='GET',data,headers={}){const req=Readable.from(data?[JSON.stringify(data)]:[]);req.url=path;req.method=method;req.headers={host:'127.0.0.1:5174',...headers};let status,payload;await handler(req,{writeHead(code){status=code},end(s){payload=JSON.parse(s)}});return {status,body:payload};}
test('API blocks foreign origins and wrong bearer keys',async()=>{const h=createHandler(null,{getConfig:()=>config});assert.equal((await request(h,'/api/breachlight/status','GET',null,{origin:'https://foreign.example'})).status,403);const secured=createHandler(null,{getConfig:()=>({...config,apiKey:'secret'})});assert.equal((await request(secured,'/api/breachlight/status')).status,403);assert.equal((await request(secured,'/api/breachlight/status','GET',null,{authorization:'Bearer secret'})).status,200);});
test('data fallback is labeled, status never exposes credential values',async()=>{const h=createHandler(null,{getConfig:()=>({...config,hfToken:'private-hf-token'})});const r=await request(h,'/api/breachlight/intelligence');assert.equal(r.body.storage,'snapshot');assert.equal(r.body.vulnerabilities.length,500);const status=await request(h,'/api/breachlight/status');assert.equal(status.body.granite.configured,true);assert.ok(!JSON.stringify(status).includes('private-hf-token'));});
test('invalid CVEs and inventory fail before provider execution',async()=>{let calls=0;const h=createHandler(null,{getConfig:()=>config,generate:async()=>{calls++}});assert.equal((await request(h,'/api/breachlight/explain','POST',{cveId:'not-an-id',assets:[]})).status,400);assert.equal((await request(h,'/api/breachlight/explain','POST',{cveId:'CVE-2026-9999999',assets:[]})).status,404);assert.equal(calls,0);});
test('workspace conflicts roll back and never overwrite a newer version',async()=>{const sql=[];const client={query:async(q)=>{sql.push(q);return {rowCount:0,rows:[]}},release(){}};const pool={connect:async()=>client};const h=createHandler(pool,{getConfig:()=>config});const r=await request(h,'/api/breachlight/workspace','PUT',{revision:1,state:{assets:[{id:'1',name:'test',product:'test',exposure:'Public',criticality:'High'}],inventoryMode:'Demo inventory',plan:[],done:[]}});assert.equal(r.status,409);assert.ok(sql.includes('ROLLBACK'));assert.ok(!sql.includes('COMMIT'));});
test('a database seeded before the evidence work still serves validation and rank-band evidence',async()=>{
 const snapshot=await request(createHandler(null,{getConfig:()=>config}),'/api/breachlight/intelligence');
 const top=snapshot.body.vulnerabilities[0];
 const stale={id:top.id,rank:top.rank,snapshot:top.snapshot},own={...stale,modelEvidence:{status:'complete',source:'ml/outputs/predictions.parquet'}};
 const poolFor=record=>({query:async(q)=>({rows:q.includes('breachlight_app.vulnerabilities')?[{record}]:[]})});
 const filled=await request(createHandler(poolFor(stale),{getConfig:()=>config}),'/api/breachlight/intelligence');
 assert.equal(filled.body.storage,'tigerdata');
 assert.ok(filled.body.validation.folds2025.model>0,'validation falls back to the bundled snapshot');
 assert.equal(filled.body.vulnerabilities[0].modelEvidence.validation.band,top.modelEvidence.validation.band);
 const seeded=await request(createHandler(poolFor(own),{getConfig:()=>config}),'/api/breachlight/intelligence');
 assert.equal(seeded.body.vulnerabilities[0].modelEvidence.status,'complete','a record carrying its own evidence wins');
});
