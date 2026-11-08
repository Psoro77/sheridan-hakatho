import { timingSafeEqual } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { loadConfig } from './config.mjs';
import { generateBriefing, evidenceFor, evidenceHash, PublicError } from './granite.mjs';
import { dependencyRoutes } from './dependency-routes.mjs';
import { ollamaStatus } from './ollama.mjs';
import { explainSchema, saveSchema } from './validation.mjs';
const fallback=JSON.parse(readFileSync(new URL('../public/data/intelligence.json',import.meta.url),'utf8'));
const cveIds=new Set(fallback.vulnerabilities.map(v=>v.id));
// Rank-band evidence is derived from the checked-in ML outputs, so a database seeded before it
// existed can still serve it. A record that carries its own evidence always wins.
const bundledEvidence=new Map(fallback.vulnerabilities.filter(v=>v.modelEvidence).map(v=>[v.id,v.modelEvidence]));
const withEvidence=record=>record.modelEvidence||!bundledEvidence.has(record.id)?record:{...record,modelEvidence:bundledEvidence.get(record.id)};
function send(res,status,data){res.writeHead(status,{'Content-Type':'application/json; charset=utf-8','Cache-Control':'no-store','X-Content-Type-Options':'nosniff'});res.end(JSON.stringify(data));}
async function body(req){let text='';for await(const chunk of req){text+=chunk;if(Buffer.byteLength(text)>700000)throw new PublicError(413,'BODY_TOO_LARGE','Request is too large.');}try{return JSON.parse(text);}catch{throw new PublicError(400,'INVALID_JSON','Invalid JSON request.');}}
function authorized(req,config){
 if(config.apiKey){const actual=Buffer.from(req.headers.authorization||''),expected=Buffer.from(`Bearer ${config.apiKey}`);return actual.length===expected.length&&timingSafeEqual(actual,expected);}
 const host=req.headers.host?.split(':')[0];
 if(!['127.0.0.1','localhost'].includes(host))return false;
 if(req.headers['sec-fetch-site']==='cross-site')return false;
 if(req.headers.origin){try{const origin=new URL(req.headers.origin);if(!['localhost','127.0.0.1'].includes(origin.hostname))return false;}catch{return false;}}
 return true;
}
export function createHandler(pool,{getConfig=loadConfig,generate=generateBriefing}={}){
 const handleDependencies=dependencyRoutes(pool,{modelRanks:Object.fromEntries(fallback.vulnerabilities.map(v=>[v.id,v.rank])),generate});
 const inFlight=new Map();let lastInference=0;let healthCache;
 return async function handler(req,res){
  const path=new URL(req.url,'http://localhost').pathname;const config=getConfig();
  try{
   if(!authorized(req,config))throw new PublicError(403,'FORBIDDEN','This API is restricted to the Aegis workspace.');
   if(path.startsWith('/api/aegis/dependencies/')){const result=await handleDependencies(path,req,config,body);if(result!==null)return send(res,200,result);}
   if(path==='/api/aegis/status'&&req.method==='GET'){
    let db={connected:false,records:0,tls:false};
    if(pool){try{if(healthCache&&Date.now()-healthCache.at<10000)db=healthCache.value;else{const r=await pool.query('SELECT (SELECT count(*) FROM aegis_app.vulnerabilities)::int as records,(SELECT ssl FROM pg_stat_ssl WHERE pid=pg_backend_pid()) as tls');db={connected:true,...r.rows[0]};healthCache={at:Date.now(),value:db};}}catch{}}
    const granite=config.graniteProvider==='ollama'?await ollamaStatus(config):{configured:!!config.hfToken,model:config.hfModel,provider:'huggingface',mode:config.hfEndpoint?'dedicated':'shared-provider'};
    return send(res,200,{database:{...db,configured:!!pool},granite,workspace:config.workspaceId});
   }
   if(path==='/api/aegis/intelligence'&&req.method==='GET'){
    if(pool){try{const [rows,months,metadata]=await Promise.all([pool.query('SELECT record FROM aegis_app.vulnerabilities ORDER BY model_rank'),pool.query('SELECT month,total as count,selected FROM aegis_app.snapshot_months ORDER BY month'),pool.query('SELECT key,value FROM aegis_app.metadata')]);if(!rows.rows.length)throw Error('empty');const meta=Object.fromEntries(metadata.rows.map(r=>[r.key,r.value]));
     // validation comes from the checked-in ML outputs, so fall back to the bundled snapshot
     // when a database predates that metadata key. Seeded values still win.
     return send(res,200,{validation:fallback.validation,...meta,vulnerabilities:rows.rows.map(r=>withEvidence(r.record)),months:months.rows,storage:'tigerdata'});}catch{}}
    return send(res,200,{...fallback,storage:'snapshot',warning:'TigerData is unavailable; showing the bundled snapshot.'});
   }
   if(path==='/api/aegis/workspace'&&req.method==='GET'){
    if(!pool)throw new PublicError(503,'DATABASE_UNAVAILABLE','TigerData is not configured.');
    const r=await pool.query('SELECT state,revision,updated_at FROM aegis_app.workspaces WHERE workspace_id=$1',[config.workspaceId]);
    return send(res,200,r.rows[0]||{state:null,revision:0});
   }
   if(path==='/api/aegis/workspace'&&req.method==='PUT'){
    if(!pool)throw new PublicError(503,'DATABASE_UNAVAILABLE','TigerData is not configured.');
    const parsed=saveSchema.safeParse(await body(req));if(!parsed.success)throw new PublicError(400,'INVALID_WORKSPACE','Invalid inventory or defense-plan data.');
    const {state,revision}=parsed.data;if(state.plan.some(id=>!cveIds.has(id)))throw new PublicError(400,'UNKNOWN_CVE','The plan contains a CVE outside the ranked dataset.');
    const client=await pool.connect();try{
     await client.query('BEGIN');
     const result=revision===0?await client.query('INSERT INTO aegis_app.workspaces(workspace_id,state) VALUES($1,$2) ON CONFLICT DO NOTHING RETURNING revision',[config.workspaceId,JSON.stringify(state)]):await client.query('UPDATE aegis_app.workspaces SET state=$1,revision=revision+1,updated_at=now() WHERE workspace_id=$2 AND revision=$3 RETURNING revision',[JSON.stringify(state),config.workspaceId,revision]);
     if(!result.rowCount)throw new PublicError(409,'WORKSPACE_CONFLICT','This workspace changed in another tab. Reload before saving again.');
     await client.query('INSERT INTO aegis_app.events(workspace_id,event_type,details) VALUES($1,$2,$3)',[config.workspaceId,'workspace_saved',JSON.stringify({assetGroups:state.assets.length,planned:state.plan.length,reviewed:state.done.length,revision:result.rows[0].revision})]);
     await client.query('COMMIT');return send(res,200,{revision:result.rows[0].revision,savedAt:new Date().toISOString()});
    }catch(e){await client.query('ROLLBACK').catch(()=>{});throw e;}finally{client.release();}
   }
   if(path==='/api/aegis/explain'&&req.method==='POST'){
    const parsed=explainSchema.safeParse(await body(req));if(!parsed.success)throw new PublicError(400,'INVALID_REQUEST','Select a valid CVE and inventory.');
    let record=fallback.vulnerabilities.find(v=>v.id===parsed.data.cveId);
    if(pool){const result=await pool.query('SELECT record FROM aegis_app.vulnerabilities WHERE cve_id=$1',[parsed.data.cveId]);if(result.rows[0])record=result.rows[0].record;}
    if(!record)throw new PublicError(404,'CVE_NOT_FOUND','This CVE is not in the ranked snapshot.');
    const evidence=evidenceFor(record,parsed.data.assets),hash=evidenceHash(evidence,config);
    if(pool){const cached=await pool.query('SELECT response FROM aegis_app.briefings WHERE evidence_hash=$1',[hash]);if(cached.rows[0])return send(res,200,{...cached.rows[0].response,cached:true,persisted:true});}
    if(!inFlight.has(hash)){
     if(config.graniteProvider==='ollama'&&inFlight.size>0)throw new PublicError(429,'LOCAL_MODEL_BUSY','Local Granite is working on another briefing. Please wait for it to finish.');
     if(Date.now()-lastInference<3000)throw new PublicError(429,'RATE_LIMIT','Please wait a few seconds before generating another briefing.');
     lastInference=Date.now();
     const promise=(async()=>{const briefing=await generate(evidence,config);let persisted=false;if(pool){try{await pool.query('INSERT INTO aegis_app.briefings(evidence_hash,cve_id,model,response) VALUES($1,$2,$3,$4) ON CONFLICT DO NOTHING',[hash,record.id,briefing.model,JSON.stringify(briefing)]);persisted=true;}catch{}}return {...briefing,cached:false,persisted};})();
     inFlight.set(hash,promise);promise.finally(()=>inFlight.delete(hash)).catch(()=>{});
    }
    return send(res,200,await inFlight.get(hash));
   }
   throw new PublicError(404,'NOT_FOUND','Endpoint not found.');
  }catch(e){if(e instanceof PublicError)return send(res,e.status,{error:e.message,code:e.code});console.error('Aegis API request failed:',e.code||e.name);return send(res,503,{error:'TigerData is temporarily unavailable. Your browser copy is retained; try again shortly.',code:'SERVICE_UNAVAILABLE'});}
 };
}
