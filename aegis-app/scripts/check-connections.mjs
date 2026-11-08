import { loadConfig } from '../server/config.mjs';
import { makePool } from '../server/database.mjs';
import { generateBriefing,evidenceFor } from '../server/granite.mjs';
const config=loadConfig(),pool=makePool(config);
try {
 console.log('Inference:',JSON.stringify({provider:config.graniteProvider,model:config.graniteProvider==='ollama'?config.ollamaModel:config.hfModel}));
 if(!pool)throw Object.assign(new Error(),{code:'DATABASE_NOT_CONFIGURED'});
 const result=await pool.query('SELECT (SELECT ssl FROM pg_stat_ssl WHERE pid=pg_backend_pid()) as tls,(SELECT count(*) FROM aegis_app.vulnerabilities)::int as records,(SELECT sum(total) FROM aegis_app.snapshot_months)::int as scoreboard_total');
 console.log('TigerData:',JSON.stringify(result.rows[0]));
 if(process.argv.includes('--verify')){
  const client=await pool.connect();try{await client.query('BEGIN');const id='integration-test-'+crypto.randomUUID();await client.query('INSERT INTO aegis_app.workspaces(workspace_id,state) VALUES($1,$2)',[id,JSON.stringify({test:true})]);const row=await client.query('SELECT state FROM aegis_app.workspaces WHERE workspace_id=$1',[id]);if(!row.rows[0].state.test)throw Error('round-trip');await client.query('ROLLBACK');console.log('Database write/read round-trip: passed (test transaction rolled back).');}finally{client.release();}
  for(const path of ['status','intelligence','workspace']){
   const response=await fetch(`http://127.0.0.1:5173/api/aegis/${path}`);
   if(!response.ok)throw Object.assign(new Error(),{code:'API_'+response.status});const data=await response.json();
   console.log('App API',path,JSON.stringify(path==='intelligence'?{storage:data.storage,rows:data.vulnerabilities?.length}:path==='workspace'?{revision:data.revision,hasState:!!data.state}:data));
  }
 }
 if(process.argv.includes('--cached-briefing')){
  const response=await fetch('http://127.0.0.1:5173/api/aegis/explain',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({cveId:'CVE-2026-77806',assets:[]}),signal:AbortSignal.timeout(190000)});
  const result=await response.json();
  if(!response.ok)throw Object.assign(new Error(),{code:result.code||'API_BRIEFING_FAILED'});
  if(result.model!==config.ollamaModel||!result.cached||!result.persisted)throw Object.assign(new Error(),{code:'CACHE_VERIFICATION_FAILED'});
  console.log('App briefing verified:',JSON.stringify({model:result.model,provider:result.provider,cached:result.cached,persisted:result.persisted,actions:result.actions.length}));
 }
 if(process.argv.includes('--dependency-priority')){
  const response=await fetch('http://127.0.0.1:5173/api/aegis/dependencies/latest');
  const {report}=await response.json();
  if(!response.ok||!report?.prioritization)throw Object.assign(new Error(),{code:'PRIORITY_API_FAILED'});
  const affected=report.packages.filter(p=>p.status==='affected');
  if(affected.some((p,i)=>!p.priority||p.priority.score!==p.priority.severityPoints+p.priority.exposurePoints+p.priority.modelPoints||(i>0&&affected[i-1].priority.score<p.priority.score)))throw Object.assign(new Error(),{code:'PRIORITY_ORDER_FAILED'});
  console.log('Saved scan priority verified:',JSON.stringify({version:report.prioritization.version,affected:affected.length,modelMatched:report.prioritization.matchedPackages,unscored:report.prioritization.unscoredPackages}));
 }
 if(process.argv.includes('--dependency-scan')){
  const response=await fetch('http://127.0.0.1:5173/api/aegis/dependencies/scan',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({source:'Example scan · Axios & Chalk',exposure:'Public',skippedCount:0,packages:[{name:'axios',version:'1.7.0',direct:true,dev:false,paths:[],instances:1},{name:'chalk',version:'5.0.0',direct:true,dev:false,paths:[],instances:1}]}),signal:AbortSignal.timeout(180000)});
  const report=await response.json();if(!response.ok)throw Object.assign(new Error(),{code:report.code||'DEPENDENCY_SCAN_FAILED'});
  console.log('Live dependency scan:',JSON.stringify({summary:report.summary,persisted:report.persisted,packages:report.packages.map(p=>({package:p.key,status:p.status,upgrade:p.upgrade?.version||null}))}));
  if(report.summary.unknown||report.summary.total!==2||!report.persisted)throw Object.assign(new Error(),{code:'DEPENDENCY_SCAN_INCOMPLETE'});
  const pkg=report.packages.find(p=>p.status==='affected');if(!pkg)throw Object.assign(new Error(),{code:'EXPECTED_ADVISORY_MATCH'});
  const payload={scanId:report.id,packageKey:pkg.key};
  const explain=await fetch('http://127.0.0.1:5173/api/aegis/dependencies/explain',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(payload),signal:AbortSignal.timeout(190000)});
  const brief=await explain.json();if(!explain.ok)throw Object.assign(new Error(),{code:brief.code||'DEPENDENCY_BRIEFING_FAILED'});
  console.log('Live package briefing:',JSON.stringify({package:pkg.key,model:brief.model,actions:brief.actions.length,persisted:brief.persisted,summary:brief.summary}));
  const again=await fetch('http://127.0.0.1:5173/api/aegis/dependencies/explain',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(payload)});const cached=await again.json();if(!again.ok||!cached.cached)throw Object.assign(new Error(),{code:'DEPENDENCY_CACHE_FAILED'});
  console.log('Dependency briefing cache: verified.');
 }
 if(process.argv.includes('--generate')){
  if(config.graniteProvider!=='ollama'&&!config.hfToken){console.log('Live inference not run: HF_TOKEN has not been added yet.');}
  else {
   const {rows}=await pool.query('SELECT record FROM aegis_app.vulnerabilities ORDER BY model_rank LIMIT 1');
   const result=await generateBriefing(evidenceFor(rows[0].record,[]),config);
   await pool.query('INSERT INTO aegis_app.briefings(evidence_hash,cve_id,model,response) VALUES($1,$2,$3,$4) ON CONFLICT DO NOTHING',[result.evidenceHash,result.cveId,result.model,JSON.stringify(result)]);
   console.log('Live Granite generation verified:',JSON.stringify({cveId:result.cveId,model:result.model,actions:result.actions.length,saved:true}));
  }
 }
} catch(e){console.error('Connection check failed:',e.code||e.name);process.exitCode=1;}finally{await pool?.end();}
