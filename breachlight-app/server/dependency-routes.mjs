import { prioritizeReport } from './dependency-priority.mjs';
import { z } from 'zod';
import { scanDependencies } from './dependencies.mjs';
import { generateBriefing,evidenceHash,PublicError } from './granite.mjs';
const explainInput=z.object({scanId:z.string().uuid(),packageKey:z.string().min(1).max(320)});
export function dependencyEvidence(report,pkg){
 return {kind:'dependency',cveId:pkg.key,description:{package:pkg.name,installedVersion:pkg.version,source:'OSV advisory records retrieved for this exact npm version',advisories:pkg.advisories.slice(0,6).map(a=>({id:a.id,summary:a.summary,details:a.details.slice(0,2500),severity:a.severity,fixedVersions:a.fixedVersions,sourceUrl:a.sourceUrl})),omittedAdvisories:Math.max(0,pkg.advisories.length-6)},model_rank:{priority:pkg.priority||null,priorityMethod:'Review-order heuristic: severity (10–40; unknown 30) + exposure (internal 10; public or unknown 20) + historical rank (20–40; unscored neutral 20). Not exploitation probability.',matches:pkg.advisories.filter(a=>a.modelMatch).map(a=>a.modelMatch),note:'A missing rank means no rank is available in this top-500 snapshot, not low risk. Rank applies to the historical benchmark only.'},snapshot_signals:{checkedAt:report.scannedAt,matchType:'Exact installed version matched by OSV',exploitAvailability:'Not assessed'},inventory_context:{exposure:report.exposure,directDependency:pkg.direct,developmentOnly:pkg.dev,reachability:'Unknown: application source code and runtime were not analyzed',upgradeCandidate:pkg.upgrade,upgradeNote:pkg.upgrade?'Candidate returned no OSV advisories at scan time; compatibility must be tested.':'No complete upgrade candidate was verified. Do not invent one.'}};
}
export function dependencyRoutes(pool,{modelRanks,generate=generateBriefing,scan=scanDependencies}={}){
 let scanning=false;const pending=new Map();
 return async(path,req,config,readBody)=>{
  if(path==='/api/breachlight/dependencies/latest'&&req.method==='GET'){
   if(!pool)return {report:null};const result=await pool.query('SELECT report FROM breachlight_app.dependency_scans WHERE workspace_id=$1 ORDER BY created_at DESC LIMIT 1',[config.workspaceId]);return {report:prioritizeReport(result.rows[0]?.report||null,modelRanks)};
  }
  if(path==='/api/breachlight/dependencies/scan'&&req.method==='POST'){
   if(scanning)throw new PublicError(429,'SCAN_BUSY','A dependency scan is already running. Please wait for it to finish.');
   scanning=true;try{const report=await scan(await readBody(req),{modelRanks});let persisted=false;
    if(pool){try{report.persisted=true;await pool.query('INSERT INTO breachlight_app.dependency_scans(id,workspace_id,report) VALUES($1,$2,$3)',[report.id,config.workspaceId,JSON.stringify(report)]);persisted=true;}catch{}}
    report.persisted=persisted;return report;
   }finally{scanning=false;}
  }
  if(path==='/api/breachlight/dependencies/explain'&&req.method==='POST'){
   if(!pool)throw new PublicError(503,'DATABASE_REQUIRED','Save the scan to TigerData before requesting its AI explanation.');
   const parsed=explainInput.safeParse(await readBody(req));if(!parsed.success)throw new PublicError(400,'INVALID_SCAN','Select a saved dependency finding.');
   const {scanId,packageKey}=parsed.data;const saved=await pool.query('SELECT report FROM breachlight_app.dependency_scans WHERE id=$1 AND workspace_id=$2',[scanId,config.workspaceId]);const report=prioritizeReport(saved.rows[0]?.report,modelRanks);const pkg=report?.packages.find(p=>p.key===packageKey);
   if(!pkg||pkg.status!=='affected')throw new PublicError(404,'FINDING_NOT_FOUND','No affected package found in this workspace scan.');
   const evidence=dependencyEvidence(report,pkg),hash=evidenceHash(evidence,config);const cached=await pool.query('SELECT response FROM breachlight_app.dependency_briefings WHERE evidence_hash=$1',[hash]);if(cached.rows[0])return {...cached.rows[0].response,cached:true,persisted:true};
   if(!pending.has(hash)){
    if(pending.size)throw new PublicError(429,'LOCAL_MODEL_BUSY','Granite is analyzing another package. Please wait.');
    const promise=(async()=>{const result=await generate(evidence,config);let persisted=false;try{await pool.query('INSERT INTO breachlight_app.dependency_briefings(evidence_hash,scan_id,package_key,response) VALUES($1,$2,$3,$4) ON CONFLICT DO NOTHING',[hash,scanId,packageKey,JSON.stringify(result)]);persisted=true;}catch{}return {...result,cached:false,persisted};})();pending.set(hash,promise);promise.finally(()=>pending.delete(hash)).catch(()=>{});
   }
   return await pending.get(hash);
  }
  return null;
 };
}
