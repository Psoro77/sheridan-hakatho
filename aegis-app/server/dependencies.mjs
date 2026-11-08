import semver from 'semver';
import { prioritizeReport } from './dependency-priority.mjs';
import { z } from 'zod';
import { randomUUID } from 'node:crypto';
import { PublicError } from './errors.mjs';
const name=z.string().max(214).regex(/^(?:@[a-z0-9][a-z0-9._-]*\/)?[a-z0-9][a-z0-9._-]*$/);
export const scanSchema=z.object({source:z.string().min(1).max(120),exposure:z.enum(['Public','Internal','Unknown']),packages:z.array(z.object({name,version:z.string().max(100).refine(v=>!!semver.valid(v)&&!v.startsWith('v')),direct:z.boolean().nullable(),dev:z.boolean(),paths:z.array(z.string().max(500)).max(8).default([]),instances:z.number().int().min(1).max(100000).default(1)})).min(1).max(2000),skippedCount:z.number().int().min(0).max(100000).default(0)}).refine(v=>new Set(v.packages.map(p=>p.name+'@'+p.version)).size===v.packages.length,'Duplicate package versions');
const severityOrder={CRITICAL:4,HIGH:3,MODERATE:2,MEDIUM:2,LOW:1,UNKNOWN:0};
const queryFor=p=>({package:{name:p.name,ecosystem:'npm'},version:p.version});
async function osv(path,body,fetcher){let res;try{res=await fetcher('https://api.osv.dev/v1/'+path,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body),redirect:'error',signal:AbortSignal.timeout(18000)});}catch{throw new PublicError(502,'OSV_UNREACHABLE','OSV is unreachable. The scan cannot establish affected status. Retry shortly.');}if(!res.ok)throw new PublicError(502,'OSV_UNAVAILABLE','OSV could not complete this scan. Retry shortly.');const result=await res.json();if(result.error)throw new PublicError(502,'OSV_UNAVAILABLE','OSV returned an error.');return result;}
async function queryAll(pkg,fetcher){let vulns=[],token;for(let page=0;page<8;page++){const r=await osv('query',{...queryFor(pkg),...(token?{page_token:token}:{})},fetcher);if(r.vulns&&!Array.isArray(r.vulns))throw Error('invalid OSV response');vulns.push(...(r.vulns||[]).filter(v=>!v.withdrawn));token=r.next_page_token;if(!token)return vulns;}throw new PublicError(502,'OSV_INCOMPLETE','OSV pagination limit reached; this package could not be fully checked.');}
export function normalizeAdvisory(v,pkg,modelRanks={}){
 const affected=(v.affected||[]).filter(a=>a.package?.ecosystem==='npm'&&a.package?.name===pkg.name);
 const events=affected.flatMap(a=>(a.ranges||[]).flatMap(r=>r.events||[]));
 const fixed=[...new Set(events.map(e=>e.fixed).filter(f=>f&&semver.valid(f)&&semver.gt(f,pkg.version)))].sort(semver.compare);
 const aliases=(v.aliases||[]).filter(x=>typeof x==='string');const ranks=[v.id,...aliases].filter(id=>modelRanks[id]).map(id=>({id,rank:modelRanks[id]}));
 const severity=String(v.database_specific?.severity||affected.find(a=>a.database_specific?.severity)?.database_specific.severity||'UNKNOWN').toUpperCase();
 const ranges=affected.flatMap(a=>(a.ranges||[]).filter(r=>r.type==='SEMVER').map(r=>r.events));
 return {id:v.id,aliases,summary:(v.summary||v.id).slice(0,500),details:(v.details||'Advisory details unavailable. Open the source advisory.').slice(0,18000),severity:severityOrder[severity]===undefined?'UNKNOWN':severity,fixedVersions:fixed,ranges,published:v.published||null,modified:v.modified||null,references:(v.references||[]).filter(r=>typeof r.url==='string'&&r.url.startsWith('https://')).slice(0,10),sourceUrl:'https://osv.dev/vulnerability/'+encodeURIComponent(v.id),modelMatch:ranks.sort((a,b)=>a.rank-b.rank)[0]||null};
}
export async function scanDependencies(input,{fetcher=fetch,modelRanks={}}={}){
 const parsed=scanSchema.safeParse(input);if(!parsed.success)throw new PublicError(400,'INVALID_DEPENDENCIES','Supply valid npm package names and exact installed versions (up to 2,000 unique pairs).');
 const {packages,source,exposure,skippedCount}=parsed.data;const started=Date.now();const results=packages.map(p=>({...p,key:p.name+'@'+p.version,status:'unknown',advisories:[],upgrade:null,error:null}));
 for(let i=0;i<packages.length;i+=200){
  try{const batch=await osv('querybatch',{queries:packages.slice(i,i+200).map(queryFor)},fetcher);if(!Array.isArray(batch.results)||batch.results.length!==Math.min(200,packages.length-i))throw Error('invalid OSV response');for(let j=0;j<batch.results.length;j++){const row=batch.results[j];if(row.error){results[i+j].error='OSV could not check this package.';continue;}results[i+j].status=row.vulns?.length||row.next_page_token?'pending':'no-known-advisories';}}
  catch{for(let j=i;j<Math.min(i+200,packages.length);j++)results[j].error='OSV lookup failed; affected status is unknown.';}
 }
 let cursor=0;const pending=results.filter(r=>r.status==='pending');
 await Promise.all(Array.from({length:Math.min(5,pending.length)},async()=>{while(cursor<pending.length){const pkg=pending[cursor++];if(Date.now()-started>120000){pkg.status='unknown';pkg.error='Scan time limit reached. Advisory matches need another scan.';continue;}try{
   const raw=await queryAll(pkg,fetcher);pkg.advisories=raw.map(v=>normalizeAdvisory(v,pkg,modelRanks)).sort((a,b)=>(severityOrder[b.severity]||0)-(severityOrder[a.severity]||0)||String(b.published||'').localeCompare(String(a.published||'')));pkg.status=raw.length?'affected':'no-known-advisories';
   if(raw.length){const candidates=[...new Set(pkg.advisories.flatMap(a=>a.fixedVersions))].filter(v=>!semver.prerelease(v)).sort((a,b)=>{const am=semver.major(a)===semver.major(pkg.version),bm=semver.major(b)===semver.major(pkg.version);return Number(bm)-Number(am)||semver.rcompare(a,b)}).slice(0,3);
    for(const version of candidates){try{const check=await queryAll({...pkg,version},fetcher);if(!check.length){pkg.upgrade={version,checkedAt:new Date().toISOString(),majorChange:semver.major(version)!==semver.major(pkg.version),method:'OSV exact-version recheck'};break;}}catch{break;}}
   }
  }catch{pkg.status='unknown';pkg.error='Advisory details could not be fully retrieved. Do not treat this package as clear.';}
 }}));
 results.sort((a,b)=>{const s=p=>p.status==='affected'?10+Math.max(0,...p.advisories.map(v=>severityOrder[v.severity]||0)):p.status==='unknown'?5:0;return s(b)-s(a)||a.name.localeCompare(b.name)});
 const affected=results.filter(p=>p.status==='affected');return prioritizeReport({id:randomUUID(),source,exposure,scannedAt:new Date().toISOString(),ecosystem:'npm',provider:'OSV.dev',skippedCount,packages:results,summary:{total:results.length,affected:affected.length,noKnownAdvisories:results.filter(p=>p.status==='no-known-advisories').length,unknown:results.filter(p=>p.status==='unknown').length,advisories:new Set(affected.flatMap(p=>p.advisories.map(a=>a.id))).size,upgradeAvailable:affected.filter(p=>p.upgrade).length,directAffected:affected.filter(p=>p.direct===true).length,transitiveAffected:affected.filter(p=>p.direct===false).length},complete:!results.some(p=>p.status==='unknown')&&skippedCount===0},modelRanks);
}
