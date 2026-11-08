// A review-order heuristic, not a calibrated probability or fresh model inference.
const severityPoints={CRITICAL:40,HIGH:30,MODERATE:20,MEDIUM:20,LOW:10};
export function prioritizeReport(report,modelRanks){
 if(!report)return report;
 const exposurePoints=report.exposure==='Internal'?10:20;
 const packages=report.packages.map(pkg=>{
  const advisories=pkg.advisories.map(a=>{
   const matches=modelRanks?[a.id,...(a.aliases||[])].filter(id=>Number.isInteger(modelRanks[id])&&modelRanks[id]>=1&&modelRanks[id]<=500).map(id=>({id,rank:modelRanks[id]})):a.modelMatch?[a.modelMatch]:[];
   const modelMatch=matches.sort((a,b)=>a.rank-b.rank)[0]||null;
   const severity=severityPoints[a.severity]??30;
   const modelPoints=modelMatch?20+Math.round(20*(500-modelMatch.rank)/499):20;
   return {...a,modelMatch,priority:{score:severity+exposurePoints+modelPoints,severityPoints:severity,exposurePoints,modelPoints,severityUnknown:!(a.severity in severityPoints)}};
  }).sort((a,b)=>b.priority.score-a.priority.score||a.id.localeCompare(b.id));
  const driver=pkg.status==='affected'?advisories[0]:null;
  const matched=advisories.filter(a=>a.modelMatch).length;
  return {...pkg,advisories,priority:driver?{...driver.priority,label:driver.priority.score>=80?'Review first':driver.priority.score>=60?'Review next':'Scheduled review',driverId:driver.id,severity:driver.severity,modelMatch:driver.modelMatch,matchedAdvisories:matched,totalAdvisories:advisories.length}:null};
 }).sort((a,b)=>{
  const group=p=>p.status==='affected'?2:p.status==='unknown'?1:0;
  return group(b)-group(a)||(b.priority?.score??0)-(a.priority?.score??0)||a.key.localeCompare(b.key);
 });
 const affected=packages.filter(p=>p.status==='affected');
 return {...report,packages,prioritization:{version:'aegis-context-v1',method:'Severity + exposure + historical model rank; highest-priority advisory drives each package.',modelSource:'Saved Aegis top-500 ranking; exact CVE/advisory alias matches only',matchedPackages:affected.filter(p=>p.priority?.matchedAdvisories>0).length,unscoredPackages:affected.filter(p=>!p.priority?.matchedAdvisories).length,reviewFirst:affected.filter(p=>p.priority?.score>=80).length}};
}
