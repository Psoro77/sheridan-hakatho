export type ModelEvidenceData={status:'complete'|'validation-only';source:string;confidence:string;reasons:string[];universe:number;validation:{year:number;band:string;hits:number;count:number;rate:number;lift:number};nearest:{id:string;product:string;similarity:number;historyCutoff:string}|null};
// Saved-snapshot and inventory facts. The inventory join is the app's own context, not a model output.
export type EvidenceContext={rank:number;signals:string[];matches:number;score:number|null;exposure:string};

// The model writes each reason as a sentence with the number buried in it. Pull the number out so it can
// be shown as the headline, and strip the phrasing that the surrounding UI already states.
function parseReason(text:string){
 const s=text.replace(/;\s*closest is CVE-[\d-]+.*$/i,'');
 const lift=s.match(/([\d.]+)\s*x\s*(?:the\s*)?(?:average|typical)/i);
 const pctile=s.match(/top\s+([\d.]+)\s*%/i);
 const counts=s.match(/([\d,]+)\s+of\s+([\d,]+)/);
 const kev=s.match(/([\d,]+)\s+KEV additions/i);
 const sim=s.match(/similarity\s+([\d.]+)/i);
 const times=s.match(/attacked\s+([\d,]+)\s+times before/i);
 const bottom=s.match(/bottom\s+([\d.]+)\s*%/i);
 const share=s.match(/^([\d.]+)%\s+of\s+past\s+(.+?)\s+CVEs were exploited/i);
 let label=s.replace(/\s*\([^)]*\d[^)]*\)/g,'')
  .replace(/^Closest past exploited CVE:\s*/i,'Reads like ').replace(/,\s*similarity\s+[\d.]+$/i,'')
  .replace(/EPSS in (?:the )?(?:top|bottom) [\d.]+\s*% of its month/i,'EPSS percentile this month')
  .replace(/^Vendor (.+?) attacked [\d,]+ times before/i,'$1 attacked before').replace(/\s*\(KEV\)/i,'')
  .replace(/rank in the top [\d.]+\s*% for resemblance to/i,'resemble')
  .replace(/\s*ranks? it in the top [\d.]+\s*%/i,'')
  .replace(/\bhad ([\d,]+) KEV additions\b/i,'KEV additions')
  .replace(/\s{2,}/g,' ').trim().replace(/[.,;]$/,'');
 let detail:string|null=counts?`${counts[1]} of ${counts[2]} similar CVEs`:null;
 if(share){label=`Past ${share[2]} CVEs were exploited`;detail=`${share[1]}% of them`;}
 return {metric:lift?`${Number(lift[1])}×`:pctile?`top ${pctile[1]}%`:bottom?`bottom ${bottom[1]}%`:kev?kev[1]:times?times[1]:sim?`${Math.round(Number(sim[1])*100)}%`:null,label,detail,
         lift:lift?Number(lift[1]):null};
}

export default function ModelEvidence({evidence,context}:{evidence?:ModelEvidenceData;context?:EvidenceContext}){
 if(!evidence)return <section className="model-proof"><h3>Evidence unavailable</h3><p>Reload the page to load the evidence behind this rank.</p></section>;
 const v=evidence.validation;
 // One dot per CVE while the band is small enough to draw; otherwise 100 dots read as "x in every 100".
 const dots=Math.min(v.count,100),filled=v.count<=100?v.hits:Math.round(v.rate*100);
 const average=v.lift>0?v.rate/v.lift:0;
 // Scale both bars to whichever is larger: below the "rest" band the average outruns the band's own rate.
 const scale=Math.max(v.rate,average,1e-9),width=(r:number)=>`${Math.max(r/scale*100,1.5)}%`;
 const pct=(r:number)=>r*100>=1?(r*100).toFixed(1):(r*100).toFixed(2);
 // "rest" is the model's label for everything below the top 10%; spell that out rather than show it raw.
 const band=v.band==='rest'?'lower-ranked':v.band,Band=band[0].toUpperCase()+band.slice(1);
 // The closest-match reason repeats the dedicated block below it, so drop it when that block renders.
 const reasons=evidence.reasons.filter(r=>!(evidence.nearest&&/^Closest past exploited CVE:/i.test(r)));
 return <section className="model-proof">
  <div className="eyebrow">Evidence behind the rank</div>
  <div className="proof-head"><span className="proof-rank">#{context?.rank??'—'}<small>of {evidence.universe.toLocaleString()}</small></span><span className="proof-chip">{Band}</span></div>
  {/* The model's own confidence sentence stays available to screen readers; the cards render its numbers. */}
  <div className="proof-visuals" role="group" aria-label={evidence.confidence}>
   <div className="proof-card"><b>{filled>0?(v.count<=100?`${v.hits} of ${v.count}`:`${filled} in every 100`):`1 in ${Math.round(1/Math.max(v.rate,1e-9)).toLocaleString()}`}</b><small>{band} CVEs from {v.year} were later attacked for real</small>{filled>0&&<div className="waffle" role="img" aria-label={`${filled} of ${dots} dots filled`}>{Array.from({length:dots},(_,i)=><i key={i} className={i<filled?'hit':''}/>)}</div>}<strong>{pct(v.rate)}%</strong></div>
   <div className="proof-card"><b>{v.lift>=1?`${v.lift.toFixed(1)}×`:`${v.lift.toFixed(2)}×`}</b><small>more likely to be attacked than a random new CVE</small><div className="rate-compare"><div><span>{Band}</span><div className="rate-track"><i style={{width:width(v.rate)}}/></div><em>{pct(v.rate)}%</em></div><div><span>Any new CVE</span><div className="rate-track"><i className="faint" style={{width:width(average)}}/></div><em>{pct(average)}%</em></div></div></div>
  </div>
  <small>Read it this way: of every {v.count.toLocaleString()} CVEs the model put in the {band} in {v.year}, {v.hits} were later confirmed under attack. It tells you what to check first — it is not a forecast for this one CVE.</small>
  <h4>Why this CVE ranks here</h4>
  {reasons.length?<ul className="reason-list">{reasons.map(parseReason).map((p,i)=><li key={i}><span className={`reason-metric${p.metric?'':' none'}`}>{p.metric??'•'}</span><div><b>{p.label}</b>{p.detail&&<small>{p.detail}</small>}{p.lift&&<div className="reason-bar"><i style={{width:`${Math.min(Math.max(Math.log10(p.lift)/Math.log10(200),.08),1)*100}%`}}/></div>}</div></li>)}</ul>:<div className="evidence-pending">The three numbers that put this CVE at #{context?.rank??'—'} — how often this vendor has been attacked before, whether exploit code is public, how closely it reads like past attacks — are not in the app yet. They load with the model&rsquo;s explanation export. The hit rate above does not depend on them.</div>}
  {evidence.nearest&&<div className="nearest-evidence"><h4>Reads like this past attack</h4><div className="nearest-row"><div><a href={`https://nvd.nist.gov/vuln/detail/${evidence.nearest.id}`} target="_blank" rel="noopener noreferrer">{evidence.nearest.id}</a><small>{evidence.nearest.product}</small></div><span className="nearest-score">{Math.round(evidence.nearest.similarity*100)}%<small>{evidence.nearest.similarity>=.85?'very close':evidence.nearest.similarity>=.75?'close':'loose'} wording</small></span></div><div className="fact-bar"><i style={{width:`${evidence.nearest.similarity*100}%`}}/></div><small>Already confirmed exploited. Similar wording is a lead, not proof the same exploit applies.</small></div>}
  {context&&<dl className="evidence-facts"><div><dt>Public exploit code</dt><dd>{context.signals.length?context.signals.join(', '):'None at snapshot'}</dd></div><div><dt>Your inventory</dt><dd>{context.matches?`${context.matches} product match${context.matches>1?'es':''} · ${context.exposure.toLowerCase()}`:'No product-name match'}</dd></div>{context.score!==null&&<div><dt>Priority index</dt><dd>{context.score} / 100<div className="fact-bar"><i style={{width:`${context.score}%`}}/></div></dd></div>}</dl>}
 </section>;
}
