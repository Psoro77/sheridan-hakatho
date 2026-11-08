'use client';
import { Target, AlertTriangle } from 'lucide-react';
import { ResponsiveContainer, BarChart, Bar, Cell, XAxis, YAxis, CartesianGrid, Tooltip, LabelList } from 'recharts';

export type ValidationData={universe:number;depth:number;folds2025:{positives:number;model:number;baselines:{name:string;hits:number}[]};bands:{band:string;hits:number;count:number;rate:number;lift:number}[]};

export default function ModelValidation({validation}:{validation?:ValidationData}){
 if(!validation?.folds2025)return <section className="model-validation"><div className="eyebrow">How this ranking was validated</div><h2>Validation evidence unavailable</h2><p>Reload the page to load the numbers.</p></section>;
 const {folds2025:f,bands,depth,universe}=validation;
 const best=Math.max(...f.baselines.map(b=>b.hits));
 const chart=[{name:'Breachlight model',hits:f.model,model:true},...f.baselines.map(b=>({name:b.name,hits:b.hits,model:false}))];
 const widest=Math.max(...bands.map(b=>b.rate));
 return <section className="model-validation">
  <div className="validation-head"><div><div className="eyebrow">How this ranking was validated</div><h2>Measured against the standard ways to triage.</h2><p>Out-of-time validation on CVEs published in 2025, after the training window. Each fold is cut at the same share of CVEs as the top {depth} of {universe.toLocaleString()} on the scoreboard.</p></div><div className="validation-headline"><span className="validation-icon"><Target size={22}/></span><strong>{f.model}<span> / {f.positives}</span></strong><b>exploited CVEs found</b><small>2025 validation · scoreboard depth</small></div></div>
  <div className="validation-grid">
   <div className="validation-chart"><h3>Exploited CVEs caught at scoreboard depth</h3><p className="chart-caption">2025 validation · {f.positives} later confirmed exploited</p><ResponsiveContainer width="100%" height={220}><BarChart data={chart} margin={{top:18,right:12,left:-18,bottom:4}}><CartesianGrid vertical={false} stroke="#dfe8e2"/><XAxis dataKey="name" tickLine={false} axisLine={false} interval={0} tick={{fontSize:10,fill:'#6f8278'}} height={42} tickFormatter={(v:string)=>v.length>16?v.slice(0,15)+'…':v}/><YAxis tickLine={false} axisLine={false} tick={{fontSize:10,fill:'#8c9c94'}} allowDecimals={false}/><Tooltip cursor={{fill:'#eef5f1'}} contentStyle={{fontSize:11,borderRadius:8,border:'1px solid #d3e1d8'}} formatter={(v)=>[`${v} of ${f.positives} found`,'']} labelStyle={{fontWeight:600}}/><Bar dataKey="hits" radius={[5,5,0,0]} maxBarSize={58}><LabelList dataKey="hits" position="top" style={{fontSize:12,fontWeight:650,fill:'#2b4a3e'}}/>{chart.map(d=><Cell key={d.name} fill={d.model?'#227a63':'#b9cdc2'}/>)}</Bar></BarChart></ResponsiveContainer><small>{best>0?`${(f.model/best).toFixed(1)}× the best baseline (${best} of ${f.positives}). `:''}Small samples: confidence intervals are wide.</small></div>
   <div className="validation-bands"><h3>Does the rank order hold up?</h3><p className="chart-caption">2025 validation · share of each band later confirmed exploited</p><ul>{bands.map(b=><li key={b.band}><div className="band-row"><b>{b.band}</b><span>{(b.rate*100).toFixed(2)}%</span></div><div className="band-track"><i style={{width:`${Math.max(b.rate/widest*100,1.5)}%`}}/></div><small>{b.hits} of {b.count.toLocaleString()} CVEs · {b.lift>=1?`${b.lift.toFixed(1)}× the average rate`:`${b.lift.toFixed(2)}× the average rate`}</small></li>)}</ul></div>
  </div>
  <div className="validation-notes"><div><span>Data</span><strong>Challenge datasets only</strong><small>Features and labels come from the provided files; exploitation labels known up to 2025-12-31.</small></div><div><span>Model selection</span><strong>Validation only</strong><small>Model, features and ranking rule chosen on 2025 data.</small></div><div><span>IBM Granite embeddings</span><strong>4–5 hits</strong><small>Validation hits lost when the Granite description features are removed (ablation).</small></div></div>
  <div className="disclosure"><AlertTriangle size={18}/><p><b>Group results, not guarantees.</b> 2025 band rates are optimistic for 2026, which has about twice the CVE volume — the ordering is the claim, not the percentage. Exploitation-language phrases in descriptions are a disclosed leakage risk.</p></div>
 </section>;
}
