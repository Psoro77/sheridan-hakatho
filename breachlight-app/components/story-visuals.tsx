'use client';
import { useEffect, useMemo, useRef, useState } from 'react';
import { ResponsiveContainer, BarChart, Bar, XAxis, Tooltip } from 'recharts';

type Group={name:string;size:number;kevHits:number;lift:number;scoreboard:number;top500:number;cx:number|null;cy:number|null};
type Story={map:{x:number[];y:number[];g:number[];k:number[]};groups:Group[];groupOf:Record<string,number>;needles:{universe:number;cutoff:string;ranks:Record<string,number[]>}};
export type ClusterFilter={label:string;ids:string[]}|null;

const ORDERS:[string,string][]=[['breachlight','Breachlight'],['exploit_then_epss','Exploit code, then EPSS'],['epss_first','EPSS first'],['cvss_first','CVSS first']];
const COLS=500;
const C={grid:'#e9e9ee',top:'#0b7a5e',needle:'#c4362c',ink:'#1d1d1f',ink3:'#86868b'};
// past-KEV lift, one hue light→dark
const liftColor=(l:number)=>l>=7?'#8a4a06':l>=4?'#c47a26':l>=2?'#e3b375':'#d4d4da';
const LIFT_STEPS:[string,string][]=[['#d4d4da','< 2×'],['#e3b375','2–4×'],['#c47a26','4–7×'],['#8a4a06','7×+']];

function useWidth<T extends HTMLElement>(){const ref=useRef<T>(null);const [w,setW]=useState(0);useEffect(()=>{if(!ref.current)return;const o=new ResizeObserver(([e])=>setW(e.contentRect.width));o.observe(ref.current);return()=>o.disconnect()},[]);return [ref,w] as const}
function setupCanvas(c:HTMLCanvasElement,w:number,h:number){const d=window.devicePixelRatio||1;c.width=w*d;c.height=h*d;c.style.width=w+'px';c.style.height=h+'px';const x=c.getContext('2d')!;x.setTransform(d,0,0,d,0,0);return x}

export default function StoryVisuals({months,active,onSelect}:{months:{month:string;count:number;selected:number}[];active:string|null;onSelect:(f:ClusterFilter)=>void}){
 const [story,setStory]=useState<Story|null>(null);
 useEffect(()=>{fetch('/data/story.json').then(r=>r.ok?r.json():null).then(s=>setStory(s as Story|null)).catch(()=>{})},[]);
 if(!story)return null;
 return <><Haystack story={story} months={months}/><ClusterMap story={story} active={active} onSelect={onSelect}/></>;
}

function Haystack({story,months}:{story:Story;months:{month:string;count:number;selected:number}[]}){
 const [order,setOrder]=useState('breachlight');
 const [box,width]=useWidth<HTMLDivElement>();
 const canvas=useRef<HTMLCanvasElement>(null);
 const pos=useRef<number[]|null>(null);
 const [tip,setTip]=useState<{x:number;y:number;rank:number}|null>(null);
 const {universe,ranks,cutoff}=story.needles;
 const rows=Math.ceil(universe/COLS),cell=width/COLS,height=Math.max(rows*cell,1);
 const found=(ranks[order]||[]).filter(r=>r<=500).length,total=(ranks.breachlight||[]).length;
 const xyOf=(r:number)=>[((r-1)%COLS+.5)*cell,(Math.floor((r-1)/COLS)+.5)*cell];
 useEffect(()=>{
  if(!canvas.current||!width)return;
  const target=ranks[order]||[],from=pos.current&&pos.current.length===target.length?pos.current:target;
  const ctx=setupCanvas(canvas.current,width,height);let raf=0;const t0=performance.now();
  const draw=(t:number)=>{
   const p=Math.min((t-t0)/650,1),e=1-Math.pow(1-p,3);
   ctx.clearRect(0,0,width,height);
   ctx.fillStyle=C.grid;ctx.fillRect(0,0,width,(rows-1)*cell);const last=universe-(rows-1)*COLS;ctx.fillRect(0,(rows-1)*cell,last*cell,cell);
   ctx.fillStyle=C.top;ctx.fillRect(0,0,width,cell);
   const cur=target.map((r,i)=>from[i]+(r-from[i])*e);pos.current=cur;
   for(const r of cur){const [x,y]=xyOf(r);ctx.beginPath();ctx.arc(x,y,4,0,7);ctx.fillStyle=C.needle;ctx.fill();ctx.lineWidth=1.5;ctx.strokeStyle='#fff';ctx.stroke()}
   if(p<1)raf=requestAnimationFrame(draw);
  };raf=requestAnimationFrame(draw);return()=>cancelAnimationFrame(raf);
 },[order,width,height]);// eslint-disable-line react-hooks/exhaustive-deps
 const move=(ev:React.MouseEvent)=>{const b=(ev.target as HTMLElement).getBoundingClientRect(),mx=ev.clientX-b.left,my=ev.clientY-b.top;let best:number|null=null,bd=64;for(const r of ranks[order]||[]){const [x,y]=xyOf(r),d=(x-mx)**2+(y-my)**2;if(d<bd){bd=d;best=r}}setTip(best?{x:xyOf(best)[0],y:xyOf(best)[1],rank:best}:null)};
 return <section className="story-card">
  <div className="story-head"><div><div className="eyebrow">The haystack</div><h2>{total} needles in {universe.toLocaleString()} CVEs</h2><p>Each pixel is a 2026 CVE in rank order. Red dots were added to CISA KEV by {cutoff}, checked after the ranking was frozen.</p></div><div className="story-stat"><strong>{found}<span> / {total}</span></strong><small>in the top 500</small></div></div>
  <div className="seg" role="tablist">{ORDERS.map(([k,l])=><button key={k} role="tab" aria-selected={order===k} className={order===k?'on':''} onClick={()=>setOrder(k)}>{l}<b>{(ranks[k]||[]).filter(r=>r<=500).length}</b></button>)}</div>
  <div className="story-split">
   <div><div ref={box} className="haystack" onMouseMove={move} onMouseLeave={()=>setTip(null)}><canvas ref={canvas} aria-label={`${found} of ${total} exploited CVEs ranked in the top 500 by ${ORDERS.find(o=>o[0]===order)?.[1]}`}/>{tip&&<div className="map-tip" style={{left:tip.x,top:tip.y}}>Rank {tip.rank.toLocaleString()}{tip.rank<=500?' · in top 500':''}</div>}</div>
    <div className="story-legend"><span><i style={{background:C.top,borderRadius:1,height:4}}/>Top 500 (first row)</span><span><i style={{background:C.needle}}/>Added to KEV</span><span className="muted">1 row = 500 CVEs</span></div></div>
   <div className="months"><h3>CVEs per month</h3><ResponsiveContainer width="100%" height={170}><BarChart data={months.map(m=>({...m,label:new Date(m.month+'-02').toLocaleString('en',{month:'short'})}))} margin={{top:8,right:0,left:0,bottom:0}}><XAxis dataKey="label" tickLine={false} axisLine={false} tick={{fontSize:10,fill:C.ink3}}/><Tooltip cursor={{fill:'#f2f2f5'}} contentStyle={{fontSize:11,borderRadius:8}} formatter={(v,_,p)=>[`${Number(v).toLocaleString()} CVEs · ${(p.payload as {selected:number}).selected} in top 500`,'']} labelFormatter={()=>''}/><Bar dataKey="count" fill="#b9bcc6" radius={[4,4,0,0]} maxBarSize={22}/></BarChart></ResponsiveContainer><small>Jul–Sep volume is 2–3× the first half (July also holds June CVEs).</small></div>
  </div>
 </section>;
}

function ClusterMap({story,active,onSelect}:{story:Story;active:string|null;onSelect:(f:ClusterFilter)=>void}){
 const {map,groups,groupOf}=story;
 const [box,width]=useWidth<HTMLDivElement>();
 const canvas=useRef<HTMLCanvasElement>(null);
 const [hover,setHover]=useState<{g:number;x:number;y:number}|null>(null);
 const [layers,setLayers]=useState({top:true,kev:false});
 const height=Math.min(Math.max(width*.72,300),520),pad=14;
 const sel=active?groups.findIndex(g=>g.name===active):-1;
 const focus=hover?.g??(sel>=0?sel:-1);
 const px=(i:number)=>pad+map.x[i]/1000*(width-2*pad),py=(i:number)=>pad+(1-map.y[i]/1000)*(height-2*pad);
 const board=useMemo(()=>groups.map((g,i)=>({...g,i})).filter(g=>g.name!=='Unclustered'&&g.kevHits>=5).slice(0,10),[groups]);
 const labelled=useMemo(()=>new Set(board.slice(0,7).map(g=>g.i)),[board]);
 useEffect(()=>{
  if(!canvas.current||!width)return;const ctx=setupCanvas(canvas.current,width,height);const n=map.x.length;
  const dim=(g:number)=>focus>=0&&g!==focus;
  const order=[...Array(n).keys()].sort((a,b)=>(groups[map.g[a]]?.lift??0)-(groups[map.g[b]]?.lift??0));// hot clusters drawn last
  for(const i of order){const g=map.g[i],grp=groups[g],un=g<0||grp?.name==='Unclustered';ctx.globalAlpha=dim(g)?.15:un?.7:.9;ctx.fillStyle=un?'#dcdce2':liftColor(grp?.lift??1);ctx.beginPath();ctx.arc(px(i),py(i),un?1.3:1.9,0,7);ctx.fill()}
  if(layers.kev){ctx.fillStyle=C.ink;for(let i=0;i<n;i++)if(map.k[i]&1){ctx.globalAlpha=dim(map.g[i])?.15:.75;ctx.beginPath();ctx.arc(px(i),py(i),1.7,0,7);ctx.fill()}}
  if(layers.top){ctx.lineWidth=1.4;ctx.strokeStyle=C.top;for(let i=0;i<n;i++)if(map.k[i]&2){ctx.globalAlpha=dim(map.g[i])?.2:1;ctx.beginPath();ctx.arc(px(i),py(i),3.2,0,7);ctx.stroke()}}
  ctx.globalAlpha=1;ctx.font='600 11px Inter, system-ui, sans-serif';ctx.textAlign='center';ctx.lineJoin='round';
  const boxes:number[][]=[];// skip labels that would collide
  groups.forEach((g,i)=>{if(g.cx===null||(!labelled.has(i)&&i!==focus)||(focus>=0&&i!==focus))return;const x=pad+g.cx/1000*(width-2*pad),y=pad+(1-(g.cy as number)/1000)*(height-2*pad),w=ctx.measureText(g.name).width/2+4;if(i!==focus&&boxes.some(b=>Math.abs(b[0]-x)<w+b[2]&&Math.abs(b[1]-y)<14))return;boxes.push([x,y,w]);ctx.lineWidth=4;ctx.strokeStyle='rgba(255,255,255,.92)';ctx.strokeText(g.name,x,y);ctx.fillStyle=C.ink;ctx.fillText(g.name,x,y)});
 },[width,height,layers,focus]);// eslint-disable-line react-hooks/exhaustive-deps
 const pick=(i:number)=>{const g=groups[i];if(!g||g.name===active){onSelect(null);return}onSelect({label:g.name,ids:Object.entries(groupOf).filter(([,v])=>v===i).map(([k])=>k)})};
 const move=(ev:React.MouseEvent)=>{const b=(ev.target as HTMLElement).getBoundingClientRect(),mx=ev.clientX-b.left,my=ev.clientY-b.top;let best=-1,bd=100;for(let i=0;i<map.x.length;i++){const d=(px(i)-mx)**2+(py(i)-my)**2;if(d<bd){bd=d;best=i}}const g=best>=0?map.g[best]:-1;setHover(g>=0&&groups[g]?.name!=='Unclustered'?{g,x:mx,y:my}:null)};
 const h=hover?groups[hover.g]:null;
 return <section className="story-card">
  <div className="story-head"><div><div className="eyebrow">The landscape · IBM Granite embeddings</div><h2>Where exploitation concentrates</h2><p>CVE descriptions embedded with Granite, clustered with UMAP + HDBSCAN. Colour shows how often each cluster reached KEV before 2026. Click a cluster to filter the table.</p></div></div>
  <div className="map-layers"><button className={layers.top?'on':''} onClick={()=>setLayers(l=>({...l,top:!l.top}))}><i className="ring"/>Our top 500</button><button className={layers.kev?'on':''} onClick={()=>setLayers(l=>({...l,kev:!l.kev}))}><i className="dot"/>Past KEV</button><span className="lift-scale">Past KEV rate vs average{LIFT_STEPS.map(([c,l])=><span key={l}><i style={{background:c}}/>{l}</span>)}</span></div>
  <div className="story-split map-split">
   <div ref={box} className="cluster-map" onMouseMove={move} onMouseLeave={()=>setHover(null)} onClick={()=>hover&&pick(hover.g)} style={{height,cursor:hover?'pointer':'default'}}><canvas ref={canvas} aria-label="Map of CVE description clusters coloured by past exploitation rate"/>
    {h&&hover&&hover.x>=0&&<div className="map-tip" style={{left:Math.min(hover.x,width-150),top:hover.y}}><b>{h.name}</b><span>{h.size.toLocaleString()} CVEs · {h.kevHits} past KEV</span><span>{h.lift.toFixed(1)}× average · {h.top500} in top 500</span></div>}</div>
   <div className="leaderboard"><h3>Most exploited clusters</h3><ul>{board.map(g=><li key={g.i}><button className={g.name===active?'on':''} onMouseEnter={()=>setHover({g:g.i,x:-999,y:-999})} onMouseLeave={()=>setHover(null)} onClick={()=>pick(g.i)}><span className="lb-name">{g.name}</span><span className="lb-track"><i style={{width:`${g.lift/board[0].lift*100}%`,background:liftColor(g.lift)}}/></span><b>{g.lift.toFixed(1)}×</b><small>{g.top500}</small></button></li>)}</ul><div className="lb-foot"><span>past KEV rate vs average</span><span>in top 500</span></div></div>
  </div>
 </section>;
}
