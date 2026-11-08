'use client';
import { useState } from 'react';
import { ArrowUpRight, Copy, Check, X } from 'lucide-react';
import { agentLink } from '../lib/project-workflow.mjs';
import { CursorMark, ClaudeMark } from './brand';
const agents=[{id:'cursor',name:'Cursor',Mark:CursorMark},{id:'claude',name:'Claude Code',Mark:ClaudeMark}];
/** Handoff panel. The trigger lives in the package action bar so it reads as a primary action. */
export default function AgentFix({prompt,onClose}:{prompt:string;onClose:()=>void}){
 const [agent,setAgent]=useState('cursor'),[cwd,setCwd]=useState(''),[message,setMessage]=useState('');
 const link=agentLink(agent,prompt,cwd);
 const name=agents.find(a=>a.id===agent)!.name;
 async function copy(){try{await navigator.clipboard.writeText(prompt);setMessage('Prompt copied. Review it in your project before running.')}catch{setMessage('Clipboard unavailable. Select and copy the prompt below.')}}
 return <div className="agent-handoff"><div className="agent-handoff-top"><h4>Hand off to your editor</h4><button className="icon-button" aria-label="Close agent handoff" onClick={onClose}><X size={16}/></button></div>
 <div className="segmented" role="tablist" aria-label="Coding agent">{agents.map(({id,name,Mark})=><button key={id} role="tab" aria-selected={agent===id} className={agent===id?'active':''} onClick={()=>{setAgent(id);setMessage('')}}><Mark size={15}/>{name}</button>)}</div>
 {agent==='claude'?<><label htmlFor="local-project">Local project folder</label><input id="local-project" placeholder="/Users/you/projects/your-app" value={cwd} onChange={e=>setCwd(e.target.value)}/><small>Absolute path. Claude Code must be installed with its link handler registered.</small></>:<small>Open the project in Cursor first — the prompt lands in its chat for review.</small>}
 <details><summary>Review the prompt</summary><textarea aria-label="Fix prompt" readOnly value={prompt}/></details>
 <div className="agent-handoff-actions"><button className="button" onClick={copy}><Copy size={14}/>Copy prompt</button>{link?<a className="button primary" href={link} onClick={()=>{void copy()}}>Open {name} <ArrowUpRight size={14}/></a>:<small>{agent==='claude'?'Enter an absolute project path to enable opening.':'Prompt too long for an app link — copy it instead.'}</small>}</div>
 {message&&<p role="status"><Check size={13}/>{message}</p>}
 <small>Opening your editor does not apply or verify the fix.</small></div>
}
