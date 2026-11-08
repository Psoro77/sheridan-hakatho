// Local inference only. Never forward Hugging Face credentials to Ollama.
import { PublicError } from './errors.mjs';
export function ollamaBase(config){
 let url;try{url=new URL(config.ollamaUrl||'http://127.0.0.1:11434');}catch{throw new PublicError(503,'OLLAMA_URL_INVALID','Configure a valid local Ollama URL.');}
 if(url.protocol!=='http:'||!['127.0.0.1','localhost','[::1]'].includes(url.hostname)||url.username||url.password||url.search||url.hash||url.pathname!=='/')throw new PublicError(503,'OLLAMA_URL_INVALID','Local inference requires a loopback Ollama URL such as http://127.0.0.1:11434.');
 return url.origin;
}
export function localModel(config){const model=config.ollamaModel||'granite4:latest';if(!/^granite[\w.:-]*$/.test(model)||model.endsWith(':cloud'))throw new PublicError(503,'GRANITE_MODEL_REQUIRED','Select an installed local IBM Granite model.');return model;}
export async function ollamaStatus(config,fetcher=fetch){
 const model=localModel(config);
 try{const res=await fetcher(ollamaBase(config)+'/api/tags',{signal:AbortSignal.timeout(2500),redirect:'error'});if(!res.ok)throw Error();const data=await res.json();const installed=data.models?.some(m=>m.name===model||m.model===model);return {configured:!!installed,ready:!!installed,model,provider:'ollama',mode:'local',message:installed?'Local Granite is ready.':`Model ${model} is not installed in Ollama.`};}catch(e){if(e instanceof PublicError)throw e;return {configured:false,ready:false,model,provider:'ollama',mode:'local',message:'Ollama is not reachable. Start the Ollama app or run ollama serve.'};}
}
export async function localChat(messages,format,config,fetcher=fetch){
 const model=localModel(config);const url=ollamaBase(config)+'/api/chat';
 let response;
 try{response=await fetcher(url,{method:'POST',redirect:'error',headers:{'Content-Type':'application/json'},body:JSON.stringify({model,messages,format,stream:false,options:{temperature:0,num_ctx:8192,num_predict:1600},keep_alive:'10m'}),signal:AbortSignal.timeout(180000)});}catch(e){throw new PublicError(502,'OLLAMA_UNREACHABLE',e.name==='TimeoutError'?'Local Granite took longer than three minutes. Retry after closing other memory-heavy apps.':'Ollama is not reachable. Start the Ollama app or run ollama serve.');}
 if(!response.ok)throw new PublicError(502,response.status===404?'OLLAMA_MODEL_MISSING':'OLLAMA_FAILED',response.status===404?`Ollama cannot find ${model}. Download that model or update OLLAMA_MODEL.`:'Local Granite could not complete the request. Check Ollama and available memory.');
 let data;try{data=await response.json();}catch{throw new PublicError(502,'INVALID_MODEL_OUTPUT','Ollama returned an invalid response.');}
 if(data.done_reason==='length')throw new PublicError(502,'INCOMPLETE_MODEL_OUTPUT','Local Granite reached its output limit. Retry for a complete briefing.');
 if(!data.done||typeof data.message?.content!=='string')throw new PublicError(502,'INVALID_MODEL_OUTPUT','Local Granite did not return a complete briefing.');
 return data.message.content;
}
