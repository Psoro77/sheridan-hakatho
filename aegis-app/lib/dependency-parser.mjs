// Browser-side parsing: never upload lockfile contents, registry URLs, or integrity tokens.
const namePattern=/^(?:@[a-z0-9][a-z0-9._-]*\/)?[a-z0-9][a-z0-9._-]*$/;
const exactVersion=/^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/;
export function parseDependencies(input){
 const found=new Map(),skipped=[];
 function add(name,version,{direct=null,dev=false,path='',resolved='',link=false}={}){
  if(link||!namePattern.test(name)||!exactVersion.test(version||'')){skipped.push({name:String(name).slice(0,200),reason:link?'Local/workspace link':'Exact installed version required'});return;}
  if(resolved&&!/^https:\/\/registry\.npmjs\.org\//.test(resolved)){skipped.push({name,reason:'Non-public registry or local dependency excluded'});return;}
  const key=name+'@'+version;
  if(found.has(key)){const prior=found.get(key);prior.direct=prior.direct===true||direct===true?true:prior.direct===false&&direct===false?false:null;prior.dev=prior.dev&&dev;if(prior.paths.length<8&&path&&!prior.paths.includes(path))prior.paths.push(path);if(path)prior.instances++;return;}
  found.set(key,{name,version,direct,dev,paths:path?[path]:[],instances:1});
 }
 if(typeof input==='string'){
  for(const line of input.split(/[\n,]+/).map(s=>s.trim()).filter(Boolean)){const at=line.lastIndexOf('@');if(at<=0){skipped.push({name:line.slice(0,200),reason:'Use package@exact.version'});continue;}add(line.slice(0,at),line.slice(at+1),{direct:true});}
 }else if(input&&typeof input==='object'&&!Array.isArray(input)){
  if(input.lockfileVersion&&input.packages){
   const root=input.packages['']||{};const directNames=new Set(Object.keys({...root.dependencies,...root.devDependencies,...root.optionalDependencies}));
   for(const [path,entry] of Object.entries(input.packages)){
    if(!path)continue;
    const marker='node_modules/';const i=path.lastIndexOf(marker);
    if(i<0){skipped.push({name:path,reason:'Workspace source excluded'});continue;}
    if(entry.name&&entry.name!==path.slice(i+marker.length)){skipped.push({name:path.slice(i+marker.length),reason:'Aliased package requires manual review'});continue;}
    const name=entry.name||path.slice(i+marker.length);const topLevel=path===marker+path.slice(i+marker.length);
    add(name,entry.version,{direct:topLevel&&directNames.has(path.slice(marker.length)),dev:!!entry.dev,path,resolved:entry.resolved||'',link:!!entry.link});
   }
  }else if(input.lockfileVersion&&input.dependencies){
   const walk=(deps,parent='')=>{for(const [name,entry] of Object.entries(deps)){const path=parent+'node_modules/'+name;add(name,entry.version,{direct:parent?false:null,dev:!!entry.dev,path,resolved:entry.resolved||''});if(entry.dependencies)walk(entry.dependencies,path+'/');}};walk(input.dependencies);
  }else if(input.dependencies||input.devDependencies||input.optionalDependencies){
   for(const [name,version] of Object.entries(input.dependencies||{}))add(name,version,{direct:true});
   for(const [name,version] of Object.entries(input.optionalDependencies||{}))add(name,version,{direct:true});
   for(const [name,version] of Object.entries(input.devDependencies||{}))add(name,version,{direct:true,dev:true});
  }else throw Error('Upload package-lock.json or a package.json with exact versions.');
 }else throw Error('Invalid dependency file.');
 if(found.size>2000)throw Error('This scan supports up to 2,000 unique package versions. Split larger inventories.');
 return {packages:[...found.values()],skipped:skipped.slice(0,100),skippedCount:skipped.length};
}
