#!/usr/bin/env node
// 학생 원본은 덮어쓰지 않는 전달 도구 설치기. import에는 파일·네트워크 부작용이 없다.
import {lstat,realpath,open,mkdir} from 'node:fs/promises';
import {resolve,dirname,join,relative,isAbsolute} from 'node:path';
import {fileURLToPath} from 'node:url';
import {createHash} from 'node:crypto';
export const PORTABLE_TOOLS_SCHEMA='keshev.portable-tools.v1';
export const PORTABLE_TOOLS_MANIFEST='PORTABLE_TOOLS_MANIFEST.json';
// 확정된 추가 파일만 허용한다. prefix 허용이나 학생 runtime 덮어쓰기로 넓히지 않는다.
export const PORTABLE_TOOL_ALLOWED_PATHS=Object.freeze([
  'tools/export-student-package.mjs','tools/install-portable-tools.mjs',
  'tools/portable/START_HERE.template.md','tools/portable/FINAL_RELEASE_CHECKLIST.template.md','tools/check-release-readiness.mjs',
  'docs/AFTER_COURSE_GUIDE.md','docs/FINAL_PACKAGE.md','docs/PERSONAL_AI_SETUP.md','src/standalone-server.mjs',
  'tools/start-standalone.ps1','tools/portable/personal-config.example.json',
  'src/portable/personal-config.mjs','src/portable/personal-model-http.mjs','src/portable/personal-ai.mjs',
  'public/portable/personal.html','public/portable/personal.js','public/portable/personal.css','public/portable/standalone.js',
]);
export const INSTALL_LIMITS=Object.freeze({files:128,fileBytes:1048576,totalBytes:16777216,manifestBytes:65536});
const allowed=new Set(PORTABLE_TOOL_ALLOWED_PATHS),plans=new WeakMap();
const sha=b=>createHash('sha256').update(b).digest('hex');
const samePath=(a,b)=>process.platform==='win32'?a.toLowerCase()===b.toLowerCase():a===b;
const identity=s=>[s.dev,s.ino,s.birthtimeNs].map(String).join(':');
const fileIdentity=s=>[identity(s),s.size,s.mtimeNs,s.ctimeNs,s.nlink].map(String).join(':');
const inside=(p,r)=>{const x=relative(r,p);return x===''||!isAbsolute(x)&&x!=='..'&&!x.startsWith('../')&&!x.startsWith('..\\');};
export class PortableToolsInstallError extends Error{
  constructor(code,detail={}){super(code);this.code=code;this.detail=detail;}
}
const fail=(code,detail)=>{throw new PortableToolsInstallError(code,detail);};
const exact=(o,keys)=>o&&Object.getPrototypeOf(o)===Object.prototype&&Object.keys(o).length===keys.length&&keys.every(k=>Object.hasOwn(o,k));
async function stat(p){try{return await lstat(p,{bigint:true});}catch(e){if(e.code==='ENOENT')return null;throw e;}}
async function directory(p){const s=await stat(p);if(!s||!s.isDirectory()||s.isSymbolicLink()||!samePath(await realpath(p),p))fail('INSTALL_UNSAFE_DIRECTORY');return identity(s);}
async function chain(p){const paths=[];for(let q=p;;q=dirname(q)){paths.push(q);if(dirname(q)===q)break;}const proofs=[];for(const q of paths.reverse())proofs.push({path:q,identity:await directory(q)});return proofs;}
async function checkChain(proofs){for(const p of proofs)if(await directory(p.path)!==p.identity)fail('INSTALL_PARENT_CHANGED');}
async function readStable(p,max){
  const parents=await chain(dirname(p)),before=await stat(p);
  if(!before||!before.isFile()||before.isSymbolicLink()||before.nlink!==1n||before.size>BigInt(max))fail('INSTALL_UNSAFE_FILE');
  const fd=await open(p,'r');
  try{const opened=await fd.stat({bigint:true});if(fileIdentity(opened)!==fileIdentity(before))fail('INSTALL_SOURCE_CHANGED');
    const bytes=await fd.readFile();const after=await fd.stat({bigint:true}),named=await stat(p);
    await checkChain(parents);
    if(!named||named.isSymbolicLink()||!named.isFile()||bytes.length>max||fileIdentity(after)!==fileIdentity(before)||fileIdentity(named)!==fileIdentity(before))fail('INSTALL_SOURCE_CHANGED');
    return {bytes,proof:fileIdentity(before)};
  }finally{await fd.close();}
}
function safeRel(p){return typeof p==='string'&&allowed.has(p)&&!p.includes('\\')&&!p.split('/').some(x=>!x||x==='.'||x==='..');}
async function targetPreflight(project,rows){
  const rootProof=await chain(project),directories=new Map(rootProof.map(p=>[p.path,p.identity])),files=[];
  for(const row of rows){const target=join(project,...row.path.split('/'));if(!inside(target,project))fail('INSTALL_PATH_INVALID');
    let parent=project,missing=false;
    for(const part of row.path.split('/').slice(0,-1)){parent=join(parent,part);if(missing)continue;const s=await stat(parent);if(!s){missing=true;continue;}directories.set(parent,await directory(parent));}
    const existing=missing?null:await stat(target);
    if(existing){const read=await readStable(target,INSTALL_LIMITS.fileBytes);if(read.bytes.length!==row.bytes||sha(read.bytes)!==row.sha256)fail('INSTALL_TARGET_CONFLICT',{path:row.path});files.push({...row,target,action:'skip',targetProof:read.proof});}
    else files.push({...row,target,action:'add'});
  }
  await checkChain([...directories].map(([path,identity])=>({path,identity})));
  return {files,directories};
}
async function sourceRows(bundle){
  const manifestRead=await readStable(join(bundle,PORTABLE_TOOLS_MANIFEST),INSTALL_LIMITS.manifestBytes);let manifest;
  try{manifest=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(manifestRead.bytes));}catch{fail('INSTALL_MANIFEST_INVALID');}
  if(!exact(manifest,['schema','files'])||manifest.schema!==PORTABLE_TOOLS_SCHEMA||!Array.isArray(manifest.files)||manifest.files.length<1||manifest.files.length>INSTALL_LIMITS.files)fail('INSTALL_MANIFEST_INVALID');
  const seen=new Set();let total=0;const rows=[];
  for(const f of manifest.files){
    if(!exact(f,['path','bytes','sha256'])||!safeRel(f.path)||seen.has(f.path.toLowerCase())||!Number.isSafeInteger(f.bytes)||f.bytes<0||f.bytes>INSTALL_LIMITS.fileBytes||typeof f.sha256!=='string'||!/^[a-f0-9]{64}$/.test(f.sha256))fail('INSTALL_MANIFEST_INVALID');
    seen.add(f.path.toLowerCase());total+=f.bytes;if(total>INSTALL_LIMITS.totalBytes)fail('INSTALL_LIMIT');
    const read=await readStable(join(bundle,...f.path.split('/')),INSTALL_LIMITS.fileBytes);
    if(read.bytes.length!==f.bytes||sha(read.bytes)!==f.sha256)fail('INSTALL_BUNDLE_MISMATCH',{path:f.path});rows.push({...f,sourceProof:read.proof});
  }
  return {rows,manifestSha256:sha(manifestRead.bytes),manifestProof:manifestRead.proof};
}
export async function planPortableToolsInstall({bundle:bundleInput,project:projectInput}={}){
  if(typeof bundleInput!=='string'||!bundleInput||typeof projectInput!=='string'||!projectInput)fail('INSTALL_ARGUMENT_INVALID');
  const bundle=resolve(bundleInput),project=resolve(projectInput);
  if(inside(bundle,project)||inside(project,bundle))fail('INSTALL_OVERLAP');
  const bundleParents=await chain(bundle),projectParents=await chain(project);
  // 대상은 기존 학생 on-client여야 한다. 이 파일은 읽기만 하며 생성·수정하지 않는다.
  const pkg=await readStable(join(project,'package.json'),INSTALL_LIMITS.fileBytes);let value;
  try{value=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(pkg.bytes));}catch{fail('INSTALL_PROJECT_INVALID');}
  if(value.name!=='alekov-client-starter')fail('INSTALL_PROJECT_INVALID');
  await readStable(join(project,'src','server.mjs'),INSTALL_LIMITS.fileBytes);
  await readStable(join(project,'student','extension.mjs'),INSTALL_LIMITS.fileBytes);
  const source=await sourceRows(bundle),target=await targetPreflight(project,source.rows);
  // SHA 목록은 바이트 대조 기준이며 배포 주체의 서명·신뢰를 인증하지 않는다.
  const result=Object.freeze({mode:'dry-run',bundle,project,manifestSha256:source.manifestSha256,manifestAuthenticated:false,files:Object.freeze(target.files.map(f=>Object.freeze({path:f.path,action:f.action,bytes:f.bytes,sha256:f.sha256}))),written:Object.freeze([])});
  plans.set(result,{bundle,project,bundleParents,projectParents,source,target,projectPackageProof:pkg.proof});return result;
}
export async function applyPortableToolsPlan(plan){
  const state=plans.get(plan);if(!state)fail('INSTALL_PLAN_INVALID');
  const {bundle,project,source}=state;const written=[],createdDirectories=[];let activePath=null;
  try{
    await checkChain(state.bundleParents);await checkChain(state.projectParents);
    await checkChain([...state.target.directories].map(([path,identity])=>({path,identity})));
    if((await readStable(join(project,'package.json'),INSTALL_LIMITS.fileBytes)).proof!==state.projectPackageProof)fail('INSTALL_PROJECT_CHANGED');
    const current=await sourceRows(bundle);
    if(current.manifestSha256!==source.manifestSha256||current.manifestProof!==source.manifestProof||current.rows.some((f,i)=>f.sourceProof!==source.rows[i].sourceProof))fail('INSTALL_SOURCE_CHANGED');
    // 모든 source와 target을 먼저 확인한 뒤에만 디렉터리·파일을 쓴다.
    const target=await targetPreflight(project,source.rows);
    for(let i=0;i<target.files.length;i++)if(target.files[i].action!==state.target.files[i].action||target.files[i].targetProof!==state.target.files[i].targetProof)fail('INSTALL_TARGET_CHANGED',{path:target.files[i].path});
    const guards=[...target.directories].map(([path,identity])=>({path,identity}));
    for(const f of target.files){
      activePath=f.path;await checkChain(guards);await checkChain(state.bundleParents);
      if(f.action==='skip'){
        const currentTarget=await readStable(f.target,INSTALL_LIMITS.fileBytes);
        if(currentTarget.proof!==f.targetProof||sha(currentTarget.bytes)!==f.sha256)fail('INSTALL_TARGET_CHANGED',{path:f.path});
        continue;
      }
      const read=await readStable(join(bundle,...f.path.split('/')),INSTALL_LIMITS.fileBytes);
      if(read.proof!==f.sourceProof||read.bytes.length!==f.bytes||sha(read.bytes)!==f.sha256)fail('INSTALL_SOURCE_CHANGED');
      let parent=project;
      for(const part of f.path.split('/').slice(0,-1)){
        parent=join(parent,part);await checkChain(guards);
        if(!guards.some(g=>samePath(g.path,parent))){
          if(await stat(parent))fail('INSTALL_PARENT_CHANGED');
          await mkdir(parent);createdDirectories.push(relative(project,parent).split('\\').join('/'));
          guards.push({path:parent,identity:await directory(parent)});
        }
      }
      await checkChain(guards);if(await stat(f.target))fail('INSTALL_TARGET_CHANGED',{path:f.path});
      const fd=await open(f.target,'wx',0o600);written.push(f.path);
      try{await fd.writeFile(read.bytes);await fd.sync();const s=await fd.stat({bigint:true});await checkChain(guards);const named=await stat(f.target);if(!named||named.isSymbolicLink()||!named.isFile()||named.nlink!==1n||identity(s)!==identity(named))fail('INSTALL_TARGET_CHANGED');}finally{await fd.close();}
      const verified=await readStable(f.target,INSTALL_LIMITS.fileBytes);if(sha(verified.bytes)!==f.sha256)fail('INSTALL_TARGET_CHANGED');
    }
    return {mode:'applied',bundle,project,manifestSha256:source.manifestSha256,manifestAuthenticated:false,files:plan.files,written,createdDirectories};
  }catch(e){
    // 부분 기록도 지우지 않는다. 같은 바이트는 다음에 건너뛰며 미완성 파일은 충돌로 보존한다.
    throw new PortableToolsInstallError(e instanceof PortableToolsInstallError?e.code:'INSTALL_IO',{...(e instanceof PortableToolsInstallError?e.detail:{}),written,createdDirectories,activePath,retry:'이미 추가한 파일은 남겨 두었습니다. 내용을 확인하고 같은 도구 묶음으로 미리보기부터 다시 진행하세요.'});
  }
}
export async function installPortableTools({bundle,project,apply=false}={}){
  if(typeof apply!=='boolean')fail('INSTALL_ARGUMENT_INVALID');const plan=await planPortableToolsInstall({bundle,project});return apply?applyPortableToolsPlan(plan):plan;
}
function argumentsOf(args){const o={apply:false};for(let i=0;i<args.length;i++){if(args[i]==='--apply'&&!o.apply){o.apply=true;continue;}const key=args[i];if(!['--bundle','--project'].includes(key)||typeof args[i+1]!=='string'||args[i+1].startsWith('--')||Object.hasOwn(o,key.slice(2)))fail('INSTALL_ARGUMENT_INVALID');o[key.slice(2)]=args[++i];}return o;}
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url)){
  try{console.log(JSON.stringify(await installPortableTools(argumentsOf(process.argv.slice(2)))));}
  catch(e){console.error(JSON.stringify({ok:false,code:e instanceof PortableToolsInstallError?e.code:'INSTALL_IO',detail:e instanceof PortableToolsInstallError?e.detail:{}}));process.exitCode=1;}
}
