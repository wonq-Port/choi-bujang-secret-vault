// Read-only preparation inventory. Never import or run a submitted package.
import {lstat,realpath,open,readdir} from 'node:fs/promises';
import {resolve,join,dirname} from 'node:path';
import {fileURLToPath} from 'node:url';
import {createHash} from 'node:crypto';
import {execFile} from 'node:child_process';
import {promisify} from 'node:util';
import {devNull} from 'node:os';

const run=promisify(execFile),sha=b=>createHash('sha256').update(b).digest('hex');
const MANIFEST='PACKAGE_MANIFEST.json',MAX_FILE=8*1024*1024,MAX_TOTAL=64*1024*1024,MAX_FILES=2000;
const REQUIRED=['README.md','package.json','.env.example','src/server.mjs','student/extension.mjs'];
const safePath=p=>typeof p==='string'&&p.length>0&&p.length<=300&&!/[\\:\u0000-\u001f\u007f]/u.test(p)&&!p.startsWith('/')&&p.split('/').every(s=>s&&!['.','..'].includes(s)&&!/[. ]$/.test(s)&&! /^(?:con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\.|$)/i.test(s));
const fault=code=>Object.assign(Error(code),{code});
const hash=v=>typeof v==='string'&&/^[a-f0-9]{64}$/.test(v);
const secret=/(?:sk-(?:proj-|ant-|svcacct-|on-)?[A-Za-z0-9_-]{20,}|Bearer\s+[A-Za-z0-9._-]{20,}|-----BEGIN [A-Z ]*PRIVATE KEY-----)|^[ \t]*(?:OPENAI_API_KEY|ANTHROPIC_API_KEY|ON_AI_APP_KEY)[ \t]*=[ \t]*[^\s#]/im;

async function rootPath(value){
  if(typeof value!=='string'||!value)throw fault('DIRECTORY_REQUIRED');
  const path=resolve(value),s=await lstat(path);
  if(!s.isDirectory()||s.isSymbolicLink())throw fault('DIRECTORY_UNSAFE');
  for(let p=path;;p=dirname(p)){
    const entry=await lstat(p),actual=await realpath(p);
    const same=process.platform==='win32'?actual.toLowerCase()===p.toLowerCase():actual===p;
    if(entry.isSymbolicLink()||!entry.isDirectory()||!same)throw fault('DIRECTORY_UNSAFE');
    if(dirname(p)===p)break;
  }
  return path;
}
async function bytesAt(root,path){
  if(!safePath(path))throw fault('PATH_UNSAFE');
  const target=join(root,...path.split('/'));
  for(let p=target;;p=dirname(p)){
    const s=await lstat(p);
    if(s.isSymbolicLink()||(p===target?(!s.isFile()||s.nlink!==1||s.size>MAX_FILE):!s.isDirectory()))throw fault('FILE_UNSAFE');
    if(p===root)break;
  }
  const before=await lstat(target),h=await open(target,'r');
  try{
    const opened=await h.stat();
    if(opened.dev!==before.dev||opened.ino!==before.ino||opened.nlink!==1||opened.size>MAX_FILE)throw fault('FILE_CHANGED');
    const bytes=await h.readFile(),after=await h.stat(),last=await lstat(target);
    if(bytes.length!==opened.size||after.size!==opened.size||after.mtimeMs!==opened.mtimeMs||after.ctimeMs!==opened.ctimeMs||last.isSymbolicLink()||last.dev!==opened.dev||last.ino!==opened.ino||last.size!==opened.size||last.mtimeMs!==opened.mtimeMs||last.ctimeMs!==opened.ctimeMs)throw fault('FILE_CHANGED');
    return bytes;
  }finally{await h.close();}
}
const codeOf=e=>['ENOENT','ENOTDIR'].includes(e?.code)?'FILE_MISSING':['PATH_UNSAFE','FILE_UNSAFE','FILE_CHANGED'].includes(e?.code)?e.code:'FILE_UNREADABLE';
function textOf(b){try{return new TextDecoder('utf-8',{fatal:true}).decode(b);}catch{return null;}}
async function gitState(root){
  // In particular, git status must not launch a repository's fsmonitor hook.
  const env={};for(const name of ['PATH','Path','SystemRoot','WINDIR','TEMP','TMP'])if(process.env[name])env[name]=process.env[name];
  const gitNull=process.platform==='win32'?'NUL':devNull;
  Object.assign(env,{GIT_OPTIONAL_LOCKS:'0',GIT_TERMINAL_PROMPT:'0',GIT_NO_REPLACE_OBJECTS:'1',GIT_NO_LAZY_FETCH:'1',GIT_CONFIG_NOSYSTEM:'1',GIT_CONFIG_GLOBAL:gitNull});
  try{
    const opts={encoding:'utf8',windowsHide:true,timeout:5000,maxBuffer:1024*1024,env};
    const base=['--no-optional-locks','-c','core.fsmonitor=false','-c','core.untrackedCache=false','-c','core.hooksPath='+gitNull,'-C',root];
    const commit=(await run('git',[...base,'rev-parse','--verify','HEAD'],opts)).stdout.trim();
    const status=(await run('git',[...base,'status','--porcelain=v1','--untracked-files=all','--','.'],opts)).stdout;
    return {status:'observed',scope:'containing_repository_not_source_attestation',commit:/^[a-f0-9]{40}$/.test(commit)?commit:null,uncommittedChanges:status.length>0};
  }catch{return {status:'unavailable',scope:'not_verified',commit:null,uncommittedChanges:null};}
}

/** Structure only. The output contains paths/statuses, never file bodies or command output. */
export async function checkReleaseReadiness({source,package:packageInput}={}){
  const report={schema:'alekov.release-readiness.v1',status:'needs_preparation',officialStageEnabled:false,actualExecutionVerified:false,
    stage21:'not_assessed',stage22:'not_assessed',source:null,package:null,checks:[],
    execution:{freshFolder:'not_run',sameFinalCommit:'not_verified',cumulative13To20:'not_run',existingRecordsPreserved:'not_verified',disconnected:'not_run',personalAi:'not_run',demo:'not_run',realConnections:'not_verified',userData:'not_inspected'}};
  const add=(id,path,status,code)=>report.checks.push({id,path,status,code});
  let sourceRoot;
  try{sourceRoot=await rootPath(source);report.source={path:sourceRoot,git:await gitState(sourceRoot)};}catch{add('source',null,'blocked','SOURCE_DIRECTORY_UNAVAILABLE');report.status='blocked';return report;}
  async function required(root,prefix){
    for(const path of REQUIRED){try{
      const b=await bytesAt(root,path),text=textOf(b);
      add(prefix+'.required',path,b.length?'present':'missing',b.length?'CONTENT_NOT_ASSESSED':'EMPTY_FILE');
      if(text!==null&&secret.test(text))add(prefix+'.known_secret',path,'blocked','KNOWN_SECRET_PATTERN');
      if(path==='package.json'){
        let pkg;try{pkg=JSON.parse(text);}catch{}
        add(prefix+'.start_configuration',path,typeof pkg?.scripts?.start==='string'&&pkg.scripts.start.trim()?'present':'missing','DECLARATION_ONLY_NOT_EXECUTED');
        add(prefix+'.node_configuration',path,typeof pkg?.engines?.node==='string'?'present':'missing','DECLARATION_ONLY_NOT_VERIFIED');
      }
    }catch(e){add(prefix+'.required',path,'missing',codeOf(e));}}
  }
  await required(sourceRoot,'source');
  if(packageInput===undefined){add('package',MANIFEST,'pending','PACKAGE_NOT_SELECTED');return finish(report);}
  let packageRoot;
  try{packageRoot=await rootPath(packageInput);report.package={path:packageRoot,manifestSha256:null,sourcePin:'not_recorded',sameSourceBytes:'not_verified'};}
  catch{add('package',null,'blocked','PACKAGE_DIRECTORY_UNAVAILABLE');return finish(report);}
  let manifest,manifestBytes;
  try{manifestBytes=await bytesAt(packageRoot,MANIFEST);manifest=JSON.parse(textOf(manifestBytes));report.package.manifestSha256=sha(manifestBytes);}
  catch(e){add('package.manifest',MANIFEST,'pending',e instanceof SyntaxError?'MANIFEST_JSON_INVALID':codeOf(e));return finish(report);}
  if(manifest?.schema!=='alekov.portable-package.v1'||!Array.isArray(manifest.files)||!manifest.files.length||manifest.files.length>MAX_FILES){add('package.manifest',MANIFEST,'blocked','MANIFEST_SHAPE_INVALID');return finish(report);}
  const expected=new Set(),rows=[];let total=0;
  for(const row of manifest.files){
    if(!row||!safePath(row.path)||row.path.toLowerCase()===MANIFEST.toLowerCase()||expected.has(row.path.toLowerCase())||!hash(row.sha256)||!Number.isSafeInteger(row.bytes)||row.bytes<0||row.bytes>MAX_FILE){add('package.manifest',MANIFEST,'blocked','MANIFEST_ROW_INVALID');return finish(report);}
    expected.add(row.path.toLowerCase());rows.push(row);total+=row.bytes;
  }
  if(total>MAX_TOTAL){add('package.manifest',MANIFEST,'blocked','PACKAGE_SIZE_LIMIT');return finish(report);}
  add('package.totals',MANIFEST,manifest.totals?.files===rows.length&&manifest.totals?.bytes===total?'verified':'blocked','MANIFEST_TOTALS_COMPARISON');
  let matchingSource=true,sourceCount=0;
  for(const row of rows){
    try{
      const b=await bytesAt(packageRoot,row.path),text=textOf(b);
      add('package.sha256',row.path,b.length===row.bytes&&sha(b)===row.sha256?'verified':'blocked','MANIFEST_BYTES_COMPARISON');
      if(text!==null&&secret.test(text))add('package.known_secret',row.path,'blocked','KNOWN_SECRET_PATTERN');
      if(row.origin!=='package'){
        sourceCount++;
        try{const original=await bytesAt(sourceRoot,row.path);if(original.length!==b.length||sha(original)!==sha(b)){matchingSource=false;add('source.package_bytes',row.path,'pending','SOURCE_BYTES_DIFFER');}}
        catch{matchingSource=false;add('source.package_bytes',row.path,'pending','SOURCE_FILE_UNAVAILABLE');}
      }
    }catch(e){add('package.sha256',row.path,'blocked',codeOf(e));matchingSource=false;}
  }
  report.package.sameSourceBytes=sourceCount&&matchingSource?'matched_source_origin_files':'not_verified';
  // A manifest's commit is a declaration. Hash agreement never proves Git membership.
  if(typeof manifest.source?.commit==='string'&&/^[a-f0-9]{40}$/.test(manifest.source.commit))report.package.sourcePin='declared_not_verified';
  let count=0,walkBytes=0;
  async function walk(directory,prefix=''){
    for(const entry of await readdir(directory,{withFileTypes:true})){
      if(++count>MAX_FILES*3)throw fault('PACKAGE_WALK_LIMIT');
      const path=prefix?prefix+'/'+entry.name:entry.name;
      const target=join(directory,entry.name),s=await lstat(target);
      if(!safePath(path)||entry.isSymbolicLink()||s.isSymbolicLink()||(!s.isFile()&&!s.isDirectory())||entry.isDirectory()!==s.isDirectory()||entry.isFile()!==s.isFile()){add('package.inventory',null,'blocked','PACKAGE_ENTRY_UNSAFE');continue;}
      if(s.isDirectory()){await rootPath(target);await walk(target,path);continue;}
      if(s.nlink!==1||s.size>MAX_FILE){add('package.inventory',path,'blocked','FILE_UNSAFE');continue;}
      walkBytes+=s.size;if(walkBytes>MAX_TOTAL+MAX_FILE)throw fault('PACKAGE_WALK_LIMIT');
      if(path!==MANIFEST&&!expected.has(path.toLowerCase()))add('package.inventory',path,'blocked','UNLISTED_FILE');
    }
  }
  try{await walk(packageRoot);}catch{add('package.inventory',null,'blocked','PACKAGE_WALK_INCOMPLETE');}
  await required(packageRoot,'package');
  add('package.student_checklist','FINAL_RELEASE_CHECKLIST.md',expected.has('final_release_checklist.md')?'present':'pending','MANUAL_EXECUTION_STILL_REQUIRED');
  add('package.mode_declarations',MANIFEST,'not_assessed','DISCONNECTED_PERSONAL_AI_DEMO_REAL_CONNECTIONS_REQUIRE_SEPARATE_OBSERVATION');
  try{if(sha(await bytesAt(packageRoot,MANIFEST))!==sha(manifestBytes))add('package.manifest',MANIFEST,'blocked','MANIFEST_CHANGED');}catch{add('package.manifest',MANIFEST,'blocked','MANIFEST_CHANGED');}
  return finish(report);
}
function finish(report){report.status=report.checks.some(c=>c.status==='blocked')?'blocked':report.checks.some(c=>['missing','pending'].includes(c.status))?'needs_preparation':'structure_checked';return report;}

export function parseReadinessArgs(args){
  const options={};for(let i=0;i<args.length;i+=2){const key=args[i];if(!['--source','--package'].includes(key)||!args[i+1]||args[i+1].startsWith('--')||Object.hasOwn(options,key.slice(2)))throw fault('ARGUMENT_INVALID');options[key.slice(2)]=args[i+1];}
  if(!options.source)throw fault('ARGUMENT_INVALID');return options;
}
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url)){
  try{const out=await checkReleaseReadiness(parseReadinessArgs(process.argv.slice(2)));process.stdout.write(JSON.stringify(out)+'\n');if(out.status==='blocked')process.exitCode=1;}
  catch{process.stdout.write(JSON.stringify({schema:'alekov.release-readiness.v1',status:'blocked',code:'READINESS_ARGUMENT_OR_READ_ERROR',officialStageEnabled:false,actualExecutionVerified:false})+'\n');process.exitCode=1;}
}
