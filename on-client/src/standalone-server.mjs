// Additive after-course entry. Existing classroom server, student code and proofs stay unchanged.
import{readFile}from'node:fs/promises';
import{resolve}from'node:path';
import{fileURLToPath}from'node:url';
import{createHash}from'node:crypto';
import{createOnServer}from'./server.mjs';
import{loadEngine,demoEngine}from'./engine.mjs';
import{captureOnAiIncident}from'./ai/service.mjs';
import{readPersonalConfiguration}from'./portable/personal-config.mjs';
import{createPersonalAiService,PERSONAL_AI_MESSAGES}from'./portable/personal-ai.mjs';

const root=fileURLToPath(new URL('../',import.meta.url));
const id=v=>typeof v==='string'&&/^[A-Za-z0-9][A-Za-z0-9._:-]{0,79}$/.test(v);
const sha=v=>createHash('sha256').update(JSON.stringify(v)).digest('hex');
const error=(code,status=503)=>Object.assign(Error(code),{code,status});
const messages={PERSONAL_AI_DISABLED:'개인 AI가 꺼져 있습니다. 수료 후 설정 안내를 확인하세요.',ENGINE_NOT_CONNECTED:'실제 기록 서버에 연결되지 않았습니다. 예제 자료와 실제 기록을 구분하세요.',SUBJECT_SCOPE_UNVERIFIED:'현재 사용자·세션과 본인 기록의 연결을 확인할 수 없습니다.',EVENT_NOT_FOUND:'현재 본인 기록에서 선택한 이벤트를 찾을 수 없습니다.',EVENT_CHANGED:'이벤트 근거나 로그인 상태가 바뀌었습니다. 최신 기록을 다시 확인하세요.',REQUEST_INVALID:'요청 항목을 확인하세요.',HOST_REJECTED:'로컬 앱 주소에서 다시 요청하세요.',ORIGIN_REJECTED:'개인 AI 화면에서 다시 요청하세요.',REQUEST_TIMEOUT:'응답 시간이 초과됐습니다. 자동으로 다시 요청하지 않습니다.',REQUEST_CANCELLED:'요청을 취소했습니다.',PERSONAL_AI_FAILED:'개인 AI 응답을 확인할 수 없습니다. 설정과 사용 한도를 확인하세요.'};
const assets=new Map([['/personal/','public/portable/personal.html'],['/personal','public/portable/personal.html'],['/portable/personal.js','public/portable/personal.js'],['/portable/personal.css','public/portable/personal.css'],['/portable/standalone.js','public/portable/standalone.js']]);
const contentType=p=>p.endsWith('.js')?'text/javascript; charset=utf-8':p.endsWith('.css')?'text/css; charset=utf-8':'text/html; charset=utf-8';

/** Local server configuration only; a browser can never select a provider, key or adapter. */
export function createStandaloneServer({config={appName:'케셰브',ai:{enabled:false,provider:'openai',model:'gpt-6.1-sol'}},engine={evidenceMode:'disconnected'},personalAi,assetsRoot=root,requestTimeoutMs=15000}={}){
  if(!Number.isSafeInteger(requestTimeoutMs)||requestTimeoutMs<1||requestTimeoutMs>120000)throw error('REQUEST_INVALID');
  const service=personalAi??createPersonalAiService({config});
  const server=createOnServer({engine,assetsRoot,aiEnv:{}}),legacy=server.listeners('request')[0];
  server.removeAllListeners('request');
  const mode=['connected','demo','disconnected'].includes(engine.evidenceMode)?engine.evidenceMode:'disconnected';
  server.on('request',async(req,res)=>{
    let path;try{path=new URL(req.url,'http://127.0.0.1').pathname;}catch{res.writeHead(400);res.end();return;}
    const own=assets.has(path)||path.startsWith('/api/personal-ai/');
    if(!own&&path!=='/'&&path!=='/index.html'){legacy(req,res);return;}
    const controller=new AbortController();let timedOut=false;
    const cancel=()=>controller.abort(),timer=setTimeout(()=>{timedOut=true;controller.abort();},requestTimeoutMs);
    req.once('aborted',cancel);res.once('close',cancel);
    const alive=()=>{if(controller.signal.aborted||res.destroyed)throw error(timedOut?'REQUEST_TIMEOUT':'REQUEST_CANCELLED');};
    async function bounded(work){alive();let stop;const cancelled=new Promise((_,reject)=>{stop=()=>reject(error(timedOut?'REQUEST_TIMEOUT':'REQUEST_CANCELLED'));controller.signal.addEventListener('abort',stop,{once:true});});try{const result=await Promise.race([Promise.resolve().then(()=>{alive();return work(controller.signal);}),cancelled]);alive();return result;}finally{controller.signal.removeEventListener('abort',stop);}}
    const send=(status,body)=>{if(res.destroyed||res.writableEnded)return;res.writeHead(status,{'content-type':'application/json; charset=utf-8','cache-control':'no-store','x-content-type-options':'nosniff'});res.end(JSON.stringify(body));};
    async function current(){
      if(!['connected','demo'].includes(mode))throw error('ENGINE_NOT_CONNECTED');
      const identity=structuredClone(await bounded(signal=>engine.readIdentity({signal})));
      if(!id(identity?.user?.id)||!id(identity?.session?.id)||identity.session.status!=='active'||!id(engine.projectId))throw error('SUBJECT_SCOPE_UNVERIFIED');
      const scope={subjectId:identity.user.id,projectId:engine.projectId,appId:'aleph-on',audience:'on-client'};
      const rows=structuredClone(await bounded(signal=>engine.readEvents(scope,{signal})));
      if(!Array.isArray(rows)||rows.length>40||new Set(rows.map(r=>r?.id)).size!==rows.length)throw error('SUBJECT_SCOPE_UNVERIFIED');
      const events=rows.map(row=>{
        if(!id(row?.id)||!['access','xdr'].includes(row.kind)||!Number.isFinite(Date.parse(row.at))||mode==='connected'&&(row.subjectId!==scope.subjectId||row.projectId!==scope.projectId))throw error('SUBJECT_SCOPE_UNVERIFIED');
        const incident=captureOnAiIncident({incidentId:row.id,evidence:row.evidence?.map(e=>({id:e.id,summary:e.text})),rules:row.rules?.map(r=>({id:r.id,description:r.text})),currentState:row.state,supportedActions:row.supportedActions});
        return {id:row.id,kind:row.kind,at:row.at,summary:row.kind==='xdr'?'XDR 보안 이벤트':'업무 앱 접근 기록',evidence:incident.evidence.map(e=>({id:e.id,text:e.summary})),rules:incident.rules.map(r=>({id:r.id,text:r.description})),state:incident.currentState,supportedActions:incident.supportedActions};
      });
      const after=structuredClone(await bounded(signal=>engine.readIdentity({signal})));
      if(after?.user?.id!==identity.user.id||after?.session?.id!==identity.session.id||after?.session?.status!=='active'||engine.projectId!==scope.projectId)throw error('SUBJECT_SCOPE_UNVERIFIED');
      return {binding:{subjectId:identity.user.id,projectId:scope.projectId,sessionId:identity.session.id},events};
    }
    try{
      const address=server.address(),origin='http://127.0.0.1:'+address?.port;
      if(!req.url.startsWith('/')||req.url.startsWith('//'))throw error('REQUEST_INVALID',400);
      if(req.headers.host!=='127.0.0.1:'+address?.port||!['127.0.0.1','::ffff:127.0.0.1'].includes(req.socket.remoteAddress))throw error('HOST_REJECTED',403);
      // A link from the course guide may navigate to the public HTML shell. Cross-site
      // API, subresource and frame requests remain blocked, including all paid POSTs.
      const documentEntry=req.method==='GET'&&['/','/index.html','/personal','/personal/'].includes(path)&&req.headers['sec-fetch-mode']==='navigate'&&req.headers['sec-fetch-dest']==='document';
      if(req.headers.origin&&req.headers.origin!==origin||req.headers['sec-fetch-site']==='cross-site'&&!documentEntry||req.method==='POST'&&req.headers.origin!==origin)throw error('ORIGIN_REJECTED',403);
      if(new URL(req.url,origin).search)throw error('REQUEST_INVALID',400);
      if(req.method==='GET'&&(path==='/'||path==='/index.html'||assets.has(path))){
        const rel=assets.get(path)??'public/index.html';let bytes=await bounded(()=>readFile(resolve(assetsRoot,rel)));
        if(path==='/'||path==='/index.html'){
          const html=new TextDecoder('utf-8',{fatal:true}).decode(bytes);if(!html.includes('</head>'))throw error('REQUEST_INVALID');
          bytes=Buffer.from(html.replace('</head>','<script type="module" src="/portable/standalone.js"></script></head>'));
        }
        alive();res.writeHead(200,{'content-type':contentType(rel),'cache-control':'no-store','x-content-type-options':'nosniff','referrer-policy':'no-referrer','content-security-policy':"default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'"});res.end(bytes);return;
      }
      if(req.method==='GET'&&path==='/api/personal-ai/status'){send(200,{ok:true,data:{...service.status(),appName:config.appName,engineMode:mode}});return;}
      if(req.method==='GET'&&path==='/api/personal-ai/events'){const snapshot=await current();send(200,{ok:true,data:{mode,events:snapshot.events}});return;}
      if(req.method==='POST'&&path==='/api/personal-ai/explain'){
        if(!/^application\/json(?:;|$)/i.test(req.headers['content-type']??''))throw error('REQUEST_INVALID',415);
        let n=0;const chunks=[];await bounded(async()=>{for await(const chunk of req){n+=chunk.length;if(n>1024)throw error('REQUEST_INVALID',413);chunks.push(chunk);}});
        let body;try{body=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(Buffer.concat(chunks)));}catch{throw error('REQUEST_INVALID',400);}
        if(!body||Object.getPrototypeOf(body)!==Object.prototype||Object.keys(body).length!==1||!id(body.eventId))throw error('REQUEST_INVALID',400);
        if(service.status().mode!=='personal')throw error('PERSONAL_AI_DISABLED');
        const before=await current(),event=before.events.find(e=>e.id===body.eventId);if(!event)throw error('EVENT_NOT_FOUND',404);
        const incident={incidentId:event.id,evidence:event.evidence.map(e=>({id:e.id,summary:e.text})),rules:event.rules.map(r=>({id:r.id,description:r.text})),currentState:event.state,supportedActions:event.supportedActions};
        const result=await bounded(signal=>service.explain(incident,{signal}));
        const after=await current(),latest=after.events.find(e=>e.id===body.eventId);if(sha(before.binding)!==sha(after.binding)||!latest||sha(event)!==sha(latest))throw error('EVENT_CHANGED');
        if(!result?.ok){const code=Object.hasOwn(PERSONAL_AI_MESSAGES,result?.code)?result.code:'PERSONAL_AI_FAILED';send(503,{ok:false,error:{code,message:PERSONAL_AI_MESSAGES[code]??messages.PERSONAL_AI_FAILED,retryable:false}});return;}
        const o=result.observation;send(200,{ok:true,data:{mode:'personal',officialAssessment:false,executed:false,explanation:result.explanation,requestedModel:o.requestedModel,responseModel:o.actualModel,usage:o.reportedUsage,latencyMs:o.latencyMs}});return;
      }
      throw error('REQUEST_INVALID',404);
    }catch(e){const code=Object.hasOwn(messages,e?.code)?e.code:'PERSONAL_AI_FAILED';send(e?.status??503,{ok:false,error:{code,message:messages[code],retryable:false}});}
    finally{clearTimeout(timer);controller.abort();req.removeListener('aborted',cancel);res.removeListener('close',cancel);}
  });
  return server;
}

if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url)){
  try{
    const args=process.argv.slice(2);let file,demo=false;
    for(let i=0;i<args.length;i++){if(args[i]==='--demo'&&!demo)demo=true;else if(args[i]==='--personal-config'&&file===undefined&&args[i+1]&&!args[i+1].startsWith('--'))file=args[++i];else throw error('REQUEST_INVALID');}
    const port=Number(process.env.ON_PORT??5189);if(!Number.isInteger(port)||port<1024||port>65535)throw error('REQUEST_INVALID');
    const config=await readPersonalConfiguration({file,projectRoot:root}),engine=demo?demoEngine():await loadEngine(process.env.ON_ENGINE_ADAPTER);
    const server=createStandaloneServer({config,engine});server.on('error',e=>{console.error(e?.code==='EADDRINUSE'?'STANDALONE_PORT_IN_USE':e?.code==='EACCES'?'STANDALONE_PERMISSION_DENIED':'STANDALONE_START_FAILED');process.exitCode=1;});
    server.listen(port,'127.0.0.1',()=>console.log(`케셰브 수료 후 실행: http://127.0.0.1:${port}/ · 개인 AI: http://127.0.0.1:${port}/personal/`));
  }catch{console.error('STANDALONE_CONFIGURATION_INVALID');process.exitCode=1;}
}
