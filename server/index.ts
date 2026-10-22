import express from 'express';
import {lookup} from 'node:dns/promises';
import {Agent,request} from 'undici';
import {pinnedLookup} from './pinnedLookup.js';
import {z} from 'zod';
import {validateTarget,isPublicIp} from './validation.js';
import {createEvidenceReport, type Page} from './assessment.js';
import path from 'node:path';
import {adminReady,adminConfigStatus,checkPassword,issueSession,requireAdmin,logout,targets,importTargets,verifyTarget} from './admin.js';
const app=express();app.disable('x-powered-by');app.use(express.json({limit:'2mb'}));
const rate=new Map<string,{n:number;until:number}>();
app.use('/api',(req,res,next)=>{if(req.path.startsWith('/admin/')&&req.path!=='/admin/login')return next();const key=req.ip||'unknown',now=Date.now();let r=rate.get(key);if(!r||r.until<now)r={n:0,until:now+60000};r.n++;rate.set(key,r);if(r.n>10){res.status(429).json({error:'Too many scans'});return;}next();});
const input=z.object({url:z.string().max(2048),ownerVersion:z.string().max(100).optional(),distribution:z.string().max(90).optional(),packageRelease:z.string().max(100).optional(),sapi:z.string().max(80).optional(),vendorAdvisory:z.string().max(250).optional()});
async function readPublic(raw:string){
 let url=validateTarget(raw);
 for(let hop=0;hop<4;hop++){
  const addresses=await lookup(url.hostname,{all:true,verbatim:true});
  if(!addresses.length||addresses.some(a=>!isPublicIp(a.address)))throw new Error('Blocked DNS result');
  const selected=addresses[0];
  const agent=new Agent({connect:{lookup:pinnedLookup(selected)},connections:1});
  try{
   const response=await request(url.toString(),{dispatcher:agent,method:'GET',maxRedirections:0,headers:{'user-agent':'PHP2Shell-Passive/1.0'},headersTimeout:5000,bodyTimeout:5000,signal:AbortSignal.timeout(8000)});
   const headers:Record<string,string>={};for(const [k,v] of Object.entries(response.headers))headers[k]=Array.isArray(v)?v.join('; '):String(v||'');
   if(response.statusCode>=300&&response.statusCode<400&&headers.location){
    await response.body.dump();url=validateTarget(new URL(headers.location,url).toString());continue;
   }
   let body='',bytes=0;
   for await(const chunk of response.body){bytes+=chunk.length;if(bytes>131072)throw new Error('Response exceeded safety limit');body+=chunk.toString('utf8');}
   return {url:url.toString(),headers,body,statusCode:response.statusCode};
  }finally{await agent.close()}
 }
 throw new Error('Too many redirects');
}
app.post('/api/scan',async(req,res)=>{
 const parsed=input.safeParse(req.body);if(!parsed.success){res.status(400).json({error:'Invalid input'});return;}
 try{
  const first=await readPublic(parsed.data.url);
  const pages:Page[]=[first];
  // Only links explicitly present in homepage HTML, capped to two additional same-origin pages.
  const links=[...first.body.matchAll(/<a\b[^>]*\bhref\s*=\s*["']([^"'#]+)["']/gi)];
  const visited=new Set([first.url]);
  for(const match of links){
   if(pages.length>=3)break;
   try{
    const candidate=validateTarget(new URL(match[1],first.url).toString());
    if(candidate.origin!==new URL(first.url).origin || visited.has(candidate.toString()))continue;
    if(/\.(?:pdf|zip|png|jpg|gif|svg|mp4|webp|css|js|woff2?)(?:$|\?)/i.test(candidate.pathname))continue;
    visited.add(candidate.toString());
    const page=await readPublic(candidate.toString());
    if(new URL(page.url).origin===new URL(first.url).origin)pages.push(page);
   }catch{/* Secondary evidence is best effort; never fail main assessment. */}
  }
  res.json(createEvidenceReport(pages,{version:parsed.data.ownerVersion,distribution:parsed.data.distribution,packageRelease:parsed.data.packageRelease,sapi:parsed.data.sapi,vendorAdvisory:parsed.data.vendorAdvisory}));
 }
 catch(e){res.status(400).json({error:e instanceof Error?e.message:'Scan failed'});}
});

const loginAttempts=new Map<string,{n:number;until:number}>();
const credentials=z.object({password:z.string().min(1).max(1024)});
app.get('/api/admin/status',requireAdmin,(_req,res)=>res.json({ok:true}));
app.post('/api/admin/login',(req,res)=>{
 const key=req.ip||'unknown',now=Date.now();let attempt=loginAttempts.get(key);if(!attempt||attempt.until<now)attempt={n:0,until:now+900000};attempt.n++;loginAttempts.set(key,attempt);
 if(attempt.n>8){res.status(429).json({error:'Too many login attempts'});return;}
 const p=credentials.safeParse(req.body);
 if(!adminReady()){const s=adminConfigStatus();res.status(503).json({error:'Administrator setup incomplete: '+[!s.passwordConfigured?'set ADMIN_PASSWORD (14+ characters) or ADMIN_PASSWORD_HASH':null,!s.sessionSecretConfigured?'set ADMIN_SESSION_SECRET (32+ characters)':null].filter(Boolean).join('; ')+'. Restart the server after updating .env.'});return;}
 if(!p.success||!checkPassword(p.data.password)){res.status(401).json({error:'Invalid credentials'});return;}
 loginAttempts.delete(key);issueSession(res);res.json({ok:true});
});
app.post('/api/admin/logout',requireAdmin,logout);
app.get('/api/admin/targets',requireAdmin,(_req,res)=>res.json([...targets.values()]));
app.post('/api/admin/import',requireAdmin,(req,res)=>{
 try{
  const input=z.object({text:z.string().max(1500000)}).parse(req.body);
  res.json(importTargets(input.text));
 }catch(e){res.status(400).json({error:e instanceof Error?e.message:'Import error'});}
});
app.post('/api/admin/verify',requireAdmin,async(req,res)=>{
 const p=z.object({url:z.string()}).safeParse(req.body);
 const target=p.success?targets.get(p.data.url):undefined;
 if(!target){res.status(404).json({error:'Target not imported'});return;}
 try{const verified=await verifyTarget(target);res.json({verified,target});}
 catch{res.status(400).json({error:'DNS TXT ownership record unavailable',target});}
});
let jobRunning=false;
let verificationRunning=false;
let verificationProgress={done:0,total:0,verified:0,failed:0};
app.delete('/api/admin/targets',requireAdmin,(_req,res)=>{
 if(jobRunning||verificationRunning){res.status(409).json({error:'Cannot clear the list during a scan or verification job'});return;}
 const removed=targets.size;targets.clear();
 verificationProgress={done:0,total:0,verified:0,failed:0};
 res.json({removed,targets:[]});
});
app.post('/api/admin/verify-all',requireAdmin,(_req,res)=>{
 if(verificationRunning||jobRunning){res.status(409).json({error:'Another batch operation is running'});return;}
 const snapshot=[...targets.values()];
 if(!snapshot.length){res.status(400).json({error:'No imported websites'});return;}
 verificationRunning=true;
 verificationProgress={done:0,total:snapshot.length,verified:0,failed:0};
 res.status(202).json({accepted:snapshot.length});
 void (async()=>{
  try {
   for(const target of snapshot){
    target.status='VERIFYING';target.error=undefined;
    try{
     const result=await verifyTarget(target);
     if(result)verificationProgress.verified++;
     else verificationProgress.failed++;
    }catch{
     target.verified=false;target.status='UNVERIFIED';target.error='DNS TXT verification unavailable';
     verificationProgress.failed++;
    }
    verificationProgress.done++;
    await new Promise(resolve=>setTimeout(resolve,250));
   }
  }finally{verificationRunning=false;}
 })();
});

app.post('/api/admin/run',requireAdmin,(_req,res)=>{
 if(jobRunning||verificationRunning){res.status(409).json({error:'Batch already running'});return;}
 const pending=[...targets.values()].filter(t=>t.verified);
 if(!pending.length){res.status(400).json({error:'No DNS-verified targets. Add each TXT token before batch scanning.'});return;}
 jobRunning=true;res.status(202).json({accepted:pending.length});
 void (async()=>{
  try{
   for(const target of pending){
    target.status='RUNNING';target.error=undefined;
    try{
     // Recheck authorization before each scan; only public HTTPS page is fetched.
     if(!await verifyTarget(target)){target.status='UNVERIFIED';continue;}
     const page=await readPublic(target.url);
     target.report=createEvidenceReport([page]);target.status='DONE';
    }catch(e){target.status='ERROR';target.error=e instanceof Error?e.message:'Scan failed';}
    await new Promise(resolve=>setTimeout(resolve,1200));
   }
  }finally{jobRunning=false;}
 })();
});
app.get('/api/admin/batch-status',requireAdmin,(_req,res)=>res.json({running:jobRunning,verificationRunning,verificationProgress,targets:[...targets.values()]}));
app.use(express.static(path.resolve('dist')));
app.get('*',(_,res)=>res.sendFile(path.resolve('dist/index.html')));
app.listen(Number(process.env.PORT||3001),'0.0.0.0');
