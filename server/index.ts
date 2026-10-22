import express from 'express';
import {lookup} from 'node:dns/promises';
import {Agent,request} from 'undici';
import {pinnedLookup} from './pinnedLookup.js';
import {z} from 'zod';
import {validateTarget,isPublicIp} from './validation.js';
import {createReport} from './assessment.js';
import path from 'node:path';
const app=express();app.disable('x-powered-by');app.use(express.json({limit:'5kb'}));
const rate=new Map<string,{n:number;until:number}>();
app.use('/api',(req,res,next)=>{const key=req.ip||'unknown',now=Date.now();let r=rate.get(key);if(!r||r.until<now)r={n:0,until:now+60000};r.n++;rate.set(key,r);if(r.n>10){res.status(429).json({error:'Too many scans'});return;}next();});
const input=z.object({url:z.string().max(2048),ownerVersion:z.string().max(100).optional()});
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
   return {url:url.toString(),headers,body};
  }finally{await agent.close()}
 }
 throw new Error('Too many redirects');
}
app.post('/api/scan',async(req,res)=>{
 const parsed=input.safeParse(req.body);if(!parsed.success){res.status(400).json({error:'Invalid input'});return;}
 try{const r=await readPublic(parsed.data.url);res.json(createReport(r.url,r.headers,r.body,parsed.data.ownerVersion));}
 catch(e){res.status(400).json({error:e instanceof Error?e.message:'Scan failed'});}
});
app.use(express.static(path.resolve('dist')));
app.get('*',(_,res)=>res.sendFile(path.resolve('dist/index.html')));
app.listen(Number(process.env.PORT||3001),'0.0.0.0');
