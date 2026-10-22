import {createHmac,randomBytes,scryptSync,timingSafeEqual} from 'node:crypto';
import {resolveTxt} from 'node:dns/promises';
import type {Request,Response,NextFunction} from 'express';
import {validateTarget} from './validation.js';
const secret=process.env.ADMIN_SESSION_SECRET||'';
const passwordHash=process.env.ADMIN_PASSWORD_HASH||'';
const plainPassword=process.env.ADMIN_PASSWORD||'';
const sessions=new Map<string,number>();
export function adminConfigStatus(){return {passwordConfigured:plainPassword.length>=14||passwordHash.startsWith('scrypt:'),sessionSecretConfigured:secret.length>=32};}
export function adminReady(){return secret.length>=32&&(plainPassword.length>=14||passwordHash.startsWith('scrypt:'));}
export function checkPassword(password:string):boolean{
 if(!adminReady())return false;
 if(plainPassword.length>=14){
  const supplied=createHmac('sha256',secret).update(password).digest();
  const expected=createHmac('sha256',secret).update(plainPassword).digest();
  return timingSafeEqual(supplied,expected);
 }
 const [,salt,hex]=passwordHash.split(':');
 if(!salt||!hex||hex.length!==128)return false;
 const expected=Buffer.from(hex,'hex'),actual=scryptSync(password,salt,64);
 return timingSafeEqual(expected,actual);
}
function sign(token:string){return createHmac('sha256',secret).update(token).digest('hex');}
export function issueSession(res:Response){
 const token=randomBytes(32).toString('hex');sessions.set(token,Date.now()+3600000);
 res.setHeader('Set-Cookie','scanner_admin='+token+'.'+sign(token)+'; HttpOnly; SameSite=Strict; Path=/api/admin; Max-Age=3600'+(process.env.ADMIN_COOKIE_SECURE==='true'?'; Secure':''));
}
export function requireAdmin(req:Request,res:Response,next:NextFunction){
 const cookie=(req.headers.cookie||'').split(';').map(x=>x.trim()).find(x=>x.startsWith('scanner_admin='))?.slice(14)||'';
 const [token,sig]=cookie.split('.');
 if(!token||!sig||sig.length!==64){res.status(401).json({error:'Admin login required'});return;}
 const a=Buffer.from(sig,'hex'),b=Buffer.from(sign(token),'hex');
 if(a.length!==b.length||!timingSafeEqual(a,b)||(sessions.get(token)||0)<Date.now()){res.status(401).json({error:'Admin session expired'});return;}
 next();
}
export function logout(req:Request,res:Response){
 const cookie=(req.headers.cookie||'').split(';').map(x=>x.trim()).find(x=>x.startsWith('scanner_admin='))?.slice(14)||'';
 sessions.delete(cookie.split('.')[0]);
 res.setHeader('Set-Cookie','scanner_admin=; HttpOnly; SameSite=Strict; Path=/api/admin; Max-Age=0');
 res.json({ok:true});
}
export type Target={url:string;host:string;token:string;verified:boolean;error?:string;status:string;report?:ReturnType<typeof import('./assessment.js').createEvidenceReport>};
export const targets=new Map<string,Target>();
export function importTargets(lines:string){
 const entries=lines.split(/\r?\n/).map(s=>s.trim()).filter(s=>s&&!s.startsWith('#'));
 if(entries.length>100)throw Error('Maximum 100 domains per import');
 if(new Set([...targets.keys(),...entries.map(line=>{try{return validateTarget(line.includes('://')?line:'https://'+line).origin+'/'}catch{return line}})]).size>100)throw Error('Maximum 100 total domains');
 for(const line of entries){
  const u=validateTarget(line.includes('://')?line:'https://'+line);
  if(u.pathname!=='/'||u.search)throw Error('Please import hostnames or site root URLs only');
  const url=u.origin+'/';
  if(!targets.has(url))targets.set(url,{url,host:u.hostname,token:randomBytes(18).toString('hex'),verified:false,status:'UNVERIFIED'});
 }
 return [...targets.values()];
}
export async function verifyTarget(t:Target){
 const records=await resolveTxt('_php2shell-check.'+t.host);
 t.verified=records.some(parts=>parts.join('').trim()===t.token);
 t.status=t.verified?'VERIFIED':'UNVERIFIED';
 return t.verified;
}
