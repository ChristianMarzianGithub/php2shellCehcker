export const fixes:Record<string,number>={'8.2':35,'8.3':36,'8.4':27,'8.5':12};
export const cves=['CVE-2026-109618','CVE-2026-109619'];
export type Observation={kind:string;value:string;source:string;strength:'strong'|'medium'|'weak'};
export type Page={url:string;headers:Record<string,string>;body:string;statusCode:number};
export type OwnerDiagnostics={version?:string;distribution?:string;packageRelease?:string;sapi?:string;vendorAdvisory?:string};
export function assessVersion(version:string|null){
 if(!version)return {status:'INSUFFICIENT EVIDENCE',confidence:10,detail:'PHP runtime patch level unknown. Public fingerprints cannot establish patch status.'};
 const v=version.match(/^(\d+)\.(\d+)\.(\d+)(?!\d)/);
 if(!v)return {status:'INSUFFICIENT EVIDENCE',confidence:10,detail:'PHP version format unrecognized.'};
 const major=Number(v[1]),minor=Number(v[2]),patch=Number(v[3]),fixed=fixes[major+'.'+minor];
 if(fixed!==undefined)return patch>=fixed
 ?{status:'REPORTED PATCHED VERSION',confidence:65,detail:'Reported upstream release meets the fixed-version baseline. Confirm the active web-serving runtime and vendor package.'}
 :{status:'AFFECTED VERSION DETECTED',confidence:60,detail:'Reported upstream version predates the fix; vendor backports may apply. Exploitability is not established.'};
 if(major<8||major===8&&minor<2)return {status:'POTENTIALLY VULNERABLE',confidence:40,detail:'Legacy PHP branch; vendor maintenance and patch state unknown.'};
 return {status:'INSUFFICIENT EVIDENCE',confidence:10,detail:'Unknown PHP branch; verify against current authoritative advisories.'};
}
export function collectEvidence(pages:Page[]):Observation[]{
 const evidence:Observation[]=[];
 function add(kind:string,value:string,source:string,strength:Observation['strength']){if(!evidence.some(e=>e.kind===kind&&e.value===value))evidence.push({kind,value:value.slice(0,180),source,strength});}
 for(const p of pages){
  const h=Object.fromEntries(Object.entries(p.headers).map(([k,v])=>[k.toLowerCase(),v]));
  const text=p.body.slice(0,131072);
  add('http-status',String(p.statusCode),p.url,'strong');
  if(h.server)add('server-header',h.server,p.url,'medium');
  if(h['x-powered-by'])add('powered-by',h['x-powered-by'],p.url,'medium');
  if(h['x-generator'])add('generator',h['x-generator'],p.url,'medium');
  if(/PHPSESSID=/i.test(h['set-cookie']||''))add('php-session','PHP session cookie name observed (value not collected)',p.url,'medium');
  const generator=text.match(/<meta\s+[^>]*name\s*=\s*["']generator["'][^>]*content\s*=\s*["']([^"']+)/i);
  if(generator)add('html-generator',generator[1],p.url,'medium');
  if(/wp-content\/|wp-includes\/|wp-json/i.test(text))add('cms','WordPress',p.url,'medium');
  if(/\/media\/system\/js\/|joomla!/i.test(text))add('cms','Joomla',p.url,'medium');
  if(/drupal-settings-json|drupal\.js|sites\/default\/files/i.test(text))add('cms','Drupal',p.url,'medium');
  if(/cloudflare/i.test(h.server||'')||h['cf-ray'])add('edge','Cloudflare indication (origin unknown)',p.url,'medium');
  if(h.via||h['x-cache'])add('proxy','Proxy/cache indicated (origin unknown)',p.url,'weak');
  if(/\.php(?:[?"'\s]|$)/i.test(p.url+' '+text.slice(0,20000)))add('php-link','Public PHP path or link seen',p.url,'weak');
 }
 return evidence;
}
export function createReport(url:string,headers:Record<string,string>,body:string,ownerVersion=''){
 return createEvidenceReport([{url,headers,body,statusCode:200}],ownerVersion?{version:ownerVersion}:{});
}
export function createEvidenceReport(pages:Page[],owner:OwnerDiagnostics={}){
 if(!pages.length)throw new Error('No web pages collected');
 const observations=collectEvidence(pages),first=pages[0];
 const powered=observations.find(e=>e.kind==='powered-by')?.value||'';
 const disclosed=powered.match(/PHP\/?\s*(\d+\.\d+\.\d+)/i)?.[1];
 const version=owner.version?.trim()||disclosed||null;
 const vendorPatchEvidence=owner.vendorAdvisory?.trim()||'';
 const evaluation=assessVersion(version);
 const phpIndicators=observations.filter(e=>['powered-by','php-session','php-link','cms'].includes(e.kind));
 const app=observations.find(e=>e.kind==='cms')?.value||'Unknown';
 const php=!!version||/php/i.test(powered)||phpIndicators.length>0;
 const versionSource=owner.version?'Owner supplied (not verified)':disclosed?'Public X-Powered-By header':'Unknown';
 const status=!owner.version && disclosed
  ? (evaluation.status==='REPORTED PATCHED VERSION'?'INSUFFICIENT EVIDENCE':'POTENTIALLY VULNERABLE')
  : evaluation.status;
 const confidence=!owner.version && disclosed?40:evaluation.confidence;
 const completeness=[pages.length>0,phpIndicators.length>0,!!version,!!owner.distribution&&!!owner.packageRelease,!!vendorPatchEvidence].filter(Boolean).length;
 const detail=(!owner.version&&disclosed?'An HTTP header suggests PHP '+disclosed+', but it may be stale, manipulated or emitted by a proxy. This cannot verify the actual runtime patch status. ':'' )+evaluation.detail+(vendorPatchEvidence?' A vendor advisory reference was supplied but is not automatically verified.':'');
 const sources=['https://github.com/NCSC-NL/php2shell','https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w','https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp'];
 const findings=cves.map(id=>({id,status,confidence,detail,impact:'If the running PHP runtime is affected and deployment conditions permit exploitation, attacker-controlled code could run with PHP worker privileges.'}));
 return {id:crypto.randomUUID(),url:first.url,createdAt:new Date().toISOString(),server:first.headers.server||first.headers.Server||'Not disclosed',php,version,app,status,confidence,detail,versionSource,
 completeness,technologyStatus:php?'PHP INDICATORS FOUND':'PHP NOT ESTABLISHED',patchStatus:status,proxy:observations.some(e=>e.kind==='edge'||e.kind==='proxy'),
 pageCount:pages.length,ownerDiagnostics:{distribution:owner.distribution||'',packageRelease:owner.packageRelease||'',sapi:owner.sapi||'',vendorAdvisory:vendorPatchEvidence},evidence:observations,
 observations:observations.map(e=>e.kind+': '+e.value),findings,
 recommendations:['Verify the actual web-serving PHP worker version; the CLI version may differ.','Match your OS distribution, package release and security advisory to vendor patch intelligence. Do not assume lower upstream versions are unpatched.','Upgrade to a release with upstream fixes (8.2.35, 8.3.36, 8.4.27, 8.5.12) or verified backported packages.','Restart PHP workers after patching and verify the active runtime.','Review web server/PHP logs for abnormal crashes or unexpected child processes.','Reduce service permissions and isolate affected workloads until fixed.'],sources};
}
