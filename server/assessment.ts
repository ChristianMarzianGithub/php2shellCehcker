export const fixes:Record<string,number>={'8.2':35,'8.3':36,'8.4':27,'8.5':12};
export const cves=['CVE-2026-109618','CVE-2026-109619'];
export function assessVersion(version:string|null){
 if(!version)return {status:'INSUFFICIENT EVIDENCE',confidence:10,detail:'No verifiable runtime version found.'};
 const v=version.match(/^(\d+)\.(\d+)\.(\d+)/);
 if(!v)return {status:'INSUFFICIENT EVIDENCE',confidence:10,detail:'Version format unrecognized.'};
 const major=Number(v[1]),minor=Number(v[2]),patch=Number(v[3]),fixed=fixes[major+'.'+minor];
 if(fixed!==undefined)return patch>=fixed
 ?{status:'REPORTED PATCHED VERSION',confidence:65,detail:'Reported upstream release includes fix; confirm active runtime.'}
 :{status:'AFFECTED VERSION DETECTED',confidence:60,detail:'Reported upstream version predates fix; distribution backports may apply.'};
 if(major<8||major===8&&minor<2)return {status:'POTENTIALLY VULNERABLE',confidence:40,detail:'Legacy PHP branch; vendor patch state unknown.'};
 return {status:'INSUFFICIENT EVIDENCE',confidence:10,detail:'Unknown PHP branch.'};
}
export function createReport(url:string,headers:Record<string,string>,body:string,ownerVersion=''){
 const powered=headers['x-powered-by']||'';
 const version=ownerVersion||powered.match(/PHP\/?\s*(\d+\.\d+\.\d+)/i)?.[1]||null;
 const assessment=assessVersion(version);
 const app=/wp-content|wp-json/i.test(body)?'WordPress':/joomla/i.test(body)?'Joomla':/drupal/i.test(body)?'Drupal':'Unknown';
 const php=!!version||/php/i.test(powered)||/PHPSESSID/i.test(headers['set-cookie']||'');
 return {id:crypto.randomUUID(),url,createdAt:new Date().toISOString(),server:headers.server||'Not disclosed',php,version,app,
 observations:[powered?'Server exposed X-Powered-By: '+powered:'No runtime version exposed',app!=='Unknown'?'Application fingerprint: '+app:'Application not identified'],
 ...assessment,findings:cves.map(id=>({id,...assessment,impact:'Possible unauthenticated remote code execution if affected runtime and deployment conditions permit.'})),
 recommendations:['Validate the PHP runtime and distributor package patch status.','Patch to 8.2.35, 8.3.36, 8.4.27, 8.5.12 or a documented vendor backport.','Restart PHP workers; verify the serving runtime.','Check server logs for crashes, memory exhaustion, unusual child processes and compromise indicators.'],
 sources:['https://github.com/NCSC-NL/php2shell','https://www.php.net/']};
}
