import type {Page,Observation} from './assessment.js';
export type Compatibility={cms:string;version:string;minimumPhp:string;testedPhp:string;source:string;note:string};
const wpSource='https://make.wordpress.org/core/handbook/references/php-compatibility-and-wordpress-versions/';
const drupalSource='https://www.drupal.org/docs/getting-started/system-requirements/php-requirements';
function wp(v:string):Compatibility|null{
 const [major,minor]=v.split('.').map(Number);
 if(!Number.isFinite(major)||!Number.isFinite(minor))return null;
 const mm=major+'.'+minor;
 const versions:Record<string,[string,string]>={
 '7.1':['7.4','7.4–8.5'],'7.0':['7.4','7.4–8.5'],
 '6.9':['7.2.24','7.2–8.5'],'6.8':['7.2.24','7.2–8.4'],'6.7':['7.2.24','7.2–8.4'],'6.6':['7.2.24','7.2–8.3'],
 '6.5':['7.0','7.0–8.3'],'6.4':['7.0','7.0–8.3'],
 '6.3':['7.0','7.0–8.2'],'6.2':['5.6.20','5.6–8.2'],'6.1':['5.6.20','5.6–8.1']
 };
 const r=versions[mm];return r?{cms:'WordPress',version:v,minimumPhp:r[0],testedPhp:r[1],source:wpSource,note:'Minimum runtime requirement and documented compatibility differ. Neither identifies the server PHP runtime.'}:null;
}
function drupal(v:string):Compatibility|null{
 const [major,minor]=v.split('.').map(Number);
 if(major===10)return {cms:'Drupal',version:v,minimumPhp:'8.1',testedPhp:'Version-specific; consult Drupal table',source:drupalSource,note:'Drupal requirements can change between minor releases.'};
 if(major===11)return {cms:'Drupal',version:v,minimumPhp:minor>=3?'8.3':'8.3',testedPhp:'Version-specific; consult Drupal table',source:drupalSource,note:'This indicates only a documented minimum, not the actual PHP runtime.'};
 return null;
}
export function analyzeSiteVersions(pages:Page[]):{evidence:Observation[];compatibility:Compatibility[]}{
 const evidence:Observation[]=[],compatibility:Compatibility[]=[];
 const add=(kind:string,value:string,source:string,strength:Observation['strength'])=>{if(!evidence.some(e=>e.kind===kind&&e.value===value))evidence.push({kind,value:value.slice(0,180),source,strength});};
 const found=new Set<string>();
 for(const page of pages){
  const html=page.body.slice(0,131072);
  const candidates:string[]=[];
  // WordPress metadata generator and wp-embed/asset version tokens are hints, not trusted runtime readings.
  for(const m of html.matchAll(/<meta\b[^>]*\b(?:name\s*=\s*["']generator["'][^>]*content|content\s*=\s*["'][^"']*wordpress)[^>]*>/gi)){
   const version=m[0].match(/wordpress\s+(\d+\.\d+(?:\.\d+)?)/i);if(version)candidates.push(version[1]);
  }
  for(const m of html.matchAll(/(?:\?|&(?:amp;)?)ver=(\d+\.\d+(?:\.\d+)?)(?:[&#"'\s]|$)/gi)){
   // Only WordPress core assets; themes/plugins have unrelated independent versions.
   const prefix=html.slice(Math.max(0,m.index-220),m.index);
   if(/wp-includes\/(?:js|css)\/|wp-emoji-release|wp-embed/i.test(prefix))candidates.push(m[1]);
  }
  for(const v of candidates){
   add('wordpress-version-hint','WordPress '+v+' (public asset or generator; unverified)',page.url,'weak');
   const key='wp:'+v;
   if(!found.has(key)){const info=wp(v);if(info){compatibility.push(info);found.add(key);}}
  }
  for(const match of html.matchAll(/<meta\b[^>]*\bcontent\s*=\s*["']Drupal\s+(\d+(?:\.\d+){1,2})/gi)){
   const v=match[1];add('drupal-version-hint','Drupal '+v+' (generator; unverified)',page.url,'weak');
   const key='drupal:'+v;if(!found.has(key)){const info=drupal(v);if(info){compatibility.push(info);found.add(key);}}
  }
  // Historical dates are kept in a separate category and NEVER feed PHP version inference.
  for(const m of html.matchAll(/(?:©|&copy;|&#169;|copyright(?:\s|&nbsp;){1,4})(?:[^<>\n]{0,60}?)(\b(?:19|20)\d{2}\b)/gi)){
   const yr=Number(m[1]);if(yr>=1990&&yr<=new Date().getUTCFullYear()+1)add('copyright-year',String(yr)+' (page content; not software age)',page.url,'weak');
  }
  const generator=html.match(/<meta\b[^>]*name\s*=\s*["']generator["'][^>]*content\s*=\s*["']([^"']+)/i);
  if(generator)add('software-generator',generator[1],page.url,'weak');
 }
 return {evidence,compatibility};
}
