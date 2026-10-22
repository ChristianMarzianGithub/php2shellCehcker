import ipaddr from 'ipaddr.js';
export function validateTarget(raw:string):URL{
 let u:URL;try{u=new URL(raw)}catch{throw new Error('Invalid URL')}
 if(u.protocol!=='https:'||u.port&&u.port!=='443'||u.username||u.password)throw new Error('Only standard HTTPS URLs without credentials are supported');
 if(u.hostname==='localhost'||u.hostname.endsWith('.local')||u.hostname.endsWith('.internal'))throw new Error('Internal host not allowed');
 return u;
}
export function isPublicIp(address:string):boolean{
 try{
 const ip=ipaddr.process(address);
 return ip.range()==='unicast'&&!['100.64.0.0/10','192.0.0.0/24','198.18.0.0/15','198.51.100.0/24','203.0.113.0/24','240.0.0.0/4'].some(c=>ip.kind()==='ipv4'&&ip.match(ipaddr.parseCIDR(c)));
 }catch{return false}
}
