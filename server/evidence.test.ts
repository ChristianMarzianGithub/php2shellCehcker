import {describe,it,expect} from 'vitest';
import {assessVersion,collectEvidence,createEvidenceReport} from './assessment';
describe('evidence collection',()=>{
 const pages=[{url:'https://example.org/',statusCode:200,headers:{server:'nginx','set-cookie':'PHPSESSID=secret; HttpOnly'},body:'<a href="/about">About</a><link href="/wp-content/themes/site.css">'}];
 it('recognizes CMS and PHP session without collecting secrets',()=>{
  const evidence=collectEvidence(pages);
  expect(evidence.some(e=>e.kind==='cms'&&e.value==='WordPress')).toBe(true);
  expect(evidence.some(e=>e.kind==='php-session')).toBe(true);
  expect(JSON.stringify(evidence)).not.toContain('secret');
 });
 it('keeps PHP detection separate from patch verdict',()=>{
  const report=createEvidenceReport(pages);
  expect(report.technologyStatus).toBe('PHP INDICATORS FOUND');
  expect(report.status).toBe('INSUFFICIENT EVIDENCE');
  expect(report.pageCount).toBe(1);
 });
 it('does not infer vendor backport solely from claimed advisory',()=>{
  const report=createEvidenceReport(pages,{version:'8.3.35',distribution:'Debian',vendorAdvisory:'DSA-EXAMPLE'});
  expect(report.status).toBe('AFFECTED VERSION DETECTED');
  expect(report.detail).toContain('not automatically verified');
 });
 it('does not treat a public PHP banner as proof of patch state',()=>{
  const report=createEvidenceReport([{url:'https://example.org',statusCode:200,headers:{'x-powered-by':'PHP/8.3.36'},body:''}]);
  expect(report.status).toBe('INSUFFICIENT EVIDENCE');
  expect(report.versionSource).toBe('Public X-Powered-By header');
 });
 it('does not pretend a fixed PHP version proves a fixed remote runtime',()=>{
  expect(assessVersion('8.3.36').status).toBe('REPORTED PATCHED VERSION');
 });
});
