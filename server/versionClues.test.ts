import {describe,it,expect} from 'vitest';
import {analyzeSiteVersions} from './versionClues';
import {createEvidenceReport} from './assessment';
const page=(body:string)=>[{url:'https://example.org/',headers:{},body,statusCode:200}];
describe('public site version clues',()=>{
 it('extracts WordPress 6.7.10 generator and its compatibility, not PHP version',()=>{
  const pages=page('<meta name="generator" content="WordPress 6.7.10"><footer>© 2018</footer>');
  const x=analyzeSiteVersions(pages);
  expect(x.compatibility[0].minimumPhp).toBe('7.2.24');
  expect(x.compatibility[0].testedPhp).toBe('7.2–8.4');
  const r=createEvidenceReport(pages);
  expect(r.version).toBeNull();
  expect(r.status).toBe('INSUFFICIENT EVIDENCE');
  expect(r.evidence.some(e=>e.kind==='copyright-year')).toBe(true);
 });
 it('does not treat an unrelated plugin query version as WordPress core',()=>{
  const x=analyzeSiteVersions(page('<script src="/wp-content/plugins/widget/main.js?ver=6.7.10"></script>'));
  expect(x.compatibility).toHaveLength(0);
 });
 it('tracks Drupal generator without assigning actual PHP runtime',()=>{
  const r=createEvidenceReport(page('<meta name="generator" content="Drupal 10.4.2">'));
  expect(r.compatibility[0].minimumPhp).toBe('8.1');
  expect(r.version).toBeNull();
 });
});
