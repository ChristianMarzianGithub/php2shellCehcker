import {describe,it,expect,beforeEach} from 'vitest';
import {targets,importTargets,checkPassword} from './admin';
beforeEach(()=>targets.clear());
describe('administrator domain import',()=>{
 it('imports newline separated domains and deduplicates entries',()=>{
  importTargets('example.org\nhttps://example.org/\n# comment\nsecond.example');
  expect(targets.size).toBe(2);
  expect([...targets.values()].every(t=>!t.verified)).toBe(true);
 });
 it('accepts and preserves website paths and query parameters',()=>{
  importTargets('https://www.cafedelsol.de/witten\nhttps://www.studienkreis.de/hattingen\nhttps://example.org/angebote?lang=de');
  expect([...targets.keys()]).toEqual([
   'https://www.cafedelsol.de/witten',
   'https://www.studienkreis.de/hattingen',
   'https://example.org/angebote?lang=de'
  ]);
  expect([...targets.values()].every(t=>!t.verified)).toBe(true);
 });
 it('allows more than 100 imported domains',()=>{
  importTargets(Array.from({length:125},(_,i)=>'a'+i+'.example').join('\n'));
  expect(targets.size).toBe(125);
 });
 it('rejects non-HTTPS and internal addresses',()=>{
  expect(()=>importTargets('http://example.org')).toThrow();
  expect(()=>importTargets('https://127.0.0.1')).toThrow();
 });
 it('does not accept a password when admin configuration is missing',()=>{
  if(!process.env.ADMIN_PASSWORD_HASH)expect(checkPassword('test')).toBe(false);
 });
});
