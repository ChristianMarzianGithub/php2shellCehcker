import {describe,it,expect} from 'vitest';
import {pinnedLookup} from './pinnedLookup';
describe('pinned DNS lookup',()=>{
 const lookup=pinnedLookup({address:'93.184.215.14',family:4});
 it('returns a list in all-address mode',()=>{
  lookup('example.org',{all:true},(err,addresses)=>{
   expect(err).toBeNull();
   expect(addresses).toEqual([{address:'93.184.215.14',family:4}]);
  });
 });
 it('returns an address in single-address mode',()=>{
  lookup('example.org',{family:4},(err,address,family)=>{
   expect(err).toBeNull();
   expect(address).toBe('93.184.215.14');
   expect(family).toBe(4);
  });
 });
});
