import {it,expect} from 'vitest';import {validateTarget,isPublicIp} from './validation';
it('rejects HTTP and internal',()=>{expect(()=>validateTarget('http://example.com')).toThrow();expect(()=>validateTarget('https://localhost')).toThrow()});
it('rejects reserved ranges',()=>{expect(isPublicIp('127.0.0.1')).toBe(false);expect(isPublicIp('169.254.169.254')).toBe(false);expect(isPublicIp('8.8.8.8')).toBe(true)});
