import type { LookupAddress } from 'node:dns';
import type { LookupFunction } from 'node:net';

/** Pin connections to an already validated public DNS address.
 * Node/Undici may request either a single address or an array.
 */
export function pinnedLookup(selected: LookupAddress): LookupFunction {
 return (_hostname, options, callback) => {
  if (typeof options === 'object' && options.all) {
   // The callback overload expects an array when all=true.
   (callback as (error: NodeJS.ErrnoException | null, addresses: LookupAddress[]) => void)(null, [{address:selected.address,family:selected.family}]);
  } else {
   (callback as (error: NodeJS.ErrnoException | null, address: string, family: number) => void)(null, selected.address, selected.family);
  }
 };
}
