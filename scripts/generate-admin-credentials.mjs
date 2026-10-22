import {randomBytes,scryptSync} from 'node:crypto';
import {createInterface} from 'node:readline/promises';
const rl=createInterface({input:process.stdin,output:process.stdout});
let password;
try {
 password=await rl.question('Choose a strong administrator password: ');
} finally {
 rl.close();
}
if(password.length<14)throw Error('Choose at least 14 characters');
const salt=randomBytes(16).toString('hex');
const key=scryptSync(password,salt,64).toString('hex');
console.log('\nAdd these values to a local .env file (never commit it):');
console.log('ADMIN_PASSWORD_HASH=scrypt:'+salt+':'+key);
console.log('ADMIN_SESSION_SECRET='+randomBytes(32).toString('hex'));
