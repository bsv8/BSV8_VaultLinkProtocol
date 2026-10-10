// Read-only audit of the actual SDK copies consumed by both products.
// Upstream mbedTLS provenance is verified separately by verify-vendor.mjs.
import {readFile} from 'node:fs/promises';
import {createHash} from 'node:crypto';
import {fileURLToPath} from 'node:url';
import {join} from 'node:path';
const source=fileURLToPath(new URL('../../',import.meta.url));
const workspace=fileURLToPath(new URL('../../../../../',import.meta.url));
const sha=bytes=>createHash('sha256').update(bytes).digest('hex');
for(const [name,root,manifest] of [
 ['Keymaster',join(process.env.VLP_KEYMASTER_ROOT??join(workspace,'keymaster.cc'),'Coding/keymaster/vaultlink-sdk'),'manifest.json'],
 ['RocKey',join(process.env.VLP_ROCKEY_ROOT??join(workspace,'Rockey'),'Coding/Rockey/vaultlink-sdk'),'MANIFEST.json'],
]){
 const receipt=JSON.parse(await readFile(join(root,manifest),'utf8'));
 let count=0;
 for(const [path,hash] of Object.entries(receipt.files)){
  if(path.startsWith('/')||path.split('/').includes('..'))throw Error('Invalid manifest path');
  const actual=await readFile(join(root,path));if(sha(actual)!==hash)throw Error(`${name}: consumer hash mismatch: ${path}`);
  const override=receipt.sourceOverrides?.[path];if(override&&override.sha256!==hash)throw Error(`${name}: override mismatch: ${path}`);
  // package.json is the declared consumer wrapper (exports/dependencies).
  if(path!=='package.json'){const origin=await readFile(path==='LICENSE'?fileURLToPath(new URL('../../../../LICENSE',import.meta.url)):join(source,path));if(sha(origin)!==hash)throw Error(`${name}: source differs: ${path}`);}
  count++;
 }
 console.log(`${name}: ${count} consumed SDK files verified against manifest and actual source`);
}
