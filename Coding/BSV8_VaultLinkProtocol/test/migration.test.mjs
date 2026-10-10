import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,writeFile,readFile,rm} from 'node:fs/promises';
import {spawnSync} from 'node:child_process';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {fileURLToPath} from 'node:url';
import {encodeDeviceMigration,decodeDeviceMigration,inspectDeviceMigration,assertDeviceMigrationBinding,encode,unhex,hex} from '../dist/index.js';
const initial=()=>({version:1,id:'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa',walletGeneration:'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb',
  publicKey:unhex('0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798'),sourceHash:new Uint8Array(32).fill(1),policyHash:new Uint8Array(32).fill(2),direction:'to-software',phase:'staged',targetHash:null});
test('public device migration record has exact CBOR fields and clones commitments',()=>{
  const r=initial(),checked=inspectDeviceMigration(r);r.policyHash.fill(0);assert.equal(checked.policyHash[0],2);
  assert.deepEqual(decodeDeviceMigration(encodeDeviceMigration(checked)),checked);
  assert.throws(()=>inspectDeviceMigration({...checked,privateKey:new Uint8Array(32)}));
  assert.throws(()=>inspectDeviceMigration({...checked,phase:'host-committed'}));
  assert.throws(()=>inspectDeviceMigration({...checked,direction:'to-hardware',phase:'erasing',targetHash:new Uint8Array(32)}));
  assert.throws(()=>inspectDeviceMigration({...checked,id:'another-wallet'}));
  assertDeviceMigrationBinding(checked,initial());
  assert.throws(()=>assertDeviceMigrationBinding(checked,{...initial(),sourceHash:new Uint8Array(32)}),/migration-conflict/);
  assert.throws(()=>assertDeviceMigrationBinding(checked,{...initial(),walletGeneration:'cccccccc-cccc-cccc-cccc-cccccccccccc'}),/migration-conflict/);
});
test('actual C++ durable journal preserves host commitment through erase stages and rejects skipped/changed/replayed stages',async()=>{
  const dir=await mkdtemp(join(tmpdir(),'vlp-migration-journal-')),path=join(dir,'journal'),exe=join(dir,'journal-test');
  try {
    const compiled=spawnSync('c++',['-std=c++17','-Wall','-Wextra','-Werror','-fsanitize=address,undefined',fileURLToPath(new URL('../device/migration_journal_test.cpp',import.meta.url)),'-o',exe],{encoding:'utf8'});
    assert.equal(compiled.status,0,compiled.stderr);
    const run=(phase,target='-',id=initial().id)=>spawnSync(exe,[path,id,phase,target],{encoding:'utf8'});
    await writeFile(path,encodeDeviceMigration(initial()));
    assert.equal(run('begin').status,0);
    const first=await readFile(path);
    assert.equal(run('erased',hex(new Uint8Array(32).fill(3))).status,1);assert.deepEqual(await readFile(path),first);
    assert.equal(run('device-committed').status,0);assert.equal(run('device-committed').status,0);
    assert.equal(run('host-committed',hex(new Uint8Array(32).fill(3))).status,0);
    const committed=await readFile(path);
    assert.equal(run('host-committed',hex(new Uint8Array(32).fill(4))).status,1);assert.deepEqual(await readFile(path),committed);
    assert.equal(run('erasing',hex(new Uint8Array(32).fill(3)),'cccccccc-cccc-cccc-cccc-cccccccccccc').status,1);
    for(const phase of ['erasing','erased','complete']) {
      assert.equal(run(phase,hex(new Uint8Array(32).fill(3))).status,0);
      const current=decodeDeviceMigration(new Uint8Array(await readFile(path)));
      assert.equal(current.phase,phase);assert.equal(current.targetHash[0],3);assertDeviceMigrationBinding(current,initial());
    }
    assert.equal(run('device-committed').status,1);
    await writeFile(path,encodeDeviceMigration({...initial(),direction:'to-hardware'}));
    assert.equal(run('device-committed').status,0);assert.equal(run('host-committed',hex(new Uint8Array(32).fill(3))).status,0);
    assert.equal(run('erasing',hex(new Uint8Array(32).fill(3))).status,1);
    assert.equal(run('complete',hex(new Uint8Array(32).fill(3))).status,0);
    await writeFile(path,encode({...initial(),privateKey:new Uint8Array(32)},1024));assert.equal(run('device-committed').status,1);
  }finally{await rm(dir,{recursive:true,force:true});}
});

test('import proof authenticates actual source key, binds fresh challenge and rejects a provisional transport key',async()=>{
 const {migrationImportProofCommitment,verifyMigrationImportProof}=await import('../dist/index.js');
 const {secp256k1}=await import('@noble/curves/secp256k1');
 const r={...initial(),direction:'to-hardware',phase:'device-committed'},challenge=new Uint8Array(32).fill(3),secret=new Uint8Array(32);secret[31]=1;
 const sig=secp256k1.sign(await migrationImportProofCommitment(r,challenge),secret,{prehash:false,lowS:true}).toDERRawBytes();
 await verifyMigrationImportProof(r,challenge,sig);
 await assert.rejects(verifyMigrationImportProof(r,new Uint8Array(32).fill(4),sig),/migration-key-proof-invalid/);
 await assert.rejects(verifyMigrationImportProof({...r,policyHash:new Uint8Array(32).fill(9)},challenge,sig),/migration-key-proof-invalid/);
 secret[31]=2;const temporary=secp256k1.sign(await migrationImportProofCommitment(r,challenge),secret,{prehash:false,lowS:true}).toDERRawBytes();secret.fill(0);
 await assert.rejects(verifyMigrationImportProof(r,challenge,temporary),/migration-key-proof-invalid/);
 await assert.rejects(verifyMigrationImportProof({...r,phase:'staged'},challenge,sig),/migration-key-proof-invalid/);
});
