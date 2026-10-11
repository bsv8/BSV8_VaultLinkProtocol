import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,readFile,writeFile,rename,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {spawnSync} from 'node:child_process';
import {PaymentPolicy,encodePaymentPolicy,decodePaymentPolicy,assertPaymentPolicyContinuation} from '../dist/index.js';
const key='0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798';
test('registered signing policies survive actual TS -> C++ -> TS storage; registration cannot reset a local decision',async()=>{
 const dir=await mkdtemp(join(tmpdir(),'vlp-signing-')),path=join(dir,'bank');
 const store={async load(){try{return decodePaymentPolicy(new Uint8Array(await readFile(path)),key);}catch(e){if(e.code==='ENOENT')return null;throw e;}},async save(s){await writeFile(path+'.tmp',encodePaymentPolicy(s,key));await rename(path+'.tmp',path);}};
 try{
  const p=await PaymentPolicy.open(store,key),channel={id:'identity.noise-proof',owner:'window-p2p',kind:'plugin',operation:'identity.noise-proof',mode:'automatic',revision:1};
  await assert.rejects(p.registerSigning([channel],'main',false),/confirmation-required/);
  await p.registerSigning([channel],'main',true);await p.configureSigning(channel.id,'manual',1);
  const before=await p.snapshot();await p.registerSigning([channel],'main',false);
  assert.deepEqual(await p.snapshot(),before);await assert.rejects(p.registerSigning([{...channel,owner:'other'}],'main',true),/channel-conflict/);
  await assert.rejects(p.signingChannel(channel.id,channel.operation,'test'),/network-identity-mismatch/);
  await assert.rejects(p.signingChannel(channel.id,'identity.peer-record','main'),/channel-required/);
  const exe=join(dir,'policy'),built=spawnSync('c++',['-std=c++17','-Wall','-Wextra','-Werror','-fsanitize=address,undefined','device/policy_transfer_test.cpp','-o',exe],{encoding:'utf8'});assert.equal(built.status,0,built.stderr);
  const cpp=spawnSync(exe,[path,key],{encoding:'utf8'});assert.equal(cpp.status,0,cpp.stderr);
  const restored=await PaymentPolicy.open(store,key);assert.deepEqual(await restored.snapshot(),before);
  await restored.configureSigning(channel.id,'automatic',2);assertPaymentPolicyContinuation(before,await restored.snapshot(),key);
  await assert.rejects(restored.configureSigning(channel.id,'manual',2),/stale-config/);
  assert.throws(()=>assertPaymentPolicyContinuation(before,{...before,signing:[]},key),/policy-rollback/);
 }finally{await rm(dir,{recursive:true,force:true});}
});
