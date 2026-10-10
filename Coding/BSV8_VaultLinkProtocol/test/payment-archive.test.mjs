import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,readFile,writeFile,rename,rm} from 'node:fs/promises';
import {spawnSync} from 'node:child_process';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {fileURLToPath} from 'node:url';
import {PaymentPolicy,encodePaymentPolicy,decodePaymentPolicy,assertPaymentPolicyContinuation} from '../dist/index.js';
const key='0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798';
// Real atomic filesystem adapter. This verifies host persistence, not ESP32 power loss.
async function disk(){const dir=await mkdtemp(join(tmpdir(),'vlp-archive-')),path=join(dir,'bank');return {dir,path,store:{async load(){try{return decodePaymentPolicy(new Uint8Array(await readFile(path)),key);}catch(e){if(e.code==='ENOENT')return null;throw e;}},async save(s){await writeFile(path+'.tmp',encodePaymentPolicy(s,key));await rename(path+'.tmp',path);}}};}
const channel={id:'money',owner:'app',kind:'app',network:'main',paymentType:'p2pkh',enabled:true,singleLimit:10000n,defaultSessionLimit:10000n,revision:1};
const request=(id,sessionId='connection')=>({requestId:id,channelId:'money',owner:'app',kind:'app',sessionId,network:'main',paymentType:'p2pkh',amount:1n,commitment:new Uint8Array(32).fill(7)});
test('terminal payments archive on real disk without resetting session used, forgetting unknown results or permitting replay',async()=>{
 const d=await disk();try{let p=await PaymentPolicy.open(d.store,key);await p.configure(channel,true);await p.startSession('connection','app',true);
 for(let i=0;i<256;i++){await p.reserve(request('payment-'+i));if(i===255)await p.markUnknown('payment-'+i);else await p.markSigned('payment-'+i);}
 const before=await p.snapshot();await p.reserve(request('next'));await p.markSigned('next');let after=await p.snapshot();assert.equal(after.version,3);assert.equal(after.sessions[0].used,257n);assert.equal(after.sessions[0].archivedUsed,255n);assert.equal(after.pending.find(x=>x.id==='payment-255').state,'unknown');assert.equal(after.archive.payments.length,255);assertPaymentPolicyContinuation(before,after,key);
 p=await PaymentPolicy.open(d.store,key);assert.deepEqual(await p.snapshot(),after);await assert.rejects(p.reserve(request('payment-0')),/request-reuse/);
 const bad=structuredClone(after);bad.sessions[0].archivedUsed=254n;assert.throws(()=>PaymentPolicy.inspectSnapshot(bad,key),/corrupt-state/);
 const lost=structuredClone(after);lost.archive.payments.shift();PaymentPolicy.inspectSnapshot(lost,key);assert.throws(()=>assertPaymentPolicyContinuation(after,lost,key),/policy-rollback/);
 }finally{await rm(d.dir,{recursive:true,force:true});}
});
test('closed-session receipts preserve later activity across migration and prohibit reconnecting retired session ids',async()=>{
 const d=await disk();try{const p=await PaymentPolicy.open(d.store,key);await p.configure(channel,true);await p.startSession('connection','app',true);const before=await p.snapshot();
 await p.reserve(request('one'));await p.markSigned('one');await p.closeSession('connection');
 for(let i=1;i<16;i++){await p.startSession('session-'+i,'app',true);await p.closeSession('session-'+i);}
 await p.startSession('seventeenth','app',true);const after=await p.snapshot();assert.equal(after.archive.sessions.length,16);assert.equal(after.archive.sessions.find(x=>x.record.id==='connection').record.used,1n);assertPaymentPolicyContinuation(before,after,key);await assert.rejects(p.startSession('connection','app',true),/session-reuse/);
 const damaged=structuredClone(after);damaged.archive.sessions[0].record.used=0n;assert.throws(()=>PaymentPolicy.inspectSnapshot(damaged,key),/corrupt-state/);
 const exe=join(d.dir,'policy'),prefix=process.env.VLP_MBEDTLS_PREFIX??'/opt/homebrew/opt/mbedtls@3';const source=fileURLToPath(new URL('../device/policy_archive_test.cpp',import.meta.url));
 const built=spawnSync('c++',['-std=c++17','-Wall','-Wextra','-Werror','-fsanitize=address,undefined','-I'+prefix+'/include',source,'-L'+prefix+'/lib','-Wl,-rpath,'+prefix+'/lib','-lmbedcrypto','-lmbedx509','-lmbedtls','-o',exe],{encoding:'utf8'});assert.equal(built.status,0,built.stderr);
 const cpp=spawnSync(exe,[d.path,key],{encoding:'utf8'});assert.equal(cpp.status,0,cpp.stderr);assert.deepEqual(decodePaymentPolicy(new Uint8Array(await readFile(d.path)),key),after);
 const native=spawnSync(exe,[d.path,key,'exercise'],{encoding:'utf8'});assert.equal(native.status,0,native.stderr);const later=decodePaymentPolicy(new Uint8Array(await readFile(d.path)),key);assert.equal(later.sessions.find(s=>s.id==='native-session').used,257n);assert.equal(later.sessions.find(s=>s.id==='native-session').archivedUsed,256n);assertPaymentPolicyContinuation(after,later,key);
 }finally{await rm(d.dir,{recursive:true,force:true});}
});
test('pool cumulative paid survives terminal compaction and finite replay archive exhaustion refuses new execution',async()=>{
 const d=await disk();try{const p=await PaymentPolicy.open(d.store,key);await p.configure({...channel,kind:'plugin',paymentType:'feepool.bitfs'},true);
 let successful=0,failure;for(let i=0;i<769;i++){try{const delta=await p.inspectPool('pool-id',new Uint8Array(32).fill(3),BigInt(i+1));await p.reserve({...request('pool-'+i),kind:'plugin',sessionId:null,paymentType:'feepool.bitfs',pool:delta.pool});await p.markSigned('pool-'+i);successful++;}catch(e){failure=e;break;}}
 assert.match(String(failure),/capacity|message-too-large/);const bank=await d.store.load();assert.equal(bank.pools[0].paid,BigInt(successful));assert(bank.archive.payments.length>0);assert(bank.pools[0].archivedPaid>0n);
 const reload=await PaymentPolicy.open(d.store,key);assert.deepEqual(await reload.snapshot(),bank);await assert.rejects(reload.inspectPool('pool-id',new Uint8Array(32).fill(3),BigInt(successful-1)),/rollback/);await assert.rejects(reload.reserve({...request('pool-0'),kind:'plugin',sessionId:null,paymentType:'feepool.bitfs'}),/request-reuse/);
 }finally{await rm(d.dir,{recursive:true,force:true});}
});
