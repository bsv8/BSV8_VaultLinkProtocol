import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {DeviceIdentityKey,encode,inspectConnectEnvelope,connectCompactSignature,sha256,ConnectEnvelopeOperation} from '../dist/index.js';
const key=new DeviceIdentityKey(Uint8Array.from([...new Uint8Array(31),1]));
const pub=key.publicKey();
function identity(claims=[]){return encode([1,'request','https://app.example',100,200,'Identity',pub,claims],8192);}
test('WebCrypto hashes only the actual Node Buffer view',async()=>{
  const slab=Buffer.alloc(128,7),slice=slab.subarray(19,40);
  assert.deepEqual(Buffer.from(await sha256(slice)),createHash('sha256').update(slice).digest());
});
test('Connect identity: exact envelope, own subject, low-S compact interoperability',async()=>{
  const body={envelope:identity([['a',null],['b',false],['z',-1]])};
  const review=await inspectConnectEnvelope('identity',body,pub);
  assert.deepEqual(review.claimNames,['a','b','z']);
  let approvals=0;
  const operation=new ConnectEnvelopeOperation(key,'identity',async r=>{assert.equal(r.audience,'https://app.example');approvals++;return true;});
  const core=await operation.verify(body),signal=new AbortController().signal;
  assert.equal(await operation.authorize(core,signal),true);
  const result=await operation.execute(core,signal);
  assert.equal(connectCompactSignature(result.signature,await sha256(body.envelope),pub).length,64);
  assert.equal(approvals,1);
});
test('Connect intent requires exact complete content and cancellation prevents signing',async()=>{
  const content=new TextEncoder().encode('actual intent');
  const envelope=encode([1,'request','https://app.example',100,200,'Intent','text/plain',await sha256(content),pub],8192);
  const body={envelope,content};
  const review=await inspectConnectEnvelope('intent',body,pub);assert.equal(review.contentLength,13);
  await assert.rejects(inspectConnectEnvelope('intent',{envelope,content:new Uint8Array()},pub),/invalid-content/);
  await assert.rejects(inspectConnectEnvelope('intent',{envelope},pub));
  const cancel=new AbortController();
  await assert.rejects(key.signConnectEnvelope('intent',body,cancel.signal,async()=>{cancel.abort();return true;}),/revoked/);
  await assert.rejects(key.signConnectEnvelope('intent',body,new AbortController().signal,async()=>false),/denied/);
});
test('Connect rejects wrong identity, unordered or duplicate claims, trailing bytes and digest substitution',async()=>{
  const wrong=new DeviceIdentityKey(Uint8Array.from([...new Uint8Array(31),2]));
  try{await assert.rejects(inspectConnectEnvelope('identity',{envelope:identity()},wrong.publicKey()),/wrong-key/);}finally{wrong.close();}
  for(const claims of [[['z',1],['a',2]],[['a',1],['a',2]]])await assert.rejects(inspectConnectEnvelope('identity',{envelope:identity(claims)},pub),/invalid-envelope/);
  await assert.rejects(inspectConnectEnvelope('identity',{envelope:new Uint8Array([...identity(),0])},pub));
  await assert.rejects(inspectConnectEnvelope('identity',{envelope:await sha256(identity())},pub));
  await assert.rejects(inspectConnectEnvelope('identity',{envelope:identity(),digest:new Uint8Array(32)},pub));
  await assert.rejects(inspectConnectEnvelope('identity',{envelope:identity([['large',Array(256).fill(null)]])},pub),/node-limit/);
});
