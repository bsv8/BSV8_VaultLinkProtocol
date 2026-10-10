import test from 'node:test';
import assert from 'node:assert/strict';
import {DeviceIdentityKey,encode,inspectBitfsWire,bitfsWireDigest,verifyChannelSignature,BitfsWireOperation,sha256} from '../dist/index.js';
const makeKey=n=>new DeviceIdentityKey(Uint8Array.from([...new Uint8Array(31),n]));
const id=n=>new Uint8Array(32).fill(n);
test('BitFS exact authentication document uses the existing wire domain and physical decision',async()=>{
 const key=makeKey(1),buyer=makeKey(2);
 try{
  const doc=encode([await sha256(Uint8Array.of(1,2,3)),buyer.publicKey(),100n,200n,3n,2000n,encode([]),'seed.bin'],16384),body={kind:1,document:doc};
  let approvals=0;const handler=new BitfsWireOperation(key,async review=>{assert.equal(review.kind,1);assert.ok(review.facts.some(f=>f.name==='seedPrice'&&f.value==='100'));approvals++;return true;});
  const core=await handler.verify(body);assert.equal(await handler.authorize(core,new AbortController().signal),true);
  const result=await handler.execute(core,new AbortController().signal);verifyChannelSignature(result.signature,await bitfsWireDigest(1,doc),key.publicKey());assert.equal(approvals,1);
 }finally{key.close();buyer.close();}
});
test('BitFS authorization is fixed-schema and rejects duplicate hashes, zero IDs and transaction signature kinds',async()=>{
 const key=makeKey(1);
 try{
  const doc=hashes=>encode([id(1),id(2),1n,300n,encode(hashes),2000n],16384);
  assert.ok((await inspectBitfsWire({kind:5,document:doc([id(3)])},key.publicKey())).facts.some(f=>f.name==='cumulativePaid'&&f.value==='300'));
  await assert.rejects(inspectBitfsWire({kind:5,document:doc([id(3),id(3)])},key.publicKey()),/duplicate-hash/);
  await assert.rejects(inspectBitfsWire({kind:5,document:encode([id(0),id(2),1n,300n,encode([id(3)]),2000n],16384)},key.publicKey()),/invalid-document/);
  for(const kind of [0,2,3,4,7,12,13,255])await assert.rejects(inspectBitfsWire({kind,document:doc([id(3)])},key.publicKey()),/unsupported-kind/);
  await assert.rejects(inspectBitfsWire({kind:5,document:await bitfsWireDigest(5,doc([id(3)]))},key.publicKey()));
  await assert.rejects(key.signBitfsWire({kind:6,document:encode([id(3)])},new AbortController().signal,async()=>false),/denied/);
  const abort=new AbortController();await assert.rejects(key.signBitfsWire({kind:6,document:encode([id(3)])},abort.signal,async()=>{abort.abort();return true;}),/revoked/);
 }finally{key.close();}
});
