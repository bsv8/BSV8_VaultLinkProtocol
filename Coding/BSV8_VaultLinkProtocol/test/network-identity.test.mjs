import test from 'node:test';
import assert from 'node:assert/strict';
import {DeviceIdentityKey,inspectNetworkIdentity,NetworkIdentitySigningOperation,unhex,hex,verifyChannelSignature} from '../dist/index.js';
test('restricted network identity matches independently captured libp2p payload and cannot sign a supplied digest',async()=>{
 const key=new DeviceIdentityKey(unhex('00'.repeat(31)+'01'));
 try{
  const base='126c69627032702d706565722d7265636f7264020301';
  const pub='0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798';
  const vectors=[['0','290a27002508021221'+pub],['1','2b0a27002508021221'+pub+'1001'],['128','2c0a27002508021221'+pub+'108001'],['18446744073709551615','340a27002508021221'+pub+'10ffffffffffffffffff01']];
  for(const [sequence,tail] of vectors){const review=await inspectNetworkIdentity('peer-record',{sequence},key.publicKey());assert.equal(hex(review.payload),base+tail);}
  const handler=new NetworkIdentitySigningOperation(key,'noise',async review=>{assert.equal(review.kind,'noise');return true;}),body={staticKey:new Uint8Array(32).fill(7)};
  const core=await handler.verify(body),signal=new AbortController().signal;assert.equal(await handler.authorize(core,signal),true);
  const result=await handler.execute(core,signal);verifyChannelSignature(result.signature,(await inspectNetworkIdentity('noise',core,key.publicKey())).digest,key.publicKey());
  for(const sequence of ['01','-1','18446744073709551616',''])await assert.rejects(inspectNetworkIdentity('peer-record',{sequence},key.publicKey()),/invalid-sequence/);
  await assert.rejects(handler.verify({...body,digest:new Uint8Array(32)}));
  await assert.rejects(key.signNetworkIdentity('noise',body,signal,async()=>false),/denied/);
  const cancel=new AbortController();await assert.rejects(key.signNetworkIdentity('noise',body,cancel.signal,async()=>{cancel.abort();return true;}),/revoked/);
 }finally{key.close();}
});
