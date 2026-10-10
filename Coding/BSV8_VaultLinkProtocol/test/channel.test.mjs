import test from 'node:test';
import assert from 'node:assert/strict';
import {DeviceIdentityKey,canonicalJson,parseCanonicalJson,channelSigningObject,base64Url,hex,ChannelOperation,inspectChannel} from '../dist/index.js';
const makeKey=n=>new DeviceIdentityKey(Uint8Array.from([...new Uint8Array(31),n]));
const signal=()=>new AbortController().signal;
function unsigned(sender,recipient){return {channel:'bsv8.inbox.'+hex(recipient.publicKey()),from_public_key:hex(sender.publicKey()),protocol:'bsv8.message.v1',message_id:base64Url(new Uint8Array(32).fill(4)),issued_at_ms:1000,expires_at_ms:2000,body:{type:'deliver',content:{text:'実際の消息',amount:1e-7}}};}
test('Channel full semantic signer and authenticated inbox round trip use actual identity keys',async()=>{
 const a=makeKey(1),b=makeKey(2);
 try{
  const message=unsigned(a,b),logical=channelSigningObject(message,'private');let approvals=0;
  const handler=new ChannelOperation(a,'private',async review=>{assert.equal(review.peer,hex(b.publicKey()));approvals++;return true;});
  const core=await handler.verify({message:logical});assert.equal(await handler.authorize(core,signal()),true);
  const {signature}=await handler.execute(core,signal());const signed=canonicalJson({...message,signature:base64Url(signature)});
  const envelope=await a.sealChannel(signed,signal(),async()=>true);
  const decrypted=await b.openChannel(envelope,signal(),async review=>{assert.equal(review.peer,hex(a.publicKey()));assert.equal(review.protocol,'bsv8.message.v1');approvals++;return true;});
  assert.deepEqual(decrypted,signed);assert.equal(approvals,2);decrypted.fill(0);
 }finally{a.close();b.close();}
});
test('Channel rejects changed signature, recipient, ciphertext and unregistered protocol',async()=>{
 const a=makeKey(1),b=makeKey(2),other=makeKey(3);
 try{
  const message=unsigned(a,b),logical=channelSigningObject(message,'private');
  const signature=await a.signChannel('private',logical,signal(),async()=>true),signed=canonicalJson({...message,signature:base64Url(signature)});
  await assert.rejects(a.sealChannel(canonicalJson({...message,body:{type:'deliver',content:'changed'},signature:base64Url(signature)}),signal(),async()=>true),/invalid-signature/);
  const envelope=await a.sealChannel(signed,signal(),async()=>true);
  await assert.rejects(other.openChannel(envelope,signal(),async()=>true),/invalid-envelope/);
  const value=parseCanonicalJson(envelope);value.ciphertext=(value.ciphertext[0]==='A'?'B':'A')+value.ciphertext.slice(1);
  await assert.rejects(b.openChannel(canonicalJson(value),signal(),async()=>true),/open-failed/);
  await assert.rejects(inspectChannel('private',channelSigningObject({...message,protocol:'unknown'},'private'),a.publicKey()),/unsupported-protocol/);
 }finally{a.close();b.close();other.close();}
});
test('Channel denial, cancellation and key lock prevent releasing signatures or plaintext',async()=>{
 const a=makeKey(1),b=makeKey(2);
 try{
  const message=unsigned(a,b),logical=channelSigningObject(message,'private');
  await assert.rejects(a.signChannel('private',logical,signal(),async()=>false),/denied/);
  const signature=await a.signChannel('private',logical,signal(),async()=>true);
  const envelope=await a.sealChannel(canonicalJson({...message,signature:base64Url(signature)}),signal(),async()=>true);
  await assert.rejects(b.openChannel(envelope,signal(),async()=>false),/denied/);
  const abort=new AbortController();await assert.rejects(b.openChannel(envelope,abort.signal,async()=>{abort.abort();return true;}),/revoked/);
  await assert.rejects(b.openChannel(envelope,signal(),async()=>{b.close();return true;}),/locked/);
 }finally{a.close();b.close();}
});
