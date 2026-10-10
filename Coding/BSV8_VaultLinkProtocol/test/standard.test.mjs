import test from 'node:test';
import assert from 'node:assert/strict';
import {DeviceIdentityKey,inspectStandard,standardUnlockKind,p2pkhScript,serializeTransaction,sha256d,concat} from '../dist/index.js';
test('standard single-key script interpretation binds complete prevouts, excludes own outputs, and rejects arbitrary input scripts',async()=>{
 const key=new DeviceIdentityKey(Uint8Array.from([...new Uint8Array(31),1])),peer=new DeviceIdentityKey(Uint8Array.from([...new Uint8Array(31),2]));
 const pub=key.publicKey(),own=concat(Uint8Array.of(3,97,98,99,0x75,33),pub,Uint8Array.of(0xac));
 assert.equal(standardUnlockKind(own,pub),'p2pk');
 assert.equal(standardUnlockKind(concat(Uint8Array.of(33),pub,Uint8Array.of(0xac,0x51)),pub),null);
 const prior=serializeTransaction({version:1,inputs:[{txid:new Uint8Array(32),vout:0,script:Uint8Array.of(1),sequence:0xffffffff}],outputs:[{satoshis:1000n,script:own}],locktime:0});
 const tx={version:1,inputs:[{txid:await sha256d(prior),vout:0,script:new Uint8Array(),sequence:0xfffffffe}],outputs:[{satoshis:100n,script:concat(Uint8Array.of(33),peer.publicKey(),Uint8Array.of(0xac))},{satoshis:890n,script:p2pkhScript(pub)}],locktime:0};
 const r=await inspectStandard(serializeTransaction(tx),[prior],pub);
 assert.equal(r.amount,100n);assert.equal(r.change,890n);assert.equal(r.fee,10n);assert.deepEqual(r.unlockKinds,['p2pk']);
 const changed=prior.slice();changed[changed.length-1]^=1;
 await assert.rejects(inspectStandard(serializeTransaction(tx),[changed],pub),/invalid-prevout/);
 await assert.rejects(inspectStandard(serializeTransaction(tx),[prior],peer.publicKey()),/unsupported-input/);
 key.close();peer.close();
});
