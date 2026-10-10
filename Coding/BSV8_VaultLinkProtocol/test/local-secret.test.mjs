import test from 'node:test';
import assert from 'node:assert/strict';
import {validateLocalScope,validateLocalSecret} from '../dist/index.js';
test('local-secret wire boundary preserves the v3 envelope and rejects malformed scopes and oversized material',()=>{
 const sealed={version:3,keySource:'active-key-hkdf-v1',saltHex:'00'.repeat(16),nonceHex:'01'.repeat(12),ciphertextHex:'02'.repeat(528)};
 assert.deepEqual(validateLocalSecret(sealed),sealed);
 assert.equal(validateLocalScope('storage.bucket-password'),'storage.bucket-password');
 assert.equal(validateLocalScope('数据.秘密'),'数据.秘密');
 for(const scope of ['', 'a'.repeat(96), 'bad\0scope','bad\x7fscope','\ud800'])assert.throws(()=>validateLocalScope(scope),/invalid-scope/);
 for(const changed of [{...sealed,version:2},{...sealed,keySource:'other'},{...sealed,extra:1},{...sealed,saltHex:'00'},{...sealed,nonceHex:'gg'.repeat(12)},{...sealed,ciphertextHex:'00'.repeat(529)},{...sealed,ciphertextHex:'00'.repeat(16)}])assert.throws(()=>validateLocalSecret(changed));
});
