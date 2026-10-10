import test from 'node:test';
import assert from 'node:assert/strict';
import {fragments,FragmentAssembler,decode,encode} from '../dist/index.js';
test('bounded authenticated-message fragments retain all bytes; reordered, changed and oversized objects fail',async()=>{
 const value={raw:new Uint8Array(12000).map((_,i)=>i%251)}, parts=await fragments(value);
 assert.ok(parts.length>1);assert.ok(parts.every(p=>p.length<=896));
 const a=new FragmentAssembler();let result;
 for(const p of parts)result=await a.accept(p);
 assert.deepEqual(result.raw,value.raw);
 await assert.rejects(new FragmentAssembler().accept(parts[1]),/fragment-order/);
 const b=new FragmentAssembler();await b.accept(parts[0]);await assert.rejects(b.accept(parts[0]),/fragment-order/);b.close();
 const typed=new FragmentAssembler();await typed.accept(parts[0],17);
 await assert.rejects(typed.accept(parts[1],18),/fragment-order/);typed.close();
 const altered=decode(parts.at(-1));altered.fragment.data[0]^=1;
 const c=new FragmentAssembler();for(const p of parts.slice(0,-1))await c.accept(p);
 await assert.rejects(c.accept(encode(altered)),/fragment-hash/);c.close();
 await assert.rejects(fragments({raw:new Uint8Array(32768)}),/message-too-large/);
});
