import test from 'node:test';
import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import {mkdtemp,readdir,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {fileURLToPath} from 'node:url';
import {canonicalJson,parseCanonicalJson} from '../dist/index.js';
test('C++ JCS matches actual ECMAScript numbers, UTF16 ordering, escapes and bounded rejection',async()=>{
  const root=fileURLToPath(new URL('../',import.meta.url)),dir=await mkdtemp(join(tmpdir(),'vlp-jcs-'));
  try {
    const upstream=join(root,'device/third_party/double-conversion');
    const sources=(await readdir(upstream)).filter(name=>name.endsWith('.cc')).sort().map(name=>join(upstream,name));
    const exe=join(dir,'jcs');
    const compiled=spawnSync(process.env.CXX??'c++',['-std=c++17','-Wall','-Wextra','-Werror','-fsanitize=address,undefined',join(root,'device/jcs_test.cpp'),...sources,'-o',exe],{encoding:'utf8'});
    assert.equal(compiled.status,0,compiled.stderr);
    const values=[null,true,false,0,-0,1,-1,1e-7,1e-6,1e20,1e21,Number.MIN_VALUE,Number.MAX_VALUE,333333333.33333329,1.80113,
      { '😀':1,'\ue000':2,'a':'quote" backslash\\ / \b\f\n\r\t \u0000'},['日本語','中文','é','😀']];
    for(let i=1;i<80;i++)values.push((Math.sin(i)*1e19)/(10**(i%40)));
    const valid=values.map(value=>new TextDecoder().decode(canonicalJson(value)));
    const invalid=['{"z":1,"a":2}','{"a":1,"a":2}','{"a":1,}','[1,]',' 1','1 ','1.0','-0','1e+0','1E-7','9007199254740993','1e999','"\\ud800"','"\\udc00"','"\\u0061"','"\\/"','truefalse'];
    const results=spawnSync(exe,[],{input:[...valid,...invalid].join('\n')+'\n',encoding:'utf8'});
    assert.equal(results.status,0,results.stderr);
    const lines=results.stdout.trimEnd().split('\n');
    assert.deepEqual(lines.slice(0,valid.length),valid.map(line=>'ok:'+line));
    for(const line of lines.slice(valid.length))assert.match(line,/^error:/);
    for(const line of valid)assert.deepEqual(canonicalJson(parseCanonicalJson(new TextEncoder().encode(line))),new TextEncoder().encode(line));
    for(const line of invalid)assert.throws(()=>parseCanonicalJson(new TextEncoder().encode(line)));
  }finally{await rm(dir,{recursive:true,force:true});}
});
