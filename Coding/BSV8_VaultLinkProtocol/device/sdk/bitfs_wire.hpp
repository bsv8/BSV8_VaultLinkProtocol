#pragma once
#include "feepool.hpp"
#include "channel.hpp"
namespace vaultlink {
inline const std::vector<Value> &bitfs_array(const Value &v,size_t size=SIZE_MAX){require(v.kind==Value::Array&&(size==SIZE_MAX||v.array.size()==size),"invalid-document");return v.array;}
inline Bytes bitfs_bytes(const Value &v,size_t size=SIZE_MAX,bool nonzero=false){auto b=v.binary();require((size==SIZE_MAX||b.size()==size)&&(!nonzero||std::any_of(b.begin(),b.end(),[](uint8_t c){return c!=0;})),"invalid-document");return b;}
inline Value bitfs_child(const Value &v,size_t size=SIZE_MAX){auto parsed=decode(v.binary(),16384,256);bitfs_array(parsed,size);return parsed;}
inline Bytes bitfs_pub(const Value &v){auto b=bitfs_bytes(v,33);pool_public_key(b);return b;}
inline Value bitfs_authorization(const Bytes &raw){
  auto value=decode(raw,16384,256);auto &v=bitfs_array(value,6);bitfs_bytes(v[0],32,true);bitfs_bytes(v[1],32,true);
  auto sequence=v[2].integer();require(sequence>=1&&sequence<=4294967294ULL,"invalid-sequence");(void)v[3].integer();
  auto hashes=bitfs_child(v[4]);require(!hashes.array.empty()&&hashes.array.size()<=64,"invalid-document");std::vector<Bytes> seen;
  for(const auto &h:hashes.array){auto b=bitfs_bytes(h,32);require(std::find(seen.begin(),seen.end(),b)==seen.end(),"duplicate-hash");seen.push_back(b);}
  auto deadline=v[5].integer();require(deadline>0&&deadline<=0x7fffffffffffffffULL,"invalid-time");return value;
}
inline Bytes bitfs_wire_digest(uint64_t kind,const Bytes &raw){return sha256(encode(Value::list({Value("bitfs/wire-signature"),Value(uint64_t(1)),Value(kind),Value(raw)}),32768));}
struct BitfsWireReview {uint64_t kind=0;Bytes digest;std::vector<std::pair<std::string,std::string>> facts;};
inline BitfsWireReview inspect_bitfs_wire(const Value &body,const Bytes &own){
  body.fields({"kind","document"});BitfsWireReview r;r.kind=body.at("kind").integer();
  require(r.kind==1||r.kind==5||r.kind==6||r.kind==8||r.kind==9||r.kind==10||r.kind==11,"unsupported-kind");
  auto raw=body.at("document").binary();auto parsed=decode(raw,16384,256);auto &v=bitfs_array(parsed);
  auto fact=[&](const std::string &name,const Value &value){r.facts.push_back({name,value.kind==Value::Binary?to_hex(value.binary()):value.kind==Value::Text?value.string():std::to_string(value.integer())});};
  if(r.kind==1){bitfs_array(parsed,8);bitfs_bytes(v[0],32);bitfs_pub(v[1]);(void)v[2].integer();(void)v[3].integer();
    auto size=v[4].integer(),expires=v[5].integer();require(size<=8192ULL*262144&&expires>0&&expires<=0x7fffffffffffffffULL,"invalid-document");
    if(size==0)require(v[0].binary()==sha256(Bytes{}),"invalid-document");
    auto arbiters=bitfs_child(v[6]);std::vector<Bytes> seen;for(const auto &a:arbiters.array){auto p=bitfs_pub(a);require(std::find(seen.begin(),seen.end(),p)==seen.end(),"duplicate-key");seen.push_back(p);}
    auto name=v[7].string();auto chars=json_utf16(name);require(!chars.empty()&&name!="."&&name!="..","invalid-filename");
    auto whitespace=[](uint16_t c){return c==32||c==0xa0||c==0x1680||(c>=0x2000&&c<=0x200a)||c==0x2028||c==0x2029||c==0x202f||c==0x205f||c==0x3000||c==0xfeff;};
    require(!whitespace(chars.front())&&!whitespace(chars.back()),"invalid-filename");for(auto c:chars)require(c!='/'&&c!='\\'&&c>31&&!(c>=127&&c<=159),"invalid-filename");
    fact("seedHash",v[0]);fact("peer",v[1]);fact("seedPrice",v[2]);fact("blockPrice",v[3]);fact("expiresAt",v[5]);
  }else if(r.kind==5){auto a=bitfs_authorization(raw);fact("quoteId",a.array[0]);fact("refundTxId",a.array[1]);fact("paymentSequence",a.array[2]);fact("cumulativePaid",a.array[3]);fact("expiresAt",a.array[5]);
  }else if(r.kind==6){bitfs_array(parsed,1);bitfs_bytes(v[0],32,true);fact("authorizationId",v[0]);
  }else if(r.kind==8){bitfs_array(parsed,5);auto amount=v[0].integer();require(amount>0,"invalid-document");auto keys=pool_roles(bitfs_bytes(v[1],105),"bitfs");require(keys[1]==own,"wrong-key");
    auto refund=parse_tx(v[2].binary());auto authorization=bitfs_authorization(v[3].binary());const auto &a=authorization.array;
    require(refund.inputs.size()==1&&refund.outputs.size()==3,"invalid-refund");const auto &input=refund.inputs[0];
    require(std::any_of(input.txid.begin(),input.txid.end(),[](uint8_t c){return c!=0;})&&input.vout==0&&input.sequence!=0xffffffff&&input.script.empty()&&a[2].integer()>input.sequence,"invalid-refund");
    uint64_t total=0;for(size_t i=0;i<3;++i){auto &output=refund.outputs[i];require(output.script==own_script(keys[i])&&(i==0||output.amount==0),"invalid-refund");total=add(total,output.amount);}
    require(total<=amount&&a[3].integer()<=total,"invalid-amount");channel_verify(keys[0],bitfs_wire_digest(5,v[3].binary()),v[4].binary());
    fact("lockedAmount",v[0]);fact("peer",Value(keys[0]));fact("quoteId",a[0]);fact("paymentSequence",a[2]);fact("cumulativePaid",a[3]);
  }else if(r.kind==9){bitfs_array(parsed,3);bitfs_bytes(v[0],32);require(v[1].integer()>0,"invalid-amount");auto signature=v[2].binary();require(!signature.empty()&&signature.size()<=256,"invalid-signature");fact("claimId",v[0]);fact("arbiterAmount",v[1]);
  }else if(r.kind==10){bitfs_array(parsed,2);bitfs_bytes(v[0],32,true);bitfs_bytes(v[1],32,true);fact("claimId",v[0]);
  }else{bitfs_array(parsed,3);bitfs_bytes(v[0],32,true);auto branch=v[1].integer();if(branch==0)require(v[2].integer()<=2,"invalid-document");else{require(branch==1,"invalid-document");bitfs_bytes(v[2],32);}fact("requestId",v[0]);fact("result",v[1]);}
  r.digest=bitfs_wire_digest(r.kind,raw);return r;
}
inline PoolReview inspect_bitfs_authorization(const Bytes &raw,const std::vector<Bytes> &previous,const Bytes &own,const Value &auth){
  auth.fields({"document","refundTemplate"});auto document=auth.at("document").binary(),refund=auth.at("refundTemplate").binary();
  auto wire=inspect_bitfs_wire(obj({{"kind",Value(uint64_t(5))},{"document",document}}),own);auto authorization=bitfs_authorization(document);const auto &v=authorization.array;
  auto review=inspect_pool(raw,previous,own,"bitfs","state","payer"),baseline=inspect_pool(refund,previous,own,"bitfs","state","payer");
  auto target=parse_tx(raw),original=parse_tx(refund);
  require(review.paid==v[3].integer()&&target.inputs[0].sequence==v[2].integer()&&target.outputs.size()==3&&target.outputs[2].amount==0&&target.locktime==0&&baseline.paid==0&&original.inputs[0].sequence<target.inputs[0].sequence&&sha256d(refund)==v[1].binary(),"invalid-authorization");
  review.review.digests={wire.digest};return review;
}
inline PoolReview inspect_bitfs_opening(const Bytes &raw,const Bytes &request,const Bytes &own){
 auto decoded=decode(request,16384,256);const auto &v=bitfs_array(decoded,8);
 require(v[0].integer()==1&&v[1].integer()==2&&v[2].binary()==raw,"invalid-opening");
 std::vector<Bytes> keys{bitfs_pub(v[3]),bitfs_pub(v[4]),bitfs_pub(v[5])};Bytes script{0x52};
 for(const auto &k:keys){script.push_back(33);script.insert(script.end(),k.begin(),k.end());}script.insert(script.end(),{0x53,0xae});pool_roles(script,"bitfs");
 const uint64_t maximum=9007199254740991ULL,rate=v[6].integer();require(keys[1]==own&&rate<=maximum,"wrong-key");
 auto tx=parse_tx(raw);require(tx.version==1&&tx.inputs.size()==1&&tx.inputs[0].vout==0&&tx.inputs[0].script.empty()&&tx.inputs[0].sequence==2&&tx.outputs.size()==3,"invalid-opening");
 for(size_t i=0;i<3;i++)require(tx.outputs[i].script==own_script(keys[i])&&(i==0||tx.outputs[i].amount==0),"invalid-opening");
 uint64_t size=raw.size()+149;require(rate==0||size<=(maximum-999)/rate,"invalid-amount");
 PoolReview r;r.review.fee=(size*rate+999)/1000;r.locked=add(tx.outputs[0].amount,r.review.fee);require(r.locked>0&&r.locked<=maximum,"invalid-amount");
 auto digest=forkid_sighash(tx,0,Output{r.locked,script});auto signature=v[7].binary();require(!signature.empty()&&signature.back()==0x41,"invalid-signature");signature.pop_back();channel_verify(keys[0],digest,signature);
 r.review.digests.push_back(digest);r.outputs=tx.outputs;return r;
}

}
