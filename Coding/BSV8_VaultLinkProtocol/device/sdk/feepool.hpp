#pragma once
#include "bsv.hpp"
namespace vaultlink {
// 使用 mbedTLS 域运算验证压缩 secp256k1 公钥；不接受仅长度正确的假公钥。
inline void pool_public_key(const Bytes &key) {
  require(key.size()==33 && (key[0]==2 || key[0]==3), "invalid-key");
  Group group(MBEDTLS_ECP_DP_SECP256K1); Mpi x, rhs, temp, exponent, y;
  check(mbedtls_mpi_read_binary(&x.v,key.data()+1,32));
  require(mbedtls_mpi_cmp_mpi(&x.v,&group.v.P)<0,"invalid-key");
  check(mbedtls_mpi_mul_mpi(&temp.v,&x.v,&x.v));
  check(mbedtls_mpi_mod_mpi(&rhs.v,&temp.v,&group.v.P));
  check(mbedtls_mpi_mul_mpi(&temp.v,&rhs.v,&x.v));
  check(mbedtls_mpi_add_int(&temp.v,&temp.v,7));
  check(mbedtls_mpi_mod_mpi(&rhs.v,&temp.v,&group.v.P));
  check(mbedtls_mpi_add_int(&exponent.v,&group.v.P,1));
  check(mbedtls_mpi_shift_r(&exponent.v,2));
  check(mbedtls_mpi_exp_mod(&y.v,&rhs.v,&exponent.v,&group.v.P,nullptr));
  check(mbedtls_mpi_mul_mpi(&temp.v,&y.v,&y.v));
  check(mbedtls_mpi_mod_mpi(&temp.v,&temp.v,&group.v.P));
  require(mbedtls_mpi_cmp_mpi(&temp.v,&rhs.v)==0 &&
          !(key[0]==3 && mbedtls_mpi_cmp_int(&y.v,0)==0),"invalid-key");
}
inline std::vector<Bytes> pool_roles(const Bytes &script, const std::string &family) {
  require(family=="connect"||family=="bitfs","unsupported");
  size_t count=family=="connect"?2:3;
  require(script.size()==3+34*count && script[0]==0x52 &&
          script[script.size()-2]==0x50+count && script.back()==0xae,"unsupported-script");
  std::vector<Bytes> keys;
  for(size_t i=0;i<count;++i) {
    require(script[1+34*i]==33,"unsupported-script");
    Bytes key(script.begin()+2+34*i,script.begin()+35+34*i);pool_public_key(key);
    require(std::find(keys.begin(),keys.end(),key)==keys.end(),"duplicate-key");keys.push_back(key);
  }
  return keys;
}
inline bool pool_proof(const Bytes &s) {
  if(s.size()<4||s[0]!=0||s[1]!=0x6a)return false;
  unsigned op=s[2];
  if(op>0 && op<76)return s.size()==3+op;
  if(op==76)return s[3]>=76 && s.size()==4+size_t(s[3]);
  if(op==77 && s.size()>=5){size_t n=s[3]+256*size_t(s[4]);return n>255 && s.size()==5+n;}
  return false;
}
struct PoolReview {
  Review review;
  uint64_t paid=0, locked=0;
  std::string pool;
  Bytes binding;
  std::vector<Output> outputs;
};
inline PoolReview inspect_pool(const Bytes &raw,const std::vector<Bytes> &previous,const Bytes &public_key,
                              const std::string &family,const std::string &stage,const std::string &role="payer") {
  require((family=="connect"||family=="bitfs") && (stage=="fund"||stage=="state"),"unsupported");
  require((role=="payer"||role=="cosigner") && (stage!="fund"||role=="payer"),"unsupported-role");
  auto tx=parse_tx(raw,640);require(tx.inputs.size()<=4 && previous.size()==tx.inputs.size(),"invalid-prevout");
  auto own=own_script(public_key);std::vector<Output> prevouts;std::vector<std::string> seen;
  uint64_t input_sum=0,output_sum=0;
  for(size_t i=0;i<tx.inputs.size();++i) {
    const auto &in=tx.inputs[i];require(in.script.empty(),"already-signed");
    auto ref=to_hex(in.txid)+":"+std::to_string(in.vout);
    require(std::find(seen.begin(),seen.end(),ref)==seen.end(),"duplicate-input");seen.push_back(ref);
    auto prev=parse_tx(previous[i]);require(sha256d(previous[i])==in.txid && in.vout<prev.outputs.size(),"invalid-prevout");
    prevouts.push_back(prev.outputs[in.vout]);input_sum=add(input_sum,prevouts.back().amount);
  }
  for(const auto &out:tx.outputs)output_sum=add(output_sum,out.amount);
  require(input_sum>=output_sum,"negative-fee");PoolReview r;r.review.fee=input_sum-output_sum;r.outputs=tx.outputs;
  if(stage=="fund") {
    require((tx.outputs.size()==1 || tx.outputs.size()==2) && (tx.outputs.size()==1 || tx.outputs[1].script==own) &&
      std::all_of(prevouts.begin(),prevouts.end(),[&](const Output &o){return o.script==own;}),"invalid-funding");
    auto keys=pool_roles(tx.outputs[0].script,family);require(keys[family=="connect"?1:0]==public_key,"wrong-key");
    r.locked=tx.outputs[0].amount;require(r.locked>0,"invalid-amount");r.review.change=tx.outputs.size()==2?tx.outputs[1].amount:0;
  } else {
    require(tx.inputs.size()==1 && tx.inputs[0].vout==0,"invalid-pool-input");
    auto keys=pool_roles(prevouts[0].script,family);auto payer=keys[family=="connect"?1:0];require(role=="payer"?payer==public_key:(payer!=public_key && std::find(keys.begin(),keys.end(),public_key)!=keys.end()),"wrong-key");
    require(tx.outputs.size()==keys.size() || (family=="bitfs" && tx.outputs.size()==4),"invalid-pool-output");
    for(size_t i=0;i<keys.size();++i){const auto &o=tx.outputs[i];require(o.script==own_script(keys[i]),"invalid-pool-output");
      if(o.script==own)r.review.change=add(r.review.change,o.amount);else r.paid=add(r.paid,o.amount);}
    if(tx.outputs.size()==4)require(tx.outputs[3].amount==0 && pool_proof(tx.outputs[3].script),"invalid-payment-proof");
    if(role=="payer"){r.pool=to_hex(tx.inputs[0].txid)+":0";r.binding=sha256d(prevouts[0].script);}
  }
  for(size_t i=0;i<prevouts.size();++i)r.review.digests.push_back(forkid_sighash(tx,i,prevouts[i]));
  return r;
}
} // namespace vaultlink
