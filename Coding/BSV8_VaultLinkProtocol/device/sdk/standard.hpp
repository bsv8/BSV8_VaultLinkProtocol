#pragma once
#include "bsv.hpp"
namespace vaultlink {
// 1=P2PKH, 2=push/drop 数据后裸公钥单签。其它输入绝不回退盲签。
inline unsigned standard_unlock(const Bytes &script,const Bytes &pub) {
  if(script==own_script(pub))return 1;
  size_t at=0;
  while(at<script.size()) {
    size_t n=script[at++];
    if(n==76){if(at>=script.size())return 0;n=script[at++];if(n<76)return 0;}
    else if(n==77){if(at+2>script.size())return 0;n=script[at]+256*size_t(script[at+1]);at+=2;if(n<256)return 0;}
    else if(n<1||n>75)return 0;
    if(n>=script.size()-at)return 0;
    Bytes data(script.begin()+at,script.begin()+at+n);at+=n;
    auto op=script[at++];
    if(op==0xac)return at==script.size()&&data==pub?2:0;
    if(op!=0x75)return 0;
  }
  return 0;
}
inline Review inspect_standard(const Bytes &raw,const std::vector<Bytes> &previous,const Bytes &pub) {
  auto tx=parse_tx(raw);require(tx.inputs.size()<=10&&tx.outputs.size()<=32&&previous.size()==tx.inputs.size(),"unsupported");
  Review r;uint64_t total_in=0,total_out=0;std::vector<std::string> seen;
  for(size_t i=0;i<tx.inputs.size();++i){const auto &in=tx.inputs[i];require(in.script.empty(),"already-signed");
    auto ref=to_hex(in.txid)+":"+std::to_string(in.vout);require(std::find(seen.begin(),seen.end(),ref)==seen.end(),"duplicate-input");seen.push_back(ref);
    auto prev=parse_tx(previous[i]);require(sha256d(previous[i])==in.txid&&in.vout<prev.outputs.size(),"invalid-prevout");
    const auto &out=prev.outputs[in.vout];require(standard_unlock(out.script,pub)!=0,"unsupported-input");
    total_in=add(total_in,out.amount);r.digests.push_back(forkid_sighash(tx,i,out));
  }
  for(const auto &out:tx.outputs){total_out=add(total_out,out.amount);
    if(standard_unlock(out.script,pub))r.change=add(r.change,out.amount);else r.amount=add(r.amount,out.amount);}
  require(total_out<=total_in,"negative-fee");r.fee=total_in-total_out;return r;
}
}
