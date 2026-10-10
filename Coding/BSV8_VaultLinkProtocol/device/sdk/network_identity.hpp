#pragma once
#include "crypto.hpp"
namespace vaultlink {
struct NetworkIdentityReview { Bytes payload,digest;std::string sequence; };
inline void network_varint(Bytes &out,uint64_t n){do{uint8_t b=n&127;n>>=7;out.push_back(b|(n?128:0));}while(n);}
// No host digest, PeerId or addresses: all signed bytes are derived here.
inline NetworkIdentityReview inspect_network_identity(const std::string &kind,const Value &body,const Bytes &own_pub){
  require(own_pub.size()==33,"wrong-key");NetworkIdentityReview r;
  if(kind=="noise"){
    body.fields({"staticKey"});auto key=body.at("staticKey").binary(32);
    std::string prefix="noise-libp2p-static-key:";r.payload.assign(prefix.begin(),prefix.end());r.payload.insert(r.payload.end(),key.begin(),key.end());
  }else if(kind=="peer-record"){
    body.fields({"sequence"});r.sequence=body.at("sequence").string();
    require(!r.sequence.empty()&&r.sequence.size()<=20&&(r.sequence.size()==1||r.sequence[0]!='0'),"invalid-sequence");
    uint64_t seq=0;for(char c:r.sequence){require(c>='0'&&c<='9',"invalid-sequence");uint64_t digit=c-'0';require(seq<=(UINT64_MAX-digit)/10,"invalid-sequence");seq=seq*10+digit;}
    Bytes record{10,39,0,37,8,2,18,33};record.insert(record.end(),own_pub.begin(),own_pub.end());if(seq){record.push_back(16);network_varint(record,seq);}
    std::string domain="libp2p-peer-record";network_varint(r.payload,domain.size());r.payload.insert(r.payload.end(),domain.begin(),domain.end());
    r.payload.insert(r.payload.end(),{2,3,1});network_varint(r.payload,record.size());r.payload.insert(r.payload.end(),record.begin(),record.end());
  }else require(false,"unsupported");
  r.digest=sha256(r.payload);return r;
}
}
