#pragma once
#include "crypto.hpp"
namespace vaultlink {
struct ConnectReview {
  std::string request, audience, content_type;
  uint64_t issued=0,expires=0,content_length=0;
  std::vector<std::string> claims;
  Bytes digest,content_digest;
};
inline std::string connect_text(const Value &v,size_t minimum,size_t maximum) {
  const auto &s=v.string();require(s.size()>=minimum&&s.size()<=maximum,"invalid-envelope");return s;
}
// Only exact canonical Connect v1 envelopes, with the device's own subject.
inline ConnectReview inspect_connect(const std::string &kind,const Value &body,const Bytes &own_pub) {
  require(kind=="identity"||kind=="intent","unsupported");
  bool identity=kind=="identity";
  if(identity)body.fields({"envelope"});else body.fields({"envelope","content"});
  auto raw=body.at("envelope").binary();require(raw.size()<=8192,"invalid-envelope");
  auto e=decode(raw,8192,256);require(e.kind==Value::Array&&e.array.size()==(identity?8u:9u),"invalid-envelope");
  require(encode(e,8192)==raw&&e.array[0].integer()==1,"invalid-envelope");
  require(e.array[identity?6:8].binary(33)==own_pub,"wrong-key");
  ConnectReview r;
  r.request=connect_text(e.array[1],1,128);r.audience=connect_text(e.array[2],1,512);
  r.issued=e.array[3].integer();r.expires=e.array[4].integer();
  require(r.issued<=9007199254740991ULL&&r.expires<=9007199254740991ULL&&r.expires>r.issued,"invalid-envelope");
  connect_text(e.array[5],0,2048);r.digest=sha256(raw);
  if(identity) {
    const auto &claims=e.array[7];require(claims.kind==Value::Array&&claims.array.size()<=32,"invalid-envelope");
    std::string previous;bool first=true;
    for(const auto &pair:claims.array) {
      require(pair.kind==Value::Array&&pair.array.size()==2,"invalid-envelope");
      auto name=connect_text(pair.array[0],1,128);
      require(first||std::lexicographical_compare(previous.begin(),previous.end(),name.begin(),name.end(),
        [](char a,char b){return uint8_t(a)<uint8_t(b);}),"invalid-envelope");
      first=false;previous=name;r.claims.push_back(name);
    }
  }else {
    auto content=body.at("content").binary();require(content.size()<=16384,"invalid-envelope");
    r.content_type=connect_text(e.array[6],1,127);r.content_length=content.size();r.content_digest=sha256(content);
    require(e.array[7].binary(32)==r.content_digest,"invalid-content");
  }
  return r;
}
}
