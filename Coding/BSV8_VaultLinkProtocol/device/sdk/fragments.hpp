#pragma once
#include "crypto.hpp"
namespace vaultlink {
inline std::vector<Bytes> message_fragments(const Value &value) {
  auto raw=encode(value,32768);WipeBytes clean{raw};if(raw.size()<=896)return {raw};
  auto hash=sha256(raw);std::vector<Bytes> result;
  for(size_t offset=0;offset<raw.size();offset+=640){auto end=std::min(raw.size(),offset+640);
    result.push_back(encode(obj({{"fragment",obj({{"total",uint64_t(raw.size())},{"offset",uint64_t(offset)},
      {"hash",hash},{"data",Bytes(raw.begin()+offset,raw.begin()+end)}})}})));}
  return result;
}
class FragmentAssembler {
  Bytes raw, hash;size_t offset=0;uint64_t started=0;unsigned type=0;
 public:
  bool accept(const Bytes &plain,uint64_t now,Value &value,unsigned frame_type=0) {
    auto v=decode(plain);bool wrapped=false;
    if(v.kind==Value::Map)for(const auto &field:v.map)if(field.first=="fragment")wrapped=true;
    if(!wrapped){value=std::move(v);return true;}
    v.fields({"fragment"});const auto &f=v.at("fragment");f.fields({"total","offset","hash","data"});
    auto total=f.at("total").integer(), at=f.at("offset").integer();const auto &data=f.at("data").binary();auto digest=f.at("hash").binary(32);
    require(total>896&&total<=32768&&!data.empty()&&data.size()<=640,"invalid-fragment");
    if(raw.empty()){require(at==0,"fragment-order");raw.resize(total);hash=digest;started=now;type=frame_type;}
    require(type==frame_type&&now-started<=8000&&total==raw.size()&&at==offset&&digest==hash&&data.size()<=raw.size()-offset&&
      (offset+data.size()==raw.size()||data.size()==640),"fragment-order");
    std::copy(data.begin(),data.end(),raw.begin()+offset);offset+=data.size();
    if(offset<raw.size())return false;
    require(sha256(raw)==hash,"fragment-hash");value=decode(raw,32768);close();return true;
  }
  void close(){wipe_bytes(raw);raw.clear();hash.clear();offset=0;started=0;}
  ~FragmentAssembler(){close();}
};
}
