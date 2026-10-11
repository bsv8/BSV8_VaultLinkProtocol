#pragma once
#include "policy.hpp"
namespace vaultlink {
inline bool migration_uuid(const std::string& s) {
  if (s.size()!=36) return false;
  for(size_t i=0;i<s.size();++i) {
    if(i==8||i==13||i==18||i==23) {if(s[i]!='-')return false;}
    else if(!((s[i]>='0'&&s[i]<='9')||(s[i]>='a'&&s[i]<='f')))return false;
  }
  return true;
}
inline Value inspect_device_migration(const Value& r) {
  r.fields({"version","id","walletGeneration","publicKey","sourceHash","policyHash","direction","phase","targetHash"});
  const auto &direction=r.at("direction").string(), &phase=r.at("phase").string();
  require(r.at("version").integer()==1 && migration_uuid(r.at("id").string())
    && migration_uuid(r.at("walletGeneration").string())
    && (direction=="to-hardware"||direction=="to-software"),"corrupt-migration");
  const auto &pub=r.at("publicKey").binary(33);
  require(pub[0]==2||pub[0]==3,"corrupt-migration");
  r.at("sourceHash").binary(32);r.at("policyHash").binary(32);
  require(phase=="staged"||phase=="device-committed"||phase=="host-committed"
    ||phase=="erasing"||phase=="erased"||phase=="complete","corrupt-migration");
  const bool target=phase!="staged"&&phase!="device-committed";
  if(target)r.at("targetHash").binary(32);else require(r.at("targetHash").kind==Value::Null,"corrupt-migration");
  require(direction!="to-hardware"||(phase!="erasing"&&phase!="erased"),"corrupt-migration");
  return r;
}
/** Store must distinguish missing from corrupt and atomically commit. This
 * class stores PUBLIC progress only; it never wraps/exports a key, accepts a PIN
 * or grants permission. The private controller owns those physical actions. */
class MigrationJournal {
  Store& store;
  Value record;
  bool alive=true;
  void persist(Value next) {
    require(alive,"storage-failed");
    next=inspect_device_migration(next);
    try {store.save(encode(next,1024));record=std::move(next);}
    catch (...) {alive=false;throw;}
  }
 public:
  explicit MigrationJournal(Store& s):store(s) {
    auto raw=store.load();
    if(!raw.empty())record=inspect_device_migration(decode(raw,1024));
  }
  Value status() const {require(alive,"storage-failed");return record;}
  bool pending() const {require(alive,"storage-failed");return record.kind!=Value::Null&&record.at("phase").string()!="complete";}
  void begin(const Value& proposed) {
    require(alive,"storage-failed");auto next=inspect_device_migration(proposed);
    require(next.at("phase").string()=="staged","migration-conflict");
    if(record.kind!=Value::Null) {
      if(record.at("id").string()==next.at("id").string()) {
        auto initial=record;
        for(auto &field:initial.map) {
          if(field.first=="phase")field.second=Value("staged");
          if(field.first=="targetHash")field.second=Value();
        }
        require(encode(initial,1024)==encode(next,1024),"migration-conflict");return;
      }
      // Export does not remove the device key. An unacknowledged export may
      // be superseded by a fresh physically authorized request; records that
      // bind a committed target or an import must never be replaced this way.
      const bool abandoned_export=record.at("direction").string()=="to-software"
        &&next.at("direction").string()=="to-software"
        &&record.at("targetHash").kind==Value::Null
        &&record.at("publicKey").binary(33)==next.at("publicKey").binary(33);
      require(!pending()||abandoned_export,"migration-conflict");
    }
    persist(std::move(next));
  }
  void advance(const std::string& id,const std::string& phase,const Value& targetHash=Value()) {
    require(alive&&record.kind!=Value::Null&&record.at("id").string()==id,"migration-conflict");
    const auto old=record.at("phase").string(),direction=record.at("direction").string();
    const bool target=phase!="staged"&&phase!="device-committed";
    if(target)targetHash.binary(32);else require(targetHash.kind==Value::Null,"migration-conflict");
    if(old==phase) {require(encode(record.at("targetHash"))==encode(targetHash),"migration-conflict");return;}
    bool legal=(old=="staged"&&phase=="device-committed")||(old=="device-committed"&&phase=="host-committed")
      ||(old=="host-committed"&&phase=="complete")
      ||(direction=="to-software"&&(((old=="host-committed"||old=="complete")&&phase=="erasing")
        ||(old=="erasing"&&phase=="erased")||(old=="erased"&&phase=="complete")));
    require(legal,"migration-conflict");
    if(old!="staged"&&old!="device-committed")require(encode(record.at("targetHash"))==encode(targetHash),"migration-conflict");
    auto next=record;for(auto &field:next.map) {
      if(field.first=="phase")field.second=Value(phase);
      if(field.first=="targetHash")field.second=targetHash;
    }
    persist(std::move(next));
  }
};
} // namespace vaultlink
