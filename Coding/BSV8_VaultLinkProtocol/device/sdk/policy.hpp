#pragma once
#include "cbor.hpp"
#include "signing_channel.hpp"
#include <functional>
namespace vaultlink {
// 存储适配必须原子提交；SDK 从不把失败当成功。真实 ESP32 使用 NVS blob +
// commit。
struct Store {
  virtual Bytes load() = 0;
  virtual void save(const Bytes &) = 0;
  virtual ~Store() = default;
};
struct Channel {
  std::string id, owner;
  uint64_t single, total, revision;
  bool enabled;
  // 插件只有单笔额度；App 才有连接会话累计额度。
  std::string kind = "app";
  std::string payment_type = "p2pkh";
};
struct PoolInspection {std::string id="";Bytes binding{};uint64_t previous_paid=0,paid=0;};
struct PoolState {std::string id;Bytes binding;uint64_t paid=0,archived_paid=0;};
struct AppSession {
  std::string id, owner;
  uint64_t limit, used = 0, revision = 1;
  bool active = true;
  uint64_t archived_used=0;
};
struct Payment {
  std::string id, channel, session;
  uint64_t amount, config_revision, session_revision;
  Bytes hash;
  std::string state;
  PoolInspection pool{};
};
struct Budget {
  bool single = false, total = false, disabled = false;
  uint64_t used = 0, limit = 0;
  bool prompt() const { return single || total || disabled; }
};
class Policy {
  Store &store;
  std::string key;
  std::string bsv_network;
  bool alive = true;
  std::vector<Channel> channels;
  std::vector<AppSession> sessions;
  std::vector<Payment> payments;
  std::vector<PoolState> pools;
  bool signing_enabled=false;
  std::vector<Value> signing_channels;
  bool archived=false;
  std::vector<Value> archived_payments,archived_sessions;
  std::function<Bytes(const Bytes&)> digest;
  Bytes id_hash(const std::string& id)const{require(bool(digest),"archive-hash-adapter-required");return digest(Bytes(id.begin(),id.end()));}
  bool archived_id(const std::vector<Value>& entries,const std::string& id)const{
    if(entries.empty())return false;auto hash=id_hash(id);return std::any_of(entries.begin(),entries.end(),[&](const Value& e){return e.at("idHash").binary(32)==hash;});
  }
  Value session_value(const AppSession& s,bool v3)const{
    auto value=obj({{"id",s.id},{"owner",s.owner},{"limit",s.limit},{"used",s.used},{"revision",s.revision},{"active",s.active}});
    if(v3)value.map.push_back({"archivedUsed",Value(s.archived_used)});return value;
  }
  Value channel_value(const Channel& c)const{return obj({{"id",c.id},{"owner",c.owner},{"kind",c.kind},{"network",bsv_network},{"paymentType",c.payment_type},{"singleLimit",c.single},{"defaultSessionLimit",c.total},{"revision",c.revision},{"enabled",c.enabled}});}
  Value pool_value(const PoolState& p)const{auto value=obj({{"id",p.id},{"binding",p.binding},{"paid",p.paid}});if(archived)value.map.emplace_back("archivedPaid",Value(p.archived_paid));return value;}
  Value payment_value(const Payment& p)const{
    return obj({{"id",p.id},{"channelId",p.channel},{"sessionId",p.session.empty()?Value():Value(p.session)},
      {"amount",p.amount},{"configRevision",p.config_revision},{"sessionRevision",p.session_revision},{"commitment",p.hash},
      {"state",p.state},{"pool",p.pool.id.empty()?Value():obj({{"id",p.pool.id},{"binding",p.pool.binding},{"previousPaid",p.pool.previous_paid},{"paid",p.pool.paid}})}});
  }
  bool compact(bool payment_records,bool session_records){
    require(alive&&bool(digest),"archive-hash-adapter-required");
    auto old_sessions=sessions;auto old_payments=payments;auto old_pools=pools;const auto old_ap_size=archived_payments.size(),old_as_size=archived_sessions.size();auto old_archived=archived;bool changed=false;
    try{
      if(payment_records)for(size_t i=0;i<payments.size();){const auto p=payments[i];
        if((p.state!="signed"&&p.state!="released")||archived_payments.size()>=512){++i;continue;}
        archived_payments.push_back(obj({{"idHash",id_hash(p.id)},{"recordHash",digest(encode(payment_value(p),65536))}}));
        if(p.state=="signed"){
          if(!p.session.empty()){auto& s=session(p.session);s.archived_used=add(s.archived_used,p.amount);}
          if(!p.pool.id.empty())for(auto& pool:pools)if(pool.id==p.pool.id)pool.archived_paid=add(pool.archived_paid,p.amount);
        }
        payments.erase(payments.begin()+i);changed=archived=true;
      }
      if(session_records)for(size_t i=0;i<sessions.size();){const auto s=sessions[i];
        if(s.active||std::any_of(payments.begin(),payments.end(),[&](const Payment& p){return p.session==s.id;})||archived_sessions.size()>=512){++i;continue;}
        auto record=session_value(s,true);
        archived_sessions.push_back(obj({{"idHash",id_hash(s.id)},{"recordHash",digest(encode(record,65536))},{"record",record}}));
        sessions.erase(sessions.begin()+i);changed=archived=true;
      }
      if(changed)encoded_bank();
    }catch(...){sessions=std::move(old_sessions);payments=std::move(old_payments);pools=std::move(old_pools);archived_payments.resize(old_ap_size);archived_sessions.resize(old_as_size);archived=old_archived;throw;}
    return changed;
  }
  static void identifier(const std::string &s) {
    require(!s.empty() && s.size() <= 96 &&
                std::all_of(s.begin(), s.end(),
                            [](char c) {
                              return (c >= 'A' && c <= 'Z') ||
                                     (c >= 'a' && c <= 'z') ||
                                     (c >= '0' && c <= '9') || c == '.' ||
                                     c == '_' || c == ':' || c == '/' ||
                                     c == '-';
                            }),
            "invalid-id");
  }
  Channel &channel(const std::string &id) {
    for (auto &c : channels)
      if (c.id == id)
        return c;
    throw Failure("invalid-channel");
  }
  AppSession &session(const std::string &id) {
    for (auto &s : sessions)
      if (s.id == id)
        return s;
    throw Failure("invalid-session");
  }
  Payment &payment(const std::string &id) {
    for (auto &p : payments)
      if (p.id == id)
        return p;
    throw Failure("invalid-request");
  }
  void persist() {
    try {
      store.save(encoded_bank());
    } catch (...) {
      alive = false;
      throw;
    }
  }

public:
  Policy(Store &s, std::string public_key,std::function<Bytes(const Bytes&)> hash = {}, std::string network = "main")
      : store(s), key(std::move(public_key)),bsv_network(std::move(network)),digest(std::move(hash)) {
    auto bytes = store.load();
    if (bytes.empty())
      return;
    auto state = decode(bytes, 65536);
    auto version=state.at("version").integer();
    if(version==1)state.fields({"version", "key", "channels", "sessions", "pending"});
    else if(version==4)state.fields({"version", "key", "channels", "sessions", "pending", "pools","archive","network","signing"});
    else if(version==3)state.fields({"version", "key", "channels", "sessions", "pending", "pools","archive"});
    else state.fields({"version", "key", "channels", "sessions", "pending", "pools"});
    require((version==1 || version==2 || version==3 || version==4) &&
                state.at("key").string() == key,
            "corrupt-state");
    if(version==4){
      require(state.at("network").string()==bsv_network,"network-identity-mismatch");
      const auto& rows=state.at("signing");require(rows.kind==Value::Array&&rows.array.size()<=32,"corrupt-state");
      for(const auto& c:rows.array){inspect_signing_channel(c);for(const auto& old:signing_channels)require(old.at("id").string()!=c.at("id").string(),"corrupt-state");signing_channels.push_back(c);}signing_enabled=true;
    }
    const auto &cs = state.at("channels"), &ss = state.at("sessions"),
               &ps = state.at("pending");
    require(cs.kind == Value::Array && ss.kind == Value::Array &&
                ps.kind == Value::Array && cs.array.size() <= 32 &&
                ss.array.size() <= 16 && ps.array.size() <= 256,
            "corrupt-state");
    if(version>=3){archived=true;auto& a=state.at("archive");a.fields({"payments","sessions"});
      // Consume the decoded archive once; cloning it while the whole input
      // tree is live can exhaust the device heap during restart recovery.
      archived_payments=std::move(a.at("payments").array);archived_sessions=std::move(a.at("sessions").array);
      require(a.at("payments").kind==Value::Array&&a.at("sessions").kind==Value::Array&&archived_payments.size()<=512&&archived_sessions.size()<=512,"corrupt-state");
      require(bool(digest)||(archived_payments.empty()&&archived_sessions.empty()),"archive-hash-adapter-required");
      for(const auto* entries:{&archived_payments,&archived_sessions})for(size_t i=0;i<entries->size();++i){const auto& e=entries->at(i);if(entries==&archived_sessions)e.fields({"idHash","recordHash","record"});else e.fields({"idHash","recordHash"});e.at("idHash").binary(32);e.at("recordHash").binary(32);
        for(size_t j=0;j<i;++j)require(entries->at(j).at("idHash").binary(32)!=e.at("idHash").binary(32),"corrupt-state");}
    }
    for(const auto& e:archived_sessions){const auto& r=e.at("record");r.fields({"id","owner","limit","used","revision","active","archivedUsed"});
      identifier(r.at("id").string());identifier(r.at("owner").string());r.at("limit").integer();
      auto rev=r.at("revision").integer();require(rev>0&&rev<0xffffffff&&!r.at("active").flag()&&r.at("archivedUsed").integer()==r.at("used").integer()&&e.at("idHash").binary(32)==id_hash(r.at("id").string())&&e.at("recordHash").binary(32)==digest(encode(r,65536)),"corrupt-state");
    }
    for (const auto &v : cs.array) {
      v.fields({"id", "owner", "singleLimit", "defaultSessionLimit", "revision",
                "enabled", "kind", "network", "paymentType"});
      require((v.at("kind").string() == "app" ||
               v.at("kind").string() == "plugin") &&
                  v.at("network").string() == bsv_network &&
                  (v.at("paymentType").string() == "p2pkh" || v.at("paymentType").string()=="feepool.connect" || v.at("paymentType").string()=="feepool.bitfs" || v.at("paymentType").string()=="bsv.standard" || v.at("paymentType").string()=="feepool.bitfs.cosigner" || v.at("paymentType").string()=="feepool.connect.cosigner"),
              "unsupported");
      channels.push_back({v.at("id").string(), v.at("owner").string(),
                          v.at("singleLimit").integer(),
                          v.at("defaultSessionLimit").integer(),
                          v.at("revision").integer(), v.at("enabled").flag(),
                          v.at("kind").string(),v.at("paymentType").string()});
    }
    for (const auto &v : ss.array) {
      if(version>=3)v.fields({"id", "owner", "limit", "used", "revision", "active","archivedUsed"});
      else v.fields({"id", "owner", "limit", "used", "revision", "active"});
      sessions.push_back({v.at("id").string(), v.at("owner").string(),
                          v.at("limit").integer(), v.at("used").integer(),
                          v.at("revision").integer(), v.at("active").flag(),version>=3?v.at("archivedUsed").integer():0});
    }
    for (const auto &v : ps.array) {
      if(version==1)v.fields({"id", "channelId", "sessionId", "amount", "configRevision", "sessionRevision", "commitment", "state"});
      else v.fields({"id", "channelId", "sessionId", "amount", "configRevision", "sessionRevision", "commitment", "state", "pool"});
      auto status = v.at("state").string();
      payments.push_back({v.at("id").string(), v.at("channelId").string(),
                          v.at("sessionId").kind == Value::Null ? "" : v.at("sessionId").string(), v.at("amount").integer(),
                          v.at("configRevision").integer(),
                          v.at("sessionRevision").integer(),
                          v.at("commitment").binary(32),
                          status == "reserved" ? "unknown" : status});
      if(version>=2 && v.at("pool").kind!=Value::Null){const auto &p=v.at("pool");p.fields({"id","binding","previousPaid","paid"});
        payments.back().pool={p.at("id").string(),p.at("binding").binary(32),p.at("previousPaid").integer(),p.at("paid").integer()};}
    }
    if(version>=2){const auto &pool_list=state.at("pools");require(pool_list.kind==Value::Array && pool_list.array.size()<=256,"corrupt-state");
      for(const auto &v:pool_list.array){if(version>=3)v.fields({"id","binding","paid","archivedPaid"});else v.fields({"id","binding","paid"});pools.push_back({v.at("id").string(),v.at("binding").binary(32),v.at("paid").integer(),version>=3?v.at("archivedPaid").integer():0});}}
    for (size_t i = 0; i < channels.size(); ++i) {
      auto &c = channels[i];
      identifier(c.id);
      identifier(c.owner);
      require(c.revision >= 1 && c.revision < UINT32_MAX, "corrupt-state");
      for (size_t j = 0; j < i; ++j)
        require(channels[j].id != c.id, "corrupt-state");
    }
    for (size_t i = 0; i < sessions.size(); ++i) {
      auto &s = sessions[i];
      identifier(s.id);
      identifier(s.owner);
      require(s.revision >= 1 && s.revision < UINT32_MAX, "corrupt-state");
      for (size_t j = 0; j < i; ++j)
        require(sessions[j].id != s.id, "corrupt-state");
      require(!archived_id(archived_sessions,s.id),"corrupt-state");
      uint64_t used = s.archived_used;
      for (const auto &p : payments)
        if (p.session == s.id && p.state != "released")
          used = add(used, p.amount);
      require(used == s.used, "corrupt-state");
    }
    for (size_t i = 0; i < payments.size(); ++i) {
      auto &p = payments[i];
      identifier(p.id);require(!archived_id(archived_payments,p.id),"corrupt-state");
      auto &c = channel(p.channel);
      require(p.config_revision > 0 &&
                  p.config_revision <= c.revision &&
                  (p.state == "signed" || p.state == "unknown" ||
                   p.state == "released"),
              "corrupt-state");
      if (c.kind == "app") {
        auto &s = session(p.session);
        require(p.session_revision > 0 && p.session_revision <= s.revision &&
                    c.owner == s.owner, "corrupt-state");
      } else {
        require(p.session.empty() && p.session_revision == 0, "corrupt-state");
      }
      for (size_t j = 0; j < i; ++j)
        require(payments[j].id != p.id, "corrupt-state");
    }
    for(size_t i=0;i<pools.size();++i){const auto &pool=pools[i];identifier(pool.id);uint64_t total=pool.archived_paid;
      for(size_t j=0;j<i;++j)require(pools[j].id!=pool.id,"corrupt-state");
      for(const auto &p:payments)if(p.pool.id==pool.id){require(p.pool.binding==pool.binding && p.pool.paid>=p.pool.previous_paid && p.amount==p.pool.paid-p.pool.previous_paid,"corrupt-state");
        if(p.state!="released")total=add(total,p.amount);}
      require(total==pool.paid,"corrupt-state");}
    for(const auto &p:payments)if(!p.pool.id.empty())require(std::any_of(pools.begin(),pools.end(),[&](const PoolState &x){return x.id==p.pool.id;}),"corrupt-state");
    // Recovery has copied and validated every field. Release the decoded tree
    // and input bank before encoding the recovered ledger; ESP32 cannot hold
    // both complete trees plus the raw bank during the atomic commit.
    state = Value();
    wipe_bytes(bytes); Bytes().swap(bytes);
    persist();
  }
  // Serialize one bounded record at a time. Canonical field order is identical
  // to encode(snapshot()), without allocating a complete duplicate ledger tree.
  Bytes encoded_bank()const{
    require(alive,"policy-unavailable");Bytes bytes;size_t size=0;
    const auto emit=[&](bool counting){
      const auto add=[&](size_t n){require(size<=65536&&n<=65536-size,"message-too-large");size+=n;};
      const auto head=[&](uint8_t major,size_t n){if(counting)add(cbor_size(Value(uint64_t(n)),65536));else cbor_head(bytes,major,n);};
      const auto value=[&](const Value& v,unsigned depth){if(counting)add(cbor_size(v,65536,depth));else cbor_write(v,bytes,65536,depth);};
      const auto key_field=[&](const char* name){value(Value(name),1);};
      head(5,signing_enabled?9:archived?7:6);
      key_field("key");value(Value(key),1);
      key_field("pools");head(4,pools.size());for(const auto& p:pools)value(pool_value(p),2);
      if(archived){key_field("archive");head(5,2);value(Value("payments"),2);head(4,archived_payments.size());for(const auto& p:archived_payments)value(p,3);value(Value("sessions"),2);head(4,archived_sessions.size());for(const auto& s:archived_sessions)value(s,3);}
      if(signing_enabled){key_field("network");value(Value(bsv_network),1);}
      key_field("pending");head(4,payments.size());for(const auto& p:payments)value(payment_value(p),2);
      if(signing_enabled){key_field("signing");head(4,signing_channels.size());for(const auto& c:signing_channels)value(c,2);}
      key_field("version");value(Value(uint64_t(signing_enabled?4:archived?3:2)),1);
      key_field("channels");head(4,channels.size());for(const auto& c:channels)value(channel_value(c),2);
      key_field("sessions");head(4,sessions.size());for(const auto& s:sessions)value(session_value(s,archived),2);
    };
    emit(true);bytes.reserve(size);emit(false);require(bytes.size()==size,"invalid-bank-size");return bytes;
  }
  Value channels_view()const{require(alive,"policy-unavailable");std::vector<Value> out;out.reserve(channels.size());for(const auto& c:channels)out.push_back(channel_value(c));return Value::list(std::move(out));}
  Value channel_view(const std::string& id)const{require(alive,"policy-unavailable");for(const auto& c:channels)if(c.id==id)return channel_value(c);throw Failure("invalid-channel");}
  Value session_view(const std::string& id)const{require(alive,"policy-unavailable");for(const auto& s:sessions)if(s.id==id)return session_value(s,archived);for(const auto& e:archived_sessions)if(e.at("record").at("id").string()==id)return e.at("record");throw Failure("invalid-session");}
  Value snapshot() const {
    require(alive, "policy-unavailable");
    std::vector<Value> cs, ss, ps;
    cs.reserve(channels.size()); ss.reserve(sessions.size()); ps.reserve(payments.size());
    for (const auto &c : channels)
      cs.push_back(obj({{"id", c.id},
                        {"owner", c.owner},
                        {"kind", c.kind},
                        {"network", bsv_network},
                        {"paymentType", c.payment_type},
                        {"singleLimit", c.single},
                        {"defaultSessionLimit", c.total},
                        {"revision", c.revision},
                        {"enabled", c.enabled}}));
    for(const auto& s:sessions)ss.push_back(session_value(s,archived));
    for(const auto& p:payments)ps.push_back(payment_value(p));
    std::vector<Value> pool_values;pool_values.reserve(pools.size());for(const auto& p:pools){auto value=obj({{"id",p.id},{"binding",p.binding},{"paid",p.paid}});if(archived)value.map.push_back({"archivedPaid",Value(p.archived_paid)});pool_values.push_back(std::move(value));}
    // An initializer_list copies its const elements. Build and move the large
    // arrays directly so a snapshot never duplicates the entire CBOR ledger.
    Value result; result.kind=Value::Map; result.map.reserve(signing_enabled?9:archived?7:6);
    result.map.emplace_back("version",Value(uint64_t(signing_enabled?4:archived?3:2)));
    result.map.emplace_back("key",Value(key));
    result.map.emplace_back("channels",Value::list(std::move(cs)));
    result.map.emplace_back("sessions",Value::list(std::move(ss)));
    result.map.emplace_back("pending",Value::list(std::move(ps)));
    result.map.emplace_back("pools",Value::list(std::move(pool_values)));
    if(signing_enabled){result.map.emplace_back("network",Value(bsv_network));result.map.emplace_back("signing",Value::list(signing_channels));}
    if(archived){Value archive;archive.kind=Value::Map;archive.map.reserve(2);archive.map.emplace_back("payments",Value::list(archived_payments));archive.map.emplace_back("sessions",Value::list(archived_sessions));result.map.emplace_back("archive",std::move(archive));}return result;
  }
  Value signing_view() const {require(alive,"policy-unavailable");return Value::list(signing_channels);}
  Value signing_channel(const std::string& id,const std::string& operation="") const {
    require(alive,"policy-unavailable");for(const auto& c:signing_channels)if(c.at("id").string()==id){require(operation.empty()||c.at("operation").string()==operation,"channel-conflict");return c;}throw Failure("channel-required");
  }
  // 只由首次注册的真实设备确认调用。建议和修订号不覆盖现有策略。
  void register_signing(const Value& rows,bool confirmed){
    require(alive&&rows.kind==Value::Array&&!rows.array.empty()&&rows.array.size()<=32,"invalid-signing-channel");
    for(size_t i=0;i<rows.array.size();++i)for(size_t j=0;j<i;++j)require(rows.array[i].at("id").string()!=rows.array[j].at("id").string(),"invalid-signing-channel");
    auto next=signing_channels;
    for(const auto& c:rows.array){inspect_signing_channel(c);auto it=std::find_if(next.begin(),next.end(),[&](const Value& v){return v.at("id").string()==c.at("id").string();});
      if(it!=next.end()){require(same_signing_registration(*it,c),"channel-conflict");continue;}
      require(confirmed&&c.at("revision").integer()==1,"confirmation-required");require(next.size()<32,"capacity");next.push_back(c);
    }
    if(next.size()==signing_channels.size())return;
    signing_channels=std::move(next);signing_enabled=archived=true;persist();
  }
  // 不提供 USB 修改入口：只有本机设置菜单持有这个能力。
  void configure_signing(const std::string& id,const std::string& mode,uint64_t expected){
    auto current=signing_channel(id);require(current.at("revision").integer()==expected&&expected<0xfffffffe,"stale-config");
    current.at("mode")=Value(mode);current.at("revision")=Value(expected+1);inspect_signing_channel(current);
    for(auto& c:signing_channels)if(c.at("id").string()==id)c=current;persist();
  }
  void configure(const Channel &c, bool confirmed) {
    require(alive, "policy-unavailable");
    identifier(c.id);
    identifier(c.owner);
    require(c.kind == "app" || c.kind == "plugin", "invalid-owner");
    require(c.payment_type=="p2pkh"||c.payment_type=="feepool.connect"||c.payment_type=="feepool.bitfs"||c.payment_type=="bsv.standard"||c.payment_type=="feepool.bitfs.cosigner"||c.payment_type=="feepool.connect.cosigner","unsupported");
    require(c.revision > 0 && c.revision < UINT32_MAX, "invalid-revision");
    // 默认会话总额是 App owner 的设置，不可因新建第二个渠道产生冲突或重置。
    for(const auto &peer:channels)if(c.kind=="app"&&peer.kind=="app"&&peer.owner==c.owner&&peer.id!=c.id&&peer.total!=c.total){
      require(peer.revision<UINT32_MAX-1,"invalid-revision");require(confirmed||c.total<=peer.total,"confirmation-required");
    }
    auto it = std::find_if(channels.begin(), channels.end(),
                           [&](const Channel &x) { return x.id == c.id; });
    if (it == channels.end()) {
      require(c.revision == 1 && confirmed && channels.size() < 32,
              "confirmation-required");
      channels.push_back(c);
    } else {
      require(it->owner == c.owner && it->kind == c.kind && it->payment_type==c.payment_type && c.revision == it->revision + 1,
              "stale-config");
      require(confirmed || (!(!it->enabled && c.enabled) &&
                            c.single <= it->single && c.total <= it->total),
              "confirmation-required");
      *it = c;
    }
    for(auto &peer:channels)if(c.kind=="app"&&peer.kind=="app"&&peer.owner==c.owner&&peer.id!=c.id&&peer.total!=c.total){peer.total=c.total;++peer.revision;}
    persist();
  }
  void start(const std::string &id, const std::string &owner, bool confirmed) {
    require(alive && confirmed, "confirmation-required");
    identifier(id);
    identifier(owner);
    require(!archived_id(archived_sessions,id),"session-reuse");
    for(const auto& s:sessions)require(s.id!=id,"session-reuse");
    if(sessions.size()>=16&&digest&&compact(true,true))persist();
    require(sessions.size() < 16, "capacity");
    for (const auto &s : sessions)
      require(s.id != id, "session-reuse");
    bool found = false;
    uint64_t limit = 0;
    for (const auto &c : channels)
      if (c.owner == owner && c.kind == "app" && c.enabled) {
        if (found)
          require(limit == c.total, "session-limit-conflict");
        found = true;
        limit = c.total;
      }
    require(found, "unknown-owner");
    sessions.push_back({id, owner, limit});
    persist();
  }
  void fresh(const std::string &id) {
    require(alive, "policy-unavailable");
    identifier(id);
    require(!archived_id(archived_payments,id),"request-reuse");
    for (const auto &p : payments)
      require(p.id != id, "request-reuse");
  }
  PoolState pool_state(const std::string &id) const {
    identifier(id);for(const auto &p:pools)if(p.id==id)return p;return {id,{},0};
  }
  PoolInspection inspect_pool_state(const std::string &id,const Bytes &binding,uint64_t paid) const {
    auto old=pool_state(id);require(binding.size()==32 && (old.binding.empty()||old.binding==binding),"pool-conflict");
    require(paid>=old.paid,"payment-rollback");return {id,binding,old.paid,paid};
  }
  void check_pool(const PoolInspection &pool,uint64_t amount) const {
    if(pool.id.empty())return;
    identifier(pool.id);require(pool.binding.size()==32,"invalid-pool");
    auto old=pool_state(pool.id);require(old.binding.empty()||old.binding==pool.binding,"pool-conflict");
    require(old.paid==pool.previous_paid,"stale-pool");
    require(pool.paid>=pool.previous_paid && amount==pool.paid-pool.previous_paid,"invalid-pool-delta");
    for(const auto &p:payments)require(p.state!="reserved"||p.pool.id!=pool.id,"busy");
  }
  Budget quote(const std::string &channel_id, const std::string &session_id,
               const std::string &owner, uint64_t amount) {
    require(alive, "policy-unavailable");
    auto &c = channel(channel_id);
    require(c.owner == owner, "invalid-channel");
    if (c.kind == "plugin") {
      require(session_id.empty(), "invalid-session");
      return {amount > c.single, false, !c.enabled, 0, 0};
    }
    auto &s = session(session_id);
    require(c.owner == owner && s.owner == owner && s.active,
            "invalid-session");
    return {amount > c.single, amount > 0 && add(s.used, amount) > s.limit, !c.enabled,
            s.used, s.limit};
  }
  void reserve(const std::string &id, const std::string &channel_id,
               const std::string &session_id, const std::string &owner,
               uint64_t amount, const Bytes &hash, bool approve,
               uint64_t raised = 0, const PoolInspection &pool = {}) {
    identifier(id);
    require(hash.size() == 32 && std::any_of(hash.begin(), hash.end(),
                                             [](uint8_t c) { return c != 0; }),
            "invalid-commitment");
    require(!archived_id(archived_payments,id),"request-reuse");
    for (const auto &p : payments)
      require(p.id != id, "request-reuse");
    if(payments.size()>=64&&digest&&compact(true,true))persist();
    require(payments.size() < 256, "capacity");
    check_pool(pool,amount);
    if(!pool.id.empty())require(!pool_state(pool.id).binding.empty()||pools.size()<256,"capacity");
    auto q = quote(channel_id, session_id, owner, amount);
    require(!q.prompt() || approve, "confirmation-required");
    auto &c = channel(channel_id);
    if (c.kind == "plugin") {
      require(raised == 0, "invalid-limit");
      payments.push_back({id, channel_id, "", amount, c.revision,
                          0, hash, "reserved",pool});
      update_pool(pool);
      persist();
      return;
    }
    auto &s = session(session_id);
    if (raised) {
      require(approve && q.total && raised >= s.limit &&
                  raised >= add(s.used, amount) && s.revision < UINT32_MAX - 1,
              "invalid-limit");
      s.limit = raised;
      ++s.revision;
    }
    s.used = add(s.used, amount);
    payments.push_back({id, channel_id, session_id, amount, c.revision,
                        s.revision, hash, "reserved",pool});
    update_pool(pool);
    persist();
  }
  void executable(const std::string &id) {
    require(alive, "policy-unavailable");
    auto &p = payment(id);
    auto &c = channel(p.channel);
    if (c.kind == "plugin") {
      require(p.state == "reserved" && c.revision == p.config_revision,
              "revoked");
      return;
    }
    auto &s = session(p.session);
    require(p.state == "reserved" && s.active &&
                c.revision == p.config_revision &&
                s.revision == p.session_revision,
            "revoked");
  }
  void signed_payment(const std::string &id) {
    executable(id);
    payment(id).state = "signed";
    persist();
  }
  void release(const std::string &id) {
    require(alive, "policy-unavailable");
    auto &p = payment(id);
    require(p.state == "reserved", "result-unknown");
    if(!p.pool.id.empty())for(auto &pool:pools)if(pool.id==p.pool.id){require(pool.paid==p.pool.paid,"corrupt-state");pool.paid=p.pool.previous_paid;}
    if (!p.session.empty()) {
      auto &s = session(p.session);
      require(s.used >= p.amount, "corrupt-state");
      s.used -= p.amount;
    }
    p.state = "released";
    persist();
  }
  // App 会话与 USB 连接独立。关闭保留账本和 tombstone，不能复活或清零 used。
  void close_session(const std::string &id) {
    require(alive, "policy-unavailable");
    identifier(id);
    auto &s = session(id);
    if (!s.active) return;
    require(s.revision < 0xffffffffffffffffULL, "revision-exhausted");
    s.active = false;
    ++s.revision;
    persist();
  }
  void close_sessions() {
    require(alive, "policy-unavailable");
    for (auto &s : sessions)
      s.active = false;
    persist();
  }
private:
  void update_pool(const PoolInspection &inspection) {
    if(inspection.id.empty())return;
    for(auto &p:pools)if(p.id==inspection.id){p.paid=inspection.paid;return;}
    pools.push_back({inspection.id,inspection.binding,inspection.paid});
  }
};
} // namespace vaultlink
