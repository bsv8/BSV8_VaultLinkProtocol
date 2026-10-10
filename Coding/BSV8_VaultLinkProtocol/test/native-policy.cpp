#include "../device/sdk/policy.hpp"
#include <filesystem>
#include <fstream>
#include <cassert>
#include <iterator>
using namespace vaultlink;
// 真正的磁盘原子替换，验证 C++ 策略持久格式；不代表 ESP32 Flash 验收。
struct FileStore final : Store {
  std::filesystem::path path;
  explicit FileStore(std::filesystem::path p) : path(std::move(p)) {}
  Bytes load() override {
    if (!std::filesystem::exists(path)) return {};
    std::ifstream in(path, std::ios::binary);
    require(bool(in), "read-failed");
    return Bytes(std::istreambuf_iterator<char>(in), {});
  }
  void save(const Bytes &bytes) override {
    auto temp = path; temp += ".tmp";
    std::ofstream out(temp, std::ios::binary | std::ios::trunc);
    out.write(reinterpret_cast<const char *>(bytes.data()), bytes.size());
    out.close(); require(bool(out), "write-failed");
    std::filesystem::rename(temp, path);
  }
};
template<class F> void fails(F f, const char *code) {
  try { f(); } catch (const Failure &e) { assert(std::string(e.what()) == code); return; }
  assert(false);
}
int main(int argc, char **argv) {
  assert(argc == 2);
  FileStore store(argv[1]);
  Bytes commitment(32, 1);
  {
    Policy p(store, "key");
    p.configure({"plugin-channel", "plugin", 400, 0, 1, true, "plugin"}, true);
    assert(!p.quote("plugin-channel", "", "plugin", 400).prompt());
    for (const auto &id : {"plugin-one", "plugin-two"}) {
      p.reserve(id, "plugin-channel", "", "plugin", 400, commitment, false);
      p.signed_payment(id);
    }
    p.reserve("self", "plugin-channel", "", "plugin", 0, commitment, false);
    p.signed_payment("self");
    assert(p.quote("plugin-channel", "", "plugin", 401).single);
    fails([&] { p.reserve("plugin-denied", "plugin-channel", "", "plugin", 401, commitment, false); }, "confirmation-required");
    p.reserve("plugin-three", "plugin-channel", "", "plugin", 401, commitment, true);
    p.signed_payment("plugin-three");
    p.configure({"pool-channel", "plugin", 100, 0, 1, true, "plugin", "feepool.connect"},true);
    auto pool=p.inspect_pool_state("pool",Bytes(32,7),100);
    p.reserve("pool-one","pool-channel","","plugin",100,commitment,false,0,pool);
    fails([&]{auto next=p.inspect_pool_state("pool",Bytes(32,7),101);p.reserve("pool-busy","pool-channel","","plugin",1,commitment,false,0,next);},"busy");
    p.signed_payment("pool-one");
    auto next=p.inspect_pool_state("pool",Bytes(32,7),150);
    p.reserve("pool-two","pool-channel","","plugin",50,commitment,false,0,next);p.signed_payment("pool-two");
    auto close=p.inspect_pool_state("pool",Bytes(32,7),150);
    p.reserve("pool-close","pool-channel","","plugin",0,commitment,false,0,close);p.signed_payment("pool-close");
    auto cancelled=p.inspect_pool_state("pool",Bytes(32,7),151);
    p.reserve("pool-cancelled","pool-channel","","plugin",1,commitment,false,0,cancelled);p.release("pool-cancelled");
    assert(p.pool_state("pool").paid==150);
    fails([&]{p.inspect_pool_state("pool",Bytes(32,7),149);},"payment-rollback");
    assert(p.snapshot().at("sessions").array.empty());
    assert(p.snapshot().at("pending").array[0].at("sessionId").kind == Value::Null);
    p.configure({"channel-a", "app", 400, 500, 1, true}, true);
    p.configure({"channel-b", "app", 400, 500, 1, true}, true);
    p.start("connection", "app", true);
    p.reserve("app-one", "channel-a", "connection", "app", 300, commitment, false);
    p.signed_payment("app-one");
    assert(!p.quote("channel-b", "connection", "app", 200).prompt());
    p.reserve("app-two", "channel-b", "connection", "app", 200, commitment, false);
    p.signed_payment("app-two");
    assert(p.quote("channel-a", "connection", "app", 1).total);
    p.reserve("app-three", "channel-a", "connection", "app", 1, commitment, true);
    p.signed_payment("app-three");
    assert(p.quote("channel-b", "connection", "app", 1).total);
  }
  {
    Policy restored(store, "key");
    auto snapshot = restored.snapshot();
    assert(restored.inspect_pool_state("pool",Bytes(32,7),160).previous_paid==150);
    assert(snapshot.at("channels").array[0].at("kind").string() == "plugin");
    assert(snapshot.at("sessions").array[0].at("used").integer() == 501);
    assert(snapshot.at("sessions").array[0].at("limit").integer() == 500);
    assert(snapshot.at("sessions").array[0].at("active").flag());
    assert(restored.quote("channel-a", "connection", "app", 1).total);
    restored.close_session("connection"); restored.close_session("connection");
    auto closed = restored.snapshot().at("sessions").array[0];
    assert(!closed.at("active").flag() && closed.at("used").integer() == 501);
    fails([&] { restored.start("connection", "app", true); }, "session-reuse");
    assert(!restored.quote("plugin-channel", "", "plugin", 400).prompt());
    fails([&] { restored.fresh("plugin-one"); }, "request-reuse");
  }
  FileStore legacy(std::string(argv[1])+".legacy");
  {
    Policy original(legacy,"legacy-key");
    original.configure({"a","app",10,15,1,true},true);
    original.configure({"b","app",10,15,1,true},true);
    original.start("old-session","app",true);
    original.reserve("old-payment","a","old-session","app",10,commitment,false);original.signed_payment("old-payment");
    original.configure({"a","app",10,30,2,true},true);
    auto state=original.snapshot();assert(state.at("channels").array[1].at("defaultSessionLimit").integer()==30);
    assert(state.at("sessions").array[0].at("limit").integer()==15);
    for(auto &field:state.map)if(field.first=="version")field.second=Value(uint64_t(1));
    state.map.erase(std::remove_if(state.map.begin(),state.map.end(),[](const auto &field){return field.first=="pools";}),state.map.end());
    for(auto &field:state.map)if(field.first=="pending")for(auto &row:field.second.array)
      row.map.erase(std::remove_if(row.map.begin(),row.map.end(),[](const auto &entry){return entry.first=="pool";}),row.map.end());
    legacy.save(encode(state,65536));
  }
  Policy migrated(legacy,"legacy-key");auto state=migrated.snapshot();
  assert(state.at("version").integer()==2);assert(state.at("sessions").array[0].at("used").integer()==10);
  assert(state.at("pending").array[0].at("state").string()=="signed");
  assert(state.at("channels").array[1].at("defaultSessionLimit").integer()==30);

}
