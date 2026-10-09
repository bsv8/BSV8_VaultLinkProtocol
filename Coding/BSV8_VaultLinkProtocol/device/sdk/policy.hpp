#pragma once
#include "cbor.hpp"
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
};
struct AppSession {
  std::string id, owner;
  uint64_t limit, used = 0, revision = 1;
  bool active = true;
};
struct Payment {
  std::string id, channel, session;
  uint64_t amount, config_revision, session_revision;
  Bytes hash;
  std::string state;
};
struct Budget {
  bool single = false, total = false, disabled = false;
  uint64_t used = 0, limit = 0;
  bool prompt() const { return single || total || disabled; }
};
class Policy {
  Store &store;
  std::string key;
  bool alive = true;
  std::vector<Channel> channels;
  std::vector<AppSession> sessions;
  std::vector<Payment> payments;
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
      store.save(encode(snapshot(), 65536));
    } catch (...) {
      alive = false;
      throw;
    }
  }

public:
  Policy(Store &s, std::string public_key)
      : store(s), key(std::move(public_key)) {
    auto bytes = store.load();
    if (bytes.empty())
      return;
    auto state = decode(bytes, 65536);
    state.fields({"version", "key", "channels", "sessions", "pending"});
    require(state.at("version").integer() == 1 &&
                state.at("key").string() == key,
            "corrupt-state");
    const auto &cs = state.at("channels"), &ss = state.at("sessions"),
               &ps = state.at("pending");
    require(cs.kind == Value::Array && ss.kind == Value::Array &&
                ps.kind == Value::Array && cs.array.size() <= 32 &&
                ss.array.size() <= 16 && ps.array.size() <= 256,
            "corrupt-state");
    for (const auto &v : cs.array) {
      v.fields({"id", "owner", "singleLimit", "defaultSessionLimit", "revision",
                "enabled", "kind", "network", "paymentType"});
      require(v.at("kind").string() == "app" &&
                  v.at("network").string() == "main" &&
                  v.at("paymentType").string() == "p2pkh",
              "unsupported");
      channels.push_back({v.at("id").string(), v.at("owner").string(),
                          v.at("singleLimit").integer(),
                          v.at("defaultSessionLimit").integer(),
                          v.at("revision").integer(), v.at("enabled").flag()});
    }
    for (const auto &v : ss.array) {
      v.fields({"id", "owner", "limit", "used", "revision", "active"});
      sessions.push_back({v.at("id").string(), v.at("owner").string(),
                          v.at("limit").integer(), v.at("used").integer(),
                          v.at("revision").integer(), false});
    }
    for (const auto &v : ps.array) {
      v.fields({"id", "channelId", "sessionId", "amount", "configRevision",
                "sessionRevision", "commitment", "state"});
      auto status = v.at("state").string();
      payments.push_back({v.at("id").string(), v.at("channelId").string(),
                          v.at("sessionId").string(), v.at("amount").integer(),
                          v.at("configRevision").integer(),
                          v.at("sessionRevision").integer(),
                          v.at("commitment").binary(32),
                          status == "reserved" ? "unknown" : status});
    }
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
      uint64_t used = 0;
      for (const auto &p : payments)
        if (p.session == s.id && p.state != "released")
          used = add(used, p.amount);
      require(used == s.used, "corrupt-state");
    }
    for (size_t i = 0; i < payments.size(); ++i) {
      auto &p = payments[i];
      identifier(p.id);
      auto &c = channel(p.channel);
      auto &s = session(p.session);
      require(p.amount > 0 && p.config_revision > 0 &&
                  p.config_revision <= c.revision && p.session_revision > 0 &&
                  p.session_revision <= s.revision && c.owner == s.owner &&
                  (p.state == "signed" || p.state == "unknown" ||
                   p.state == "released"),
              "corrupt-state");
      for (size_t j = 0; j < i; ++j)
        require(payments[j].id != p.id, "corrupt-state");
    }
    persist();
  }
  Value snapshot() const {
    require(alive, "policy-unavailable");
    std::vector<Value> cs, ss, ps;
    for (const auto &c : channels)
      cs.push_back(obj({{"id", c.id},
                        {"owner", c.owner},
                        {"kind", "app"},
                        {"network", "main"},
                        {"paymentType", "p2pkh"},
                        {"singleLimit", c.single},
                        {"defaultSessionLimit", c.total},
                        {"revision", c.revision},
                        {"enabled", c.enabled}}));
    for (const auto &s : sessions)
      ss.push_back(obj({{"id", s.id},
                        {"owner", s.owner},
                        {"limit", s.limit},
                        {"used", s.used},
                        {"revision", s.revision},
                        {"active", s.active}}));
    for (const auto &p : payments)
      ps.push_back(obj({{"id", p.id},
                        {"channelId", p.channel},
                        {"sessionId", p.session},
                        {"amount", p.amount},
                        {"configRevision", p.config_revision},
                        {"sessionRevision", p.session_revision},
                        {"commitment", p.hash},
                        {"state", p.state}}));
    return obj({{"version", uint64_t(1)},
                {"key", key},
                {"channels", Value::list(cs)},
                {"sessions", Value::list(ss)},
                {"pending", Value::list(ps)}});
  }
  void configure(const Channel &c, bool confirmed) {
    require(alive, "policy-unavailable");
    identifier(c.id);
    identifier(c.owner);
    require(c.revision > 0 && c.revision < UINT32_MAX, "invalid-revision");
    auto it = std::find_if(channels.begin(), channels.end(),
                           [&](const Channel &x) { return x.id == c.id; });
    if (it == channels.end()) {
      require(c.revision == 1 && confirmed && channels.size() < 32,
              "confirmation-required");
      channels.push_back(c);
    } else {
      require(it->owner == c.owner && c.revision == it->revision + 1,
              "stale-config");
      require(confirmed || (!(!it->enabled && c.enabled) &&
                            c.single <= it->single && c.total <= it->total),
              "confirmation-required");
      *it = c;
    }
    persist();
  }
  void start(const std::string &id, const std::string &owner, bool confirmed) {
    require(alive && confirmed, "confirmation-required");
    identifier(id);
    identifier(owner);
    require(sessions.size() < 16, "capacity");
    for (const auto &s : sessions)
      require(s.id != id, "session-reuse");
    bool found = false;
    uint64_t limit = 0;
    for (const auto &c : channels)
      if (c.owner == owner && c.enabled) {
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
    for (const auto &p : payments)
      require(p.id != id, "request-reuse");
  }
  Budget quote(const std::string &channel_id, const std::string &session_id,
               const std::string &owner, uint64_t amount) {
    require(alive && amount > 0, "invalid-amount");
    auto &c = channel(channel_id);
    auto &s = session(session_id);
    require(c.owner == owner && s.owner == owner && s.active,
            "invalid-session");
    return {amount > c.single, add(s.used, amount) > s.limit, !c.enabled,
            s.used, s.limit};
  }
  void reserve(const std::string &id, const std::string &channel_id,
               const std::string &session_id, const std::string &owner,
               uint64_t amount, const Bytes &hash, bool approve,
               uint64_t raised = 0) {
    identifier(id);
    require(hash.size() == 32 && std::any_of(hash.begin(), hash.end(),
                                             [](uint8_t c) { return c != 0; }),
            "invalid-commitment");
    for (const auto &p : payments)
      require(p.id != id, "request-reuse");
    require(payments.size() < 256, "capacity");
    auto q = quote(channel_id, session_id, owner, amount);
    require(!q.prompt() || approve, "confirmation-required");
    auto &c = channel(channel_id);
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
                        s.revision, hash, "reserved"});
    persist();
  }
  void executable(const std::string &id) {
    require(alive, "policy-unavailable");
    auto &p = payment(id);
    auto &c = channel(p.channel);
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
    auto &s = session(p.session);
    require(s.used >= p.amount, "corrupt-state");
    s.used -= p.amount;
    p.state = "released";
    persist();
  }
  void close_sessions() {
    require(alive, "policy-unavailable");
    for (auto &s : sessions)
      s.active = false;
    persist();
  }
};
} // namespace vaultlink
