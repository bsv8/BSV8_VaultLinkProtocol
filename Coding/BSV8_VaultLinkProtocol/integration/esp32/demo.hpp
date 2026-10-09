#pragma once
#ifndef VLP_E2E_TEST_ONLY
#error                                                                         \
    "This demo contains a PUBLIC test key and remote test decisions. Never build as wallet firmware."
#endif
#include "../../device/sdk/endpoint.hpp"
#include "../../device/sdk/policy.hpp"
#include <optional>
namespace vlp_e2e {
using namespace vaultlink;
struct Platform {
  virtual Store &policy_store() = 0;
  virtual Bytes load_plan() = 0;
  virtual void save_plan(const Bytes &) = 0;
  virtual void clear_policy() = 0;
  virtual void restart() = 0;
  virtual void reject_next_write() = 0;
  virtual ~Platform() = default;
};
class Immediate : public Operation {
  std::function<Value()> action;

public:
  explicit Immediate(std::function<Value()> f) : action(std::move(f)) {}
  bool ready() override { return true; }
  bool allowed() override { return true; }
  Value execute() override { return action(); }
};
class Demo {
  Platform &platform;
  IdentityKey &key;
  std::unique_ptr<Policy> policy;
  std::string session_id, decision = "deny", fault;
  uint64_t raise = 0;
  unsigned prompts = 0;
  bool waiting = false, decided = false;
  void reload() {
    policy = std::make_unique<Policy>(platform.policy_store(),
                                      to_hex(key.public_key()));
    session_id.clear();
    waiting = false;
    decided = false;
  }
  void trip(const std::string &point) {
    if (fault != point)
      return;
    fault.clear();
    platform.save_plan({});
    platform.restart();
    throw Failure("restart-returned");
  }
  struct PaymentOp : Operation {
    Demo &demo;
    Value core;
    Review review;
    Bytes hash;
    std::string session, mode;
    uint64_t raised;
    Budget budget;
    bool pending, cancelled = false;
    PaymentOp(Demo &d, Value c, Review r, Bytes h)
        : demo(d), core(std::move(c)), review(std::move(r)), hash(std::move(h)),
          session(d.session_id), mode(d.decision), raised(d.raise) {
      d.policy->fresh(core.at("paymentId").string());
      budget = d.policy->quote(core.at("channelId").string(), session,
                               "e2e-app", review.amount);
      pending = budget.prompt() && mode == "wait";
      if (budget.prompt())
        ++demo.prompts;
      if (pending) {
        demo.waiting = true;
        demo.decided = false;
      }
    }
    bool ready() override { return !pending || demo.decided || cancelled; }
    bool allowed() override {
      demo.waiting = false;
      return !cancelled &&
             (!budget.prompt() || (pending ? demo.decision : mode) != "deny");
    }
    void cancel() override {
      cancelled = true;
      demo.waiting = false;
    }
    Value execute() override {
      demo.waiting = false;
      auto &b = core;
      auto payment_id = b.at("paymentId").string();
      demo.trip("before-reserve");
      demo.policy->reserve(payment_id, b.at("channelId").string(), session,
                           "e2e-app", review.amount, hash, budget.prompt(),
                           (pending ? demo.decision : mode) == "raise"
                               ? (pending ? demo.raise : raised)
                               : 0);
      demo.trip("after-reserve");
      demo.policy->executable(payment_id);
      std::vector<Value> signatures;
      for (const auto &digest : review.digests) {
        auto sig = demo.key.sign(digest);
        sig.push_back(0x41);
        signatures.emplace_back(sig);
      }
      demo.trip("after-sign");
      demo.policy->signed_payment(payment_id);
      demo.trip("after-commit");
      return obj(
          {{"signatures", Value::list(signatures)}, {"amount", review.amount}});
    }
  };

public:
  Demo(Platform &p, IdentityKey &k) : platform(p), key(k) {
    auto plan = platform.load_plan();
    if (!plan.empty())
      fault = decode(plan).at("phase").string();
    reload();
  }
  void disconnected() {
    waiting = false;
    decided = false;
    session_id.clear();
    // SDK 已在断链时清除私钥。只有 E2E Demo 自动重新装载公开测试标量。
    Bytes test_key(32);
    test_key[31] = 1;
    key.unlock(test_key);
    std::fill(test_key.begin(), test_key.end(), 0);
    if (policy) {
      try {
        policy->close_sessions();
      } catch (...) { /* 存储失败仍不恢复执行，下一次操作/重启显式失败。 */
      }
    }
  }
  Prepared prepare(const std::string &op, const Value &body,
                   const Bytes &hash) {
    require(op == "bsv.pay", "unsupported");
    body.fields({"rawTx", "prevTransactions", "channelId", "paymentId"});
    require(body.at("prevTransactions").kind == Value::Array,
            "invalid-request");
    std::vector<Bytes> prev;
    for (const auto &v : body.at("prevTransactions").array)
      prev.push_back(v.binary());
    auto review = inspect(body.at("rawTx").binary(), prev, key.public_key());
    require(review.amount > 0, "invalid-amount");
    auto core = body;
    core.map.emplace_back("amount", Value(review.amount));
    require(commitment("bsv-payment", core) == hash, "invalid-commitment");
    return {"bsv-payment", core,
            std::make_unique<PaymentOp>(*this, core, review, hash)};
  }
  Value control(const std::string &op, const Value &body, const Bytes &hash) {
    require(commitment("test", obj({{"op", op}, {"body", body}})) == hash,
            "invalid-commitment");
    if (op == "test.reset") {
      body.fields({});
      require(!waiting, "busy");
      platform.clear_policy();
      fault.clear();
      platform.save_plan({});
      reload();
      prompts = 0;
      decision = "deny";
      return obj({{"reset", true}, {"testOnly", true}});
    }
    if (op == "test.configure") {
      body.fields(
          {"channelId", "singleLimit", "sessionLimit", "revision", "enabled"});
      require(!waiting, "busy");
      trip("before-config");
      policy->configure(
          {body.at("channelId").string(), "e2e-app",
           body.at("singleLimit").integer(), body.at("sessionLimit").integer(),
           body.at("revision").integer(), body.at("enabled").flag()},
          true);
      trip("after-config");
      return obj({{"configured", true}});
    }
    if (op == "test.session") {
      body.fields({"sessionId"});
      require(!waiting, "busy");
      policy->start(body.at("sessionId").string(), "e2e-app", true);
      session_id = body.at("sessionId").string();
      return obj({{"sessionId", session_id}});
    }
    if (op == "test.authorize" || op == "test.decide") {
      body.fields({"decision", "raise"});
      auto mode = body.at("decision").string();
      require(mode == "deny" || mode == "allow" || mode == "raise" ||
                  (op == "test.authorize" && mode == "wait"),
              "invalid-decision");
      if (op == "test.authorize")
        require(!waiting, "busy");
      else
        require(waiting, "invalid-state");
      decision = mode;
      raise = body.at("raise").integer();
      if (op == "test.decide")
        decided = true;
      return obj({{"decision", mode}});
    }
    if (op == "test.arm") {
      body.fields({"phase"});
      require(!waiting, "busy");
      auto point = body.at("phase").string();
      require(point == "before-reserve" || point == "after-reserve" ||
                  point == "after-sign" || point == "after-commit" ||
                  point == "before-config" || point == "after-config" ||
                  point == "write-failure" || point == "restart" || point == "",
              "invalid-fault");
      if (point == "write-failure") {
        platform.reject_next_write();
        return obj({{"armed", point}});
      }
      fault = point;
      platform.save_plan(encode(obj({{"phase", fault}})));
      return obj({{"armed", point}});
    }
    if (op == "test.state") {
      body.fields({"sessionId", "paymentId"});
      auto snap = policy->snapshot();
      Value s, p;
      for (const auto &v : snap.at("sessions").array)
        if (v.at("id").string() == body.at("sessionId").string())
          s = v;
      for (const auto &v : snap.at("pending").array)
        if (v.at("id").string() == body.at("paymentId").string())
          p = v;
      return obj({{"testOnly", true},
                  {"key", snap.at("key")},
                  {"channels", snap.at("channels")},
                  {"session", s},
                  {"payment", p},
                  {"prompts", uint64_t(prompts)},
                  {"waiting", waiting},
                  {"fault", fault}});
    }
    throw Failure("unsupported");
  }
  void tick() { trip("restart"); }
};
} // namespace vlp_e2e
