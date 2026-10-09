#pragma once
#include "../core.hpp"
#include "bsv.hpp"
#include <functional>
#include <memory>
namespace vaultlink {
// 物理串口/本地管道共用相同 SDK
// 接口；适配器只能搬运真实字节，不生成协议成功结果。
struct ByteTransport {
  virtual int read_byte() = 0;
  virtual void write(const Bytes &) = 0;
  virtual uint64_t millis() = 0;
  virtual ~ByteTransport() = default;
};
struct Operation {
  virtual bool ready() = 0;
  virtual bool allowed() = 0;
  virtual Value execute() = 0;
  virtual void cancel() {}
  virtual ~Operation() = default;
};
struct Prepared {
  std::string profile;
  Value core;
  std::unique_ptr<Operation> operation;
};
class Endpoint {
  ByteTransport &transport;
  IdentityKey &identity;
  Rng rng;
  uint32_t run, connection = 0, session_id = 0;
  FrameReader frames;
  RequestGate gate;
  std::unique_ptr<Record> receive, send;
  Bytes digest;
  std::string code;
  Value binding, active_request;
  std::unique_ptr<Operation> active;
  uint8_t stage = 0;
  uint64_t last = 0;
  uint32_t recent_id = 0;
  Value recent_payload;
  std::function<Prepared(const std::string &, const Value &, const Bytes &)>
      prepare;
  std::function<void()> disconnected;
  std::function<bool(const std::string &)> confirm_pairing;
#ifdef VLP_E2E_TEST_ONLY
  std::function<Value(const std::string &, const Value &, const Bytes &)>
      extension;
#endif
  void send_frame(uint8_t type, uint32_t seq, const Bytes &payload) {
    require(payload.size() <= 1024, "message-too-large");
    Bytes out{0xa5, 0x5a, 2, type, 0};
    auto s = le32(seq);
    out.insert(out.end(), s.begin(), s.end());
    out.push_back(payload.size() & 255);
    out.push_back(payload.size() >> 8);
    out.insert(out.end(), payload.begin(), payload.end());
    uint32_t crc = crc32(out.data() + 2, out.size() - 2);
    auto c = le32(crc);
    out.insert(out.end(), c.begin(), c.end());
    transport.write(out);
  }
  void encrypted(uint8_t type, const Value &v) {
    require(bool(send), "disconnected");
    auto bytes = send->seal(type, encode(v));
    send_frame(type, send->sequence(), bytes);
  }
  void response(const Value &r, const Value &payload) {
    encrypted(17, obj({{"requestId", r.at("requestId")},
                       {"binding", binding},
                       {"commitment", r.at("commitment")},
                       {"payload", payload}}));
  }
  static uint32_t number(const Value &v) {
    uint64_t n = v.integer();
    require(n > 0 && n <= UINT32_MAX, "invalid-generation");
    return n;
  }
  Request request(const Value &r) {
    Request result;
    result.id = number(r.at("requestId"));
    result.session = session_id;
    auto b = r.at("commitment").binary(32);
    std::copy(b.begin(), b.end(), result.commitment.begin());
    return result;
  }
  void hello(const Frame &f) {
    require(f.seq == 0, "bad-hello");
    if (stage)
      reset();
    auto h = decode(Bytes(f.payload.begin(), f.payload.begin() + f.size));
    h.fields({"hostEph", "hostNonce", "protocolVersion", "capabilities",
              "walletGeneration", "backendGeneration", "hostRunGeneration"});
    require(h.at("protocolVersion").integer() == 2, "version-mismatch");
    h.at("hostNonce").binary(32);
    number(h.at("walletGeneration"));
    number(h.at("backendGeneration"));
    number(h.at("hostRunGeneration"));
    auto &caps = h.at("capabilities");
    require(caps.kind == Value::Array && caps.array.size() <= 32,
            "invalid-capabilities");
    std::vector<uint32_t> seen;
    for (const auto &c : caps.array) {
      auto n = number(c);
      require(std::find(seen.begin(), seen.end(), n) == seen.end(),
              "invalid-capabilities");
      seen.push_back(n);
    }
    X25519 eph(rng);
    Bytes random(32);
    check(rng(nullptr, random.data(), 32));
    require(connection < UINT32_MAX, "connection-exhausted");
    ++connection;
    auto ack = obj({{"deviceEph", eph.public_key()},
                    {"deviceNonce", random},
                    {"publicKey", identity.public_key()},
                    {"deviceRunId", uint64_t(run)},
                    {"connectionId", uint64_t(connection)},
                    {"protocolVersion", uint64_t(2)},
                    {"capabilities", Value::list({Value(uint64_t(0x221))})}});
    static constexpr char label[] = "vlp:handshake:v2\0";
    digest = sha256(join({text_bytes(label, sizeof(label) - 1),
                          encode(obj({{"hello", h}, {"ack", ack}}), 2048)}));
    auto shared = eph.shared(h.at("hostEph").binary(32));
    auto in = hkdf(shared, digest, "vlp:link:c2s:key:v2", 32),
         out = hkdf(shared, digest, "vlp:link:s2c:key:v2", 32);
    receive = std::make_unique<Record>(
        in, hkdf(shared, digest, "vlp:link:c2s:nonce:v2", 12), run, connection);
    send = std::make_unique<Record>(
        out, hkdf(shared, digest, "vlp:link:s2c:nonce:v2", 12), run,
        connection);
    std::fill(shared.begin(), shared.end(), 0);
    std::fill(in.begin(), in.end(), 0);
    std::fill(out.begin(), out.end(), 0);
    static constexpr char pairing[] = "vlp:link:pairing:v2";
    auto hash =
        sha256(join({text_bytes(pairing, sizeof(pairing) - 1), digest}));
    uint32_t value =
        ((uint32_t(hash[0]) << 16) | (uint32_t(hash[1]) << 8) | hash[2]) %
        1000000;
    code = std::to_string(value);
    code.insert(0, 6 - code.size(), '0');
    send_frame(2, 0, encode(ack));
    stage = 1;
    last = transport.millis();
  }
  void finish(State state, const Value &payload) {
    uint32_t id = number(active_request.at("requestId"));
    require(gate.finish(id, state) == Error::ok, "invalid-state");
    recent_id = id;
    recent_payload = payload;
    response(active_request, payload);
    active.reset();
  }
  void business(const Value &r) {
    require(!active, "busy");
    auto op = r.at("op").string();
    require(op.size() <= 48, "invalid-operation");
    auto prepared = prepare(op, r.at("body"), r.at("commitment").binary(32));
    require(commitment(prepared.profile, prepared.core) ==
                r.at("commitment").binary(32),
            "invalid-commitment");
    State state;
    auto ref = request(r);
    auto e = gate.accept(ref, state);
    if (e == Error::busy)
      throw Failure("busy");
    if (e == Error::replay)
      throw Failure("replay");
    if (e == Error::conflict)
      throw Failure("request-conflict");
    require(e == Error::ok, "invalid-request");
    if (state != State::waiting) {
      response(r, recent_id == ref.id ? recent_payload
                                      : obj({{"state", "unknown"}}));
      return;
    }
    require(!active, "busy");
    active_request = r;
    active = std::move(prepared.operation);
    require(bool(active), "unsupported");
  }
  void control(const Value &r) {
    auto op = r.at("op").string();
    if (op == "system.ping") {
      r.at("body").fields({});
      response(r, obj({{"alive", true}}));
      return;
    }
    if (op == "system.close" || op == "system.lock") {
      r.at("body").fields({});
      reset();
      return;
    }
    if (op == "system.query" || op == "system.cancel") {
      auto &b = r.at("body");
      b.fields({"requestId", "commitment"});
      Request q;
      q.id = number(b.at("requestId"));
      q.session = session_id;
      auto hash = b.at("commitment").binary(32);
      std::copy(hash.begin(), hash.end(), q.commitment.begin());
      State state;
      auto e = gate.query(q, state);
      if (e == Error::conflict)
        throw Failure("request-conflict");
      if (e != Error::ok) {
        response(r, obj({{"state", "unknown"}, {"payload", Value()}}));
        return;
      }
      if (op == "system.cancel" && state == State::waiting && active) {
        active->cancel();
        require(gate.finish(q.id, State::cancelled) == Error::ok,
                "invalid-state");
        recent_id = q.id;
        recent_payload = obj({{"error", "cancelled"}});
        response(active_request, recent_payload);
        active.reset();
        state = State::cancelled;
      }
      const char *names[] = {"awaiting-user", "executing", "completed",
                             "denied",        "cancelled", "unknown"};
      Value payload;
      if (recent_id == q.id)
        payload = Value(encode(recent_payload));
      response(r,
               obj({{"state", names[unsigned(state)]}, {"payload", payload}}));
      return;
    }
    throw Failure("unsupported");
  }
  void handle(const Frame &f) {
    if (f.type == 1) {
      hello(f);
      return;
    }
    require(stage > 0 && bool(receive), "disconnected");
    auto body = decode(receive->open(
        f.type, f.seq, Bytes(f.payload.begin(), f.payload.begin() + f.size)));
    last = transport.millis();
    if (stage == 1) {
      require(f.type == 3, "bad-pair");
      body.fields({"code"});
      require(body.at("code").string() == code, "bad-pair");
      // 配对许可由设备产品提供；SDK 不能替产品自动批准。
      require(confirm_pairing(code), "pairing-denied");
      encrypted(4, obj({{"paired", true}}));
      stage = 2;
      return;
    }
    if (stage == 2) {
      require(f.type == 5, "bad-proof");
      body.fields({"challenge"});
      auto challenge = body.at("challenge").binary(32);
      check(rng(nullptr, reinterpret_cast<uint8_t *>(&session_id), 4));
      if (!session_id)
        session_id = 1;
      static constexpr char label[] = "vlp:possession:v2\0";
      auto pub = identity.public_key();
      auto hash = sha256d(join({text_bytes(label, sizeof(label) - 1), digest,
                                pub, be32(session_id), challenge}));
      encrypted(6, obj({{"challenge", challenge},
                        {"publicKey", pub},
                        {"sessionId", uint64_t(session_id)},
                        {"sessionEpoch", uint64_t(1)},
                        {"signature", identity.sign(hash)}}));
      binding = obj({{"sessionId", std::to_string(session_id)},
                     {"sessionEpoch", uint64_t(1)},
                     {"connectionId", uint64_t(connection)},
                     {"deviceRunId", uint64_t(run)}});
      stage = 3;
      return;
    }
    require(f.type == 16, "invalid-message");
    body.fields(
        {"op", "opVersion", "body", "requestId", "binding", "commitment"});
    require(encode(body.at("binding")) == encode(binding) &&
                body.at("opVersion").integer() == 1,
            "stale-session");
    number(body.at("requestId"));
    body.at("commitment").binary(32);
    try {
      if (body.at("op").string().rfind("system.", 0) == 0)
        control(body);
#ifdef VLP_E2E_TEST_ONLY
      else if (extension && body.at("op").string().rfind("test.", 0) == 0)
        response(body, extension(body.at("op").string(), body.at("body"),
                                 body.at("commitment").binary(32)));
#endif
      else
        business(body);
    } catch (const Failure &e) {
      response(body, obj({{"error", e.what()}}));
    }
  }

public:
  Endpoint(
      ByteTransport &t, IdentityKey &key, Rng random, uint32_t run_id,
      std::function<Prepared(const std::string &, const Value &, const Bytes &)>
          factory,
      std::function<void()> on_disconnect,
      std::function<bool(const std::string &)> on_pairing)
      : transport(t), identity(key), rng(random), run(run_id),
        prepare(std::move(factory)), disconnected(std::move(on_disconnect)),
        confirm_pairing(std::move(on_pairing)) {
    require(run != 0, "invalid-generation");
    require(bool(confirm_pairing), "pairing-callback-required");
  }
#ifdef VLP_E2E_TEST_ONLY
  void set_test_control(
      std::function<Value(const std::string &, const Value &, const Bytes &)>
          f) {
    extension = std::move(f);
  }
#endif
  void reset() {
    if (active)
      active->cancel();
    active.reset();
    receive.reset();
    send.reset();
    gate = RequestGate();
    recent_id = 0;
    stage = 0;
    session_id = 0;
    identity.lock();
    disconnected();
  }
  void poll() {
    int byte;
    Frame f;
    unsigned count = 0;
    while (count++ < 2048 && (byte = transport.read_byte()) >= 0) {
      if (frames.feed(uint8_t(byte), f)) {
        try {
          handle(f);
        } catch (...) {
          reset();
        }
      }
    }
    if (stage && transport.millis() - last > 8000) {
      reset();
      frames.close();
    }
    if (active && active->ready()) {
      try {
        if (!active->allowed()) {
          finish(State::denied, obj({{"error", "denied"}}));
        } else {
          require(gate.start(number(active_request.at("requestId"))) ==
                      Error::ok,
                  "invalid-state");
          auto value = active->execute();
          finish(State::completed, value);
        }
      } catch (const Failure &e) {
        if (active)
          finish(State::unknown, obj({{"error", e.what()}}));
      }
    }
  }
  uint32_t run_id() const { return run; }
  uint32_t connection_id() const { return connection; }
};
} // namespace vaultlink
