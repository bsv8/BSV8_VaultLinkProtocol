#pragma once
#include "crypto.hpp"

namespace vaultlink {
struct Input {
  Bytes txid, script;
  uint32_t vout, sequence;
};
struct Output {
  uint64_t amount;
  Bytes script;
};
struct Transaction {
  uint32_t version, locktime;
  std::vector<Input> inputs;
  std::vector<Output> outputs;
};
class TxReader {
  const Bytes &b;
  size_t at = 0;

public:
  explicit TxReader(const Bytes &raw) : b(raw) {}
  Bytes take(size_t n) {
    require(n <= b.size() - at, "truncated-transaction");
    Bytes x(b.begin() + at, b.begin() + at + n);
    at += n;
    return x;
  }
  uint64_t number(unsigned n) {
    auto x = take(n);
    uint64_t v = 0;
    for (unsigned i = 0; i < n; ++i)
      v |= uint64_t(x[i]) << (8 * i);
    return v;
  }
  size_t count() {
    uint64_t n = number(1);
    if (n < 253)
      return n;
    require(n == 253, "transaction-limit");
    n = number(2);
    require(n >= 253, "non-shortest");
    return n;
  }
  bool end() const { return at == b.size(); }
};
inline Transaction parse_tx(const Bytes &b, size_t limit = 8192) {
  require(b.size() <= limit, "transaction-limit");
  TxReader r(b);
  Transaction t;
  t.version = r.number(4);
  auto n = r.count();
  require(n >= 1 && n <= 128, "transaction-limit");
  for (size_t i = 0; i < n; ++i) {
    auto txid = r.take(32);
    uint32_t vout = r.number(4);
    auto len = r.count();
    require(len <= 1024, "transaction-limit");
    auto script = r.take(len);
    uint32_t seq = r.number(4);
    t.inputs.push_back({txid, script, vout, seq});
  }
  n = r.count();
  require(n >= 1 && n <= 128, "transaction-limit");
  for (size_t i = 0; i < n; ++i) {
    uint64_t amount = r.number(8);
    auto len = r.count();
    require(len <= 1024, "transaction-limit");
    t.outputs.push_back({amount, r.take(len)});
  }
  t.locktime = r.number(4);
  require(r.end(), "trailing-transaction");
  return t;
}
inline Bytes compact(size_t n) {
  require(n <= 65535, "transaction-limit");
  return n < 253 ? Bytes{uint8_t(n)} : Bytes{253, uint8_t(n), uint8_t(n >> 8)};
}
inline Bytes output_bytes(const Output &o) {
  return join({le64(o.amount), compact(o.script.size()), o.script});
}
inline bool is_p2pkh(const Bytes &s) {
  return s.size() == 25 && s[0] == 0x76 && s[1] == 0xa9 && s[2] == 0x14 &&
         s[23] == 0x88 && s[24] == 0xac;
}
// 地址由实际输出脚本生成，不能采用主机提供的收款方标签。
inline std::string p2pkh_output_address(const Bytes &script, bool testnet = false) {
  require(is_p2pkh(script), "unsupported-script");
  Bytes payload{static_cast<uint8_t>(testnet ? 111 : 0)};
  payload.insert(payload.end(), script.begin() + 3, script.begin() + 23);
  auto checksum = sha256d(payload);
  payload.insert(payload.end(), checksum.begin(), checksum.begin() + 4);
  std::vector<unsigned> digits;
  size_t zeros = 0;
  while (zeros < payload.size() && payload[zeros] == 0) ++zeros;
  for (size_t i = zeros; i < payload.size(); ++i) {
    unsigned carry = payload[i];
    for (auto &digit : digits) { carry += digit * 256; digit = carry % 58; carry /= 58; }
    while (carry) { digits.push_back(carry % 58); carry /= 58; }
  }
  constexpr char alphabet[] = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
  std::string address(zeros, '1');
  for (auto i = digits.rbegin(); i != digits.rend(); ++i) address += alphabet[*i];
  return address;
}
inline Bytes own_script(const Bytes &pub) {
  return join({Bytes{0x76, 0xa9, 0x14}, hash160(pub), Bytes{0x88, 0xac}});
}
struct Review {
  uint64_t amount = 0, change = 0, fee = 0;
  std::vector<Bytes> digests;
};
inline Bytes forkid_sighash(const Transaction &t, size_t index, const Output &prev) {
  require(index < t.inputs.size() && !prev.script.empty() && prev.script.size() <= 1024, "invalid-prevout");
  Bytes refs, seqs, outs;
  for (const auto &i : t.inputs) {
    auto b = join({i.txid, le32(i.vout)});
    refs.insert(refs.end(), b.begin(), b.end());
    auto s = le32(i.sequence);
    seqs.insert(seqs.end(), s.begin(), s.end());
  }
  for (const auto &o : t.outputs) {
    auto b = output_bytes(o);
    outs.insert(outs.end(), b.begin(), b.end());
  }
  const auto &i = t.inputs[index];
  return sha256d(
      join({le32(t.version), sha256d(refs), sha256d(seqs), i.txid, le32(i.vout),
            compact(prev.script.size()), prev.script, le64(prev.amount),
            le32(i.sequence), sha256d(outs), le32(t.locktime), le32(0x41)}));
}
inline Bytes sighash(const Transaction &t, size_t index, const Output &prev) {
  require(is_p2pkh(prev.script), "invalid-prevout");
  return forkid_sighash(t, index, prev);
}
inline Review inspect(const Bytes &raw, const std::vector<Bytes> &evidence,
                      const Bytes &public_key) {
  auto t = parse_tx(raw, 640);
  require(t.inputs.size() <= 4 && t.outputs.size() <= 6 &&
              evidence.size() == t.inputs.size(),
          "unsupported");
  auto own = own_script(public_key);
  Review review;
  uint64_t total_in = 0, total_out = 0;
  std::vector<Output> prev;
  std::vector<std::string> seen;
  for (size_t i = 0; i < t.inputs.size(); ++i) {
    const auto &input = t.inputs[i];
    require(input.script.empty(), "already-signed");
    auto p = parse_tx(evidence[i]);
    require(sha256d(evidence[i]) == input.txid && input.vout < p.outputs.size(),
            "invalid-prevout");
    auto ref = to_hex(input.txid) + ":" + std::to_string(input.vout);
    require(std::find(seen.begin(), seen.end(), ref) == seen.end(),
            "duplicate-input");
    seen.push_back(ref);
    auto o = p.outputs[input.vout];
    require(o.script == own, "wrong-key");
    total_in = add(total_in, o.amount);
    prev.push_back(o);
  }
  for (const auto &o : t.outputs) {
    require(is_p2pkh(o.script), "unsupported-script");
    total_out = add(total_out, o.amount);
    if (o.script == own)
      review.change = add(review.change, o.amount);
    else
      review.amount = add(review.amount, o.amount);
  }
  require(total_in >= total_out, "negative-fee");
  review.fee = total_in - total_out;
  for (size_t i = 0; i < t.inputs.size(); ++i)
    review.digests.push_back(sighash(t, i, prev[i]));
  return review;
}
inline Bytes commitment(const std::string &profile, const Value &core) {
  std::string label = "vlp:commit:v2";
  label.push_back(0);
  label += profile;
  label.push_back(0);
  auto encoded=encode(core,32768);WipeBytes wipe_encoded{encoded};
  Bytes bytes(label.begin(),label.end());WipeBytes wipe_input{bytes};bytes.push_back(1);
  bytes.insert(bytes.end(),encoded.begin(),encoded.end());return sha256d(bytes);
}
} // namespace vaultlink
