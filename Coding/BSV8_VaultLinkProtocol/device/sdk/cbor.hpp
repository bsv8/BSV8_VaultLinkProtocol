#pragma once
#include <algorithm>
#include <cstdint>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>
namespace vaultlink {
using Bytes = std::vector<uint8_t>;
struct Failure : std::runtime_error {
  using std::runtime_error::runtime_error;
};
inline void require(bool ok, const char *code) {
  if (!ok)
    throw Failure(code);
}
// 有界通用值；仅协议处理使用，入口长度/层数/容器容量均先检查。
struct Value {
  enum Kind {
    Null,
    Bool,
    Uint,
    Negative,
    Text,
    Binary,
    Array,
    Map
  } kind = Null;
  uint64_t n = 0;
  bool boolean = false;
  std::string text;
  Bytes bytes;
  std::vector<Value> array;
  std::vector<std::pair<std::string, Value>> map;
  Value() = default;
  Value(uint64_t v) : kind(Uint), n(v) {};
  Value(bool v) : kind(Bool), boolean(v) {}
  Value(const char *v) : kind(Text), text(v) {};
  Value(std::string v) : kind(Text), text(std::move(v)) {}
  Value(Bytes v) : kind(Binary), bytes(std::move(v)) {}
  static Value list(std::vector<Value> v) {
    Value x;
    x.kind = Array;
    x.array = std::move(v);
    return x;
  }
  static Value object(std::vector<std::pair<std::string, Value>> v) {
    Value x;
    x.kind = Map;
    x.map = std::move(v);
    return x;
  }
  const Value &at(const std::string &key) const {
    require(kind == Map, "invalid-object");
    for (const auto &p : map)
      if (p.first == key)
        return p.second;
    throw Failure("missing-field");
  }
  uint64_t integer() const {
    require(kind == Uint, "invalid-integer");
    return n;
  }
  const std::string &string() const {
    require(kind == Text, "invalid-text");
    return text;
  }
  const Bytes &binary(size_t size = SIZE_MAX) const {
    require(kind == Binary && (size == SIZE_MAX || bytes.size() == size),
            "invalid-bytes");
    return bytes;
  }
  bool flag() const {
    require(kind == Bool, "invalid-boolean");
    return boolean;
  }
  void fields(std::initializer_list<const char *> keys) const {
    require(kind == Map && map.size() == keys.size(), "invalid-fields");
    for (auto k : keys)
      (void)at(k);
  }
};
inline bool key_less(const std::string &a, const std::string &b) {
  return a.size() != b.size() ? a.size() < b.size() : a < b;
}
inline bool utf8_valid(const std::string &s) {
  size_t i = 0;
  while (i < s.size()) {
    uint8_t c = s[i++];
    if (c < 128)
      continue;
    unsigned n;
    uint32_t cp, min;
    if (c >= 0xc2 && c <= 0xdf) {
      n = 1;
      cp = c & 31;
      min = 128;
    } else if (c >= 0xe0 && c <= 0xef) {
      n = 2;
      cp = c & 15;
      min = 2048;
    } else if (c >= 0xf0 && c <= 0xf4) {
      n = 3;
      cp = c & 7;
      min = 65536;
    } else
      return false;
    if (i + n > s.size())
      return false;
    while (n--) {
      uint8_t t = s[i++];
      if ((t & 192) != 128)
        return false;
      cp = (cp << 6) | (t & 63);
    }
    if (cp < min || cp > 0x10ffff || (cp >= 0xd800 && cp <= 0xdfff))
      return false;
  }
  return true;
}
inline void cbor_head(Bytes &b, uint8_t m, uint64_t n) {
  if (n < 24) {
    b.push_back((m << 5) | n);
    return;
  }
  unsigned w = n <= 255 ? 1 : n <= 65535 ? 2 : n <= UINT32_MAX ? 4 : 8;
  b.push_back((m << 5) | (w == 1 ? 24 : w == 2 ? 25 : w == 4 ? 26 : 27));
  for (int i = int(w) - 1; i >= 0; --i)
    b.push_back(uint8_t(n >> (8 * i)));
}
inline void cbor_write(const Value &v, Bytes &b, size_t limit, unsigned depth) {
  require(depth <= 6, "depth-exceeded");
  switch (v.kind) {
  case Value::Null:
    b.push_back(0xf6);
    break;
  case Value::Bool:
    b.push_back(v.boolean ? 0xf5 : 0xf4);
    break;
  case Value::Uint:
  case Value::Negative:
    cbor_head(b, v.kind == Value::Uint ? 0 : 1, v.n);
    break;
  case Value::Text:
    require(utf8_valid(v.text), "invalid-utf8");
    cbor_head(b, 3, v.text.size());
    b.insert(b.end(), v.text.begin(), v.text.end());
    break;
  case Value::Binary:
    cbor_head(b, 2, v.bytes.size());
    b.insert(b.end(), v.bytes.begin(), v.bytes.end());
    break;
  case Value::Array:
    require(depth < 6 && v.array.size() <= 256, "container-limit");
    cbor_head(b, 4, v.array.size());
    for (const auto &x : v.array)
      cbor_write(x, b, limit, depth + 1);
    break;
  case Value::Map: {
    require(depth < 6 && v.map.size() <= 24, "map-too-large");
    auto items = v.map;
    std::sort(items.begin(), items.end(), [](const auto &a, const auto &c) {
      return key_less(a.first, c.first);
    });
    cbor_head(b, 5, items.size());
    std::string prev;
    for (const auto &p : items) {
      require(p.first.size() > 0 && p.first.size() <= 31 &&
                  (prev.empty() || key_less(prev, p.first)),
              "invalid-key");
      cbor_write(Value(p.first), b, limit, depth + 1);
      cbor_write(p.second, b, limit, depth + 1);
      prev = p.first;
    }
    break;
  }
  }
  require(b.size() <= limit, "message-too-large");
}
inline Bytes encode(const Value &v, size_t limit = 896) {
  Bytes b;
  cbor_write(v, b, limit, 0);
  return b;
}
class CborReader {
  const Bytes &b;
  size_t i = 0;
  uint8_t take() {
    require(i < b.size(), "truncated");
    return b[i++];
  }
  Value read(unsigned depth) {
    require(depth <= 6, "depth-exceeded");
    uint8_t h = take(), m = h >> 5, ai = h & 31;
    if (m == 7) {
      if (ai == 20)
        return Value(false);
      if (ai == 21)
        return Value(true);
      if (ai == 22)
        return Value();
      throw Failure("invalid-simple");
    }
    require(m <= 5 && ai <= 27, "invalid-type");
    uint64_t n = ai;
    if (ai >= 24) {
      unsigned w = 1u << (ai - 24);
      n = 0;
      for (unsigned j = 0; j < w; ++j)
        n = (n << 8) | take();
      require(n >= (w == 1   ? 24ull
                    : w == 2 ? 256ull
                    : w == 4 ? 65536ull
                             : 4294967296ull),
              "non-shortest");
    }
    if (m <= 1) {
      Value v(n);
      if (m == 1)
        v.kind = Value::Negative;
      return v;
    }
    require(n <= b.size() - i, "invalid-length");
    if (m == 2 || m == 3) {
      Bytes x(b.begin() + i, b.begin() + i + size_t(n));
      i += n;
      if (m == 2)
        return Value(std::move(x));
      std::string s(x.begin(), x.end());
      require(utf8_valid(s), "invalid-utf8");
      return Value(std::move(s));
    }
    require(depth < 6, "depth-exceeded");
    if (m == 4) {
      require(n <= 256, "container-limit");
      std::vector<Value> a;
      while (n--)
        a.push_back(read(depth + 1));
      return Value::list(std::move(a));
    }
    require(n <= 24 && n * 2 <= b.size() - i, "map-too-large");
    std::vector<std::pair<std::string, Value>> o;
    std::string previous;
    while (n--) {
      std::string k = read(depth + 1).string();
      require(!k.empty() && k.size() <= 31 &&
                  (previous.empty() || key_less(previous, k)),
              "key-order");
      previous = k;
      o.emplace_back(std::move(k), read(depth + 1));
    }
    return Value::object(std::move(o));
  }

public:
  explicit CborReader(const Bytes &x) : b(x) {}
  Value finish() {
    auto v = read(0);
    require(i == b.size(), "trailing-bytes");
    return v;
  }
};
inline Value decode(const Bytes &b, size_t limit = 896) {
  require(b.size() <= limit, "message-too-large");
  return CborReader(b).finish();
}
inline Value obj(std::initializer_list<std::pair<std::string, Value>> v) {
  return Value::object(v);
}
inline Bytes join(std::initializer_list<Bytes> parts) {
  Bytes b;
  for (const auto &p : parts)
    b.insert(b.end(), p.begin(), p.end());
  return b;
}
inline Bytes text_bytes(const char *s, size_t n) { return Bytes(s, s + n); }
inline Bytes be32(uint32_t n) {
  return {uint8_t(n >> 24), uint8_t(n >> 16), uint8_t(n >> 8), uint8_t(n)};
}
inline Bytes le32(uint32_t n) {
  return {uint8_t(n), uint8_t(n >> 8), uint8_t(n >> 16), uint8_t(n >> 24)};
}
inline Bytes le64(uint64_t n) {
  Bytes b(8);
  for (unsigned i = 0; i < 8; ++i)
    b[i] = n >> (8 * i);
  return b;
}
inline Bytes from_hex(const std::string &s) {
  require(s.size() % 2 == 0, "invalid-hex");
  Bytes b;
  auto digit = [](char c) {
    return c >= '0' && c <= '9'   ? c - '0'
           : c >= 'a' && c <= 'f' ? c - 'a' + 10
                                  : -1;
  };
  for (size_t i = 0; i < s.size(); i += 2) {
    int a = digit(s[i]), c = digit(s[i + 1]);
    require(a >= 0 && c >= 0, "invalid-hex");
    b.push_back((a << 4) | c);
  }
  return b;
}
inline std::string to_hex(const Bytes &b) {
  const char *h = "0123456789abcdef";
  std::string s;
  for (auto c : b) {
    s += h[c >> 4];
    s += h[c & 15];
  }
  return s;
}
inline uint64_t add(uint64_t a, uint64_t b) {
  require(a <= UINT64_MAX - b, "amount-overflow");
  return a + b;
}
} // namespace vaultlink
