#pragma once
#include <algorithm>
#include <array>
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
inline void wipe_bytes(Bytes &bytes) {
  volatile uint8_t *p=bytes.data();for(size_t i=0;i<bytes.size();++i)p[i]=0;
}
struct WipeBytes {
  Bytes &bytes;
  ~WipeBytes(){wipe_bytes(bytes);}
};
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
  // 协议值可含本地秘密。复制/替换/离开作用域均清理原字节，不留下明文结果缓存。
  void wipe() {wipe_bytes(bytes);volatile char *p=text.data();for(size_t i=0;i<text.size();++i)p[i]=0;}
  ~Value(){wipe();}
  Value(const Value &)=default;
  Value(Value &&) noexcept=default;
  Value &operator=(const Value &v) {if(this!=&v){wipe();kind=v.kind;n=v.n;boolean=v.boolean;text=v.text;bytes=v.bytes;array=v.array;map=v.map;}return *this;}
  Value &operator=(Value &&v) noexcept {if(this!=&v){wipe();kind=v.kind;n=v.n;boolean=v.boolean;text=std::move(v.text);bytes=std::move(v.bytes);array=std::move(v.array);map=std::move(v.map);}return *this;}
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
  Value &at(const std::string &key) {
    return const_cast<Value&>(static_cast<const Value&>(*this).at(key));
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
    require(depth < 6 && v.array.size() <= (limit>=65536?512:256), "container-limit");
    cbor_head(b, 4, v.array.size());
    for (const auto &x : v.array)
      cbor_write(x, b, limit, depth + 1);
    break;
  case Value::Map: {
    require(depth < 6 && v.map.size() <= 24, "map-too-large");
    // Sorting copied Values duplicates every nested ledger array. The map is
    // already bounded to 24 entries: sort stack-held references instead.
    std::array<const std::pair<std::string, Value>*,24> items{};
    for(size_t i=0;i<v.map.size();++i)items[i]=&v.map[i];
    std::sort(items.begin(), items.begin()+v.map.size(), [](const auto *a, const auto *c) {
      return key_less(a->first, c->first);
    });
    cbor_head(b, 5, v.map.size());
    const std::string* prev=nullptr;
    for (size_t i=0;i<v.map.size();++i) {
      const auto &p=*items[i];
      require(p.first.size() > 0 && p.first.size() <= 31 &&
                  (!prev || key_less(*prev, p.first)),
              "invalid-key");
      cbor_write(Value(p.first), b, limit, depth + 1);
      cbor_write(p.second, b, limit, depth + 1);
      prev = &p.first;
    }
    break;
  }
  }
  require(b.size() <= limit, "message-too-large");
}
inline size_t cbor_size(const Value& v,size_t limit,unsigned depth=0) {
  require(depth<=6,"depth-exceeded");
  const auto head=[](uint64_t n)->size_t{return n<24?1:n<=255?2:n<=65535?3:n<=0xffffffff?5:9;};
  size_t size=0;
  const auto add=[&](size_t n){require(size<=limit&&n<=limit-size,"message-too-large");size+=n;};
  switch(v.kind) {
    case Value::Null: case Value::Bool:add(1);break;
    case Value::Uint: case Value::Negative:add(head(v.n));break;
    case Value::Text:add(head(v.text.size()));add(v.text.size());break;
    case Value::Binary:add(head(v.bytes.size()));add(v.bytes.size());break;
    case Value::Array:
      require(depth<6&&v.array.size()<=(limit>=65536?512:256),"container-limit");
      add(head(v.array.size()));for(const auto& child:v.array)add(cbor_size(child,limit,depth+1));break;
    case Value::Map:
      require(depth<6&&v.map.size()<=24,"map-too-large");
      add(head(v.map.size()));for(const auto& item:v.map){add(head(item.first.size()));add(item.first.size());add(cbor_size(item.second,limit,depth+1));}break;
  }
  return size;
}
inline Bytes encode(const Value &v, size_t limit = 896) {
  Bytes b;
  // One exact allocation: vector doubling otherwise retains the old buffer
  // alongside the new one while a complete ledger tree is still live.
  b.reserve(cbor_size(v,limit));
  cbor_write(v, b, limit, 0);
  return b;
}
class CborReader {
  const Bytes &b;
  size_t i = 0;
  size_t nodes = 0, node_limit,array_limit;
  uint8_t take() {
    require(i < b.size(), "truncated");
    return b[i++];
  }
  Value read(unsigned depth) {
    require(++nodes <= node_limit,"node-limit");
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
      require(n <= array_limit, "container-limit");
      require(n<=b.size()-i,"truncated");
      std::vector<Value> a;
      a.reserve(size_t(n));
      while (n--)
        a.push_back(read(depth + 1));
      return Value::list(std::move(a));
    }
    require(n <= 24 && n * 2 <= b.size() - i, "map-too-large");
    std::vector<std::pair<std::string, Value>> o;
    o.reserve(size_t(n));
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
  explicit CborReader(const Bytes &x,size_t maximum_nodes=SIZE_MAX,size_t maximum_array=256) : b(x),node_limit(maximum_nodes),array_limit(maximum_array) {}
  Value finish() {
    auto v = read(0);
    require(i == b.size(), "trailing-bytes");
    return v;
  }
};
inline Value decode(const Bytes &b, size_t limit = 896,size_t maximum_nodes=SIZE_MAX) {
  require(b.size() <= limit, "message-too-large");
  return CborReader(b,maximum_nodes,limit>=65536?512:256).finish();
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
