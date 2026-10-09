#pragma once
#include "cbor.hpp"
#include <mbedtls/ecdh.h>
#include <mbedtls/ecdsa.h>
#include <mbedtls/gcm.h>
#include <mbedtls/hkdf.h>
#include <mbedtls/ripemd160.h>
#include <mbedtls/sha256.h>
#include <mbedtls/version.h>
#ifndef MBEDTLS_PRIVATE
#define MBEDTLS_PRIVATE(member) member
#endif
namespace vaultlink {
using Rng = int (*)(void *, unsigned char *, size_t);
inline void check(int rc) { require(rc == 0, "crypto-failed"); }
inline Bytes sha256(const Bytes &b) {
  Bytes out(32);
#if MBEDTLS_VERSION_MAJOR >= 3
  check(mbedtls_sha256(b.data(), b.size(), out.data(), 0));
#else
  check(mbedtls_sha256_ret(b.data(), b.size(), out.data(), 0));
#endif
  return out;
}
inline Bytes sha256d(const Bytes &b) { return sha256(sha256(b)); }
inline Bytes hash160(const Bytes &b) {
  auto s = sha256(b);
  Bytes out(20);
#if MBEDTLS_VERSION_MAJOR >= 3
  check(mbedtls_ripemd160(s.data(), s.size(), out.data()));
#else
  check(mbedtls_ripemd160_ret(s.data(), s.size(), out.data()));
#endif
  return out;
}
inline Bytes hkdf(const Bytes &secret, const Bytes &salt,
                  const std::string &label, size_t n) {
  Bytes out(n);
  check(mbedtls_hkdf(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), salt.data(),
                     salt.size(), secret.data(), secret.size(),
                     reinterpret_cast<const unsigned char *>(label.data()),
                     label.size(), out.data(), n));
  return out;
}
struct Mpi {
  mbedtls_mpi v;
  Mpi() { mbedtls_mpi_init(&v); }
  ~Mpi() { mbedtls_mpi_free(&v); }
  Mpi(const Mpi &) = delete;
};
struct Point {
  mbedtls_ecp_point v;
  Point() { mbedtls_ecp_point_init(&v); }
  ~Point() { mbedtls_ecp_point_free(&v); }
};
struct Group {
  mbedtls_ecp_group v;
  explicit Group(mbedtls_ecp_group_id id) {
    mbedtls_ecp_group_init(&v);
    int rc = mbedtls_ecp_group_load(&v, id);
    if (rc)
      mbedtls_ecp_group_free(&v);
    check(rc);
  }
  ~Group() { mbedtls_ecp_group_free(&v); }
};
// 使用库原语，不使用项目自己的椭圆曲线运算；公钥/私钥为 RFC7748 小端。
class X25519 {
  Group g{MBEDTLS_ECP_DP_CURVE25519};
  Mpi d;
  Point pub;
  Rng rng;

public:
  explicit X25519(Rng r) : rng(r) {
    check(mbedtls_ecp_gen_keypair(&g.v, &d.v, &pub.v, rng, nullptr));
  }
  Bytes public_key() {
    Bytes b(32);
    check(mbedtls_mpi_write_binary_le(&pub.v.MBEDTLS_PRIVATE(X), b.data(), 32));
    return b;
  }
  Bytes shared(const Bytes &b) {
    require(b.size() == 32, "invalid-peer");
    Point q;
    Mpi z;
    auto peer = b;
    peer[31] &= 127;
    check(mbedtls_mpi_read_binary_le(&q.v.MBEDTLS_PRIVATE(X), peer.data(), 32));
    check(mbedtls_mpi_lset(&q.v.MBEDTLS_PRIVATE(Z), 1));
    check(mbedtls_ecdh_compute_shared(&g.v, &z.v, &q.v, &d.v, rng, nullptr));
    Bytes out(32);
    check(mbedtls_mpi_write_binary_le(&z.v, out.data(), 32));
    require(
        std::any_of(out.begin(), out.end(), [](uint8_t c) { return c != 0; }),
        "invalid-peer");
    return out;
  }
};
class IdentityKey {
  Group g{MBEDTLS_ECP_DP_SECP256K1};
  Mpi d;
  Rng rng;
  bool unlocked = false;
  Bytes public_bytes;
  static Bytes der_int(mbedtls_mpi &v) {
    Bytes b(32);
    check(mbedtls_mpi_write_binary(&v, b.data(), 32));
    while (b.size() > 1 && b[0] == 0)
      b.erase(b.begin());
    if (b[0] & 128)
      b.insert(b.begin(), 0);
    Bytes out{2, uint8_t(b.size())};
    out.insert(out.end(), b.begin(), b.end());
    return out;
  }

public:
  IdentityKey(const Bytes &private_key, Rng r) : rng(r) { unlock(private_key); }
  // 只有可信设备适配层在本地 PIN 成功后调用；USB 不提供私钥/PIN 输入接口。
  void unlock(const Bytes &private_key) {
    require(private_key.size() == 32, "invalid-key");
    lock();
    check(mbedtls_mpi_read_binary(&d.v, private_key.data(), 32));
    check(mbedtls_ecp_check_privkey(&g.v, &d.v));
    Point q;
    check(mbedtls_ecp_mul(&g.v, &q.v, &d.v, &g.v.G, rng, nullptr));
    public_bytes.resize(33);
    size_t n = 0;
    check(mbedtls_ecp_point_write_binary(&g.v, &q.v, MBEDTLS_ECP_PF_COMPRESSED,
                                         &n, public_bytes.data(),
                                         public_bytes.size()));
    require(n == 33, "invalid-key");
    unlocked = true;
  }
  void lock() {
    unlocked = false;
    mbedtls_mpi_free(&d.v);
    mbedtls_mpi_init(&d.v);
  }
  Bytes public_key() const {
    require(public_bytes.size() == 33, "invalid-key");
    return public_bytes;
  }
  // 仅设备执行器内部调用；不注册 USB signHash 操作。
  Bytes sign(const Bytes &digest) {
    require(unlocked, "locked");
    require(digest.size() == 32, "invalid-digest");
    Mpi r, s, half;
    check(mbedtls_ecdsa_sign(&g.v, &r.v, &s.v, &d.v, digest.data(), 32, rng,
                             nullptr));
    check(mbedtls_mpi_copy(&half.v, &g.v.N));
    check(mbedtls_mpi_shift_r(&half.v, 1));
    if (mbedtls_mpi_cmp_mpi(&s.v, &half.v) > 0)
      check(mbedtls_mpi_sub_mpi(&s.v, &g.v.N, &s.v));
    auto body = join({der_int(r.v), der_int(s.v)});
    Bytes out{0x30, uint8_t(body.size())};
    out.insert(out.end(), body.begin(), body.end());
    return out;
  }
};
class Record {
  mbedtls_gcm_context ctx;
  Bytes base;
  uint32_t run, connection, seq = 0;
  uint64_t counter = 0;
  bool alive = true;
  Bytes aad(uint8_t type, uint32_t s) {
    return join({Bytes{2, type, 0}, be32(s), be32(run), be32(connection)});
  }
  Bytes nonce() {
    require(counter < UINT64_MAX, "counter-exhausted");
    auto b = base;
    uint64_t c = counter;
    for (int i = 11; i >= 0; --i) {
      uint64_t part = (c & 255) + b[i];
      b[i] = part & 255;
      c = (c >> 8) + (part >> 8);
    }
    return b;
  }

public:
  Record(const Bytes &key, const Bytes &b, uint32_t r, uint32_t c)
      : base(b), run(r), connection(c) {
    require(key.size() == 32 && b.size() == 12 && r && c, "invalid-record");
    mbedtls_gcm_init(&ctx);
    int rc = mbedtls_gcm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES, key.data(), 256);
    if (rc)
      mbedtls_gcm_free(&ctx);
    check(rc);
  }
  Record(const Record &) = delete;
  Record &operator=(const Record &) = delete;
  ~Record() {
    close();
    mbedtls_gcm_free(&ctx);
  }
  void close() {
    alive = false;
    std::fill(base.begin(), base.end(), 0);
    mbedtls_gcm_free(&ctx);
    mbedtls_gcm_init(&ctx);
  }
  Bytes seal(uint8_t type, const Bytes &plain) {
    require(alive && plain.size() <= 896 && seq < UINT32_MAX, "invalid-record");
    auto iv = nonce(), a = aad(type, seq + 1);
    Bytes out(plain.size() + 16);
    int rc = mbedtls_gcm_crypt_and_tag(
        &ctx, MBEDTLS_GCM_ENCRYPT, plain.size(), iv.data(), iv.size(), a.data(),
        a.size(), plain.data(), out.data(), 16, out.data() + plain.size());
    if (rc) {
      close();
      check(rc);
    }
    ++seq;
    ++counter;
    return out;
  }
  uint32_t sequence() const { return seq; }
  Bytes open(uint8_t type, uint32_t s, const Bytes &cipher) {
    try {
      require(alive && seq < UINT32_MAX && s == seq + 1 &&
                  cipher.size() >= 16 && cipher.size() <= 912,
              "replay-or-gap");
      auto iv = nonce(), a = aad(type, s);
      Bytes out(cipher.size() - 16);
      check(mbedtls_gcm_auth_decrypt(
          &ctx, out.size(), iv.data(), iv.size(), a.data(), a.size(),
          cipher.data() + out.size(), 16, cipher.data(), out.data()));
      seq = s;
      ++counter;
      return out;
    } catch (...) {
      close();
      throw;
    }
  }
};
} // namespace vaultlink
