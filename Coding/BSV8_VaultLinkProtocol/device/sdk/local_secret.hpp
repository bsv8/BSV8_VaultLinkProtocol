#pragma once
#include "crypto.hpp"
#include <mbedtls/platform_util.h>
namespace vaultlink {
inline void local_scope(const std::string &scope) {
  require(!scope.empty()&&scope.size()<=95&&utf8_valid(scope),"invalid-scope");
  for(unsigned char c:scope)require(c>31&&c!=127,"invalid-scope");
}
struct SecretBuffer {
  Bytes bytes;
  explicit SecretBuffer(size_t n):bytes(n){}
  ~SecretBuffer(){if(!bytes.empty())mbedtls_platform_zeroize(bytes.data(),bytes.size());}
  SecretBuffer(const SecretBuffer &)=delete;
};
struct LocalGcm {
  mbedtls_gcm_context ctx;
  LocalGcm(){mbedtls_gcm_init(&ctx);}
  ~LocalGcm(){mbedtls_gcm_free(&ctx);}
};
inline Bytes local_aad(const std::string &scope,const Bytes &salt) {
  auto text=std::string("keymaster:local-secret:v3|")+scope;
  return join({Bytes(text.begin(),text.end()),Bytes{0},salt});
}
// 仅在设备内部派生；信封 salt 只参与 AAD，不能误用成 HKDF salt。
inline Value IdentityKey::seal_local(const std::string &scope,const Bytes &plain) {
  require(unlocked,"locked");local_scope(scope);require(!plain.empty()&&plain.size()<=512,"invalid-secret");
  SecretBuffer ikm(32),derived(32);check(mbedtls_mpi_write_binary(&d.v,ikm.bytes.data(),32));
  const std::string salt_text="keymaster.vault.local-secret.v3";
  auto info=to_hex(public_bytes)+std::string(1,'\0')+scope;
  derived.bytes=hkdf(ikm.bytes,Bytes(salt_text.begin(),salt_text.end()),info,32);
  Bytes salt(16),nonce(12),cipher(plain.size()+16);check(rng(nullptr,salt.data(),salt.size()));check(rng(nullptr,nonce.data(),nonce.size()));
  auto aad=local_aad(scope,salt);LocalGcm gcm;check(mbedtls_gcm_setkey(&gcm.ctx,MBEDTLS_CIPHER_ID_AES,derived.bytes.data(),256));
  check(mbedtls_gcm_crypt_and_tag(&gcm.ctx,MBEDTLS_GCM_ENCRYPT,plain.size(),nonce.data(),nonce.size(),aad.data(),aad.size(),plain.data(),cipher.data(),16,cipher.data()+plain.size()));
  return obj({{"version",uint64_t(3)},{"keySource","active-key-hkdf-v1"},{"saltHex",to_hex(salt)},{"nonceHex",to_hex(nonce)},{"ciphertextHex",to_hex(cipher)}});
}
inline Bytes IdentityKey::open_local(const std::string &scope,const Value &sealed) {
  require(unlocked,"locked");local_scope(scope);
  sealed.fields({"version","keySource","saltHex","nonceHex","ciphertextHex"});
  require(sealed.at("version").integer()==3&&sealed.at("keySource").string()=="active-key-hkdf-v1","invalid-secret");
  require(sealed.at("saltHex").string().size()==32&&sealed.at("nonceHex").string().size()==24&&sealed.at("ciphertextHex").string().size()>=34&&sealed.at("ciphertextHex").string().size()<=1056,"invalid-secret");
  auto salt=from_hex(sealed.at("saltHex").string()),nonce=from_hex(sealed.at("nonceHex").string()),cipher=from_hex(sealed.at("ciphertextHex").string());
  SecretBuffer ikm(32),derived(32),plain(cipher.size()-16);check(mbedtls_mpi_write_binary(&d.v,ikm.bytes.data(),32));
  const std::string salt_text="keymaster.vault.local-secret.v3";
  derived.bytes=hkdf(ikm.bytes,Bytes(salt_text.begin(),salt_text.end()),to_hex(public_bytes)+std::string(1,'\0')+scope,32);
  auto aad=local_aad(scope,salt);LocalGcm gcm;check(mbedtls_gcm_setkey(&gcm.ctx,MBEDTLS_CIPHER_ID_AES,derived.bytes.data(),256));
  int rc=mbedtls_gcm_auth_decrypt(&gcm.ctx,plain.bytes.size(),nonce.data(),nonce.size(),aad.data(),aad.size(),cipher.data()+plain.bytes.size(),16,cipher.data(),plain.bytes.data());
  require(rc==0,"invalid-secret");return plain.bytes;
}
} // namespace vaultlink
