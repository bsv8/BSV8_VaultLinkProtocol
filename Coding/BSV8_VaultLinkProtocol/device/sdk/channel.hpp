#pragma once
#include "crypto.hpp"
#include "jcs.hpp"
#include "local_secret.hpp"
#include <mbedtls/base64.h>
namespace vaultlink {
inline std::string channel_base64(const Bytes &bytes) {
  Bytes out(4*((bytes.size()+2)/3)+1);size_t n=0;
  check(mbedtls_base64_encode(out.data(),out.size(),&n,bytes.data(),bytes.size()));
  std::string s(out.begin(),out.begin()+n);for(char &c:s){if(c=='+')c='-';else if(c=='/')c='_';}
  while(!s.empty()&&s.back()=='=')s.pop_back();return s;
}
inline Bytes channel_unbase64(const std::string &text,size_t length=SIZE_MAX) {
  require(text.size()<=22000&&text.size()%4!=1,"invalid-base64");std::string padded=text;
  for(char &c:padded){require((c>='A'&&c<='Z')||(c>='a'&&c<='z')||(c>='0'&&c<='9')||c=='-'||c=='_',"invalid-base64");if(c=='-')c='+';else if(c=='_')c='/';}
  while(padded.size()%4)padded+='=';Bytes out(3*(padded.size()/4)+1);size_t n=0;
  check(mbedtls_base64_decode(out.data(),out.size(),&n,reinterpret_cast<const unsigned char *>(padded.data()),padded.size()));
  out.resize(n);require((length==SIZE_MAX||n==length)&&channel_base64(out)==text,"invalid-base64");return out;
}
inline void channel_point(Group &group,Point &q,const Bytes &pub) {
  require(pub.size()==33&&(pub[0]==2||pub[0]==3),"invalid-key");Mpi rhs,temp,exponent;
  auto &x=q.v.MBEDTLS_PRIVATE(X),&y=q.v.MBEDTLS_PRIVATE(Y);
  check(mbedtls_mpi_read_binary(&x,pub.data()+1,32));require(mbedtls_mpi_cmp_mpi(&x,&group.v.P)<0,"invalid-key");
  check(mbedtls_mpi_mul_mpi(&temp.v,&x,&x));check(mbedtls_mpi_mod_mpi(&rhs.v,&temp.v,&group.v.P));
  check(mbedtls_mpi_mul_mpi(&temp.v,&rhs.v,&x));check(mbedtls_mpi_add_int(&temp.v,&temp.v,7));check(mbedtls_mpi_mod_mpi(&rhs.v,&temp.v,&group.v.P));
  check(mbedtls_mpi_add_int(&exponent.v,&group.v.P,1));check(mbedtls_mpi_shift_r(&exponent.v,2));
  check(mbedtls_mpi_exp_mod(&y,&rhs.v,&exponent.v,&group.v.P,nullptr));
  check(mbedtls_mpi_mul_mpi(&temp.v,&y,&y));check(mbedtls_mpi_mod_mpi(&temp.v,&temp.v,&group.v.P));require(mbedtls_mpi_cmp_mpi(&temp.v,&rhs.v)==0,"invalid-key");
  if(mbedtls_mpi_get_bit(&y,0)!=(pub[0]&1))check(mbedtls_mpi_sub_mpi(&y,&group.v.P,&y));
  check(mbedtls_mpi_lset(&q.v.MBEDTLS_PRIVATE(Z),1));check(mbedtls_ecp_check_pubkey(&group.v,&q.v));
}
inline Bytes channel_pub(const std::string &s) {
  require(s.size()==66&&s.substr(0,2)!="00","invalid-key");
  for(char c:s)require((c>='0'&&c<='9')||(c>='a'&&c<='f'),"invalid-key");
  auto bytes=from_hex(s);Group group(MBEDTLS_ECP_DP_SECP256K1);Point q;channel_point(group,q,bytes);return bytes;
}
inline void channel_verify(const Bytes &pub,const Bytes &digest,const Bytes &der) {
  require(digest.size()==32&&der.size()>=8&&der.size()<=72&&der[0]==0x30&&size_t(der[1])+2==der.size(),"invalid-signature");
  size_t pos=2;Mpi r,s,half;Group group(MBEDTLS_ECP_DP_SECP256K1);Point q;
  auto integer=[&](mbedtls_mpi &out){require(pos+2<=der.size()&&der[pos++]==2,"invalid-signature");size_t n=der[pos++];require(n>=1&&n<=33&&n<=der.size()-pos&&!(der[pos]&128),"invalid-signature");
    require(!(n>1&&der[pos]==0&&!(der[pos+1]&128)),"invalid-signature");check(mbedtls_mpi_read_binary(&out,der.data()+pos,n));pos+=n;
    require(mbedtls_mpi_cmp_int(&out,1)>=0&&mbedtls_mpi_cmp_mpi(&out,&group.v.N)<0,"invalid-signature");};
  integer(r.v);integer(s.v);require(pos==der.size(),"invalid-signature");check(mbedtls_mpi_copy(&half.v,&group.v.N));check(mbedtls_mpi_shift_r(&half.v,1));require(mbedtls_mpi_cmp_mpi(&s.v,&half.v)<=0,"invalid-signature");
  channel_point(group,q,pub);require(mbedtls_ecdsa_verify(&group.v,digest.data(),digest.size(),&q.v,&r.v,&s.v)==0,"invalid-signature");
}
inline uint64_t channel_lifetime(const std::string &protocol) {
  if(protocol=="bsv8.message.v1")return 86400000;
  if(protocol=="bsv8.ping.v1")return 60000;
  if(protocol=="bsv8.webrtc.signal.v1")return 120000;
  throw Failure("unsupported-protocol");
}
struct ChannelReview {std::string channel,peer,protocol,message_id;uint64_t issued=0,expires=0;Bytes digest;};
inline void channel_private_body(const std::string &protocol,const Json &body) {
  if(protocol=="bsv8.webrtc.signal.v1") {
    body.fields({"request_message_id","session_id","signal"});channel_unbase64(body.at("request_message_id").string(),32);channel_unbase64(body.at("session_id").string(),32);
    const auto &s=body.at("signal");auto type=s.at("type").string();
    if(type=="offer"||type=="answer"){s.fields({"type","sdp"});require(!s.at("sdp").string().empty(),"invalid-body");}
    else if(type=="end-of-candidates")s.fields({"type"});
    else if(type=="ice-candidate") {
      s.fields({"type","candidate"});const auto &c=s.at("candidate");c.fields({"candidate","sdp_mid","sdp_m_line_index"});(void)c.at("candidate").string();
      require(c.at("sdp_mid").kind==Json::Null||c.at("sdp_mid").kind==Json::String,"invalid-body");
      if(c.at("sdp_m_line_index").kind!=Json::Null)(void)c.at("sdp_m_line_index").integer();
    }else throw Failure("invalid-body");return;
  }
  auto type=body.at("type").string();
  if(protocol=="bsv8.ping.v1"&&type=="ping"){body.fields({"type"});return;}
  if(protocol=="bsv8.message.v1"&&type=="deliver"){body.fields({"type","content"});return;}
  if(protocol=="bsv8.ping.v1"&&type=="pong"){body.fields({"type","ping_message_id"});channel_unbase64(body.at("ping_message_id").string(),32);return;}
  if(protocol=="bsv8.message.v1"&&type=="ack"){body.fields({"type","acknowledged_message_id"});channel_unbase64(body.at("acknowledged_message_id").string(),32);return;}
  throw Failure("invalid-body");
}
inline ChannelReview inspect_channel(const std::string &kind,const Bytes &raw,const Bytes &own_pub) {
  auto root=parse_jcs(raw);root.fields({"channel","from_public_key","message","scope"});
  bool priv=kind=="private";require(priv||kind=="public"||kind=="hash","unsupported");
  require(root.at("scope").string()==(priv?"bsv8.private-message.v1":"bsv8.public-message.v1"),"invalid-scope");
  require(channel_pub(root.at("from_public_key").string())==own_pub,"wrong-key");ChannelReview r;r.channel=root.at("channel").string();
  require(!r.channel.empty()&&r.channel!="*"&&r.channel.size()<=256,"invalid-channel");for(unsigned char c:r.channel)require(c>31&&c!=127,"invalid-channel");
  if(kind=="hash")require(r.channel=="bsv8.hash.request.v1","invalid-channel");
  const auto &message=root.at("message");
  if(priv)message.fields({"protocol","message_id","issued_at_ms","expires_at_ms","body"});else message.fields({"message_id","issued_at_ms","expires_at_ms","body"});
  r.message_id=message.at("message_id").string();channel_unbase64(r.message_id,32);
  r.issued=message.at("issued_at_ms").integer();r.expires=message.at("expires_at_ms").integer();
  uint64_t lifetime=600000;
  if(priv){r.protocol=message.at("protocol").string();lifetime=channel_lifetime(r.protocol);require(r.channel.substr(0,11)=="bsv8.inbox.","invalid-channel");r.peer=r.channel.substr(11);channel_pub(r.peer);channel_private_body(r.protocol,message.at("body"));}
  require(r.expires>r.issued&&r.expires-r.issued<=lifetime,"invalid-time");
  if(kind=="hash") {
    const auto &b=message.at("body");b.fields({"hash","locators"});auto hash=b.at("hash").string();require(hash.size()==64,"invalid-body");
    for(char c:hash)require((c>='0'&&c<='9')||(c>='a'&&c<='f'),"invalid-body");
    const auto &locators=b.at("locators");require(locators.kind==Json::Array&&!locators.array.empty(),"invalid-body");
    for(const auto &locator:locators.array){auto k=locator.at("kind").string();if(k=="webrtc-sdp")locator.fields({"kind"});else{locator.fields({"kind","address"});require(k=="multiaddr"&&locator.at("address").string().substr(0,1)=="/","invalid-body");}}
  }
  r.digest=sha256(raw);return r;
}
inline std::string channel_logical(const Json &signed_message) {
  const auto &v=signed_message;
  return "{\"channel\":"+v.at("channel").canonical+",\"from_public_key\":"+v.at("from_public_key").canonical+
    ",\"message\":{\"body\":"+v.at("body").canonical+",\"expires_at_ms\":"+v.at("expires_at_ms").canonical+
    ",\"issued_at_ms\":"+v.at("issued_at_ms").canonical+",\"message_id\":"+v.at("message_id").canonical+
    ",\"protocol\":"+v.at("protocol").canonical+"},\"scope\":\"bsv8.private-message.v1\"}";
}
inline ChannelReview inspect_signed_channel(const Bytes &raw,const Bytes &pub) {
  auto message=parse_jcs(raw);message.fields({"channel","from_public_key","protocol","message_id","issued_at_ms","expires_at_ms","body","signature"});
  auto review=inspect_channel("private",json_bytes(channel_logical(message)),pub);
  channel_verify(pub,review.digest,channel_unbase64(message.at("signature").string()));return review;
}
inline Bytes IdentityKey::inbox_key(const Bytes &peer,const Bytes &salt,const std::string &channel,const std::string &sender) {
  require(unlocked&&salt.size()==32,"locked");Point q;channel_point(g,q,peer);Mpi shared;
  check(mbedtls_ecdh_compute_shared(&g.v,&shared.v,&q.v,&d.v,rng,nullptr));Bytes bytes(32);WipeBytes wipe{bytes};check(mbedtls_mpi_write_binary(&shared.v,bytes.data(),32));
  auto info="{\"channel\":"+json_quote(channel)+",\"from_public_key\":"+json_quote(sender)+",\"scope\":\"bsv8.inbox.envelope.v1\"}";
  return hkdf(bytes,salt,info,32);
}
inline Bytes IdentityKey::seal_channel(const Bytes &raw) {
  auto review=inspect_signed_channel(raw,public_key());require(unlocked,"locked");auto message=parse_jcs(raw);
  Bytes salt(32),nonce(12);check(rng(nullptr,salt.data(),salt.size()));check(rng(nullptr,nonce.data(),nonce.size()));
  auto sender=to_hex(public_key()),salt_text=channel_base64(salt),nonce_text=channel_base64(nonce);
  auto aad="{\"channel\":"+json_quote(review.channel)+",\"envelope_version\":1,\"from_public_key\":"+json_quote(sender)+",\"kdf_salt\":"+json_quote(salt_text)+",\"nonce\":"+json_quote(nonce_text)+"}";
  auto plain=json_bytes("{\"body\":"+message.at("body").canonical+",\"expires_at_ms\":"+message.at("expires_at_ms").canonical+
    ",\"issued_at_ms\":"+message.at("issued_at_ms").canonical+",\"message_id\":"+message.at("message_id").canonical+
    ",\"protocol\":"+message.at("protocol").canonical+",\"signature\":"+message.at("signature").canonical+"}");WipeBytes wipe_plain{plain};
  auto derived=inbox_key(channel_pub(review.peer),salt,review.channel,sender);WipeBytes wipe_key{derived};LocalGcm gcm;check(mbedtls_gcm_setkey(&gcm.ctx,MBEDTLS_CIPHER_ID_AES,derived.data(),256));
  Bytes cipher(plain.size()+16);check(mbedtls_gcm_crypt_and_tag(&gcm.ctx,MBEDTLS_GCM_ENCRYPT,plain.size(),nonce.data(),nonce.size(),reinterpret_cast<const unsigned char *>(aad.data()),aad.size(),plain.data(),cipher.data(),16,cipher.data()+plain.size()));
  return json_bytes("{\"channel\":"+json_quote(review.channel)+",\"ciphertext\":"+json_quote(channel_base64(cipher))+",\"envelope_version\":1,\"from_public_key\":"+json_quote(sender)+",\"kdf_salt\":"+json_quote(salt_text)+",\"nonce\":"+json_quote(nonce_text)+"}");
}
inline Bytes IdentityKey::open_channel(const Bytes &raw) {
  require(unlocked,"locked");auto envelope=parse_jcs(raw);envelope.fields({"channel","ciphertext","envelope_version","from_public_key","kdf_salt","nonce"});
  auto channel=envelope.at("channel").string(),sender=envelope.at("from_public_key").string();
  require(channel=="bsv8.inbox."+to_hex(public_key())&&envelope.at("envelope_version").integer()==1,"invalid-envelope");
  auto peer=channel_pub(sender),salt=channel_unbase64(envelope.at("kdf_salt").string(),32),nonce=channel_unbase64(envelope.at("nonce").string(),12),cipher=channel_unbase64(envelope.at("ciphertext").string());require(cipher.size()>=16,"invalid-envelope");
  auto aad="{\"channel\":"+json_quote(channel)+",\"envelope_version\":1,\"from_public_key\":"+json_quote(sender)+",\"kdf_salt\":"+envelope.at("kdf_salt").canonical+",\"nonce\":"+envelope.at("nonce").canonical+"}";
  auto derived=inbox_key(peer,salt,channel,sender);WipeBytes wipe_key{derived};LocalGcm gcm;check(mbedtls_gcm_setkey(&gcm.ctx,MBEDTLS_CIPHER_ID_AES,derived.data(),256));
  Bytes plain(cipher.size()-16);WipeBytes wipe_plain{plain};require(mbedtls_gcm_auth_decrypt(&gcm.ctx,plain.size(),nonce.data(),nonce.size(),reinterpret_cast<const unsigned char *>(aad.data()),aad.size(),cipher.data()+plain.size(),16,cipher.data(),plain.data())==0,"open-failed");
  auto message=parse_jcs(plain);message.fields({"protocol","message_id","issued_at_ms","expires_at_ms","body","signature"});
  auto full=json_bytes("{\"body\":"+message.at("body").canonical+",\"channel\":"+json_quote(channel)+",\"expires_at_ms\":"+message.at("expires_at_ms").canonical+",\"from_public_key\":"+json_quote(sender)+",\"issued_at_ms\":"+message.at("issued_at_ms").canonical+",\"message_id\":"+message.at("message_id").canonical+",\"protocol\":"+message.at("protocol").canonical+",\"signature\":"+message.at("signature").canonical+"}");
  try{inspect_signed_channel(full,peer);return full;}catch(...){wipe_bytes(full);throw;}
}
}
