#pragma once
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>

// 平台无关、无动态分配；密钥、CryptoProvider/持久原子提交由设备适配提供。
namespace vaultlink {
enum class Error { ok, invalid, busy, replay, conflict, unavailable, confirmation, overflow };
enum class State { waiting, executing, completed, denied, cancelled, unknown };
struct Request { uint32_t id=0, session=0; std::array<uint8_t,32> commitment{}; State state=State::waiting; };
class RequestGate {
  uint32_t watermark_=0; bool closed_=false, has_active_=false, has_recent_=false;
  Request active_{},recent_{};
  static bool same(const Request&a,const Request&b){return a.session==b.session&&a.commitment==b.commitment;}
 public:
  Error accept(const Request&r,State&state){
    if(closed_)return Error::unavailable;
    bool nonzero=false;for(auto b:r.commitment)nonzero|=b!=0;
    if(!r.id||!r.session||!nonzero)return Error::invalid;
    const Request*old=has_active_&&active_.id==r.id?&active_:has_recent_&&recent_.id==r.id?&recent_:nullptr;
    if(old){if(!same(*old,r))return Error::conflict;state=old->state;return Error::ok;}
    if(r.id<=watermark_)return Error::replay;
    if(has_active_)return Error::busy;
    watermark_=r.id;active_=r;active_.state=State::waiting;has_active_=true;state=State::waiting;return Error::ok;
  }
  Error start(uint32_t id){if(closed_)return Error::unavailable;if(!has_active_||active_.id!=id||active_.state!=State::waiting)return Error::invalid;active_.state=State::executing;return Error::ok;}
  Error finish(uint32_t id,State state){if(closed_)return Error::unavailable;if(!has_active_||active_.id!=id)return Error::invalid;
    if(state==State::completed&&active_.state!=State::executing)return Error::invalid;
    if((state==State::cancelled||state==State::denied)&&active_.state!=State::waiting)return Error::invalid;
    if(state==State::waiting||state==State::executing)return Error::invalid;
    active_.state=state;recent_=active_;has_recent_=true;has_active_=false;return Error::ok;}
  Error query(const Request&r,State&state)const{if(closed_)return Error::unavailable;const Request*p=has_active_&&active_.id==r.id?&active_:has_recent_&&recent_.id==r.id?&recent_:nullptr;if(!p)return Error::unavailable;if(!same(*p,r))return Error::conflict;state=p->state;return Error::ok;}
  void close(){closed_=true;has_active_=has_recent_=false;active_={};recent_={};}
};
inline uint32_t crc32(const uint8_t*data,size_t size){uint32_t c=0xffffffffu;for(size_t i=0;i<size;i++){c^=data[i];for(unsigned j=0;j<8;j++)c=(c&1)?(c>>1)^0xedb88320u:c>>1;}return c^0xffffffffu;}
struct Frame {uint8_t type=0;uint32_t seq=0;uint16_t size=0;std::array<uint8_t,1024> payload{};};
inline bool valid_type(uint8_t t){return (t>=1&&t<=6)||t==16||t==17||t==18;}
class FrameReader {
  std::array<uint8_t,1039> buffer_{};size_t used_=0;
  void shift(size_t n){std::memmove(buffer_.data(),buffer_.data()+n,used_-n);used_-=n;}
  static uint32_t le32(const uint8_t*p){return uint32_t(p[0])|(uint32_t(p[1])<<8)|(uint32_t(p[2])<<16)|(uint32_t(p[3])<<24);}
 public:
  // 调用者逐字节投入，不受一次 USB read 边界影响。true 时 frame 为完整副本。
  bool feed(uint8_t byte,Frame&frame){if(used_==buffer_.size())shift(1);buffer_[used_++]=byte;
    while(used_>=2){if(buffer_[0]!=0xa5||buffer_[1]!=0x5a){shift(1);continue;}if(used_<11)return false;
      uint16_t len=uint16_t(buffer_[9])|(uint16_t(buffer_[10])<<8);
      if(buffer_[2]!=2||buffer_[4]!=0||!valid_type(buffer_[3])||len>1024){shift(1);continue;}
      if(used_<size_t(len)+15)return false;
      if(le32(buffer_.data()+11+len)!=crc32(buffer_.data()+2,9+len)){shift(1);continue;}
      frame.type=buffer_[3];frame.seq=le32(buffer_.data()+5);frame.size=len;
      std::memcpy(frame.payload.data(),buffer_.data()+11,len);shift(size_t(len)+15);return true;
    }return false;
  }
  void close(){buffer_.fill(0);used_=0;}
};
struct Quote {bool single=false,total=false;uint64_t next_used=0;};
// 纯数学核算，不是完整授权。必须由实际 Profile 提供输出金额，持久状态检查及实体确认后才能提交。
inline Error quote(uint64_t amount,uint64_t single_limit,bool app,uint64_t used,uint64_t session_limit,Quote&q){
  q={};if(!amount)return Error::invalid;q.single=amount>single_limit;
  if(app){if(amount>std::numeric_limits<uint64_t>::max()-used)return Error::overflow;q.next_used=used+amount;q.total=q.next_used>session_limit;}
  return Error::ok;
}
inline Error external_output(uint64_t satoshis,bool owned,uint64_t&total){if(owned)return Error::ok;if(satoshis>std::numeric_limits<uint64_t>::max()-total)return Error::overflow;total+=satoshis;return Error::ok;}
} // namespace vaultlink
