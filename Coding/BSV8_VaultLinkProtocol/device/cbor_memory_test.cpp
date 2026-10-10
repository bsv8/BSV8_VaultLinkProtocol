#include "sdk/cbor.hpp"
#include <cstdlib>
#include <cstdio>
#include <cstddef>
#include <new>

// Measure actual C++ allocations: a 32KiB canonical map must encode with
// 40KiB additional heap. Cloning the nested Value tree exceeds this budget.
namespace {
struct alignas(std::max_align_t) Header { size_t size; };
size_t live=0, ceiling=SIZE_MAX;
}
void* operator new(size_t n) {
  if(n>ceiling-live)throw std::bad_alloc();
  auto* p=static_cast<Header*>(std::malloc(sizeof(Header)+n));
  if(!p)throw std::bad_alloc();p->size=n;live+=n;return p+1;
}
void operator delete(void* p) noexcept {if(p){auto* h=static_cast<Header*>(p)-1;live-=h->size;std::free(h);}}
void operator delete(void* p,size_t) noexcept {::operator delete(p);}
void* operator new[](size_t n){return ::operator new(n);}
void operator delete[](void* p) noexcept {::operator delete(p);}
void operator delete[](void* p,size_t) noexcept {::operator delete(p);}
int main() {
  using namespace vaultlink;
  try {
    auto value=obj({{"blob",Value(Bytes(32768,0x42))}});
    ceiling=live+40960;
    auto encoded=encode(value,65536);
    ceiling=SIZE_MAX;
    require(encoded.size()==32777,"unexpected-size");
    const Bytes prefix={0xa1,0x64,'b','l','o','b',0x59,0x80,0x00};
    require(std::equal(prefix.begin(),prefix.end(),encoded.begin()),"noncanonical-prefix");
    require(decode(encoded,65536).at("blob").binary()==value.at("blob").binary(),"roundtrip-failed");
    std::puts("PASS: canonical CBOR encoding within 40KiB extra heap");return 0;
  } catch(const std::exception& e) {
    ceiling=SIZE_MAX;std::fprintf(stderr,"FAIL: %s\n",e.what());return 1;
  }
}
