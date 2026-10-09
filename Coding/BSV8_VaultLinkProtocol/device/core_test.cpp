#include "core.hpp"
#include <cassert>
#include <iostream>
#include <fstream>
#include <vector>
using namespace vaultlink;
int main(int argc,char**argv){assert(argc==2);std::ifstream in(argv[1],std::ios::binary);assert(in.good());std::vector<uint8_t>bytes((std::istreambuf_iterator<char>(in)),{});assert(!bytes.empty());FrameReader reader;Frame frame;unsigned frames=0;for(auto b:bytes)if(reader.feed(b,frame)){frames++;assert(frame.type==16&&frame.size==1024&&frame.seq==7);}assert(frames==1);
const uint8_t check[]={'1','2','3','4','5','6','7','8','9'};assert(crc32(check,9)==0xcbf43926);
RequestGate g;Request r;r.id=1;r.session=2;r.commitment.fill(3);State state;assert(g.accept(r,state)==Error::ok);assert(g.start(1)==Error::ok);assert(g.finish(1,State::cancelled)==Error::invalid);assert(g.finish(1,State::completed)==Error::ok);assert(g.accept(r,state)==Error::ok&&state==State::completed);r.id=2;assert(g.accept(r,state)==Error::ok);assert(g.finish(2,State::denied)==Error::ok);r.id=1;assert(g.accept(r,state)==Error::replay);g.close();r.id=3;assert(g.accept(r,state)==Error::unavailable);
Quote q;assert(quote(10,10,true,5,15,q)==Error::ok&&!q.single&&!q.total&&q.next_used==15);assert(quote(11,10,true,5,15,q)==Error::ok&&q.single&&q.total);assert(quote(1,10,true,UINT64_MAX,UINT64_MAX,q)==Error::overflow);assert(quote(10,10,false,UINT64_MAX,0,q)==Error::ok&&!q.total);uint64_t total=0;assert(external_output(5,false,total)==Error::ok&&total==5);assert(external_output(100,true,total)==Error::ok&&total==5);
std::cout<<"device core: frame byte interoperability, request watermark, quota boundaries passed\n";}
