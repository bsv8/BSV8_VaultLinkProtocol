// Host-only, real SDK Policy reading and rewriting a real disk bank.
#include "sdk/policy.hpp"
#include "sdk/crypto.hpp"
#include <fstream>
#include <filesystem>
#include <iostream>
using namespace vaultlink;
class Files final:public Store {
 std::string path;
 public:explicit Files(std::string p):path(std::move(p)){}
 Bytes load()override{std::ifstream in(path,std::ios::binary);require(bool(in),"read-failed");return Bytes(std::istreambuf_iterator<char>(in),{});}
 void save(const Bytes &bytes)override{auto temporary=path+".tmp";std::ofstream out(temporary,std::ios::binary);out.write(reinterpret_cast<const char*>(bytes.data()),bytes.size());out.close();require(bool(out),"write-failed");std::filesystem::rename(temporary,path);}
};
int main(int argc,char **argv){try{require(argc==3||argc==4,"path-required");Files files(argv[1]);Policy policy(files,argv[2],sha256);if(argc==4){policy.configure({"native","native-owner",10000,10000,1,true,"app","p2pkh"},true);policy.start("native-session","native-owner",true);
for(int i=0;i<257;++i){auto id="native-pay-"+std::to_string(i);policy.reserve(id,"native","native-session","native-owner",1,Bytes(32,9),false);policy.signed_payment(id);}
require(policy.snapshot().at("version").integer()==3,"archive-not-used");
require(policy.encoded_bank()==encode(policy.snapshot(),65536),"streamed-bank-not-canonical");
bool rejected=false;try{policy.fresh("native-pay-0");}catch(const std::exception&){rejected=true;}require(rejected,"replay-not-rejected");}
files.save(encode(policy.snapshot(),65536));return 0;}catch(const std::exception &e){std::cerr<<e.what()<<'\n';return 1;}}
