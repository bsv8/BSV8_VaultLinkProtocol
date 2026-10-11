// Host test executes the SDK journal against actual disk files. It is not an
// ESP32 Flash/power-cut test, nor a private-key migration implementation.
#include "sdk/migration.hpp"
#include <filesystem>
#include <fstream>
#include <iostream>
using namespace vaultlink;
class Files final:public Store {
  std::string path;
 public:
  explicit Files(std::string p):path(std::move(p)){}
  Bytes load()override {
    if(!std::filesystem::exists(path))return {};
    std::ifstream in(path,std::ios::binary);require(bool(in),"read-failed");
    return Bytes(std::istreambuf_iterator<char>(in),{});
  }
  void save(const Bytes& bytes)override {
    auto tmp=path+".tmp";std::ofstream out(tmp,std::ios::binary);
    out.write(reinterpret_cast<const char*>(bytes.data()),bytes.size());out.close();
    require(bool(out),"write-failed");std::filesystem::rename(tmp,path);
  }
};
int main(int argc,char** argv) {
  try {
    require(argc==5,"arguments-required");Files store(argv[1]);MigrationJournal journal(store);
    Value target;
    if(std::string(argv[4])!="-") {
      std::string text(argv[4]);require(text.size()==64,"invalid-hash");Bytes bytes;
      auto digit=[](char c)->int {if(c>='0'&&c<='9')return c-'0';if(c>='a'&&c<='f')return c-'a'+10;throw Failure("invalid-hash");};
      for(size_t i=0;i<text.size();i+=2)bytes.push_back(uint8_t(digit(text[i])*16+digit(text[i+1])));
      target=Value(bytes);
    }
    if(std::string(argv[3])=="begin") {
      require(journal.status().kind!=Value::Null,"missing-journal");auto proposed=journal.status();
      for(auto& field:proposed.map) {
        if(field.first=="id")field.second=Value(argv[2]);
        if(field.first=="phase")field.second=Value("staged");
        if(field.first=="targetHash")field.second=Value();
      }
      journal.begin(proposed);
    }else journal.advance(argv[2],argv[3],target);
    // Reopen the actual committed disk record and validate its exact state.
    MigrationJournal reopened(store);require(encode(journal.status(),1024)==encode(reopened.status(),1024),"readback-failed");
    return 0;
  }catch(const std::exception& e) {std::cerr<<e.what()<<'\n';return 1;}
}
