#pragma once
#include "cbor.hpp"
#include "../third_party/double-conversion/double-conversion.h"
#include <cmath>
#include <limits>
namespace vaultlink {
// A bounded JSON tree used only for the actual Channel object, not a display summary.
struct Json {
  enum Kind { Null,Bool,Number,String,Array,Object } kind=Null;
  std::string text,canonical;
  double number=0;
  bool boolean=false;
  std::vector<Json> array;
  std::vector<std::pair<std::string,Json>> object;
  Json()=default;
  Json(const Json&)=default;
  Json(Json&&)=default;
  Json& operator=(const Json&)=default;
  Json& operator=(Json&&)=default;
  ~Json(){
    // Decrypted inbox bodies also pass through this bounded tree.
    for(auto *s:{&text,&canonical}){volatile char *p=s->empty()?nullptr:&(*s)[0];for(size_t i=0;i<s->size();++i)p[i]=0;}
  }
  const Json &at(const std::string &name) const {
    require(kind==Object,"invalid-json");for(const auto &p:object)if(p.first==name)return p.second;
    throw Failure("missing-field");
  }
  std::string string() const{require(kind==String,"invalid-json");return text;}
  uint64_t integer() const{
    require(kind==Number&&number>=0&&number<=9007199254740991.0&&std::floor(number)==number,"invalid-json");return uint64_t(number);
  }
  void fields(std::initializer_list<const char *> names) const {
    require(kind==Object&&object.size()==names.size(),"invalid-fields");for(auto name:names)(void)at(name);
  }
};
inline void json_utf8(std::string &out,uint32_t cp) {
  require(cp<=0x10ffff&&!(cp>=0xd800&&cp<=0xdfff),"invalid-utf8");
  if(cp<0x80)out.push_back(char(cp));
  else if(cp<0x800){out.push_back(char(0xc0|(cp>>6)));out.push_back(char(0x80|(cp&63)));}
  else if(cp<0x10000){out.push_back(char(0xe0|(cp>>12)));out.push_back(char(0x80|((cp>>6)&63)));out.push_back(char(0x80|(cp&63)));}
  else{out.push_back(char(0xf0|(cp>>18)));out.push_back(char(0x80|((cp>>12)&63)));out.push_back(char(0x80|((cp>>6)&63)));out.push_back(char(0x80|(cp&63)));}
}
inline std::vector<uint16_t> json_utf16(const std::string &s) {
  require(utf8_valid(s),"invalid-utf8");std::vector<uint16_t> out;
  for(size_t i=0;i<s.size();) {
    uint32_t cp=uint8_t(s[i++]);unsigned n=cp<128?0:(cp<224?1:(cp<240?2:3));
    if(n)cp&=(1u<<(6-n))-1;
    while(n--)cp=(cp<<6)|(uint8_t(s[i++])&63);
    if(cp<0x10000)out.push_back(uint16_t(cp));
    else{cp-=0x10000;out.push_back(uint16_t(0xd800+(cp>>10)));out.push_back(uint16_t(0xdc00+(cp&1023)));}
  }return out;
}
inline std::string json_quote(const std::string &s) {
  require(utf8_valid(s),"invalid-utf8");std::string out="\"";const char *hex="0123456789abcdef";
  for(unsigned char c:s) {
    switch(c){case '"':out+="\\\"";break;case '\\':out+="\\\\";break;case '\b':out+="\\b";break;
      case '\f':out+="\\f";break;case '\n':out+="\\n";break;case '\r':out+="\\r";break;case '\t':out+="\\t";break;
      default:if(c<32){out+="\\u00";out+=hex[c>>4];out+=hex[c&15];}else out.push_back(char(c));}
  }return out+'"';
}
class JcsReader {
  const std::string &source;
  size_t position=0,nodes=0,materialized=0;
  char take(){require(position<source.size(),"truncated-json");return source[position++];}
  uint32_t hex4(){uint32_t cp=0;for(unsigned i=0;i<4;++i){char c=take();unsigned v=c>='0'&&c<='9'?unsigned(c-'0'):c>='a'&&c<='f'?unsigned(c-'a'+10):c>='A'&&c<='F'?unsigned(c-'A'+10):16;require(v<16,"invalid-json");cp=(cp<<4)|v;}return cp;}
  std::string string() {
    size_t begin=position;require(take()=='"',"invalid-json");std::string out;
    for(;;){unsigned char c=uint8_t(take());if(c=='"')break;require(c>=32,"invalid-json");
      if(c!='\\'){out.push_back(char(c));continue;}
      char escaped=take();
      switch(escaped){case '"':case '\\':case '/':out.push_back(escaped);break;
        case 'b':out+='\b';break;case 'f':out+='\f';break;case 'n':out+='\n';break;case 'r':out+='\r';break;case 't':out+='\t';break;
        case 'u':{uint32_t cp=hex4();if(cp>=0xd800&&cp<=0xdbff){require(take()=='\\'&&take()=='u',"invalid-utf8");uint32_t low=hex4();require(low>=0xdc00&&low<=0xdfff,"invalid-utf8");cp=0x10000+((cp-0xd800)<<10)+(low-0xdc00);}json_utf8(out,cp);break;}
        default:throw Failure("invalid-json");}
    }
    require(json_quote(out)==source.substr(begin,position-begin),"non-canonical-json");return out;
  }
  Json read(unsigned depth) {
    require(depth<=12&&++nodes<=256,"json-limit");size_t begin=position;Json out;char c=take();
    if(c=='n'||c=='t'||c=='f') {
      const std::string token=c=='n'?"null":c=='t'?"true":"false";
      for(size_t i=1;i<token.size();++i)require(take()==token[i],"invalid-json");
      out.kind=c=='n'?Json::Null:Json::Bool;out.boolean=c=='t';
    }else if(c=='"'){--position;out.kind=Json::String;out.text=string();}
    else if(c=='['||c=='{') {
      bool array=c=='[';out.kind=array?Json::Array:Json::Object;char close=array?']':'}';
      require(position<source.size(),"truncated-json");
      if(source[position]!=close){std::vector<uint16_t> previous;bool first=true;
        for(;;) {
          if(array)out.array.push_back(read(depth+1));
          else{require(++nodes<=256,"json-limit");auto name=string();auto ordered=json_utf16(name);
            require(first||std::lexicographical_compare(previous.begin(),previous.end(),ordered.begin(),ordered.end()),"json-key-order");
            first=false;previous=std::move(ordered);require(take()==':',"invalid-json");out.object.emplace_back(std::move(name),read(depth+1));}
          require(position<source.size(),"truncated-json");if(source[position]==close)break;require(take()==',',"invalid-json");
        }
      }require(take()==close,"invalid-json");
    }else {
      require(c=='-'||(c>='0'&&c<='9'),"invalid-json");
      while(position<source.size()){char d=source[position];if((d>='0'&&d<='9')||d=='e'||d=='E'||d=='+'||d=='-'||d=='.')++position;else break;}
      auto raw=source.substr(begin,position-begin);
      using namespace double_conversion;
      StringToDoubleConverter parser(StringToDoubleConverter::NO_FLAGS,0,std::numeric_limits<double>::quiet_NaN(),nullptr,nullptr);
      int processed=0;out.number=parser.StringToDouble(raw.data(),int(raw.size()),&processed);
      require(processed==int(raw.size())&&std::isfinite(out.number),"invalid-json-number");
      char result[128];StringBuilder builder(result,sizeof(result));
      require(DoubleToStringConverter::EcmaScriptConverter().ToShortest(out.number,&builder),"invalid-json-number");
      auto canonical=std::string(builder.Finalize());require(canonical==raw,"non-canonical-json-number");
      out.kind=Json::Number;
    }
    materialized+=position-begin;require(materialized<=32768,"json-limit");
    out.canonical=source.substr(begin,position-begin);return out;
  }
 public:
  explicit JcsReader(const std::string &s):source(s){require(s.size()<=16384&&utf8_valid(s),"invalid-json");}
  Json finish(){auto value=read(0);require(position==source.size(),"trailing-json");return value;}
};
inline Json parse_jcs(const Bytes &bytes){
  std::string s(bytes.begin(),bytes.end());
  struct Wipe {std::string &s;~Wipe(){volatile char *p=s.empty()?nullptr:&s[0];for(size_t i=0;i<s.size();++i)p[i]=0;}} wipe{s};
  return JcsReader(s).finish();
}
inline Bytes json_bytes(const std::string &s){return Bytes(s.begin(),s.end());}
}
