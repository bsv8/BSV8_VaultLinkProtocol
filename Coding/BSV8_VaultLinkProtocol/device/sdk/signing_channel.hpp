#pragma once
#include "cbor.hpp"
namespace vaultlink {
inline void signing_identifier(const std::string& s){require(!s.empty()&&s.size()<=96&&std::all_of(s.begin(),s.end(),[](char c){return (c>='a'&&c<='z')||(c>='A'&&c<='Z')||(c>='0'&&c<='9')||c=='.'||c=='_'||c==':'||c=='/'||c=='-';}),"invalid-id");}
inline bool signing_operation(const std::string& op){return op=="identity.noise-proof"||op=="identity.peer-record"||op=="connect.identity-sign"||op=="connect.intent-sign"||op=="bitfs.wire-sign"||op=="channel.public-message"||op=="channel.hash-request"||op=="channel.private-message"||op=="software.digest-sign";}
inline Value inspect_signing_channel(const Value& c){
 c.fields({"id","owner","kind","operation","mode","revision"});
 signing_identifier(c.at("id").string());signing_identifier(c.at("owner").string());
 require(c.at("kind").string()=="app"||c.at("kind").string()=="plugin","invalid-owner");
 require(signing_operation(c.at("operation").string()),"unsupported");
 require(c.at("mode").string()=="automatic"||c.at("mode").string()=="manual","invalid-mode");
 auto rev=c.at("revision").integer();require(rev>0&&rev<0xffffffff,"invalid-revision");return c;
}
inline bool same_signing_registration(const Value& a,const Value& b){for(const char* k:{"id","owner","kind","operation"})if(a.at(k).string()!=b.at(k).string())return false;return true;}
}
