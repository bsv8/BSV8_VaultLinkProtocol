#include "sdk/jcs.hpp"
#include <iostream>
int main(){std::string line;while(std::getline(std::cin,line)){
  try{auto value=vaultlink::JcsReader(line).finish();std::cout<<"ok:"<<value.canonical<<"\n";}
  catch(const std::exception &e){std::cout<<"error:"<<e.what()<<"\n";}
}return 0;}
